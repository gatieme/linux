/*
 * cmodels-kgraft.c - KLP kGraft Consistency Model
 *
 * Copyright (C) 2015 SUSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/ftrace.h>
#include <linux/livepatch.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

#define KGRAFT_TIMEOUT 2

static void klp_kgraft_work_fn(struct work_struct *work);

static struct workqueue_struct *klp_kgraft_wq;
static DECLARE_DELAYED_WORK(klp_kgraft_work, klp_kgraft_work_fn);
/*
 * This lock protects manipulation of func->state and TIF_KGR_IN_PROGRESS
 * flag when a patch is being added or removed. kGraft stub has to see
 * both values in a consistent state for the whole patch and all threads.
 */
static DEFINE_RWLOCK(klp_kgr_state_lock);

static void notrace klp_kgraft_stub(struct list_head *func_stack,
		struct klp_func *func, struct pt_regs *regs)
{
	unsigned long flags;
	bool go_old;

	if (current->flags & PF_KTHREAD)
		return;

	/*
	 * The corresponding write lock is taken only when functions are moved
	 * to _ASYNC_ states and _IN_PROGRESS flag is set for all threads.
	 */
	read_lock_irqsave(&klp_kgr_state_lock, flags);

	switch (func->state) {
	case KLP_DISABLED:
	case KLP_PREPARED:
		go_old = true;
		break;
	case KLP_ASYNC_ENABLED:
		go_old = klp_kgraft_task_in_progress(current);
		break;
	case KLP_ENABLED:
		go_old = false;
		break;
	case KLP_ASYNC_DISABLED:
		go_old = !klp_kgraft_task_in_progress(current);
		break;
	/* default: none to catch missing states at compile time! */
	}

	read_unlock_irqrestore(&klp_kgr_state_lock, flags);

	if (go_old)
		func = list_entry_rcu(list_next_rcu(&func->stack_node),
				struct klp_func, stack_node);

	/* did we hit the bottom => run the original */
	if (&func->stack_node != func_stack)
		klp_arch_set_pc(regs, (unsigned long)func->new_func);
}

static void klp_kgraft_pre_patch(struct klp_patch *patch)
	__acquires(&klp_kgr_state_lock)
{
	write_lock_irq(&klp_kgr_state_lock);
}

static bool klp_kgraft_still_patching(void)
{
	struct task_struct *p;
	bool failed = false;

	/*
	 * We do not need to take klp_kgr_state_lock here.
	 * Any race will just delay finalization.
	 */
	read_lock(&tasklist_lock);
	for_each_process(p) {
		if (klp_kgraft_task_in_progress(p)) {
			failed = true;
			break;
		}
	}
	read_unlock(&tasklist_lock);
	return failed;
}

static void klp_kgraft_work_fn(struct work_struct *work)
{
	static bool printed = false;

	if (klp_kgraft_still_patching()) {
		if (!printed) {
			pr_info("kGraft still in progress after timeout, will keep trying every %d seconds\n",
				KGRAFT_TIMEOUT);
			printed = true;
		}
		/* recheck again later */
		queue_delayed_work(klp_kgraft_wq, &klp_kgraft_work,
				KGRAFT_TIMEOUT * HZ);
		return;
	}

	/*
	 * victory, patching finished, put everything back in shape
	 * with as less performance impact as possible again
	 */
	klp_async_patch_done();
	pr_info("kGraft succeeded\n");

	printed = false;
}

static void klp_kgraft_handle_processes(void)
{
	struct task_struct *p;

	read_lock(&tasklist_lock);
	for_each_process(p) {
		/* kthreads cannot be patched yet */
		if (p->flags & PF_KTHREAD)
			continue;

		klp_kgraft_mark_task_in_progress(p);
	}
	read_unlock(&tasklist_lock);
}

static void klp_kgraft_post_patch(struct klp_patch *patch)
	__releases(&klp_kgr_state_lock)
{
	klp_kgraft_handle_processes();
	write_unlock_irq(&klp_kgr_state_lock);

	/*
	 * give everyone time to exit the kernel, and check after a while
	 */
	queue_delayed_work(klp_kgraft_wq, &klp_kgraft_work,
			KGRAFT_TIMEOUT * HZ);
}

static struct klp_cmodel kgraft_model = {
	.id = KLP_CM_KGRAFT,
	.async_finish = true,
	.stub = klp_kgraft_stub,
	.pre_patch = klp_kgraft_pre_patch,
	.post_patch = klp_kgraft_post_patch,
};

void klp_init_cmodel_kgraft(void)
{
	klp_kgraft_wq = create_singlethread_workqueue("kgraft");
	if (!klp_kgraft_wq) {
		pr_err("kGraft: cannot allocate a work queue, aborting!\n");
		return;
	}

	klp_register_cmodel(&kgraft_model);
}
