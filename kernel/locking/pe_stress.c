#define pr_fmt(fmt) "pe_stress: "fmt

#include <linux/completion.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <uapi/linux/sched/types.h>
#include <linux/mutex.h>
#include <linux/atomic.h>

static DEFINE_MUTEX(pe_mutex);
static struct completion owned = COMPLETION_INITIALIZER(owned);

static struct task_struct *owner_task;
static struct task_struct *blocker_task;
static struct task_struct *nop_task;

static atomic_t nb_waiting = ATOMIC_INIT(0);
static bool proxied;

static int owner_fn(void *data)
{
	mutex_lock(&pe_mutex);
	complete_all(&owned);

	/* Never release */
	for (;;) {
		if (proxied) {
			wake_up_process(nop_task);
			proxied = false;
		}

		cpu_relax();
	}

	return 0;
}

static int blocker_fn(void *data)
{
	atomic_inc(&nb_waiting);
	wait_for_completion(&owned);

	/* Not really true *now*, but will be when this is read by owner */
	proxied = true;

	/* (Try to) get the lock */
	mutex_lock(&pe_mutex);

	pr_err("blocker acquired lock!!!\n");

	return 0;
}

static int nop_fn(void *data)
{
	/* Should never get to run */
	pr_err("Failed priority inheritance, nop shouldn't run\n");
	BUG();

	return 0;
}

static int __init pe_stress_rt_bound_proxy(void)
{
	struct sched_param param = {
		.sched_priority = MAX_RT_PRIO / 2,
	};
	int bind_cpu = 1;

	owner_task = kthread_create(owner_fn, NULL, "pe_owner");
	if (IS_ERR(owner_task))
		return -1;

	blocker_task = kthread_create(blocker_fn, NULL, "pe_blocker");
	if (IS_ERR(blocker_task))
		return -1;

	nop_task = kthread_create(nop_fn, NULL, "pe_nop");
	if (IS_ERR(nop_task))
		return -1;

	/*
	 * All tasks on same CPU makes it much simpler
	 *
	 * As soon as the blocker task fails to acquire the mutex, we don't
	 * need to do any migration and can expect to switch to the owner
	 *
	 * This means once owner_task resumes (it would've been preempted by the
	 * RT blocker_task), we can expect that it executes with the right
	 * scheduling context, i.e. it will always preempt nop_task from then on.
	 */
	kthread_bind(owner_task, bind_cpu);
	kthread_bind(blocker_task, bind_cpu);
	kthread_bind(nop_task, bind_cpu);

	/* Make sure blocker has higher priority than owner */
	sched_setscheduler_nocheck(blocker_task, SCHED_FIFO, &param);

	/* Make nop_task RT but lower prio than blocker_task */
	param.sched_priority = 1;
	sched_setscheduler_nocheck(nop_task, SCHED_FIFO, &param);

	wake_up_process(blocker_task);
	while (!atomic_read(&nb_waiting))
		cpu_relax();

	/* Wait for the mutex acquisition to fail */
	wait_task_inactive(blocker_task, TASK_NORMAL);
	wake_up_process(owner_task);

	return 0;
}

static int __init pe_stress_init(void)
{
	int err;

	if (err = pe_stress_rt_bound_proxy())
		return err;

	return 0;
}

static void pe_stress_exit(void)
{
	kthread_stop(nop_task);
	kthread_stop(blocker_task);
	kthread_stop(owner_task);
}

module_init(pe_stress_init);
module_exit(pe_stress_exit);
