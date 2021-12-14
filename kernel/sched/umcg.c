// SPDX-License-Identifier: GPL-2.0-only

/*
 * User Managed Concurrency Groups (UMCG).
 *
 */

#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/umcg.h>
#include <linux/mm.h>

#include <asm/syscall.h>
#include <asm/ptrace.h>

#include "sched.h"

static struct task_struct *umcg_get_task(u32 tid)
{
	struct task_struct *tsk = NULL;

	if (tid) {
		rcu_read_lock();
		tsk = find_task_by_vpid(tid & UMCG_TID_MASK);
		if (tsk && current->mm == tsk->mm && tsk->umcg_task)
			get_task_struct(tsk);
		else
			tsk = NULL;
		rcu_read_unlock();
	}

	return tsk;
}

/*
 * Pinning a page inhibits rmap based unmap for Anon pages. Doing a load
 * through the user mapping ensures the user mapping exists.
 */
#define umcg_pin_and_load(_self, _pagep, _member)				\
({										\
	__label__ __out;							\
	int __ret = -EFAULT;							\
										\
	if (pin_user_pages_fast((unsigned long)(_self), 1, 0, &(_pagep)) != 1)	\
		goto __out;							\
										\
	if (!PageAnon(_pagep) ||						\
	    get_user(_member, &(_self)->_member)) {				\
		unpin_user_page(_pagep);					\
		goto __out;							\
	}									\
	__ret = 0;								\
__out:	__ret;									\
})

/**
 * umcg_pin_pages: pin pages containing struct umcg_task of
 *		   this task and its server (possibly this task again).
 */
static int umcg_pin_pages(void)
{
	struct task_struct *server = NULL, *tsk = current;
	struct umcg_task __user *self = READ_ONCE(tsk->umcg_task);
	int server_tid;
	int ret;

	/* must not have stale state */
	if (WARN_ON_ONCE(tsk->umcg_page ||
			 tsk->umcg_server_page ||
			 tsk->umcg_server_task ||
			 tsk->umcg_server))
		return -EBUSY;

	ret = umcg_pin_and_load(self, tsk->umcg_page, server_tid);
	if (ret)
		goto clear_self;

	ret = -ESRCH;
	server = umcg_get_task(server_tid);
	if (!server)
		goto unpin_self;

	/* must cache due to possible concurrent change */
	tsk->umcg_server_task = READ_ONCE(server->umcg_task);
	ret = umcg_pin_and_load(tsk->umcg_server_task, tsk->umcg_server_page, server_tid);
	if (ret)
		goto clear_server;

	tsk->umcg_server = server;

	return 0;

clear_server:
	tsk->umcg_server_task = NULL;
	tsk->umcg_server_page = NULL;

unpin_self:
	unpin_user_page(tsk->umcg_page);
clear_self:
	tsk->umcg_page = NULL;

	return ret;
}

static void umcg_unpin_pages(void)
{
	struct task_struct *tsk = current;

	if (tsk->umcg_server) {
		unpin_user_page(tsk->umcg_page);
		tsk->umcg_page = NULL;

		unpin_user_page(tsk->umcg_server_page);
		tsk->umcg_server_page = NULL;
		tsk->umcg_server_task = NULL;

		put_task_struct(tsk->umcg_server);
		tsk->umcg_server = NULL;
	}
}

static void umcg_clear_task(struct task_struct *tsk)
{
	/*
	 * This is either called for the current task, or for a newly forked
	 * task that is not yet running, so we don't need strict atomicity
	 * below.
	 */
	if (tsk->umcg_task) {
		WRITE_ONCE(tsk->umcg_task, NULL);
		tsk->umcg_page = NULL;

		tsk->umcg_server = NULL;
		tsk->umcg_server_page = NULL;
		tsk->umcg_server_task = NULL;

		tsk->flags &= ~PF_UMCG_WORKER;
		clear_task_syscall_work(tsk, SYSCALL_UMCG);
		clear_tsk_thread_flag(tsk, TIF_UMCG);
	}
}

/* Called for a forked or execve-ed child. */
void umcg_clear_child(struct task_struct *tsk)
{
	umcg_clear_task(tsk);
}

/* Called both by normally (unregister) and abnormally exiting workers. */
void umcg_worker_exit(void)
{
	umcg_unpin_pages();
	umcg_clear_task(current);
}

/*
 * Do a state transition: @from -> @to.
 *
 * Will clear UMCG_TF_PREEMPT, UMCG_TF_COND_WAIT.
 *
 * When @to == {BLOCKED,RUNNABLE}, update timestamps.
 *
 * Returns:
 *   0: success
 *   -EAGAIN: when self->state != @from
 *   -EFAULT
 */
static int umcg_update_state(struct task_struct *tsk,
			     struct umcg_task __user *self,
			     u32 from, u32 to)
{
	u32 old, new;
	u64 now;

	if (to >= UMCG_TASK_RUNNABLE) {
		switch (tsk->umcg_clock) {
		case CLOCK_REALTIME:      now = ktime_get_real_ns();     break;
		case CLOCK_MONOTONIC:     now = ktime_get_ns();          break;
		case CLOCK_BOOTTIME:      now = ktime_get_boottime_ns(); break;
		case CLOCK_TAI:           now = ktime_get_clocktai_ns(); break;
		}
	}

	if (!user_access_begin(self, sizeof(*self)))
		return -EFAULT;

	unsafe_get_user(old, &self->state, Efault);
	do {
		if ((old & UMCG_TASK_MASK) != from)
			goto fail;

		new = old & ~(UMCG_TASK_MASK |
			      UMCG_TF_PREEMPT | UMCG_TF_COND_WAIT);
		new |= to & UMCG_TASK_MASK;

	} while (!unsafe_try_cmpxchg_user(&self->state, &old, new, Efault));

	if (to == UMCG_TASK_BLOCKED)
		unsafe_put_user(now, &self->blocked_ts, Efault);
	if (to == UMCG_TASK_RUNNABLE)
		unsafe_put_user(now, &self->runnable_ts, Efault);

	user_access_end();
	return 0;

fail:
	user_access_end();
	return -EAGAIN;

Efault:
	user_access_end();
	return -EFAULT;
}

#define __UMCG_DIE(stmt, reason)	do {				\
	stmt;								\
	pr_warn_ratelimited("%s: killing task %s/%d because: " reason "\n",\
			    __func__, current->comm, current->pid);	\
	force_sig(SIGKILL);						\
	return;								\
} while (0)

#define UMCG_DIE(reason)	__UMCG_DIE(,reason)
#define UMCG_DIE_PF(reason)	__UMCG_DIE(pagefault_enable(), reason)
#define UMCG_DIE_UNPIN(reason)	__UMCG_DIE(umcg_unpin_pages(), reason)

/* Called from syscall enter path and exceptions that can schedule */
void umcg_sys_enter(struct pt_regs *regs, long syscall)
{
	/* avoid recursion vs our own syscalls */
	if (syscall == __NR_umcg_wait ||
	    syscall == __NR_umcg_ctl)
		return;

	/* avoid recursion vs schedule() */
	current->flags &= ~PF_UMCG_WORKER;

	/*
	 * Pin all the state on sys_enter() such that we can rely on it
	 * from dodgy contexts. It is either unpinned from pre-schedule()
	 * or sys_exit(), whichever comes first, thereby ensuring the pin
	 * is temporary.
	 */
	if (umcg_pin_pages())
		UMCG_DIE("pin");

	current->flags |= PF_UMCG_WORKER;
}

static int umcg_wake_task(struct task_struct *tsk, struct umcg_task __user *self)
{
	int ret = umcg_update_state(tsk, self, UMCG_TASK_RUNNABLE, UMCG_TASK_RUNNING);
	if (ret)
		return ret;

	try_to_wake_up(tsk, TASK_NORMAL, WF_CURRENT_CPU);
	return 0;
}

static int umcg_wake_server(struct task_struct *tsk)
{
	int ret = umcg_wake_task(tsk->umcg_server, tsk->umcg_server_task);
	if (ret == -EAGAIN) {
		/*
		 * Server could have timed-out or already be running
		 * due to a runnable enqueue. See umcg_sys_exit().
		 */
		ret = 0;
	}
	return ret;
}

/* pre-schedule() */
void umcg_wq_worker_sleeping(struct task_struct *tsk)
{
	struct umcg_task __user *self = READ_ONCE(tsk->umcg_task);
	int ret;

	if (!tsk->umcg_server) {
		/*
		 * Already blocked before, the pages are unpinned.
		 */
		return;
	}

	/* Must not fault, mmap_sem might be held. */
	pagefault_disable();

	ret = umcg_update_state(tsk, self, UMCG_TASK_RUNNING, UMCG_TASK_BLOCKED);
	if (ret == -EAGAIN) {
		/*
		 * Consider:
		 *
		 *   self->state = UMCG_TASK_RUNNABLE | UMCG_TF_COND_WAIT;
		 *   ...
		 *   sys_umcg_wait();
		 *
		 * and the '...' code doing a blocking syscall/fault. This
		 * ensures that returns with UMCG_TASK_RUNNING, which will make
		 * sys_umcg_wait() return with -EAGAIN.
		 */
		ret = umcg_update_state(tsk, self, UMCG_TASK_RUNNABLE, UMCG_TASK_BLOCKED);
	}
	if (ret)
		UMCG_DIE_PF("state");

	if (umcg_wake_server(tsk))
		UMCG_DIE_PF("wake");

	pagefault_enable();

	/*
	 * We're going to sleep, make sure to unpin the pages, this ensures
	 * the pins are temporary. Also see umcg_sys_exit().
	 */
	umcg_unpin_pages();
}

/* post-schedule() */
void umcg_wq_worker_running(struct task_struct *tsk)
{
	/* nothing here, see umcg_sys_exit() */
}

/*
 * Enqueue @tsk on it's server's runnable list
 *
 * Must be called in umcg_pin_pages() context, relies on tsk->umcg_server.
 *
 * cmpxchg based single linked list add such that list integrity is never
 * violated.  Userspace *MUST* remove it from the list before changing ->state.
 * As such, we must change state to RUNNABLE before enqueue.
 *
 * Returns:
 *   0: success
 *   -EFAULT
 */
static int umcg_enqueue_runnable(struct task_struct *tsk)
{
	struct umcg_task __user *server = tsk->umcg_server_task;
	struct umcg_task __user *self = tsk->umcg_task;
	u64 first_ptr, *head = &server->runnable_workers_ptr;
	u64 self_ptr = (unsigned long)self;

	/*
	 * umcg_pin_pages() did access_ok() on both pointers, use self here
	 * only because __user_access_begin() isn't available in generic code.
	 */
	if (!user_access_begin(self, sizeof(*self)))
		return -EFAULT;

	unsafe_get_user(first_ptr, head, Efault);
	do {
		unsafe_put_user(first_ptr, &self->runnable_workers_ptr, Efault);
	} while (!unsafe_try_cmpxchg_user(head, &first_ptr, self_ptr, Efault));

	user_access_end();
	return 0;

Efault:
	user_access_end();
	return -EFAULT;
}

static int umcg_enqueue_and_wake(struct task_struct *tsk)
{
	int ret;

	ret = umcg_enqueue_runnable(tsk);
	if (!ret)
		ret = umcg_wake_server(tsk);

	return ret;
}

/*
 * umcg_wait: Wait for ->state to become RUNNING
 *
 * Returns:
 * 0		- success
 * -EINTR	- pending signal
 * -EINVAL	- ::state is not {RUNNABLE,RUNNING}
 * -ETIMEDOUT
 * -EFAULT
 */
static int umcg_wait(u64 timo)
{
	struct task_struct *tsk = current;
	struct umcg_task __user *self = tsk->umcg_task;
	struct page *page = NULL;
	u32 state;
	int ret;

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);

		ret = -EINTR;
		if (signal_pending(current))
			break;

		/*
		 * Faults can block and scribble our wait state.
		 */
		pagefault_disable();
		if (get_user(state, &self->state)) {
			pagefault_enable();
			__set_current_state(TASK_RUNNING);

			ret = -EFAULT;
			if (page) {
				unpin_user_page(page);
				page = NULL;
				break;
			}

			ret = umcg_pin_and_load(self, page, state);
			if (ret) {
				page = NULL;
				break;
			}

			continue;
		}

		if (page) {
			unpin_user_page(page);
			page = NULL;
		}
		pagefault_enable();

		state &= UMCG_TASK_MASK;
		if (state != UMCG_TASK_RUNNABLE) {
			ret = 0;
			if (state == UMCG_TASK_RUNNING)
				break;

			ret = -EINVAL;
			break;
		}

		if (!schedule_hrtimeout_range_clock(timo ? &timo : NULL,
						    tsk->timer_slack_ns,
						    HRTIMER_MODE_ABS,
						    tsk->umcg_clock)) {
			ret = -ETIMEDOUT;
			break;
		}
	}
	__set_current_state(TASK_RUNNING);

	return ret;
}

/*
 * Blocked case for umcg_sys_exit(), shared with sys_umcg_ctl().
 */
static void umcg_unblock_and_wait(void)
{
	struct task_struct *tsk = current;
	struct umcg_task __user *self = READ_ONCE(tsk->umcg_task);

	/* avoid recursion vs schedule() */
	tsk->flags &= ~PF_UMCG_WORKER;

	if (umcg_pin_pages())
		UMCG_DIE("pin");

	if (umcg_update_state(tsk, self, UMCG_TASK_BLOCKED, UMCG_TASK_RUNNABLE))
		UMCG_DIE_UNPIN("state");

	if (umcg_enqueue_and_wake(tsk))
		UMCG_DIE_UNPIN("enqueue-wake");

	umcg_unpin_pages();

	switch (umcg_wait(0)) {
	case 0:
	case -EINTR:
		/* notify_resume will continue the wait after the signal */
		break;

	default:
		UMCG_DIE("wait");
	}

	tsk->flags |= PF_UMCG_WORKER;
}

/* Called from syscall exit path and exceptions that can schedule */
void umcg_sys_exit(struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	long syscall = syscall_get_nr(tsk, regs);

	if (syscall == __NR_umcg_wait ||
	    syscall == __NR_umcg_ctl)
		return;

	if (tsk->umcg_server) {
		/*
		 * Didn't block, we done.
		 */
		umcg_unpin_pages();
		return;
	}

	umcg_unblock_and_wait();
}

/* return-to-user path */
void umcg_notify_resume(struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	struct umcg_task __user *self = tsk->umcg_task;
	bool worker = tsk->flags & PF_UMCG_WORKER;
	u32 state;

	/* avoid recursion vs schedule() */
	if (worker)
		current->flags &= ~PF_UMCG_WORKER;

	if (get_user(state, &self->state))
		UMCG_DIE("get-state");

	state &= UMCG_TASK_MASK | UMCG_TF_MASK;
	if (state == UMCG_TASK_RUNNING)
		goto done;

	/*
	 * See comment at UMCG_TF_COND_WAIT; TL;DR: user *will* call
	 * sys_umcg_wait() and signals/interrupts shouldn't block
	 * return-to-user.
	 */
	if (state == (UMCG_TASK_RUNNABLE | UMCG_TF_COND_WAIT))
		goto done;

	if (state & UMCG_TF_PREEMPT) {
		if (umcg_pin_pages())
			UMCG_DIE("pin");

		if (umcg_update_state(tsk, self,
				      UMCG_TASK_RUNNING,
				      UMCG_TASK_RUNNABLE))
			UMCG_DIE_UNPIN("state");

		if (umcg_enqueue_and_wake(tsk))
			UMCG_DIE_UNPIN("enqueue-wake");

		umcg_unpin_pages();
	}

	switch (umcg_wait(0)) {
	case 0:
	case -EINTR:
		/* we will resume the wait after the signal */
		break;

	default:
		UMCG_DIE("wait");
	}

done:
	if (worker)
		current->flags |= PF_UMCG_WORKER;
}

/**
 * sys_umcg_kick: makes a UMCG task cycle through umcg_notify_resume()
 *
 * Returns:
 * 0		- Ok;
 * -ESRCH	- not a related UMCG task
 * -EINVAL	- another error happened (unknown flags, etc..)
 */
SYSCALL_DEFINE2(umcg_kick, u32, flags, pid_t, tid)
{
	struct task_struct *task = umcg_get_task(tid);
	if (!task)
		return -ESRCH;

	if (flags)
		return -EINVAL;

#ifdef CONFIG_SMP
	smp_send_reschedule(task_cpu(task));
#endif

	return 0;
}

/*
 * Handles ::next_tid as per sys_umcg_wait().
 *
 * ::next_tid		- return
 * -----------------------------
 * 0			- 0 (success)
 *
 * tid			- -ESRCH (no such task, or not of this UMCG)
 *			- -EAGAIN (next::state != RUNNABLE)
 *			- 0 (success, ::next_tid |= RUNNING)
 *
 * tid|RUNNING		- -EAGAIN (next::state != RUNNING)
 *			- 0 (success)
 *
 * Returns:
 *  0: success
 *  -EFAULT
 *  -ESRCH
 *  -EAGAIN
 */
static int umcg_wake_next(struct task_struct *tsk, struct umcg_task __user *self)
{
	struct umcg_task __user *next_task;
	struct task_struct *next;
	u32 next_tid, state;
	int ret;

	if (get_user(next_tid, &self->next_tid))
		return -EFAULT;

	if (!next_tid)
		return 0;

	next = umcg_get_task(next_tid);
	if (!next)
		return -ESRCH;

	next_task = READ_ONCE(next->umcg_task);

	if (next_tid & UMCG_TID_RUNNING) {
		ret = -EFAULT;
		if (get_user(state, &next_task->state))
			goto put_next;

		ret = 0;
		if ((state & UMCG_TASK_MASK) != UMCG_TASK_RUNNING)
			ret = -EAGAIN;

	} else {
		ret = umcg_wake_task(next, next_task);
		if (ret)
			goto put_next;

		ret = -EFAULT;
		if (put_user(next_tid | UMCG_TID_RUNNING, &self->next_tid))
			goto put_next;

		/*
		 * If this is a worker doing sys_umcg_wait() switching to
		 * another worker, userspace has the responsibility to update
		 * server::next_tid.
		 */

		ret = 0;
	}

put_next:
	put_task_struct(next);
	return ret;
}

/**
 * sys_umcg_wait: transfer running context
 *
 * Called like:
 *
 *	self->state = UMCG_TASK_RUNNABLE | UMCG_TF_COND_WAIT;
 *	...
 *	sys_umcg_wait(0, time);
 *
 * The syscall will clear TF_COND_WAIT and wait until state becomes RUNNING.
 * The code '...' must not contain syscalls
 *
 * If self->next_tid is set and indicates a valid UMCG task with RUNNABLE state
 * that task will be made RUNNING and woken -- transfering the running context
 * to that task. In this case self->next_tid is modified with TID_RUNNING to
 * indicate self->next_tid is consumed.
 *
 * If self->next has TID_RUNNING set, it is validated the related task has
 * RUNNING state, otherwise -EAGAIN is returned to indicate a new task needs to
 * be selected.
 *
 * If the caller is a worker:
 *
 *  - it will be enqueued on the associated server's runnable_workers_ptr list
 *    and the server will be woken.
 *
 *  - when ::next_tid is used to affect a worker-to-worker transfer, it is up
 *    to userspace to keep server::next_tid consistent.
 *
 * The corrolary is that a server setting ::next_tid to 0 will idle.
 *
 * Returns:
 * 0		- OK;
 * -ETIMEDOUT	- the timeout expired;
 * -ERANGE	- the timeout is out of range (worker);
 * -EAGAIN	- ::state wasn't RUNNABLE, concurrent wakeup;
 * -EFAULT	- failed accessing struct umcg_task __user of the current
 *		  task, the server or next;
 * -ESRCH	- the task to wake not found or not a UMCG task;
 * -EINVAL	- another error happened (e.g. the current task is not a
 *		  UMCG task, etc.)
 */
SYSCALL_DEFINE2(umcg_wait, u32, flags, u64, timo)
{
	struct task_struct *tsk = current;
	struct umcg_task __user *self = READ_ONCE(tsk->umcg_task);
	bool worker = tsk->flags & PF_UMCG_WORKER;
	int ret;

	if (!self || flags)
		return -EINVAL;

	if (worker) {
		tsk->flags &= ~PF_UMCG_WORKER;
		if (timo)
			return -ERANGE;
	}

	/* see umcg_sys_{enter,exit}() syscall exceptions */
	ret = umcg_pin_pages();
	if (ret)
		goto unblock;

	/*
	 * Clear UMCG_TF_COND_WAIT *and* check state == RUNNABLE.
	 */
	ret = umcg_update_state(tsk, self, UMCG_TASK_RUNNABLE, UMCG_TASK_RUNNABLE);
	if (ret)
		goto unpin;

	ret = umcg_wake_next(tsk, self);
	if (ret)
		goto unpin;

	if (worker) {
		/*
		 * If this fails it is possible ::next_tid is already running
		 * while this task is not going to block. This violates our
		 * constraints.
		 *
		 * That said, pretty much the only way to make this fail is by
		 * force munmap()'ing things. In which case one is most welcome
		 * to the pieces.
		 */
		ret = umcg_enqueue_and_wake(tsk);
		if (ret)
			goto unpin;
	}

	umcg_unpin_pages();

	ret = umcg_wait(timo);
	switch (ret) {
	case 0:		/* all done */
	case -EINTR:	/* umcg_notify_resume() will continue the wait */
		ret = 0;
		break;

	default:
		goto unblock;
	}
out:
	if (worker)
		tsk->flags |= PF_UMCG_WORKER;
	return ret;

unpin:
	umcg_unpin_pages();
unblock:
	umcg_update_state(tsk, self, UMCG_TASK_RUNNABLE, UMCG_TASK_RUNNING);
	goto out;
}

static int umcg_register(struct umcg_task __user *self, u32 flags, clockid_t which_clock)
{
	struct task_struct *server;
	struct umcg_task ut;

	switch (which_clock) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
	case CLOCK_BOOTTIME:
	case CLOCK_TAI:
		current->umcg_clock = which_clock;
		break;

	default:
		return -EINVAL;
	}

	if (current->umcg_task || !self)
		return -EINVAL;

	if (copy_from_user(&ut, self, sizeof(ut)))
		return -EFAULT;

	if (ut.next_tid || ut.__hole[0] || ut.__zero[0] || ut.__zero[1] || ut.__zero[2])
		return -EINVAL;

	rcu_read_lock();
	server = find_task_by_vpid(ut.server_tid);
	if (server && server->mm == current->mm) {
		if (flags == UMCG_CTL_WORKER) {
			if (!server->umcg_task ||
			    (server->flags & PF_UMCG_WORKER))
				server = NULL;
		} else {
			if (server != current)
				server = NULL;
		}
	} else {
		server = NULL;
	}
	rcu_read_unlock();

	if (!server)
		return -ESRCH;

	if (flags == UMCG_CTL_WORKER) {
		if ((ut.state & (UMCG_TASK_MASK | UMCG_TF_MASK)) != UMCG_TASK_BLOCKED)
			return -EINVAL;

		WRITE_ONCE(current->umcg_task, self);
		current->flags |= PF_UMCG_WORKER;	/* hook schedule() */
		set_syscall_work(SYSCALL_UMCG);		/* hook syscall */
		set_thread_flag(TIF_UMCG);		/* hook return-to-user */

		umcg_unblock_and_wait();

	} else {
		if ((ut.state & (UMCG_TASK_MASK | UMCG_TF_MASK)) != UMCG_TASK_RUNNING)
			return -EINVAL;

		WRITE_ONCE(current->umcg_task, self);
		set_thread_flag(TIF_UMCG);		/* hook return-to-user */

		/* umcg_notify_resume() would block if not RUNNING */
	}

	return 0;
}

static int umcg_unregister(struct umcg_task __user *self, u32 flags)
{
	bool worker = current->flags & PF_UMCG_WORKER;
	int ret;

	if (!self || self != current->umcg_task)
		return -EINVAL;

	if (!worker != !(flags & UMCG_CTL_WORKER))
		return -EINVAL;

	current->flags &= ~PF_UMCG_WORKER;

	ret = umcg_pin_pages();
	if (ret) {
		if (worker)
			current->flags |= PF_UMCG_WORKER;
		return ret;
	}

	ret = umcg_update_state(current, self, UMCG_TASK_RUNNING, UMCG_TASK_NONE);
	if (ret) {
		if (worker)
			current->flags |= PF_UMCG_WORKER;
		return ret;
	}

	if (worker)
		umcg_wake_server(current);

	umcg_unpin_pages();
	umcg_clear_task(current);
	return 0;
}

#define UMCG_CTL_CMD	0xff

/**
 * sys_umcg_ctl: (un)register the current task as a UMCG task.
 * @flags:       ORed values from enum umcg_ctl_flag; see below;
 * @self:        a pointer to struct umcg_task that describes this
 *               task and governs the behavior of sys_umcg_wait.
 * @which_clock: clockid to use for timestamps and timeouts
 *
 * @flags & UMCG_CTL_REGISTER: register a UMCG task:
 *
 *	UMCG workers:
 *	 - @flags & UMCG_CTL_WORKER
 *	 - self->state must be UMCG_TASK_BLOCKED
 *
 *	UMCG servers:
 *	 - !(@flags & UMCG_CTL_WORKER)
 *	 - self->state must be UMCG_TASK_RUNNING
 *
 *	All tasks:
 *	 - self->server_tid must be a valid server
 *	 - self->next_tid must be zero
 *
 *	If the conditions above are met, sys_umcg_ctl() immediately returns
 *	if the registered task is a server. If the registered task is a
 *	worker it will be added to it's server's runnable_workers_ptr list
 *	and the server will be woken.
 *
 * @flags & UMCG_CTL_UNREGISTER: unregister a UMCG task.
 *
 *	UMCG workers:
 *	 - @flags & UMCG_CTL_WORKER
 *
 *	UMCG servers:
 *	 - !(@flags & UMCG_CTL_WORKER)
 *
 *	All tasks:
 *	 - self must match with UMCG_CTL_REGISTER
 *	 - self->state must be UMCG_TASK_RUNNING
 *	 - self->server_tid must be a valid server
 *
 *	If the conditions above are met, sys_umcg_ctl() will change state to
 *	UMCG_TASK_NONE, and for workers, wake either next or server.
 *
 * Return:
 * 0		- success
 * -EFAULT	- failed to read @self
 * -EINVAL	- some other error occurred
 * -ESRCH	- no such server_tid
 */
SYSCALL_DEFINE3(umcg_ctl, u32, flags, struct umcg_task __user *, self, clockid_t, which_clock)
{
	int cmd = flags & UMCG_CTL_CMD;

	if ((unsigned long)self % UMCG_TASK_ALIGN)
		return -EINVAL;

	flags &= ~UMCG_CTL_CMD;

	if (flags & ~(UMCG_CTL_WORKER))
		return -EINVAL;

	switch (cmd) {
	case UMCG_CTL_REGISTER:
		return umcg_register(self, flags, which_clock);

	case UMCG_CTL_UNREGISTER:
		return umcg_unregister(self, flags);

	default:
		break;
	}

	return -EINVAL;
}
