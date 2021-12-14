/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_UMCG_H
#define _UAPI_LINUX_UMCG_H

#include <linux/types.h>

/*
 * UMCG: User Managed Concurrency Groups.
 *
 * Syscalls (see kernel/sched/umcg.c):
 *      sys_umcg_ctl()  - register/unregister UMCG tasks;
 *      sys_umcg_wait() - wait/wake/context-switch.
 *      sys_umcg_kick() - prod a UMCG task
 *
 * struct umcg_task (below): controls the state of UMCG tasks.
 */

/*
 * UMCG task states, the first 8 bits of struct umcg_task.state.
 *
 *   ,--------(TF_PREEMPT + notify_resume)-------.   ,----------.
 *   |                                           v   |          |
 * RUNNING -(schedule)-> BLOCKED -(sys_exit)-> RUNNABLE  (signal + notify_resume)
 *   ^                      ^                    | | ^          |
 *   |                      `-----(schedule)-----' | |          |
 *   `--------------(sys_umcg_wait)----------------' `----------'
 *
 */
#define UMCG_TASK_NONE			0x0000U
#define UMCG_TASK_RUNNING		0x0001U
#define UMCG_TASK_RUNNABLE		0x0002U
#define UMCG_TASK_BLOCKED		0x0003U

#define UMCG_TASK_MASK			0x00ffU

/*
 * UMCG_TF_PREEMPT: userspace indicates the worker should be preempted.
 *
 * Must only be set on UMCG_TASK_RUNNING; once set, any subsequent
 * return-to-user (eg sys_umcg_kick()) will perform the equivalent of
 * sys_umcg_wait() on it. That is, it will wake next_tid/server_tid, transfer
 * to RUNNABLE and enqueue on the server's runnable list.
 */
#define UMCG_TF_PREEMPT			0x0100U
/*
 * UMCG_TF_COND_WAIT: indicate the task *will* call sys_umcg_wait()
 *
 * Enables server loops like (vs umcg_sys_exit()):
 *
 *   for(;;) {
 *	self->state = UMCG_TASK_RUNNABLE | UMCG_TF_COND_WAIT;
 *
 *	// smp_mb() implied by xchg()
 *	runnable_ptr = (void *)xchg(self->runnable_workers_ptr, NULL);
 *	while (runnable_ptr) {
 *		next = (void *)runnable_ptr->runnable_workers_ptr;
 *		umcg_server_add_runnable(self, runnable_ptr);
 *		runnable_ptr = next;
 *	}
 *
 *	self->next_tid = umcg_server_pick_next(self);
 *	sys_umcg_wait(0, 0);
 *   }
 *
 * without a signal or interrupt in between setting umcg_task::state and
 * sys_umcg_wait() resulting in an infinite wait in umcg_notify_resume().
 */
#define UMCG_TF_COND_WAIT		0x0200U

#define UMCG_TF_MASK			0xff00U

#define UMCG_TASK_ALIGN			64

/**
 * struct umcg_task - controls the state of UMCG tasks.
 *
 * The struct is aligned at 64 bytes to ensure that it fits into
 * a single cache line.
 */
struct umcg_task {
	/**
	 * @state: the current state of the UMCG task described by
	 *         this struct.
	 *
	 * Readable/writable by both the kernel and the userspace.
	 *
	 * UMCG task state:
	 *   bits  0 -  7: task state;
	 *   bits  8 - 15: state flags;
	 *   bits 16 - 31: for userspace use;
	 */
	__u32	state;				/* r/w */

#define UMCG_TID_RUNNING	0x80000000U
#define UMCG_TID_MASK		0x3fffffffU
	/**
	 * @next_tid: the TID of the UMCG task that should be context-switched
	 *            into in sys_umcg_wait(). Can be zero.
	 *
	 * @server_tid: the TID of the UMCG server that hosts this task,
	 *		when RUNNABLE this task will get added to it's
	 *		runnable_workers_ptr list.
	 *
	 * Read-only for the kernel, read/write for the userspace.
	 */
	__u32	next_tid;			/* r   */
	__u32	server_tid;			/* r   */

	__u32	__hole[1];

	/*
	 * Timestamps for when last we became BLOCKED, RUNNABLE.
	 */
	__u64	blocked_ts;			/*   w */
	__u64   runnable_ts;			/*   w */

	/**
	 * @runnable_workers_ptr: a single-linked list of runnable workers.
	 *
	 * Readable/writable by both the kernel and the userspace: the
	 * kernel adds items to the list, userspace removes them.
	 */
	__u64	runnable_workers_ptr;		/* r/w */

	__u64	__zero[3];

} __attribute__((packed, aligned(UMCG_TASK_ALIGN)));

/**
 * enum umcg_ctl_flag - flags to pass to sys_umcg_ctl
 * @UMCG_CTL_REGISTER:   register the current task as a UMCG task
 * @UMCG_CTL_UNREGISTER: unregister the current task as a UMCG task
 * @UMCG_CTL_WORKER:     register the current task as a UMCG worker
 */
enum umcg_ctl_flag {
	UMCG_CTL_REGISTER	= 0x00001,
	UMCG_CTL_UNREGISTER	= 0x00002,
	UMCG_CTL_WORKER		= 0x10000,
};

#endif /* _UAPI_LINUX_UMCG_H */
