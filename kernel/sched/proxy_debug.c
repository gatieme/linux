#define pr_fmt(fmt) "pe_stress: "fmt

#include "sched.h"

#include <linux/completion.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <uapi/linux/sched/types.h>
#include <linux/mutex.h>
#include <linux/delay.h>

static DEFINE_MUTEX(spinner_mutex);

#define NR_SPINNERS 10

static struct task_struct *spinner_tasks[NR_SPINNERS];

static int lock_spinner(void *data)
{
	unsigned long prev_stats[NR_SPINNERS];
	unsigned long low_delta, high_delta, this_delta;
	int id = (int)data;
	int i;

	do {

		/*
		 * sum_exec_runtime is a decent alias to figure out which scheduling
		 * context was used.
		 */
		low_delta = 0;
		high_delta = 0;
		for (i = 0; i < NR_SPINNERS; i++)
			prev_stats[i] = READ_ONCE(spinner_tasks[i]->se.sum_exec_runtime);

		mutex_lock(&spinner_mutex);
		/*
		 * We got the lock.
		 * It might not have been contested => ?
		 * It might have:
		 *  higher prio should have gotten more runtime
		 *  lower prio should have gotten less runtime
		 * lower prio <= 10% what the higher prio got
		 * delta per task?
		 */

		mdelay(500);

		/* No interesting check for extrema priorities */
		if (!id || id == NR_SPINNERS - 1)
			goto unlock;

		/* XXX assumes all tasks blocked during most of above delay */
		for (i = 0; i < id; i++)
			low_delta += READ_ONCE(spinner_tasks[i]->se.sum_exec_runtime) -
				prev_stats[i];
		for (i = id+1; i < NR_SPINNERS; i++)
			high_delta += READ_ONCE(spinner_tasks[i]->se.sum_exec_runtime) -
				prev_stats[i];

		/* pr_info("spinner[%d]: low_delta=%lu high_delta=%lu\n", */
		/*	id, low_delta, high_delta); */

		WARN_ON((low_delta * 1100) / (id + 1) >
			(high_delta * 1000) / (NR_SPINNERS - (id + 1)));

		/* XXX: check task_current_proxy here? */
unlock:
		mutex_unlock(&spinner_mutex);

	} while (!kthread_should_stop());

	return 0;
}

static int __init proxy_debug_rt_bound_proxy(void)
{
	struct sched_param param = {};
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(spinner_tasks); i++) {
		spinner_tasks[i] = kthread_create(lock_spinner, (void *)i, "proxy_spn");

		if (IS_ERR(spinner_tasks[i]))
			goto err;
	}

	/* XXX create some with eq prio? */
	for (i = 0; i < ARRAY_SIZE(spinner_tasks); i++) {
		param.sched_priority = i + 1;
		sched_setscheduler_nocheck(spinner_tasks[i], SCHED_FIFO, &param);
	}

	/* wake */
	for (i = 0; i < ARRAY_SIZE(spinner_tasks); i++)
		wake_up_process(spinner_tasks[i]);


	/* assert RT throttling works */
	/* XXX RT throttling means 1 isn't guaranteed */
	/* Get RT throttling period? */
	/* global_rt_period() */
	/* global_rt_runtime() */

	return 0;
err:
	return -1;
}

static int __init pe_stress_init(void)
{
	int err = 0;

	err = proxy_debug_rt_bound_proxy();

	return err;
}

static void pe_stress_exit(void)
{
	/* XXX kill threads */
}

module_init(pe_stress_init);
module_exit(pe_stress_exit);
