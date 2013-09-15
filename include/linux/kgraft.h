/*
 * kGraft Online Kernel Patching
 *
 *  Copyright (c) 2013-2014 SUSE
 *   Authors: Jiri Kosina
 *	      Vojtech Pavlik
 *	      Jiri Slaby
 */

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef LINUX_KGR_H
#define LINUX_KGR_H

#include <linux/bitops.h>
#include <linux/ftrace.h>
#include <linux/sched.h>

#if IS_ENABLED(CONFIG_KGRAFT)

#include <asm/kgraft.h>

#define KGR_TIMEOUT 30

/**
 * struct kgr_patch_fun -- state of a single function in a kGraft patch
 *
 * @name: function to patch
 * @new_fun: function with the new body
 * @loc_old: cache of @name's fentry
 * @loc_new: cache of @new_name's fentry
 * @ftrace_ops_slow: ftrace ops for slow (temporary) stub
 * @ftrace_ops_fast: ftrace ops for fast () stub
 */
struct kgr_patch_fun {
	const char *name;
	void *new_fun;

	unsigned long loc_old;
	unsigned long loc_new;

	struct ftrace_ops ftrace_ops_slow;
	struct ftrace_ops ftrace_ops_fast;
};

/**
 * struct kgr_patch -- a kGraft patch
 *
 * @owner: module to refcount on patching
 * @patches: array of @kgr_patch_fun structures
 */
struct kgr_patch {
	/* a patch shall set these */
	struct module *owner;
	struct kgr_patch_fun patches[];
};

#define kgr_for_each_patch_fun(p, pf)	\
	for (pf = p->patches; pf->name; pf++)

#define KGR_PATCH(_name, _new_function)		{			\
		.name = #_name,						\
		.new_fun = _new_function,				\
	}
#define KGR_PATCH_END				{ }

extern int kgr_patch_kernel(struct kgr_patch *);

static inline void kgr_mark_task_in_progress(struct task_struct *p)
{
	/* This is replaced by thread_flag later. */
	set_bit(0, &task_thread_info(p)->kgr_in_progress);
}

static inline bool kgr_task_in_progress(struct task_struct *p)
{
	return test_bit(0, &task_thread_info(p)->kgr_in_progress);
}

#endif /* IS_ENABLED(CONFIG_KGRAFT) */

#endif /* LINUX_KGR_H */
