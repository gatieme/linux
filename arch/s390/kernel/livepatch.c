/*
 * livepatch.c - s390-specific Kernel Live Patching Core
 *
 * Copyright (C) 2014-2015 SUSE
 *
 * This file is licensed under the GPLv2.
 */

#include <linux/sched.h>

asmlinkage void s390_handle_kgraft(void)
{
	klp_kgraft_mark_task_safe(current);
}
