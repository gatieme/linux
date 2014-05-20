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

#include <linux/kernel.h>
#include <linux/kgraft.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

static struct kobject *kgr_sysfs_dir;

static ssize_t in_progress_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", kgr_in_progress);
}

static struct kobj_attribute kgr_attr_in_progress = __ATTR_RO(in_progress);

static struct attribute *kgr_sysfs_entries[] = {
	&kgr_attr_in_progress.attr,
	NULL
};

static struct attribute_group kgr_sysfs_group = {
	.attrs = kgr_sysfs_entries,
};

int kgr_add_files(void)
{
	int ret;

	kgr_sysfs_dir = kobject_create_and_add("kgraft", kernel_kobj);
	if (!kgr_sysfs_dir) {
		pr_err("kgr: cannot create kfraft directory in sysfs!\n");
		return -EIO;
	}

	ret = sysfs_create_group(kgr_sysfs_dir, &kgr_sysfs_group);
	if (ret) {
		pr_err("kgr: cannot create attributes in sysfs\n");
		goto err_put_sysfs;
	}

	return 0;
err_put_sysfs:
	kobject_put(kgr_sysfs_dir);
	return ret;
}

void kgr_remove_files(void)
{
	sysfs_remove_group(kgr_sysfs_dir, &kgr_sysfs_group);
	kobject_put(kgr_sysfs_dir);
}
