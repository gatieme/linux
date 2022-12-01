/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A minimal dummy scheduler.
 *
 * In terms of scheduling, this behaves the same as not specifying any ops at
 * all - a global FIFO. The only things it adds are the following niceties:
 *
 * - Statistics tracking how many are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include "scx_common.bpf.h"

char _license[] SEC("license") = "GPL";

struct user_exit_info uei;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

void BPF_STRUCT_OPS(dummy_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (enq_flags & SCX_ENQ_LOCAL) {
		stat_inc(0);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
	} else {
		stat_inc(1);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	}
}

void BPF_STRUCT_OPS(dummy_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops")
struct sched_ext_ops dummy_ops = {
	.enqueue		= (void *)dummy_enqueue,
	.exit			= (void *)dummy_exit,
	.name			= "dummy",
};
