// SPDX-License-Identifier: GPL-2.0
/*
 * DEVIRT: Support de-virtualization to run kata BM
 *
 * Copyright (C) 2021-2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Authors:
 *   Liang Deng   <dengliang.1214@bytedance.com>
 *   Hangjing Li  <lihangjing@bytedance.com>
 *
 */
#include <linux/kvm_host.h>
#include <asm/devirt.h>
#include <asm/apic.h>

static DEFINE_PER_CPU(u32, devirt_cpu_set);

static void devirt_set_host_timer(void)
{
	unsigned long flags;

	local_irq_save(flags);
	tick_broadcast_enable_devirt();
	while (tick_broadcast_enter_devirt()) {
		/* If tick_broadcast_enter_devirt returns -EBUSY, we
		 * should wait until another non devirt cpu owns the
		 * hrtimer broadcast mechanism
		 */
		local_irq_restore(flags);
		local_irq_save(flags);
	}
	local_irq_restore(flags);
}

static void devirt_unset_host_timer(void)
{
	unsigned long flags;

	local_irq_save(flags);
	tick_broadcast_exit_devirt();
	tick_broadcast_disable_devirt();
	local_irq_restore(flags);
}

static void devirt_unset_devirt_cpu(void *arg)
{
	u32 *set;
	unsigned long flags;

	/* Disable irq to ensure the operation to devirt_cpu_set and
	 * devirt_unset_host_timer must be atomic.
	 */
	local_irq_save(flags);
	set = this_cpu_ptr(&devirt_cpu_set);
	if (*set) {
		devirt_unset_host_timer();
		*set = 0;
	}
	local_irq_restore(flags);
}

void devirt_unset_devirt_cpu_on(int cpu, struct devirt_cpu_unset_info *info)
{
	smp_call_function_single(cpu, devirt_unset_devirt_cpu, info, 1);
}

static void devirt_check_devirt_cpu_set(struct kvm_vcpu *vcpu)
{
	u32 *set = this_cpu_ptr(&devirt_cpu_set);
	u32 set_val = *set;
	u32 new_val = DEVIRT_CPU_SET(vcpu->kvm->userspace_pid, vcpu->vcpu_id);

	/* If a new vcpu thread is migrated to a core, the core's devirt_cpu_set
	 * must be zero.
	 */
	if (!set_val) {
		/* Set the host timer on devirt cpu */
		devirt_set_host_timer();
		*set = new_val;
	} else
		WARN_ON(set_val != new_val);
}

static void devirt_check_devirt_cpu_unset(struct kvm_vcpu *vcpu)
{
	int old_cpu = vcpu_to_devirt(vcpu)->devirt_cpu;
	int cpu = smp_processor_id();
	struct devirt_cpu_unset_info *info;

	if (old_cpu != -1 && old_cpu != cpu) {
		/* unset last cpu's devirt state, when the vcpu is migrated to a new cpu. */
		info->new_cpu = cpu;
		devirt_unset_devirt_cpu_on(old_cpu, info);
	}
}

static void devirt_check_devirt_cpu(struct kvm_vcpu *vcpu)
{
	devirt_check_devirt_cpu_set(vcpu);
	devirt_check_devirt_cpu_unset(vcpu);
	vcpu_to_devirt(vcpu)->devirt_cpu = smp_processor_id();
}

void devirt_enter_guest_irqoff(struct kvm_vcpu *vcpu)
{
	/* irq is disabled, so that it will not be interrupted when other core calls
	 * devirt_unset_devirt_cpu_on
	 */
	devirt_check_devirt_cpu(vcpu);
}

void devirt_exit_guest_irqoff(struct kvm_vcpu *vcpu)
{
}

void devirt_enter_guest(struct kvm_vcpu *vcpu)
{
}

void devirt_vcpu_create(struct kvm_vcpu *vcpu)
{
}

void devirt_vcpu_free(struct kvm_vcpu *vcpu)
{
}

void devirt_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct devirt_vcpu_arch *devirt = vcpu_to_devirt(vcpu);

	devirt->devirt_cpu = -1;
}

void devirt_init_vm(struct kvm *kvm)
{
}

void devirt_destroy_vm(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned int i;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		devirt_unset_devirt_cpu_on(vcpu_to_devirt(vcpu)->devirt_cpu, NULL);
	}
}

void devirt_init(void)
{
}

struct devirt_kvm_operations *devirt_kvm_ops;
EXPORT_SYMBOL(devirt_kvm_ops);
