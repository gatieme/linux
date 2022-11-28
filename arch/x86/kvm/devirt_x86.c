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

static void devirt_copy_guest_irq_map(int dst, int src)
{
	int i = 0;
	unsigned long *src_bitmap, *dst_bitmap;

	src_bitmap = per_cpu_ptr(&devirt_guest_irq_pending, src)->pending_map;
	dst_bitmap = per_cpu_ptr(&devirt_guest_irq_pending, dst)->pending_map;

	for_each_set_bit(i, src_bitmap, 256) {
		set_bit(i, dst_bitmap);
		clear_bit(i, src_bitmap);
	}
}

static void devirt_clear_guest_irq_map(int cpu)
{
	int i = 0;
	unsigned long *bitmap;

	bitmap = per_cpu_ptr(&devirt_guest_irq_pending, cpu)->pending_map;

	for_each_set_bit(i, bitmap, 256) {
		clear_bit(i, bitmap);
	}
}

static void devirt_unset_devirt_cpu(void *arg)
{
	u32 *set;
	unsigned long flags;
	struct devirt_cpu_unset_info *info = (struct devirt_cpu_unset_info *)arg;
	int new_cpu = -1;

	if (info)
		new_cpu = info->new_cpu;

	/* Disable irq to ensure the operation to devirt_cpu_set and
	 * devirt_unset_host_timer must be atomic.
	 */
	local_irq_save(flags);
	set = this_cpu_ptr(&devirt_cpu_set);
	if (*set) {
		devirt_unset_host_timer();
		/* If the vcpu on current cpu is migrated to a new cpu */
		if (new_cpu >= 0)
			/* migrate last cpu's guest irq pending bitmap */
			devirt_copy_guest_irq_map(new_cpu, smp_processor_id());
		/* If the vcpu on current cpu is destroyed */
		if (new_cpu == -1) {
			/* clear cpu's guest irq pending bitmap */
			devirt_clear_guest_irq_map(smp_processor_id());
		}
		*set = 0;
	}
	local_irq_restore(flags);
}

void devirt_unset_devirt_cpu_on(int cpu, struct devirt_cpu_unset_info *info)
{
	smp_call_function_single(cpu, devirt_unset_devirt_cpu, info, 1);
}

static void devirt_set_guest_irq(void)
{
	unsigned long *bitmap;
	int i = 0;

	bitmap = this_cpu_ptr(&devirt_guest_irq_pending)->pending_map;
	for_each_set_bit(i, bitmap, 256) {
		apic->send_IPI_self(i);
		clear_bit(i, bitmap);
	}
}

static int APIC_ISR_is_set(void)
{
	int i;

	for (i = 0; i < 8; i++) {
		if (apic_read(APIC_ISR + i * 0x10))
			return 1;
	}

	return 0;
}

static void devirt_check_eoi(void)
{
	if (APIC_ISR_is_set())
		apic_eoi();
}

DEFINE_PER_CPU(struct devirt_guest_irq_pending, devirt_guest_irq_pending) = {0};

bool devirt_has_guest_interrupt(struct kvm_vcpu *vcpu)
{
	struct devirt_guest_irq_pending *pending;

	pending = this_cpu_ptr(&devirt_guest_irq_pending);

	if (!bitmap_empty(pending->pending_map, 256))
		return true;

	return false;
}

static DEFINE_PER_CPU(struct list_head, devirt_blocked_vcpu_on_cpu);
static DEFINE_PER_CPU(spinlock_t, devirt_blocked_vcpu_on_cpu_lock);

static void devirt_guest_interrupt_handler(u8 vector)
{
	struct devirt_guest_irq_pending *pending;
	struct kvm_vcpu *vcpu;
	int cpu = smp_processor_id();

	pending = this_cpu_ptr(&devirt_guest_irq_pending);
	set_bit(vector, pending->pending_map);

	spin_lock(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, cpu));
	list_for_each_entry(vcpu, &per_cpu(devirt_blocked_vcpu_on_cpu, cpu),
			blocked_vcpu_list) {
		kvm_vcpu_wake_up(vcpu);
	}
	spin_unlock(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, cpu));
}

void devirt_set_guest_interrupt_handler(void (*handler)(u8 vector))
{
	if (handler)
		guest_interrupt_handler = handler;
}

bool devirt_host_system_interrupt_pending(void)
{
	u32 irr;

	irr = apic_read(APIC_IRR + (FIRST_SYSTEM_VECTOR >> 5) * 0x10);

	if (irr)
		return true;

	return false;
}
EXPORT_SYMBOL(devirt_host_system_interrupt_pending);

int devirt_pre_block(struct kvm_vcpu *vcpu)
{
	int ret = 0;

	if (!devirt_enable(vcpu->kvm))
		return 0;
	WARN_ON(irqs_disabled());
	local_irq_disable();
	if (devirt_has_guest_interrupt(vcpu)) {
		ret = 1;
		goto out;
	}

	if (!WARN_ON_ONCE(vcpu->pre_pcpu != -1)) {
		vcpu->pre_pcpu = vcpu->cpu;
		spin_lock(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		list_add_tail(&vcpu->blocked_vcpu_list,
			      &per_cpu(devirt_blocked_vcpu_on_cpu,
				       vcpu->pre_pcpu));
		spin_unlock(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
	}

out:
	local_irq_enable();
	return ret;
}

void devirt_post_block(struct kvm_vcpu *vcpu)
{
	if (!devirt_enable(vcpu->kvm))
		return;
	WARN_ON(irqs_disabled());
	local_irq_disable();
	if (!WARN_ON_ONCE(vcpu->pre_pcpu == -1)) {
		spin_lock(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		list_del(&vcpu->blocked_vcpu_list);
		spin_unlock(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		vcpu->pre_pcpu = -1;
	}
	local_irq_enable();
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
	devirt_set_guest_irq();
}

void devirt_exit_guest_irqoff(struct kvm_vcpu *vcpu)
{
	devirt_check_eoi();
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
	int cpu;

	devirt_set_guest_interrupt_handler(devirt_guest_interrupt_handler);

	for_each_possible_cpu(cpu) {
		INIT_LIST_HEAD(&per_cpu(devirt_blocked_vcpu_on_cpu, cpu));
		spin_lock_init(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, cpu));
	}
}

struct devirt_kvm_operations *devirt_kvm_ops;
EXPORT_SYMBOL(devirt_kvm_ops);
