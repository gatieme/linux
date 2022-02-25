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

#include "kvm_cache_regs.h"

static DEFINE_PER_CPU(u32, devirt_cpu_set);
static DEFINE_RAW_SPINLOCK(devirt_vcpu_migration_lock);
static DEFINE_PER_CPU(struct list_head, devirt_notify_vm_list);
static DEFINE_PER_CPU(spinlock_t, devirt_notify_vm_list_lock);

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

static void devirt_load_guest_tpr(struct kvm_vcpu *vcpu)
{
	struct devirt_vcpu_arch *devirt = vcpu_to_devirt(vcpu);

	devirt->devirt_host_tpr = apic_read(APIC_TASKPRI);
	apic_write(APIC_TASKPRI, GUEST1_IRQ_PRI_THREHOLD);
}

static void devirt_save_guest_tpr(struct kvm_vcpu *vcpu)
{
	struct devirt_vcpu_arch *devirt = vcpu_to_devirt(vcpu);

	apic_write(APIC_TASKPRI, devirt->devirt_host_tpr);
}

void devirt_check_guest_icr_apicid(struct kvm_vcpu *vcpu)
{
	unsigned long rip;
	struct kvm *kvm = vcpu->kvm;
	struct apic_maps *maps = kvm->arch.devirt.apic_maps;
	struct kvm_vcpu *target;
	struct devirt_vcpu_arch *devirt;
	int i = 0;

	/*
	 * Vcpu can't enter guest until all vcpu's
	 * guest_irq_pending->bitmap migrate completely.
	 */
	kvm_for_each_vcpu(i, target, kvm) {
		if (target->vcpu_id != vcpu->vcpu_id) {
			devirt = vcpu_to_devirt(vcpu);
			smp_cond_load_acquire(
				&devirt->devirt_apic_maps_update_status,
				!(VAL & DEVIRT_APIC_MAPS_UPDATING));
		}
	}

	/*
	 * Now the vcpu is sending IPI to dest vcpu, but the dest vcpu is migrated
	 * to another vcpu. So, when the vcpu enter into the guest mode, the vcpu
	 * will send ipi again.
	 */
	rip = kvm_rip_read(vcpu);
	if (rip > kvm->devirt_apic_rip_start &&
	    rip <= kvm->devirt_apic_rip_end)
		kvm_rip_write(vcpu, kvm->devirt_apic_rip_start);
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

static void devirt_vcpu_update_apic_maps_entry(struct kvm_vcpu *vcpu, int cpu)
{
	struct apic_maps *maps = vcpu->kvm->arch.devirt.apic_maps;

	/* In both QEMU and CLH, vcpu_id is equal to guest apicid, so the guest
	 * can use guest apicid to index apic maps and find the physical apicid.
	 */
	maps->entries[vcpu->vcpu_id].papic_id = per_cpu(x86_cpu_to_apicid, cpu);
	maps->entries[vcpu->vcpu_id].pcpu_id = cpu;
	/* Make sure the writes are completed before the status write */
	smp_wmb();
	maps->entries[vcpu->vcpu_id].status = 1;
}

static void devirt_vcpu_kick_func(void *UNUSED)
{
	/* Do nothing */
}

/*
 * During reset vcpu thread's affinity, all other vcpu in guest mode
 * must exit to host mode. Then, we can migrate the guest_irq_pending->bitmap
 * from old cpu to new cpu. If we don't do it, other vcpu still run'
 * in guest mode, it may still send ipi to the vcpu's old physical apicid.
 * The interrupt which sends to vcpu's old physical apicid will be lost.
 */
static void devirt_vcpu_update_guest_irq_bitmap(struct kvm_vcpu *vcpu,
										int cpu)
{
	int i;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu *target;
	struct cpumask mask = {0};
	struct devirt_vcpu_arch *devirt = vcpu_to_devirt(vcpu);

	if (!raw_spin_trylock(&devirt_vcpu_migration_lock)) {
		/* Failed to aquire the spin lock, so just trigger a VM exit and try
		 * again at next VM entry round. We cannot spin here, as we have
		 * disabled irq and would cause deadlock.
		 */
		devirt_kvm_ops->devirt_tigger_failed_vm_entry(vcpu);
		return;
	}

	devirt->devirt_apic_maps_update_status = DEVIRT_APIC_MAPS_UPDATING;
	/* Make the write visable to other cores */
	smp_wmb();

	/* kick other vcpu by smp_call_function */
	kvm_for_each_vcpu(i, target, kvm) {
		if (target->vcpu_id != vcpu->vcpu_id)
			cpumask_set_cpu(target->cpu, &mask);
	}

	smp_call_function_many(&mask, devirt_vcpu_kick_func, NULL, 1);

	devirt_vcpu_update_apic_maps_entry(vcpu, cpu);

	/* Make sure the write is completed */
	smp_store_release(&devirt->devirt_apic_maps_update_status, 0);
	raw_spin_unlock(&devirt_vcpu_migration_lock);
}

void devirt_update_apic_maps(struct kvm_vcpu *vcpu)
{
	int status;
	int vcpu_id = vcpu->vcpu_id;
	struct apic_maps *maps;
	int cpu = smp_processor_id();

	if (!vcpu->kvm->arch.devirt.apic_maps)
		return;

	maps = vcpu->kvm->arch.devirt.apic_maps;
	status = maps->entries[vcpu_id].status;

	if (!status)
		/* apic_maps need update when vcpu first into guest mode. */
		devirt_vcpu_update_apic_maps_entry(vcpu, cpu);
	else
		/* apic_maps need update when vcpu migrate from old cpu to
		 * new cpu.
		 */
		devirt_vcpu_update_guest_irq_bitmap(vcpu, cpu);
}

void devirt_clear_apic_maps(struct kvm_vcpu *vcpu)
{
	struct apic_maps *maps;
	int vcpu_id = vcpu->vcpu_id;

	maps = vcpu->kvm->arch.devirt.apic_maps;
	maps->entries[vcpu_id].status = 0;
	/* Make sure the write is completed */
	smp_mb();
	maps->entries[vcpu_id].papic_id = -1;
	maps->entries[vcpu_id].pcpu_id = -1;
}

/* Allocate one page to store papicid-vcpu mapping */
static int devirt_apic_maps_alloc_page(struct kvm *kvm)
{
	int r = 0;
	struct apic_maps_msr val;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.devirt.apic_maps_msr_val)
		goto out;

	r = __x86_set_memory_region(kvm, DEVIRT_APIC_MAPS_PRIVATE_MEMSLOT,
				    DEVIRT_APIC_MAPS_PHYS_BASE,
				    PAGE_SIZE);
	if (r) {
		pr_emerg("set memory region failed for DEVIRT_APIC_MAPS_PRIVATE_MEMSLOT %d\n", r);
		goto out;
	}
	val.apic_maps_gfn = DEVIRT_APIC_MAPS_PHYS_BASE >> PAGE_SHIFT;
	val.apic_maps_enable = 1;
	kvm->arch.devirt.apic_maps_msr_val = val.val;
	kvm->arch.devirt.apic_maps = NULL;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int devirt_apic_maps_setup(struct kvm_vcpu *vcpu, struct kvm *kvm)
{
	struct apic_maps *maps;
	struct apic_maps_msr val;
	struct page *page;
	int r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.devirt.apic_maps || !kvm->arch.devirt.apic_maps_msr_val)
		goto out;

	val.val = kvm->arch.devirt.apic_maps_msr_val;
	page = kvm_vcpu_gfn_to_page(vcpu, val.apic_maps_gfn);
	if (is_error_page(page)) {
		pr_warn("cannot get page from gfn: 0x%llx\n",
			val.val);
		r = -EFAULT;
		goto out;
	}

	maps = (struct apic_maps *)(page_address(page));
	memset(maps, 0x00, sizeof(struct apic_maps));
	kvm->arch.devirt.apic_maps = maps;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int devirt_virtio_notify_alloc_pages(struct kvm *kvm)
{
	int r = 0;
	struct dvn_msr val;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.devirt.dvn_msr_val)
		goto out;

	r = __x86_set_memory_region(kvm, DEVIRT_VIRTIO_NOTIFY_MEMOSLOT,
				    DEVIRT_VIRTIO_NOTIFY_PHYS_BASE,
				    PAGE_SIZE);
	if (r)
		goto out;

	val.dvn_gfn = DEVIRT_VIRTIO_NOTIFY_PHYS_BASE >> PAGE_SHIFT;
	val.dvn_enable = 1;
	kvm->arch.devirt.dvn_msr_val = val.val;
	kvm->arch.devirt.dvn_desc = NULL;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

/*
 * devirt_get_dvn_cpu() - Return the target cpu for devirt virtio-exitless
 *                        notification.
 */
extern struct cpumask devirt_virtio_notify_mask;
static unsigned int devirt_get_virtio_notify_cpu(void)
{
	int cpu = smp_processor_id();
	int node = cpu_to_node(cpu);

	if (cpumask_empty(&devirt_virtio_notify_mask))
		return 0;


	/* Select the first managed cpu in the same NUMA node. */
	for_each_cpu_and(cpu, cpumask_of_node(node), &devirt_virtio_notify_mask)
		return cpu;

	cpu = cpumask_next(cpu, &devirt_virtio_notify_mask);
	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(&devirt_virtio_notify_mask);
	return cpu;
}

static int devirt_virtio_notify_setup_desc(struct kvm_vcpu *vcpu,
					   struct kvm *kvm)
{
	struct dvn_desc *desc;
	struct dvn_msr val;
	struct page *page;
	int dest_cpu, r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.devirt.dvn_desc || !kvm->arch.devirt.dvn_msr_val)
		goto out;

	val.val = kvm->arch.devirt.dvn_msr_val;
	page = kvm_vcpu_gfn_to_page(vcpu, val.dvn_gfn);
	if (is_error_page(page)) {
		pr_warn("cannot get page from gfn: 0x%llx\n", val.val);
		r = -EFAULT;
		goto out;
	}

	desc = (struct dvn_desc *)(page_address(page));
	memset(desc, 0x00, sizeof(struct dvn_desc));
	dest_cpu = devirt_get_virtio_notify_cpu();
	desc->cpu = dest_cpu;
	desc->dest_apicid = per_cpu(x86_cpu_to_apicid, dest_cpu);
	spin_lock(&per_cpu(devirt_notify_vm_list_lock, dest_cpu));
	list_add(&kvm->devirt_notify_vm_list,
		 &per_cpu(devirt_notify_vm_list, dest_cpu));
	spin_unlock(&per_cpu(devirt_notify_vm_list_lock, dest_cpu));
	kvm->arch.devirt.dvn_desc = desc;
	kvm->arch.devirt.dvn_desc->kvm_id = kvm->userspace_pid;
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
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

int devirt_virtio_notify(struct kvm *kvm, gpa_t addr,
			 int len,
			 unsigned long val)
{
	int r = 0;

	/* Scan KVM_FAST_MMIO_BUS */
	r = kvm_io_bus_handler(kvm, KVM_FAST_MMIO_BUS, addr, len, &val);

	/* Scan KVM_MMIO_BUS */
	if (r != 0)
		r = kvm_io_bus_handler(kvm, KVM_MMIO_BUS, addr, len, &val);

	/* Scan KVM_PIO_BUS */
	if (r != 0)
		r = kvm_io_bus_handler(kvm, KVM_PIO_BUS, addr, len, &val);

	return r;
}

/* Handler for DEVIRT_VIRTIO_NOTIFY_VECTOR */
static void devirt_virtio_notify_handler(void)
{
	struct kvm *kvm;
	struct dvn_desc *desc;
	int nr, status;
	struct kick_entry *entry;
	struct list_head *head;
	unsigned long flags;

	head = this_cpu_ptr(&devirt_notify_vm_list);
	spin_lock_irqsave(this_cpu_ptr(&devirt_notify_vm_list_lock), flags);
	list_for_each_entry(kvm, head, devirt_notify_vm_list) {
		if (!devirt_enable(kvm) || !kvm->arch.devirt.dvn_desc)
			continue;

		desc = kvm->arch.devirt.dvn_desc;
		for (nr = 0; nr < DEVIRT_VIRTIO_NOTIFY_ENTRY_MAX; nr++) {
			entry = &(desc->entries[nr]);
			status = atomic_read_acquire(&(entry->status));
			if (status == DEVIRT_VIRTIO_NOTIFY_ENTRY_USED) {
				if (devirt_virtio_notify(kvm, entry->addr, entry->len, entry->val))
					pr_warn("Not find device: 0x%llx\n", entry->addr);

				atomic_set_release(&(entry->status),
					DEVIRT_VIRTIO_NOTIFY_ENTRY_UNUSED);
			}
		}
	}
	spin_unlock_irqrestore(this_cpu_ptr(&devirt_notify_vm_list_lock), flags);
}

static void devirt_set_virtio_notify_handler(void (*handler)(void))
{
	if (handler)
		virtio_notify_handler = handler;
}

static inline bool kvm_can_mwait_in_guest(void)
{
	return boot_cpu_has(X86_FEATURE_MWAIT) &&
		!boot_cpu_has_bug(X86_BUG_MONITOR) &&
		boot_cpu_has(X86_FEATURE_ARAT);
}

static void devirt_disable_hlt(struct kvm *kvm)
{
	if (kvm_can_mwait_in_guest())
		kvm->arch.mwait_in_guest = true;
	kvm->arch.hlt_in_guest = true;
	kvm->arch.pause_in_guest = true;
	kvm->arch.cstate_in_guest = true;
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
		/* The guest apic maps must also be updated */
		devirt_update_apic_maps(vcpu);
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

static void devirt_del_notify_vm_list(struct kvm *kvm)
{
	int cpu;

	if (!kvm->arch.devirt.dvn_desc)
		return;

	cpu = kvm->arch.devirt.dvn_desc->cpu;

	spin_lock(&per_cpu(devirt_notify_vm_list_lock, cpu));
	list_del(&kvm->devirt_notify_vm_list);
	spin_unlock(&per_cpu(devirt_notify_vm_list_lock, cpu));
}

void devirt_enter_guest_irqoff(struct kvm_vcpu *vcpu)
{
	/* irq is disabled, so that it will not be interrupted when other core calls
	 * devirt_unset_devirt_cpu_on
	 */
	devirt_check_devirt_cpu(vcpu);
	devirt_check_guest_icr_apicid(vcpu);
	devirt_load_guest_tpr(vcpu);
	devirt_set_guest_irq();
}

void devirt_exit_guest_irqoff(struct kvm_vcpu *vcpu)
{
	devirt_save_guest_tpr(vcpu);
	devirt_check_eoi();
}

void devirt_enter_guest(struct kvm_vcpu *vcpu)
{
}

void devirt_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	devirt_virtio_notify_alloc_pages(kvm);
	devirt_virtio_notify_setup_desc(vcpu, kvm);
	devirt_apic_maps_alloc_page(kvm);
	devirt_apic_maps_setup(vcpu, kvm);
	devirt_kvm_ops->devirt_set_msr_interception(vcpu);
}

void devirt_vcpu_free(struct kvm_vcpu *vcpu)
{
	devirt_clear_apic_maps(vcpu);
}

void devirt_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct devirt_vcpu_arch *devirt = vcpu_to_devirt(vcpu);

	devirt->devirt_cpu = -1;
}

void devirt_init_vm(struct kvm *kvm)
{
	devirt_disable_hlt(kvm);
}

void devirt_destroy_vm(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned int i;
	struct page *page;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		devirt_unset_devirt_cpu_on(vcpu_to_devirt(vcpu)->devirt_cpu, NULL);
	}

	/*
	 * Free the two pages which used for apic_maps and dvn_desc.
	 */
	if (kvm->arch.devirt.apic_maps) {
		page = virt_to_page(kvm->arch.devirt.apic_maps);
		put_page(page);
	}
	if (kvm->arch.devirt.dvn_desc) {
		devirt_del_notify_vm_list(kvm);
		page = virt_to_page(kvm->arch.devirt.dvn_desc);
		put_page(page);
	}
}

void devirt_init(void)
{
	int cpu;

	devirt_set_guest_interrupt_handler(devirt_guest_interrupt_handler);
	devirt_set_virtio_notify_handler(devirt_virtio_notify_handler);

	for_each_possible_cpu(cpu) {
		INIT_LIST_HEAD(&per_cpu(devirt_blocked_vcpu_on_cpu, cpu));
		spin_lock_init(&per_cpu(devirt_blocked_vcpu_on_cpu_lock, cpu));
		INIT_LIST_HEAD(&per_cpu(devirt_notify_vm_list, cpu));
		spin_lock_init(&per_cpu(devirt_notify_vm_list_lock, cpu));
	}
}

struct devirt_kvm_operations *devirt_kvm_ops;
EXPORT_SYMBOL(devirt_kvm_ops);
