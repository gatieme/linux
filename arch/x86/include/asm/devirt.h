/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DEVIRT: Support de-virtualization to run kata BM
 *
 * Copyright (C) 2021-2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Deng Liang <dengliang.1214@bytedance.com>
 *
 */
#ifndef _ASM_X86_DEVIRT_H
#define _ASM_X86_DEVIRT_H

#include <linux/kvm_host.h>
#include <linux/tick.h>
#include <asm/devirt_types.h>

#define DEVERT_IN_GUEST           (1 << 0)
#define DEVIRT_FLUSH_TLB_LOCAL          (1 << 1)
#define DEVIRT_FLUSH_TLB_ALL          (1 << 2)
#define DEVIRT_SYNC_CORE          (1 << 3)

#define DEVIRT_HOST_SERVER_INTEL 1
#define DEVIRT_HOST_SERVER_AMD 2

#define DEVIRT_VM_RUN_FAILED 2
#define DEVIRT_VMENTRY_FAILED_FLAG        0x8000000000000000
#define DEVIRT_VMENTRY_SHUTDOWN_FLAG        0x4000000000000000

#define DEVIRT_AFFINITY_INFO_TYPE 0xffffffffffffffff

/*
 * Now virtual MSI interrupts which injected by don't rely on the
 * host handling of guest EOI. For katabm, such virtual MSI interrupts
 * can be directly injected into the BM using physical IPI.
 */
#define DEVIRT_DELIVERY_MSI_USING_IPI_FLAG   0x1

#define DEVIRT_VIRTIO_NOTIFY_PHYS_BASE   0xfefb0000
#define DEVIRT_VIRTIO_NOTIFY_ENTRY_MAX   168
#define DEVIRT_VIRTIO_NOTIFY_ENTRY_UNUSED  0
#define DEVIRT_VIRTIO_NOTIFY_ENTRY_USING   1
#define DEVIRT_VIRTIO_NOTIFY_ENTRY_USED    2

/* For mem-devirt */
#define DEVIRT_MEM_MAP_HEAD_MAX_SIZE 0x200000ul
#define DEVIRT_MEM_MAP_HEAD_PHYS_BASE 0x10000000000
#define DEVIRT_MEM_MAP_PHYS_BASE \
		(DEVIRT_MEM_MAP_HEAD_PHYS_BASE + DEVIRT_MEM_MAP_HEAD_MAX_SIZE)
#define DEVIRT_MEM_MAP_MAX_SIZE 0x20000000ul
#define DEVIRT_MEM_MAP_TOTAl_MAX_SIZE (DEVIRT_MEM_MAP_MAX_SIZE + DEVIRT_MEM_MAP_HEAD_MAX_SIZE)

#define DEVIRT_MAP_HEAD_NPAGES ((KVM_MEM_SLOTS_NUM * sizeof(struct devirt_mem_map_head) \
		+ PAGE_SIZE - 1) / PAGE_SIZE)
#define DEVIRT_MEM_MAP_FLAG_VALID 1

#define DEVIRT_MEM_RMAP_MAX_SIZE 0x400000000ul
#define DEVIRT_MEM_RMAP_PHYS_BASE 0x10040000000

#define DEVIRT_MEM_PT_MAX_SIZE 0x10000000ul
#define DEVIRT_MEM_PT_PHYS_BASE 0x10440000000

#define DEVIRT_MEM_RMAP_VIRT 0xffff810000000000
#define DEVIRT_MEM_MAP_HEAD_VIRT 0xffff800000000000
#define DEVIRT_MEM_MAP_VIRT 0xffff800000200000

#define KVM_DEVIRT_VIRTIO_NOTIFY_CPU    0

#define DEVIRT_CPU_SET(pid, vcpuid) ((pid << 2) + vcpuid)

/* Dvn: devirt virtio notify */
struct kick_entry {
	u64 addr;         /* Legal pio/mmio address */
	/*
	 * Devirt virtio device notify status:
	 *      0: entry is unused.
	 *      1: entry is using during update.
	 *      2: entry is used and update is completely.
	 */
	atomic_t status;
	u32 len;
	u64 val;
};

struct dvn_desc {
	struct kick_entry entries[DEVIRT_VIRTIO_NOTIFY_ENTRY_MAX];
	pid_t kvm_id;
	int dest_apicid;
	int cpu;
	char rsvd[52];
};

struct dvn_msr {
	union {
		struct  {
			/* Expose devirt notify desc to guest gfn, */
			u64 dvn_gfn     : 50;
			/* Enable/disable devirt notify feature */
			u64 dvn_enable  : 1;
		};
		u64 val;
	};
} __aligned(8);

/* Store physical apicid maps for kata bm */
#define DEVIRT_APIC_MAPS_PHYS_BASE       0xfefa0000
#define DEVIRT_APIC_MAPS_UPDATING        1
/* fix me if the core num is greater than 256 */
#define DEVIRT_APIC_MAPS_ENTRY_MAX       256

struct apic_maps_entry {
	u16 papic_id;
	u16 pcpu_id;
	/*
	 * 0: cpu offline
	 * 1: cpu online
	 */
	int status;
	unsigned long tsc_offset;
};

struct apic_maps {
	struct apic_maps_entry entries[DEVIRT_APIC_MAPS_ENTRY_MAX];
};

struct apic_maps_msr {
	union {
		struct {
			/* Expose apic maps to guest gfn */
			u64 apic_maps_gfn    : 50;
			/* Enable/disable to expose physical apicid*/
			u64 apic_maps_enable : 1;
		};
		u64 val;
	};
} __aligned(8);

/* Keep the same layout with struct vcpu_data  */
struct devirt_affinity_info {
	u64 type;
	u16 vector;
	u16 dest_id;
};

struct devirt_mem_rmap_head_info {
	unsigned long start_pfn;
	unsigned long end_pfn;
	unsigned long nrpages;
};

struct devirt_nmi_operations {
	int (*devirt_in_guest_mode)(void);
	void (*devirt_tigger_failed_vm_entry)(struct kvm_vcpu *vcpu);
};

struct devirt_kvm_operations {
	void (*devirt_set_msr_interception)(struct kvm_vcpu *vcpu);
	void (*devirt_tigger_failed_vm_entry)(struct kvm_vcpu *vcpu);
	void (*devirt_trigger_vm_shut_down)(struct kvm_vcpu *vcpu);
	void (*devirt_set_mem_interception)(struct kvm_vcpu *vcpu);
	unsigned long (*devirt_guest_cr3)(struct kvm_vcpu *vcpu);
	void (*devirt_set_guest_cr3)(struct kvm_vcpu *vcpu, unsigned long addr);
	void (*devirt_enable_pf_trap)(struct kvm_vcpu *vcpu);
};

struct devirt_guest_irq_pending {
	DECLARE_BITMAP(pending_map, 256);
};

struct devirt_cpu_unset_info {
	int new_cpu;
};

static inline bool devirt_enable(struct kvm *kvm)
{
	return kvm->devirt_enable;
}

static inline bool devirt_enable_intel(struct kvm *kvm)
{
	return kvm->devirt_enable_intel;
}

static inline bool devirt_enable_amd(struct kvm *kvm)
{
	return kvm->devirt_enable_amd;
}

static inline struct devirt_vcpu_arch *vcpu_to_devirt(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.devirt;
}

static inline void tick_broadcast_enable_devirt(void)
{
	tick_broadcast_control(TICK_BROADCAST_ON_DEVIRT);
}

static inline void tick_broadcast_disable_devirt(void)
{
	tick_broadcast_control(TICK_BROADCAST_OFF_DEVIRT);
}

static inline int tick_broadcast_enter_devirt(void)
{
	return tick_broadcast_oneshot_control(TICK_BROADCAST_ENTER_DEVIRT);
}

static inline void tick_broadcast_exit_devirt(void)
{
	tick_broadcast_oneshot_control(TICK_BROADCAST_EXIT_DEVIRT);
}

extern bool devirt_arat_disable;

extern bool devirt_enable_at_startup;
extern int devirt_host_server_type;
extern struct devirt_nmi_operations *devirt_nmi_ops;
extern struct devirt_kvm_operations *devirt_kvm_ops;
DECLARE_PER_CPU(u8, devirt_state);
DECLARE_PER_CPU(struct devirt_guest_irq_pending, devirt_guest_irq_pending);

extern struct cpumask cpu_devirt_mask;
extern struct cpumask nmi_ipi_mask;

extern void devirt_memory_init_mmu_ops(struct kvm_vcpu *vcpu);
extern void devirt_vmx_disable_pf_trap(struct kvm_vcpu *vcpu);

extern int apic_extirq_clear(struct kvm_vcpu *vcpu);
extern void devirt_flush_tlb(void);

/* Notify the virtio backend with ioeventfd */
extern int devirt_virtio_notify(struct kvm *kvm,
				gpa_t addr,
				int len,
				unsigned long val);

/* External functions used for guest interrupt handling*/
extern void (*virtio_notify_handler)(void);
extern void (*guest_interrupt_handler)(u8 vector);

extern bool devirt_has_guest_interrupt(struct kvm_vcpu *vcpu);
extern int devirt_pre_block(struct kvm_vcpu *vcpu);
extern void devirt_post_block(struct kvm_vcpu *vcpu);

extern void devirt_vmx_disable_intercept_for_msr(unsigned long *msr_bitmap,
						 u32 msr, int type);
extern void devirt_vmx_enable_intercept_for_msr(unsigned long *msr_bitmap,
						u32 msr, int type);

extern struct devirt_nmi_operations devirt_vmx_nmi_ops;
extern struct devirt_nmi_operations devirt_svm_nmi_ops;
extern struct devirt_kvm_operations devirt_vmx_kvm_ops;
extern struct devirt_kvm_operations devirt_svm_kvm_ops;

extern void devirt_tick_broadcast_set_event(ktime_t expires);
extern bool devirt_host_system_interrupt_pending(void);

extern int devirt_mem_start(struct kvm_vcpu *vcpu, unsigned long guest_cr3);
extern int devirt_mem_convert(struct kvm_vcpu *vcpu, unsigned long guest_cr3);
extern bool devirt_gva_mmio_access(struct kvm_vcpu *vcpu, unsigned long gva);
extern void devirt_svm_disable_pf_trap(struct kvm_vcpu *vcpu);
extern int devirt_create_mapping_info(struct kvm *kvm,
			    struct kvm_memory_slot *new, struct kvm_memory_slot *old,
			    enum kvm_mr_change change);
extern int devirt_mem_mmap(struct file *file, struct vm_area_struct *vma);
extern struct devirt_mem_rmap_head_info devirt_mem_pfn_info[MAX_NUMNODES];
extern int devirt_mem_node_num;
extern unsigned long devirt_mem_max_pfn;

void delete_devirt_vfio_irq_info_by_vcpu(struct kvm_vcpu *vcpu);

extern unsigned int devirt_num_cpus_for_device(void);
extern struct cpumask devirt_managed_irq_mask;

extern void devirt_enter_guest_irqoff(struct kvm_vcpu *vcpu);
extern void devirt_exit_guest_irqoff(struct kvm_vcpu *vcpu);
extern void devirt_enter_guest(struct kvm_vcpu *vcpu);
extern void devirt_vmx_exit_guest(struct kvm_vcpu *vcpu);
extern int devirt_vmx_enter_guest(struct kvm_vcpu *vcpu);
extern void devirt_vcpu_create(struct kvm_vcpu *vcpu);
extern void devirt_vcpu_free(struct kvm_vcpu *vcpu);
extern void devirt_vcpu_init(struct kvm_vcpu *vcpu);
extern void devirt_init_vm(struct kvm *kvm);
extern void devirt_destroy_vm(struct kvm *kvm);
extern int devirt_init(void);
extern void devirt_exit(void);

#endif /* _ASM_X86_DEVIRT_H */
