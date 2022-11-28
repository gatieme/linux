/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DEVIRT: Support de-virtualization to run kata BM
 *
 * Copyright (C) 2021-2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Deng Liang <dengliang.1214@bytedance.com>
 *
 */
#ifndef _ASM_X86_DEVIRT_TYPES_H
#define _ASM_X86_DEVIRT_TYPES_H

#define KVM_USER_MEM_SLOTS 509
#define KVM_PRIVATE_MEM_SLOTS 10
#define KVM_MEM_SLOTS_NUM (KVM_USER_MEM_SLOTS + KVM_PRIVATE_MEM_SLOTS)

struct devirt_vfio_irq_info {
	int host_irq;
	u8 vector;
	int prev_vcpu_id;
	struct list_head node;
};

/* Make the structure size can be divide by PAGE_SIZE */
struct devirt_mem_map_head {
	unsigned long base_gfn;
	unsigned long map_addr;
	unsigned long map_guest_virt_addr;
	unsigned int nr_pages;
	unsigned int flags;
};

struct devirt_mem_map_head_kaddr {
	unsigned long kaddr;
};

struct devirt_vcpu_arch {
	/* Used to record the id of pcpu where devirt vcpu runs */
	int devirt_cpu;

	/* Used for tpr switch */
	unsigned int devirt_host_tpr;
	/* Check all vcpu not in migration */
	int devirt_apic_maps_update_status;
	struct list_head devirt_vfio_irq_list;
	spinlock_t devirt_vfio_irq_lock;
	int devirt_vfio_cpu;
	bool devirt_mem_start;
};

struct devirt_kvm_arch {
	/* Used for virtio-device notification */
	u64 dvn_msr_val;
	struct dvn_desc *dvn_desc;

	/* Used for apic maps */
	u64 apic_maps_msr_val;
	struct apic_maps *apic_maps;

	/* Used for prefault */
	spinlock_t devirt_pf_lock;
	bool need_prefault;
	hpa_t last_root_hpa;

	/* Used for mem-devirt */
	bool devirt_mem_init;
	unsigned long used_heads;
	/* Host user-space address */
	unsigned long base_map_addr;
	unsigned long cur_map_addr;
	unsigned long map_total_size;
	/* record the host kernel address for each devirt_mem_map_head */
	struct devirt_mem_map_head_kaddr map_head_kaddrs[KVM_MEM_SLOTS_NUM];
	unsigned long *rmap;
	unsigned long rmap_size;
	unsigned long used_pt_pages;
	struct page **pinned_pages;
	unsigned long cur_pinned_nrpages;
	struct file *mem_filp;
	bool mem_mapping_init;
	struct file *hp_filp;
};

#endif /* _ASM_X86_DEVIRT_TYPES_H */

