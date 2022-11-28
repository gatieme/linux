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

struct devirt_vfio_irq_info {
	int host_irq;
	u8 vector;
	int prev_vcpu_id;
	struct list_head node;
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
};

struct devirt_kvm_arch {
	/* Used for virtio-device notification */
	u64 dvn_msr_val;
	struct dvn_desc *dvn_desc;

	/* Used for apic maps */
	u64 apic_maps_msr_val;
	struct apic_maps *apic_maps;
};

#endif /* _ASM_X86_DEVIRT_TYPES_H */

