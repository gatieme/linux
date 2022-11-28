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

struct devirt_vcpu_arch {
	/* Used to record the id of pcpu where devirt vcpu runs */
	int devirt_cpu;

	/* Used for tpr switch */
	unsigned int devirt_host_tpr;
	/* Check all vcpu not in migration */
	int devirt_apic_maps_update_status;
};

struct devirt_kvm_arch {
	/* Used for apic maps */
	u64 apic_maps_msr_val;
	struct apic_maps *apic_maps;
};

#endif /* _ASM_X86_DEVIRT_TYPES_H */

