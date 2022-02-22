/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DEVIRT: Support de-virtualization to run kata BM
 *
 * Copyright (C) 2021-2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Deng Liang <dengliang.1214@bytedance.com>
 *
 */
#ifndef _ASM_X86_DEVIRT_IRQ_VECTORS_H
#define _ASM_X86_DEVIRT_IRQ_VECTORS_H

/* Kata BM IRQ vector layout.
 *
 * Vectors   0x0 ... 0x1f : system traps and exceptions
 * Vectors  0x20 ... 0x6a : device interrupts for host kernel
 * Vectors  0x6b ... 0x7f : special/system interrupts for host kernel
 * Vectors  0x80 ... 0xbf : reserved for Kata VM use
 * Vectors  0xc0 ... 0xeb : device interrupts for Kata BM
 * Vectors  0xec ... 0xff : special/system interrupts for Kata BM
 */

#define NMI_VECTOR			0x02
#define MCE_VECTOR			0x12

#define FIRST_EXTERNAL_VECTOR		0x20

#define IRQ_MOVE_CLEANUP_VECTOR		FIRST_EXTERNAL_VECTOR

#define IA32_SYSCALL_VECTOR		0x80

#define ISA_IRQ_VECTOR(irq)		(((FIRST_EXTERNAL_VECTOR + 16) & ~15) + irq)

#define SPURIOUS_APIC_VECTOR		0x7f
/*
 * Sanity check
 */
#if ((SPURIOUS_APIC_VECTOR & 0x0F) != 0x0F)
# error SPURIOUS_APIC_VECTOR definition error
#endif

#define ERROR_APIC_VECTOR		0x7e
#define RESCHEDULE_VECTOR		0x7d
#define CALL_FUNCTION_VECTOR		0x7c
#define CALL_FUNCTION_SINGLE_VECTOR	0x7b
#define THERMAL_APIC_VECTOR		0x7a
#define THRESHOLD_APIC_VECTOR		0x79
#define REBOOT_VECTOR			0x78
/* System vector for virtio interrupt passthough */
#define DEVIRT_VIRTIO_NOTIFY_VECTOR     0x6c

/*
 * Generic system vector for platform specific use
 */
#define X86_PLATFORM_IPI_VECTOR		0x77

/*
 * IRQ work vector:
 */
#define IRQ_WORK_VECTOR			0x76

#define UV_BAU_MESSAGE			0x75
#define DEFERRED_ERROR_VECTOR		0x74

/* Vector on which hypervisor callbacks will be delivered */
#define HYPERVISOR_CALLBACK_VECTOR	0x73

/* Vector for KVM to deliver posted interrupt IPI */
#ifdef CONFIG_HAVE_KVM
#define POSTED_INTR_VECTOR		0x72
#define POSTED_INTR_WAKEUP_VECTOR	0x71
#define POSTED_INTR_NESTED_VECTOR	0x70
#endif

#define MANAGED_IRQ_SHUTDOWN_VECTOR	0x6f

#if IS_ENABLED(CONFIG_HYPERV)
#define HYPERV_REENLIGHTENMENT_VECTOR	0x6e
#define HYPERV_STIMER0_VECTOR		0x6d
#endif

#define LOCAL_TIMER_VECTOR		0x6b

#define NR_VECTORS			 256

#ifdef CONFIG_X86_LOCAL_APIC
#define FIRST_SYSTEM_VECTOR		LOCAL_TIMER_VECTOR
#else
#define FIRST_SYSTEM_VECTOR		NR_VECTORS
#endif

/* System vector definition for Kata BM */
#define GUEST1_LOCAL_TIMER_VECTOR 0xec
#define GUEST1_IRQ_MOVE_CLEANUP_VECTOR 0xc0
#define GUEST1_HYPERV_STIMER0_VECTOR 0xed
#define GUEST1_HYPERV_REENLIGHTENMENT_VECTOR 0xee
#define GUEST1_MANAGED_IRQ_SHUTDOWN_VECTOR 0xef
#define GUEST1_POSTED_INTR_NESTED_VECTOR 0xf0
#define GUEST1_POSTED_INTR_WAKEUP_VECTOR 0xf1
#define GUEST1_POSTED_INTR_VECTOR 0xf2
#define GUEST1_HYPERVISOR_CALLBACK_VECTOR 0xf3
#define GUEST1_DEFERRED_ERROR_VECTOR 0xf4
#define GUEST1_UV_BAU_MESSAGE 0xf5
#define GUEST1_IRQ_WORK_VECTOR 0xf6
#define GUEST1_X86_PLATFORM_IPI_VECTOR 0xf7
#define GUEST1_REBOOT_VECTOR 0xf8
#define GUEST1_THRESHOLD_APIC_VECTOR 0xf9
#define GUEST1_THERMAL_APIC_VECTOR 0xfa
#define GUEST1_CALL_FUNCTION_SINGLE_VECTOR 0xfb
#define GUEST1_CALL_FUNCTION_VECTOR 0xfc
#define GUEST1_RESCHEDULE_VECTOR 0xfd
#define GUEST1_ERROR_APIC_VECTOR 0xfe
#define GUEST1_SPURIOUS_APIC_VECTOR 0xff
/* Note that GUEST1_IRQ_MOVE_CLEANUP_VECTOR(0xc0) must be excluded */
#define GUEST1_FIRST_EXTERNAl_VECTOR  0xc1
#define GUEST1_END_EXTERNAl_VECTOR    GUEST1_LOCAL_TIMER_VECTOR

/* System vector definition for the second Kata BM */
#define GUEST2_LOCAL_TIMER_VECTOR 0xac
#define GUEST2_IRQ_MOVE_CLEANUP_VECTOR 0x80
#define GUEST2_HYPERV_STIMER0_VECTOR 0xad
#define GUEST2_HYPERV_REENLIGHTENMENT_VECTOR 0xae
#define GUEST2_MANAGED_IRQ_SHUTDOWN_VECTOR 0xaf
#define GUEST2_POSTED_INTR_NESTED_VECTOR 0xb0
#define GUEST2_POSTED_INTR_WAKEUP_VECTOR 0xb1
#define GUEST2_POSTED_INTR_VECTOR 0xb2
#define GUEST2_HYPERVISOR_CALLBACK_VECTOR 0xb3
#define GUEST2_DEFERRED_ERROR_VECTOR 0xb4
#define GUEST2_UV_BAU_MESSAGE 0xb5
#define GUEST2_IRQ_WORK_VECTOR 0xb6
#define GUEST2_X86_PLATFORM_IPI_VECTOR 0xb7
#define GUEST2_REBOOT_VECTOR 0xb8
#define GUEST2_THRESHOLD_APIC_VECTOR 0xb9
#define GUEST2_THERMAL_APIC_VECTOR 0xba
#define GUEST2_CALL_FUNCTION_SINGLE_VECTOR 0xbb
#define GUEST2_CALL_FUNCTION_VECTOR 0xbc
#define GUEST2_RESCHEDULE_VECTOR 0xbd
#define GUEST2_ERROR_APIC_VECTOR 0xbe
#define GUEST2_SPURIOUS_APIC_VECTOR 0xbf
/* Note that GUEST2_IRQ_MOVE_CLEANUP_VECTOR(0x80) must be excluded */
#define GUEST2_FIRST_EXTERNAl_VECTOR  0x81
#define GUEST2_END_EXTERNAl_VECTOR    GUEST2_LOCAL_TIMER_VECTOR

#define GUEST1_IRQ_PRI_THREHOLD 0xb0

#endif /* _ASM_X86_DEVIRT_IRQ_VECTORS_H */
