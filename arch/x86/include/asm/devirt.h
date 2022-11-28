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

#define DEVIRT_HOST_SERVER_INTEL 1
#define DEVIRT_HOST_SERVER_AMD 2

#define DEVIRT_VM_RUN_FAILED 2
#define DEVIRT_CPU_SET(pid, vcpuid) ((pid << 2) + vcpuid)

struct devirt_nmi_operations {
	int (*devirt_in_guest_mode)(void);
	void (*devirt_tigger_failed_vm_entry)(struct kvm_vcpu *vcpu);
};

struct devirt_kvm_operations {
	void (*devirt_set_msr_interception)(struct kvm_vcpu *vcpu);
	void (*devirt_tigger_failed_vm_entry)(struct kvm_vcpu *vcpu);
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

extern unsigned int kvm_devirt_enable;
extern int devirt_host_server_type;
extern struct devirt_nmi_operations *devirt_nmi_ops;
extern struct devirt_kvm_operations *devirt_kvm_ops;

extern struct devirt_nmi_operations devirt_vmx_nmi_ops;
extern struct devirt_nmi_operations devirt_svm_nmi_ops;
extern struct devirt_kvm_operations devirt_vmx_kvm_ops;
extern struct devirt_kvm_operations devirt_svm_kvm_ops;

extern void devirt_tick_broadcast_set_event(ktime_t expires);

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
extern void devirt_init(void);

#endif /* _ASM_X86_DEVIRT_H */
