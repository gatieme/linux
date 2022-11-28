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
#include <asm/vmx.h>
#include <asm/devirt.h>

#include "ops.h"
#include "vmx.h"

int devirt_vmx_enter_guest(struct kvm_vcpu *vcpu)
{
	return 0;
}

void devirt_vmx_exit_guest(struct kvm_vcpu *vcpu)
{
}

int devirt_vmx_in_guest_mode(void)
{
	return 0;
}

void devirt_vmx_tigger_failed_vm_entry(struct kvm_vcpu *vcpu)
{
}

void devirt_vmx_set_msr_interception(struct kvm_vcpu *vcpu)
{
}

struct devirt_nmi_operations devirt_vmx_nmi_ops = {
	.devirt_in_guest_mode = devirt_vmx_in_guest_mode,
	.devirt_tigger_failed_vm_entry = devirt_vmx_tigger_failed_vm_entry,
};

struct devirt_kvm_operations devirt_vmx_kvm_ops = {
	.devirt_set_msr_interception = devirt_vmx_set_msr_interception,
	.devirt_tigger_failed_vm_entry = devirt_vmx_tigger_failed_vm_entry,
};
