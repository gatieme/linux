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

static void vmx_disalbe_apic_tscdeadline(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long *msr_bitmap;

	msr_bitmap = vmx->vmcs01.msr_bitmap;
	devirt_vmx_disable_intercept_for_msr(msr_bitmap, MSR_IA32_TSC_DEADLINE, MSR_TYPE_RW);
}

static void vmx_disable_apic_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long *msr_bitmap;

	msr_bitmap = vmx->vmcs01.msr_bitmap;
	devirt_vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_EOI), MSR_TYPE_RW);
	devirt_vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_IRR), MSR_TYPE_RW);
}

static void vmx_disable_apic_tmr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long *msr_bitmap;

	msr_bitmap = vmx->vmcs01.msr_bitmap;
	devirt_vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_TDCR), MSR_TYPE_RW);
	devirt_vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_TMCCT), MSR_TYPE_RW);
	devirt_vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_LVTT), MSR_TYPE_RW);
	devirt_vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_TMICT), MSR_TYPE_RW);
}

static void vmx_disable_apic_icr(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long *msr_bitmap;

	msr_bitmap = vmx->vmcs01.msr_bitmap;

	devirt_vmx_disable_intercept_for_msr(msr_bitmap, X2APIC_MSR(APIC_ICR), MSR_TYPE_RW);
}

bool vmx_extirq_get_and_clear(struct kvm_vcpu *vcpu, u32 *v)
{
	u32 intr_info = vmcs_read32(VM_ENTRY_INTR_INFO_FIELD);

	if (is_external_intr(intr_info)) {
		apic_extirq_clear(vcpu);
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info & ~INTR_INFO_VALID_MASK);
		*v = intr_info & INTR_INFO_VECTOR_MASK;
		return true;
	}

	return false;
}

static DEFINE_PER_CPU(int, devirt_in_guest);

int devirt_vmx_enter_guest(struct kvm_vcpu *vcpu)
{
	u32 injected_vector;

	if (vmx_extirq_get_and_clear(vcpu, &injected_vector))
		apic->send_IPI_self(injected_vector);

	*this_cpu_ptr(&devirt_in_guest) = 1;
	/* Make sure the write is comleted before the execution of
	 * devirt_host_system_interrupt_pending
	 */
	smp_wmb();

	return devirt_host_system_interrupt_pending();
}

void devirt_vmx_exit_guest(struct kvm_vcpu *vcpu)
{
	*this_cpu_ptr(&devirt_in_guest) = 0;
}

int devirt_vmx_in_guest_mode(void)
{
	return *this_cpu_ptr(&devirt_in_guest);
}

void devirt_vmx_tigger_failed_vm_entry(struct kvm_vcpu *vcpu)
{
	u64 guest_rflags = vmcs_readl(GUEST_RFLAGS);

	/* use the invalid bit in GUEST_RFLAGS to trigger VM entry failed */
	vmcs_writel(GUEST_RFLAGS, guest_rflags | DEVIRT_VMENTRY_FAILED_FLAG);
}

void devirt_vmx_set_msr_interception(struct kvm_vcpu *vcpu)
{
	vmx_disable_apic_irq(vcpu);
	vmx_disalbe_apic_tscdeadline(vcpu);
	vmx_disable_apic_tmr(vcpu);
	vmx_disable_apic_icr(vcpu);
}

struct devirt_nmi_operations devirt_vmx_nmi_ops = {
	.devirt_in_guest_mode = devirt_vmx_in_guest_mode,
	.devirt_tigger_failed_vm_entry = devirt_vmx_tigger_failed_vm_entry,
};

struct devirt_kvm_operations devirt_vmx_kvm_ops = {
	.devirt_set_msr_interception = devirt_vmx_set_msr_interception,
	.devirt_tigger_failed_vm_entry = devirt_vmx_tigger_failed_vm_entry,
};
