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
#include <asm/tlbflush.h>

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

static void vmx_notify_tsc_offset(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct apic_maps *maps = kvm->arch.devirt.apic_maps;

	maps->entries[vcpu->vcpu_id].tsc_offset = vmcs_read64(TSC_OFFSET);
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
	u8 *state = this_cpu_ptr(&devirt_state);

	if (vmx_extirq_get_and_clear(vcpu, &injected_vector))
		apic->send_IPI_self_devirt(injected_vector);
	vmx_notify_tsc_offset(vcpu);

	*this_cpu_ptr(&devirt_in_guest) = 1;
	/* Make sure the write is comleted before the execution of
	 * devirt_host_system_interrupt_pending
	 */
	smp_wmb();

	WARN_ON(*state != 0);
	*state = DEVERT_IN_GUEST;

	return devirt_host_system_interrupt_pending();
}

/* Existing sync_core is implemented by iret which will unmask NMIs and will
 * cause NMIs before vmx_do_interrupt_nmi_irqoff on Intel. This will futher
 * result in undetected swallow NMI issue. So we use cpuid instead.
 */
static void devirt_sync_core(void)
{
	unsigned int a, b, c, d;

	cpuid(0x80000002, &a, &b, &c, &d);
}

void devirt_vmx_exit_guest(struct kvm_vcpu *vcpu)
{
	u8 *state = this_cpu_ptr(&devirt_state);
	u8 state_val;

	state_val = xchg(state, 0);
	if (state_val & DEVIRT_FLUSH_TLB_ALL)
		__flush_tlb_all();
	else if (state_val & DEVIRT_FLUSH_TLB_LOCAL)
		devirt_flush_tlb();
	if (state_val & DEVIRT_SYNC_CORE)
		devirt_sync_core();

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
	vmx_disalbe_apic_tscdeadline(vcpu);
	if (devirt_x2apic_enabled()) {
		vmx_disable_apic_irq(vcpu);
		vmx_disable_apic_tmr(vcpu);
		vmx_disable_apic_icr(vcpu);
	}
}

void devirt_vmx_trigger_vm_shut_down(struct kvm_vcpu *vcpu)
{
	u64 guest_rflag = vmcs_readl(GUEST_RFLAGS);

	/* use the invalid bit in GUEST_RFLAGS to trigger VM shut down */
	vmcs_writel(GUEST_RFLAGS, guest_rflag | DEVIRT_VMENTRY_SHUTDOWN_FLAG);
}

void devirt_vmx_disable_pf_trap(struct kvm_vcpu *vcpu)
{
	vmcs_write32(EXCEPTION_BITMAP, vmcs_read32(EXCEPTION_BITMAP) & ~(1u << PF_VECTOR));
}

void devirt_vmx_set_mem_interception(struct kvm_vcpu *vcpu)
{
	secondary_exec_controls_clearbit(to_vmx(vcpu), SECONDARY_EXEC_ENABLE_EPT);
	secondary_exec_controls_clearbit(to_vmx(vcpu), SECONDARY_EXEC_ENABLE_VPID);
	secondary_exec_controls_clearbit(to_vmx(vcpu), SECONDARY_EXEC_UNRESTRICTED_GUEST);

	devirt_vmx_disable_pf_trap(vcpu);
}

unsigned long devirt_vmx_guest_cr3(struct kvm_vcpu *vcpu)
{
	return vmcs_readl(GUEST_CR3);
}

void devirt_vmx_set_guest_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	return vmcs_writel(GUEST_CR3, cr3);
}

void devirt_vmx_enable_pf_trap(struct kvm_vcpu *vcpu)
{
	vmcs_write32(EXCEPTION_BITMAP, vmcs_read32(EXCEPTION_BITMAP) | (1u << PF_VECTOR));
}

struct devirt_nmi_operations devirt_vmx_nmi_ops = {
	.devirt_in_guest_mode = devirt_vmx_in_guest_mode,
	.devirt_tigger_failed_vm_entry = devirt_vmx_tigger_failed_vm_entry,
};

struct devirt_kvm_operations devirt_vmx_kvm_ops = {
	.devirt_set_msr_interception = devirt_vmx_set_msr_interception,
	.devirt_tigger_failed_vm_entry = devirt_vmx_tigger_failed_vm_entry,
	.devirt_trigger_vm_shut_down = devirt_vmx_trigger_vm_shut_down,
	.devirt_set_mem_interception = devirt_vmx_set_mem_interception,
	.devirt_guest_cr3 = devirt_vmx_guest_cr3,
	.devirt_set_guest_cr3 = devirt_vmx_set_guest_cr3,
	.devirt_enable_pf_trap = devirt_vmx_enable_pf_trap,
};
