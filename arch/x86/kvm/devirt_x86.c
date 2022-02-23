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

void devirt_enter_guest_irqoff(struct kvm_vcpu *vcpu)
{
}

void devirt_exit_guest_irqoff(struct kvm_vcpu *vcpu)
{
}

void devirt_enter_guest(struct kvm_vcpu *vcpu)
{
}

void devirt_vcpu_create(struct kvm_vcpu *vcpu)
{
}

void devirt_vcpu_free(struct kvm_vcpu *vcpu)
{
}

void devirt_vcpu_init(struct kvm_vcpu *vcpu)
{
}

void devirt_init_vm(struct kvm *kvm)
{
}

void devirt_destroy_vm(struct kvm *kvm)
{
}

void devirt_init(void)
{
}

struct devirt_kvm_operations *devirt_kvm_ops;
EXPORT_SYMBOL(devirt_kvm_ops);
