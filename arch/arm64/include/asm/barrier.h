/*
 * Based on arch/arm/include/asm/barrier.h
 *
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_BARRIER_H
#define __ASM_BARRIER_H

#ifndef __ASSEMBLY__

#define __nops(n)	".rept	" #n "\nnop\n.endr\n"
#define nops(n)		asm volatile(__nops(n))

#define sev()		asm volatile("sev" : : : "memory")
#define wfe()		asm volatile("wfe" : : : "memory")
#define wfi()		asm volatile("wfi" : : : "memory")

#define isb()		asm volatile("isb" : : : "memory")
#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")

#define psb_csync()	asm volatile("hint #17" : : : "memory")

#define mb()		dsb(sy)
#define rmb()		dsb(ld)
#define wmb()		dsb(st)

#define dma_rmb()	dmb(oshld)
#define dma_wmb()	dmb(oshst)

#define nospec_array_ptr(arr, idx, sz)					\
({									\
	typeof(&(arr)[0]) __nap_arr = (arr);				\
	typeof(idx) __nap_idx = (idx);					\
	typeof(sz) __nap_sz = (sz);					\
									\
	unsigned long __nap_ptr = (unsigned long)__nap_arr +		\
				  sizeof(__nap_arr[0]) * idx;		\
									\
	asm volatile(							\
	"	cmp	%[i], %[s]\n"					\
	"	b.cs	1f\n"						\
	"	ldr	%[p], %[pp]\n"					\
	"1:	csel	%[p], %[p], xzr, cc\n"				\
	"	hint	#0x14 // CSDB\n"				\
	: [p] "=&r" (__nap_ptr)						\
	: [pp] "m" (__nap_ptr),						\
	  [i] "r" ((unsigned long)__nap_idx),				\
	  [s] "r" ((unsigned long)__nap_sz)				\
	: "cc");							\
									\
	(typeof(&(__nap_arr)[0]))__nap_ptr;				\
})

#define __smp_mb()	dmb(ish)
#define __smp_rmb()	dmb(ishld)
#define __smp_wmb()	dmb(ishst)

#define __smp_store_release(p, v)					\
do {									\
	union { typeof(*p) __val; char __c[1]; } __u =			\
		{ .__val = (__force typeof(*p)) (v) }; 			\
	compiletime_assert_atomic_type(*p);				\
	switch (sizeof(*p)) {						\
	case 1:								\
		asm volatile ("stlrb %w1, %0"				\
				: "=Q" (*p)				\
				: "r" (*(__u8 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 2:								\
		asm volatile ("stlrh %w1, %0"				\
				: "=Q" (*p)				\
				: "r" (*(__u16 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 4:								\
		asm volatile ("stlr %w1, %0"				\
				: "=Q" (*p)				\
				: "r" (*(__u32 *)__u.__c)		\
				: "memory");				\
		break;							\
	case 8:								\
		asm volatile ("stlr %1, %0"				\
				: "=Q" (*p)				\
				: "r" (*(__u64 *)__u.__c)		\
				: "memory");				\
		break;							\
	}								\
} while (0)

#define __smp_load_acquire(p)						\
({									\
	union { typeof(*p) __val; char __c[1]; } __u;			\
	compiletime_assert_atomic_type(*p);				\
	switch (sizeof(*p)) {						\
	case 1:								\
		asm volatile ("ldarb %w0, %1"				\
			: "=r" (*(__u8 *)__u.__c)			\
			: "Q" (*p) : "memory");				\
		break;							\
	case 2:								\
		asm volatile ("ldarh %w0, %1"				\
			: "=r" (*(__u16 *)__u.__c)			\
			: "Q" (*p) : "memory");				\
		break;							\
	case 4:								\
		asm volatile ("ldar %w0, %1"				\
			: "=r" (*(__u32 *)__u.__c)			\
			: "Q" (*p) : "memory");				\
		break;							\
	case 8:								\
		asm volatile ("ldar %0, %1"				\
			: "=r" (*(__u64 *)__u.__c)			\
			: "Q" (*p) : "memory");				\
		break;							\
	}								\
	__u.__val;							\
})

#define smp_cond_load_acquire(ptr, cond_expr)				\
({									\
	typeof(ptr) __PTR = (ptr);					\
	typeof(*ptr) VAL;						\
	for (;;) {							\
		VAL = smp_load_acquire(__PTR);				\
		if (cond_expr)						\
			break;						\
		__cmpwait_relaxed(__PTR, VAL);				\
	}								\
	VAL;								\
})

#include <asm-generic/barrier.h>

#endif	/* __ASSEMBLY__ */

#endif	/* __ASM_BARRIER_H */
