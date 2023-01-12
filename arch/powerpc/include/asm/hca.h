// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright 2021, Sandipan Das, IBM Corp.
 * Configuration helpers for the Hot-Cold Affinity helper
 */

#ifndef _ASM_POWERPC_HCA_H
#define _ASM_POWERPC_HCA_H

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/minmax.h>

#define KB	(1024UL)
#define MB	(1024 * KB)
#define GB	(1024 * MB)
#define TB	(1024 * GB)

#define HCA_ENGINES_PER_CHIP	1 /* 2 */
#define HCA_ENTRY_SIZE		8

#ifdef CONFIG_PPC_4K_PAGES
#define HCA_PAGE_SIZE		(4 * KB)
#else  /* CONFIG_PPC_64K_PAGES */
#define HCA_PAGE_SIZE		(64 * KB)
#endif /* CONFIG_PPC_4K_PAGES  */

/*
 * @m: The counter overflow mask
 *
 * Supported overflow masks are 16, 32, 64 ... 4096. The page stats in
 * the HCA cache are written back to memory once the count reaches @m.
 */
#define HCA_OVERFLOW_MASK(m)		min((u64)4096, max((u64)16, (u64)roundup_pow_of_two(m)))
#define HCA_OVERFLOW_MASK_DEFAULT	4096

/*
 * @m: The command sampling mode
 *
 * Supported command sampling modes are
 * 	0 -> No sampling (capture all commands)
 * 	1 -> Sample 1 of 16 commands
 * 	2 -> Sample 1 of 32 commands
 * 	3 -> Dynamic sampling (configured separately)
 *
 * The HCA fabric update traffic is reduced at the cost of accuracy. The
 * counts are scaled based on the sampling rate, i.e. if a single command
 * is seen when 1 of 16 mode is used, the corresponding page count will be
 * incremented by 16.
 */
#define HCA_SAMPLING_MODE(m)		min((u64)3, max((u64)0, (u64)(m) & 0x3))
#define HCA_SAMPLING_MODE_DEFAULT	3

/*
 * @p: The command sampling period (in cycles)
 *
 * Supported command sampling periods are 256, 512, 1024 ... 65536 cycles.
 * HCA update commands sent to the fabric are counted every @p cycles.
 *
 * Only used when dynamic sampling is enabled.
 * Actual period is = (value+1) * 256
 *
 */
#define HCA_SAMPLING_PERIOD(p)		min((u64)65536, max((u64)256, (u64)roundup_pow_of_two(p)))
#define HCA_SAMPLING_PERIOD_DEFAULT	0

/*
 * @t: The command threshold
 *
 * Supported command thresholds are 0, 1, 2 ... 255 commands.
 *
 * With the upper command threshold, the sampling rate will reduce when
 * more than @t number of update commands are detected within a sampling
 * period.
 *
 * With the lower command threshold, the sampling rate will increase when
 * fewer than @t number of update commands are detected within a sampling
 * period.
 *
 * Only used when dynamic sampling is enabled.
 */
#define HCA_SAMPLING_LOWER_THRESH(t)		min((u64)255, (u64)(t))
#define HCA_SAMPLING_LOWER_THRESH_DEFAULT	64UL

/*
 * @t: The command threshold
 *
 * Supported command thresholds are 0, 1, 2 ... 255 commands.
 *
 * With the upper command threshold, the sampling rate will reduce when
 * more than @t number of update commands are detected within a sampling
 * period.
 *
 * With the lower command threshold, the sampling rate will increase when
 * fewer than @t number of update commands are detected within a sampling
 * period.
 *
 * Only used when dynamic sampling is enabled.
 */
#define HCA_SAMPLING_UPPER_THRESH(t)		min((u64)255, (u64)(t))
#define HCA_SAMPLING_UPPER_THRESH_DEFAULT	255UL

/*
 * @s: The monitor region size (in bytes)
 *
 * Supported monitor region sizes are 16GB, 32GB, 64GB ... 512TB. The
 * minimum and maximum region sizes are always guaranteed to be 16GB
 * and 512TB respectively if the specified value is out of bounds.
 */
#define HCA_MONITOR_SIZE(s)		min((u64)512 * TB, max((u64)16 * GB, (u64)roundup_pow_of_two(s)))
//#define HCA_MONITOR_SIZE_DEFAULT	(16 * GB)

/*
 * @b: The monitor region base
 * @s: The monitor region size (in bytes)
 *
 * The monitor region base address must be aligned to its size.
 */
#define HCA_MONITOR_BASE(b, s)		ALIGN((u64)(b), HCA_MONITOR_SIZE(s))
//#define HCA_MONITOR_BASE_DEFAULT	0

/*
 * @s: The monitor region size
 *
 * The counter region size is directly derived from the monitor region
 * size and the page size.
 */
#define HCA_COUNTER_SIZE(s)		((HCA_MONITOR_SIZE(s) * (u64)HCA_ENTRY_SIZE) / PAGE_SIZE)
#define HCA_COUNTER_SIZE_DEFAULT	0
#define HCA_COUNTER_BASE_DEFAULT	0

/*
 * @d: The decay delay (in ns)
 *
 * Decay delay defines the interval between updates to HCA cachelines of
 * 128 bytes. This parameter is not indicative of the absolute time taken
 * to apply decay updates to the entire counter region. However, that can
 * be derived from the configured decay delay.
 *
 * E.g. monitoring a 512GB region of 64kB pages requires a 64MB counter
 * region. To apply one round of decay updates to the entire region will
 * require (64M / 128) = 524288 HCA cache lines to be updated. If @d is
 * 2048, (524288 * 2048) ns = ~1.07s is required to update the entire
 * counter region.
 *
 * If the delay is set to 0, the decay feature is disabled. Otherwise,
 * supported decay delay periods are 16ns, 32ns, 64ns ... 147573952589s.
 * Since @d is in the nanosecond scale, representing the upper bound is
 * not possible with a 64-bit integer. Moreover, such large delays are
 * impractical for most intents and purposes. So, while the hardware can
 * support it, the maximum configurable decay delay is restricted to
 * 9223372036854775808ns. The minimum and maximum decay delays are always
 * guaranteed to be 32ns and 9223372036854775808ns respectively if the
 * specified value is out of bounds.
 */
#define HCA_DECAY_DELAY(d)		((d) ? min((uint64_t)9223372036854775808ULL, max((uint64_t)16, (uint64_t)roundup_pow_of_two(d))) : (uint64_t)0)
/* 1 msec */
#define HCA_DECAY_DELAY_DEFAULT		1

/* Entry constants and helpers */
#define HCA_ENTRY_SIZE		8

/*
 * @v: The raw value of the entry
 * @s: The start of the bitfield
 * @n: The length of the bitfield
 */
#define HCA_ENTRY_FIELD(v, s, n)	(((v) >> ( 64 - (s + n))) & ((1UL << (n)) - 1))

/*
 * The value of the HCA count is : 4^e * m
 * e = X[0:3], m = X[4:15]
 */
#define HCA_ENTRY_COUNT_EXP(e)		HCA_ENTRY_FIELD((e), 0, 4)
#define HCA_ENTRY_COUNT_MNT(e)		HCA_ENTRY_FIELD((e), 4, 12)
#define HCA_ENTRY_COUNT(e)		((1UL << (2 * HCA_ENTRY_COUNT_EXP(e))) * HCA_ENTRY_COUNT_MNT(e))

#define HCA_ENTRY_AGE(e)		HCA_ENTRY_FIELD((e), 16, 3)

#define HCA_ENTRY_GEN(e)		HCA_ENTRY_FIELD((e), 19, 1)

/*
 * The value of the HCA prev_count is : 4^e * m
 * e = X[0:3], m = X[4:11]
 */
#define HCA_ENTRY_PREV_COUNT_EXP_LENGTH	4
#define HCA_ENTRY_PREV_COUNT_EXP_START	20
#define HCA_ENTRY_PREV_COUNT_MNT_LENGTH	8
#define HCA_ENTRY_PREV_COUNT_MNT_START	24
#define HCA_ENTRY_PREV_COUNT_EXP(e)	HCA_ENTRY_FIELD((e), 20, 4)
#define HCA_ENTRY_PREV_COUNT_MNT(e)	HCA_ENTRY_FIELD((e), 24, 8)
#define HCA_ENTRY_PREV_COUNT(e)		((1UL << (2 * HCA_ENTRY_PREV_COUNT_EXP(e))) * HCA_ENTRY_PREV_COUNT_MNT(e))

#define HCA_ENTRY_TIMELOG_LENGTH	7
#define HCA_ENTRY_TIMELOG_START		32
#define HCA_ENTRY_TIMELOG(e)		HCA_ENTRY_FIELD((e), 32, 7)

#define HCA_ENTRY_SOCKETID_COUNT	5
#define HCA_ENTRY_SOCKETID_LENGTH	5
#define HCA_ENTRY_SOCKETID_START(s)	(39 + (s) * HCA_ENTRY_SOCKETID_LENGTH)
#define HCA_ENTRY_SOCKETID(e, s)	HCA_ENTRY_FIELD((e), HCA_ENTRY_SOCKETID_START(s), HCA_ENTRY_SOCKETID_LENGTH)

struct hca_entry {
	unsigned long count;
	uint8_t age;
	uint8_t gen;
	unsigned long prev_count;
	uint8_t timelog;
	uint8_t socketid[HCA_ENTRY_SOCKETID_COUNT];
};

static inline unsigned long hotness_score(struct hca_entry * entry)
{
	unsigned long hotness;

	/*
	 * Give more weightage to the prev_count because it got
	 * historical values. Take smaller part of count as we
	 * age more because prev_count would be a better approximation.
	 * We still need to consider count to accomidate spike in access.
	 * + 1 with age to handle age == 0.
	 */
	hotness = entry->prev_count + (entry->count / (entry->age + 1));

	return hotness;
}

extern bool hca_lru_age;
extern bool hca_lru_evict;
extern int  (*hca_pfn_entry)(unsigned long pfn, struct hca_entry *entry);
extern bool (*hca_node_enabled)(int numa_node);
extern void (*hca_backend_node_debugfs_init)(int numa_node, struct dentry *node_dentry);
extern void (*hca_backend_debugfs_init)(struct dentry *root_dentry);
extern int  (*hca_clear_entry)(unsigned long pfn);
int map_hca_lru_seq(struct lruvec *lruvec, struct folio *folio);
bool hca_try_to_inc_max_seq(struct lruvec *lruvec, unsigned long nr_to_scan, unsigned long max_seq);
void restablish_hotness_range(int node);
#endif /* _ASM_POWERPC_HCA_H */
