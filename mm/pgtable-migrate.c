/* Copyright (C) 2020 VMware, Inc. */
// SPDX-License-Identifier: GPL-2.0

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/highmem.h>
#include <linux/mm_types.h>
#include <linux/sched/signal.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/sched/mm.h>

#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "internal.h"

#define PGALLOC_GFP (GFP_KERNEL_ACCOUNT | __GFP_ZERO)

#ifdef CONFIG_HIGHPTE
#define PGALLOC_USER_GFP __GFP_HIGHMEM
#else
#define PGALLOC_USER_GFP 0
#endif

static inline bool misplaced_pgtable(struct page *page, int nid)
{

	if (nid == NUMA_NO_NODE || page_to_nid(page) == nid)
		return false;

	return true;
}

static inline void copy_pgtable(struct page *dst, struct page *src)
{
	void *to, *from;

	to = kmap_atomic(dst);
	from = kmap_atomic(src);
	copy_page(to, from);
	kunmap_atomic(to);
	kunmap_atomic(from);
}

pud_t *mm_find_pud(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud))
		goto out;

	return pud;
out:
	return NULL;
}

static inline spinlock_t *p4d_lockptr(struct mm_struct *mm, p4d_t *p4d)
{
	return &mm->page_table_lock;
}

static struct page *alloc_pgtable_page(int nid)
{
	struct page *page;
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO;

	if (nid != -1)
		page = alloc_pages_node(nid, gfp, 0);
	else
		page = alloc_pages(gfp, 0);

	if (!page)
		return NULL;
	if (!pgtable_pmd_page_ctor(page)) {
		__free_pages(page, 0);
		return NULL;
	}
	return page;
}

static inline void withdraw_pmd_pgtables(struct mm_struct *mm, pud_t *pud,
	unsigned long addr, unsigned long end, pgtable_t *pgtables)
{
	int count = 0;
	pmd_t *pmd;
	spinlock_t *ptl;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;
		if (pmd_trans_huge(*pmd)) {
			ptl = pmd_lock(mm, pmd);
			pgtables[count++] = pgtable_trans_huge_withdraw(mm, pmd);
			spin_unlock(ptl);
		}
	} while (pmd++, addr = next, addr != end);
}

static inline void deposit_pmd_pgtables(struct mm_struct *mm, pud_t *pud,
		unsigned long addr, unsigned long end, pgtable_t *pgtables)
{
	int count = 0;
	pmd_t *pmd;
	spinlock_t *ptl;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;
		if (pmd_trans_huge(*pmd)) {
			BUG_ON(!pgtables[count]);
			ptl = pmd_lock(mm, pmd);
			pgtable_trans_huge_deposit(mm, pmd, pgtables[count++]);
			spin_unlock(ptl);
		}
	} while (pmd++, addr = next, addr != end);
}

#define MAX_NUMA_NODES		8
enum {
	PGTABLE_PGD_LEVEL,
	PGTABLE_P4D_LEVEL = PGTABLE_PGD_LEVEL,
	PGTABLE_PUD_LEVEL,
	PGTABLE_PMD_LEVEL,
	PGTABLE_PTE_LEVEL,
	NR_PGTABLE_LEVELS
};

/*
 * The pgtable should be fairly populated to make useful migration decisions.
 * However, the upper levels map much larger memory so threshold depends on the
 * layer.
 */
int pgtable_population_threshold[NR_PGTABLE_LEVELS] = {1, 1, 1, 1};

static int get_optimal_pgtable_node(int *count, int level)
{
	int nid, total, max;

	max = 0;
	total = count[0];
	for (nid = 1; nid < MAX_NUMA_NODES; nid++) {
		total += count[nid];
		if (count[nid] > count[max])
			max = nid;
	}

	if (total >= pgtable_population_threshold[level])
		return max;

	return NUMA_NO_NODE;
}

static int calc_pte_pgtable_optimal_node(struct vm_area_struct *vma, pmd_t *pmd,
					unsigned long addr)
{
	pte_t *pte;
	int nid, count[MAX_NUMA_NODES] = {0};
	unsigned long end;

	end = pmd_addr_end(addr, min(addr + PMD_SIZE, vma->vm_end));
	pte = pte_offset_map(pmd, addr);
	for(;;) {
		if (pte_none(*pte))
			goto next;

		nid = pfn_to_nid(pte_pfn(*pte));
		if (nid == NUMA_NO_NODE)
			goto next;

		count[nid]++;
next:
		addr += PAGE_SIZE;
		if (addr == end)
			break;
		pte++;
	};

	pte_unmap(pte);
	count_vm_numa_events(NUMA_PGTABLE_PTE_SCANNED, 1);
	return get_optimal_pgtable_node(count, PGTABLE_PTE_LEVEL);
}

/*
 * PMD is a regular PMD here, pointing to a PTE table
 * TODO: Verify the sequence of operations here. It may be safer to
 * invalidate the PMD entry first, before migrating the PMD table.
 */
static bool migrate_pte_pgtable(struct mm_struct *mm, pmd_t *pmd,
				unsigned long addr, int *new_nid)
{
	pmd_t new_pmd;
	int nid;
	bool result = false;
	struct page *src, *dst;
	struct vm_area_struct *vma;
	spinlock_t *ptl;

	vma = find_vma(mm, addr);
	if (!vma)
		return false;

	nid = calc_pte_pgtable_optimal_node(vma, pmd, addr);
	src = pfn_to_page(pmd_pfn(*pmd));
	/* check if we need to migrate at all */
	if (likely(!misplaced_pgtable(src, nid)))
		return false;

	dst = alloc_pgtable_page(nid);
	if (unlikely(!dst))
		return false;

	new_pmd = __pmd(((pteval_t)page_to_pfn(dst) << PAGE_SHIFT) | _PAGE_TABLE);
	smp_wmb();
	up_read(&mm->mmap_sem);
	mmu_notifier_invalidate_range_start(mm, addr, addr + HPAGE_PMD_SIZE);
	/* prevent all accesses to page tables */
	down_write(&mm->mmap_sem);
	/* lock the page-table */
	ptl = pmd_lockptr(mm, pmd);
	spin_lock(ptl);
	/* verify if the tables has been updated somewhere */
	if (mm_find_pmd(mm, addr) != pmd) {
		printk(KERN_INFO"PMD modified in-between migration\n");
		goto out;
	}
	/* invalidate the existing entry first */
	pmdp_invalidate(vma, addr, pmd);
	copy_pgtable(dst, src);
	/* set_pmd(pmd, new_pmd); */
	pmd_populate(mm, pmd, dst);
	mmu_notifier_invalidate_range_end(mm, addr, addr + HPAGE_PMD_SIZE);
	__free_page(src);
	*new_nid = nid;
	count_vm_numa_events(NUMA_PGTABLE_PTE_MIGRATED, 1);
	result = true;

out:
	spin_unlock(ptl);
	up_write(&mm->mmap_sem);
	down_read(&mm->mmap_sem);
	return result;
}

/*
 * Trick here is to migrate deposited pgtables as well. We cannot
 * risk allocation failure here so simply re-use the pgtables
 * deposited in the older PMD table.
 * TODO: Verify the sequence of operations here. It may be safer to
 * invalidate the PUD entry first, before migrating the PMD table.
 */
static bool migrate_pmd_pgtable(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, int nid)
{
	int source_nid;
	pmd_t *new_pmd;
	pgtable_t *pgtables;
	struct page *src, *dst;
	struct vm_area_struct *vma;
	unsigned long end;
	spinlock_t *ptl;

	vma = find_vma(mm, addr);
	if (!vma)
		return false;

	end = pud_addr_end(addr, min(vma->vm_end, addr + PUD_SIZE));
	src = pfn_to_page(pud_pfn(*pud));
	source_nid = page_to_nid(src);
	/* check if we need to migrate at all */
	if (likely(!misplaced_pgtable(src, nid)))
		return false;

	dst = alloc_pgtable_page(nid);
	if (unlikely(!dst))
		return false;

	pgtables = kmalloc(HPAGE_PMD_NR * sizeof(pgtable_t *), GFP_KERNEL);
	if (unlikely(!pgtables))
		return false;

	smp_wmb();
	up_read(&mm->mmap_sem);
	down_write(&mm->mmap_sem);
	mmu_notifier_invalidate_range_start(mm, addr, end);
	ptl = pud_lockptr(mm, pud);
	spin_lock(ptl);
	/* verify if the tables has been updated somewhere */
	if (mm_find_pud(mm, addr) != pud) {
		printk(KERN_INFO"PMD modified in-between migration\n");
		goto out;
	}
	/* we need to withdraw pgtables from this PMD page first */
	withdraw_pmd_pgtables(mm, pud, addr, end, pgtables);
	pud_clear(pud);
	copy_pgtable(dst, src);
	new_pmd = (pmd_t *)page_address(dst);
	pud_populate(mm, pud, new_pmd);
	deposit_pmd_pgtables(mm, pud, addr, end, pgtables);
	flush_tlb_range(vma, addr, end);
	mmu_notifier_invalidate_range_end(mm, addr, end);
	__free_page(src);
	count_vm_numa_events(NUMA_PGTABLE_PMD_MIGRATED, 1);
out:
	spin_unlock(ptl);
	up_write(&mm->mmap_sem);
	down_read(&mm->mmap_sem);
	kfree(pgtables);
	return true;
}

/*
 * TODO: Verify the sequence of operations here. It may be safer to
 * invalidate the P4D entry first, before migrating the PMD table.
 */
static bool migrate_pud_pgtable(struct mm_struct *mm, p4d_t *p4d,
			unsigned long addr, int nid)
{
        spinlock_t *ptl;
        int source_nid;
        struct page *src, *dst;
        struct vm_area_struct *vma;

        vma = find_vma(mm, addr);
        if (!vma)
                return false;

        src = pfn_to_page(p4d_pfn(*p4d));
        source_nid = page_to_nid(src);
        /* check if we need to migrate at all */
	if (likely(!misplaced_pgtable(src, nid)))
		return false;

        dst = alloc_pgtable_page(nid);
        if (unlikely(!dst))
                return false;

        smp_wmb();
	up_read(&mm->mmap_sem);
	down_write(&mm->mmap_sem);
        ptl = p4d_lockptr(mm, p4d);
        mmu_notifier_invalidate_range_start(mm, addr, addr + PUD_SIZE);
        spin_lock(ptl);
	copy_pgtable(dst, src);
        p4d_populate(mm, p4d, (pud_t *)page_address(dst));
	/* even if va->pa mappings dont change, we need this to flush page-walk caches */
        flush_tlb_range(vma, addr, addr + PUD_SIZE);
        spin_unlock(ptl);
        mmu_notifier_invalidate_range_end(mm, addr, addr + PUD_SIZE);
        __free_page(src);
	count_vm_numa_events(NUMA_PGTABLE_PUD_MIGRATED, 1);
	up_write(&mm->mmap_sem);
	down_read(&mm->mmap_sem);
        return true;
}

/*
 * Scan and migrate the next level (PTE) first.
 * This helps in determining the optimal placement of PMD pgtable.
 * Return new node identifier if PMD pgtable is migrated to a different socket.
 * Else, return the original node id.
 */
static int scan_pmd_range(struct mm_struct *mm, pud_t *pud, unsigned long addr,
				unsigned long end)
{
	pmd_t *pmd;
	int old_nid, new_nid, count[MAX_NUMA_NODES] = {0};
	unsigned long next, start = addr;

	old_nid = pfn_to_nid(pud_pfn(*pud));
	/*
	 * Process all the children first.
	 */
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;

		if (pmd_trans_huge(*pmd)) {
			count[pfn_to_nid(pmd_pfn(*pmd))]++;
			continue;
		}

		if(migrate_pte_pgtable(mm, pmd, addr, &new_nid))
			count[new_nid]++;

	} while (pmd++, addr = next, addr != end);
	/*
	 * Align the PMD pgtable placement now.
	 */
	count_vm_numa_events(NUMA_PGTABLE_PMD_SCANNED, 1);
	new_nid = get_optimal_pgtable_node(count, PGTABLE_PMD_LEVEL);
	if (migrate_pmd_pgtable(mm, pud, start, new_nid))
		return new_nid;

	return old_nid;
}

/*
 * Scan and migrate the next level (PMD) first.
 * This helps in determining the optimal placement of PUD pgtable.
 */
static int scan_pud_range(struct mm_struct *mm, p4d_t *p4d, unsigned long addr,
				unsigned long end)
{
	pud_t *pud;
	int old_nid, new_nid, count[MAX_NUMA_NODES] = {0};
	unsigned long next, start = addr;

	old_nid = pfn_to_nid(p4d_pfn(*p4d));
	/* process the children first */
	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*pud))
			continue;
		if (pud_trans_huge(*pud)) {
			count[pud_pfn(*pud)]++;
			continue;
		}

		new_nid = scan_pmd_range(mm, pud, addr, next);
		count[new_nid]++;
	} while (pud++, addr = next, addr != end);

	/*
	 * Align the PUD pgtable placement now.
	 */
	count_vm_numa_events(NUMA_PGTABLE_PUD_SCANNED, 1);
	new_nid = get_optimal_pgtable_node(count, PGTABLE_PUD_LEVEL);
	if (migrate_pud_pgtable(mm, p4d, start, new_nid))
		return new_nid;

	return old_nid;
}

/*
 * No support to migrate P4D pgtables yet.
 */
static void scan_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
		struct mm_struct *mm)
{
	p4d_t *p4d;
	unsigned long next;

	/* process the children first */
	p4d = p4d_offset(pgd, addr);
	do {
		next =  p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;

		scan_pud_range(mm, p4d, addr, next);
	} while(p4d++, addr = next, addr != end);
}

/*
 * No support to migrate PGD pgtables yet.
 */
static void scan_pgd_range(struct mm_struct *mm, unsigned long addr, unsigned long end,
		bool migrate)
{
	pgd_t *pgd;
	unsigned long next;

	pgd = pgd_offset(mm, addr);
	do {
		next =  pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;

		scan_p4d_range(pgd, addr, next, mm);
	} while (pgd++, addr = next, addr != end);
}

void task_pgtables_work(struct mm_struct *mm, bool bypass_autonuma)
{
	struct vm_area_struct *vma;
	unsigned long start, end;

	/*
	 * pgtable migration is primarily for large memory workloads.
	 * ignore smaller than 1GB processes.
	 */
	if (get_mm_rss(mm) < 250000)
		return;

	if (!bypass_autonuma)
		start = mm->pgtable_scan_offset;
	else
		start = 0;

	vma = find_vma(mm, start);
	if (!vma) {
		start = 0;
		vma = mm->mmap;
	}

	for (; vma; vma = vma->vm_next) {
		/*
		 * There is no need to be aggressive here.
		 * Let AutoNUMA process the VMA before making pgtable placement decisions.
		 */
		if ((vma->numa_scan_seq <= vma->pgtable_scan_seq) && !bypass_autonuma)
			continue;

		if (!vma_migratable(vma) || !vma_policy_mof(vma) ||
			is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_MIXEDMAP)) {
			goto vma_done;
		}
		/* ignore shared library pages */
		if (!vma->vm_mm ||
			(vma->vm_file && (vma->vm_flags & (VM_READ|VM_WRITE)) == (VM_READ)))
			goto vma_done;

		/* ignore inaccessible vmas */
		if (!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE)))
			goto vma_done;

		start = max(start, vma->vm_start);
		end = vma->vm_end;
		/*
		 * Scan the entire leftover range of the vma.
		 * We can optimize this later to migrate pgtables incrementally.
		 */
		scan_pgd_range(mm, start, end, true);
vma_done:
		if (!bypass_autonuma)
			WRITE_ONCE(vma->pgtable_scan_seq, READ_ONCE(vma->pgtable_scan_seq) + 1);
	}
	if (!bypass_autonuma) {
		if (vma)
			mm->pgtable_scan_offset = start;
		else
			mm->pgtable_scan_offset = 0;
	}
}

int sysctl_numa_migrate_pid_pgtable_ctl(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct task_struct *task = NULL;
	struct pid *pid_struct = NULL;
	struct mm_struct *mm;
	struct ctl_table t;
	int err, pid = 0;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &pid;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write) {
		if (pid < 2)
			return -EINVAL;

		pid_struct = find_get_pid(pid);
		if (!pid_struct) {
			printk("pid %d not found\n", pid);
			return -EINVAL;
		}

		task = pid_task(pid_struct, PIDTYPE_PID);
		if (!task) {
			printk("task_struct not found for pid %d\n", pid);
			return -EINVAL;
		}
		mm = get_task_mm(task);
		down_read(&mm->mmap_sem);
		printk("migrate pgtables of pid: %d %s\n", pid, task->comm);
		task_pgtables_work(mm, true);
		up_read(&mm->mmap_sem);
		mmput(mm);
	}
	printk("pgtable migration complete\n");
	return err;
}
