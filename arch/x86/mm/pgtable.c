/* Copyright (C) 2018-2020 VMware, Inc. */
// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/hugetlb.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>
#include <asm/fixmap.h>
#include <asm/mtrr.h>
#include <linux/swapops.h>


#define PGALLOC_GFP (GFP_KERNEL_ACCOUNT | __GFP_ZERO)

#ifdef CONFIG_HIGHPTE
#define PGALLOC_USER_GFP __GFP_HIGHMEM
#else
#define PGALLOC_USER_GFP 0
#endif


#ifdef CONFIG_PGTABLE_REPLICATION
void pgtable_cache_free(int node, struct page *p);
struct page *pgtable_cache_alloc(int node);
#endif

gfp_t __userpte_alloc_gfp = PGALLOC_GFP | PGALLOC_USER_GFP;

pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
	struct page *page;

	page = alloc_page_ptable(PGALLOC_GFP & ~__GFP_ACCOUNT);
	if (page) {
			return (pte_t *) page_to_virt(page);
	}
	return NULL;
}

pgtable_t pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

	pte = alloc_page_ptable(__userpte_alloc_gfp);

	if (!pte)
		return NULL;
	if (!pgtable_page_ctor(pte)) {
		__free_page(pte);
		return NULL;
	}
	return pte;
}

static int __init setup_userpte(char *arg)
{
	if (!arg)
		return -EINVAL;

	/*
	 * "userpte=nohigh" disables allocation of user pagetables in
	 * high memory.
	 */
	if (strcmp(arg, "nohigh") == 0)
		__userpte_alloc_gfp &= ~__GFP_HIGHMEM;
	else
		return -EINVAL;
	return 0;
}
early_param("userpte", setup_userpte);

void ___pte_free_tlb(struct mmu_gather *tlb, struct page *pte)
{
	pgtable_page_dtor(pte);
	paravirt_release_pte(page_to_pfn(pte));
	tlb_remove_table(tlb, pte);
}

#if CONFIG_PGTABLE_LEVELS > 2
void ___pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd)
{
	struct page *page = virt_to_page(pmd);
	paravirt_release_pmd(__pa(pmd) >> PAGE_SHIFT);
	/*
	 * NOTE! For PAE, any changes to the top page-directory-pointer-table
	 * entries need a full cr3 reload to flush.
	 */
#ifdef CONFIG_X86_PAE
	tlb->need_flush_all = 1;
#endif
	pgtable_pmd_page_dtor(page);
	tlb_remove_table(tlb, page);
}

#if CONFIG_PGTABLE_LEVELS > 3
void ___pud_free_tlb(struct mmu_gather *tlb, pud_t *pud)
{
	paravirt_release_pud(__pa(pud) >> PAGE_SHIFT);
	tlb_remove_table(tlb, virt_to_page(pud));
}

#if CONFIG_PGTABLE_LEVELS > 4
void ___p4d_free_tlb(struct mmu_gather *tlb, p4d_t *p4d)
{
	paravirt_release_p4d(__pa(p4d) >> PAGE_SHIFT);
	tlb_remove_table(tlb, virt_to_page(p4d));
}
#endif	/* CONFIG_PGTABLE_LEVELS > 4 */
#endif	/* CONFIG_PGTABLE_LEVELS > 3 */
#endif	/* CONFIG_PGTABLE_LEVELS > 2 */

static inline void pgd_list_add(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_add(&page->lru, &pgd_list);
}

static inline void pgd_list_del(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_del(&page->lru);
}

#define UNSHARED_PTRS_PER_PGD				\
	(SHARED_KERNEL_PMD ? KERNEL_PGD_BOUNDARY : PTRS_PER_PGD)


static void pgd_set_mm(pgd_t *pgd, struct mm_struct *mm)
{
	BUILD_BUG_ON(sizeof(virt_to_page(pgd)->index) < sizeof(mm));
	virt_to_page(pgd)->index = (pgoff_t)mm;
}

struct mm_struct *pgd_page_get_mm(struct page *page)
{
	return (struct mm_struct *)page->index;
}

static void pgd_ctor(struct mm_struct *mm, pgd_t *pgd)
{
	/* If the pgd points to a shared pagetable level (either the
	   ptes in non-PAE, or shared PMD in PAE), then just copy the
	   references from swapper_pg_dir. */
	if (CONFIG_PGTABLE_LEVELS == 2 ||
	    (CONFIG_PGTABLE_LEVELS == 3 && SHARED_KERNEL_PMD) ||
	    CONFIG_PGTABLE_LEVELS >= 4) {
		clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY,
				swapper_pg_dir + KERNEL_PGD_BOUNDARY,
				KERNEL_PGD_PTRS);
	}

	/* list required to sync kernel mapping updates */
	if (!SHARED_KERNEL_PMD) {
		pgd_set_mm(pgd, mm);
		pgd_list_add(pgd);
	}
}

static void pgd_dtor(pgd_t *pgd)
{
	if (SHARED_KERNEL_PMD)
		return;

	spin_lock(&pgd_lock);
	pgd_list_del(pgd);
	spin_unlock(&pgd_lock);
}

/*
 * List of all pgd's needed for non-PAE so it can invalidate entries
 * in both cached and uncached pgd's; not needed for PAE since the
 * kernel pmd is shared. If PAE were not to share the pmd a similar
 * tactic would be needed. This is essentially codepath-based locking
 * against pageattr.c; it is the unique case in which a valid change
 * of kernel pagetables can't be lazily synchronized by vmalloc faults.
 * vmalloc faults work because attached pagetables are never freed.
 * -- nyc
 */

#ifdef CONFIG_X86_PAE
/*
 * In PAE mode, we need to do a cr3 reload (=tlb flush) when
 * updating the top-level pagetable entries to guarantee the
 * processor notices the update.  Since this is expensive, and
 * all 4 top-level entries are used almost immediately in a
 * new process's life, we just pre-populate them here.
 *
 * Also, if we're in a paravirt environment where the kernel pmd is
 * not shared between pagetables (!SHARED_KERNEL_PMDS), we allocate
 * and initialize the kernel pmds here.
 */
#define PREALLOCATED_PMDS	UNSHARED_PTRS_PER_PGD

void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmd)
{
	paravirt_alloc_pmd(mm, __pa(pmd) >> PAGE_SHIFT);

	/* Note: almost everything apart from _PAGE_PRESENT is
	   reserved at the pmd (PDPT) level. */
	set_pud(pudp, __pud(__pa(pmd) | _PAGE_PRESENT));

	/*
	 * According to Intel App note "TLBs, Paging-Structure Caches,
	 * and Their Invalidation", April 2007, document 317080-001,
	 * section 8.1: in PAE mode we explicitly have to flush the
	 * TLB via cr3 if the top-level pgd is changed...
	 */
	flush_tlb_mm(mm);
}
#else  /* !CONFIG_X86_PAE */

/* No need to prepopulate any pagetable entries in non-PAE modes. */
#define PREALLOCATED_PMDS	0

#endif	/* CONFIG_X86_PAE */

static void free_pmds(struct mm_struct *mm, pmd_t *pmds[])
{
	int i;

	for(i = 0; i < PREALLOCATED_PMDS; i++)
		if (pmds[i]) {
			pgtable_pmd_page_dtor(virt_to_page(pmds[i]));
			free_page((unsigned long)pmds[i]);
			mm_dec_nr_pmds(mm);
		}
}

static int preallocate_pmds(struct mm_struct *mm, pmd_t *pmds[])
{
	int i;
	bool failed = false;
	gfp_t gfp = PGALLOC_GFP;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;

	for(i = 0; i < PREALLOCATED_PMDS; i++) {
		struct page *page;
		pmd_t *pmd = NULL;

		page = alloc_page_ptable(gfp);
		if (page) {
			pmd  = (pmd_t *) page_to_virt(page);
		}

		if (!pmd)
			failed = true;
		if (pmd && !pgtable_pmd_page_ctor(virt_to_page(pmd))) {
			free_page((unsigned long)pmd);
			pmd = NULL;
			failed = true;
		}
		if (pmd)
			mm_inc_nr_pmds(mm);
		pmds[i] = pmd;
	}

	if (failed) {
		free_pmds(mm, pmds);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Mop up any pmd pages which may still be attached to the pgd.
 * Normally they will be freed by munmap/exit_mmap, but any pmd we
 * preallocate which never got a corresponding vma will need to be
 * freed manually.
 */
static void pgd_mop_up_pmds(struct mm_struct *mm, pgd_t *pgdp)
{
	int i;

	for(i = 0; i < PREALLOCATED_PMDS; i++) {
		pgd_t pgd = pgdp[i];

		if (pgd_val(pgd) != 0) {
			pmd_t *pmd = (pmd_t *)pgd_page_vaddr(pgd);

			pgdp[i] = native_make_pgd(0);

			paravirt_release_pmd(pgd_val(pgd) >> PAGE_SHIFT);
			pmd_free(mm, pmd);
			mm_dec_nr_pmds(mm);
		}
	}
}

static void pgd_prepopulate_pmd(struct mm_struct *mm, pgd_t *pgd, pmd_t *pmds[])
{
	p4d_t *p4d;
	pud_t *pud;
	int i;

	if (PREALLOCATED_PMDS == 0) /* Work around gcc-3.4.x bug */
		return;

	p4d = p4d_offset(pgd, 0);
	pud = pud_offset(p4d, 0);

	for (i = 0; i < PREALLOCATED_PMDS; i++, pud++) {
		pmd_t *pmd = pmds[i];

		if (i >= KERNEL_PGD_BOUNDARY)
			memcpy(pmd, (pmd_t *)pgd_page_vaddr(swapper_pg_dir[i]),
			       sizeof(pmd_t) * PTRS_PER_PMD);

		pud_populate(mm, pud, pmd);
	}
}

#if (PGD_ALLOCATION_ORDER != 0)
#error "Mitosis currenlty doesn't support PGD_ALLOCATION_ORDER > 0"
#endif

/*
 * Xen paravirt assumes pgd table should be in one page. 64 bit kernel also
 * assumes that pgd should be in one page.
 *
 * But kernel with PAE paging that is not running as a Xen domain
 * only needs to allocate 32 bytes for pgd instead of one page.
 */
#ifdef CONFIG_X86_PAE

#include <linux/slab.h>

#define PGD_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))
#define PGD_ALIGN	32

static struct kmem_cache *pgd_cache;

static int __init pgd_cache_init(void)
{
	/*
	 * When PAE kernel is running as a Xen domain, it does not use
	 * shared kernel pmd. And this requires a whole page for pgd.
	 */
	if (!SHARED_KERNEL_PMD)
		return 0;

	/*
	 * when PAE kernel is not running as a Xen domain, it uses
	 * shared kernel pmd. Shared kernel pmd does not require a whole
	 * page for pgd. We are able to just allocate a 32-byte for pgd.
	 * During boot time, we create a 32-byte slab for pgd table allocation.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_ALIGN,
				      SLAB_PANIC, NULL);
	if (!pgd_cache)
		return -ENOMEM;

	return 0;
}
core_initcall(pgd_cache_init);

static inline pgd_t *_pgd_alloc(void)
{
	/*
	 * If no SHARED_KERNEL_PMD, PAE kernel is running as a Xen domain.
	 * We allocate one page for pgd.
	 */
	if (!SHARED_KERNEL_PMD)
		return (pgd_t *)__get_free_page(PGALLOC_GFP);

	/*
	 * Now PAE kernel is not running as a Xen domain. We can allocate
	 * a 32-byte slab for pgd to save memory space.
	 */
	return kmem_cache_alloc(pgd_cache, PGALLOC_GFP);
}

static inline void _pgd_free(pgd_t *pgd)
{
	if (!SHARED_KERNEL_PMD)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
}
#else

static inline pgd_t *_pgd_alloc(void)
{
	struct page *page;

	page = alloc_pages_ptable(PGALLOC_GFP, PGD_ALLOCATION_ORDER);
	if (!page)
		return 0;
	return (pgd_t *) page_to_virt(page);
}

static inline void _pgd_free(pgd_t *pgd)
{
	free_pages((unsigned long)pgd, PGD_ALLOCATION_ORDER);
}
#endif /* CONFIG_X86_PAE */

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;
	pmd_t *pmds[PREALLOCATED_PMDS];

	pgd = _pgd_alloc();

	if (pgd == NULL)
		goto out;

	mm->pgd = pgd;

	if (preallocate_pmds(mm, pmds) != 0)
		goto out_free_pgd;

	if (paravirt_pgd_alloc(mm) != 0)
		goto out_free_pmds;

	/*
	 * Make sure that pre-populating the pmds is atomic with
	 * respect to anything walking the pgd_list, so that they
	 * never see a partially populated pgd.
	 */
	spin_lock(&pgd_lock);

	pgd_ctor(mm, pgd);
	pgd_prepopulate_pmd(mm, pgd, pmds);

	spin_unlock(&pgd_lock);

	return pgd;

out_free_pmds:
	free_pmds(mm, pmds);
out_free_pgd:
	_pgd_free(pgd);
out:
	return NULL;
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	pgd_mop_up_pmds(mm, pgd);
	pgd_dtor(pgd);
	paravirt_pgd_free(mm, pgd);
	_pgd_free(pgd);
}

#ifndef CONFIG_PGTABLE_REPLICATION
/*
 * Used to set accessed or dirty bits in the page table entries
 * on other architectures. On x86, the accessed and dirty bits
 * are tracked by hardware. However, do_wp_page calls this function
 * to also make the pte writeable at the same time the dirty bit is
 * set. In that case we do actually need to write the PTE.
 */
int ptep_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pte_t *ptep,
			  pte_t entry, int dirty)
{
	int changed = !pte_same(get_pte(ptep), entry);
	if (changed) {
		set_pte(ptep, entry);
	}
	return changed;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
int pmdp_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp,
			  pmd_t entry, int dirty)
{
	int changed = !pmd_same(get_pmd(pmdp), entry);

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);

	if (changed && dirty) {
		set_pmd(pmdp, entry);
		/*
		 * We had a write-protection fault here and changed the pmd
		 * to to more permissive. No need to flush the TLB for that,
		 * #PF is architecturally guaranteed to do that and in the
		 * worst-case we'll generate a spurious fault.
		 */
	}

	return changed;
}

int pudp_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			  pud_t *pudp, pud_t entry, int dirty)
{
	int changed = !pud_same(get_pud(pudp), entry);

	VM_BUG_ON(address & ~HPAGE_PUD_MASK);
	if (changed && dirty) {
		set_pud(pudp, entry);
		/*
		 * We had a write-protection fault here and changed the pud
		 * to to more permissive. No need to flush the TLB for that,
		 * #PF is architecturally guaranteed to do that and in the
		 * worst-case we'll generate a spurious fault.
		 */
	}

	return changed;
}
#endif

int ptep_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long addr, pte_t *ptep)
{
	int ret = 0;

	if (pte_young(*ptep))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *) &ptep->pte);

	return ret;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
int pmdp_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long addr, pmd_t *pmdp)
{
	int ret = 0;

	if (pmd_young(get_pmd(pmdp)))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *)pmdp);

	return ret;
}
int pudp_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long addr, pud_t *pudp)
{
	int ret = 0;

	if (pud_young(get_pud(pudp)))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *)pudp);

	return ret;
}
#endif
#endif

int ptep_clear_flush_young(struct vm_area_struct *vma,
			   unsigned long address, pte_t *ptep)
{
	/*
	 * On x86 CPUs, clearing the accessed bit without a TLB flush
	 * doesn't cause data corruption. [ It could cause incorrect
	 * page aging and the (mistaken) reclaim of hot pages, but the
	 * chance of that should be relatively low. ]
	 *
	 * So as a performance optimization don't flush the TLB when
	 * clearing the accessed bit, it will eventually be flushed by
	 * a context switch or a VM operation anyway. [ In the rare
	 * event of it not getting flushed for a long time the delay
	 * shouldn't really matter because there's no real memory
	 * pressure for swapout to react to. ]
	 */
	return ptep_test_and_clear_young(vma, address, ptep);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
int pmdp_clear_flush_young(struct vm_area_struct *vma,
			   unsigned long address, pmd_t *pmdp)
{
	int young;

	VM_BUG_ON(address & ~HPAGE_PMD_MASK);

	young = pmdp_test_and_clear_young(vma, address, pmdp);
	if (young)
		flush_tlb_range(vma, address, address + HPAGE_PMD_SIZE);

	return young;
}
#endif

/**
 * reserve_top_address - reserves a hole in the top of kernel address space
 * @reserve - size of hole to reserve
 *
 * Can be used to relocate the fixmap area and poke a hole in the top
 * of kernel address space to make room for a hypervisor.
 */
void __init reserve_top_address(unsigned long reserve)
{
#ifdef CONFIG_X86_32
	BUG_ON(fixmaps_set > 0);
	__FIXADDR_TOP = round_down(-reserve, 1 << PMD_SHIFT) - PAGE_SIZE;
	printk(KERN_INFO "Reserving virtual address space above 0x%08lx (rounded to 0x%08lx)\n",
	       -reserve, __FIXADDR_TOP + PAGE_SIZE);
#endif
}

int fixmaps_set;

void __native_set_fixmap(enum fixed_addresses idx, pte_t pte)
{
	unsigned long address = __fix_to_virt(idx);

	if (idx >= __end_of_fixed_addresses) {
		BUG();
		return;
	}
	set_pte_vaddr(address, pte);
	fixmaps_set++;
}

void native_set_fixmap(enum fixed_addresses idx, phys_addr_t phys,
		       pgprot_t flags)
{
	/* Sanitize 'prot' against any unsupported bits: */
	pgprot_val(flags) &= __default_kernel_pte_mask;

	__native_set_fixmap(idx, pfn_pte(phys >> PAGE_SHIFT, flags));
}

#ifdef CONFIG_HAVE_ARCH_HUGE_VMAP
#ifdef CONFIG_X86_5LEVEL
/**
 * p4d_set_huge - setup kernel P4D mapping
 *
 * No 512GB pages yet -- always return 0
 */
int p4d_set_huge(p4d_t *p4d, phys_addr_t addr, pgprot_t prot)
{
	return 0;
}

/**
 * p4d_clear_huge - clear kernel P4D mapping when it is set
 *
 * No 512GB pages yet -- always return 0
 */
int p4d_clear_huge(p4d_t *p4d)
{
	return 0;
}
#endif

/**
 * pud_set_huge - setup kernel PUD mapping
 *
 * MTRRs can override PAT memory types with 4KiB granularity. Therefore, this
 * function sets up a huge page only if any of the following conditions are met:
 *
 * - MTRRs are disabled, or
 *
 * - MTRRs are enabled and the range is completely covered by a single MTRR, or
 *
 * - MTRRs are enabled and the corresponding MTRR memory type is WB, which
 *   has no effect on the requested PAT memory type.
 *
 * Callers should try to decrease page size (1GB -> 2MB -> 4K) if the bigger
 * page mapping attempt fails.
 *
 * Returns 1 on success and 0 on failure.
 */
int pud_set_huge(pud_t *pud, phys_addr_t addr, pgprot_t prot)
{
	u8 mtrr, uniform;

	mtrr = mtrr_type_lookup(addr, addr + PUD_SIZE, &uniform);
	if ((mtrr != MTRR_TYPE_INVALID) && (!uniform) &&
	    (mtrr != MTRR_TYPE_WRBACK))
		return 0;

	/* Bail out if we are we on a populated non-leaf entry: */
	if (pud_present(*pud) && !pud_huge(*pud))
		return 0;

	prot = pgprot_4k_2_large(prot);

	set_pte((pte_t *)pud, pfn_pte(
		(u64)addr >> PAGE_SHIFT,
		__pgprot(pgprot_val(prot) | _PAGE_PSE)));

	return 1;
}

/**
 * pmd_set_huge - setup kernel PMD mapping
 *
 * See text over pud_set_huge() above.
 *
 * Returns 1 on success and 0 on failure.
 */
int pmd_set_huge(pmd_t *pmd, phys_addr_t addr, pgprot_t prot)
{
	u8 mtrr, uniform;

	mtrr = mtrr_type_lookup(addr, addr + PMD_SIZE, &uniform);
	if ((mtrr != MTRR_TYPE_INVALID) && (!uniform) &&
	    (mtrr != MTRR_TYPE_WRBACK)) {
		pr_warn_once("%s: Cannot satisfy [mem %#010llx-%#010llx] with a huge-page mapping due to MTRR override.\n",
			     __func__, addr, addr + PMD_SIZE);
		return 0;
	}

	/* Bail out if we are we on a populated non-leaf entry: */
	if (pmd_present(*pmd) && !pmd_huge(*pmd))
		return 0;

	prot = pgprot_4k_2_large(prot);

	set_pte((pte_t *)pmd, pfn_pte(
		(u64)addr >> PAGE_SHIFT,
		__pgprot(pgprot_val(prot) | _PAGE_PSE)));

	return 1;
}

/**
 * pud_clear_huge - clear kernel PUD mapping when it is set
 *
 * Returns 1 on success and 0 on failure (no PUD map is found).
 */
int pud_clear_huge(pud_t *pud)
{
	if (pud_large(*pud)) {
		pud_clear(pud);
		return 1;
	}

	return 0;
}

/**
 * pmd_clear_huge - clear kernel PMD mapping when it is set
 *
 * Returns 1 on success and 0 on failure (no PMD map is found).
 */
int pmd_clear_huge(pmd_t *pmd)
{
	if (pmd_large(*pmd)) {
		pmd_clear(pmd);
		return 1;
	}

	return 0;
}

#ifdef CONFIG_PGTABLE_REPLICATION

/*
 * ===============================================================================
 * Free Sub Page Tables
 * ===============================================================================
 */


/**
 * pmd_free_pte_page - Clear pmd entry and free pte page.
 * @pmd: Pointer to a PMD.
 *
 * Context: The pmd range has been unmaped and TLB purged.
 * Return: 1 if clearing the entry succeeded. 0 otherwise.
 */
int pmd_free_pte_page(pmd_t *pmd)
{
	int i;
	pte_t *pte;
	struct page *page, *pcurrent;

	if (pmd_none(*pmd))
		return 1;

	pte = (pte_t *)pmd_page_vaddr(*pmd);
	pmd_clear(pmd);

	page = virt_to_page(pte);
	if (page != NULL) {
		page = page->replica;
		for (i = 0; i < nr_node_ids && page; i++) {
			pcurrent = page;
			page = page->replica;
			pgtable_cache_free(i, pcurrent);
		}
	}

	free_page((unsigned long)pte);

	return 1;
}

/**
 * pupd_free_pmd_page - Clear pud entry and free pmd page.
 * @pud: Pointer to a PUD.
 *
 * Context: The pud range has been unmaped and TLB purged.
 * Return: 1 if clearing the entry succeeded. 0 otherwise.
 */
int pud_free_pmd_page(pud_t *pud)
{
	struct page *page, *pcurrent;
	pmd_t *pmd;
	int i;

	if (pud_none(*pud))
		return 1;

	pmd = (pmd_t *)pud_page_vaddr(*pud);

	for (i = 0; i < PTRS_PER_PMD; i++)
		if (!pmd_free_pte_page(&pmd[i]))
			return 0;

	pud_clear(pud);

	page = virt_to_page(pmd);
	if (page != NULL) {
		page = page->replica;
		for (i = 0; i < nr_node_ids && page; i++) {
			pcurrent = page;
			page = page->replica;
			pgtable_cache_free(i, pcurrent);
		}
	}

	free_page((unsigned long)pmd);

	return 1;
}

#else // !CONFIG_PGTABLE_REPLICATION

/**
 * pud_free_pmd_page - Clear pud entry and free pmd page.
 * @pud: Pointer to a PUD.
 *
 * Context: The pud range has been unmaped and TLB purged.
 * Return: 1 if clearing the entry succeeded. 0 otherwise.
 */
int pud_free_pmd_page(pud_t *pud)
{
	pmd_t *pmd;
	int i;

	if (pud_none(*pud))
		return 1;

	pmd = (pmd_t *)pud_page_vaddr(*pud);

	for (i = 0; i < PTRS_PER_PMD; i++)
		if (!pmd_free_pte_page(&pmd[i]))
			return 0;

	pud_clear(pud);
	free_page((unsigned long)pmd);

	return 1;
}

/**
 * pmd_free_pte_page - Clear pmd entry and free pte page.
 * @pmd: Pointer to a PMD.
 *
 * Context: The pmd range has been unmaped and TLB purged.
 * Return: 1 if clearing the entry succeeded. 0 otherwise.
 */
int pmd_free_pte_page(pmd_t *pmd)
{
	pte_t *pte;

	if (pmd_none(*pmd))
		return 1;

	pte = (pte_t *)pmd_page_vaddr(*pmd);
	pmd_clear(pmd);
	free_page((unsigned long)pte);

	return 1;
}

#endif /* !CONFIG_PGTABLE_REPLICATION */
#endif	/* CONFIG_HAVE_ARCH_HUGE_VMAP */



/*
 * ==================================================================
 * Page Table replication extension using paravirt ops
 * ==================================================================
 */

#ifdef CONFIG_PGTABLE_REPLICATION

///> pgtable_repl_initialized tracks whether the system is ready for handling page table replication
static bool pgtable_repl_initialized = false;

///> tracks whether page table replication is activated for new processes by default
static bool pgtable_repl_activated = false;

///> where to allocate the page tables from
int pgtable_fixed_node = -1;
nodemask_t pgtable_fixed_nodemask = NODE_MASK_NONE;


#define MAX_SUPPORTED_NODE 8

///> page table cache
static struct page *pgtable_cache[MAX_SUPPORTED_NODE] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

///> page table cache sizes
static size_t pgtable_cache_size[MAX_SUPPORTED_NODE] = { 0 };

///> lock for the page table cache
static DEFINE_SPINLOCK(pgtable_cache_lock);


/*
 * ==================================================================
 * Debug Macros
 * ==================================================================
 */

#define DEBUG_PGTABLE_REPLICATION
#ifdef DEBUG_PGTABLE_REPLICATION

#define check_page(p) \
	if (unlikely(!(p))) { printk("PTREPL:%s:%u - page was NULL!\n", __FUNCTION__, __LINE__); }

#define check_offset(offset) if (offset >= 4096 || (offset % 8)) { \
	printk("PTREPL: %s:%d - offset=%lu, %lu\n", __FUNCTION__, __LINE__, offset, offset % 8); }

#define check_page_node(p, n) do {\
	if (!virt_addr_valid((void *)p)) {/*printk("PTREP: PAGE IS NOT VALID!\n");*/} \
	if (p == NULL) {printk("PTREPL: PAGE WAS NULL!\n");} \
	if (pfn_to_nid(page_to_pfn(p)) != (n)) { \
		printk("PTREPL: %s:%u page table nid mismatch! pfn: %zu, nid %u expected: %u\n", \
		__FUNCTION__, __LINE__, page_to_pfn(p), pfn_to_nid(page_to_pfn(p)), (int)(n)); \
		dump_stack();\
	}} while(0);

#else
#define check_page(p)
#define check_offset(offset)
#define check_page_node(p, n)
#endif



/*
 * ===============================================================================
 * Helper functions
 * ===============================================================================
 */
static inline struct page *page_of_ptable_entry(void *pgtableep)
{
	/* the pointer to a page table entry is a kernel virtual address.
	   we need to get the page of this pointer.
	   kva -> pa -> pfn -> struct page, virt_to_page should do this for us
	 */
	return virt_to_page((long)pgtableep);
}

/*
 * ===============================================================================
 * Reading and writing the CR3
 * ===============================================================================
 */

unsigned long pgtable_repl_read_cr3(void)
{
	unsigned long cr3;

	struct mm_struct *mm = this_cpu_read(cpu_tlbstate.loaded_mm);

	cr3 = __native_read_cr3();
	if (unlikely(!pgtable_repl_initialized)) {
		return cr3;
	}

	if (!mm->repl_pgd_enabled) {
		return cr3;
	}

	if (unlikely((cr3 & CR3_ADDR_MASK) != __pa(mm->repl_pgd[numa_node_id()]))) {
		if (unlikely((cr3 & CR3_ADDR_MASK) == __pa(mm->pgd))) {
			return cr3;
		}
		panic("PTREPL: %s:%u ##############################\n", __FUNCTION__, __LINE__);
	}

	return build_cr3(mm->pgd, cr3 & CR3_PCID_MASK);
}

void pgtable_repl_write_cr3(unsigned long cr3)
{
	pgd_t *pgd;
	struct mm_struct *mm = this_cpu_read(cpu_tlbstate.loaded_mm);

	if (unlikely(!pgtable_repl_initialized)) {
		native_write_cr3(cr3);
		return;
	}

	if (!mm->repl_pgd_enabled) {
		native_write_cr3(cr3);
		return;
	}

	pgd = mm_get_pgd_for_node(mm);
	check_page_node(page_of_ptable_entry(pgd), numa_node_id());
	native_write_cr3(build_cr3(pgd, CR3_PCID_MASK & cr3));
}


/*
 * ===============================================================================
 * Set Page Table Entries
 * ===============================================================================
 */


void pgtable_repl_set_pte(pte_t *ptep, pte_t pteval)
{
	int i;
	long offset;
	struct page *page_pte;

	/* set the entry of the first replica */
	native_set_pte(ptep, pteval);

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	page_pte = page_of_ptable_entry(ptep);
	check_page(page_pte);

	if (page_pte->replica == NULL) {
		return;
	}

	offset = (long)ptep - (long)page_to_virt(page_pte);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page_pte = page_pte->replica;
		check_page_node(page_pte, i);

		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);
		native_set_pte(ptep, pteval);
	}
}


void pgtable_repl_set_pte_at(struct mm_struct *mm, unsigned long addr,
							 pte_t *ptep, pte_t pteval)
{
	pgtable_repl_set_pte(ptep, pteval);
}


void pgtable_repl_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	int i;
	long offset;
	struct page *page_pmd, *page_pte;

	/* set the native entry */
	native_set_pmd(pmdp, pmdval);

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	page_pmd = page_of_ptable_entry(pmdp);
	check_page(page_pmd);

	if (page_pmd->replica == NULL) {
		return;
	}

	page_pte = pmd_page(pmdval);

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);

	/* the entry is a large entry i.e. pointing to a frame, or the entry is not valid */
	if (!page_pte || pmd_none(pmdval) || !pmd_present(pmdval) || pmd_large(pmdval)
			|| is_pmd_migration_entry(pmdval) || is_swap_pmd(pmdval)) {
		for (i = 0; i < nr_node_ids; i++) {
			page_pmd = page_pmd->replica;
			check_page_node(page_pmd, i);
			pmdp = (pmd_t *)((long)page_to_virt(page_pmd) + offset);
			native_set_pmd(pmdp, pmdval);
		}
		return;
	}

	/* where the entry points to */
	for (i = 0; i < nr_node_ids; i++) {
		page_pmd = page_pmd->replica;
		page_pte = page_pte->replica;

		check_page_node(page_pmd, i);
		check_page_node(page_pte, i);

		pmdp = (pmd_t *)((long)page_to_virt(page_pmd) + offset);

		pmdval = native_make_pmd((page_to_pfn(page_pte) << PAGE_SHIFT) | pmd_flags(pmdval));

		native_set_pmd(pmdp, pmdval);
	}
}


void pgtable_repl_set_pud(pud_t *pudp, pud_t pudval)
{
	int i;
	long offset;
	struct page *page_pud, *page_pmd;

	native_set_pud(pudp, pudval);

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	page_pud = page_of_ptable_entry(pudp);
	check_page(page_pud);

	if (page_pud->replica == NULL) {
		return;
	}

	offset = ((long)pudp & ~PAGE_MASK);
	check_offset(offset);

	page_pmd = pud_page(pudval);

	/* there is no age for this entry or the entry is huge or the entry is not present */
	if (!page_pmd || !pud_present(pudval) || pud_huge(pudval) || pud_none(pudval)) {
		for (i = 0; i < nr_node_ids; i++) {
			page_pud = page_pud->replica;
			check_page_node(page_pud, i);
			pudp = (pud_t *)((long)page_to_virt(page_pud) + offset);
			native_set_pud(pudp, pudval);
		}
		return;
	}

	for (i = 0; i < nr_node_ids; i++) {
		page_pud = page_pud->replica;
		page_pmd = page_pmd->replica;

		check_page_node(page_pud, i);
		check_page_node(page_pmd, i);

		pudp = (pud_t *)((long)page_to_virt(page_pud) + offset);
		pudval = native_make_pud((page_to_pfn(page_pmd) << PAGE_SHIFT) | pud_flags(pudval));
		native_set_pud(pudp, pudval);
	}
}


void pgtable_repl_set_p4d(p4d_t *p4dp, p4d_t p4dval)
{
	int i;
	long offset;
	struct page *page_p4d, *page_pud;

	native_set_p4d(p4dp, p4dval);

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	page_p4d = page_of_ptable_entry(p4dp);
	check_page(page_p4d);

	if (page_p4d->replica == NULL) {
		return;
	}

	offset = ((long)p4dp & ~PAGE_MASK);
	check_offset(offset);

	page_pud = p4d_page(p4dval);

	if (!page_pud || p4d_none(p4dval) || !p4d_present(p4dval)) {
		for (i = 0; i < nr_node_ids; i++) {
			page_p4d = page_p4d->replica;
			check_page_node(page_p4d, i);
			p4dp = (p4d_t *)((long)page_to_virt(page_p4d) + offset);
			native_set_p4d(p4dp, p4dval);
		}
		return;
	}

	for (i = 0; i < nr_node_ids; i++) {
		page_pud = page_pud->replica;
		page_p4d = page_p4d->replica;

		check_page_node(page_p4d, i);
		check_page_node(page_pud, i);

		p4dp = (p4d_t *)((long)page_to_virt(page_p4d) + offset);

		p4dval = native_make_p4d((page_to_pfn(page_pud) << PAGE_SHIFT) | p4d_flags(p4dval));
		native_set_p4d(p4dp, p4dval);
	}
}

void pgtable_repl_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
	panic("PTREPL: %s:%d:  not yet implemented by Mitosis\n", __FUNCTION__, __LINE__);
}


/*
 * ===============================================================================
 * Get Page Table Entries
 * ===============================================================================
 */


pte_t pgtable_repl_get_pte(pte_t *ptep)
{
	int i;
	long offset;
	struct page *page;

	pteval_t val = pte_val(*ptep);

	if (unlikely(!pgtable_repl_initialized)) {
		return native_make_pte(val);
	}

	if (!pte_present(*ptep) || is_swap_pte(*ptep) || (!pte_present(*ptep) && is_migration_entry(pte_to_swp_entry(*ptep)))) {
		return native_make_pte(val);
	}

	page = page_of_ptable_entry(ptep);
	check_page(page);

	if (page->replica == NULL) {
		return native_make_pte(val);
	}

	offset = ((long)ptep & ~PAGE_MASK);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		ptep = (pte_t *)((long)page_to_virt(page) + offset);
		val |= pte_val(*ptep);
	}

	return native_make_pte(val);
}

pte_t pgtable_repl_get_pte_at(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
    return pgtable_repl_get_pte(ptep);
}


pmd_t pgtable_repl_get_pmd(pmd_t *pmdp)
{
	int i;
	long offset;
	struct page *page;

	pmdval_t flags;
	pmdval_t val = pmd_val(*pmdp);

	if (unlikely(!pgtable_repl_initialized)) {
		return native_make_pmd(val);
	}

	if (!pmd_large(*pmdp) || !pmd_present(*pmdp) || is_pmd_migration_entry(*pmdp) || is_swap_pmd(*pmdp)) {
		return native_make_pmd(val);
	}

	page = page_of_ptable_entry(pmdp);
	check_page(page);

	if (page->replica == NULL) {
		return native_make_pmd(val);
	}

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);


	flags = pmd_flags(*pmdp);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		pmdp = (pmd_t *)((long)page_to_virt(page) + offset);
		flags |= pmd_flags(*pmdp);
	}
	return native_make_pmd(val | flags);
}


pud_t pgtable_repl_get_pud(pud_t *pudp)
{
	int i;
	long offset;
	struct page *page;

	pudval_t flags;

	pudval_t val = pud_val(*pudp);

	if (unlikely(!pgtable_repl_initialized)) {
		return native_make_pud(val);
	}

	if (!pud_large(*pudp)) {
		return native_make_pud(val);
	}

	page = page_of_ptable_entry(pudp);
	check_page(page);

	if (page->replica == NULL) {
		return native_make_pud(val);
	}

	offset =  ((long)pudp & ~PAGE_MASK);;
	check_offset(offset);

	flags = pud_flags(*pudp);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		pudp = (pud_t *)((long)page_to_virt(page) + offset);
		flags |= pud_flags(*pudp);
	}

	return native_make_pud(val | flags);
}


p4d_t pgtable_repl_get_p4d(p4d_t *p4dp)
{
	int i;
	long offset;
	struct page *page;

	p4dval_t flags = p4d_flags(*p4dp);
	p4dval_t val = p4d_val(*p4dp);

	if (unlikely(!pgtable_repl_initialized)) {
		return native_make_p4d(val);
	}

	page = page_of_ptable_entry(p4dp);
	check_page(page);

	if (page->replica == NULL) {
		return native_make_p4d(val);
	}

	offset =  ((long)p4dp & ~PAGE_MASK);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		p4dp = (p4d_t *)((long)page_to_virt(page) + offset);
		flags |= p4d_flags(*p4dp);
	}

	return native_make_p4d(val | flags);
}


pgd_t pgtable_repl_get_pgd(pgd_t *pgdp)
{
	int i;
	long offset;
	struct page *page;

	pgdval_t flags = pgd_flags(*pgdp);
	pgdval_t val = pgd_val(*pgdp);

	if (unlikely(!pgtable_repl_initialized)) {
		return native_make_pgd(val);
	}

	page = page_of_ptable_entry(pgdp);
	check_page(page);

	if (page->replica == NULL) {
		return native_make_pgd(val);
	}

	offset =  ((long)pgdp & ~PAGE_MASK);;
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {

		page = page->replica;
		check_page_node(page, i);
		pgdp = (pgd_t *)((long)page_to_virt(page) + offset);
		flags |= pgd_flags(*pgdp);
	}

	return native_make_pgd(val | flags);
}


/*
 * ===============================================================================
 * Get_and_Clear Page Table Entries
 * ===============================================================================
 */



pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	int i;
	long offset;
	struct page *page_pte;

	pteval_t pteval;
	pteval_t flags;

	flags =  pte_flags(*ptep);
	pteval = pte_val(native_ptep_get_and_clear(ptep));

	if (!mm->repl_pgd_enabled) {
		return native_make_pte(pteval);
	}

	page_pte = page_of_ptable_entry(ptep);
	check_page(page_pte);

	if (unlikely(page_pte->replica == NULL)) {
		return native_make_pte(pteval);
	}

	offset = ((long)ptep & ~PAGE_MASK);
	check_offset(offset);



	for (i = 0; i < nr_node_ids; i++) {
		page_pte = page_pte->replica;
		check_page_node(page_pte, i);

		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);

		flags |= pte_flags(native_ptep_get_and_clear(ptep));
	}

	return pte_set_flags(native_make_pte(pteval), flags);
}


pmd_t pmdp_get_and_clear(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp)
{
	int i;
	long offset;
	struct page *page_pmd;

	pmd_t pmd;
	pmdval_t flags;

	pmd = native_pmdp_get_and_clear(pmdp);

	if (!mm->repl_pgd_enabled) {
		return pmd;
	}

	page_pmd = page_of_ptable_entry(pmdp);
	check_page(page_pmd);

	if (unlikely(page_pmd->replica == NULL)) {
		return pmd;
	}

	flags = pmd_flags(pmd);

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page_pmd = page_pmd->replica;
		check_page_node(page_pmd, i);

		pmdp = (pmd_t *)((long)page_to_virt(page_pmd) + offset);
		flags |= pmd_flags(native_pmdp_get_and_clear(pmdp));
	}

	return pmd_set_flags(pmd, flags);
}


pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp)
{
	return pmdp_get_and_clear(mm, addr, pmdp);
}


pud_t pudp_get_and_clear(struct mm_struct *mm, unsigned long addr, pud_t *pudp)
{
	int i;
	long offset;
	struct page *page_pud;
	pudval_t flags;
	pud_t pud;

	pud = native_pudp_get_and_clear(pudp);

	if (!mm->repl_pgd_enabled) {
		return pud;
	}

	page_pud = page_of_ptable_entry(pudp);
	check_page(page_pud);

	if (unlikely(page_pud->replica == NULL)) {
		return pud;
	}

	offset =  ((long)pudp & ~PAGE_MASK);;
	check_offset(offset);

	flags = pud_flags(pud);

	for (i = 0; i < nr_node_ids; i++) {
		page_pud = page_pud->replica;
		check_page_node(page_pud, i);

		pudp = (pud_t *)((long)page_to_virt(page_pud) + offset);
		flags |= pud_flags(native_pudp_get_and_clear(pudp));
	}

	return pud_set_flags(pud, flags);
}


pud_t pudp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr, pud_t *pudp)
{
	return pudp_get_and_clear(mm, addr, pudp);
}


/*
 * ===============================================================================
 * Test and Clear Young
 * ===============================================================================
 */

int ptep_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long addr, pte_t *ptep)
{
	int i;
	long offset;
	struct page *page;
	int ret = 0;

	if (pte_young(*ptep))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *) &ptep->pte);

	page = page_of_ptable_entry(ptep);
	check_page(page);

	if (page->replica == NULL) {
		return ret;
	}

	offset = ((long)ptep & ~PAGE_MASK);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		ptep = (pte_t *)((long)page_to_virt(page) + offset);
		if (pte_young(*ptep))
			ret |= test_and_clear_bit(_PAGE_BIT_ACCESSED,
						(unsigned long *) &ptep->pte);
	}

	return ret;
}


int pmdp_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long addr, pmd_t *pmdp)
{

	int i;
	long offset;
	struct page *page;
	int ret = 0;

	if (pmd_young(*pmdp))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *) &pmdp->pmd);

	page = page_of_ptable_entry(pmdp);
	check_page(page);

	if (page->replica == NULL) {
		return ret;
	}

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		pmdp = (pmd_t *)((long)page_to_virt(page) + offset);
		if (pmd_young(*pmdp))
			ret |= test_and_clear_bit(_PAGE_BIT_ACCESSED,
						(unsigned long *) &pmdp->pmd);
	}

	return ret;
}


int pudp_test_and_clear_young(struct vm_area_struct *vma,
			      unsigned long addr, pud_t *pudp)
{

	int i;
	long offset;
	struct page *page;
	int ret = 0;

	if (pud_young(*pudp))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *) &pudp->pud);

	page = page_of_ptable_entry(pudp);
	check_page(page);

	if (page->replica == NULL) {
		return ret;
	}

	offset =  ((long)pudp & ~PAGE_MASK);;
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		pudp = (pud_t *)((long)page_to_virt(page) + offset);
		if (pud_young(*pudp))
			ret |= test_and_clear_bit(_PAGE_BIT_ACCESSED,
						(unsigned long *) &pudp->pud);
	}

	return ret;
}


/*
 * ===============================================================================
 * Setting Access Flags
 * ===============================================================================
 */


/*
 * Used to set accessed or dirty bits in the page table entries
 * on other architectures. On x86, the accessed and dirty bits
 * are tracked by hardware. However, do_wp_page calls this function
 * to also make the pte writeable at the same time the dirty bit is
 * set. In that case we do actually need to write the PTE.
 */
int ptep_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pte_t *ptep,
			  pte_t entry, int dirty)
{
	int i;
	int changed;
	long offset;
	struct page *page;

	changed = !pte_same(*ptep, entry);
	if (changed && dirty) {
		native_set_pte_at(vma->vm_mm, address, ptep, entry);
	}

	page = page_of_ptable_entry(ptep);
	check_page(page);

	if (page->replica == NULL) {
		goto out;
	}

	offset = ((long)ptep & ~PAGE_MASK);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		ptep = (pte_t *)((long)page_to_virt(page) + offset);

		changed |= !pte_same(*ptep, entry);
		if (dirty) {
			native_set_pte_at(vma->vm_mm, address, ptep, entry);
		}
	}

	out :
	if (changed) {
		flush_tlb_fix_spurious_fault(vma, address);
	}

	return changed;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
int pmdp_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pmd_t *pmdp,
			  pmd_t entry, int dirty)
{
	int i;
	int changed;
	long offset;
	struct page *page;

	changed = !pmd_same(*pmdp, entry);
	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
	if (changed) {
		native_set_pmd(pmdp, entry);
	}

	page = page_of_ptable_entry(pmdp);
	check_page(page);

	if (page->replica == NULL) {
		goto out_flush;
	}

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);


	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		pmdp = (pmd_t *)((long)page_to_virt(page) + offset);
		changed |= !pmd_same(*pmdp, entry);
		native_set_pmd(pmdp, entry);
	}

	out_flush:
	if (changed) {
		flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
	}

	return changed;
}


int pudp_set_access_flags(struct vm_area_struct *vma, unsigned long address,
			  pud_t *pudp, pud_t entry, int dirty)
{
	int i;
	int changed;
	long offset;
	struct page *page;


	changed = !pud_same(*pudp, entry);

	VM_BUG_ON(address & ~HPAGE_PUD_MASK);
	if (changed && dirty) {
		native_set_pud(pudp, entry);
	}

	page = page_of_ptable_entry(pudp);
	check_page(page);

	if (page->replica == NULL) {
		return changed;
	}

	offset =  ((long)pudp & ~PAGE_MASK);;
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page = page->replica;
		check_page_node(page, i);

		pudp = (pud_t *)((long)page_to_virt(page) + offset);
		changed |= !pud_same(*pudp, entry);
		if (dirty) {
			native_set_pud(pudp, entry);
		}
	}

	return changed;
}
#endif


/*
 * ===============================================================================
 * Entry Invalidation
 * ===============================================================================
 */


pmd_t pmdp_invalidate(struct vm_area_struct *vma, unsigned long address, pmd_t *pmdp)
{
	pmd_t old;

	old = pmdp_establish(vma, address, pmdp, pmd_mknotpresent(get_pmd(pmdp)));
	flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
	return old;
}


/*
 * ===============================================================================
 * Write Protect Pages
 * ===============================================================================
 */




pmd_t pmdp_establish(struct vm_area_struct *vma, unsigned long address, pmd_t *pmdp, pmd_t pmd)
{


	int i;
	long offset;
	struct page *page_pmd;
	struct page *page_pmd_debug;
	pmdval_t pmdval;

	if (IS_ENABLED(CONFIG_SMP)) {
		pmdval = pmd_val(xchg(pmdp, pmd));
	} else {
		pmdval = pmd_val(*pmdp);
		native_set_pmd(pmdp, pmd);
	}

	if (unlikely(vma->vm_mm == &init_mm)) {
		return native_make_pmd(pmdval);
	}

	if (unlikely(!pgtable_repl_initialized)) {
		return native_make_pmd(pmdval);;
	}

	page_pmd = page_of_ptable_entry(pmdp);
	check_page(page_pmd);


	if (page_pmd->replica == NULL) {
		return native_make_pmd(pmdval);
	}

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);

	page_pmd_debug = page_pmd;

	for (i = 0; i < nr_node_ids; i++) {
		page_pmd = page_pmd->replica;
		if (page_pmd == NULL || page_pmd == page_pmd_debug) {
			panic("PTREPL: %s:%d i=%u, %u %u\n", __FUNCTION__, __LINE__, i, page_pmd == NULL, page_pmd == page_pmd_debug);
		}

		pmdp = (pmd_t *)((long)page_to_virt(page_pmd) + offset);

		if (IS_ENABLED(CONFIG_SMP)) {
			pmdval |= pmd_flags(xchg(pmdp, pmd));
		} else {
			pmdval |= pmd_flags(*pmdp);
			native_set_pmd(pmdp, pmd);
		}
	}

	return native_make_pmd(pmdval);
}


pte_t pgtable_repl_ptep_modify_prot_start(struct mm_struct *mm,
										  unsigned long addr,
										  pte_t *ptep)
{
	int i;
	long offset;
	struct page *page_pte;
	struct page *page_pte_debug;
    pteval_t pteval;

	pte_t pte = native_ptep_get_and_clear(ptep);
	pteval = pte_val(pte);

	if (unlikely(!pgtable_repl_initialized)) {
		return pte;
	}

	if (!mm->repl_pgd_enabled) {
		return pte;
	}

	page_pte = page_of_ptable_entry(ptep);
	check_page(page_pte);


	if (page_pte->replica == NULL) {
		return pte;
	}

	offset = ((long)ptep & ~PAGE_MASK);
	check_offset(offset);

	page_pte_debug = page_pte;

	for (i = 0; i < nr_node_ids; i++) {
		page_pte = page_pte->replica;
		if (page_pte == NULL || page_pte == page_pte_debug) {
			panic("PTREPL: %s:%d i=%u, %u %u\n", __FUNCTION__, __LINE__, i, page_pte == NULL, page_pte == page_pte_debug);
		}

		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);

		if (pte_pfn(*ptep) != (pte_pfn(pte))) {
			panic("the entries are not the same!!!\n");
		}

		pte = native_ptep_get_and_clear(ptep);

		pteval |= pte_val(pte);
	}

	return native_make_pte(pteval);
}


void pgtable_repl_ptep_modify_prot_commit(struct mm_struct *mm,
										  unsigned long addr,
										  pte_t *ptep, pte_t pte)
{
	/* this function calls ptep_set_at which in turn calls all */
	__ptep_modify_prot_commit(mm, addr, ptep, pte);
}


void ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	int i;
	long offset;
	struct page *page_pte;

	clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	if (!mm->repl_pgd_enabled) {
		return;
	}

	page_pte = page_of_ptable_entry(ptep);
	check_page(page_pte);

	if (page_pte->replica == NULL) {
		return;
	}

	offset = ((long)ptep & ~PAGE_MASK);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page_pte = page_pte->replica;
		check_page_node(page_pte, i);

		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);

		clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
	}
}



void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp)
{
	int i;
	long offset;
	struct page *page_pmd;
	struct page *page_pmd_debug;

	clear_bit(_PAGE_BIT_RW, (unsigned long *)pmdp);

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	if (!mm->repl_pgd_enabled) {
		return;
	}

	page_pmd = page_of_ptable_entry(pmdp);
	check_page(page_pmd);

	if (page_pmd->replica == NULL) {
		return;
	}

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);

	page_pmd_debug = page_pmd;

	for (i = 0; i < nr_node_ids; i++) {
		page_pmd = page_pmd->replica;
		check_page_node(page_pmd, i);

		pmdp = (pmd_t *)((long)page_to_virt(page_pmd) + offset);
		clear_bit(_PAGE_BIT_RW, (unsigned long *)pmdp);
	}
}


/*
 * ===============================================================================
 * Allocation and Freeing of Page Tables
 * ===============================================================================
 */

int pgtable_repl_pgd_alloc(struct mm_struct *mm)
{
	int i;
	struct page *pgd, *pgd2;

	for (i = 0; i < sizeof(mm->repl_pgd) / sizeof(mm->repl_pgd[0]); i++) {
		/* set the first replicatin entry */
		mm->repl_pgd[i] = mm->pgd;
	}

	/* don't do replication for init */
	if (unlikely(mm == &init_mm)) {
		printk("PTREPL: Not activating mm because it was init.\n");
		mm->repl_pgd_enabled = false;
		return 0;
	}

	if (unlikely(!pgtable_repl_initialized)) {
		pgtable_repl_initialized = (nr_node_ids != MAX_NUMNODES);
		if (pgtable_repl_initialized) {
			if (pgtable_fixed_node == -1) {
				pgtable_repl_activated = false;
			}
			printk("PTREPL: set state to %s.\n", (pgtable_repl_activated ? "activated" : "deactivated"));
		}
	}

	if (!pgtable_repl_initialized) {
		mm->repl_pgd_enabled = false;
		return 0;
	}

	if (pgtable_repl_activated) {
		mm->repl_pgd_enabled = true;
	}

	if (mm->repl_pgd_enabled == false ) {
		return 0;
	}

	printk("PTREPL: enable replication for the pgd of process\n");

	// replication is enabled for this domain
	mm->repl_pgd_enabled = true;

	/* get the page of the previously allocated pgd */
	pgd = page_of_ptable_entry(mm->pgd);

	pgd2 = pgd;
	for (i = 0; i < nr_node_ids; i++) {

		/* allocte a new page, and place it in the replica list */
		pgd2->replica = pgtable_cache_alloc(i);
		if (pgd2->replica == NULL) {
			goto cleanup;
		}

		check_page_node(pgd2->replica, i);

		/* set the replica pgd poiter */
		mm->repl_pgd[i] = (pgd_t *) page_to_virt(pgd2->replica);

		/* call the ctor, which maps the kernel portion of the ptable */
		spin_lock(&pgd_lock);
		pgd_ctor(mm, mm->repl_pgd[i]);
		spin_unlock(&pgd_lock);

		pgd2 = pgd2->replica;
	}

	/* finish the loop: last -> first replica */
	pgd2->replica = pgd;

	/* let's verify */
	#if 1
	pgd2 = pgd->replica;
	for (i = 0; i < nr_node_ids; i++) {
		check_page_node(pgd2, i);
		pgd2 = pgd2->replica;
	}
	if (pgd2 != pgd) {
		panic("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
	}
	#endif

	return 0;
	cleanup:

	panic("%s:%d: PTREPL: FAILED!!!!\n", __FUNCTION__, __LINE__);

	return -1;
}

void pgtable_repl_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	int i;
	struct page *pgd_page, *p;

	if (unlikely(mm == &init_mm)) {
		return;
	}

	pgd_page = page_of_ptable_entry(mm->pgd);
	if (pgd_page->replica == NULL) {
		if (mm->repl_pgd[0] != mm->pgd) {
			panic("mm->repl_pgd[i] != mm->pgd. should have been the same\n");
		}
		return;
	}

	pgd_page = pgd_page->replica;

	/* XXX: check if there are infact replicas */
	for (i = 0; i < nr_node_ids; i++) {
		p = pgd_page;
		pgd_page = pgd_page->replica;

		if (p != page_of_ptable_entry(mm->repl_pgd[i])) {
			panic("mm->repl_pgd[i] != mm->pgd. should have been the same\n");
		};

		check_page_node(p, i);

		/* call the destructor */
		pgd_dtor(mm->repl_pgd[i]);

		/* free the pgd */
		pgtable_cache_free(i, p);

		/* we set the replica pointer to the first one */
		mm->repl_pgd[i] = pgd;
	}
	pgd_page = page_of_ptable_entry(mm->pgd);
	pgd_page->replica = NULL;
}


static void __pgtable_repl_alloc_one(struct mm_struct *mm, unsigned long pfn,
								     bool (*ctor)(struct page *page) )
{
	int i;
	struct page *p, *p2;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	/* obtain the page for the pfn */
	p = pfn_to_page(pfn);
	if (p == NULL) {
		return;
	}

	if (!mm->repl_pgd_enabled) {
		p->replica = NULL;
		return;
	}

	if (p->replica) {
		printk("PTREP: Called alloc on an already allocated replica... verifying!\n");
		p2 = p->replica;
		for (i = 0; i < nr_node_ids; i++) {
			check_page_node(p2, i);
			p2 = p2->replica;
		}
		if (p2 != p) {
			printk("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
		}
		return;
	}

	p2 = p;
	for (i = 0; i < nr_node_ids; i++) {
		/* allocte a new page, and place it in the replica list */
		p2->replica  = pgtable_cache_alloc(i);
		if (p2->replica == NULL) {
			goto cleanup;
		}

		check_page_node(p2->replica, i);

		if (ctor) {
			if(!ctor(p2->replica)) {
				panic("Failed to call ctor!\n");
			}
		}

		/* set the replica pgd poiter */
		p2 = p2->replica;
	}

	/* finish the loop: last -> first replica */
	p2->replica = p;

	/* let's verify */
	#if 0
	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		printk("page: %lx", (long)p2);
		check_page_node(p2, i);
		p2 = p2->replica;
	}
	if (p2 != p) {
		panic("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
	}
	#endif
	return;

	cleanup:

	panic("%s:%d: PTREPL: FAILED!!!!\n", __FUNCTION__, __LINE__);
}

static void __pgtable_repl_release_one(unsigned long pfn, void (*dtor)(struct page *page))
{
	int i;
	struct page *p, *p2, *pcurrent;
	p = pfn_to_page(pfn);
	if (unlikely(p == NULL)) {
		return;
	}

	if (p->replica == NULL) {
		return;
	}

	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		check_page_node(p2, i);
		pcurrent = p2;
		if (dtor) {
			dtor(pcurrent);
		}
		p2 = p2->replica;
		pgtable_cache_free(i, pcurrent);
	}

	p->replica = NULL;
}


void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_one(mm, pfn, pgtable_page_ctor);
}

void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_one(mm, pfn, pgtable_pmd_page_ctor);
}

void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_one(mm, pfn, NULL);
}

void pgtable_repl_alloc_p4d(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_one(mm, pfn, NULL);
}

void pgtable_repl_release_pte(unsigned long pfn)
{
	__pgtable_repl_release_one(pfn, pgtable_page_dtor);
}

void pgtable_repl_release_pmd(unsigned long pfn)
{
	__pgtable_repl_release_one(pfn, pgtable_pmd_page_dtor);
}

void pgtable_repl_release_pud(unsigned long pfn)
{
	__pgtable_repl_release_one(pfn, NULL);
}

void pgtable_repl_release_p4d(unsigned long pfn)
{
	__pgtable_repl_release_one(pfn, NULL);
}

void pgtable_repl_activate_mm(struct mm_struct *prev, struct mm_struct *next)
{

}


/*
 * ==================================================================
 * Page Table Cache
 * ==================================================================
 */

int pgtable_cache_populate(size_t numpgtables)
{
	size_t i, j;
	size_t num_nodes = MAX_SUPPORTED_NODE;
	struct page *p;
	nodemask_t nm = NODE_MASK_NONE;

	printk("PGREPL: populating pgtable cache with %zu tables per node\n",
			numpgtables);

	spin_lock(&pgtable_cache_lock);

	if (nr_node_ids < num_nodes) {
		num_nodes = nr_node_ids;
	}

	for (i = 0; i < num_nodes; i++) {

		printk("PGREPL: populating pgtable cache node[%zu] with %zu tables\n",
				i, numpgtables);

		nodes_clear(nm);
		node_set(i, nm);

		for (j = 0; j < numpgtables; j++) {
			/* allocte a new page, and place it in the replica list */
			p = __alloc_pages_nodemask(PGALLOC_GFP, 0, i, &nm);
			if (p) {
				check_page_node(p, i);
				p->replica = pgtable_cache[i];
				pgtable_cache[i] = p;
				pgtable_cache_size[i]++;
			} else {
				break;
			}
		}

		printk("PGREPL: node[%lu] populated with %zu  tables\n",
				i, pgtable_cache_size[i]);

	}

	spin_unlock(&pgtable_cache_lock);

	return 0;
}

int pgtable_cache_drain(void)
{
	int i;
	struct page *p;
	spin_lock(&pgtable_cache_lock);

	for (i = 0; i < MAX_SUPPORTED_NODE; i++) {
		p = pgtable_cache[i];
		while(p) {
			pgtable_cache[i] = p->replica;
			pgtable_cache_size[i]--;
			p->replica = NULL;
			__free_page(p);
			p = pgtable_cache[i];

		}
	}

	spin_unlock(&pgtable_cache_lock);

	return 0;
}

struct page *pgtable_cache_alloc(int node)
{
	struct page *p;
	nodemask_t nm;

	if (unlikely(node >= MAX_SUPPORTED_NODE)) {
		panic("PTREPL: WARNING NODE ID %u >= %u. Override to 0 \n",
				node, nr_node_ids);
		node = 0;
	}

	if (pgtable_cache[node] == NULL) {
		nm = NODE_MASK_NONE;
		node_set(node, nm);

		/* allocte a new page, and place it in the replica list */
		p = __alloc_pages_nodemask(PGALLOC_GFP, 0, node, &nm);
		check_page_node(p, node);
		return p;
	}

	spin_lock(&pgtable_cache_lock);
	p = pgtable_cache[node];
	pgtable_cache[node] = p->replica;
	pgtable_cache_size[node]--;
	p->replica = NULL;
	spin_unlock(&pgtable_cache_lock);

	/* need to clear the page */
	clear_page(page_to_virt(p));

	check_page_node(p, node);

	return p;
}

void pgtable_cache_free(int node, struct page *p)
{
	check_page_node(p, node);
	spin_lock(&pgtable_cache_lock);
	/* set the replica to NULL */
	p->replica = NULL;

	p->replica = pgtable_cache[node];
	pgtable_cache[node] = p;
	pgtable_cache_size[node]++;
	spin_unlock(&pgtable_cache_lock);
}





/*
 * ==================================================================
 * Prepare Replication
 * ==================================================================
 */

#include <linux/sched/task.h>

#ifndef virt_to_pfn
#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)
#endif

int pgtbl_repl_prepare_replication(struct mm_struct *mm, nodemask_t nodes)
{
	int err = 0;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	size_t p4d_idx, pud_idx, pmd_idx, pte_idx;


	/* check if the subsystem is initialized. this should actually be the case */
	if (unlikely(!pgtable_repl_initialized)) {
		panic("PTREPL: %s:%u - subsystem should be enabled by now! \n", __FUNCTION__, __LINE__);
	}

	/* if it already has been enbaled, don't do anything */
	if (unlikely(mm->repl_pgd_enabled)) {
		return 0;
	}

	p4d = (p4d_t *)mm->pgd;
	task_lock(current);
	spin_lock(&mm->page_table_lock);

	/* we need to talk the page table */
	mm->repl_pgd_nodes = nodes;
	mm->repl_pgd_enabled = true;


	/* this will replicate the pgd */
	pgtable_repl_pgd_alloc(mm);
	//	if (!mm->repl_pgd_enabled) {panic("FOOOF");}
	//	printk("%s:%u p4d=%lx..%lx\n", __FUNCTION__, __LINE__, (long)p4d, (long)p4d + 4095);
	for (p4d_idx = 0; p4d_idx < KERNEL_PGD_BOUNDARY; p4d_idx++) {
		if (p4d_none(p4d[p4d_idx])) {
			continue;
		}

		pud = (pud_t *)p4d_page_vaddr(p4d[p4d_idx]);

		pgtable_repl_alloc_pud(mm, page_to_pfn(page_of_ptable_entry(pud)));
		//	printk("%s:%u set_p4d(p4d[%zu], 0x%lx, 0x%lx\n",__FUNCTION__, __LINE__,  p4d_idx, _PAGE_TABLE | __pa(pud_new), p4d_val(__p4d(_PAGE_TABLE | __pa(pud_new))));
		set_p4d(p4d + p4d_idx, p4d[p4d_idx]);

		for (pud_idx = 0; pud_idx < 512; pud_idx++) {
			if (pud_none(pud[pud_idx])) {
				continue;
			}

			if (pud_huge(pud[pud_idx])) {
				set_pud(pud + pud_idx, pud[pud_idx]);
				continue;
			}

			pmd =  (pmd_t *)pud_page_vaddr(pud[pud_idx]);

			pgtable_repl_alloc_pmd(mm, page_to_pfn(page_of_ptable_entry(pmd)));
			set_pud(pud + pud_idx,pud[pud_idx]);

			for (pmd_idx = 0; pmd_idx < 512; pmd_idx++) {

				if (pmd_none(pmd[pmd_idx])) {
					continue;
				}

				if (pmd_huge(pmd[pmd_idx])) {
					set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
					continue;
				}

				/* get the pte page */
				pte = (pte_t *)pmd_page_vaddr(pmd[pmd_idx]);

				pgtable_repl_alloc_pte(mm, page_to_pfn(page_of_ptable_entry(pte)));

				set_pmd(pmd + pmd_idx, pmd[pmd_idx]);

				for (pte_idx = 0; pte_idx < 512; pte_idx++) {
					if (pte_none(pte[pte_idx])) {
						continue;
					}
					set_pte(pte + pte_idx, pte[pte_idx]);
				}
			}
		}
	}

	spin_unlock(&mm->page_table_lock);
	task_unlock(current);
	if (err) {
		mm->repl_pgd_enabled = false;
		printk("PGREPL: DISABLE MITOSIS DUE TO ERROR\n");

	}
	pgtable_repl_write_cr3(__native_read_cr3());

	return err;
}

/*
 * procfs control files
 */
#ifdef CONFIG_PROC_SYSCTL

int sysctl_numa_pgtable_replication(struct ctl_table *table, int write, void __user *buffer,
                                    size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = (pgtable_repl_activated ? 1 : pgtable_fixed_node);

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write) {
		if (state == -1) {
			/* the default behavior */
			printk("Page table allocation set to normal behavior\n");
			pgtable_repl_activated = false;
			pgtable_fixed_node = -1;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
		} else if (state == 0) {
			/* fixed on node 0 */
			printk("Page table allocation set to fixed on node 0\n");
			pgtable_repl_activated = false;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else {
			/* replication enabled */
			printk("Page table allocation set to replicated\n");
			pgtable_repl_activated = true;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		}
	}
	return err;
}


int sysctl_numa_pgtable_replication_cache_ctl(struct ctl_table *table, int write, void __user *buffer,
                                              size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = 0;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write) {
		if (state < 0) {
			/* the default behavior */
			printk("PROCFS: Command ot drain the pgtable cache\n");
			pgtable_cache_drain();
		} else if (state > 0) {
			printk("PROCFS: Command ot populate the pgtable cache\n");
			pgtable_cache_populate(state);
		}
	}
	return err;
}
#endif /* CONFIG_PROC_SYSCTL */
#endif /* CONFIG_PGTABLE_REPLICATION */
