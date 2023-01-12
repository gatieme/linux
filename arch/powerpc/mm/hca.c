#include <linux/mm.h>
#include <linux/jiffies.h>
#include <linux/debugfs.h>
#include <linux/mm_inline.h>

#include <asm/hca.h>

/* Hold hotness stat for the system */
struct hca_node_stats {
	unsigned long max_hotness;
	unsigned long min_hotness;

        unsigned long max_hotness_pfn;
	unsigned long min_hotness_pfn;

	u64 next_span_scan;
	struct mutex lock;
};

bool hca_lru_age = false;
bool hca_lru_evict = false;
static struct dentry *hca_debugfs_root;
static struct hca_node_stats hca_node_stats[MAX_NUMNODES];
/*
 * Number of pfns to randomly scan to determine max/min hotness
 */
static ulong scan_pfn_count __read_mostly = 100;
/*
 * Millisec to wait/skip before starting another random scan
 */
static ulong scan_skip_msec __read_mostly = 60;

/* backend callbacks  */
int  (*hca_pfn_entry)(unsigned long pfn, struct hca_entry *entry);
bool (*hca_node_enabled)(int numa_node);
void (*hca_backend_node_debugfs_init)(int numa_node, struct dentry *node_dentry);
void (*hca_backend_debugfs_init)(struct dentry *root_dentry);
int  (*hca_clear_entry)(unsigned long pfn);

static int parse_hca_age(char *arg)
{
        return strtobool(arg, &hca_lru_age);
}
early_param("hca_age", parse_hca_age);

static int parse_hca_evict(char *arg)
{
        return strtobool(arg, &hca_lru_evict);
}
early_param("hca_evict", parse_hca_evict);

static inline int folio_hca_entry(struct folio *folio, struct hca_entry *entry)
{
	return hca_pfn_entry(folio_pfn(folio), entry);
}

static inline int get_nr_gens(struct lruvec *lruvec, int type)
{
	return lruvec->lrugen.max_seq - lruvec->lrugen.min_seq[type] + 1;
}

void restablish_hotness_range(int node)
{
	int new_scan_pfn_count;
	struct pglist_data *pgdat = NODE_DATA(node);
	struct hca_node_stats *hca_node_stat = &hca_node_stats[node];

	if (!mutex_trylock(&hca_node_stat->lock))
		return;
	/* Look around 'scan_pfn_count' number of pfns randomly selected */
	if (time_is_before_jiffies64(hca_node_stat->next_span_scan)) {
		unsigned long current_hotness, max_hotness = 0, min_hotness = 0;
		unsigned long max_hotness_pfn = 0, min_hotness_pfn = 0;

		/*
		 * 10 % of available pages
		 */
		new_scan_pfn_count = max(scan_pfn_count, pgdat->node_present_pages/ 10);
		for (int index = 0; index < new_scan_pfn_count; index++) {

			struct page *page;
			struct hca_entry entry;
			/*
			 * we are trying to find a hot and cold pages in this
			 * lruvec which is node specific.
			 */
			unsigned long pfn;

			/* Yield if we get too much get_random call */
			cond_resched();
			pfn = prandom_u32_max((u32)pgdat->node_spanned_pages);

			pfn += pgdat->node_start_pfn;
			if (!pfn_valid((pfn)))
				continue;

			page = pfn_to_page(pfn);
			if (!PageLRU(page) || PageUnevictable(page))
				continue;

			if (hca_pfn_entry(pfn, &entry))
				continue;

			current_hotness = hotness_score(&entry);
			/* If the page didn't see any access, skip it */
			if (!current_hotness)
				continue;

			/*
			 * Let's make sure we atleast wait 1 decay updates before looking at this
			 * pfn for max/min computation.
			 */
			if (entry.age < 1)
				continue;

			//index++;

			if (current_hotness > max_hotness) {
				max_hotness = (current_hotness + max_hotness) / 2;
				max_hotness_pfn = pfn;
			} else if ((current_hotness < min_hotness) || !min_hotness) {
				min_hotness = (current_hotness + min_hotness) / 2;
				min_hotness_pfn = pfn;
			} else if ((current_hotness - min_hotness) < (max_hotness - min_hotness) / 2) {
				min_hotness = (current_hotness + min_hotness) / 2;
			} else {
				max_hotness = (current_hotness + max_hotness) / 2;
			}
		}

		hca_node_stat->next_span_scan = get_jiffies_64() + msecs_to_jiffies(scan_skip_msec);
		if (min_hotness) {
			hca_node_stat->max_hotness	=  max_hotness;
			hca_node_stat->max_hotness_pfn =  max_hotness_pfn;
			hca_node_stat->min_hotness	=  min_hotness;
			hca_node_stat->min_hotness_pfn =  min_hotness_pfn;
		}
	}
	mutex_unlock(&hca_node_stat->lock);
	return;
}

/* Return Multigen LRU generation based on folio hotness */
int map_hca_lru_seq(struct lruvec *lruvec, struct folio *folio)
{
	int seq, type;
	struct pglist_data *pgdat =  lruvec->pgdat;
	struct lru_gen_struct *lrugen = &lruvec->lrugen;
	struct hca_entry folio_entry;
	unsigned long hotness, seq_range;
	struct hca_node_stats *hca_node_stat = &hca_node_stats[pgdat->node_id];

	if (folio_hca_entry(folio, &folio_entry))
		/* return youngest generation ? */
		return lrugen->max_seq;

	type = folio_is_file_lru(folio);
	hotness = hotness_score(&folio_entry);
	/* The page didn't see any access, return oldest generation */
	if (!hotness)
		return lrugen->min_seq[type];

	/* Also adjust based on current value. */
	if (hotness > hca_node_stat->max_hotness) {
		hca_node_stat->max_hotness =  (hotness + hca_node_stat->max_hotness) / 2;
		hca_node_stat->max_hotness_pfn =  folio_pfn(folio);
	} else if (hotness < hca_node_stat->min_hotness) {
		hca_node_stat->min_hotness =  (hotness + hca_node_stat->min_hotness) / 2;
		hca_node_stat->min_hotness_pfn =  folio_pfn(folio);
	}

	/*
	 * Convert the max and min hotness into 4 ranges for sequence.
	 * Then place our current hotness into one of these range.
	 * We use the range number as an increment factor for generation.
	 */
	seq_range =  (hca_node_stat->max_hotness  - hca_node_stat->min_hotness)/ get_nr_gens(lruvec, type);

	/* higher the hotness younger the generation */
	seq = lrugen->min_seq[type] + ((hotness - hca_node_stat->min_hotness)/seq_range);
	return seq;
}

static inline int map_hca_lru_gen(struct lruvec *lruvec, struct folio *folio)
{
	int seq;

	seq = map_hca_lru_seq(lruvec, folio);
	return lru_gen_from_seq(seq);
}

static void hca_debugfs_init(void)
{
	int node;
	char name[32];
	struct dentry *node_dentry;
	hca_debugfs_root = debugfs_create_dir("hca", arch_debugfs_dir);

	for_each_online_node(node) {
		snprintf(name, sizeof(name), "node%u", node);
		node_dentry = debugfs_create_dir(name, hca_debugfs_root);


		debugfs_create_ulong("max-hotness", 0400, node_dentry,
				     &hca_node_stats[node].max_hotness);
		debugfs_create_ulong("max-hotness-pfn", 0400, node_dentry,
				     &hca_node_stats[node].max_hotness_pfn);

		debugfs_create_ulong("min-hotness", 0400, node_dentry,
				     &hca_node_stats[node].min_hotness);
		debugfs_create_ulong("min-hotness-pfn", 0400, node_dentry,
				     &hca_node_stats[node].min_hotness_pfn);

		if (hca_backend_node_debugfs_init)
			hca_backend_node_debugfs_init(node, node_dentry);
	}

	debugfs_create_ulong("scan-pfn-count", 0600, hca_debugfs_root,
			     &scan_pfn_count);
	debugfs_create_ulong("scan-skip-msec", 0600, hca_debugfs_root,
			     &scan_skip_msec);
	debugfs_create_bool("hca_lru_age", 0600, hca_debugfs_root,
			    &hca_lru_age);
	debugfs_create_bool("hca_lru_evict", 0600, hca_debugfs_root,
			    &hca_lru_evict);

	/* Now create backend debugs */
	if (hca_backend_debugfs_init)
		hca_backend_debugfs_init(hca_debugfs_root);
}

void arch_alloc_page(struct page *page, int order)
{
	int i;

	if (!hca_clear_entry)
		return;

	/* zero the counter value when we allocate the page */
	for (i = 0; i < (1 << order); i++)
		hca_clear_entry(page_to_pfn(page + i));
	return;
}
EXPORT_SYMBOL(arch_alloc_page);

static int __init hca_init(void)
{
	if (!hca_clear_entry) {
		pr_info("No HCA device registered. Disabling hca lru gen\n");
		hca_lru_age = false;
	}

	hca_debugfs_init();
	for (int i = 0; i < MAX_NUMNODES; i++)
		mutex_init(&hca_node_stats[i].lock);
	return 0;
}

late_initcall(hca_init);

void inc_max_seq(struct lruvec *lruvec, bool can_swap, bool force_scan);
int folio_update_gen(struct folio *folio, int gen);
/*
 * The generic version also does mark the page dirty if pte is dirty. We can't do that
 * here. That would mean background flusher may not find some of these pages ready to
 * flush.
 */
bool hca_try_to_inc_max_seq(struct lruvec *lruvec, unsigned long nr_to_scan,
			    unsigned long max_seq)
{
	int aged_count = 0;
	bool success = true;
	int type, zone, gen, new_gen, seq;
	struct lru_gen_struct *lrugen = &lruvec->lrugen;

	spin_lock_irq(&lruvec->lru_lock);
	/* Check whether someone created a new generation while we are here. */
	if (max_seq != lrugen->max_seq) {
		success = false;
		goto done;
	}

	/* counter region scan of pages in lruvec */
	for (type = 0; type < ANON_AND_FILE; type++) {
		for (zone = 0; zone < MAX_NR_ZONES; zone++) {
			/*
			 * oldest to youngest generation. We may
			 * want to breakout in between based on
			 * sc->priority?
			 */
			for (seq = lrugen->min_seq[type]; seq < lrugen->max_seq; seq++) {

				int map_seq;
				struct list_head *head;
				struct folio *folio;

				gen = lru_gen_from_seq(seq);
				head = &lrugen->lists[gen][type][zone];
				list_for_each_entry(folio, head, lru) {
					/*
					 * We work with the existing min and max
					 * seq of lruvec here later will increase
					 * the max seq/create a younger generation.
					 */
					map_seq = map_hca_lru_seq(lruvec, folio);
					new_gen = lru_gen_from_seq(map_seq);
					folio_update_gen(folio, new_gen);
					if (map_seq <= seq)
						aged_count++;
					/*
					 * Since we are holding lruvec lock may be
					 * we can move things around?
					 */
					if (aged_count == nr_to_scan)
						goto success_done;

				}
				spin_unlock_irq(&lruvec->lru_lock);
				cond_resched();
				spin_lock_irq(&lruvec->lru_lock);
			}
		}
	}

success_done:
	success = true;
done:
	spin_unlock_irq(&lruvec->lru_lock);
	return success;
}

