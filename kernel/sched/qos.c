#include <linux/types.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include "sched.h"
#include "qos.h"

void qos_record_wait(struct task_group *tg, u64 delta)
{
	int cpu = smp_processor_id();

	while (tg) {
		WRITE_ONCE(*per_cpu_ptr(tg->acc_wait, cpu), READ_ONCE(*per_cpu_ptr(tg->acc_wait, cpu)) + delta);
		tg = tg->parent;
	}
}

u64 qos_read_reset_wait(struct task_group *tg)
{
	u64 acc_wait = 0;
	int cpu;

	for_each_online_cpu(cpu) {
		acc_wait += READ_ONCE(*per_cpu_ptr(tg->acc_wait, cpu));
		WRITE_ONCE(*per_cpu_ptr(tg->acc_wait, cpu), 0);
	}

	return acc_wait;
}

u64 qos_cpuusage_read(struct cgroup_subsys_state *css);

u64 qos_read_reset_usage(struct task_group *tg)
{
	struct cgroup_subsys_state *ca_css = tg->css.cgroup->subsys[cpuacct_cgrp_id];
	u64 acc_usage, last;
	u64 usage = 0;

	if (!ca_css)
		return 0;

	acc_usage = qos_cpuusage_read(ca_css);
	last = READ_ONCE(tg->last_acc_usage);
	if (last)
		usage = acc_usage - last;
	WRITE_ONCE(tg->last_acc_usage, acc_usage);

	return usage;
}

int qos_walk_update_stats_down(struct task_group *tg, void *data)
{
	u32 nperiods = *(u32*)data;
	u64 avg_usage = READ_ONCE(tg->avg_usage);
	u64 avg_wait = READ_ONCE(tg->avg_wait);
	u64 new_wait, new_usage;
	struct task_group *child;
	unsigned long totalg;

	local_irq_disable();
	new_usage = qos_read_reset_usage(tg);
	new_wait = qos_read_reset_wait(tg);
	if (nperiods > 1) {
		new_usage /= nperiods;
		new_wait /= nperiods;
	}
	avg_usage = avg_usage * (EMA_SCALE - qosp_avg_usage_alpha) >> EMA_SHIFT;
	avg_usage += new_usage * qosp_avg_usage_alpha >> EMA_SHIFT;
	avg_wait = avg_wait * (EMA_SCALE - qosp_avg_wait_alpha) >> EMA_SHIFT;
	avg_wait += new_wait * qosp_avg_wait_alpha >> EMA_SHIFT;
	WRITE_ONCE(tg->curr_usage, new_usage);
	WRITE_ONCE(tg->curr_wait, new_wait);
	WRITE_ONCE(tg->avg_usage, avg_usage);
	WRITE_ONCE(tg->avg_wait, avg_wait);
	local_irq_enable();

	totalg = 0;
	list_for_each_entry_rcu(child, &tg->children, siblings) {
		totalg += child->guaranteed_shares;
	}
	WRITE_ONCE(tg->children_total_guaranteed, totalg);

	return TG_WALK_OK;
}

u64 qos_get_avg_usage(struct task_group *tg)
{
	return (READ_ONCE(tg->avg_usage) << QOS_SHIFT) / qosp_control_loop_interval;
}

u64 qos_get_avg_wait(struct task_group *tg)
{
	return (READ_ONCE(tg->avg_wait) << QOS_SHIFT) / qosp_control_loop_interval;
}

inline unsigned int qnext(unsigned int c, unsigned int qsize)
{
	return c + 1 >= qsize? 0 : c + 1;
}

extern struct mutex shares_mutex;

int qos_visit_bandwidth_down(struct task_group *tg, void *data)
{
	u64 usage, wait;
	unsigned long max_shares, prev_shares, shares;
	u64 usage_factor;
	int waiting;
	int pinc, pdec;

	if (!tg->parent)
		return TG_WALK_OK;

	if (!READ_ONCE(tg->guaranteed_shares))
		return TG_WALK_SKIP;

	if (!tg->parent->parent)
		tg->abs_guaranteed = READ_ONCE(tg->guaranteed_shares);
	else
		tg->abs_guaranteed = READ_ONCE(tg->parent->abs_guaranteed) *
		  READ_ONCE(tg->guaranteed_shares) /
		  max(1UL, READ_ONCE(tg->parent->children_total_guaranteed));

	if (!READ_ONCE(tg->abs_guaranteed))
		return TG_WALK_SKIP;

	if (!mutex_trylock(&shares_mutex))
		return TG_WALK_SKIP;

	usage = qos_get_avg_usage(tg);
	wait = qos_get_avg_wait(tg);
	pinc = tg->parent && tg->parent->shares_increased;
	pdec = tg->parent && tg->parent->shares_decreased;
	prev_shares = shares = tg->shares;
	max_shares = tg->guaranteed_shares * qosp_max_share_boost;

	if (qos_show_debug_bw())
		printk("==QOS cgroup %s    usage %llu    wait %llu    guaranteed %lu\n",
		  tg->css.cgroup->kn->name, usage, wait, tg->guaranteed_shares);
	usage_factor = (usage << QOS_SHIFT) / max(1UL, scale_load_down(tg->abs_guaranteed));
	waiting = usage && wait > usage * qosp_target_wait_fraction >> QOS_SHIFT;
	if (qos_show_debug_bw())
		printk("==QOS cgroup %s    usage factor %llu    waiting %d    pinc %d   pdec %d\n",
		  tg->css.cgroup->kn->name, usage_factor, waiting, pinc, pdec);

	if (!pinc && usage_factor < QOS_SCALE) {
		if (waiting && shares < max_shares) {
			shares += (max_shares - shares) * (QOS_SCALE - usage_factor) * 100 >> QOS_SHIFT * 2;
		} else if (shares > tg->guaranteed_shares) {
			shares -= (shares - tg->guaranteed_shares) * 10 >> QOS_SHIFT;
		}
	} else if (!pdec && shares > tg->guaranteed_shares) {
		shares -= (shares - tg->guaranteed_shares) * 20 >> QOS_SHIFT;
	}
	WRITE_ONCE(tg->shares, clamp(shares, tg->guaranteed_shares, max_shares));

	if (qos_show_debug_bw())
		printk("==QOS cgroup %s    old shares %lu    new shares %lu\n", tg->css.cgroup->kn->name,
		  prev_shares, tg->shares);

	tg->shares_increased = tg->shares > prev_shares;
	tg->shares_decreased = tg->shares < prev_shares;

	mutex_unlock(&shares_mutex);

	return TG_WALK_OK;
}

static int kschedqosd(void *param)
{
	ktime_t last_run, next_run, now;
	u32 nperiods;

	for (;;) {
		last_run = ktime_get();

		rcu_read_lock();
		walk_tg_tree(qos_walk_update_stats_down, tg_nop, &nperiods);
		rcu_read_unlock();

		rcu_read_lock();
		walk_tg_tree(qos_visit_bandwidth_down, tg_nop, &nperiods);
		rcu_read_unlock();

		preempt_disable();
		next_run = ktime_add_ns(last_run, qosp_control_loop_interval);
		now = ktime_get();
		nperiods = 1;
		while (ktime_after(now, next_run)) {
			next_run = ktime_add_ns(next_run, qosp_control_loop_interval);
			nperiods++;
		}
		preempt_enable();
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_hrtimeout(&next_run, HRTIMER_MODE_ABS);
	}

	return 0;
}

static __init int qos_init(void)
{
	kthread_run(kschedqosd, NULL, "kschedqosd");
	return 0;
}
late_initcall(qos_init)


#undef QOS_PARAM_S32
#define QOS_PARAM_S32(name, init_val) s32 __read_mostly qosp_##name = init_val;
#undef QOS_PARAM_U32
#define QOS_PARAM_U32(name, init_val) u32 __read_mostly qosp_##name = init_val;
#undef QOS_PARAM_S64
#define QOS_PARAM_S64(name, init_val) s64 __read_mostly qosp_##name = init_val;
#undef QOS_PARAM_U64
#define QOS_PARAM_U64(name, init_val) u64 __read_mostly qosp_##name = init_val;
#include "qos_params.h"

#undef QOS_PARAM_S32
#define QOS_PARAM_S32(name, init_val) seq_printf(m, "%25s %d\n", #name, qosp_##name);
#undef QOS_PARAM_U32
#define QOS_PARAM_U32(name, init_val) seq_printf(m, "%25s %u\n", #name, qosp_##name);
#undef QOS_PARAM_S64
#define QOS_PARAM_S64(name, init_val) seq_printf(m, "%25s %lld\n", #name, qosp_##name);
#undef QOS_PARAM_U64
#define QOS_PARAM_U64(name, init_val) seq_printf(m, "%25s %llu\n", #name, qosp_##name);

int sched_qos_params_show(struct seq_file *m, void *v)
{
	#include "qos_params.h"
	return 0;
}

#undef QOS_PARAM_S32
#define QOS_PARAM_S32(name, init_val) else if (!strcmp(#name, pname)) {if (sscanf(val, "%d", &qosp_##name) != 1) goto invalid;}
#undef QOS_PARAM_U32
#define QOS_PARAM_U32(name, init_val) else if (!strcmp(#name, pname)) {if (sscanf(val, "%u", &qosp_##name) != 1) goto invalid;}
#undef QOS_PARAM_S64
#define QOS_PARAM_S64(name, init_val) else if (!strcmp(#name, pname)) {if (sscanf(val, "%lld", &qosp_##name) != 1) goto invalid;}
#undef QOS_PARAM_U64
#define QOS_PARAM_U64(name, init_val) else if (!strcmp(#name, pname)) {if (sscanf(val, "%llu", &qosp_##name) != 1) goto invalid;}

ssize_t sched_qos_params_write(struct file *filp, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	char buf[128], pname[64], val[64];
	struct inode *inode;

	if (cnt > 127)
		cnt = 127;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	buf[cnt] = 0;

	/* Ensure the static_key remains in a consistent state */
	inode = file_inode(filp);
	inode_lock(inode);

	if (sscanf(buf, "%63s %63s", pname, val) != 2)
		goto invalid;

	if (0) {}
	#include "qos_params.h"
	else goto invalid;

	inode_unlock(inode);
	*ppos += cnt;
	return cnt;

invalid:
	inode_unlock(inode);
	return -EINVAL;
}

static int sched_qos_params_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, sched_qos_params_show, NULL);
}

static const struct file_operations sched_qos_params_fops = {
	.open		= sched_qos_params_open,
	.write		= sched_qos_params_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


struct dentry *qos_root;

static __init int qos_debug_init(void)
{
	qos_root = debugfs_create_dir("qos", NULL);
	if (!qos_root)
		return -ENOMEM;

	debugfs_create_file("qos_params", 0644, qos_root,NULL,  &sched_qos_params_fops);

	return 0;
}
late_initcall(qos_debug_init)
