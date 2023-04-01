#include <linux/sched.h>
#include "sched.h"

#define QOS_SHIFT 10
#define QOS_SCALE (1 << QOS_SHIFT)
#define QOS_HSHIFT 20
#define QOS_HSCALE (1 << QOS_HSHIFT)

#define EMA_SHIFT 10
#define EMA_SCALE (1 << EMA_SHIFT)

#ifdef CONFIG_FAIR_GROUP_SCHED

#undef QOS_PARAM_S32
#define QOS_PARAM_S32(name, init_val) extern s32 qosp_##name;
#undef QOS_PARAM_U32
#define QOS_PARAM_U32(name, init_val) extern u32 qosp_##name;
#undef QOS_PARAM_S64
#define QOS_PARAM_S64(name, init_val) extern s64 qosp_##name;
#undef QOS_PARAM_U64
#define QOS_PARAM_U64(name, init_val) extern u64 qosp_##name;
#include "qos_params.h"

u64 qos_get_avg_usage(struct task_group *tg);
u64 qos_get_avg_wait(struct task_group *tg);

int sched_fdl_check_dl_cpu(int cpu, u64 wt, u64 *dl);

#ifndef for_each_sched_entity
#define for_each_sched_entity(se) \
		for (; se; se = se->parent)
#endif

static inline struct sched_entity *top_se_of(struct sched_entity *se)
{
	for_each_sched_entity(se) {
		if (!se->parent)
			break;
	}
	return se;
}

static inline u64 entity_rdl(struct sched_entity *se)
{
	return READ_ONCE(se->my_q->tg->deadline_rr);
}

static inline u64 entity_wdl(struct sched_entity *se)
{
	return READ_ONCE(se->my_q->tg->deadline_wakeup);
}

static inline u64 entity_is_fdl(struct sched_entity *se)
{
	return se->my_q && entity_rdl(se);
}

static inline int entity_fdl_active(struct sched_entity *se)
{
	return !!se->dl;
}

static inline int task_fdl_active(struct task_struct *p)
{
	return entity_fdl_active(top_se_of(&p->se));
}

static inline u64 vdt_cfs_rq(struct cfs_rq *cfs, u64 wt)
{
	return wt - cfs->vdt_lag;
}

static inline u64 vdt_se(struct sched_entity *se, u64 wt)
{
	return vdt_cfs_rq(cfs_rq_of(se), wt);
}

static inline int qos_show_debug_bw(void)
{
	return qosp_debug_bw && printk_ratelimit();
}

static inline int qos_show_hf_debug(struct sched_entity *cse)
{
	struct task_struct *p;
	struct sched_entity *se;

	if (qosp_dump_debug)
		goto toshow;

	if (!qosp_debug_hf)
		return 0;

	if (qosp_debug_cpu >= 0 && smp_processor_id() == qosp_debug_cpu)
		goto toshow;

	if (qosp_debug_nontask && !cse)
		goto toshow;

	if (qosp_debug_pid && cse) {
		rcu_read_lock();
		p = find_task_by_pid_ns(qosp_debug_pid, &init_pid_ns);
		if (!p) {
			rcu_read_unlock();
			return 0;
		}
		se = &p->se;
		for_each_sched_entity(se) {
			if (se == cse) {
				rcu_read_unlock();
				goto toshow;
			}
		}
		rcu_read_unlock();
	}

	return 0;

toshow:
	return printk_ratelimit();
}

static inline int qos_dump_fdl_rq(struct cfs_rq *cfs_rq)
{
	return qosp_dump_fdl_rq && cfs_rq->fdl_nr_running && qosp_debug_cpu >= 0 &&
	  smp_processor_id() == qosp_debug_cpu && printk_ratelimit();
}

#else

static inline int qos_show_debug_bw(void) {return 0;}
static inline int qos_show_hf_debug(struct sched_entity *se) {return 0;}
static inline int qos_dump_fdl_rq(struct cfs_rq *cfs_rq) {return 0;}

#endif
