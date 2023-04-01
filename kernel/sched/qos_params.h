/* debug params */
QOS_PARAM_S32(debug_bw, 0) /* Debug cpu bandwidth */
QOS_PARAM_S32(debug_cpu, -1)
QOS_PARAM_S64(debug_pid, 0)
QOS_PARAM_S32(debug_nontask, 0) /* Messages for cgroups */
QOS_PARAM_S32(dump_fdl_rq, 0)
QOS_PARAM_S32(debug_hf, 1) /* On/off switch for high frequency messages */
QOS_PARAM_S32(dump_debug, 0) /* Print everything */

/* latency params */
QOS_PARAM_U32(tick_margin, 970)
QOS_PARAM_U32(dl_slack, 970)
QOS_PARAM_U64(tick_skip, 80000) /* Min time to next tick after a tick miss, prevents consecutive misses */
QOS_PARAM_U64(dl_skip, 50000) /* Min deadline extension after a deadline miss, prevents consecutive misses */
QOS_PARAM_U64(max_tick_interval, 100000000)
QOS_PARAM_U64(default_fair_dl, 5000000)
QOS_PARAM_S32(wake_dl_scan, 1) /* Deadline based wake up load balancing search in addition to idle search */
QOS_PARAM_U32(wake_dl_interval_shift, 0) /* Dl based wake lb every n wakeups */
QOS_PARAM_U32(wake_dl_margin, 1500) /* Only consider wake lb to a cpu with a dl greater than task's dl scaled by this */
QOS_PARAM_S32(wake_prefer_preempt_prev, 1) /* Don't check other cpus if the previous cpu can be preempted */
QOS_PARAM_S32(wake_prefer_preempt_others, 0) /* Wake lb ends when a preemptible cpu is found, idle cpu not required */

/* bandwidth params */
QOS_PARAM_U32(target_wait_fraction, 100) /* Allow cpu shares increase only if wait time / on cpu time > this / 1024 */
QOS_PARAM_U32(guaranteed_share_boost, 1)
QOS_PARAM_U32(guaranteed_share_ratio, 800) /* Won't try to increase guaranteed cgroups cpu shares above this level */
QOS_PARAM_U32(avg_usage_alpha, 10)
QOS_PARAM_U32(avg_wait_alpha, 10)
QOS_PARAM_U64(control_loop_interval, 10000000)
QOS_PARAM_U32(max_share_boost, 10)
