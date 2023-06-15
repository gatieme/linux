
# 1 社区方案
-------

## 1.1 SCHED
-------

| TITLE | BRANCH | DESCRIPITION |
|:-----:|:------:|:------------:|
| FDL/The Fair Deadline Scheduling Class | [sched/fdl/linux-6.3-fair_deadline_scheduling_class-rfc](https://github.com/gatieme/linux/tree/sched/fdl/linux-6.3-fair_deadline_scheduling_class-rfc) | [sched: Morphing CFS into FDL, The Fair Deadline Scheduling Class](https://lore.kernel.org/all/20230401230556.2781604-2-xii@google.com) |
| Intel Thread Director | [sched/intel_thread_director/linux-6.0-rc7-itd-v2](https://github.com/gatieme/linux/tree/sched/intel_thread_director/linux-6.0-rc7-itd-v2) | [sched: Introduce classes of tasks for load balance, Ricardo Neri, 20230207](https://lore.kernel.org/all/20230207051105.11575-1-ricardo.neri-calderon@linux.intel.com) |
| Latency Nice | [sched/latency_nice/linux-5.19-rc5-latency_nice-v2](https://github.com/gatieme/linux/tree/sched/latency_nice/linux-5.19-rc5-latency_nice-v2) | [Add latency_nice priority, Vincent Guittot, 2023/02/24](https://lore.kernel.org/all/20230224093454.956298-1-vincent.guittot@linaro.org/)<br>*-*-*-*-*-*-*-* <br>[sched: EEVDF using latency-nice, Peter Zijlstra, 20230328](https://lore.kernel.org/all/20230328092622.062917921@infradead.org) |
| Scheduler eBPF | [sched/scheduler_ebpf/linux-5.15-rc3-scheduler_ebpf-v1](https://github.com/gatieme/linux/tree/sched/scheduler_ebpf/linux-5.15-rc3-scheduler_ebpf-v1)<br>[sched/scheduler_ebpf/linux-6.1-rc7-scheduler_ebpf-v2](https://github.com/gatieme/linux/tree/sched/scheduler_ebpf/linux-5.15-rc3-scheduler_ebpf-v1) | [sched: Implement BPF extensible scheduler class, Tejun Heo, 20230128](https://lore.kernel.org/lkml/20230128001639.3510083-1-tj@kernel.org) |
| UMCG(User Managed Concurrency Groups) | [sched/umcg](https://github.com/gatieme/linux/tree/sched/umcg) | [sched,mm,x86/uaccess: implement User Managed Concurrency Groups, Peter Oskolkov, 2021/11/22](https://patchwork.kernel.org/project/linux-mm/cover/20211122211327.5931-1-posk@google.com)<br>*-*-*-*-*-*-*-* <br>[sched: User Managed Concurrency Groups, Peter Zijlstra, 20220120](https://patchwork.kernel.org/project/linux-mm/cover/20220120155517.066795336@infradead.org)|
| Proxy Execution | [priority-inversion/proxy_execution-arm_valentin-sched-rfc-v3](https://github.com/gatieme/linux/tree/priority-inversion/proxy_execution-arm_valentin-sched-rfc-v3)<br>[priority-inversion/proxy_execution-jlelli-deadline-rfc-v2-debug](https://github.com/gatieme/linux/tree/priority-inversion/proxy_execution-jlelli-deadline-rfc-v2-debug) | NA |
| EEVDF | [sched/eevdf/linux-6.4-rc5-eevdf-v1](https://github.com/gatieme/linux/tree/sched/eevdf/linux-6.4-rc5-eevdf-v1) | [sched: EEVDF and latency-nice and/or slice-attr](https://lore.kernel.org/all/20230531124603.654144274@infradead.org) |
| BORE | [sched/bore/linux-6.1.33-bore_v2.4.0](https://github.com/gatieme/linux/tree/sched/bore/linux-6.1.33-bore_v2.4.0)<br>[sched/bore/linux-6.4-rc5-eevdf_bore_v2.4.0](https://github.com/gatieme/linux/tree/sched/bore/linux-6.4-rc5-eevdf_bore_v2.4.0) | [BORE (Burst-Oriented Response Enhancer) CPU Scheduler](https://github.com/firelzrd/bore-scheduler) |

## 1.2 MM
-------


| TITLE | BRANCH | DESCRIPITION |
|:-----:|:------:|:------------:|
| MGLRU | [5.18-rc3-mm-MGLRU_v10](https://github.com/gatieme/linux/tree/5.18-rc3-mm-MGLRU_v10) | [Multigenerational LRU Framework, Yu Zhao, 2022/04/07](https://lore.kernel.org/lkml/20220407031525.2368067-1-yuzhao@google.com) |
| Core Scheduling | [pie-x86-kernel-4.19-core_scheduling_v4](https://github.com/gatieme/linux/tree/pie-x86-kernel-4.19-core_scheduling_v4) | [Core scheduling, Peter Zijlstra, 2020/11/17](https://lore.kernel.org/lkml/20201117232003.3580179-1-joel@joelfernandes.org) |
| Hot Cold Page | [hot-cold-page/linux-6.1.0-hot_cold_page_tracking-kvaneesh-rfc-v1](https://github.com/gatieme/linux/tree/hot-cold-page/linux-6.1.0-hot_cold_page_tracking-kvaneesh-rfc-v1) | [[LSF/MM/BPF TOPIC] Using hardware counters to determine hot/cold pages](https://lore.kernel.org/all/6bbf2c47-05ab-b78c-3165-2eff18962d6d@linux.ibm.com)<br>PowerPC 体系结构 (POWER10) 支持热/冷页面跟踪功能(Hot/Cold page tracking), 参见 [HotChips2020-Server_Processors_IBM_Starke_POWER10_v33](https://hc32.hotchips.org/assets/program/conference/day1/HotChips2020_Server_Processors_IBM_Starke_POWER10_v33.pdf), 该功能以可配置的页面大小粒度, 提供访问计数器和访问关联详细信息. 原始 RFC 版本可以在 [kvaneesh/linux](https://github.com/kvaneesh/linux/commit/b472e2c8080823bb4114c286270aea3e18ffe221) 找到. |
| Mitosis | mitosis/4.17 | [Mitosis: Transparently Self-Replicating Page-Tables for Large-Memory Machines, ASPLOS '20](https://dl.acm.org/doi/10.1145/3373376.3378468). NUMA 迁移的时候考虑迁移 page-table. 在 NUMA 系统下, 内存的增长速度超过了 TLB 容量的增长速度, 从而可能引入严重的性能问题, 而 NUMA 已有的研究都集中在的内存中数据的分配和迁移策略上, 但没有关于如何在各 NUMA 之间放置页表的问题的研究. Mitosis 实现了一种程序无感的页表复制和迁移算法, 通过透明地跨 NUMA 复制和迁移页表来减轻 NUMA 对页表遍历的影响, 这降低了在 Page Walk 执行页表遍历时访问远程 NUMA 节点的频率. 原始 GitHub [mitosis-project/mitosis-linux](https://github.com/mitosis-project/mitosis-linux) |



# 2 M 分支
-------

| BRANCH | DESCRIPITION |
|:------:|:------------:|
| damon/master | NA |
| livepatching | NA |
| master | NA |
| mm  | maintainer/mm | 原始地址 [](https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git) |
| rt  | NA |
| TIP | [maintainer/tip](https://github.com/gatieme/linux/tree/tip) | x86 架构的三个主要维护者 Thomas Gleixner, Ingo Molnar 和 Peter Anvin. 因为工作相互重叠, 于 2007 年建立了 TIP 分支; 最初专注于 x86 架构, 但后来扩展到调度等主要核心内核领域. 参见 [Git tree maintenance](https://lwn.net/Articles/572068). 原始地址 [tip/tip.git](https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git) |




# 3 各发行版
-------


| BRANCH | DESCRIPITION |
|:------:|:------------:|
| openanolis/devel-4.19<br>openanolis/devel-5.10 | NA |
