
/*
    本节介绍捕获进程调度延迟
    进程调度延迟，也被称为 "run queue latency"，是衡量线程从变得可运行
    （例如，接收到中断，促使其处理更多工作）到实际在 CPU 上运行的时间。
    当进程被排队时，trace_enqueue 函数会在一个映射中记录时间戳。
    当进程被调度到 CPU 上运行时，handle_switch 函数会检索时间戳，并计算当前时间与排队时间之间的时间差。
    这个差值（delta）被用于更新进程的直方图，该直方图记录运行队列延迟的分布。
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "runqlat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

// 过滤对应的追踪目标, 最大映射项数量
#define MAX_ENTRIES    10240
#define TASK_RUNNING     0

const volatile bool  filter_cg        = false; // 是否过滤cgroup
const volatile bool  targ_per_process = false; // hkey参数，为true表示以进程id作为键进行追踪
const volatile bool  targ_per_thread  = false; // hkey参数，为true表示以线程id作为键进行追踪
const volatile bool  targ_per_pidns   = false; // hkey参数，为true表示以进程所属的 PID namespace作为键进行追踪
const volatile pid_t targ_tgid        = 0;     // 用于过滤追踪的目标

// 用于过滤 cgroup
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} cgroup_map SEC(".maps");

// 用于存储进程入队时的时间戳
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

// 用于存储直方图数据，记录进程调度延迟
/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

// 用于在进程入队时记录其时间戳
static int trace_enqueue(u32 tgid, u32 pid) {
    if (!pid)
        return 0;
    if (targ_tgid && targ_tgid != tgid)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

// 用于获取进程所属的 PID namespace
static unsigned int get_pid_namespace(struct task_struct *task) {
    struct   pid *pid  = BPF_CORE_READ(task, thread_pid);
    unsigned int level = BPF_CORE_READ(pid, level);

    struct upid upid;
    bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
    unsigned int inum = BPF_CORE_READ(upid.ns, ns.inum);
    return inum;
}

// handle_sched_wakeup：用于处理 sched_wakeup 事件，当一个进程从睡眠状态被唤醒时触发。
SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p) {
    if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
        return 0;
    return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

// handle_sched_wakeup_new：用于处理 sched_wakeup_new 事件，当一个新创建的进程被唤醒时触发。
SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p) {
    if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
        return 0;
    return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

// handle_sched_switch：用于处理 sched_switch 事件，当调度器选择一个新的进程运行时触发。
SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))  // 过滤 cgroup
        return 0;
    if (get_task_state(prev) == TASK_RUNNING)  // 只记录运行中的任务
        trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));  // 记录进程的入队时间

    u32 pid = BPF_CORE_READ(next, pid);
    u64 *tsp = bpf_map_lookup_elem(&start, &pid);  // 查找下一个进程的入队时间戳
    if (!tsp)
        return 0;

    // 计算进程调度时间戳，以微妙为单位，毫秒则改为除以 1000000U;
    s64 delta = (bpf_ktime_get_ns() - *tsp) / 1000U;  
    if (delta < 0)
        goto cleanup;

    // 根据用户参数，确定直方图映射的键 hkey
    u32 hkey = -1;
    if (targ_per_process) {
        hkey = BPF_CORE_READ(next, tgid);
    } else if (targ_per_thread) {
        hkey = pid;
    }else if (targ_per_pidns) {
        hkey = get_pid_namespace(next);
    }

    struct hist *histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);  // 查找或初始化直方图映射
    if (!histp)
        goto cleanup;
    if (!histp->comm[0])
        bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm), next->comm); // 将内核空间的数据next->comm拷贝到bpf堆栈
 
    u64 *slot = log2l(delta);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&histp->slots[slot], 1);  // 更新直方图数据，记录进程调度时间戳

cleanup:
    bpf_map_delete_elem(&start, &pid);  // 删除进程的入队时间戳记录
    return 0;
}

/*
    运行结果：
    sudo ecli run examples/bpftools/runqlat/package.json --targ_per_process
    key =  3189
    comm = cpptools

         (unit)              : count    distribution
             0 -> 1          : 0        |                                        |
             2 -> 3          : 0        |                                        |
             4 -> 7          : 0        |                                        |
             8 -> 15         : 1        |***                                     |
            16 -> 31         : 2        |*******                                 |
            32 -> 63         : 11       |****************************************|
            64 -> 127        : 8        |*****************************           |
           128 -> 255        : 3        |**********                              |

    上图中unit表示时间区间，count表述落在这个时间区间的事件个数，distribution是可视化方式展示占比
    例如第一行表示有9个事件耗时在0~1微妙之间
*/

char LICENSE[] SEC("license") = "GPL";
