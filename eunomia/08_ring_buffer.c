
/*
    上一章介绍了perf buffer（当今从内核向用户空间发送数据的事实上的标准），
    而本章的ring buffer可以解决perf buffer内存效率和事件重排问题，同时达到或超过了它的性能
    下面介绍在 eBPF 中使用 exitsnoop 监控进程退出事件，并使用 ring buffer 向用户态打印输出。
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 使用 exitsnoop 监控进程退出事件
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx) {
    u64   id  = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    pid_t tid = (u32)id;

    if (pid != tid)  // ignore thread exits
        return 0;  
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);  // 为事件结构体 e 在 ring buffer 中预留空间
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();  // 获取了当前进程的 task_struct 结构体
    u64 start_time = BPF_CORE_READ(task, start_time);  // 读取task结构体里的字段

    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);  // 将数据发送到用户空间

    return 0;
}

/*
    运行结果
    sudo ./ecli run package.json 
    TIME     PID     PPID    EXIT_CODE  DURATION_NS  COMM    
    21:40:09  42050  42049   0          0            which
    21:40:09  42049  3517    0          0            sh
    21:40:09  42052  42051   0          0            ps
    21:40:09  42051  3517    0          0            sh
    21:40:09  42055  42054   0          0            sed
    21:40:09  42056  42054   0          0            cat
    21:40:09  42057  42054   0          0            cat
    21:40:09  42058  42054   0          0            cat
    21:40:09  42059  42054   0          0            cat
*/

char LICENSE[] SEC("license") = "Dual BSD/GPL";
