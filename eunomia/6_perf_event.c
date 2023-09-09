
/*
    使用这段代码，我们就可以捕获 Linux 内核中进程执行的事件, 并分析进程的执行情况。
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    bool is_exit;
    char comm[TASK_COMM_LEN];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 捕获进程执行 execve 系统调用
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    struct event event={0};
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();  // 获取了当前进程的 task_struct 结构体

    pid_t tgid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event.pid  = tgid;
    event.uid  = (u32)bpf_get_current_uid_gid();

    char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);  // 获取进程名称

    // 通过events，将进程执行事件输出到 perf buffer，也就是执行 ecli 命令行的控制台
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

/* 
    运行结果：
    sudo ./ecli run package.json 
    TIME     PID     PPID    UID     COMM    
    21:28:30  40747  3517    1000    node
    21:28:30  40748  40747   1000    sh
    21:28:30  40749  3517    1000    node
    21:28:30  40750  40749   1000    sh
    21:28:30  40751  3517    1000    node
    21:28:30  40752  40751   1000    sh
*/

char LICENSE[] SEC("license") = "GPL";
