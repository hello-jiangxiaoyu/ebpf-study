
/*
    捕获进程发送信号的系统调用集合（包括 kill、tkill 和 tgkill），
    使用 hash map 保存状态
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

// 哈希表value数据结构
struct event {
    unsigned int pid;
    unsigned int tpid;
    int sig;
    int ret;
    char comm[TASK_COMM_LEN];
};

// hash map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct event);
} values SEC(".maps");

// kill系统调用进入
static int probe_entry(pid_t tpid, int sig) {
    struct event event = {};
    __u64 pid_tgid;
    __u32 tid;

    pid_tgid = bpf_get_current_pid_tgid();  // 获取进程id
    tid = (__u32)pid_tgid;
    event.pid = pid_tgid >> 32;
    event.tpid = tpid;
    event.sig = sig;
    bpf_get_current_comm(event.comm, sizeof(event.comm));  // 获取当前任务的名称
    bpf_map_update_elem(&values, &tid, &event, BPF_ANY);   // 向hash map里插入一个元素，key为tid，value为event
    return 0;
}

// kill系统调用退出
static int probe_exit(void *ctx, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct event *eventp;

    eventp = bpf_map_lookup_elem(&values, &tid);  // 在values哈希表里找key为tid的元素
    if (!eventp)
        return 0;  // not found

    eventp->ret = ret;
    bpf_printk("PID %d (%s) sent signal %d ", eventp->pid, eventp->comm, eventp->sig);
    bpf_printk("to PID %d, ret = %d", eventp->tpid, ret);
    bpf_map_delete_elem(&values, &tid);  // 删除hash map里的元素
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx) {
    pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx) {
    return probe_exit(ctx, ctx->ret);
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
