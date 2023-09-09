/*
    uprobe 是一种用于捕获用户空间函数调用的 eBPF 的探针，我们可以通过它来捕获用户空间程序调用的系统函数。
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

// 使用 uprobe 来捕获 /bin/bash 二进制文件中的 readline 函数。 
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret) {
    char str[MAX_LINE_SIZE];  // 存储用户态函数返回内容
    char comm[TASK_COMM_LEN]; // 存储当前任务名称
    u32 pid;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));      // 获取当前任务的名称
    pid = bpf_get_current_pid_tgid() >> 32;         // 获取用户进程pid
    bpf_probe_read_user_str(str, sizeof(str), ret); // 从用户空间读取 readline 函数的返回值
    bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

    return 0;
};

char LICENSE[] SEC("license") = "GPL";
