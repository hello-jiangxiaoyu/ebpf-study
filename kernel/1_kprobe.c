/* 
   利用 kprobes 技术，用户可以定义自己的回调函数，
   然后在内核或者模块中几乎所有的函数中动态地插入探测点，
   当内核执行流程执行到指定的探测函数时，会调用该回调函数，
   用户即可收集所需的信息了，同时内核最后还会回到原本的正常执行流程。
*/

// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// 捕获在 Linux 内核中执行的 unlink 系统调用
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name) {
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;  // 获取用户进程pid
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

// 当从do_unlinkat函数退出时，它会被触发
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret) {
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;  // 获取用户进程pid
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}


/*
    ecc 1_kprobe.c              # 编译
    sudo ecli run package.json  # 加载到内核

    touch test1
    rm test1
    touch test2
    rm test2

    sudo cat /sys/kernel/debug/tracing/trace_pipe  # 查看日志
*/

char LICENSE[] SEC("license") = "Dual BSD/GPL";
