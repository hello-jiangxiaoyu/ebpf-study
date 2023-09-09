
/*
   与 kprobes 相比，fentry 和 fexit 程序有更高的性能和可用性
   fexit 和 kretprobe 程序最大的区别在于，fexit 程序可以访问函数的输入参数和返回值，
   而 kretprobe 只能访问返回值
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}

/*
    ecc 2_fentry_fexit.c        # 编译
    sudo ecli run package.json  # 加载到内核

    touch test1
    rm test1
    touch test2
    rm test2

    sudo cat /sys/kernel/debug/tracing/trace_pipe  # 查看日志
*/

char LICENSE[] SEC("license") = "Dual BSD/GPL";
