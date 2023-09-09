
/*
    在代码中，通过@description注解告诉eBPF，pid_target是全局变量，
    它们允许用户态程序与 eBPF 程序之间进行数据交互，
    可以通过 --pid_target 参数修改pid_target的值，
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @description "Process ID to trace"
const volatile int pid_target = 0;

// 捕获用户态进程打开文件的系统调用
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;
    
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/*
    ecc 3_global_value.c  # 编译
    sudo ecli run package.json  --pid_target 618  # 加载到内核

    touch test1
    rm test1
    touch test2
    rm test2

    sudo cat /sys/kernel/debug/tracing/trace_pipe  # 查看日志
*/

char LICENSE[] SEC("license") = "GPL";
