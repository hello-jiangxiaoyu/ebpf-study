
/*
    XDP是一个支持可编程包处理的系统，下面是一段 C 语言实现的 eBPF 内核侧代码，
    它能够通过 xdp 捕获所有经过目标网络设备的数据包，计算其大小并输出到 trace_pipe 中。
    在代码中我们使用了注释，告诉eunomia-bpf想要挂载的目标网络设备编号，挂载的标志和选项
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/// @ifindex 1
/// @flags 0
/// @xdpopts {"old_prog_fd":0}
SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int pkt_sz = data_end - data;

    bpf_printk("packet size is %d", pkt_sz);  // 获取网络数据包大小
    return XDP_PASS;  // 将经过目标网络设备的包正常交付给内核的网络协议栈
}


char __license[] SEC("license") = "GPL";
