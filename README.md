# ebpf-study
ebpf bcc study

# 1. 编译部署

下载工具链
```bash
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
```


编译
```bash
sudo apt install linux-tools-common
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h  # 通过bpftool生成vmlinux.h头文件

sudo apt install clang llvm  # 编译前需要安装clang和llvm
./ecc minimal.bpf.c
或者使用docker编译：docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest
```


部署
```bash
sudo ./ecli run package.json
```


如果正在使用的 Linux 发行版（例如 Ubuntu ）默认情况下没有启用跟踪子系统可能看不到任何输出，使用以下指令打开这个功能：
sudo echo 1 > /sys/kernel/debug/tracing/tracing_on


# eBPF常用函数
```bash
bpf_printk              # 内核日志打印函数
BPF_CORE_READ           # 数据读取宏函数，用于读取结构体中的某个字段

bpf_get_current_pid_tgid  # 获取用户进程pid
bpf_get_current_uid_gid   # 获取用户进程uid
bpf_get_current_comm      # 获取当前任务名称，例如bash
bpf_get_current_task      # 获取了当前进程的 task_struct 结构体

bpf_probe_read_str    # 获取进程名称
bpf_perf_event_output   # 将进程执行事件输出到 perf buffer，也就是输出到 ecli 命令行控制台

bpf_map_lookup_elem  # 查找hash表里的元素
bpf_map_update_elem  # 更新hash表里的元素
bpf_map_delete_elem  # 删除hash表里的元素

```

