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




