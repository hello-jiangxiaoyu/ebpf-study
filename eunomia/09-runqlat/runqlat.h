
#ifndef __RUNQLAT_H
#define __RUNQLAT_H

#define TASK_COMM_LEN	16
#define MAX_SLOTS	26

// 用来给用户态处理从内核态上报的事件
struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
};

#endif /* __RUNQLAT_H */
