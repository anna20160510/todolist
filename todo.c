#include "todo.h"
#include <string.h>

static Task tasks[MAX_TASKS];
static int task_count = 0;
static char desc_buffer[MAX_DESC_LEN];  // 用於傳回 task 描述

int add_task(const char* desc) {
    if (task_count >= MAX_TASKS || strlen(desc) >= MAX_DESC_LEN)
        return 0;
    strncpy(tasks[task_count].desc, desc, MAX_DESC_LEN);
    tasks[task_count].done = 0;
    task_count++;
    return 1;
}

void mark_done(int index) {
    if (index >= 0 && index < task_count) {
        tasks[index].done = 1;
    }
}

void delete_task(int index) {
    if (index >= 0 && index < task_count) {
        for (int i = index; i < task_count - 1; i++) {
            tasks[i] = tasks[i + 1];
        }
        task_count--;
    }
}

int get_task_count() {
    return task_count;
}

const char* get_task_desc(int index) {
    if (index >= 0 && index < task_count) {
        strncpy(desc_buffer, tasks[index].desc, MAX_DESC_LEN);
        return desc_buffer;
    }
    return "";
}

int is_task_done(int index) {
    if (index >= 0 && index < task_count) {
        return tasks[index].done;
    }
    return 0;
}
