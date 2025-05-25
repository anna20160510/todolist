#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_TASKS 100
#define MAX_LEN 100

typedef struct {
    char desc[MAX_LEN];
    int done;
    char due_date[MAX_LEN]; // format: YYYY-MM-DD HH:MM
} Task;

static Task tasks[MAX_TASKS];
static int task_count = 0;

// Portable manual parser for "YYYY-MM-DD HH:MM"
time_t get_time_from_string(const char* date_str) {
    int year, month, day, hour, minute;
    struct tm tm_time = {0};

    if (sscanf(date_str, "%4d-%2d-%2d %2d:%2d", &year, &month, &day, &hour, &minute) != 5) {
        return (time_t)-1;
    }

    tm_time.tm_year = year - 1900;
    tm_time.tm_mon  = month - 1;
    tm_time.tm_mday = day;
    tm_time.tm_hour = hour;
    tm_time.tm_min  = minute;

    return mktime(&tm_time);
}

int compare_due_date(const void *a, const void *b) {
    const Task *task_a = (const Task*)a;
    const Task *task_b = (const Task*)b;

    int a_has_no_explicit_date = (task_a->due_date[0] == '\0');
    int b_has_no_explicit_date = (task_b->due_date[0] == '\0');

    // Case 1: 處理至少一方沒有明確截止日期的情況
    if (a_has_no_explicit_date && b_has_no_explicit_date) {
        return 0; // 兩者都沒有截止日期，視為相等
    }
    if (a_has_no_explicit_date) {
        return 1; // A 沒有截止日期，B 有 (或格式錯誤但非空)，A 排在 B 之後
    }
    if (b_has_no_explicit_date) {
        return -1; // B 沒有截止日期，A 有 (或格式錯誤但非空)，B 排在 A 之後
    }

    // Case 2: 兩者都有非空的 due_date 字串，嘗試解析
    time_t time_a = get_time_from_string(task_a->due_date);
    time_t time_b = get_time_from_string(task_b->due_date);

    // 檢查解析是否失敗 (get_time_from_string 返回 (time_t)-1)
    int a_is_malformed = (time_a == (time_t)-1);
    int b_is_malformed = (time_b == (time_t)-1);

    if (a_is_malformed && b_is_malformed) {
        return 0; // 兩者日期格式都錯誤 (但非空)，視為相等
    }
    if (a_is_malformed) {
        return 1; // A 日期格式錯誤，B 有效，A 排在 B 之後
    }
    if (b_is_malformed) {
        return -1; // B 日期格式錯誤，A 有效，B 排在 A 之後
    }

    // Case 3: 兩者都有有效且成功解析的截止日期
    return (time_a > time_b) - (time_a < time_b);
}

void sort_tasks_by_due_date() {
    qsort(tasks, task_count, sizeof(Task), compare_due_date);
}

int add_task(const char* desc, const char* due_date) {
    if (task_count >= MAX_TASKS) return -1;

    strncpy(tasks[task_count].desc, desc, MAX_LEN - 1);
    tasks[task_count].desc[MAX_LEN - 1] = '\0';

    if (due_date != NULL && due_date[0] != '\0') { // Check if due_date is provided and not empty
        strncpy(tasks[task_count].due_date, due_date, MAX_LEN - 1);
        tasks[task_count].due_date[MAX_LEN - 1] = '\0';
    } else {
        tasks[task_count].due_date[0] = '\0'; // Set to empty string if no due date is provided
    }
    tasks[task_count].done = 0;

    task_count++;
    sort_tasks_by_due_date();
    return task_count - 1;
}

int update_task(int index, const char* new_desc, const char* new_due_date) {
    if (index < 0 || index >= task_count) return -1;

    strncpy(tasks[index].desc, new_desc, MAX_LEN - 1);
    tasks[index].desc[MAX_LEN - 1] = '\0';

    if (new_due_date != NULL && new_due_date[0] != '\0') { // Check if new_due_date is provided and not empty
        strncpy(tasks[index].due_date, new_due_date, MAX_LEN - 1);
        tasks[index].due_date[MAX_LEN - 1] = '\0';
    } else {
        tasks[index].due_date[0] = '\0'; // Set to empty string if no new due date is provided
    }

    sort_tasks_by_due_date();
    return 0;
}

int mark_done(int index) {
    if (index < 0 || index >= task_count) return -1;
    tasks[index].done = 1;
    return 0;
}

int delete_task(int index) {
    if (index < 0 || index >= task_count) return -1;
    for (int i = index; i < task_count - 1; i++) {
        tasks[i] = tasks[i + 1];
    }
    task_count--;
    return 0;
}

int get_task_count() {
    return task_count;
}

const char* get_task_desc(int index) {
    if (index < 0 || index >= task_count) return "";
    return tasks[index].desc;
}

int is_task_done(int index) {
    if (index < 0 || index >= task_count) return -1;
    return tasks[index].done;
}

const char* get_task_due_date(int index) {
    if (index < 0 || index >= task_count) return "";
    return tasks[index].due_date;
}
