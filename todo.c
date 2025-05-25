#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_TASKS 100
#define MAX_LEN 100

typedef struct {
    char desc[MAX_LEN];
    int done;
    char due_date[MAX_LEN]; // format:YYYY-MM-DD HH:MM
    int id; // 新增：用於記錄任務的創建順序
} Task;

static Task tasks[MAX_TASKS];
static int task_count = 0;
static int next_id = 0; // 新增：用於產生唯一的任務ID

// Portable manual parser for "YYYY-MM-DD HH:MM"
time_t get_time_from_string(const char* date_str) {
    int year, month, day, hour, minute;
    struct tm tm_time = {0};

    if (sscanf(date_str, "%4d-%2d-%2d %2d:%2d", &year, &month, &day, &hour, &minute) != 5) {
        return (time_t)-1; // Return error value if parsing fails
    }

    memset(&tm_time, 0, sizeof(struct tm)); // Ensure tm_time is cleared

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

    // 判斷任務是否有有效的（非空）截止日期字串
    int a_has_due_date_str = (task_a->due_date[0] != '\0');
    int b_has_due_date_str = (task_b->due_date[0] != '\0');

    time_t time_a = (time_t)-1; // 預設為無效時間
    if (a_has_due_date_str) {
        time_a = get_time_from_string(task_a->due_date);
    }

    time_t time_b = (time_t)-1; // 預設為無效時間
    if (b_has_due_date_str) {
        time_b = get_time_from_string(task_b->due_date);
    }

    // 判斷日期是否有效解析 (即便字串存在，解析也可能失敗)
    int a_is_valid_date = (time_a != (time_t)-1);
    int b_is_valid_date = (time_b != (time_t)-1);


    // 優先處理沒有截止日期（或日期無效）的任務
    // 如果 A 有效日期，B 無效日期 -> A 在前
    if (a_is_valid_date && !b_is_valid_date) {
        return -1;
    }
    // 如果 B 有效日期，A 無效日期 -> B 在前 (A 在後)
    if (!a_is_valid_date && b_is_valid_date) {
        return 1;
    }

    // 兩者都有有效截止日期：按時間排序 (早到晚)
    if (a_is_valid_date && b_is_valid_date) {
        return (time_a > time_b) - (time_a < time_b);
    }

    // 兩者都沒有有效截止日期：按新增 ID 排序 (早到晚)
    // 這裡我們不區分字串是否為空和解析失敗，只要 `is_valid_date` 為 false 就進入此邏輯
    if (!a_is_valid_date && !b_is_valid_date) {
        return (task_a->id > task_b->id) - (task_a->id < task_b->id);
    }

    // 理論上所有情況都已被處理，這裡作為一個安全網
    return 0;
}

void sort_tasks_by_due_date() {
    qsort(tasks, task_count, sizeof(Task), compare_due_date);
}

int add_task(const char* desc, const char* due_date) {
    if (task_count >= MAX_TASKS) return -1;

    strncpy(tasks[task_count].desc, desc, MAX_LEN - 1);
    tasks[task_count].desc[MAX_LEN - 1] = '\0';

    if (due_date != NULL && due_date[0] != '\0') {
        strncpy(tasks[task_count].due_date, due_date, MAX_LEN - 1);
        tasks[task_count].due_date[MAX_LEN - 1] = '\0';
    } else {
        tasks[task_count].due_date[0] = '\0'; // Set to empty string if no due date is provided
    }
    tasks[task_count].done = 0;
    tasks[task_count].id = next_id++; // 為新任務分配一個 ID

    task_count++;
    sort_tasks_by_due_date();
    return task_count - 1;
}

int update_task(int index, const char* new_desc, const char* new_due_date) {
    if (index < 0 || index >= task_count) return -1;

    strncpy(tasks[index].desc, new_desc, MAX_LEN - 1);
    tasks[index].desc[MAX_LEN - 1] = '\0';

    if (new_due_date != NULL && new_due_date[0] != '\0') {
        strncpy(tasks[index].due_date, new_due_date, MAX_LEN - 1);
        tasks[index].due_date[MAX_LEN - 1] = '\0';
    } else {
        tasks[index].due_date[0] = '\0'; // Set to empty string if no new due date is provided
    }

    // 注意：這裡不更新 ID，因為任務的創建順序是不變的。
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
    // 注意：刪除後不需要更新 next_id，因為 ID 是遞增的，已使用的 ID 不會重複。
    // 但是，為了保持 ID 的連續性，如果需要嚴格的 ID 順序，可能需要重新分配 ID，
    // 但對於排序來說，當前的處理方式已足夠。
    sort_tasks_by_due_date(); // 刪除後也重新排序
    return 0;
}

void clear_completed_tasks() {
    int i, j;
    for (i = 0, j = 0; i < task_count; i++) {
        if (!tasks[i].done) {
            if (i != j) {
                tasks[j] = tasks[i];
            }
            j++;
        }
    }
    task_count = j;
    sort_tasks_by_due_date(); // Re-sort after clearing
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