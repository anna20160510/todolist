#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_TASKS 100
#define MAX_LEN 100 // 任務描述和日期字串的最大長度

typedef struct {
    char desc[MAX_LEN];
    int done;
    char due_date[MAX_LEN]; // 內部儲存完整的 YYYY-MM-DD HH:MM
    int id; // 用於記錄任務的創建順序
} Task;

static Task tasks[MAX_TASKS];
static int task_count = 0;
static int next_id = 0; // 用於產生唯一的任務ID

// 內部使用的輔助函數：獲取當前年份
static int get_current_year() {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    return info->tm_year + 1900;
}

// 解析 MM-DD HH:MM 格式字串，內部補足當前年份
time_t get_time_from_string(const char* date_str) {
    int month, day, hour, minute;
    struct tm tm_time = {0};
    time_t current_time;
    struct tm *current_tm;

    // 嘗試解析完整格式 YYYY-MM-DD HH:MM
    int year;
    if (sscanf(date_str, "%4d-%2d-%2d %2d:%2d", &year, &month, &day, &hour, &minute) == 5) {
        tm_time.tm_year = year - 1900;
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;
        return mktime(&tm_time);
    }
    
    // 如果不是完整格式，則嘗試解析 MM-DD HH:MM，並補上當前年份
    if (sscanf(date_str, "%2d-%2d %2d:%2d", &month, &day, &hour, &minute) == 4) {
        current_time = time(NULL);
        current_tm = localtime(&current_time);

        tm_time.tm_year = current_tm->tm_year; // 使用當前年份
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;
        // 如果這個日期在當前時間之前，嘗試使用下一年
        // 這是為了處理跨年的情況，例如在12月新增1月的任務
        time_t parsed_time = mktime(&tm_time);
        if (parsed_time != (time_t)-1 && parsed_time < current_time) {
            tm_time.tm_year++; // 嘗試增加一年
            parsed_time = mktime(&tm_time);
        }
        return parsed_time;
    }

    return (time_t)-1; // Return error value if parsing fails
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

    return 0; // 理論上所有情況都已被處理
}

void sort_tasks_by_due_date() {
    qsort(tasks, task_count, sizeof(Task), compare_due_date);
}

// 輔助函數：將 MM-DD HH:MM 轉換為 YYYY-MM-DD HH:MM
// 內部使用，不作為 DLL 導出
static void format_due_date_with_year(char* dest, const char* src, size_t dest_len) {
    if (src == NULL || src[0] == '\0') {
        dest[0] = '\0';
        return;
    }
    
    int month, day, hour, minute;
    // 檢查輸入是否是 MM-DD HH:MM 格式
    if (sscanf(src, "%2d-%2d %2d:%2d", &month, &day, &hour, &minute) == 4) {
        snprintf(dest, dest_len, "%04d-%02d-%02d %02d:%02d", get_current_year(), month, day, hour, minute);
    } else {
        // 如果已經是 YYYY-MM-DD HH:MM 格式，直接複製
        strncpy(dest, src, dest_len - 1);
        dest[dest_len - 1] = '\0';
    }
}


int add_task(const char* desc, const char* due_date) {
    if (task_count >= MAX_TASKS) return -1;

    strncpy(tasks[task_count].desc, desc, MAX_LEN - 1);
    tasks[task_count].desc[MAX_LEN - 1] = '\0';

    if (due_date != NULL && due_date[0] != '\0') {
        // 在內部儲存完整的帶年份格式
        format_due_date_with_year(tasks[task_count].due_date, due_date, MAX_LEN);
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
        // 在內部儲存完整的帶年份格式
        format_due_date_with_year(tasks[index].due_date, new_due_date, MAX_LEN);
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
    // 直接返回完整的日期字串，Python 端會處理格式化
    return tasks[index].due_date;
}