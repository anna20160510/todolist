#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_TASKS 100               // 最大任務數量
#define MAX_LEN 100                 // 任務描述與日期字串的最大長度
#define FILENAME "tasks.txt"        // 任務預設儲存檔案名稱

// 任務資料結構
typedef struct {
    char desc[MAX_LEN];            // 任務描述
    int done;                      // 是否完成 (0 = 未完成, 1 = 已完成)
    char due_date[MAX_LEN];        // 任務截止日期，格式為 YYYY-MM-DD HH:MM
    int id;                        // 任務唯一 ID，表示建立順序
    int pinned;                    // 是否置頂 (0 = 否, 1 = 是)
} Task;

static Task tasks[MAX_TASKS];      // 任務陣列
static int task_count = 0;         // 當前任務數
static int next_id = 0;            // 下一個可用的任務 ID

// 函式前向宣告：用於依截止日期排序任務
void sort_tasks_by_due_date(); 

// 取得當前年份
static int get_current_year() {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    return info->tm_year + 1900;
}

// 將字串格式的日期轉為 time_t
// 支援格式：YYYY-MM-DD HH:MM 或 MM-DD HH:MM
time_t get_time_from_string(const char* date_str) {
    int month, day, hour, minute;
    struct tm tm_time = {0}; // 初始化為全零
    time_t current_time;
    struct tm *current_tm;

    int year;
    // 嘗試解析 YYYY-MM-DD HH:MM
    if (sscanf(date_str, "%4d-%2d-%2d %2d:%2d", &year, &month, &day, &hour, &minute) == 5) {
        tm_time.tm_year = year - 1900;
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;
        return mktime(&tm_time);
    }
    
    // 嘗試解析 MM-DD HH:MM，使用當前年份
    if (sscanf(date_str, "%2d-%2d %2d:%2d", &month, &day, &hour, &minute) == 4) {
        current_time = time(NULL);
        current_tm = localtime(&current_time);

        tm_time.tm_year = current_tm->tm_year; 
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;
        
        time_t parsed_time = mktime(&tm_time);
        // 若解析出的時間在過去，則視為下一年
        if (parsed_time != (time_t)-1 && parsed_time < current_time) {
            tm_time.tm_year++; 
            parsed_time = mktime(&tm_time);
        }
        return parsed_time;
    }
    return (time_t)-1; // 解析失敗
}

// 任務排序用的比較函式
int compare_due_date(const void *a, const void *b) {
    const Task *task_a = (const Task*)a;
    const Task *task_b = (const Task*)b;

    // 優先排列置頂任務
    if (task_a->pinned != task_b->pinned) {
        return task_b->pinned - task_a->pinned;
    }

    int a_has_due_date_str = (task_a->due_date[0] != '\0');
    int b_has_due_date_str = (task_b->due_date[0] != '\0');
    time_t time_a = a_has_due_date_str ? get_time_from_string(task_a->due_date) : (time_t)-1;
    time_t time_b = b_has_due_date_str ? get_time_from_string(task_b->due_date) : (time_t)-1;
    int a_is_valid_date = (time_a != (time_t)-1);
    int b_is_valid_date = (time_b != (time_t)-1);

    if (a_is_valid_date && !b_is_valid_date) return -1; // A 有日期、B 無 -> A 在前
    if (!a_is_valid_date && b_is_valid_date) return 1;  // B 有日期、A 無 -> B 在前

    // 若兩者都有合法日期，按時間早晚排序
    if (a_is_valid_date && b_is_valid_date) {
        if (time_a < time_b) return -1;
        if (time_a > time_b) return 1;
    }

    // 若兩者都無有效日期或日期相同，依任務 ID 排序
    return (task_a->id > task_b->id) - (task_a->id < task_b->id);
}

// 任務排序
void sort_tasks_by_due_date() {
    qsort(tasks, task_count, sizeof(Task), compare_due_date);
}

// 將 MM-DD HH:MM 格式補上年份轉為 YYYY-MM-DD HH:MM
static void format_due_date_with_year(char* dest, const char* src, size_t dest_len) {
    if (src == NULL || src[0] == '\0') {
        dest[0] = '\0';
        return;
    }
    int month, day, hour, minute;
    if (sscanf(src, "%2d-%2d %2d:%2d", &month, &day, &hour, &minute) == 4) {
        snprintf(dest, dest_len, "%04d-%02d-%02d %02d:%02d", get_current_year(), month, day, hour, minute);
    } else {
        strncpy(dest, src, dest_len - 1);
        dest[dest_len - 1] = '\0';
    }
}

// --- 任務管理功能 ---
// 新增任務
int add_task(const char* desc, const char* due_date) {
    if (task_count >= MAX_TASKS) return -1; // 任務已滿

    strncpy(tasks[task_count].desc, desc, MAX_LEN - 1);
    tasks[task_count].desc[MAX_LEN - 1] = '\0';

    if (due_date != NULL && due_date[0] != '\0') {
        format_due_date_with_year(tasks[task_count].due_date, due_date, MAX_LEN);
    } else {
        tasks[task_count].due_date[0] = '\0';
    }
    tasks[task_count].done = 0;
    tasks[task_count].id = next_id++;
    tasks[task_count].pinned = 0;

    task_count++;
    sort_tasks_by_due_date();
    return task_count - 1; // 回傳任務索引
}

// 更新任務內容
int update_task(int index, const char* new_desc, const char* new_due_date) {
    if (index < 0 || index >= task_count) return -1; // 無效索引

    strncpy(tasks[index].desc, new_desc, MAX_LEN - 1);
    tasks[index].desc[MAX_LEN - 1] = '\0';

    if (new_due_date != NULL && new_due_date[0] != '\0') {
        format_due_date_with_year(tasks[index].due_date, new_due_date, MAX_LEN);
    } else {
        tasks[index].due_date[0] = '\0';
    }

    sort_tasks_by_due_date();
    return 0; // 成功
}

// 將任務標記為完成
int mark_done(int index) {
    if (index < 0 || index >= task_count) return -1;
    tasks[index].done = 1;
    // 若排序與完成狀態無關，可以不重排
    // sort_tasks_by_due_date(); 
    return 0;
}

// 刪除任務
int delete_task(int index) {
    if (index < 0 || index >= task_count) return -1;
    for (int i = index; i < task_count - 1; i++) {
        tasks[i] = tasks[i + 1];
    }
    task_count--;
    // sort_tasks_by_due_date(); // 可略，下一次操作會排序
    return 0;
}

// 清除所有已完成的任務
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
    // sort_tasks_by_due_date(); // 若排序會受影響再重排
}

// 切換任務的置頂狀態
int toggle_pin(int index) {
    if (index < 0 || index >= task_count) return -1;
    tasks[index].pinned = !tasks[index].pinned;
    sort_tasks_by_due_date(); // 置頂狀態會影響排序
    return 0;
}

// --- 存取任務資訊的函式 ---
int is_task_pinned(int index) {
    if (index < 0 || index >= task_count) return -1; 
    return tasks[index].pinned;
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

// --- 儲存與載入任務功能 ---

// 將任務儲存到指定檔案，成功回傳 0，失敗回傳 -1
int save_tasks_to_file(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("開啟檔案寫入失敗");
        return -1;
    }

    // 儲存 next_id
    fprintf(file, "%d\n", next_id);

    // 寫入所有任務資料
    for (int i = 0; i < task_count; i++) {
        fprintf(file, "%d|%d|%d|%s|%s\n",
                tasks[i].id,
                tasks[i].done,
                tasks[i].pinned,
                tasks[i].due_date,
                tasks[i].desc);
    }

    if (fclose(file) != 0) {
        perror("關閉檔案時發生錯誤");
        return -1; 
    }
    return 0; // 成功
}

// 從指定檔案載入任務
// 成功回傳 0，找不到檔案回傳 1，解析錯誤回傳 -1
int load_tasks_from_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        // 檔案不存在，初始化並回傳成功
        task_count = 0;
        next_id = 0;
        return 1;
    }

    // 讀取 next_id
    if (fscanf(file, "%d\n", &next_id) != 1) {
        fclose(file);
        task_count = 0;
        next_id = 0;
        if (feof(file)) return 1; // 空檔案視為成功
        fprintf(stderr, "讀取 next_id 時發生錯誤。\n");
        return -1;
    }

    task_count = 0;
    char line_buffer[MAX_LEN * 4];

    while (fgets(line_buffer, sizeof(line_buffer), file) != NULL && task_count < MAX_TASKS) {
        line_buffer[strcspn(line_buffer, "\n\r")] = 0; // 去除換行符

        if (strlen(line_buffer) == 0) continue;

        Task current_task = {0};
        char* p = line_buffer;
        char* next_p;

        // 解析 ID
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "格式錯誤 (ID): %s\n", line_buffer); continue; }
        *next_p = '\0';
        current_task.id = atoi(p);
        p = next_p + 1;

        // 解析 Done
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "格式錯誤 (Done): %s\n", line_buffer); continue; }
        *next_p = '\0';
        current_task.done = atoi(p);
        p = next_p + 1;

        // 解析 Pinned
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "格式錯誤 (Pinned): %s\n", line_buffer); continue; }
        *next_p = '\0';
        current_task.pinned = atoi(p);
        p = next_p + 1;

        // 解析 Due Date
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "格式錯誤 (Due Date): %s\n", line_buffer); continue; }
        *next_p = '\0';
        strncpy(current_task.due_date, p, MAX_LEN - 1);
        current_task.due_date[MAX_LEN - 1] = '\0';
        p = next_p + 1;

        // 解析 Description
        strncpy(current_task.desc, p, MAX_LEN - 1);
        current_task.desc[MAX_LEN - 1] = '\0';

        tasks[task_count++] = current_task;
    }

    fclose(file);
    sort_tasks_by_due_date(); // 載入後排序
    return 0; // 成功
}
