#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_TASKS 100
#define MAX_LEN 100

typedef struct {
    char desc[MAX_LEN];
    int done;
    char due_date[MAX_LEN];
    int id;
} Task;

static Task tasks[MAX_TASKS];
static int task_count = 0;
static int next_id = 0;

static int get_current_year() {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    return info->tm_year + 1900;
}

time_t get_time_from_string(const char* date_str) {
    int year, month, day, hour, minute;
    struct tm tm_time = {0};
    time_t current_time;
    struct tm *current_tm;

    if (sscanf(date_str, "%4d-%2d-%2d %2d:%2d", &year, &month, &day, &hour, &minute) == 5) {
        tm_time.tm_year = year - 1900;
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;
        return mktime(&tm_time);
    }

    if (sscanf(date_str, "%2d-%2d %2d:%2d", &month, &day, &hour, &minute) == 4) {
        current_time = time(NULL);
        current_tm = localtime(&current_time);
        tm_time.tm_year = current_tm->tm_year;
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;

        time_t parsed_time = mktime(&tm_time);
        if (parsed_time != (time_t)-1 && parsed_time < current_time) {
            tm_time.tm_year++;
            parsed_time = mktime(&tm_time);
        }
        return parsed_time;
    }

    return (time_t)-1;
}

int compare_due_date(const void *a, const void *b) {
    const Task *task_a = (const Task*)a;
    const Task *task_b = (const Task*)b;

    int a_has_due = task_a->due_date[0] != '\0';
    int b_has_due = task_b->due_date[0] != '\0';

    time_t time_a = a_has_due ? get_time_from_string(task_a->due_date) : (time_t)-1;
    time_t time_b = b_has_due ? get_time_from_string(task_b->due_date) : (time_t)-1;

    int a_valid = time_a != (time_t)-1;
    int b_valid = time_b != (time_t)-1;

    if (a_valid && !b_valid) return -1;
    if (!a_valid && b_valid) return 1;
    if (a_valid && b_valid) return (time_a > time_b) - (time_a < time_b);
    return (task_a->id > task_b->id) - (task_a->id < task_b->id);
}

void sort_tasks_by_due_date() {
    qsort(tasks, task_count, sizeof(Task), compare_due_date);
}

static void format_due_date_with_year(char* dest, const char* src, size_t dest_len) {
    if (!src || src[0] == '\0') {
        dest[0] = '\0';
        return;
    }

    int month, day, hour, minute;
    if (sscanf(src, "%2d-%2d %2d:%2d", &month, &day, &hour, &minute) == 4) {
        snprintf(dest, dest_len, "%04d-%02d-%02d %02d:%02d",
                 get_current_year(), month, day, hour, minute);
    } else {
        strncpy(dest, src, dest_len - 1);
        dest[dest_len - 1] = '\0';
    }
}

__declspec(dllexport)
int add_task(const char* desc, const char* due_date) {
    if (!desc || task_count >= MAX_TASKS) return -1;

    strncpy(tasks[task_count].desc, desc, MAX_LEN - 1);
    tasks[task_count].desc[MAX_LEN - 1] = '\0';

    if (due_date && due_date[0] != '\0') {
        format_due_date_with_year(tasks[task_count].due_date, due_date, MAX_LEN);
    } else {
        tasks[task_count].due_date[0] = '\0';
    }

    tasks[task_count].done = 0;
    tasks[task_count].id = next_id++;

    task_count++;
    sort_tasks_by_due_date();
    return task_count - 1;
}

__declspec(dllexport)
int update_task(int index, const char* new_desc, const char* new_due_date) {
    if (index < 0 || index >= task_count || !new_desc) return -1;

    strncpy(tasks[index].desc, new_desc, MAX_LEN - 1);
    tasks[index].desc[MAX_LEN - 1] = '\0';

    if (new_due_date && new_due_date[0] != '\0') {
        format_due_date_with_year(tasks[index].due_date, new_due_date, MAX_LEN);
    } else {
        tasks[index].due_date[0] = '\0';
    }

    sort_tasks_by_due_date();
    return 0;
}

__declspec(dllexport)
int mark_done(int index) {
    if (index < 0 || index >= task_count) return -1;
    tasks[index].done = 1;
    return 0;
}

__declspec(dllexport)
int delete_task(int index) {
    if (index < 0 || index >= task_count) return -1;
    for (int i = index; i < task_count - 1; i++) {
        tasks[i] = tasks[i + 1];
    }
    task_count--;
    sort_tasks_by_due_date();
    return 0;
}

__declspec(dllexport)
void clear_completed_tasks() {
    int i, j;
    for (i = 0, j = 0; i < task_count; i++) {
        if (!tasks[i].done) {
            if (i != j) tasks[j] = tasks[i];
            j++;
        }
    }
    task_count = j;
    sort_tasks_by_due_date();
}

__declspec(dllexport)
int get_task_count() {
    return task_count;
}

__declspec(dllexport)
const char* get_task_desc(int index) {
    if (index < 0 || index >= task_count) return "";
    return tasks[index].desc;
}

__declspec(dllexport)
int is_task_done(int index) {
    if (index < 0 || index >= task_count) return -1;
    return tasks[index].done;
}

__declspec(dllexport)
const char* get_task_due_date(int index) {
    if (index < 0 || index >= task_count) return "";
    return tasks[index].due_date;
}

__declspec(dllexport)
int save_tasks(const char* filename) {
    if (!filename) return -1;

    FILE* fp = fopen(filename, "w");
    if (!fp) return -1;

    for (int i = 0; i < task_count; ++i) {
        fprintf(fp, "%d\t%d\t%s\t%s\n",
            tasks[i].done,
            tasks[i].id,
            tasks[i].due_date[0] == '\0' ? "<none>" : tasks[i].due_date,
            tasks[i].desc);
    }

    fclose(fp);
    return 0;
}

__declspec(dllexport)
int load_tasks(const char* filename) {
    if (!filename) return -1;

    FILE* fp = fopen(filename, "r");
    if (!fp) return -1;

    task_count = 0;
    next_id = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (task_count >= MAX_TASKS) break;

        int done, id;
        char raw_due[MAX_LEN] = "";
        char desc[MAX_LEN] = "";

        if (sscanf(line, "%d\t%d\t%99[^\t]\t%99[^\n]", &done, &id, raw_due, desc) == 4) {
            strncpy(tasks[task_count].desc, desc, MAX_LEN - 1);
            tasks[task_count].desc[MAX_LEN - 1] = '\0';

            if (strcmp(raw_due, "<none>") == 0) {
                tasks[task_count].due_date[0] = '\0';
            } else {
                strncpy(tasks[task_count].due_date, raw_due, MAX_LEN - 1);
                tasks[task_count].due_date[MAX_LEN - 1] = '\0';
            }

            tasks[task_count].done = done;
            tasks[task_count].id = id;

            task_count++;
            if (id >= next_id) next_id = id + 1;
        }
    }

    fclose(fp);
    sort_tasks_by_due_date();
    return 0;
}
