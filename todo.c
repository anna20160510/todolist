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
    int has_due_date;           // 0 for no due date, 1 for has due date
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

 // Tasks without a due date are sorted to the end of the list
    if (task_a->has_due_date == 0 && task_b->has_due_date == 1) return 1;  // A has no date, B has date -> A comes after B
    if (task_a->has_due_date == 1 && task_b->has_due_date == 0) return -1; // A has date, B has no date -> A comes before B
    if (task_a->has_due_date == 0 && task_b->has_due_date == 0) return 0;  // Both have no date -> they are equal in terms of date

    time_t time_a = get_time_from_string(task_a->due_date);
    time_t time_b = get_time_from_string(task_b->due_date);

    // Handle potential parsing errors if any were to occur (though sscanf is used carefully)
    if (time_a == (time_t)-1 && time_b != (time_t)-1) return 1; // A parsing failed, B didn't -> A comes after B
    if (time_a != (time_t)-1 && time_b == (time_t)-1) return -1; // A didn't fail, B did -> A comes before B
    if (time_a == (time_t)-1 && time_b == (time_t)-1) return 0; // Both parsing failed -> they are equal

    return (time_a > time_b) - (time_a < time_b);
}

void sort_tasks_by_due_date() {
    qsort(tasks, task_count, sizeof(Task), compare_due_date);
}

int add_task(const char* desc, const char* due_date) {
    if (task_count >= MAX_TASKS) return -1;

    strncpy(tasks[task_count].desc, desc, MAX_LEN - 1);
    tasks[task_count].desc[MAX_LEN - 1] = '\0';

    // If due_date is an empty string, set has_due_date to 0
    if (due_date == NULL || strlen(due_date) == 0) {
        tasks[task_count].due_date[0] = '\0'; // Ensure the string is empty
        tasks[task_count].has_due_date = 0;
    } else {
        strncpy(tasks[task_count].due_date, due_date, MAX_LEN - 1);
        tasks[task_count].due_date[MAX_LEN - 1] = '\0';
        tasks[task_count].has_due_date = 1;
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

    // If new_due_date is an empty string, set has_due_date to 0
    if (new_due_date == NULL || strlen(new_due_date) == 0) {
        tasks[index].due_date[0] = '\0'; // Ensure the string is empty
        tasks[index].has_due_date = 0;
    } else {
        strncpy(tasks[index].due_date, new_due_date, MAX_LEN - 1);
        tasks[index].due_date[MAX_LEN - 1] = '\0';
        tasks[index].has_due_date = 1;
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

// New helper function to check if a task has a due date
int has_task_due_date(int index) {
    if (index < 0 || index >= task_count) return -1;
    return tasks[index].has_due_date;
}
