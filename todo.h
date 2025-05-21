#ifndef TODO_H
#define TODO_H

#define MAX_TASKS 100
#define MAX_DESC_LEN 256

typedef struct {
    char desc[MAX_DESC_LEN];
    int done;
} Task;

int add_task(const char* desc);
void mark_done(int index);
void delete_task(int index);
int get_task_count();
const char* get_task_desc(int index);
int is_task_done(int index);

#endif
