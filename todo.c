#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_TASKS 100
#define MAX_LEN 100 // Task description and date string max length
#define FILENAME "tasks.txt" // Default filename for tasks

typedef struct {
    char desc[MAX_LEN];
    int done;
    char due_date[MAX_LEN]; // Internal storage: YYYY-MM-DD HH:MM
    int id; // Unique ID for creation order
    int pinned; // 0 = not pinned, 1 = pinned
} Task;

static Task tasks[MAX_TASKS];
static int task_count = 0;
static int next_id = 0; // For generating unique task IDs

// Forward declaration for sort_tasks_by_due_date
void sort_tasks_by_due_date(); 

// Internal helper: get current year
static int get_current_year() {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    return info->tm_year + 1900;
}

// Parse MM-DD HH:MM or YYYY-MM-DD HH:MM string to time_t
time_t get_time_from_string(const char* date_str) {
    int month, day, hour, minute;
    struct tm tm_time = {0}; // Initialize to all zeros
    time_t current_time;
    struct tm *current_tm;

    // Try parsing YYYY-MM-DD HH:MM
    int year;
    if (sscanf(date_str, "%4d-%2d-%2d %2d:%2d", &year, &month, &day, &hour, &minute) == 5) {
        tm_time.tm_year = year - 1900;
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;
        return mktime(&tm_time);
    }
    
    // Try parsing MM-DD HH:MM, using current year
    if (sscanf(date_str, "%2d-%2d %2d:%2d", &month, &day, &hour, &minute) == 4) {
        current_time = time(NULL);
        current_tm = localtime(&current_time);

        tm_time.tm_year = current_tm->tm_year; 
        tm_time.tm_mon  = month - 1;
        tm_time.tm_mday = day;
        tm_time.tm_hour = hour;
        tm_time.tm_min  = minute;
        
        time_t parsed_time = mktime(&tm_time);
        // If parsed date is in the past (e.g. adding Jan task in Dec), assume next year
        if (parsed_time != (time_t)-1 && parsed_time < current_time) {
            tm_time.tm_year++; 
            parsed_time = mktime(&tm_time);
        }
        return parsed_time;
    }
    return (time_t)-1; // Parsing failed
}

// Comparison function for qsort
int compare_due_date(const void *a, const void *b) {
    const Task *task_a = (const Task*)a;
    const Task *task_b = (const Task*)b;

    // Pinned tasks come first
    if (task_a->pinned != task_b->pinned) {
        return task_b->pinned - task_a->pinned;
    }

    int a_has_due_date_str = (task_a->due_date[0] != '\0');
    int b_has_due_date_str = (task_b->due_date[0] != '\0');
    time_t time_a = a_has_due_date_str ? get_time_from_string(task_a->due_date) : (time_t)-1;
    time_t time_b = b_has_due_date_str ? get_time_from_string(task_b->due_date) : (time_t)-1;
    int a_is_valid_date = (time_a != (time_t)-1);
    int b_is_valid_date = (time_b != (time_t)-1);

    if (a_is_valid_date && !b_is_valid_date) return -1; // A has date, B doesn't -> A first
    if (!a_is_valid_date && b_is_valid_date) return 1;  // B has date, A doesn't -> B first

    // Both have valid dates: sort by time
    if (a_is_valid_date && b_is_valid_date) {
        if (time_a < time_b) return -1;
        if (time_a > time_b) return 1;
    }

    // Neither has valid date (or dates are equal): sort by creation ID
    return (task_a->id > task_b->id) - (task_a->id < task_b->id);
}

// Sort tasks
void sort_tasks_by_due_date() {
    qsort(tasks, task_count, sizeof(Task), compare_due_date);
}

// Helper to format MM-DD HH:MM to YYYY-MM-DD HH:MM
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

// --- Task Management Functions ---
int add_task(const char* desc, const char* due_date) {
    if (task_count >= MAX_TASKS) return -1; // Task list full

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
    return task_count - 1; // Return index of new task
}

int update_task(int index, const char* new_desc, const char* new_due_date) {
    if (index < 0 || index >= task_count) return -1; // Invalid index

    strncpy(tasks[index].desc, new_desc, MAX_LEN - 1);
    tasks[index].desc[MAX_LEN - 1] = '\0';

    if (new_due_date != NULL && new_due_date[0] != '\0') {
        format_due_date_with_year(tasks[index].due_date, new_due_date, MAX_LEN);
    } else {
        tasks[index].due_date[0] = '\0';
    }

    sort_tasks_by_due_date();
    return 0; // Success
}

int mark_done(int index) {
    if (index < 0 || index >= task_count) return -1;
    tasks[index].done = 1;
    // Re-sorting might not be strictly necessary here unless 'done' status affects sort order directly
    // sort_tasks_by_due_date(); 
    return 0;
}

int delete_task(int index) {
    if (index < 0 || index >= task_count) return -1;
    for (int i = index; i < task_count - 1; i++) {
        tasks[i] = tasks[i + 1];
    }
    task_count--;
    // sort_tasks_by_due_date(); // Already sorted, or will be on next relevant op
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
    // sort_tasks_by_due_date(); // Re-sort if order might change
}

int toggle_pin(int index) {
    if (index < 0 || index >= task_count) return -1;
    tasks[index].pinned = !tasks[index].pinned;
    sort_tasks_by_due_date(); // Pin status affects sort order
    return 0;
}

// --- Getters ---
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


// --- Save and Load Functions ---

// Saves tasks to the specified file.
// Returns 0 on success, -1 on failure.
int save_tasks_to_file(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file for writing");
        return -1;
    }

    // Write next_id first
    fprintf(file, "%d\n", next_id);

    // Write each task
    for (int i = 0; i < task_count; i++) {
        fprintf(file, "%d|%d|%d|%s|%s\n",
                tasks[i].id,
                tasks[i].done,
                tasks[i].pinned,
                tasks[i].due_date, // Due date can be empty, fprintf handles "" fine
                tasks[i].desc);
    }

    if (fclose(file) != 0) {
        perror("Error closing file after writing");
        return -1; 
    }
    return 0; // Success
}

// Loads tasks from the specified file.
// Returns 0 on success, 1 if file not found (treated as success with 0 tasks), -1 on parsing error.
int load_tasks_from_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        // File not found, likely first run. Initialize and return success.
        task_count = 0;
        next_id = 0;
        return 1; // Indicate file not found, but operation is "successful" (empty list)
    }

    // Read next_id
    if (fscanf(file, "%d\n", &next_id) != 1) {
        // If next_id cannot be read (e.g., empty or malformed file)
        fclose(file);
        task_count = 0; // Reset state
        next_id = 0;
        if (feof(file)) return 1; // Empty file is like file not found
        fprintf(stderr, "Error reading next_id from file.\n");
        return -1; // Parsing error
    }
    
    task_count = 0; // Reset task count before loading
    char line_buffer[MAX_LEN * 4]; // Buffer for reading lines

    while (fgets(line_buffer, sizeof(line_buffer), file) != NULL && task_count < MAX_TASKS) {
        // Remove newline characters
        line_buffer[strcspn(line_buffer, "\n\r")] = 0;

        if (strlen(line_buffer) == 0) continue; // Skip empty lines

        Task current_task = {0}; // Initialize task struct
        char* p = line_buffer;
        char* next_p;
        int field_index = 0;

        // Field 0: ID
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "Malformed line (ID): %s\n", line_buffer); continue; }
        *next_p = '\0';
        current_task.id = atoi(p);
        p = next_p + 1;

        // Field 1: Done
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "Malformed line (Done): %s\n", line_buffer); continue; }
        *next_p = '\0';
        current_task.done = atoi(p);
        p = next_p + 1;

        // Field 2: Pinned
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "Malformed line (Pinned): %s\n", line_buffer); continue; }
        *next_p = '\0';
        current_task.pinned = atoi(p);
        p = next_p + 1;

        // Field 3: Due Date
        next_p = strchr(p, '|');
        if (next_p == NULL) { fprintf(stderr, "Malformed line (Due Date): %s\n", line_buffer); continue; }
        *next_p = '\0';
        strncpy(current_task.due_date, p, MAX_LEN - 1);
        current_task.due_date[MAX_LEN - 1] = '\0';
        p = next_p + 1;
        
        // Field 4: Description (rest of the string)
        strncpy(current_task.desc, p, MAX_LEN - 1);
        current_task.desc[MAX_LEN - 1] = '\0';

        tasks[task_count++] = current_task;
    }

    fclose(file);
    sort_tasks_by_due_date(); // Sort tasks after loading
    return 0; // Success
}