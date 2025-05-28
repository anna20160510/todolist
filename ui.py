import tkinter as tk
import ctypes
from ctypes import c_char_p, c_int
import sys
import os
import traceback
import datetime # 新增：用於獲取當前年份和日期格式化

# --- DLL Path Helper Function ---
def get_dll_path(dll_name="todo.dll"):
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, dll_name)
    else:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), dll_name)

# --- Optional Error Logging for PyInstaller Builds ---
if getattr(sys, 'frozen', False):
    try:
        pass
    except Exception as e:
        with open("error.log", "w") as f:
            f.write(traceback.format_exc())
        raise

# --- Load C Library and Define Function Interfaces ---
try:
    lib = ctypes.CDLL(get_dll_path())
except Exception as e:
    print(f"Error loading C library: {e}")
    print(f"Make sure '{get_dll_path()}' exists and is compiled for your system architecture.")
    sys.exit(1)

lib.add_task.argtypes = [c_char_p, c_char_p]
lib.add_task.restype = c_int
lib.update_task.argtypes = [c_int, c_char_p, c_char_p]
lib.update_task.restype = c_int
lib.mark_done.argtypes = [c_int]
lib.mark_done.restype = c_int
lib.delete_task.argtypes = [c_int]
lib.delete_task.restype = c_int
lib.clear_completed_tasks.restype = None
lib.get_task_count.restype = c_int
lib.get_task_desc.argtypes = [c_int]
lib.get_task_desc.restype = c_char_p
lib.is_task_done.argtypes = [c_int]
lib.is_task_done.restype = c_int
lib.get_task_due_date.argtypes = [c_int]
lib.get_task_due_date.restype = c_char_p

# --- Global variable to store selected task index ---
current_selected_task_index = -1
task_text_ranges = []
HIGHLIGHT_TAG = "selected_task_highlight"

# --- Core Task Management Functions (Python Wrappers) ---

def set_action_buttons_state(state):
    update_btn.config(state=state)
    mark_done_btn.config(state=state)
    delete_btn.config(state=state)

def update_task_list():
    task_display_text.config(state=tk.NORMAL)
    task_display_text.delete(1.0, tk.END)

    global task_text_ranges
    task_text_ranges = []

    for i in range(lib.get_task_count()):
        desc = lib.get_task_desc(i).decode()
        full_due_date_str = lib.get_task_due_date(i).decode() # 從 C 獲取完整日期字串
        done = lib.is_task_done(i)
        symbol = "✔️" if done else "❌"
        
        # 在 Python 端處理日期格式化，移除年份
        due_display = ""
        if full_due_date_str:
            try:
                # 嘗試解析 YYYY-MM-DD HH:MM
                dt_object = datetime.datetime.strptime(full_due_date_str, "%Y-%m-%d %H:%M")
                due_display = dt_object.strftime(" (Due: %m-%d %H:%M)") # 格式化為 MM-DD HH:MM
            except ValueError:
                # 如果 C 端存儲了不符合預期的格式，則不顯示日期
                pass

        display_text = f"{symbol} {desc}{due_display}\n"

        start_index = task_display_text.index(tk.END + "-1c")
        task_display_text.insert(tk.END, display_text)
        end_index = task_display_text.index(tk.END + "-1c")

        task_text_ranges.append({"task_index": i, "start_index": start_index, "end_index": end_index})

    task_display_text.config(state=tk.DISABLED)
    highlight_selected_task()

def add_task(event=None):
    desc = desc_entry.get().strip()
    due = due_entry.get().strip()
    
    if not desc:
        print("Please enter a task description.")
        return

    # --- 新增：在 Python 端為 MM-DD HH:MM 格式的日期補上當前年份 ---
    processed_due_date = ""
    if due:
        try:
            # 檢查是否是 MM-DD HH:MM 格式
            datetime.datetime.strptime(due, "%m-%d %H:%M") 
            current_year = datetime.datetime.now().year
            processed_due_date = f"{current_year}-{due}" # 補上當年年份
        except ValueError:
            # 如果是 YYYY-MM-DD HH:MM 格式，或其它無法解析的，直接使用原始輸入
            processed_due_date = due
            
    if lib.add_task(desc.encode(), processed_due_date.encode()) >= 0: # 傳遞處理過的日期字串
        update_task_list()
        desc_entry.delete(0, tk.END)
        due_entry.delete(0, tk.END)
        clear_selection_and_fields()
        desc_entry.focus_set()

def mark_task_done():
    if current_selected_task_index == -1:
        print("Please select a task to mark as done.")
        return
    lib.mark_done(current_selected_task_index)
    update_task_list()
    clear_selection_and_fields()

def delete_task():
    if current_selected_task_index == -1:
        print("Please select a task to delete.")
        return
    lib.delete_task(current_selected_task_index)
    update_task_list()
    clear_selection_and_fields()

def clear_completed():
    lib.clear_completed_tasks()
    update_task_list()
    clear_selection_and_fields()

def update_task():
    if current_selected_task_index == -1:
        print("Select a task to update.")
        return
    new_desc = desc_entry.get().strip()
    new_due = due_entry.get().strip()
    
    if not new_desc:
        print("Please enter a new task description.")
        return
    
    # --- 新增：在 Python 端為 MM-DD HH:MM 格式的日期補上當前年份 (更新時) ---
    processed_new_due_date = ""
    if new_due:
        try:
            # 檢查是否是 MM-DD HH:MM 格式
            datetime.datetime.strptime(new_due, "%m-%d %H:%M") 
            current_year = datetime.datetime.now().year
            processed_new_due_date = f"{current_year}-{new_due}" # 補上當年年份
        except ValueError:
            processed_new_due_date = new_due

    if lib.update_task(current_selected_task_index, new_desc.encode(), processed_new_due_date.encode()) == 0: # 傳遞處理過的日期字串
        update_task_list()
        clear_selection_and_fields()

def select_task_and_fill_fields(index):
    global current_selected_task_index
    if index == current_selected_task_index:
        clear_selection_and_fields()
        return

    current_selected_task_index = index
    desc = lib.get_task_desc(index).decode()
    full_due = lib.get_task_due_date(index).decode() # 獲取完整日期

    # 在選取時，將完整日期格式化為 MM-DD HH:MM 填充到輸入框
    display_due = ""
    if full_due:
        try:
            dt_object = datetime.datetime.strptime(full_due, "%Y-%m-%d %H:%M")
            display_due = dt_object.strftime("%m-%d %H:%M")
        except ValueError:
            display_due = full_due # 如果解析失敗，則顯示原始字串

    desc_entry.delete(0, tk.END)
    desc_entry.insert(0, desc)
    due_entry.delete(0, tk.END)
    due_entry.insert(0, display_due) # 填充格式化後的日期
    set_action_buttons_state(tk.NORMAL)
    highlight_selected_task()

def text_click_handler(event):
    clicked_text_index = task_display_text.index(f"@{event.x},{event.y}")

    selected_task_idx = -1
    for item in task_text_ranges:
        if task_display_text.compare(clicked_text_index, ">=", item["start_index"]) and \
           task_display_text.compare(clicked_text_index, "<", item["end_index"]):
            selected_task_idx = item["task_index"]
            break
    
    root.after(1, lambda: _process_click_selection(selected_task_idx))

def _process_click_selection(selected_task_idx):
    if selected_task_idx != -1:
        select_task_and_fill_fields(selected_task_idx)
    else:
        clear_selection_and_fields()

def clear_selection_and_fields():
    global current_selected_task_index
    current_selected_task_index = -1
    desc_entry.delete(0, tk.END)
    due_entry.delete(0, tk.END)
    set_action_buttons_state(tk.DISABLED)
    highlight_selected_task()

def highlight_selected_task():
    task_display_text.tag_remove(HIGHLIGHT_TAG, 1.0, tk.END)
    
    if current_selected_task_index != -1:
        for item in task_text_ranges:
            if item["task_index"] == current_selected_task_index:
                task_display_text.tag_add(HIGHLIGHT_TAG, item["start_index"], item["end_index"])
                task_display_text.see(item["start_index"])
                break

# --- UI Setup ---
root = tk.Tk()
root.title("To-Do List Manager")

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

main_frame = tk.Frame(root)
main_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

main_frame.grid_columnconfigure(0, weight=3)
main_frame.grid_columnconfigure(1, weight=1)
main_frame.grid_rowconfigure(0, weight=1)

left_frame = tk.Frame(main_frame)
left_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

task_display_text = tk.Text(left_frame, height=15, font=('Arial', 10), wrap=tk.WORD, state=tk.DISABLED, relief=tk.FLAT, bd=0)
task_display_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

task_display_text.bind("<Button-1>", text_click_handler)
task_display_text.tag_configure(HIGHLIGHT_TAG, background="SystemHighlight", foreground="white")

scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=task_display_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

task_display_text.config(yscrollcommand=scrollbar.set)

right_frame = tk.Frame(main_frame)
right_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

tk.Label(right_frame, text="Task Description:").pack(pady=(0, 2))
desc_entry = tk.Entry(right_frame, width=40, font=('Arial', 10))
desc_entry.pack(pady=(0, 5))

desc_entry.bind("<Return>", add_task)

# --- 修改提示：不再包含年份 ---
tk.Label(right_frame, text="Due Date (MM-DD HH:MM):").pack(pady=(0, 2))
due_entry = tk.Entry(right_frame, width=40, font=('Arial', 10))
due_entry.pack(pady=(0, 10))

due_entry.bind("<Return>", add_task)


add_btn = tk.Button(right_frame, text="Add Task", command=add_task, width=15)
add_btn.pack(pady=5)

update_btn = tk.Button(right_frame, text="Update Task", command=update_task, width=15, state=tk.DISABLED)
update_btn.pack(pady=5)

mark_done_btn = tk.Button(right_frame, text="Mark as Done", command=mark_task_done, width=15, state=tk.DISABLED)
mark_done_btn.pack(pady=5)

delete_btn = tk.Button(right_frame, text="Delete Task", command=delete_task, width=15, state=tk.DISABLED)
delete_btn.pack(pady=5)

clear_completed_btn = tk.Button(right_frame, text="Clear Completed", command=clear_completed, width=15)
clear_completed_btn.pack(pady=5)

update_task_list()
set_action_buttons_state(tk.DISABLED)

root.mainloop()