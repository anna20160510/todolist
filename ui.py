import tkinter as tk
import ctypes
from ctypes import c_char_p, c_int
import sys
import os
import datetime
import subprocess # --- 新增：用於啟動外部程序 ---
from tkinter import messagebox # --- 新增：用於顯示彈出訊息 ---

# --- DLL Path Helper Function ---

def get_dll_path(dll_name="todo.dll"):
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, dll_name)
    else:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), dll_name)

# --- 新增：Pygame Script Path Helper Function ---
def get_pygame_path(script_name="ant_ai.py"):
    """獲取 Pygame 腳本的路徑。"""
    if getattr(sys, 'frozen', False):
        # 如果是打包後的執行檔
        return os.path.join(sys._MEIPASS, script_name)
    else:
        # 如果是直接執行的 .py 檔
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), script_name)

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
    messagebox.showerror("啟動錯誤", f"載入 C 函式庫時發生錯誤:\n{e}\n\n請確認 '{get_dll_path()}' 存在且適用於您的系統。")
    sys.exit(1)

# --- Define C Function Interfaces ---
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

lib.save_tasks.argtypes = [c_char_p]
lib.save_tasks.restype = c_int
lib.load_tasks.argtypes = [c_char_p]
lib.load_tasks.restype = c_int

# --- Global State ---
current_selected_task_index = -1
task_text_ranges = []
HIGHLIGHT_TAG = "selected_task_highlight"
TASK_CURSOR_TAG = "task_cursor_tag"

# --- Core Logic ---
def set_action_buttons_state(state):
    update_btn.config(state=state)
    mark_done_btn.config(state=state)
    delete_btn.config(state=state)

def update_task_list():
    task_display_text.config(state=tk.NORMAL)
    task_display_text.delete(1.0, tk.END)
    global task_text_ranges
    task_text_ranges = []
    task_display_text.tag_remove(TASK_CURSOR_TAG, 1.0, tk.END)

    for i in range(lib.get_task_count()):
        desc = lib.get_task_desc(i).decode()
        full_due_date = lib.get_task_due_date(i).decode()
        done = lib.is_task_done(i)
        symbol = "✔️" if done else "❌"

        due_display = ""
        if full_due_date:
            try:
                dt = datetime.datetime.strptime(full_due_date, "%Y-%m-%d %H:%M")
                due_display = dt.strftime(" (Due: %m-%d %H:%M)")
            except ValueError:
                pass

        display_text = f"{symbol} {desc}{due_display}\n"
        start_index = task_display_text.index(tk.END + "-1c")
        task_display_text.insert(tk.END, display_text)
        end_index = task_display_text.index(tk.END + "-1c")

        task_text_ranges.append({
            "task_index": i,
            "start_index": start_index,
            "end_index": end_index
        })

        task_display_text.tag_add(TASK_CURSOR_TAG, start_index, end_index)
        task_display_text.tag_bind(TASK_CURSOR_TAG, "<Enter>", lambda e, idx=i: _on_task_enter(e, idx))
        task_display_text.tag_bind(TASK_CURSOR_TAG, "<Leave>", lambda e, idx=i: _on_task_leave(e, idx))

    task_display_text.config(state=tk.DISABLED)
    highlight_selected_task()

def _on_task_enter(event, task_idx):
    idx = task_display_text.index(f"@{event.x},{event.y}")
    for item in task_text_ranges:
        if item["task_index"] == task_idx and \
           task_display_text.compare(idx, ">=", item["start_index"]) and \
           task_display_text.compare(idx, "<", item["end_index"]):
            task_display_text.config(cursor="hand2")
            break

def _on_task_leave(event, task_idx):
    task_display_text.config(cursor="arrow")

def add_task(event=None):
    desc = desc_entry.get().strip()
    due = due_entry.get().strip()
    if not desc:
        messagebox.showwarning("輸入提示", "請輸入任務描述。")
        return

    processed_due_date = ""
    if due:
        try:
            datetime.datetime.strptime(due, "%m-%d %H:%M")
            year = datetime.datetime.now().year
            processed_due_date = f"{year}-{due}"
        except ValueError:
            processed_due_date = due

    if lib.add_task(desc.encode(), processed_due_date.encode()) >= 0:
        update_task_list()
        desc_entry.delete(0, tk.END)
        due_entry.delete(0, tk.END)
        clear_selection_and_fields()
        desc_entry.focus_set()
    else:
        messagebox.showerror("錯誤", "新增任務失敗。")

def mark_task_done():
    if current_selected_task_index == -1:
        messagebox.showwarning("選取提示", "請選取要標記為完成的任務。")
        return
    lib.mark_done(current_selected_task_index)
    update_task_list()
    clear_selection_and_fields()

def delete_task():
    if current_selected_task_index == -1:
        messagebox.showwarning("選取提示", "請選取要刪除的任務。")
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
        messagebox.showwarning("選取提示", "請選取要更新的任務。")
        return
    new_desc = desc_entry.get().strip()
    new_due = due_entry.get().strip()
    if not new_desc:
        messagebox.showwarning("輸入提示", "請輸入新的任務描述。")
        return

    processed_new_due_date = ""
    if new_due:
        try:
            datetime.datetime.strptime(new_due, "%m-%d %H:%M")
            year = datetime.datetime.now().year
            processed_new_due_date = f"{year}-{new_due}"
        except ValueError:
            processed_new_due_date = new_due

    if lib.update_task(current_selected_task_index, new_desc.encode(), processed_new_due_date.encode()) == 0:
        update_task_list()
        clear_selection_and_fields()

    if new_due:
        try:
            datetime.datetime.strptime(new_due, "%m-%d %H:%M")
            year = datetime.datetime.now().year
            formatted_due = f"{year}-{new_due}"
        except ValueError:
            formatted_due = new_due

    if lib.update_task(current_selected_task_index, new_desc.encode(), formatted_due.encode()) == 0:
        update_task_list()
        clear_selection_and_fields()
    else:
        messagebox.showerror("錯誤", "更新任務失敗。")

def mark_task_done():
    if current_selected_task_index == -1:
        return
    lib.mark_done(current_selected_task_index)
    update_task_list()
    clear_selection_and_fields()

def delete_task():
    if current_selected_task_index == -1:
        return
    lib.delete_task(current_selected_task_index)
    update_task_list()
    clear_selection_and_fields()

def clear_completed():
    lib.clear_completed_tasks()
    update_task_list()
    clear_selection_and_fields()

def select_task_and_fill_fields(index):
    global current_selected_task_index
    if index == current_selected_task_index:
        clear_selection_and_fields()
        return

    current_selected_task_index = index
    desc = lib.get_task_desc(index).decode()
    full_due = lib.get_task_due_date(index).decode()
    display_due = ""

    if full_due:
        try:
            dt = datetime.datetime.strptime(full_due, "%Y-%m-%d %H:%M")
            display_due = dt.strftime("%m-%d %H:%M")
        except ValueError:
            display_due = full_due

    desc_entry.delete(0, tk.END)
    desc_entry.insert(0, desc)
    due_entry.delete(0, tk.END)
    due_entry.insert(0, display_due)
    set_action_buttons_state(tk.NORMAL)
    highlight_selected_task()

def text_click_handler(event):
    index = task_display_text.index(f"@{event.x},{event.y}")
    selected_idx = -1
    for item in task_text_ranges:
        if task_display_text.compare(index, ">=", item["start_index"]) and \
           task_display_text.compare(index, "<", item["end_index"]):
            selected_idx = item["task_index"]
            break
    root.after(1, lambda: _process_click_selection(selected_idx))

def _process_click_selection(selected_idx):
    if selected_idx != -1:
        select_task_and_fill_fields(selected_idx)
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

# --- 新增：啟動 Pygame 應用程式的函式 ---
def launch_pygame_app():
    """啟動 ant_ai.py (Pygame 應用程式) 作為一個獨立的程序。"""
    pygame_script_path = get_pygame_path() # 使用輔助函式獲取路徑

    try:
        if not os.path.exists(pygame_script_path):
            print(f"錯誤：找不到 Pygame 腳本 '{pygame_script_path}'。")
            messagebox.showerror("錯誤", f"找不到 Pygame 腳本:\n{pygame_script_path}")
            return

        print(f"正在啟動 Pygame 應用程式: {pygame_script_path}...")
        # 使用 Popen 啟動，這樣 Tkinter 視窗不會被凍結
        subprocess.Popen([sys.executable, pygame_script_path])

    except Exception as e:
        print(f"啟動 Pygame 時發生錯誤: {e}")
        print(traceback.format_exc())
        messagebox.showerror("啟動錯誤", f"啟動 Pygame 時發生錯誤:\n{e}")

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
task_display_text.config(
    selectbackground=task_display_text.cget("background"),
    selectforeground=task_display_text.cget("foreground")
)
task_display_text.tag_configure(HIGHLIGHT_TAG, background="#0078D7", foreground="white")
task_display_text.tag_configure(TASK_CURSOR_TAG)
task_display_text.bind("<Button-1>", text_click_handler)

scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=task_display_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
task_display_text.config(yscrollcommand=scrollbar.set)

right_frame = tk.Frame(main_frame)
right_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

tk.Label(right_frame, text="Task Description:").pack(pady=(0, 2))
desc_entry = tk.Entry(right_frame, width=40, font=('Arial', 10))
desc_entry.pack(pady=(0, 5))
desc_entry.bind("<Return>", add_task)

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


# --- Load saved tasks at startup ---
lib.load_tasks(b"tasks.txt")

# --- 新增：啟動 Pygame 的按鈕 ---
pygame_btn = tk.Button(right_frame, text="dont know what to do?", command=launch_pygame_app, width=20) # 加點顏色區分
pygame_btn.pack(pady=(15, 5)) # 增加一些頂部間距

update_task_list()

# --- Save tasks at exit ---
def on_close():
    lib.save_tasks(b"tasks.txt")
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)
set_action_buttons_state(tk.DISABLED)

root.mainloop()
