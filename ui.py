import tkinter as tk
import ctypes
from ctypes import c_char_p, c_int
import sys
import os
import traceback
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

# NEW: Pinning functions
lib.toggle_pin.argtypes = [c_int]
lib.toggle_pin.restype = c_int
lib.is_task_pinned.argtypes = [c_int]
lib.is_task_pinned.restype = c_int

# --- Global variable to store selected task index ---
current_selected_task_index = -1
task_text_ranges = []
HIGHLIGHT_TAG = "selected_task_highlight"
TASK_CURSOR_TAG = "task_cursor_tag" # 新增：用於游標變更的標籤

# --- Core Task Management Functions (Python Wrappers) ---

def set_action_buttons_state(state):
    update_btn.config(state=state)
    mark_done_btn.config(state=state)
    delete_btn.config(state=state)
    pin_btn.config(state=state) # NEW: control pin button state

def update_task_list():
    task_display_text.config(state=tk.NORMAL)
    task_display_text.delete(1.0, tk.END)

    global task_text_ranges
    task_text_ranges = []

    # 移除所有之前的游標綁定，避免重複
    task_display_text.tag_remove(TASK_CURSOR_TAG, 1.0, tk.END)

    for i in range(lib.get_task_count()):
        desc = lib.get_task_desc(i).decode()
        full_due_date_str = lib.get_task_due_date(i).decode()
        done = lib.is_task_done(i)
        pinned = lib.is_task_pinned(i) # NEW: Get pinned status

        done_symbol = "✔️" if done else "❌"
        pin_symbol = "📌 " if pinned else "" # NEW: Add pin symbol if pinned
        
        due_display = ""
        if full_due_date_str:
            try:
                dt_object = datetime.datetime.strptime(full_due_date_str, "%Y-%m-%d %H:%M")
                due_display = dt_object.strftime(" (Due: %m-%d %H:%M)")
            except ValueError:
                pass

        # NEW: Prepend pin_symbol to the display text
        display_text = f"{pin_symbol}{done_symbol} {desc}{due_display}\n"

        start_index = task_display_text.index(tk.END + "-1c")
        task_display_text.insert(tk.END, display_text)
        end_index = task_display_text.index(tk.END + "-1c")

        task_info = {"task_index": i, "start_index": start_index, "end_index": end_index}
        task_text_ranges.append(task_info)

        # 為每個任務的文本範圍綁定游標變更事件
        task_display_text.tag_add(TASK_CURSOR_TAG, start_index, end_index)
        task_display_text.tag_bind(TASK_CURSOR_TAG, "<Enter>", lambda event, idx=i: _on_task_enter(event, idx))
        task_display_text.tag_bind(TASK_CURSOR_TAG, "<Leave>", lambda event, idx=i: _on_task_leave(event, idx))

    task_display_text.config(state=tk.DISABLED)
    highlight_selected_task()

# 新增：滑鼠進入任務區域時改變游標
def _on_task_enter(event, task_idx):
    # 確保只在鼠標確實位於某個任務文本上時才改變游標
    # 因為 tag_bind 可能會觸發多次，這是一個防禦性檢查
    clicked_text_index = task_display_text.index(f"@{event.x},{event.y}")
    for item in task_text_ranges:
        if item["task_index"] == task_idx and \
           task_display_text.compare(clicked_text_index, ">=", item["start_index"]) and \
           task_display_text.compare(clicked_text_index, "<", item["end_index"]):
            task_display_text.config(cursor="hand2") # "hand2" 是手形游標
            break

# 新增：滑鼠離開任務區域時恢復游標
def _on_task_leave(event, task_idx):
    task_display_text.config(cursor="arrow") # 恢復預設游標

def add_task(event=None):
    desc = desc_entry.get().strip()
    due = due_entry.get().strip()
    
    if not desc:
        messagebox.showwarning("輸入提示", "請輸入任務描述。")
        return





    processed_due_date = ""
    if due:
        try:
            # First, try to parse as MM-DD HH:MM to determine if current year needs to be prepended
            datetime.datetime.strptime(due, "%m-%d %H:%M") 
            current_year = datetime.datetime.now().year
            processed_due_date = f"{current_year}-{due}"
        except ValueError:
            # If it's not MM-DD HH:MM, assume it's already YYYY-MM-DD HH:MM or another valid format
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
    

    # --- 在 Python 端為 MM-DD HH:MM 格式的日期補上當前年份 (更新時) ---

    processed_new_due_date = ""
    if new_due:
        try:
            datetime.datetime.strptime(new_due, "%m-%d %H:%M") 
            current_year = datetime.datetime.now().year
            processed_new_due_date = f"{current_year}-{new_due}"
        except ValueError:
            processed_new_due_date = new_due

    if lib.update_task(current_selected_task_index, new_desc.encode(), processed_new_due_date.encode()) == 0:
        update_task_list()
        clear_selection_and_fields()
    else:
        messagebox.showerror("錯誤", "更新任務失敗。")

# NEW: Toggle pin status for selected task
def toggle_pin_task():
    global current_selected_task_index
    if current_selected_task_index == -1:
        print("Please select a task to pin/unpin.")
        return
    
    if lib.toggle_pin(current_selected_task_index) == 0:
        update_task_list()
        # After toggling, the index might change due to sorting, so clear selection
        clear_selection_and_fields() 
    else:
        print("Error toggling pin status.")

def select_task_and_fill_fields(index):
    global current_selected_task_index
    if index == current_selected_task_index:
        clear_selection_and_fields()
        return

    current_selected_task_index = index
    desc = lib.get_task_desc(index).decode()
    full_due = lib.get_task_due_date(index).decode()
    pinned = lib.is_task_pinned(index) # NEW: Get pinned status

    display_due = ""
    if full_due:
        try:
            dt_object = datetime.datetime.strptime(full_due, "%Y-%m-%d %H:%M")
            display_due = dt_object.strftime("%m-%d %H:%M")
        except ValueError:
            display_due = full_due

    desc_entry.delete(0, tk.END)
    desc_entry.insert(0, desc)
    due_entry.delete(0, tk.END)
    due_entry.insert(0, display_due)
    set_action_buttons_state(tk.NORMAL)
    highlight_selected_task()

    # NEW: Update pin button text based on current task's pinned status
    if pinned == 1:
        pin_btn.config(text="Unpin Task")
    else:
        pin_btn.config(text="Pin Task")

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
    # NEW: Reset pin button text
    pin_btn.config(text="Toggle Pin") 
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

# --- 禁用 Text Widget 的文字選取視覺效果 ---
# 設置選取背景和前景顏色與普通文本相同，使其看起來沒有被選取
task_display_text.config(
    selectbackground=task_display_text.cget("background"), # 使用 Text 的背景色
    selectforeground=task_display_text.cget("foreground")  # 使用 Text 的前景(文字)色
)

task_display_text.bind("<Button-1>", text_click_handler)
task_display_text.tag_configure(HIGHLIGHT_TAG, background="SystemHighlight", foreground="white")

# 定義游標變更的標籤樣式 (這裡不需要額外配置樣式，只需定義名稱)
task_display_text.tag_configure(TASK_CURSOR_TAG)

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

# NEW: Pin/Unpin Button
pin_btn = tk.Button(right_frame, text="Toggle Pin", command=toggle_pin_task, width=15, state=tk.DISABLED)
pin_btn.pack(pady=5)

clear_completed_btn = tk.Button(right_frame, text="Clear Completed", command=clear_completed, width=15)
clear_completed_btn.pack(pady=5)

# --- 新增：啟動 Pygame 的按鈕 ---
pygame_btn = tk.Button(right_frame, text="dont know what to do?", command=launch_pygame_app, width=20) # 加點顏色區分
pygame_btn.pack(pady=(15, 5)) # 增加一些頂部間距

update_task_list()
set_action_buttons_state(tk.DISABLED)

root.mainloop()