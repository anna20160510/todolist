import tkinter as tk # 引入 Tkinter 模組，用於 GUI
import ctypes # 引入 ctypes 模組，用於呼叫 C 函式庫
from ctypes import c_char_p, c_int # 從 ctypes 引入 C 語言型別
import sys # 引入 sys 模組，提供系統相關功能
import os # 引入 os 模組，提供作業系統互動功能
import traceback # 引入 traceback 模組，用於處理錯誤資訊
import datetime # 引入 datetime 模組，用於處理日期和時間
import tempfile # 引入 tempfile 模組，用於建立臨時檔案/目錄
import shutil # 引入 shutil 模組，提供高階檔案操作
import subprocess # 引入 subprocess 模組，用於啟動外部程序
from tkinter import messagebox # 從 tkinter 引入 messagebox，用於顯示訊息方塊
import multiprocessing # 引入 multiprocessing 模組，用於在單獨進程中啟動遊戲
import atexit # 引入 atexit 模組，用於註冊程序退出時執行的函式

# --- 設定 ---
TASKS_FILENAME = "tasks.txt" # 任務檔案名稱

# --- 全域變數，用於追蹤臨時目錄 ---
_active_temp_dirs = [] # 儲存活動的臨時目錄路徑

def cleanup_all_temp_dirs_on_exit():
    """在程序退出時清理所有殘留的臨時目錄。"""
    for temp_dir_path in list(_active_temp_dirs):
        if os.path.exists(temp_dir_path):
            try:
                shutil.rmtree(temp_dir_path) # 刪除臨時目錄
                print(f"Cleaned up temp dir on exit: {temp_dir_path}")
                if temp_dir_path in _active_temp_dirs:
                    _active_temp_dirs.remove(temp_dir_path)
            except Exception as e:
                print(f"Error cleaning up temp dir {temp_dir_path} on exit: {e}")

atexit.register(cleanup_all_temp_dirs_on_exit) # 註冊清理函式在程序退出時執行

# --- DLL 路徑輔助函式 ---
def get_dll_path(dll_name="todo.dll"):
    """根據執行環境 (打包或腳本) 取得 DLL 路徑。"""
    if getattr(sys, 'frozen', False): # PyInstaller 打包
        return os.path.join(sys._MEIPASS, dll_name)
    else: # 作為腳本運行
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), dll_name)

# --- Pygame 腳本路徑輔助函式 (修訂版) ---
def get_pygame_path_revised(script_name="ant_ai.py"):
    """
    取得 Pygame 腳本路徑。
    如果應用程式被打包，則提取腳本到臨時目錄。
    """
    if getattr(sys, 'frozen', False):
        try:
            bundled_path = os.path.join(sys._MEIPASS, script_name)
            if not os.path.exists(bundled_path):
                raise FileNotFoundError(f"Bundled script '{script_name}' not found in _MEIPASS: {sys._MEIPASS}")

            temp_dir = tempfile.mkdtemp() # 建立臨時目錄
            _active_temp_dirs.append(temp_dir) # 追蹤臨時目錄以便清理
            temp_script_path = os.path.join(temp_dir, script_name)
            shutil.copyfile(bundled_path, temp_script_path) # 複製腳本
            return temp_script_path, temp_dir
        except Exception as e:
            print(f"Error in get_pygame_path_revised (frozen): {e}")
            messagebox.showerror("Game Asset Error", f"Could not prepare game assets: {e}")
            raise
    else:
        local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_name)
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Development script '{script_name}' not found at: {local_path}")
        return local_path, None

# --- 載入 C 函式庫並定義函式介面 ---
try:
    lib_path = get_dll_path()
    if not os.path.exists(lib_path):
        messagebox.showerror("Startup Error", f"C library not found at: {lib_path}\nPlease ensure 'todo.dll' is in the correct location and build the project if necessary.")
        sys.exit(1)
    lib = ctypes.CDLL(lib_path) # 載入 C 函式庫
except OSError as e:
    print(f"OSError loading C library: {e}")
    print(f"Attempted to load from: {lib_path}")
    messagebox.showerror("Startup Error", f"Error loading C library:\n{e}\n\nPath: {lib_path}\nMake sure 'todo.dll' is compiled for your system architecture (32-bit/64-bit) and all its dependencies are available.")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected error loading C library: {e}")
    messagebox.showerror("Startup Error", f"An unexpected error occurred while loading the C library:\n{e}")
    sys.exit(1)

# 定義 C 函式原型 (參數型別和返回值型別)
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
lib.toggle_pin.argtypes = [c_int]
lib.toggle_pin.restype = c_int
lib.is_task_pinned.argtypes = [c_int]
lib.is_task_pinned.restype = c_int
lib.save_tasks_to_file.argtypes = [c_char_p]
lib.save_tasks_to_file.restype = c_int
lib.load_tasks_from_file.argtypes = [c_char_p]
lib.load_tasks_from_file.restype = c_int

# --- 全域變數和標籤 ---
current_selected_task_index = -1 # 當前選定的任務索引
task_text_ranges = [] # 任務在顯示文字框中的範圍
HIGHLIGHT_TAG = "selected_task_highlight" # 選定任務的高亮標籤
TASK_CURSOR_TAG = "task_cursor_tag" # 任務游標標籤

# --- 核心任務管理功能 (Python 封裝) ---

def set_action_buttons_state(state):
    """設定操作按鈕的啟用/禁用狀態。"""
    update_btn.config(state=state)
    mark_done_btn.config(state=state)
    delete_btn.config(state=state)
    pin_btn.config(state=state)

def update_task_list():
    """更新任務列表顯示。"""
    task_display_text.config(state=tk.NORMAL)
    task_display_text.delete(1.0, tk.END)

    global task_text_ranges
    task_text_ranges = []

    task_display_text.tag_remove(TASK_CURSOR_TAG, 1.0, tk.END)

    for i in range(lib.get_task_count()):
        desc_bytes = lib.get_task_desc(i)
        desc = desc_bytes.decode('utf-8', errors='replace') if desc_bytes else ""

        due_date_bytes = lib.get_task_due_date(i)
        full_due_date_str = due_date_bytes.decode('utf-8', errors='replace') if due_date_bytes else ""

        done = lib.is_task_done(i)
        pinned = lib.is_task_pinned(i)

        done_symbol = "✔️" if done else "❌" # 完成符號
        pin_symbol = "📌 " if pinned == 1 else "" # 釘選符號

        due_display = ""
        if full_due_date_str:
            try:
                dt_object = datetime.datetime.strptime(full_due_date_str, "%Y-%m-%d %H:%M")
                due_display = dt_object.strftime(" (Due: %m-%d %H:%M)")
            except ValueError:
                pass

        display_text = f"{pin_symbol}{done_symbol} {desc}{due_display}\n"

        start_index = task_display_text.index(tk.END + "-1c")
        task_display_text.insert(tk.END, display_text)
        end_index = task_display_text.index(tk.END + "-1c")

        task_info = {"task_index": i, "start_index": start_index, "end_index": end_index}
        task_text_ranges.append(task_info)

        task_display_text.tag_add(TASK_CURSOR_TAG, start_index, end_index)
        task_display_text.tag_bind(TASK_CURSOR_TAG, "<Enter>", lambda event, idx=i: _on_task_enter(event, idx))
        task_display_text.tag_bind(TASK_CURSOR_TAG, "<Leave>", lambda event, idx=i: _on_task_leave(event, idx))

    task_display_text.config(state=tk.DISABLED)
    highlight_selected_task() # 高亮顯示選定任務

def _on_task_enter(event, task_idx):
    """滑鼠進入任務文字區域時改變游標。"""
    current_mouse_pos = task_display_text.index(f"@{event.x},{event.y}")
    for item in task_text_ranges:
        if item["task_index"] == task_idx:
            if task_display_text.compare(current_mouse_pos, ">=", item["start_index"]) and \
               task_display_text.compare(current_mouse_pos, "<", item["end_index"]):
                task_display_text.config(cursor="hand2") # 設置手形游標
            return

def _on_task_leave(event, task_idx):
    """滑鼠離開任務文字區域時恢復游標。"""
    task_display_text.config(cursor="")

def add_task_ui(event=None):
    """新增任務。"""
    desc = desc_entry.get().strip()
    due_str_input = due_entry.get().strip()

    if not desc:
        messagebox.showwarning("Input Missing", "Please enter a task description.")
        return

    if lib.add_task(desc.encode('utf-8'), due_str_input.encode('utf-8')) >= 0:
        update_task_list()
        desc_entry.delete(0, tk.END)
        due_entry.delete(0, tk.END)
        clear_selection_and_fields()
        desc_entry.focus_set() # 將焦點設回描述輸入框
    else:
        messagebox.showerror("Error", "Failed to add task. The task list might be full.")

def mark_task_done_ui():
    """將選定任務標記為完成。"""
    if current_selected_task_index == -1:
        messagebox.showwarning("No Selection", "Please select a task to mark as done.")
        return
    lib.mark_done(current_selected_task_index)
    update_task_list()

def delete_task_ui():
    """刪除選定任務。"""
    if current_selected_task_index == -1:
        messagebox.showwarning("No Selection", "Please select a task to delete.")
        return
    if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this task?"):
        lib.delete_task(current_selected_task_index)
        update_task_list()
        clear_selection_and_fields()

def clear_completed_ui():
    """清除所有已完成的任務。"""
    if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear all completed tasks?"):
        lib.clear_completed_tasks()
        update_task_list()
        clear_selection_and_fields()

def update_task_ui():
    """更新選定任務。"""
    if current_selected_task_index == -1:
        messagebox.showwarning("No Selection", "Please select a task to update.")
        return
    new_desc = desc_entry.get().strip()
    new_due_str_input = due_entry.get().strip()

    if not new_desc:
        messagebox.showwarning("Input Missing", "Please enter the new task description.")
        return

    if lib.update_task(current_selected_task_index, new_desc.encode('utf-8'), new_due_str_input.encode('utf-8')) == 0:
        update_task_list()
        clear_selection_and_fields()
    else:
        messagebox.showerror("Error", "Failed to update task.")

def toggle_pin_task_ui():
    """切換選定任務的釘選狀態。"""
    global current_selected_task_index
    if current_selected_task_index == -1:
        messagebox.showwarning("No Selection", "Please select a task to pin or unpin.")
        return

    if lib.toggle_pin(current_selected_task_index) == 0:
        update_task_list()
        clear_selection_and_fields()
    else:
        messagebox.showerror("Error", "Failed to toggle pin status.")


def select_task_and_fill_fields(task_index_in_list):
    """選中任務並填充輸入欄位。"""
    global current_selected_task_index

    if task_index_in_list == current_selected_task_index:
        clear_selection_and_fields() # 如果重複點擊，則取消選中
        return

    current_selected_task_index = task_index_in_list

    desc_bytes = lib.get_task_desc(task_index_in_list)
    desc = desc_bytes.decode('utf-8', errors='replace') if desc_bytes else ""

    full_due_bytes = lib.get_task_due_date(task_index_in_list)
    full_due_str = full_due_bytes.decode('utf-8', errors='replace') if full_due_bytes else ""

    pinned_status = lib.is_task_pinned(task_index_in_list)

    display_due_for_entry = ""
    if full_due_str:
        try:
            dt_object = datetime.datetime.strptime(full_due_str, "%Y-%m-%d %H:%M")
            display_due_for_entry = dt_object.strftime("%m-%d %H:%M")
        except ValueError:
            display_due_for_entry = full_due_str

    desc_entry.delete(0, tk.END)
    desc_entry.insert(0, desc)
    due_entry.delete(0, tk.END)
    due_entry.insert(0, display_due_for_entry)

    set_action_buttons_state(tk.NORMAL) # 啟用操作按鈕
    highlight_selected_task()

    pin_btn.config(text="Unpin Task" if pinned_status == 1 else "Pin Task") # 更新釘選按鈕文字


def text_click_handler(event):
    """處理任務列表中的點擊事件。"""
    clicked_text_char_index = task_display_text.index(f"@{event.x},{event.y}")
    selected_task_actual_index = -1
    for item in task_text_ranges:
        if task_display_text.compare(clicked_text_char_index, ">=", item["start_index"]) and \
           task_display_text.compare(clicked_text_char_index, "<", item["end_index"]):
            selected_task_actual_index = item["task_index"]
            break

    if selected_task_actual_index != -1:
        root.after(1, lambda: select_task_and_fill_fields(selected_task_actual_index))
    else:
        root.after(1, clear_selection_and_fields)


def clear_selection_and_fields():
    """清除選定任務和輸入欄位。"""
    global current_selected_task_index
    current_selected_task_index = -1
    desc_entry.delete(0, tk.END)
    due_entry.delete(0, tk.END)
    set_action_buttons_state(tk.DISABLED)
    pin_btn.config(text="Toggle Pin")
    highlight_selected_task()

def highlight_selected_task():
    """高亮顯示選定任務。"""
    task_display_text.tag_remove(HIGHLIGHT_TAG, 1.0, tk.END)
    if current_selected_task_index != -1:
        for item in task_text_ranges:
            if item["task_index"] == current_selected_task_index:
                task_display_text.tag_add(HIGHLIGHT_TAG, item["start_index"], item["end_index"])
                task_display_text.see(item["start_index"]) # 滾動到選定任務
                break

# --- 遊戲啟動邏輯 (修訂版) ---
_game_process_mp = None # 全域變數，儲存遊戲進程

def run_ant_ai_game_target():
    """多進程程序運行 ant_ai 遊戲的目標函式。"""
    script_path, temp_dir_for_this_run = None, None
    original_sys_path = list(sys.path) # 儲存原始 sys.path

    try:
        script_path, temp_dir_for_this_run = get_pygame_path_revised()

        if temp_dir_for_this_run: # 打包模式，腳本已提取
            sys.path.insert(0, temp_dir_for_this_run)
            import ant_ai # 動態導入
            ant_ai.main() # 呼叫遊戲主函式
        else: # 開發模式
            subprocess.run([sys.executable, script_path], check=True) # 直接運行腳本

    except FileNotFoundError as e:
        print(f"ERROR in game process: Pygame script not found. {e}\n{traceback.format_exc()}")
    except ImportError as e:
        print(f"ERROR in game process: Failed to import ant_ai. {e}\n{traceback.format_exc()}")
    except Exception as e:
        print(f"ERROR in game process: An unexpected error occurred. {e}\n{traceback.format_exc()}")
    finally:
        sys.path = original_sys_path # 恢復原始 sys.path
        if temp_dir_for_this_run and os.path.exists(temp_dir_for_this_run):
            try:
                shutil.rmtree(temp_dir_for_this_run)
                if temp_dir_for_this_run in _active_temp_dirs:
                    _active_temp_dirs.remove(temp_dir_for_this_run)
                print(f"Game process cleaned up temp dir: {temp_dir_for_this_run}")
            except Exception as e_cleanup:
                print(f"Error cleaning up temp dir {temp_dir_for_this_run} in game process: {e_cleanup}")


def launch_pygame_app_revised():
    """在獨立進程中啟動 ant_ai.py 遊戲。"""
    global _game_process_mp

    if _game_process_mp and _game_process_mp.is_alive():
        messagebox.showinfo("Game Running", "The ant game is already running.\nPlease close the current game window before starting a new one.")
        return

    try:
        multiprocessing.freeze_support() # 對於打包應用程式的多進程支持

        _game_process_mp = multiprocessing.Process(target=run_ant_ai_game_target)
        _game_process_mp.start() # 啟動新進程
    except Exception as e:
        messagebox.showerror("Launch Error", f"Failed to start the game process:\n{e}\n{traceback.format_exc()}")


# --- 儲存/載入函式 ---
def auto_load_tasks_on_startup():
    """應用程式啟動時自動載入任務。"""
    result = lib.load_tasks_from_file(TASKS_FILENAME.encode('utf-8'))
    if result == -1:
        messagebox.showerror("Load Error", f"Error loading tasks from '{TASKS_FILENAME}'.\nThe file might be corrupted or unreadable.")
    elif result == 1:
        print(f"'{TASKS_FILENAME}' not found. Starting with an empty task list.")
    update_task_list()

def auto_save_tasks_on_exit():
    """應用程式退出時自動儲存任務。"""
    result = lib.save_tasks_to_file(TASKS_FILENAME.encode('utf-8'))
    if result != 0:
        messagebox.showwarning("Save Warning", f"Could not save all tasks to '{TASKS_FILENAME}'.\nCheck file permissions or disk space.")
    else:
        print(f"Tasks saved successfully to {TASKS_FILENAME}.")

    global _game_process_mp
    if _game_process_mp and _game_process_mp.is_alive():
        try:
            _game_process_mp.terminate() # 請求終止遊戲進程
            _game_process_mp.join(timeout=1)
            if _game_process_mp.is_alive():
                _game_process_mp.kill() # 強制終止
            print("Terminated game process on exit.")
        except Exception as e_term:
            print(f"Error terminating game process on exit: {e_term}")

    cleanup_all_temp_dirs_on_exit() # 確保清理臨時目錄
    root.destroy() # 銷毀 Tkinter 視窗


# --- UI 設定 ---
if __name__ == '__main__':
    multiprocessing.freeze_support() # 啟動時為多進程提供支持

    root = tk.Tk() # 創建主 Tkinter 視窗
    root.title("To-Do List Manager") # 設定視窗標題
    root.geometry("750x450") # 設定視窗大小

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    main_frame = tk.Frame(root, padx=10, pady=10) # 創建主框架
    main_frame.grid(row=0, column=0, sticky="nsew")

    main_frame.grid_columnconfigure(0, weight=3)
    main_frame.grid_columnconfigure(1, weight=1)
    main_frame.grid_rowconfigure(0, weight=1)

    left_frame = tk.Frame(main_frame) # 創建左側框架 (任務列表)
    left_frame.grid(row=0, column=0, padx=(0,10), pady=5, sticky="nsew")
    left_frame.grid_rowconfigure(0, weight=1)
    left_frame.grid_columnconfigure(0, weight=1)

    task_display_text = tk.Text(left_frame, height=15, font=('Arial', 10), wrap=tk.WORD, relief=tk.FLAT, bd=0) # 任務顯示文字框
    task_display_text.grid(row=0, column=0, sticky="nsew")
    task_display_text.config(
        selectbackground=task_display_text.cget("background"),
        selectforeground=task_display_text.cget("foreground"),
        state=tk.DISABLED
    )
    task_display_text.bind("<Button-1>", text_click_handler) # 綁定點擊事件
    task_display_text.tag_configure(HIGHLIGHT_TAG, background="SystemHighlight", foreground="SystemHighlightText")
    task_display_text.tag_configure(TASK_CURSOR_TAG)

    scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=task_display_text.yview) # 滾動條
    scrollbar.grid(row=0, column=1, sticky="ns")
    task_display_text.config(yscrollcommand=scrollbar.set)

    right_frame = tk.Frame(main_frame) # 創建右側框架 (輸入和按鈕)
    right_frame.grid(row=0, column=1, padx=(5,0), pady=5, sticky="nsew")

    tk.Label(right_frame, text="Task Description:").pack(pady=(0,2), anchor="w")
    desc_entry = tk.Entry(right_frame, width=35, font=('Arial', 10)) # 任務描述輸入框
    desc_entry.pack(pady=(0,10), fill=tk.X, expand=False)
    desc_entry.bind("<Return>", lambda e: add_task_ui())

    tk.Label(right_frame, text="Due Date (MM-DD HH:MM):").pack(pady=(0,2), anchor="w")
    due_entry = tk.Entry(right_frame, width=35, font=('Arial', 10)) # 截止日期輸入框
    due_entry.pack(pady=(0,15), fill=tk.X, expand=False)
    due_entry.bind("<Return>", lambda e: add_task_ui())

    btn_width = 18
    add_btn = tk.Button(right_frame, text="Add Task", command=add_task_ui, width=btn_width) # 新增任務按鈕
    add_btn.pack(pady=3, fill=tk.X)

    update_btn = tk.Button(right_frame, text="Update Task", command=update_task_ui, width=btn_width, state=tk.DISABLED) # 更新任務按鈕
    update_btn.pack(pady=3, fill=tk.X)

    mark_done_btn = tk.Button(right_frame, text="Mark as Done", command=mark_task_done_ui, width=btn_width, state=tk.DISABLED) # 標記完成按鈕
    mark_done_btn.pack(pady=3, fill=tk.X)

    delete_btn = tk.Button(right_frame, text="Delete Task", command=delete_task_ui, width=btn_width, state=tk.DISABLED) # 刪除任務按鈕
    delete_btn.pack(pady=3, fill=tk.X)

    pin_btn = tk.Button(right_frame, text="Toggle Pin", command=toggle_pin_task_ui, width=btn_width, state=tk.DISABLED) # 釘選按鈕
    pin_btn.pack(pady=3, fill=tk.X)

    clear_completed_btn = tk.Button(right_frame, text="Clear Completed", command=clear_completed_ui, width=btn_width) # 清除已完成按鈕
    clear_completed_btn.pack(pady=(3,10), fill=tk.X)

    pygame_btn = tk.Button(right_frame, text="Don't know what to do?", command=launch_pygame_app_revised, width=btn_width + 5) # 啟動遊戲按鈕
    pygame_btn.pack(pady=(10, 5), fill=tk.X)

    auto_load_tasks_on_startup() # 應用程式啟動時載入任務
    set_action_buttons_state(tk.DISABLED) # 初始禁用操作按鈕
    root.protocol("WM_DELETE_WINDOW", auto_save_tasks_on_exit) # 設置視窗關閉時的處理函式

    root.mainloop() # 啟動 Tkinter 事件循環