import tkinter as tk
import ctypes
from ctypes import c_char_p, c_int

# Load compiled C library
# 把路徑換成你電腦裡to.dll的路徑
lib = ctypes.CDLL("C:/Users/USER/Documents/GitHub/todolist/todo.dll")  # Or "./todo.so" on Linux/macOS

# Define C function interfaces
lib.add_task.argtypes = [c_char_p, c_char_p]
lib.add_task.restype = c_int

lib.update_task.argtypes = [c_int, c_char_p, c_char_p]
lib.update_task.restype = c_int

lib.mark_done.argtypes = [c_int]
lib.mark_done.restype = c_int

lib.delete_task.argtypes = [c_int]
lib.delete_task.restype = c_int

lib.get_task_count.restype = c_int
lib.get_task_desc.argtypes = [c_int]
lib.get_task_desc.restype = c_char_p
lib.is_task_done.argtypes = [c_int]
lib.is_task_done.restype = c_int
lib.get_task_due_date.argtypes = [c_int]
lib.get_task_due_date.restype = c_char_p

# *** 新增：宣告新的 C 函數介面 ***
lib.has_task_due_date.argtypes = [c_int]
lib.has_task_due_date.restype = c_int

# Update the displayed task list
def update_task_list():
    task_listbox.delete(0, tk.END)
    for i in range(lib.get_task_count()):
        desc = lib.get_task_desc(i).decode()
        done = lib.is_task_done(i)
        symbol = "✔️" if done else "❌"

        # *** 修改：根據 has_due_date 判斷顯示內容，避免重複解碼 ***
        if lib.has_task_due_date(i) == 1: # 如果有截止日期
            due_display = lib.get_task_due_date(i).decode()
            task_listbox.insert(tk.END, f"{symbol} {desc} (Due: {due_display})")
        else: # 如果沒有截止日期
            task_listbox.insert(tk.END, f"{symbol} {desc} (No Due Date)")

# Add a new task
def add_task():
    desc = desc_entry.get().strip()
    due = due_entry.get().strip() # due 可以是空字串

    if not desc: # 任務描述不能為空
        print("Please fill in the task description.")
        return

    # *** 修改：直接將 due 傳入，C 函數會處理空值。移除對 due 的檢查。 ***
    if lib.add_task(desc.encode(), due.encode()) >= 0:
        update_task_list()
        desc_entry.delete(0, tk.END)
        due_entry.delete(0, tk.END)
        print(f"Task '{desc}' added.") # 增加成功的訊息

# Mark task as done
def mark_task_done():
    sel = task_listbox.curselection()
    if sel:
        if lib.mark_done(sel[0]) == 0:
            update_task_list()
            print(f"Task {sel[0]} marked as done.")
        else:
            print("Failed to mark task as done.")
    else:
        print("Please select a task to mark as done.")

# Delete selected task
def delete_task():
    sel = task_listbox.curselection()
    if sel:
        if lib.delete_task(sel[0]) == 0:
            update_task_list()
            print(f"Task {sel[0]} deleted.")
        else:
            print("Failed to delete task.")
    else:
        print("Please select a task to delete.")

# Update task's description and due date
def update_task():
    sel = task_listbox.curselection()
    if not sel:
        print("Select a task to update.")
        return

    index = sel[0]
    new_desc = desc_entry.get().strip()
    new_due = due_entry.get().strip() # new_due 可以是空字串

    if not new_desc: # 任務描述不能為空
        print("Fill in the new description.")
        return

    # *** 修改：直接將 new_due 傳入，C 函數會處理空值。移除對 new_due 的檢查。 ***
    if lib.update_task(index, new_desc.encode(), new_due.encode()) == 0:
        update_task_list()
        print(f"Task {index} updated.")
    else:
        print("Failed to update task.")

# Fill entry fields when selecting a task
def fill_fields_on_select(event):
    sel = task_listbox.curselection()
    if sel:
        index = sel[0]
        desc = lib.get_task_desc(index).decode()
        
        # *** 修改：根據 has_due_date 決定是否填入日期 ***
        if lib.has_task_due_date(index) == 1:
            due = lib.get_task_due_date(index).decode()
        else:
            due = "" # 如果沒有截止日期，則日期輸入框顯示為空

        desc_entry.delete(0, tk.END)
        desc_entry.insert(0, desc)

        due_entry.delete(0, tk.END)
        due_entry.insert(0, due)

# Clear fields when clicking outside tasks
def handle_click(event):
    # This ensures that a click that's NOT on an item clears selection and entries
    # The 'nearest' method might return an index even if the click is in the empty space
    # but still within the listbox bounds. We need to check if the click was *on* an item.
    try:
        index = task_listbox.nearest(event.y)
        # Check if the click was exactly on an item (within its bounding box)
        if index not in task_listbox.curselection() or task_listbox.bbox(index) is None:
            # If the index is not currently selected, or if there's no bbox (e.g., empty listbox area)
            task_listbox.selection_clear(0, tk.END)
            desc_entry.delete(0, tk.END)
            due_entry.delete(0, tk.END)
    except tk.TclError:
        # This can happen if the listbox is completely empty
        task_listbox.selection_clear(0, tk.END)
        desc_entry.delete(0, tk.END)
        due_entry.delete(0, tk.END)


# --- UI Setup ---
root = tk.Tk()
root.title("To-Do List Manager")

task_listbox = tk.Listbox(root, width=60, height=10)
task_listbox.pack(pady=10)
task_listbox.bind('<<ListboxSelect>>', fill_fields_on_select)
task_listbox.bind("<Button-1>", handle_click)

tk.Label(root, text="Due Date (YYYY-MM-DD HH:MM, or leave blank):").pack() # *** 修改提示文字 ***
due_entry = tk.Entry(root, width=40)
due_entry.pack()

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Add Task", command=add_task).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Update Task", command=update_task).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Mark as Done", command=mark_task_done).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Delete Task", command=delete_task).pack(side=tk.LEFT, padx=5)

update_task_list()
root.mainloop()