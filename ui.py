import tkinter as tk
import ctypes
from ctypes import c_char_p, c_int
import sys
import os
import traceback

"""
    Dynamically locates and loads the compiled C library (todo.dll).

    This function ensures compatibility with both:
    - Direct script execution (e.g. python ui.py)
    - PyInstaller builds (which extract the DLL to a temporary folder)

    Just make sure the correct version of the DLL (32-bit or 64-bit) is compiled for your system.
"""

def get_dll_path(dll_name="todo.dll"):
    if getattr(sys, 'frozen', False):
        # PyInstaller bundle — DLL extracted to temp folder
        return os.path.join(sys._MEIPASS, dll_name)
    else:
        # Normal script — DLL next to the .py file
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), dll_name)


# Optional error logging
if getattr(sys, 'frozen', False):
    try:
        # your normal app logic starts here
        pass
    except Exception as e:
        with open("error.log", "w") as f:
            f.write(traceback.format_exc())
        raise

lib = ctypes.CDLL(get_dll_path())

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

# Update the displayed task list
def update_task_list():
    task_listbox.delete(0, tk.END)
    for i in range(lib.get_task_count()):
        desc = lib.get_task_desc(i).decode()
        due = lib.get_task_due_date(i).decode()
        done = lib.is_task_done(i)
        symbol = "✔️" if done else "❌"
        task_listbox.insert(tk.END, f"{symbol} {desc} (Due: {due})")

# Add a new task
def add_task():
    desc = desc_entry.get().strip()
    due = due_entry.get().strip()
    if not desc or not due:
        print("Please fill in both fields.")
        return
    if lib.add_task(desc.encode(), due.encode()) >= 0:
        update_task_list()
        desc_entry.delete(0, tk.END)
        due_entry.delete(0, tk.END)

# Mark task as done
def mark_task_done():
    sel = task_listbox.curselection()
    if sel:
        lib.mark_done(sel[0])
        update_task_list()

# Delete selected task
def delete_task():
    sel = task_listbox.curselection()
    if sel:
        lib.delete_task(sel[0])
        update_task_list()

# Update task's description and due date
def update_task():
    sel = task_listbox.curselection()
    if not sel:
        print("Select a task to update.")
        return

    index = sel[0]
    new_desc = desc_entry.get().strip()
    new_due = due_entry.get().strip()
    if not new_desc or not new_due:
        print("Fill in both fields.")
        return

    if lib.update_task(index, new_desc.encode(), new_due.encode()) == 0:
        update_task_list()

# Fill entry fields when selecting a task
def fill_fields_on_select(event):
    sel = task_listbox.curselection()
    if sel:
        index = sel[0]
        desc = lib.get_task_desc(index).decode()
        due = lib.get_task_due_date(index).decode()

        desc_entry.delete(0, tk.END)
        desc_entry.insert(0, desc)

        due_entry.delete(0, tk.END)
        due_entry.insert(0, due)

# Clear fields when clicking outside tasks
def handle_click(event):
    def clear_if_not_on_item():
        index = task_listbox.nearest(event.y)
        bbox = task_listbox.bbox(index)

        if not bbox or event.y < bbox[1] or event.y > bbox[1] + bbox[3]:
            task_listbox.selection_clear(0, tk.END)
            desc_entry.delete(0, tk.END)
            due_entry.delete(0, tk.END)

    root.after(1, clear_if_not_on_item)


# --- UI Setup ---
root = tk.Tk()
root.title("To-Do List Manager")

task_listbox = tk.Listbox(root, width=60, height=10)
task_listbox.pack(pady=10)
task_listbox.bind('<<ListboxSelect>>', fill_fields_on_select)
task_listbox.bind("<Button-1>", handle_click)

tk.Label(root, text="Task Description:").pack()
desc_entry = tk.Entry(root, width=40)
desc_entry.pack()

tk.Label(root, text="Due Date (YYYY-MM-DD HH:MM):").pack()
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
