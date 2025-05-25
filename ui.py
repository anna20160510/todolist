import tkinter as tk
import ctypes
from ctypes import c_char_p, c_int
import sys
import os
import traceback

# --- DLL Path Helper Function ---
# Dynamically locates and loads the compiled C library (todo.dll).
# This function ensures compatibility with both:
# - Direct script execution (e.g. python ui.py)
# - PyInstaller builds (which extract the DLL to a temporary folder)
# Just make sure the correct version of the DLL (32-bit or 64-bit) is compiled for your system.
def get_dll_path(dll_name="todo.dll"):
    if getattr(sys, 'frozen', False):
        # PyInstaller bundle — DLL extracted to temp folder
        return os.path.join(sys._MEIPASS, dll_name)
    else:
        # Normal script — DLL next to the .py file
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), dll_name)

# --- Optional Error Logging for PyInstaller Builds ---
# This block catches unhandled exceptions and writes them to an error.log file,
# which is useful for debugging issues in bundled applications.
if getattr(sys, 'frozen', False):
    try:
        # Your normal app logic would start here, but for this simple script,
        # it mostly encompasses the entire execution after imports.
        pass
    except Exception as e:
        with open("error.log", "w") as f:
            f.write(traceback.format_exc())
        raise # Re-raise the exception after logging it

# --- Load C Library and Define Function Interfaces ---
# Ensure the DLL is in the same directory as this script, or in a system PATH.
try:
    lib = ctypes.CDLL(get_dll_path())
except Exception as e:
    print(f"Error loading C library: {e}")
    print(f"Make sure '{get_dll_path()}' exists and is compiled for your system architecture.")
    sys.exit(1)

# Define argument and return types for C functions using ctypes
lib.add_task.argtypes = [c_char_p, c_char_p]
lib.add_task.restype = c_int

lib.update_task.argtypes = [c_int, c_char_p, c_char_p]
lib.update_task.restype = c_int

lib.mark_done.argtypes = [c_int]
lib.mark_done.restype = c_int

lib.delete_task.argtypes = [c_int]
lib.delete_task.restype = c_int # Corrected from previous error

# New C function for clearing completed tasks
lib.clear_completed_tasks.restype = None

lib.get_task_count.restype = c_int
lib.get_task_desc.argtypes = [c_int]
lib.get_task_desc.restype = c_char_p
lib.is_task_done.argtypes = [c_int]
lib.is_task_done.restype = c_int
lib.get_task_due_date.argtypes = [c_int]
lib.get_task_due_date.restype = c_char_p

# --- Core Task Management Functions (Python Wrappers) ---

# Updates the displayed task list in the Tkinter Listbox.
# Implements Feature 2: If no due date, don't show "(Due: )".
def update_task_list():
    task_listbox.delete(0, tk.END)
    for i in range(lib.get_task_count()):
        desc = lib.get_task_desc(i).decode()
        due = lib.get_task_due_date(i).decode()
        done = lib.is_task_done(i)
        symbol = "✔️" if done else "❌"

        # Construct the due date display string
        due_display = f" (Due: {due})" if due else "" # Only show " (Due: ...)" if a due date exists
        task_listbox.insert(tk.END, f"{symbol} {desc}{due_display}")

# Adds a new task using the C library function.
def add_task():
    desc = desc_entry.get().strip()
    due = due_entry.get().strip()

    if not desc:
        print("Please enter a task description.")
        return

    # Pass an empty string if due date is empty
    if lib.add_task(desc.encode(), due.encode()) >= 0:
        update_task_list()
        desc_entry.delete(0, tk.END)
        due_entry.delete(0, tk.END)

# Marks the selected task as done using the C library function.
def mark_task_done():
    sel = task_listbox.curselection()
    if sel:
        lib.mark_done(sel[0])
        update_task_list()

# Deletes the selected task using the C library function.
def delete_task():
    sel = task_listbox.curselection()
    if sel:
        lib.delete_task(sel[0])
        update_task_list()

# Implements Feature 1: Clears all tasks marked as completed.
def clear_completed():
    lib.clear_completed_tasks() # Call the new C function
    update_task_list()          # Refresh the list after clearing

# Updates the description and/or due date of the selected task.
def update_task():
    sel = task_listbox.curselection()
    if not sel:
        print("Select a task to update.")
        return

    index = sel[0]
    new_desc = desc_entry.get().strip()
    new_due = due_entry.get().strip()

    if not new_desc:
        print("Please enter a new task description.")
        return

    # Pass an empty string if new_due is empty
    if lib.update_task(index, new_desc.encode(), new_due.encode()) == 0:
        update_task_list()

# Populates entry fields when a task is selected in the Listbox.
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

# Clears entry fields and selection if user clicks outside of a task item.
def handle_click(event):
    # This uses root.after to ensure the Listbox selection event processes first,
    # then checks if a non-item area was clicked.
    def clear_if_not_on_item():
        try:
            index = task_listbox.nearest(event.y)
            bbox = task_listbox.bbox(index) # Get bounding box of the item near click
        except Exception:
            # If no item is found (e.g., listbox is empty), bbox will fail
            bbox = None

        # Check if the click was outside any item's bounding box or if no item was found
        if not bbox or event.y < bbox[1] or event.y > bbox[1] + bbox[3]:
            task_listbox.selection_clear(0, tk.END)
            desc_entry.delete(0, tk.END)
            due_entry.delete(0, tk.END)

    root.after(1, clear_if_not_on_item)


# --- UI Setup ---
root = tk.Tk()
root.title("To-Do List Manager")

# Task Listbox
task_listbox = tk.Listbox(root, width=60, height=10, font=('Arial', 10))
task_listbox.pack(pady=10, padx=10)
task_listbox.bind('<<ListboxSelect>>', fill_fields_on_select) # Event for selecting an item
task_listbox.bind("<Button-1>", handle_click) # Event for any mouse click

# Input Fields
tk.Label(root, text="Task Description:").pack(pady=(0, 2))
desc_entry = tk.Entry(root, width=50, font=('Arial', 10))
desc_entry.pack(pady=(0, 5))

tk.Label(root, text="Due Date (YYYY-MM-DD HH:MM):").pack(pady=(0, 2))
due_entry = tk.Entry(root, width=50, font=('Arial', 10))
due_entry.pack(pady=(0, 10))

# Buttons Frame
btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

# Buttons
tk.Button(btn_frame, text="Add Task", command=add_task, width=15).pack(side=tk.LEFT, padx=5, pady=5)
tk.Button(btn_frame, text="Update Task", command=update_task, width=15).pack(side=tk.LEFT, padx=5, pady=5)
tk.Button(btn_frame, text="Mark as Done", command=mark_task_done, width=15).pack(side=tk.LEFT, padx=5, pady=5)
tk.Button(btn_frame, text="Delete Task", command=delete_task, width=15).pack(side=tk.LEFT, padx=5, pady=5)
tk.Button(btn_frame, text="Clear Completed", command=clear_completed, width=15).pack(side=tk.LEFT, padx=5, pady=5) # New button for Feature 1

# Initial population of the task list
update_task_list()

# Start the Tkinter event loop
root.mainloop()