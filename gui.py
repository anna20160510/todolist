import ctypes
from tkinter import *

# 載入 DLL（根據作業系統調整）
lib = ctypes.CDLL(r"./dll/todo.dll")


# 宣告函式原型
lib.add_task.argtypes = [ctypes.c_char_p]
lib.add_task.restype = ctypes.c_int
lib.mark_done.argtypes = [ctypes.c_int]
lib.delete_task.argtypes = [ctypes.c_int]
lib.get_task_count.restype = ctypes.c_int
lib.get_task_desc.argtypes = [ctypes.c_int]
lib.get_task_desc.restype = ctypes.c_char_p
lib.is_task_done.argtypes = [ctypes.c_int]
lib.is_task_done.restype = ctypes.c_int

# Tkinter UI 建構
root = Tk()
root.title("To-Do List (C + Python)")

entry = Entry(root, width=40)
entry.pack(pady=5)

tasks_frame = Frame(root)
tasks_frame.pack()

def refresh_tasks():
    for widget in tasks_frame.winfo_children():
        widget.destroy()
    count = lib.get_task_count()
    for i in range(count):
        desc = lib.get_task_desc(i).decode()
        done = lib.is_task_done(i)
        text = f"[✓] {desc}" if done else f"[ ] {desc}"
        lbl = Label(tasks_frame, text=text, width=40, anchor="w", fg="gray" if done else "black")
        lbl.grid(row=i, column=0)
        Button(tasks_frame, text="Done", command=lambda i=i: mark_done(i)).grid(row=i, column=1)
        Button(tasks_frame, text="Delete", command=lambda i=i: delete(i)).grid(row=i, column=2)

def add():
    task = entry.get().strip()
    if task:
        lib.add_task(task.encode('utf-8'))
        entry.delete(0, END)
        refresh_tasks()

def mark_done(index):
    lib.mark_done(index)
    refresh_tasks()

def delete(index):
    lib.delete_task(index)
    refresh_tasks()

Button(root, text="Add Task", command=add).pack(pady=5)
refresh_tasks()
root.mainloop()
