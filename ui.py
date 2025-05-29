import tkinter as tk
import ctypes
from ctypes import c_char_p, c_int
import sys
import os
import traceback
import datetime
import tempfile
import shutil
import subprocess 
from tkinter import messagebox
import multiprocessing # Added for launching the game
import atexit # Added for cleanup

# --- Configuration ---
TASKS_FILENAME = "tasks.txt"

# --- Global list to keep track of temporary directories created ---
_active_temp_dirs = []

def cleanup_all_temp_dirs_on_exit():
    """Cleans up any temporary directories that might have been left over."""
    for temp_dir_path in list(_active_temp_dirs): # Iterate over a copy
        if os.path.exists(temp_dir_path):
            try:
                shutil.rmtree(temp_dir_path)
                print(f"Cleaned up temp dir on exit: {temp_dir_path}")
                if temp_dir_path in _active_temp_dirs: # Check again before removing
                    _active_temp_dirs.remove(temp_dir_path)
            except Exception as e:
                print(f"Error cleaning up temp dir {temp_dir_path} on exit: {e}")

atexit.register(cleanup_all_temp_dirs_on_exit)


# --- DLL Path Helper Function ---
def get_dll_path(dll_name="todo.dll"):
    if getattr(sys, 'frozen', False): # PyInstaller bundle
        # noinspection PyProtectedMember
        return os.path.join(sys._MEIPASS, dll_name)
    else: # Running as script
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), dll_name)

# --- Pygame Script Path Helper (Revised) ---
def get_pygame_path_revised(script_name="ant_ai.py"):
    """
    Gets the path to the Pygame script.
    If frozen, extracts it to a temporary directory and returns the script path and temp directory.
    If not frozen, returns the local script path and None for the temp directory.
    """
    if getattr(sys, 'frozen', False):
        try:
            # noinspection PyProtectedMember
            bundled_path = os.path.join(sys._MEIPASS, script_name)
            if not os.path.exists(bundled_path):
                raise FileNotFoundError(f"Bundled script '{script_name}' not found in _MEIPASS: {sys._MEIPASS}")

            temp_dir = tempfile.mkdtemp()
            _active_temp_dirs.append(temp_dir) # Track for cleanup
            temp_script_path = os.path.join(temp_dir, script_name)
            shutil.copyfile(bundled_path, temp_script_path)
            return temp_script_path, temp_dir 
        except Exception as e:
            print(f"Error in get_pygame_path_revised (frozen): {e}")
            messagebox.showerror("Game Asset Error", f"Could not prepare game assets: {e}")
            raise
    else:
        # Development mode: script is local
        local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_name)
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Development script '{script_name}' not found at: {local_path}")
        return local_path, None


# --- Load C Library and Define Function Interfaces ---
try:
    lib_path = get_dll_path()
    if not os.path.exists(lib_path):
        messagebox.showerror("Startup Error", f"C library not found at: {lib_path}\nPlease ensure 'todo.dll' is in the correct location and build the project if necessary.")
        sys.exit(1)
    lib = ctypes.CDLL(lib_path)
except OSError as e: 
    print(f"OSError loading C library: {e}")
    print(f"Attempted to load from: {lib_path}")
    messagebox.showerror("Startup Error", f"Error loading C library:\n{e}\n\nPath: {lib_path}\nMake sure 'todo.dll' is compiled for your system architecture (32-bit/64-bit) and all its dependencies are available.")
    sys.exit(1)
except Exception as e: 
    print(f"Unexpected error loading C library: {e}")
    messagebox.showerror("Startup Error", f"An unexpected error occurred while loading the C library:\n{e}")
    sys.exit(1)


# Define C function prototypes
lib.add_task.argtypes = [c_char_p, c_char_p]
lib.add_task.restype = c_int
# ... (rest of your C function prototypes are assumed to be correct as before) ...
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

# --- Global variable to store selected task index ---
current_selected_task_index = -1
task_text_ranges = [] 
HIGHLIGHT_TAG = "selected_task_highlight"
TASK_CURSOR_TAG = "task_cursor_tag"

# --- Core Task Management Functions (Python Wrappers) ---
# ... (Your existing UI functions: set_action_buttons_state, update_task_list, _on_task_enter, etc. remain largely the same)

def set_action_buttons_state(state):
    update_btn.config(state=state)
    mark_done_btn.config(state=state)
    delete_btn.config(state=state)
    pin_btn.config(state=state)

def update_task_list():
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

        done_symbol = "✔️" if done else "❌"
        pin_symbol = "📌 " if pinned == 1 else "" 
        
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
    highlight_selected_task() 

def _on_task_enter(event, task_idx):
    current_mouse_pos = task_display_text.index(f"@{event.x},{event.y}")
    for item in task_text_ranges:
        if item["task_index"] == task_idx:
            if task_display_text.compare(current_mouse_pos, ">=", item["start_index"]) and \
               task_display_text.compare(current_mouse_pos, "<", item["end_index"]):
                task_display_text.config(cursor="hand2")
            return 

def _on_task_leave(event, task_idx):
    task_display_text.config(cursor="") 

def add_task_ui(event=None): 
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
        desc_entry.focus_set()
    else:
        messagebox.showerror("Error", "Failed to add task. The task list might be full.")

def mark_task_done_ui():
    if current_selected_task_index == -1:
        messagebox.showwarning("No Selection", "Please select a task to mark as done.")
        return
    lib.mark_done(current_selected_task_index)
    update_task_list()

def delete_task_ui():
    if current_selected_task_index == -1:
        messagebox.showwarning("No Selection", "Please select a task to delete.")
        return
    if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this task?"):
        lib.delete_task(current_selected_task_index)
        update_task_list()
        clear_selection_and_fields()

def clear_completed_ui():
    if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear all completed tasks?"):
        lib.clear_completed_tasks()
        update_task_list()
        clear_selection_and_fields()

def update_task_ui():
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
    global current_selected_task_index
    
    if task_index_in_list == current_selected_task_index:
        clear_selection_and_fields()
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
    
    set_action_buttons_state(tk.NORMAL)
    highlight_selected_task()

    pin_btn.config(text="Unpin Task" if pinned_status == 1 else "Pin Task")


def text_click_handler(event):
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
    global current_selected_task_index
    current_selected_task_index = -1
    desc_entry.delete(0, tk.END)
    due_entry.delete(0, tk.END)
    set_action_buttons_state(tk.DISABLED)
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

# --- Game Launch Logic (Revised) ---
_game_process_mp = None # Global variable to store the game process

def run_ant_ai_game_target():
    """Target function for the multiprocessing.Process to run the ant_ai game."""
    script_path, temp_dir_for_this_run = None, None
    original_sys_path = list(sys.path) # Save original sys.path to restore it

    try:
        # This function now returns (script_path, temp_dir) or (script_path, None)
        script_path, temp_dir_for_this_run = get_pygame_path_revised()

        if temp_dir_for_this_run: # Frozen mode, script was extracted
            sys.path.insert(0, temp_dir_for_this_run)
            import ant_ai # Dynamically import after adding path
            ant_ai.main() # Call the game's main function
        else: # Development mode (not frozen)
            # In development, ant_ai.py is run directly using the system's Python interpreter
            subprocess.run([sys.executable, script_path], check=True)

    except FileNotFoundError as e:
        # Errors in the child process won't show Tkinter message boxes from the parent.
        # Print to console (or log to a file if more robust logging is needed for the child).
        print(f"ERROR in game process: Pygame script not found. {e}\n{traceback.format_exc()}")
    except ImportError as e:
        print(f"ERROR in game process: Failed to import ant_ai. {e}\n{traceback.format_exc()}")
    except Exception as e:
        print(f"ERROR in game process: An unexpected error occurred. {e}\n{traceback.format_exc()}")
    finally:
        # Restore original sys.path
        sys.path = original_sys_path
        # Clean up the temporary directory if one was created for this specific run
        if temp_dir_for_this_run and os.path.exists(temp_dir_for_this_run):
            try:
                shutil.rmtree(temp_dir_for_this_run)
                if temp_dir_for_this_run in _active_temp_dirs: # Remove from global tracking
                    _active_temp_dirs.remove(temp_dir_for_this_run)
                print(f"Game process cleaned up temp dir: {temp_dir_for_this_run}")
            except Exception as e_cleanup:
                print(f"Error cleaning up temp dir {temp_dir_for_this_run} in game process: {e_cleanup}")


def launch_pygame_app_revised():
    """Launches the ant_ai.py game in a separate process using multiprocessing."""
    global _game_process_mp

    if _game_process_mp and _game_process_mp.is_alive():
        messagebox.showinfo("Game Running", "The ant game is already running.\nPlease close the current game window before starting a new one.")
        return

    try:
        # freeze_support() is essential for multiprocessing in frozen apps (Windows/macOS)
        # It should be called early, ideally in the main part of the script.
        # Calling it here just before starting the process is also common.
        multiprocessing.freeze_support() 

        _game_process_mp = multiprocessing.Process(target=run_ant_ai_game_target)
        _game_process_mp.start()
        # The UI remains responsive as we don't call _game_process_mp.join()
    except Exception as e:
        messagebox.showerror("Launch Error", f"Failed to start the game process:\n{e}\n{traceback.format_exc()}")


# --- Save/Load Functions ---
def auto_load_tasks_on_startup():
    result = lib.load_tasks_from_file(TASKS_FILENAME.encode('utf-8'))
    if result == -1:
        messagebox.showerror("Load Error", f"Error loading tasks from '{TASKS_FILENAME}'.\nThe file might be corrupted or unreadable.")
    elif result == 1: # File not found
        print(f"'{TASKS_FILENAME}' not found. Starting with an empty task list.")
    update_task_list()

def auto_save_tasks_on_exit():
    result = lib.save_tasks_to_file(TASKS_FILENAME.encode('utf-8'))
    if result != 0:
        # This message might not always be visible if the app closes very quickly
        messagebox.showwarning("Save Warning", f"Could not save all tasks to '{TASKS_FILENAME}'.\nCheck file permissions or disk space.")
    else:
        print(f"Tasks saved successfully to {TASKS_FILENAME}.")
    
    # Ensure any running game process is terminated (optional, but good practice)
    global _game_process_mp
    if _game_process_mp and _game_process_mp.is_alive():
        try:
            _game_process_mp.terminate() # Politely ask to terminate
            _game_process_mp.join(timeout=1) # Wait a bit
            if _game_process_mp.is_alive():
                _game_process_mp.kill() # Force kill if still alive
            print("Terminated game process on exit.")
        except Exception as e_term:
            print(f"Error terminating game process on exit: {e_term}")

    cleanup_all_temp_dirs_on_exit() # Explicit call to ensure cleanup attempt
    root.destroy()


# --- UI Setup ---
if __name__ == '__main__': # Essential for multiprocessing on Windows when frozen
    multiprocessing.freeze_support() # Call freeze_support at the start of the main execution block

    root = tk.Tk()
    root.title("To-Do List Manager")
    root.geometry("750x450") 

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    main_frame = tk.Frame(root, padx=10, pady=10)
    main_frame.grid(row=0, column=0, sticky="nsew")

    main_frame.grid_columnconfigure(0, weight=3) 
    main_frame.grid_columnconfigure(1, weight=1) 
    main_frame.grid_rowconfigure(0, weight=1)    

    left_frame = tk.Frame(main_frame)
    left_frame.grid(row=0, column=0, padx=(0,10), pady=5, sticky="nsew") 
    left_frame.grid_rowconfigure(0, weight=1)
    left_frame.grid_columnconfigure(0, weight=1)

    task_display_text = tk.Text(left_frame, height=15, font=('Arial', 10), wrap=tk.WORD, relief=tk.FLAT, bd=0)
    task_display_text.grid(row=0, column=0, sticky="nsew")
    task_display_text.config(
        selectbackground=task_display_text.cget("background"), 
        selectforeground=task_display_text.cget("foreground"),
        state=tk.DISABLED 
    )
    task_display_text.bind("<Button-1>", text_click_handler) 
    task_display_text.tag_configure(HIGHLIGHT_TAG, background="SystemHighlight", foreground="SystemHighlightText") 
    task_display_text.tag_configure(TASK_CURSOR_TAG) 

    scrollbar = tk.Scrollbar(left_frame, orient="vertical", command=task_display_text.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    task_display_text.config(yscrollcommand=scrollbar.set)

    right_frame = tk.Frame(main_frame)
    right_frame.grid(row=0, column=1, padx=(5,0), pady=5, sticky="nsew")

    tk.Label(right_frame, text="Task Description:").pack(pady=(0,2), anchor="w")
    desc_entry = tk.Entry(right_frame, width=35, font=('Arial', 10)) 
    desc_entry.pack(pady=(0,10), fill=tk.X, expand=False) 
    desc_entry.bind("<Return>", lambda e: add_task_ui())

    tk.Label(right_frame, text="Due Date (MM-DD HH:MM):").pack(pady=(0,2), anchor="w")
    due_entry = tk.Entry(right_frame, width=35, font=('Arial', 10)) 
    due_entry.pack(pady=(0,15), fill=tk.X, expand=False) 
    due_entry.bind("<Return>", lambda e: add_task_ui())

    btn_width = 18 
    add_btn = tk.Button(right_frame, text="Add Task", command=add_task_ui, width=btn_width)
    add_btn.pack(pady=3, fill=tk.X)

    update_btn = tk.Button(right_frame, text="Update Task", command=update_task_ui, width=btn_width, state=tk.DISABLED)
    update_btn.pack(pady=3, fill=tk.X)

    mark_done_btn = tk.Button(right_frame, text="Mark as Done", command=mark_task_done_ui, width=btn_width, state=tk.DISABLED)
    mark_done_btn.pack(pady=3, fill=tk.X)

    delete_btn = tk.Button(right_frame, text="Delete Task", command=delete_task_ui, width=btn_width, state=tk.DISABLED)
    delete_btn.pack(pady=3, fill=tk.X)

    pin_btn = tk.Button(right_frame, text="Toggle Pin", command=toggle_pin_task_ui, width=btn_width, state=tk.DISABLED)
    pin_btn.pack(pady=3, fill=tk.X)

    clear_completed_btn = tk.Button(right_frame, text="Clear Completed", command=clear_completed_ui, width=btn_width)
    clear_completed_btn.pack(pady=(3,10), fill=tk.X) 

    # Update the button command to call the revised launch function
    pygame_btn = tk.Button(right_frame, text="Don't know what to do?", command=launch_pygame_app_revised, width=btn_width + 5) 
    pygame_btn.pack(pady=(10, 5), fill=tk.X)

    auto_load_tasks_on_startup() 
    set_action_buttons_state(tk.DISABLED) 
    root.protocol("WM_DELETE_WINDOW", auto_save_tasks_on_exit) 

    root.mainloop()

