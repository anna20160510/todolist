### Use `build_all.bat` to compile `todo.c` by simply running it. If you have *pyinstaller* installed in your computer, it'll even make you a .exe file. If not, you can still run `ui.py` to execute the program.
-----------------------
# Detailed explanation:

## To-Do List App (C + Python GUI)

This is a lightweight To-Do List application that combines:

- A **C backend** for fast task management and sorting
- A **Python Tkinter GUI** frontend
- Cross-platform compatibility (Windows focused)
- Optional bundling as a `.exe` using PyInstaller

---

## ✅ Features

- Add, edit, delete, and mark tasks as done
- Due date support with automatic sorting
- Portable `.exe` build option — no Python install required
- Clean UI built with Tkinter
- Fast core logic powered by native C code

---

## 🗂️ File Overview

| File             | Purpose                                                                 |
|------------------|-------------------------------------------------------------------------|
| `todo.c`         | C backend for task management (compiled into `todo.dll`)                |
| `ui.py`          | Python Tkinter GUI that uses `ctypes` to load and run C code            |
| `build_all.py`   | Smart build script — compiles C code, builds `.exe`, checks compatibility |
| `build.bat`      | One-click launcher for `build_all.py` on Windows                        |
| `todo.dll`       | Compiled C library (auto-generated — **not stored in repo**)            |
| `build_log.txt`  | Log file generated during builds                                        |

---

## ⚙️ Getting Started

### Option 1: Run as Python script

1. Make sure you have:
    - Python 3.8+ installed
    - A compiled `todo.dll` in the same folder as `ui.py`
2. Open a terminal in the project folder
3. Run:
   ```bash
   python ui.py
   ```

### Option 2: Build & run the .exe (Windows only)

1. Install required tools:
    - MinGW-w64 (for `gcc`)
    - (Optional) PyInstaller: `pip install pyinstaller`

2. Double-click `build.bat`
OR
Run from terminal:

```bash
python build_all.py
```

If PyInstaller is installed, this will generate an `.exe` in the `dist/` folder.

## 🛠 How the Build Works
- `build_all.py` checks your Python architecture (32-bit or 64-bit)

- Shows correct compile commands

- Compiles `todo.c` into `todo.dll`

- Optionally builds a `.exe` using PyInstaller

- Creates a `build_log.txt` for diagnostics

You can run it even if PyInstaller is not installed — it’ll still compile the DLL and guide you through setup.

## 📎 Notes
- Only the compiled `.dll` is used at runtime; no Python logic is re-implemented in C

- All tasks are stored in memory — no save/load to disk (yet)

- This project is a learning/demo tool, but can be expanded
