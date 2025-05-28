import os
import sys
import subprocess
import shutil
import struct
import io

try:
    import pefile
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "pefile"])
    import pefile

DLL_NAME = "todo.dll"
PY_FILE = "ui.py"
EXE_NAME = os.path.splitext(PY_FILE)[0] + ".exe"

def get_python_arch():
    return f"{struct.calcsize('P') * 8}-bit"

def get_dll_arch(dll_path):
    try:
        pe = pefile.PE(dll_path)
        machine = pe.FILE_HEADER.Machine
        if machine == 0x8664:
            return "64-bit"
        elif machine == 0x14c:
            return "32-bit"
        else:
            return f"Unknown (Machine ID: {hex(machine)})"
    except Exception as e:
        return f"Error reading DLL: {e}"

def show_compile_instructions(py_arch):
    print("\n--- COMPILATION INSTRUCTIONS ---")
    print(f"Your Python Architecture  : {py_arch}")
    print("To compile todo.c correctly:")

    if py_arch == "64-bit":
        print("\nMinGW-w64 (PowerShell):")
        print('  gcc -shared -o todo.dll "-Wl,--out-implib,libtodo.a" todo.c')
        print("\nMinGW-w64 (CMD):")
        print("  gcc -shared -o todo.dll -Wl,--out-implib,libtodo.a todo.c")
        print("\nVisual Studio Dev Command Prompt:")
        print("  cl /LD todo.c /Fe:todo.dll")
    else:
        print("\n32-bit MinGW (PowerShell):")
        print('  i686-w64-mingw32-gcc -shared -o todo.dll "-Wl,--out-implib,libtodo.a" todo.c')
        print("\n32-bit MinGW (CMD):")
        print("  i686-w64-mingw32-gcc -shared -o todo.dll -Wl,--out-implib,libtodo.a todo.c")

def check_existing_dll(py_arch):
    if os.path.exists(DLL_NAME):
        print(f"\nFound '{DLL_NAME}' — checking architecture...")
        arch = get_dll_arch(DLL_NAME)
        print(f"DLL Architecture Detected : {arch}")
        if arch != py_arch:
            print("\nMismatch detected!")
            print("DLL does not match your Python architecture.")
            print("Recompile using the command shown above.\n")
        else:
            print("DLL matches your Python architecture.")
    else:
        print(f"\n(No DLL found — compile instructions shown above.)")

def ensure_pyinstaller_installed():
    try:
        subprocess.run(["pyinstaller", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def compile_c():
    print("\n[Compiling] Building todo.dll...")

    # Remove old files
    for file in [DLL_NAME, "libtodo.a"]:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"Removed old {file}")
            except Exception as e:
                print(f"Could not delete {file}: {e}")
                sys.exit(1)

    # Run gcc
    result = subprocess.run([
        "gcc",
        "-shared", "-o", DLL_NAME,
        "-Wl,--out-implib,libtodo.a",
        "todo.c"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print("Compilation failed:")
        print(result.stderr)
        sys.exit(1)

    print("DLL compiled — verifying...")

    if not os.path.exists(DLL_NAME):
        print("❌ todo.dll was not created. Something went wrong.")
        sys.exit(1)

    arch = get_dll_arch(DLL_NAME)
    py_arch = get_python_arch()
    print(f"DLL Architecture Detected: {arch}")

    if py_arch != arch:
        print(f"❌ DLL architecture mismatch: Python is {py_arch}, but DLL is {arch}")
        print("Make sure you’re using MinGW-w64 and targeting the correct bitness.")
        sys.exit(1)

    print("✅ DLL is valid and matches Python architecture.")

def build_exe():
    print("\n[Bundling] Building executable with PyInstaller...")
    result = subprocess.run([
        "pyinstaller",
        "--onefile",
        "--windowed",
        f"--add-binary={DLL_NAME};.",
        PY_FILE
    ])
    if result.returncode != 0:
        print("PyInstaller build failed.")
        sys.exit(1)
    print("Executable built successfully.")

def clean_up():
    print("\n[Cleanup] Removing build leftovers...")
    for folder in ["build", "__pycache__"]:
        shutil.rmtree(folder, ignore_errors=True)
    for file in [f"{os.path.splitext(PY_FILE)[0]}.spec", "libtodo.a"]:
        if os.path.exists(file):
            os.remove(file)
    print("Cleanup complete.")

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    log_file = open("build_log.txt", "w", encoding="utf-8")
    sys.stdout = sys.stderr = io.TextIOWrapper(log_file.buffer, encoding="utf-8")

    print("==============================")
    print("To-Do App Build Script")
    print("==============================\n")

    py_arch = get_python_arch()
    print(f"Detected Python Architecture: {py_arch}")
    show_compile_instructions(py_arch)
    check_existing_dll(py_arch)

    compile_c()

    if ensure_pyinstaller_installed():
        build_exe()
        exe_path = os.path.join("dist", EXE_NAME)
        print(f"\n[Success] Your .exe is ready at:\n{exe_path}")
    else:
        print("\n[Warning] PyInstaller not found — .exe build skipped.")
        print("To install it, run: pip install pyinstaller")
        print("You can still run ui.py manually after compiling todo.dll.")

    clean_up()

    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    print("\n✅ Build finished successfully.")

if __name__ == "__main__":
    main()
