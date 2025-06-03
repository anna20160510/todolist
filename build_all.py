import os
import sys
import subprocess
import shutil
import struct
import io

try:
    import pefile
except ImportError:
    # 如果沒有安裝 pefile 模組，則使用 pip 進行安裝
    subprocess.run([sys.executable, "-m", "pip", "install", "pefile"])
    import pefile

DLL_NAME = "todo.dll"  # 定義 DLL 檔案的名稱
PY_FILE = "ui.py"      # 定義 Python 腳本檔案的名稱
EXE_NAME = os.path.splitext(PY_FILE)[0] + ".exe" # 根據 Python 腳本名稱生成 EXE 檔案名稱

def get_python_arch():
    # 獲取 Python 解釋器的位元架構 (32-bit 或 64-bit)
    return f"{struct.calcsize('P') * 8}-bit"

def get_dll_arch(dll_path):
    # 獲取 DLL 檔案的位元架構
    try:
        pe = pefile.PE(dll_path) # 解析 PE 檔案 (DLL)
        machine = pe.FILE_HEADER.Machine # 讀取檔案頭中的機器類型
        if machine == 0x8664:
            return "64-bit" # 64 位元架構
        elif machine == 0x14c:
            return "32-bit" # 32 位元架構
        else:
            return f"Unknown (Machine ID: {hex(machine)})" # 未知架構
    except Exception as e:
        return f"Error reading DLL: {e}" # 讀取 DLL 錯誤

def show_compile_instructions(py_arch):
    # 顯示編譯 todo.c 的指令
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
    # 檢查現有的 DLL 檔案，並比對其架構與 Python 架構是否一致
    if os.path.exists(DLL_NAME):
        print(f"\nFound '{DLL_NAME}' — checking architecture...")
        arch = get_dll_arch(DLL_NAME) # 獲取 DLL 的架構
        print(f"DLL Architecture Detected : {arch}")
        if arch != py_arch:
            print("\nMismatch detected!")
            print("DLL does not match your Python architecture.")
            print("Recompile using the command shown above.\n")
        else:
            print("DLL matches your Python architecture.")
    else:
        print(f"\n(No DLL found — compile instructions shown above.)") # 未找到 DLL

def ensure_pyinstaller_installed():
    # 檢查 PyInstaller 是否已安裝
    try:
        subprocess.run(["pyinstaller", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def compile_c():
    # 編譯 C 語言原始碼生成 DLL
    print("\n[Compiling] Building todo.dll...")

    # 刪除舊的 DLL 檔案和相關檔案
    for file in [DLL_NAME, "libtodo.a"]:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"Removed old {file}")
            except Exception as e:
                print(f"Could not delete {file}: {e}")
                sys.exit(1)

    # 執行 gcc 編譯指令
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

    arch = get_dll_arch(DLL_NAME) # 獲取新編譯的 DLL 架構
    py_arch = get_python_arch()   # 獲取 Python 架構
    print(f"DLL Architecture Detected: {arch}")

    if py_arch != arch:
        print(f"❌ DLL architecture mismatch: Python is {py_arch}, but DLL is {arch}")
        print("Make sure you’re using MinGW-w64 and targeting the correct bitness.")
        sys.exit(1)

    print("✅ DLL is valid and matches Python architecture.")

def build_exe():
    # 使用 PyInstaller 打包生成可執行檔
    print("\n[Bundling] Building executable with PyInstaller...")
    result = subprocess.run([
        "pyinstaller",
        "--onefile", # 打包成單一檔案
        "--windowed", # 創建無控制台視窗的可執行檔
        f"--add-binary={DLL_NAME};.",  # 將 DLL 檔案添加到可執行檔中
        "--add-binary=ant_ai.py;.",  # 👈 添加這行以打包 ant_ai.py
        PY_FILE # 指定要打包的 Python 腳本
    ])
    if result.returncode != 0:
        print("PyInstaller build failed.")
        sys.exit(1)
    print("Executable built successfully.")

def clean_up():
    # 清理建置過程中產生的檔案和資料夾
    print("\n[Cleanup] Removing build leftovers...")
    for folder in ["build", "__pycache__"]:
        shutil.rmtree(folder, ignore_errors=True) # 刪除資料夾
    for file in [f"{os.path.splitext(PY_FILE)[0]}.spec", "libtodo.a"]:
        if os.path.exists(file):
            os.remove(file) # 刪除檔案
    print("Cleanup complete.")

def main():
    # 主函數，執行整個建置流程
    os.chdir(os.path.dirname(os.path.abspath(__file__))) # 將當前工作目錄更改為腳本所在目錄

    # 將標準輸出和標準錯誤重定向到日誌檔案
    log_file = open("build_log.txt", "w", encoding="utf-8")
    sys.stdout = sys.stderr = io.TextIOWrapper(log_file.buffer, encoding="utf-8")

    print("==============================")
    print("To-Do App Build Script")
    print("==============================\n")

    py_arch = get_python_arch() # 獲取 Python 架構
    print(f"Detected Python Architecture: {py_arch}")
    show_compile_instructions(py_arch) # 顯示編譯指令
    check_existing_dll(py_arch) # 檢查現有 DLL

    compile_c() # 編譯 C 語言檔案

    if ensure_pyinstaller_installed():
        build_exe() # 如果 PyInstaller 已安裝，則打包可執行檔
        exe_path = os.path.join("dist", EXE_NAME)
        print(f"\n[Success] Your .exe is ready at:\n{exe_path}")
    else:
        print("\n[Warning] PyInstaller not found — .exe build skipped.")
        print("To install it, run: pip install pyinstaller")
        print("You can still run ui.py manually after compiling todo.dll.")

    clean_up() # 清理建置產生的檔案

    # 將標準輸出和標準錯誤恢復到控制台
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    print("\n✅ Build finished successfully.")

if __name__ == "__main__":
    main() # 執行主函數