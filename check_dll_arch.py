import struct
import os
import sys
import platform

# Try to import pefile (used to inspect DLL architecture)
try:
    import pefile
except ImportError:
    print("Missing module 'pefile'. Installing it now...")
    os.system(f"{sys.executable} -m pip install pefile")
    import pefile

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
            return f"Unknown architecture (Machine ID: {hex(machine)})"
    except Exception as e:
        return f"Error reading DLL: {e}"

def show_compile_instructions(py_arch):
    print("\n--- COMPILATION INSTRUCTIONS ---")
    if py_arch == "64-bit":
        print("You are using 64-bit Python.")
        print("To compile todo.c as a 64-bit DLL (✅ RECOMMENDED):\n")

        if platform.system() == "Windows":
            print("➡️  Using MinGW-w64 (on Windows):")
            print("    PowerShell:")
            print('      gcc -shared -o todo.dll "-Wl,--out-implib,libtodo.a" todo.c')
            print("    CMD:")
            print("      gcc -shared -o todo.dll -Wl,--out-implib,libtodo.a todo.c")
        else:
            print("➡️  On Linux/macOS:")
            print("    gcc -shared -fPIC -o libtodo.so todo.c")

        print("\n➡️  Using Visual Studio Developer Command Prompt:")
        print("    cl /LD todo.c /Fe:todo.dll")

    elif py_arch == "32-bit":
        print("You are using 32-bit Python.")
        print("To compile todo.c as a 32-bit DLL:\n")

        if platform.system() == "Windows":
            print("➡️  Using MinGW (32-bit):")
            print("    PowerShell:")
            print('      i686-w64-mingw32-gcc -shared -o todo.dll "-Wl,--out-implib,libtodo.a" todo.c')
            print("    CMD:")
            print("      i686-w64-mingw32-gcc -shared -o todo.dll -Wl,--out-implib,libtodo.a todo.c")
        else:
            print("➡️  On Linux/macOS:")
            print("    gcc -shared -fPIC -m32 -o libtodo.so todo.c")
    else:
        print("Unsupported Python architecture detected. Please check manually.")

def main():
    print("\n==============================")
    print(" DLL Compatibility Checker")
    print("==============================\n")

    py_arch = get_python_arch()
    print(f"Your Python Architecture  : {py_arch}")

    show_compile_instructions(py_arch)

    dll_path = "todo.dll"
    if os.path.exists(dll_path):
        print("\nFound 'todo.dll' — checking architecture...")
        dll_arch = get_dll_arch(dll_path)
        print(f"DLL Architecture Detected : {dll_arch}")

        if "Error" in dll_arch:
            print("\n❌ Could not read the DLL. Make sure it's a valid Windows .dll file.")
            return

        if py_arch != dll_arch:
            print("\n❌ ARCHITECTURE MISMATCH DETECTED!")
            print("Recompile using the instructions above to fix this.")
        else:
            print("\n✅ Good news! Your DLL matches your Python architecture.")
            print("You are ready to run your Python app.")
    else:
        print("\n(No DLL found — compile instructions shown above.)")
        print("Once compiled, re-run this script to verify DLL architecture.")

    print("\n==============================\n")

if __name__ == "__main__":
    main()
