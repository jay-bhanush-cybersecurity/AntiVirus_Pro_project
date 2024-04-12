
import ctypes
import sys
import subprocess
def is_admin():
    try:
        # Check if the current process has admin privileges
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        print(f"Error checking admin privileges: {e}")
        return False

def run_as_admin():
    try:
        if is_admin():
            # If already running as admin, just run the main script
            subprocess.Popen([sys.executable, 'MAIN.py'])
        else:
            # If not running as admin, elevate privileges and run the main script
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, 'MAIN.py', None, 1)
    except Exception as e:
        print(f"Error running as admin: {e}")

if __name__ == "__main__":
    run_as_admin()
