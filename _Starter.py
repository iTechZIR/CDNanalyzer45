# This code is for the main setup

import subprocess
import sys
import os

def _run_ip_check():
    filepath = "main/_cdn_checker_/__cdn_checker__.py"

    if not os.path.exists(filepath):
        print(f"-  error: file {filepath} not found")
        return

    try:
        subprocess.run([sys.executable, filepath])
    except KeyboardInterrupt:
        print("-  stopped by user")
    except Exception as e:
        print(f"-  error running file: {e}")

if __name__ == "__main__":
    _run_ip_check()
