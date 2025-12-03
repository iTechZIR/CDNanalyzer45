# This code is required to install the libraries.
# cmd: pip install psutil

import os

filename = "requirements.txt"

if os.path.exists(filename):
    with open(filename, "r") as file:
        libraries = file.readlines()

    for lib in libraries:
        lib = lib.strip()
        
        if lib:
            os.system(f"pip install {lib}")
            print(f"Installing {lib}...")
else:
    print(f"File {filename} does not exist")
