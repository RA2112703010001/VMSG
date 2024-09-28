import os
import sys
from cx_Freeze import setup, Executable
import PyQt5  # Import PyQt5 to access its path

# Get the directory of PyQt5
qt_dir = os.path.dirname(PyQt5.__file__)

# Define the build options
build_exe_options = {
    "packages": ["os", "sys", "PyQt5"],  # Include necessary packages
    "include_files": [
        (os.path.join(qt_dir, "Qt"), "Qt"),  # Include Qt files
    ],
}

# Setup the application
setup(
    name="VMSG",
    version="0.1",
    description="Visual Malware Signature Generator",
    options={"build_exe": build_exe_options},
    executables=[Executable("src/main.py")],
)
