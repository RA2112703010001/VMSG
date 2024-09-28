# src/run_all.py

import subprocess

def run_script(script):
    result = subprocess.run(["python", script], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error running {script}:\n{result.stderr}")

def main():
    scripts = [
        "data_collection/static_analysis.py",
        "data_collection/dynamic_analysis.py",
        "data_processing/data_parser.py",
        "data_processing/pattern_recognition.py",
        "visualization/graph_builder.py",
        "visualization/visualizer.py",
        "main.py"
    ]

    for script in scripts:
        run_script(f"src/{script}")

if __name__ == "__main__":
    main()
