import os
import time
import logging
import psutil
import subprocess
import json
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tempfile
import sys

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class FileChangeHandler(FileSystemEventHandler):
    """Handles file system change events."""
    def __init__(self, log_list):
        self.log_list = log_list

    def on_modified(self, event):
        self.log_list.append({'event': 'modified', 'src_path': event.src_path, 'timestamp': datetime.now().isoformat()})
        logger.info(f"File modified: {event.src_path}")

    def on_created(self, event):
        self.log_list.append({'event': 'created', 'src_path': event.src_path, 'timestamp': datetime.now().isoformat()})
        logger.info(f"File created: {event.src_path}")

    def on_deleted(self, event):
        self.log_list.append({'event': 'deleted', 'src_path': event.src_path, 'timestamp': datetime.now().isoformat()})
        logger.info(f"File deleted: {event.src_path}")

class DynamicAnalyzer:
    def __init__(self, sample_path, timeout=60, env_vars=None):
        self.sample_path = sample_path
        self.timeout = timeout
        self.process_info = {}
        self.network_logs = []
        self.file_change_logs = []
        self.registry_changes = []
        self.memory_dumps = []
        self.start_time = None
        self.end_time = None
        self.process_tree = []
        self.env_vars = env_vars or {}
        self.observer = None

    def start_analysis(self):
        """Starts the dynamic analysis of the malware sample."""
        try:
            logger.info(f"Starting dynamic analysis for {self.sample_path}")
            self.start_time = time.time()  # Start timer
            process = subprocess.Popen(self.sample_path, shell=True, env=self.env_vars)

            # Start monitoring in separate threads
            monitor_thread = threading.Thread(target=self.monitor_process, args=(process,))
            monitor_thread.start()

            # Start file system monitoring
            self.start_file_monitoring()

            # Wait for the process to finish or timeout
            process.wait(timeout=self.timeout)
            logger.info(f"Process {process.pid} completed.")

        except subprocess.TimeoutExpired:
            logger.warning(f"Process {self.sample_path} exceeded timeout of {self.timeout} seconds.")
            process.kill()
        except Exception as e:
            logger.error(f"Error during dynamic analysis: {e}")
        finally:
            # Stop the file system monitoring
            if self.observer:
                self.observer.stop()
                self.observer.join()
            # Collect analysis results
            self.end_time = time.time()  # End timer
            self.collect_process_info()
            self.collect_network_logs()
            self.collect_file_changes()
            self.collect_registry_changes()
            self.save_memory_dump()

    def monitor_process(self, process):
        """Monitors the process and logs its resource usage."""
        while True:
            if process.poll() is not None:  # Process has finished
                break

            cpu_usage = psutil.cpu_percent(interval=1)
            mem_info = psutil.Process(process.pid).memory_info()

            logger.info(f"Process ID: {process.pid}, CPU Usage: {cpu_usage}%, Memory Usage: {mem_info.rss / (1024 ** 2):.2f} MB")
            self.process_tree.append((process.pid, process.name(), datetime.now().isoformat()))
            time.sleep(1)

    def start_file_monitoring(self):
        """Starts monitoring the file system for changes."""
        self.file_change_logs = []  # Reset file change logs
        event_handler = FileChangeHandler(self.file_change_logs)
        self.observer = Observer()
        observer_path = os.path.dirname(self.sample_path)  # Monitor the directory of the sample
        self.observer.schedule(event_handler, path=observer_path, recursive=True)  # Monitor the directory where the sample is located
        self.observer.start()
        logger.info("Started monitoring file system changes.")

    def start_registry_monitoring(self):
        """Starts monitoring registry changes."""
        if sys.platform.startswith('win'):
            # Import winreg only if on Windows
            import winreg
            logger.info("Started monitoring registry changes (functionality not implemented).")
        else:
            logger.info("Registry monitoring is not supported on this platform.")

    def collect_process_info(self):
        """Collects information about the running process."""
        try:
            process = psutil.Process(os.getpid())
            self.process_info = {
                'pid': process.pid,
                'name': process.name(),
                'status': process.status(),
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                'memory_usage': process.memory_info().rss / (1024 ** 2),  # Convert to MB
                'cpu_usage': process.cpu_percent(interval=1),
                'execution_time': self.end_time - self.start_time,
                'child_processes': [p.pid for p in process.children()]
            }
            logger.info(f"Collected process information: {self.process_info}")

        except Exception as e:
            logger.error(f"Error collecting process info: {e}")

    def collect_network_logs(self):
        """Collects network logs during the analysis."""
        try:
            # Simulated network data; replace with actual traffic capture logic
            dummy_network_data = [
                {"timestamp": "2024-09-26T12:00:00Z", "src_ip": "192.168.1.1", "dst_ip": "93.184.216.34", "bytes_sent": 500},
                {"timestamp": "2024-09-26T12:00:05Z", "src_ip": "192.168.1.1", "dst_ip": "93.184.216.34", "bytes_sent": 300}
            ]
            self.network_logs.extend(dummy_network_data)
            logger.info(f"Collected network logs: {self.network_logs}")

        except Exception as e:
            logger.error(f"Error collecting network logs: {e}")

    def collect_file_changes(self):
        """Collects file changes detected during the analysis."""
        logger.info(f"Collected file changes: {self.file_change_logs}")

    def collect_registry_changes(self):
        """Collects changes in the registry during the analysis."""
        # This is a placeholder for actual implementation.
        logger.info(f"Collected registry changes: {self.registry_changes}")

    def save_memory_dump(self):
        """Captures and saves memory dump of the process."""
        try:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.dmp')
            dump_file_path = temp_file.name
            # This would normally use a library or system call to create a memory dump
            logger.info(f"Saved memory dump to {dump_file_path}")
            self.memory_dumps.append(dump_file_path)

        except Exception as e:
            logger.error(f"Error saving memory dump: {e}")

    def save_results(self, output_file='dynamic_analysis_results.json'):
        """Saves the analysis results to a JSON file."""
        results = {
            "process_info": self.process_info,
            "network_logs": self.network_logs,
            "file_change_logs": self.file_change_logs,
            "registry_changes": self.registry_changes,
            "memory_dumps": self.memory_dumps,
            "sample_path": self.sample_path,
            "timestamp": datetime.now().isoformat()
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            logger.info(f"Results saved to {output_file}")

        except Exception as e:
            logger.error(f"Error saving results: {e}")

# Example usage
if __name__ == "__main__":
    # Prompt user for the path of the malware sample
    sample_path = input("Enter the path of the malware sample to analyze: ")
    timeout = 60  # You can also prompt the user for this if needed
    env_variables = {'TEST_ENV_VAR': 'TestValue'}  # Example of setting custom environment variables
    analyzer = DynamicAnalyzer(sample_path=sample_path, timeout=timeout, env_vars=env_variables)
    analyzer.start_analysis()
    analyzer.save_results()
