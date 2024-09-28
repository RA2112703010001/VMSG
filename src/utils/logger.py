import logging
import os
import smtplib
import gzip
import shutil
import json
import time
import threading
from logging.handlers import RotatingFileHandler, Filter
from queue import Queue

class CustomFilter(Filter):
    """Custom filter to allow filtering of log messages."""
    def __init__(self, level=logging.DEBUG):
        super().__init__()
        self.level = level

    def filter(self, record):
        return record.levelno >= self.level

class Logger:
    """Logger class to handle application logging."""

    def __init__(self, log_file='application.log', max_bytes=5 * 1024 * 1024,
                 backup_count=3, email_notifications=False, timestamp_format='%Y-%m-%d %H:%M:%S',
                 min_log_level=logging.DEBUG, retention_days=30):
        """Initialize the logger with file and console handlers."""
        self.logger = logging.getLogger('MalwareSignatureGenerator')
        self.logger.setLevel(logging.DEBUG)

        # Create a rotating file handler
        self.log_file = log_file
        self.retention_days = retention_days
        file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        console_handler = logging.StreamHandler()

        # Set the log format
        log_format = logging.Formatter(f'%(asctime)s - %(levelname)s - %(message)s', datefmt=timestamp_format)
        file_handler.setFormatter(log_format)
        console_handler.setFormatter(log_format)

        # Add custom filter for minimum log level
        if min_log_level is not None:
            custom_filter = CustomFilter(level=min_log_level)
            file_handler.addFilter(custom_filter)
            console_handler.addFilter(custom_filter)

        # Add handlers to the logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        # Email notification flag
        self.email_notifications = email_notifications

        # Initialize queue for asynchronous logging
        self.log_queue = Queue()
        self.is_logging = True
        threading.Thread(target=self.process_log_queue, daemon=True).start()

    def log(self, level, message, context=None):
        """Log a message at the specified level with optional context."""
        log_message = {
            "level": level,
            "message": message,
            "context": context if context else {},
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.log_queue.put(log_message)

    def process_log_queue(self):
        """Process log messages from the queue asynchronously."""
        while self.is_logging:
            while not self.log_queue.empty():
                log_message = self.log_queue.get()
                if log_message["level"] == 'debug':
                    self.logger.debug(json.dumps(log_message))
                elif log_message["level"] == 'info':
                    self.logger.info(json.dumps(log_message))
                elif log_message["level"] == 'warning':
                    self.logger.warning(json.dumps(log_message))
                elif log_message["level"] == 'error':
                    self.logger.error(json.dumps(log_message))
                    if self.email_notifications:
                        self.send_error_notification(log_message["message"])
                elif log_message["level"] == 'critical':
                    self.logger.critical(json.dumps(log_message))
                    if self.email_notifications:
                        self.send_error_notification(log_message["message"])
                self.log_queue.task_done()

    def send_error_notification(self, message):
        """Send an email notification for critical errors."""
        sender = "your_email@example.com"  # Update with your email
        receiver = "admin@example.com"      # Update with receiver email
        subject = "Critical Error in Application"
        body = f"Critical error occurred: {message}"

        try:
            with smtplib.SMTP('smtp.example.com', 587) as server:  # Update SMTP server and port
                server.starttls()
                server.login(sender, 'your_email_password')  # Update with your email password
                server.sendmail(sender, receiver, f"Subject: {subject}\n\n{body}")
                self.logger.info("Error notification sent to %s", receiver)
        except Exception as e:
            self.logger.error("Failed to send error notification: %s", str(e))

    def compress_old_log_files(self):
        """Compress old log files to save space."""
        if os.path.exists(self.log_file):
            with open(self.log_file, 'rb') as f_in:
                with gzip.open(f"{self.log_file}.gz", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(self.log_file)  # Remove the original log file after compression

    def adjust_log_level(self, level):
        """Dynamically adjust the logging level."""
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)
        self.logger.info(f"Log level adjusted to: {level}")

    def delete_old_logs(self):
        """Delete logs older than retention_days."""
        now = time.time()
        for filename in os.listdir(os.path.dirname(self.log_file)):
            file_path = os.path.join(os.path.dirname(self.log_file), filename)
            if os.path.isfile(file_path):
                if (now - os.path.getmtime(file_path)) > (self.retention_days * 86400):  # 86400 seconds in a day
                    os.remove(file_path)
                    self.logger.info(f"Deleted old log file: {filename}")

# Sample Usage
if __name__ == "__main__":
    logger = Logger(email_notifications=True)
    logger.log('info', 'Application started.')
    logger.log('debug', 'Debugging application...')
    logger.log('warning', 'This is a warning message.')
    logger.log('error', 'An error has occurred!')
    logger.log('critical', 'A critical error has occurred!')

    # Dynamically adjust log level
    logger.adjust_log_level(logging.ERROR)

    # Compress old log files
    logger.compress_old_log_files()

    # Delete old log files based on retention policy
    logger.delete_old_logs()
