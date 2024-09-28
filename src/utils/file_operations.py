import os
import shutil
import zipfile
import logging
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet
from difflib import unified_diff

class FileOperations:
    """Utility class for file handling operations."""

    def __init__(self, logger=None):
        """Initialize the FileOperations with an optional logger."""
        self.logger = logger or logging.getLogger(__name__)
        self.key = Fernet.generate_key()  # Generate a new key for encryption
        self.cipher = Fernet(self.key)

    def validate_file(self, file_path):
        """Check if a file is valid (exists, not empty, correct format)."""
        if not os.path.isfile(file_path):
            self.logger.error("File does not exist: %s", file_path)
            return False
        if os.path.getsize(file_path) == 0:
            self.logger.error("File is empty: %s", file_path)
            return False
        if not file_path.endswith(('.json', '.txt', '.log', '.csv', '.xml')):
            self.logger.error("Invalid file format: %s", file_path)
            return False
        return True

    def backup_file(self, file_path):
        """Create a backup of the specified file."""
        if self.validate_file(file_path):
            backup_path = f"{file_path}.bak"
            shutil.copy2(file_path, backup_path)
            self.logger.info("Backup created for file: %s at %s", file_path, backup_path)
            return backup_path
        return None

    def restore_file(self, backup_path):
        """Restore a file from its backup."""
        original_file = backup_path[:-4]  # Remove .bak
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, original_file)
            self.logger.info("File restored from backup: %s to %s", backup_path, original_file)
            return original_file
        self.logger.error("Backup file does not exist: %s", backup_path)
        return None

    def batch_process_files(self, file_paths, operation, *args, **kwargs):
        """Batch process multiple files with a specified operation."""
        for file_path in file_paths:
            if self.validate_file(file_path):
                try:
                    operation(file_path, *args, **kwargs)
                    self.logger.info("Processed file: %s", file_path)
                except Exception as e:
                    self.logger.error("Error processing file %s: %s", file_path, str(e))

    def create_directory(self, dir_path):
        """Create a directory if it does not exist."""
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        self.logger.info("Directory created or already exists: %s", dir_path)

    def delete_directory(self, dir_path):
        """Delete a directory and all its contents."""
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
            self.logger.info("Directory deleted: %s", dir_path)
        else:
            self.logger.error("Directory does not exist: %s", dir_path)

    def list_files_in_directory(self, dir_path):
        """List all files in a given directory."""
        if os.path.isdir(dir_path):
            files = os.listdir(dir_path)
            self.logger.info("Files in directory %s: %s", dir_path, files)
            return files
        self.logger.error("Path is not a directory: %s", dir_path)
        return []

    def compress_file(self, file_path):
        """Compress a file into a ZIP format."""
        if self.validate_file(file_path):
            zip_file_path = f"{file_path}.zip"
            with zipfile.ZipFile(zip_file_path, 'w') as zipf:
                zipf.write(file_path, arcname=os.path.basename(file_path))
            self.logger.info("File compressed: %s to %s", file_path, zip_file_path)
            return zip_file_path
        return None

    def batch_compress_files(self, file_paths, zip_file_name):
        """Compress multiple files into a single ZIP file."""
        zip_file_path = f"{zip_file_name}.zip"
        with zipfile.ZipFile(zip_file_path, 'w') as zipf:
            for file_path in file_paths:
                if self.validate_file(file_path):
                    zipf.write(file_path, arcname=os.path.basename(file_path))
                    self.logger.info("Added to ZIP: %s", file_path)
        self.logger.info("Compressed files into: %s", zip_file_path)
        return zip_file_path

    def decompress_file(self, zip_file_path):
        """Decompress a ZIP file."""
        if os.path.isfile(zip_file_path) and zip_file_path.endswith('.zip'):
            with zipfile.ZipFile(zip_file_path, 'r') as zipf:
                zipf.extractall(os.path.dirname(zip_file_path))
            self.logger.info("File decompressed: %s", zip_file_path)
            return True
        self.logger.error("Invalid ZIP file: %s", zip_file_path)
        return False

    def get_file_metadata(self, file_path):
        """Retrieve metadata of a file."""
        if self.validate_file(file_path):
            metadata = {
                "size": os.path.getsize(file_path),
                "creation_time": datetime.fromtimestamp(os.path.getctime(file_path)),
                "modification_time": datetime.fromtimestamp(os.path.getmtime(file_path)),
            }
            self.logger.info("Metadata for %s: %s", file_path, metadata)
            return metadata
        return None

    def secure_delete(self, file_path):
        """Securely delete a file by overwriting it before deletion."""
        if self.validate_file(file_path):
            with open(file_path, "r+b") as f:
                length = os.path.getsize(file_path)
                f.write(os.urandom(length))  # Overwrite with random data
            os.remove(file_path)
            self.logger.info("Securely deleted file: %s", file_path)
        else:
            self.logger.error("File not found for secure deletion: %s", file_path)

    def encrypt_file(self, file_path):
        """Encrypt a file using symmetric encryption."""
        if self.validate_file(file_path):
            with open(file_path, 'rb') as f:
                file_data = f.read()
            encrypted_data = self.cipher.encrypt(file_data)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            self.logger.info("File encrypted: %s", file_path)
            return True
        return False

    def decrypt_file(self, file_path):
        """Decrypt a previously encrypted file."""
        if self.validate_file(file_path):
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.cipher.decrypt(encrypted_data)
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            self.logger.info("File decrypted: %s", file_path)
            return True
        return False

    def file_diff(self, file_path1, file_path2):
        """Compare two text files and return the differences."""
        if self.validate_file(file_path1) and self.validate_file(file_path2):
            with open(file_path1, 'r') as f1, open(file_path2, 'r') as f2:
                diff = list(unified_diff(
                    f1.readlines(),
                    f2.readlines(),
                    fromfile=file_path1,
                    tofile=file_path2,
                ))
            self.logger.info("Differences between %s and %s: %s", file_path1, file_path2, diff)
            return diff
        return None

# Sample Usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('FileOperationsExample')
    file_ops = FileOperations(logger)

    # Example file operations
    test_file = 'test_file.txt'
    backup = file_ops.backup_file(test_file)
    if backup:
        file_ops.restore_file(backup)

    # Create and delete a directory
    dir_name = 'test_directory'
    file_ops.create_directory(dir_name)
    file_ops.list_files_in_directory(dir_name)
    file_ops.delete_directory(dir_name)

    # Compress multiple files
    files_to_compress = ['test_file.txt', 'another_file.txt']
    file_ops.batch_compress_files(files_to_compress, 'compressed_files')

    # Encrypt and decrypt a file
    file_ops.encrypt_file(test_file)
    file_ops.decrypt_file(test_file)

    # Compare two files
    diff = file_ops.file_diff('file1.txt', 'file2.txt')
    if diff:
        print("Differences:", diff)

    # Get file metadata
    file_metadata = file_ops.get_file_metadata(test_file)

    # Secure delete a file
    file_ops.secure_delete(test_file)

