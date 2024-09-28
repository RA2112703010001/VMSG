import os
import hashlib
import pefile
import json
import logging
import binascii
import math
import mimetypes
import pyclamd  # Import ClamAV library
from typing import List, Dict

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class StaticAnalyzer:
    def __init__(self, sample_path: str):
        self.sample_path = sample_path
        self.analysis_results = {
            "file_type": None,
            "file_hash": None,
            "metadata": {},
            "sections": [],
            "imports": [],
            "strings": [],
            "signature_matches": [],
            "entropy": {},
            "api_calls": [],
            "hex_dump": "",
            "ioc_logs": [],
            "binary_size": None,
            "checksum_validation": None,
            "clamav_matches": []
        }
        self.cd = None  # Initialize ClamAV connection

    def analyze(self) -> Dict:
        """Perform static analysis on the provided malware sample."""
        logger.info(f"Starting static analysis for {self.sample_path}")

        if not os.path.exists(self.sample_path):
            logger.error(f"File not found: {self.sample_path}")
            return self.analysis_results

        self.analysis_results["file_type"] = self.detect_file_type()
        self.analysis_results["file_hash"] = self.calculate_file_hash()
        self.extract_metadata()
        self.analyze_pe_file()
        self.analyze_strings()
        self.match_signatures()
        self.analyze_entropy()
        self.extract_api_calls()
        self.generate_hex_dump()
        self.log_indicators_of_compromise()
        self.analyze_binary_size()
        self.validate_checksum()
        self.match_clamav_rules()

        logger.info(f"Static analysis completed for {self.sample_path}")
        return self.analysis_results

    def detect_file_type(self) -> str:
        """Detect the file type of the sample using mimetypes."""
        mime_type, _ = mimetypes.guess_type(self.sample_path)
        logger.info(f"Detected MIME type: {mime_type}")
        return mime_type or "unknown"

    def calculate_file_hash(self) -> str:
        """Calculate the SHA-256 hash of the file."""
        hasher = hashlib.sha256()
        with open(self.sample_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        logger.info(f"Calculated file hash: {file_hash}")
        return file_hash

    def extract_metadata(self):
        """Extract metadata from the sample."""
        try:
            file_stats = os.stat(self.sample_path)
            self.analysis_results["metadata"] = {
                "size": file_stats.st_size,
                "creation_time": file_stats.st_ctime,
                "modification_time": file_stats.st_mtime,
                "access_time": file_stats.st_atime,
            }
            logger.info(f"Extracted metadata: {self.analysis_results['metadata']}")
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")

    def analyze_pe_file(self):
        """Analyze Portable Executable (PE) files."""
        try:
            pe = pefile.PE(self.sample_path)
            self.analysis_results["sections"] = [section.Name.decode().rstrip('\x00') for section in pe.sections]
            self.analysis_results["imports"] = [imp.name.decode() for imp in pe.DIRECTORY_ENTRY_IMPORT]

            logger.info(f"PE Sections: {self.analysis_results['sections']}")
            logger.info(f"PE Imports: {self.analysis_results['imports']}")
        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")

    def analyze_strings(self):
        """Extract and analyze strings from the binary."""
        try:
            with open(self.sample_path, 'rb') as f:
                data = f.read()
                strings = self.extract_strings(data)
                self.analysis_results["strings"] = strings
                logger.info(f"Extracted strings: {strings[:10]}...")  # Show only first 10 for brevity
        except Exception as e:
            logger.error(f"Error analyzing strings: {e}")

    def extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data."""
        strings = []
        current_string = []
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
        # Catch any remaining string
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))
        return strings

    def match_signatures(self):
        """Match the sample against known malware signatures."""
        # Example of a simple signature database (In real scenarios, load from a file or database)
        known_signatures = {
            "malware_signature_1": ["malicious_string_1", "malicious_string_2"],
            "malware_signature_2": ["malicious_string_3"],
        }

        for signature, patterns in known_signatures.items():
            if any(pattern in ' '.join(self.analysis_results["strings"]) for pattern in patterns):
                self.analysis_results["signature_matches"].append(signature)

        logger.info(f"Matched signatures: {self.analysis_results['signature_matches']}")

    def analyze_entropy(self):
        """Calculate entropy of the sections to identify packed/encrypted content."""
        try:
            pe = pefile.PE(self.sample_path)
            for section in pe.sections:
                section_data = section.get_data()
                entropy_value = self.calculate_entropy(section_data)
                self.analysis_results["entropy"][section.Name.decode().rstrip('\x00')] = entropy_value

            logger.info(f"Calculated entropy values: {self.analysis_results['entropy']}")
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate the Shannon entropy of given data."""
        if not data:
            return 0.0
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        entropy = 0.0
        length = len(data)
        for freq in frequency:
            if freq > 0:
                p_x = freq / length
                entropy -= p_x * math.log2(p_x)
        return entropy

    def extract_api_calls(self):
        """Placeholder for extracting API calls made by the malware."""
        logger.info("Extracting API calls (placeholder)")
        self.analysis_results["api_calls"] = ["CreateFileA", "WriteFile", "ExitProcess"]

    def generate_hex_dump(self):
        """Generate a hex dump of the malware sample."""
        try:
            with open(self.sample_path, 'rb') as f:
                data = f.read()
                hex_dump = binascii.hexlify(data).decode()
                self.analysis_results["hex_dump"] = hex_dump[:1000]  # Limit to first 1000 chars
            logger.info(f"Generated hex dump (truncated): {self.analysis_results['hex_dump']}")
        except Exception as e:
            logger.error(f"Error generating hex dump: {e}")

    def log_indicators_of_compromise(self):
        """Log indicators of compromise based on analysis results."""
        if self.analysis_results["signature_matches"]:
            for signature in self.analysis_results["signature_matches"]:
                self.analysis_results["ioc_logs"].append(f"Matched signature: {signature}")
        if self.analysis_results["strings"]:
            for s in self.analysis_results["strings"]:
                self.analysis_results["ioc_logs"].append(f"Found string: {s}")

        logger.info(f"Logged indicators of compromise: {self.analysis_results['ioc_logs']}")

    def analyze_binary_size(self):
        """Analyze the binary size for common malware patterns."""
        size = os.path.getsize(self.sample_path)
        self.analysis_results["binary_size"] = size
        logger.info(f"Binary size: {size} bytes")

        # Example logic for malware size patterns
        if size < 1024 * 10:  # Less than 10KB
            logger.warning("Binary size is suspiciously small.")
        elif size > 1024 * 10 * 10:  # Greater than 100KB
            logger.warning("Binary size is suspiciously large.")

    def validate_checksum(self):
        """Validate known checksums against the malware sample."""
        known_checksums = {
            "known_malware.exe": "example_sha256_hash",
        }

        if self.analysis_results["file_hash"] in known_checksums.values():
            self.analysis_results["checksum_validation"] = "Malware known to exist."
            logger.info("Checksum validation: Malware known to exist.")
        else:
            self.analysis_results["checksum_validation"] = "No known malware match."
            logger.info("Checksum validation: No known malware match.")

    def match_clamav_rules(self):
        """Match the sample against ClamAV."""
        try:
            self.cd = pyclamd.ClamdUnixSocket()  # Initialize the ClamAV connection

            # Check if ClamAV is running
            if self.cd.ping():
                logger.info("ClamAV is running.")
            else:
                logger.error("ClamAV is not running. Cannot perform scan.")
                return

            # Scan the file
            scan_result = self.cd.scan_file(self.sample_path)
            if scan_result:
                self.analysis_results["clamav_matches"] = [result[0] for result in scan_result.values()]
                logger.info(f"ClamAV matches: {self.analysis_results['clamav_matches']}")
            else:
                logger.info("No ClamAV matches found.")

        except Exception as e:
            logger.error(f"Error matching ClamAV rules: {e}")

if __name__ == "__main__":
    # Dynamically get the sample path from user input
    sample_path = input("Enter the path to the malware sample (e.g., path_to_your_sample.exe): ").strip()
    analyzer = StaticAnalyzer(sample_path)
    results = analyzer.analyze()

    # Optionally save results to a JSON file
    with open('analysis_results.json', 'w') as f:
        json.dump(results, f, indent=4)
    logger.info("Analysis results saved to analysis_results.json")
