import json
import csv
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class DataParser:
    def __init__(self, data: Dict[str, Any]):
        self.data = data

    def parse_json(self, json_data: str) -> Dict:
        """Parse JSON data into a dictionary."""
        try:
            parsed_data = json.loads(json_data)
            logger.info("Successfully parsed JSON data.")
            return parsed_data
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON data: {e}")
            return {}

    def parse_xml(self, xml_data: str) -> Dict:
        """Parse XML data into a dictionary."""
        try:
            root = ET.fromstring(xml_data)
            parsed_data = {child.tag: child.text for child in root}
            logger.info("Successfully parsed XML data.")
            return parsed_data
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML data: {e}")
            return {}

    def parse_txt(self, txt_data: str) -> Dict:
        """Parse TXT data into a dictionary (key-value pairs)."""
        try:
            parsed_data = {}
            for line in txt_data.splitlines():
                key, value = line.split(':', 1)
                parsed_data[key.strip()] = value.strip()
            logger.info("Successfully parsed TXT data.")
            return parsed_data
        except Exception as e:
            logger.error(f"Failed to parse TXT data: {e}")
            return {}

    def export_to_csv(self, filename: str) -> None:
        """Export data to a CSV file."""
        try:
            with open(filename, mode='w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(self.data.keys())  # Write header
                writer.writerow(self.data.values())  # Write data
            logger.info(f"Data successfully exported to {filename}.")
        except Exception as e:
            logger.error(f"Error exporting data to CSV: {e}")

    def export_to_json(self, filename: str) -> None:
        """Export data to a JSON file."""
        try:
            with open(filename, mode='w') as jsonfile:
                json.dump(self.data, jsonfile, indent=4)
            logger.info(f"Data successfully exported to {filename}.")
        except Exception as e:
            logger.error(f"Error exporting data to JSON: {e}")

    def validate_data(self) -> bool:
        """Validate the integrity of the collected data."""
        if not isinstance(self.data, dict):
            logger.error("Data is not in dictionary format.")
            return False
        
        # Add specific validation checks as needed
        if "file_hash" not in self.data or "strings" not in self.data:
            logger.error("Missing required fields in data.")
            return False
        
        logger.info("Data validation successful.")
        return True

    def normalize_api_calls(self) -> List[str]:
        """Normalize API calls for consistent representation."""
        normalized_calls = [call.lower() for call in self.data.get("api_calls", [])]
        logger.info("API calls normalized.")
        return normalized_calls

    def aggregate_api_calls(self) -> Dict[str, int]:
        """Aggregate API calls and count their frequencies."""
        api_calls = self.normalize_api_calls()
        aggregated_data = {}
        
        for call in api_calls:
            if call in aggregated_data:
                aggregated_data[call] += 1
            else:
                aggregated_data[call] = 1
        
        logger.info("API call aggregation complete.")
        return aggregated_data

    def enrich_data(self) -> None:
        """Enrich data by looking up additional information (stub for database/API call)."""
        # This is a stub; in a real implementation, you would query a database or external service.
        self.data["enrichment"] = "Enriched data based on file_hash"
        logger.info("Data enrichment completed.")

    def generate_summary_report(self) -> str:
        """Generate a summary report after processing data."""
        summary = f"File Hash: {self.data.get('file_hash')}\n"
        summary += f"File Type: {self.data.get('file_type')}\n"
        summary += f"Strings Found: {len(self.data.get('strings', []))}\n"
        api_calls_count = self.aggregate_api_calls()
        summary += f"API Calls: {len(api_calls_count)}\n"
        summary += f"Aggregated API Calls: {api_calls_count}\n"
        logger.info("Summary report generated.")
        return summary

    def process_analysis_results(self) -> None:
        """Process the analysis results to extract relevant information."""
        if not self.validate_data():
            logger.error("Data validation failed. Processing aborted.")
            return
        
        logger.info("Processing analysis results.")
        self.enrich_data()
        api_call_counts = self.aggregate_api_calls()
        logger.info(f"API Call Counts: {api_call_counts}")

        # Generate and log summary report
        report = self.generate_summary_report()
        logger.info(f"Summary Report:\n{report}")

    def batch_process_data(self, data_list: List[Dict[str, Any]]) -> None:
        """Process a list of analysis results."""
        error_summary = []
        total_entries = len(data_list)
        for idx, data in enumerate(data_list):
            logger.info(f"Processing data entry {idx + 1}/{total_entries}")
            self.data = data
            try:
                self.process_analysis_results()
            except Exception as e:
                error_summary.append(f"Error processing data entry {idx + 1}: {str(e)}")
        
        if error_summary:
            logger.error("Batch processing completed with errors:")
            for error in error_summary:
                logger.error(error)
        else:
            logger.info("Batch processing completed successfully.")

if __name__ == "__main__":
    # Example usage
    sample_data = {
        "file_hash": "example_hash",
        "file_type": "exe",
        "strings": ["malicious_string_1", "malicious_string_2"],
        "api_calls": ["CreateFileA", "WriteFile", "CreateFileA"]
    }
    
    parser = DataParser(sample_data)
    
    # Process and export data
    parser.process_analysis_results()
    parser.export_to_csv("analysis_results.csv")
    parser.export_to_json("analysis_results.json")
    
    # Example of batch processing
    batch_data = [
        {
            "file_hash": "hash_1",
            "file_type": "exe",
            "strings": ["string_1", "string_2"],
            "api_calls": ["ReadFile", "WriteFile"]
        },
        {
            "file_hash": "hash_2",
            "file_type": "dll",
            "strings": ["string_3", "string_4"],
            "api_calls": ["LoadLibraryA", "GetProcAddress"]
        }
    ]
    
    parser.batch_process_data(batch_data)
