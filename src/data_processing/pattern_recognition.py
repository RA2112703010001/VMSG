import re
import logging
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class PatternRecognizer:
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.patterns = []
        self.pattern_weights = {}
        self.pattern_counts = defaultdict(int)
        self.cache = {}

    def add_patterns(self, patterns: List[str], weights: Optional[List[int]] = None) -> None:
        """Add patterns for recognition with optional weights."""
        if weights and len(weights) != len(patterns):
            logger.error("Weights length must match patterns length.")
            return
        
        self.patterns.extend(patterns)
        if weights:
            for pattern, weight in zip(patterns, weights):
                self.pattern_weights[pattern] = weight
        logger.info(f"Added {len(patterns)} patterns for recognition with weights.")

    def validate_patterns(self) -> List[str]:
        """Validate patterns to ensure they are well-formed."""
        valid_patterns = []
        for pattern in self.patterns:
            try:
                re.compile(pattern)
                valid_patterns.append(pattern)
            except re.error:
                logger.error(f"Invalid regex pattern: '{pattern}'")
        return valid_patterns

    def recognize_patterns_regex(self) -> Dict[str, int]:
        """Recognize patterns using regular expressions."""
        valid_patterns = self.validate_patterns()
        for pattern in valid_patterns:
            try:
                matches = re.findall(pattern, self.data.get("strings", ""))
                self.pattern_counts[pattern] += len(matches)
                logger.info(f"Pattern '{pattern}' matched {len(matches)} times.")
            except re.error as e:
                logger.error(f"Regex error for pattern '{pattern}': {e}")
        return dict(self.pattern_counts)

    def recognize_multiple_patterns(self) -> Dict[str, int]:
        """Recognize multiple patterns in a single pass for efficiency."""
        valid_patterns = self.validate_patterns()
        combined_pattern = "|".join(f"({p})" for p in valid_patterns)
        try:
            matches = re.findall(combined_pattern, self.data.get("strings", ""))
            for match in matches:
                for group in match:
                    if group:  # Only count non-empty matches
                        self.pattern_counts[group] += 1
            logger.info("Multiple patterns recognized in a single pass.")
        except re.error as e:
            logger.error(f"Regex error while recognizing multiple patterns: {e}")
        return dict(self.pattern_counts)

    def dynamic_thresholding(self) -> int:
        """Determine a dynamic threshold based on recognized patterns statistics."""
        if not self.pattern_counts:
            return 1  # Default threshold
        mean_count = sum(self.pattern_counts.values()) / len(self.pattern_counts)
        threshold = max(1, int(mean_count))  # Ensure threshold is at least 1
        logger.info(f"Dynamic threshold determined: {threshold}")
        return threshold

    def filter_low_frequency_patterns(self, threshold: Optional[int] = None) -> Dict[str, int]:
        """Filter out patterns that occur below a specified frequency threshold."""
        if threshold is None:
            threshold = self.dynamic_thresholding()  # Use dynamic threshold if not specified
        filtered_patterns = {pattern: count for pattern, count in self.pattern_counts.items() if count >= threshold}
        logger.info(f"Filtered patterns, keeping {len(filtered_patterns)} above threshold of {threshold}.")
        return filtered_patterns

    def gather_pattern_statistics(self) -> Dict[str, Any]:
        """Gather statistics on recognized patterns."""
        total_patterns = sum(self.pattern_counts.values())
        logger.info(f"Total recognized patterns: {total_patterns}")
        return {
            "total_patterns": total_patterns,
            "unique_patterns": len(self.pattern_counts),
            "pattern_counts": dict(self.pattern_counts)
        }

    def visualize_patterns(self) -> None:
        """Visualize recognized patterns (stub for visualization logic)."""
        logger.info("Pattern visualization is not yet implemented.")

    def cache_results(self) -> None:
        """Cache results of recognized patterns to avoid redundant computations."""
        self.cache = dict(self.pattern_counts)
        logger.info("Pattern recognition results cached.")

    def retrieve_cached_results(self) -> Optional[Dict[str, int]]:
        """Retrieve cached results if available."""
        if self.cache:
            logger.info("Retrieved cached pattern recognition results.")
            return self.cache
        else:
            logger.warning("No cached results found.")
            return None

    def fetch_external_patterns(self, source: str) -> List[str]:
        """Fetch patterns from external sources (stub for external fetching logic)."""
        logger.info(f"Fetching patterns from external source: {source}")
        # This should include logic to fetch patterns from an API or database
        return []  # Return empty list for now as a placeholder

    def process_patterns(self) -> None:
        """Process the patterns in the collected data."""
        logger.info("Starting pattern recognition process.")
        
        recognized_patterns = self.recognize_multiple_patterns()  # Use multiple patterns method
        logger.info(f"Recognized patterns: {recognized_patterns}")

        # Gather statistics
        stats = self.gather_pattern_statistics()
        logger.info(f"Pattern Statistics: {stats}")

        # Cache results
        self.cache_results()

        # Visualize patterns
        self.visualize_patterns()

if __name__ == "__main__":
    # Example usage
    sample_data = {
        "strings": "malicious_string_1 malicious_string_2 benign_string_1",
        "api_calls": ["CreateFileA", "ReadFile", "WriteFile"]
    }

    recognizer = PatternRecognizer(sample_data)
    recognizer.add_patterns([r"malicious_string_\d", r"benign_string_\d"], weights=[1, 0])
    recognizer.process_patterns()
    
    # Example of filtering low-frequency patterns
    filtered_patterns = recognizer.filter_low_frequency_patterns()
    logger.info(f"Filtered Patterns: {filtered_patterns}")
