"""
Utility Module
This module contains utility functions and classes that are reused across the application.
"""

__version__ = '1.0.0'
__author__ = 'Bathina Harsha Vardhan'
__all__ = ['logger', 'file_operations']

import logging

# Configure logging for the utils module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.info("Utilities module initialized.")

def setup_logging(log_level=logging.INFO, log_file=None):
    """Sets up logging for the application."""
    logging.basicConfig(level=log_level, filename=log_file,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    logger.info("Logging setup complete.")
