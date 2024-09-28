"""
User Interface Module
This module manages the user interface components of the application.
"""

__version__ = '1.0.0'
__author__ = 'Bathina Harsha Vardhan'
__all__ = ['main_window', 'dialogs']

import logging

# Configure logging for the UI module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.info("User Interface module initialized.")
