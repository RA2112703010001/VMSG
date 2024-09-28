import unittest
import os

# Automatically discover and load tests from the tests directory
def load_tests(loader, tests, ignore):
    """Load tests from all test files in the tests directory."""
    test_dir = os.path.dirname(__file__)
    for filename in os.listdir(test_dir):
        if filename.startswith("test_") and filename.endswith(".py"):
            module_name = filename[:-3]  # Remove .py extension
            __import__(f'tests.{module_name}')  # Import the test module
    return tests

# Run all tests when this module is executed
if __name__ == "__main__":
    unittest.main()
