import os
import json
import yaml
import logging
from jsonschema import validate, ValidationError

# Define a schema for configuration validation
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "data_directory": {"type": "string"},
        "output_directory": {"type": "string"},
        "analysis_mode": {"type": "string", "enum": ["static", "dynamic"]},
        "file_types": {"type": "array", "items": {"type": "string"}},
        "email_settings": {
            "type": "object",
            "properties": {
                "smtp_server": {"type": "string"},
                "smtp_port": {"type": "integer"},
                "email_address": {"type": "string"},
                "email_password": {"type": "string"},
            },
            "required": ["smtp_server", "smtp_port", "email_address", "email_password"],
        },
        "logging": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                "file": {"type": "string"},
            },
        },
    },
    "required": ["data_directory", "output_directory", "analysis_mode", "file_types", "email_settings"],
}

class Config:
    def __init__(self, config_files=['config.json']):
        self.config_files = config_files
        self.settings = {}
        self.load_config()

    def load_config(self):
        """Load configuration settings from JSON or YAML files."""
        for config_file in self.config_files:
            if not os.path.exists(config_file):
                logging.error(f"Configuration file '{config_file}' not found.")
                continue

            try:
                if config_file.endswith('.json'):
                    with open(config_file, 'r') as f:
                        new_settings = json.load(f)
                elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    with open(config_file, 'r') as f:
                        new_settings = yaml.safe_load(f)
                else:
                    logging.error("Unsupported configuration file format. Use JSON or YAML.")
                    continue
                
                # Merge new settings with existing settings
                self.merge_settings(new_settings)

            except Exception as e:
                logging.error(f"Error loading configuration from '{config_file}': {e}")
                raise e

        # Validate the final configuration
        self.validate_config()
        # Load sensitive data from environment variables
        self.load_sensitive_data_from_env()

    def merge_settings(self, new_settings):
        """Merge new settings into the existing settings."""
        self.settings = {**self.settings, **new_settings}

    def load_sensitive_data_from_env(self):
        """Load sensitive information from environment variables."""
        email_password = os.getenv('EMAIL_PASSWORD')
        if email_password:
            self.settings['email_settings']['email_password'] = email_password

    def validate_config(self):
        """Validate the loaded configuration settings against a schema."""
        try:
            validate(instance=self.settings, schema=CONFIG_SCHEMA)
        except ValidationError as e:
            logging.error(f"Configuration validation error: {e.message}")
            raise ValueError(f"Configuration validation error: {e.message}")

    def configure_logging(self):
        """Configure logging settings based on the configuration."""
        log_level = self.settings.get('logging', {}).get('level', 'INFO').upper()
        log_file = self.settings.get('logging', {}).get('file', None)

        logging.basicConfig(level=log_level, filename=log_file,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def reload_config(self):
        """Reload configuration settings from the files."""
        self.settings = {}
        self.load_config()

    def get_setting(self, key):
        """Get a specific configuration setting."""
        return self.settings.get(key)

    def get_data_directory(self):
        """Get the data directory."""
        return self.settings['data_directory']

    def get_output_directory(self):
        """Get the output directory."""
        return self.settings['output_directory']

    def get_analysis_mode(self):
        """Get the analysis mode."""
        return self.settings['analysis_mode']

    def get_file_types(self):
        """Get the list of file types for analysis."""
        return self.settings['file_types']

    def get_email_settings(self):
        """Get email settings for error reporting."""
        return self.settings['email_settings']

    def add_custom_setting(self, key, value):
        """Add a custom setting dynamically."""
        self.settings[key] = value

# Example usage
if __name__ == "__main__":
    try:
        config = Config(['config.json', 'config.yaml'])  # Multiple files can be specified
        config.configure_logging()
        print("Configuration loaded successfully.")
        print(f"Data Directory: {config.get_data_directory()}")
        print(f"Output Directory: {config.get_output_directory()}")
        print(f"Analysis Mode: {config.get_analysis_mode()}")
        print(f"File Types: {config.get_file_types()}")
        print(f"Email Settings: {config.get_email_settings()}")
        
        # Adding a custom setting
        config.add_custom_setting('custom_setting', 'This is a custom value')
        print(f"Custom Setting: {config.get_setting('custom_setting')}")

        # Reload configuration example
        # config.reload_config()  # Uncomment to reload settings at runtime

    except Exception as e:
        print(f"Failed to load configuration: {e}")
