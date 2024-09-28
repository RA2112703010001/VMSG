import logging
import os
import sys
import json
import time
import shutil
import threading
from tqdm import tqdm
import smtplib
from email.mime.text import MIMEText
from data_collection.dynamic_analysis import DynamicAnalyzer
from data_collection.static_analysis import StaticAnalyzer
from data_processing.data_parser import DataParser
from data_processing.pattern_recognition import PatternRecognizer
from visualization.graph_builder import GraphBuilder
from visualization.visualizer import Visualizer
from ui.main_window import MainWindow

# Configure logging
def configure_logging(log_level):
    logging.basicConfig(
        filename='app.log',
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def load_config(config_path):
    """Load configuration settings from a JSON file."""
    with open(config_path, 'r') as f:
        return json.load(f)

def send_error_report(email_address, error_message):
    """Send an error report to the specified email address."""
    msg = MIMEText(error_message)
    msg['Subject'] = 'Visual Malware Signature Generator - Error Report'
    msg['From'] = 'your_email@example.com'  # Replace with your sender email
    msg['To'] = email_address

    try:
        with smtplib.SMTP('smtp.example.com', 587) as server:  # Replace with your SMTP server and port
            server.starttls()
            server.login('your_email@example.com', 'your_password')  # Replace with your login credentials
            server.send_message(msg)
        logging.info("Error report sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send error report: {e}")

def collect_user_feedback():
    """Collect user feedback after processing."""
    feedback = input("Please provide your feedback about the tool (type 'exit' to skip): ")
    if feedback.lower() != 'exit':
        with open('feedback.txt', 'a') as f:
            f.write(feedback + '\n')
        logging.info("User feedback collected.")

def backup_results(output_dir):
    """Backup the analysis results."""
    backup_dir = f"{output_dir}_backup_{int(time.time())}"
    shutil.copytree(output_dir, backup_dir)
    logging.info(f"Backup created at: {backup_dir}")

def generate_summary_report(patterns, output_dir):
    """Generate a summary report after analysis."""
    report_path = os.path.join(output_dir, 'summary_report.txt')
    with open(report_path, 'w') as report_file:
        report_file.write("Summary Report of Malware Analysis\n")
        report_file.write("=" * 40 + "\n")
        report_file.write(f"Total Patterns Found: {len(patterns)}\n")
        report_file.write("Patterns:\n")
        for pattern in patterns:
            report_file.write(f"- {pattern}\n")
    logging.info(f"Summary report generated at: {report_path}")

def run_analysis(analyzer):
    """Run data collection and processing in a separate thread."""
    logging.info("Collecting data...")
    samples_data = analyzer.analyze()
    logging.info("Data collection complete.")
    
    logging.info("Processing data...")
    parser = DataParser(samples_data)
    processed_data = parser.parse()
    recognizer = PatternRecognizer(processed_data)
    patterns = recognizer.recognize_patterns()
    logging.info("Data processing complete.")
    
    return patterns

def run_visualization(graph, output_dir, output_format):
    """Run the visualization process in a separate thread."""
    visualizer = Visualizer(graph)
    visualizer.visualize(output_dir, output_format)

def start_analysis(samples, analysis_mode, output_dir, config, console_output, email_errors):
    # Initialize analyzers based on the selected mode
    if analysis_mode == 'static':
        analyzer = StaticAnalyzer(samples)
    elif analysis_mode == 'dynamic':
        analyzer = DynamicAnalyzer(samples)
    else:
        logging.error("Invalid analysis mode selected.")
        print("Invalid analysis mode selected.")
        if email_errors:
            send_error_report(email_errors, "Invalid analysis mode selected.")
        sys.exit(1)

    # Run analysis in a separate thread
    analysis_thread = threading.Thread(target=run_analysis, args=(analyzer,))
    analysis_thread.start()
    
    # Display progress bar while waiting for analysis to complete
    with tqdm(total=100, desc="Analysis Progress", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        while analysis_thread.is_alive():
            pbar.update(10)  # Update progress every 10 seconds
            time.sleep(10)   # Adjust this value based on expected time
    
    analysis_thread.join()  # Wait for analysis to complete
    
    # Retrieve patterns (assuming this is how the result is stored)
    patterns = analysis_thread.result()  # You might need to adjust this depending on your threading implementation
    
    # Visualize data
    try:
        logging.info("Visualizing data...")
        graph_builder = GraphBuilder(patterns)
        graph = graph_builder.build_graph()

        # Run visualization in a separate thread
        output_format = config.get('output_format', 'png')
        visualization_thread = threading.Thread(target=run_visualization, args=(graph, output_dir, output_format))
        visualization_thread.start()

        # Display progress for visualization
        with tqdm(total=100, desc="Visualization Progress", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as vbar:
            while visualization_thread.is_alive():
                vbar.update(10)  # Update progress every 10 seconds
                time.sleep(10)   # Adjust this value based on expected time

        visualization_thread.join()  # Wait for visualization to complete
        logging.info("Data visualization complete.")

        # Output to console if requested
        if console_output:
            print("Visualization completed. Check output directory for results.")
    except Exception as e:
        logging.error(f"Error during data visualization: {e}")
        print(f"Error during data visualization: {e}")
        if email_errors:
            send_error_report(email_errors, str(e))
        sys.exit(1)

    # Backup the results
    backup_results(output_dir)

    # Generate summary report
    generate_summary_report(patterns, output_dir)

def main():
    # Configure logging
    log_level = logging.INFO
    configure_logging(log_level)

    # Load configuration settings
    try:
        config = load_config('config.json')  # Hardcoded path since command line args are not used
    except Exception as e:
        logging.error(f"Error loading configuration file: {e}")
        print(f"Error loading configuration file: {e}")
        sys.exit(1)

    # Create output directory if it does not exist
    output_dir = 'output/'  # Hardcoded output directory
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    logging.info("Starting Visual Malware Signature Generator")

    # Prompt user for the path of the malware samples
    samples_input = input("Enter the path of the malware samples to analyze (comma-separated if multiple): ")
    samples = [s.strip() for s in samples_input.split(',')]

    # Prompt user for analysis mode
    analysis_mode = input("Select analysis mode (static/dynamic): ").strip().lower()
    
    # Ask for console output option
    console_output = input("Do you want to see console output? (yes/no): ").strip().lower() == 'yes'

    # Ask for email errors option
    email_errors = input("Enter email address for error reports (leave empty for none): ").strip() or None

    # Start analysis
    start_analysis(samples, analysis_mode, output_dir, config, console_output, email_errors)

    # Launch GUI
    try:
        logging.info("Launching user interface...")
        app = MainWindow(output_dir)
        app.run()  # This should start the GUI main loop
    except Exception as e:
        logging.error(f"Error launching GUI: {e}")
        print(f"Error launching GUI: {e}")
        if email_errors:
            send_error_report(email_errors, str(e))
        sys.exit(1)

    # Collect user feedback
    collect_user_feedback()

    logging.info("Visual Malware Signature Generator finished successfully.")

if __name__ == "__main__":
    main()
