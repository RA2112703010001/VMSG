from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QMessageBox,
    QFormLayout,
    QProgressDialog,
    QCheckBox,
    QComboBox,
    QSpinBox,
    QTextEdit,
    QFileDialog,
)
import sys

class InfoDialog(QDialog):
    """Dialog to display information about the application."""
    def __init__(self, parent=None):
        super(InfoDialog, self).__init__(parent)
        self.setWindowTitle("Information")
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()
        info_label = QLabel("Visual Malware Signature Generator\n\n"
                            "This application allows users to analyze malware signatures "
                            "using various visualization techniques and export results.")
        layout.addWidget(info_label)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button)

        self.setLayout(layout)


class ConfirmationDialog(QDialog):
    """Dialog to confirm user actions."""
    def __init__(self, message, parent=None):
        super(ConfirmationDialog, self).__init__(parent)
        self.setWindowTitle("Confirm Action")
        self.setGeometry(100, 100, 300, 150)

        layout = QVBoxLayout()
        confirmation_label = QLabel(message)
        layout.addWidget(confirmation_label)

        button_layout = QVBoxLayout()
        yes_button = QPushButton("Yes")
        yes_button.clicked.connect(self.accept)
        button_layout.addWidget(yes_button)

        no_button = QPushButton("No")
        no_button.clicked.connect(self.reject)
        button_layout.addWidget(no_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)


class InputDialog(QDialog):
    """Dialog to prompt for user input."""
    def __init__(self, label_text, parent=None):
        super(InputDialog, self).__init__(parent)
        self.setWindowTitle("Input Required")
        self.setGeometry(100, 100, 300, 150)

        layout = QFormLayout()
        self.input_line_edit = QLineEdit()
        layout.addRow(label_text, self.input_line_edit)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button)

        self.setLayout(layout)

    def get_input(self):
        """Return the input text from the dialog."""
        return self.input_line_edit.text()


class ErrorDialog(QMessageBox):
    """Custom dialog to show error messages."""
    def __init__(self, title, message, parent=None):
        super(ErrorDialog, self).__init__(parent)
        self.setWindowTitle(title)
        self.setText(message)
        self.setIcon(QMessageBox.Critical)
        self.setStandardButtons(QMessageBox.Ok)
        self.setButtonText(QMessageBox.Ok, "Close")


class ProgressDialog(QProgressDialog):
    """Dialog to show progress of an ongoing operation."""
    def __init__(self, parent=None):
        super(ProgressDialog, self).__init__("Processing...", "Cancel", 0, 100, parent)
        self.setWindowTitle("Progress")
        self.setModal(True)
        self.setValue(0)

    def update_progress(self, value):
        """Update the progress dialog with the current value."""
        self.setValue(value)
        if value >= 100:
            self.close()


class SettingsDialog(QDialog):
    """Dialog for application settings."""
    def __init__(self, parent=None):
        super(SettingsDialog, self).__init__(parent)
        self.setWindowTitle("Settings")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        self.path_check_box = QCheckBox("Use custom paths")
        self.path_check_box.setChecked(False)
        layout.addWidget(self.path_check_box)

        self.default_path_input = QLineEdit()
        layout.addWidget(QLabel("Default File Path:"))
        layout.addWidget(self.default_path_input)

        self.analysis_combo = QComboBox()
        self.analysis_combo.addItems(["Quick Analysis", "Deep Analysis"])
        layout.addWidget(QLabel("Default Analysis Type:"))
        layout.addWidget(self.analysis_combo)

        self.spin_box = QSpinBox()
        self.spin_box.setMinimum(1)
        self.spin_box.setMaximum(100)
        layout.addWidget(QLabel("Max Concurrent Threads:"))
        layout.addWidget(self.spin_box)

        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.accept)
        layout.addWidget(save_button)

        self.setLayout(layout)


class HelpDialog(QDialog):
    """Dialog to display help information."""
    def __init__(self, parent=None):
        super(HelpDialog, self).__init__(parent)
        self.setWindowTitle("Help")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()
        help_text = QLabel("Help Instructions:\n\n"
                           "1. Load malware samples to analyze.\n"
                           "2. Choose analysis type from settings.\n"
                           "3. Visualize the analysis results.\n"
                           "4. Use the export feature to save results.\n"
                           "5. For further assistance, contact support.")
        layout.addWidget(help_text)

        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

        self.setLayout(layout)


class FeedbackDialog(QDialog):
    """Dialog to allow users to provide feedback."""
    def __init__(self, parent=None):
        super(FeedbackDialog, self).__init__(parent)
        self.setWindowTitle("Feedback")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()
        self.feedback_text_edit = QTextEdit()
        self.feedback_text_edit.setPlaceholderText("Enter your feedback or report a bug here...")
        layout.addWidget(self.feedback_text_edit)

        submit_button = QPushButton("Submit Feedback")
        submit_button.clicked.connect(self.submit_feedback)
        layout.addWidget(submit_button)

        self.setLayout(layout)

    def submit_feedback(self):
        """Handle feedback submission."""
        feedback = self.feedback_text_edit.toPlainText()
        if feedback:
            # Here, you could implement code to send feedback to a server or save it to a file.
            print("Feedback submitted:", feedback)  # For demonstration purposes
            self.accept()
        else:
            ErrorDialog("Error", "Feedback cannot be empty.").exec_()


class ThemeDialog(QDialog):
    """Dialog to customize application theme."""
    def __init__(self, parent=None):
        super(ThemeDialog, self).__init__(parent)
        self.setWindowTitle("Customize Theme")
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light Mode", "Dark Mode"])
        layout.addWidget(QLabel("Select Theme:"))
        layout.addWidget(self.theme_combo)

        save_button = QPushButton("Apply Theme")
        save_button.clicked.connect(self.apply_theme)
        layout.addWidget(save_button)

        self.setLayout(layout)

    def apply_theme(self):
        """Apply the selected theme."""
        theme = self.theme_combo.currentText()
        print(f"Theme applied: {theme}")  # For demonstration purposes
        self.accept()


class MultiFileInputDialog(QDialog):
    """Dialog to select multiple files for analysis."""
    def __init__(self, parent=None):
        super(MultiFileInputDialog, self).__init__(parent)
        self.setWindowTitle("Select Files for Analysis")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()
        self.file_list = QTextEdit()
        self.file_list.setReadOnly(True)
        layout.addWidget(self.file_list)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_files)
        layout.addWidget(browse_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button)

        self.setLayout(layout)

    def browse_files(self):
        """Open a file dialog to select multiple files."""
        files, _ = QFileDialog.getOpenFileNames(self, "Select Malware Files", "", "All Files (*.*)")
        if files:
            self.file_list.setPlainText("\n".join(files))

    def get_selected_files(self):
        """Return the list of selected files."""
        return self.file_list.toPlainText().splitlines()


# Sample Usage
if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Example of using FeedbackDialog
    feedback_dialog = FeedbackDialog()
    feedback_dialog.exec_()

    # Example of using ThemeDialog
    theme_dialog = ThemeDialog()
    theme_dialog.exec_()

    # Example of using MultiFileInputDialog
    multi_file_dialog = MultiFileInputDialog()
    if multi_file_dialog.exec_() == QDialog.Accepted:
        selected_files = multi_file_dialog.get_selected_files()
        print(f"Files selected for analysis: {selected_files}")

    sys.exit(app.exec_())
