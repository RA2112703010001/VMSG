import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QAction, QToolBar,
                             QFileDialog, QMessageBox, QVBoxLayout, QWidget,
                             QLabel, QStatusBar, QComboBox, QLineEdit, QPushButton, QTextEdit)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from visualizer import Visualizer
import networkx as nx
import logging
import json

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Visual Malware Signature Generator")
        self.setGeometry(100, 100, 800, 600)

        self.visualizer = Visualizer()
        self.graph = nx.Graph()
        
        # Central widget and layout
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Graph type selection
        self.graph_type_selector = QComboBox(self)
        self.graph_type_selector.addItems(["Select Graph Type", "Bar Graph", "Line Graph", "Scatter Plot"])
        self.graph_type_selector.currentIndexChanged.connect(self.change_graph_type)
        self.layout.addWidget(self.graph_type_selector)

        # Layout selection
        self.layout_selector = QComboBox(self)
        self.layout_selector.addItems(["Select Layout", "Circular", "Hierarchical"])
        self.layout_selector.currentIndexChanged.connect(self.change_graph_layout)
        self.layout.addWidget(self.layout_selector)

        # Search functionality
        self.search_bar = QLineEdit(self)
        self.search_bar.setPlaceholderText("Search nodes...")
        self.search_bar.textChanged.connect(self.search_node)
        self.layout.addWidget(self.search_bar)

        # Node information display
        self.node_info_display = QTextEdit(self)
        self.node_info_display.setReadOnly(True)
        self.layout.addWidget(self.node_info_display)

        # Save/Load state buttons
        self.save_state_button = QPushButton("Save State", self)
        self.save_state_button.clicked.connect(self.save_state)
        self.layout.addWidget(self.save_state_button)

        self.load_state_button = QPushButton("Load State", self)
        self.load_state_button.clicked.connect(self.load_state)
        self.layout.addWidget(self.load_state_button)

        # Button to clear node selection
        self.clear_selection_button = QPushButton("Clear Selection", self)
        self.clear_selection_button.clicked.connect(self.clear_selection)
        self.layout.addWidget(self.clear_selection_button)

        # Add toolbar
        self.init_toolbar()
        
        # Label for instructions
        self.label = QLabel("Select a graph from the dropdown or load a new graph.")
        self.layout.addWidget(self.label)

        # Status indicator
        self.status_indicator = QLabel("Status: Ready")
        self.layout.addWidget(self.status_indicator)

        # Theme switch button
        self.theme_switch_button = QPushButton("Switch to Dark Theme", self)
        self.theme_switch_button.clicked.connect(self.switch_theme)
        self.layout.addWidget(self.theme_switch_button)

    def init_toolbar(self):
        """Initialize the toolbar with actions."""
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)

        # Load graph action
        load_action = QAction("Load Graph", self)
        load_action.triggered.connect(self.load_graph)
        toolbar.addAction(load_action)

        # Export graph action
        export_action = QAction("Export Graph", self)
        export_action.triggered.connect(self.export_graph)
        toolbar.addAction(export_action)

        # Export graph to image action
        export_image_action = QAction("Export to Image", self)
        export_image_action.triggered.connect(self.export_graph_to_image)
        toolbar.addAction(export_image_action)

        # Refresh graph action
        refresh_action = QAction("Refresh Graph", self)
        refresh_action.triggered.connect(self.refresh_graph)
        toolbar.addAction(refresh_action)

        # Undo action
        undo_action = QAction("Undo", self)
        undo_action.triggered.connect(self.undo_action)
        toolbar.addAction(undo_action)

        # Redo action
        redo_action = QAction("Redo", self)
        redo_action.triggered.connect(self.redo_action)
        toolbar.addAction(redo_action)

        # Help action
        help_action = QAction("Help", self)
        help_action.triggered.connect(self.show_help)
        toolbar.addAction(help_action)

        # Exit action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        toolbar.addAction(exit_action)

    def load_graph(self):
        """Load a graph from a file."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Graph File", "", "Graph Files (*.graph *.gml *.xml)")
        if file_name:
            try:
                self.graph = nx.read_gml(file_name)  # or appropriate format
                self.visualizer.set_graph(self.graph)
                self.update_graph_selector()
                self.status_bar.showMessage(f"Loaded graph from {file_name}")
                self.status_indicator.setText("Status: Graph Loaded")
                logger.info(f"Graph loaded from {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not load graph: {str(e)}")
                logger.error(f"Failed to load graph: {e}")

    def export_graph(self):
        """Export the current graph to a file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Graph File", "", "Graph Files (*.graph *.gml *.xml)")
        if file_name:
            try:
                nx.write_gml(self.graph, file_name)  # or appropriate format
                self.status_bar.showMessage(f"Exported graph to {file_name}")
                self.status_indicator.setText("Status: Graph Exported")
                logger.info(f"Graph exported to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not export graph: {str(e)}")
                logger.error(f"Failed to export graph: {e}")

    def export_graph_to_image(self):
        """Export the current graph visualization as an image."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Image File", "", "Image Files (*.png *.jpg *.bmp)")
        if file_name:
            try:
                self.visualizer.export_graph_image(file_name)  # Implement this method in your Visualizer class
                self.status_bar.showMessage(f"Graph image saved as {file_name}")
                self.status_indicator.setText("Status: Image Exported")
                logger.info(f"Graph image exported to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not export graph image: {str(e)}")
                logger.error(f"Failed to export graph image: {e}")

    def refresh_graph(self):
        """Refresh the graph visualization."""
        self.visualizer.visualize_graph("Malware Signature Patterns")
        self.status_bar.showMessage("Graph refreshed")
        self.status_indicator.setText("Status: Graph Refreshed")
        logger.info("Graph visualization refreshed.")

    def change_graph_type(self, index):
        """Change the type of graph displayed."""
        graph_type = self.graph_type_selector.currentText()
        if graph_type == "Bar Graph":
            self.visualizer.visualize_bar_graph(self.graph)
        elif graph_type == "Line Graph":
            self.visualizer.visualize_line_graph(self.graph)
        elif graph_type == "Scatter Plot":
            self.visualizer.visualize_scatter_plot(self.graph)
        else:
            self.status_bar.showMessage("Invalid graph type selected.")

    def change_graph_layout(self, index):
        """Change the layout of the graph visualization."""
        layout_type = self.layout_selector.currentText()
        if layout_type == "Circular":
            self.visualizer.set_graph_layout("circular")
        elif layout_type == "Hierarchical":
            self.visualizer.set_graph_layout("hierarchical")
        else:
            self.status_bar.showMessage("Invalid layout type selected.")
        self.refresh_graph()

    def search_node(self, text):
        """Search for a node in the graph."""
        if text:
            found_nodes = [node for node in self.graph.nodes if text.lower() in str(node).lower()]
            if found_nodes:
                self.node_info_display.setPlainText("\n".join(found_nodes))
            else:
                self.node_info_display.setPlainText("No nodes found.")
        else:
            self.node_info_display.clear()

    def clear_selection(self):
        """Clear the current node selection."""
        self.search_bar.clear()
        self.node_info_display.clear()
        self.status_bar.showMessage("Selection cleared.")
        self.status_indicator.setText("Status: Selection Cleared")

    def save_state(self):
        """Save the current application state to a file."""
        state = {
            "graph": self.graph,  # Consider serialization method
            "selected_nodes": list(self.node_info_display.toPlainText().splitlines())  # Example
        }
        file_name, _ = QFileDialog.getSaveFileName(self, "Save State", "", "JSON Files (*.json)")
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    json.dump(state, f)  # Serialize your graph properly
                self.status_bar.showMessage(f"State saved to {file_name}")
                self.status_indicator.setText("Status: State Saved")
                logger.info(f"Application state saved to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not save state: {str(e)}")
                logger.error(f"Failed to save state: {e}")

    def load_state(self):
        """Load the application state from a file."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Load State", "", "JSON Files (*.json)")
        if file_name:
            try:
                with open(file_name, 'r') as f:
                    state = json.load(f)
                    # Deserialize graph here, implement the proper loading mechanism
                    # self.graph = deserialize_graph(state["graph"])  # Placeholder
                    self.node_info_display.setPlainText("\n".join(state.get("selected_nodes", [])))
                self.status_bar.showMessage(f"State loaded from {file_name}")
                self.status_indicator.setText("Status: State Loaded")
                logger.info(f"Application state loaded from {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not load state: {str(e)}")
                logger.error(f"Failed to load state: {e}")

    def switch_theme(self):
        """Toggle between light and dark themes."""
        if self.theme_switch_button.text() == "Switch to Dark Theme":
            self.setStyleSheet("background-color: #2E2E2E; color: white;")
            self.theme_switch_button.setText("Switch to Light Theme")
        else:
            self.setStyleSheet("")
            self.theme_switch_button.setText("Switch to Dark Theme")
        self.status_indicator.setText("Status: Theme Switched")

    def undo_action(self):
        """Implement undo functionality (Placeholder for actual implementation)."""
        self.status_bar.showMessage("Undo action (not implemented yet).")
        logger.info("Undo action requested.")

    def redo_action(self):
        """Implement redo functionality (Placeholder for actual implementation)."""
        self.status_bar.showMessage("Redo action (not implemented yet).")
        logger.info("Redo action requested.")

    def show_help(self):
        """Show help dialog with instructions."""
        help_text = "This is the Visual Malware Signature Generator.\n\n"
        help_text += "1. Use the Load Graph option to load a malware signature graph.\n"
        help_text += "2. Select the type of graph and layout to visualize.\n"
        help_text += "3. Use the search bar to find specific nodes.\n"
        help_text += "4. Click on nodes to see their details.\n"
        help_text += "5. Use Undo/Redo for managing actions.\n"
        help_text += "6. Save/Load application state to resume later.\n"
        help_text += "7. Export graphs and images to save your work."
        QMessageBox.information(self, "Help", help_text)

    def update_graph_selector(self):
        """Update the dropdown selector for loaded graphs."""
        self.graph_type_selector.addItem("Loaded Graph")  # Update this as per actual graphs
        self.graph_type_selector.setCurrentIndex(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
