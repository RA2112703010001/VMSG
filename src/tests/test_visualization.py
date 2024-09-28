import unittest
from unittest.mock import patch, MagicMock
from src.visualization.graph_builder import GraphBuilder
from src.visualization.visualizer import Visualizer
import time
import networkx as nx

class TestVisualization(unittest.TestCase):

    def setUp(self):
        """Set up necessary objects for testing the visualization components."""
        self.graph_builder = GraphBuilder()
        self.visualizer = Visualizer()

    def tearDown(self):
        """Clean up after each test."""
        del self.graph_builder
        del self.visualizer

    @patch('src.visualization.graph_builder.nx')
    def test_build_graph(self, mock_networkx):
        """Test the graph building functionality."""
        mock_graph = MagicMock()
        mock_networkx.Graph.return_value = mock_graph

        pattern_counts = {'node1': 5, 'node2': 3, 'node3': 2}
        self.graph_builder.build_graph(pattern_counts)

        mock_networkx.Graph.assert_called_once()
        mock_graph.add_node.assert_any_call('node1', count=5, x=0, y=0)
        mock_graph.add_node.assert_any_call('node2', count=3, x=0, y=0)
        mock_graph.add_node.assert_any_call('node3', count=2, x=0, y=0)
        mock_graph.add_edge.assert_any_call('node1', 'node2')
        mock_graph.add_edge.assert_any_call('node2', 'node3')

    def test_build_empty_graph(self):
        """Test graph builder with empty pattern counts."""
        graph = self.graph_builder.build_graph({})
        self.assertIsNotNone(graph)
        self.assertEqual(len(graph.nodes), 0)
        self.assertEqual(len(graph.edges), 0)

    def test_render_large_dynamic_graph(self):
        """Test rendering large dynamic graph (graph that grows over time)."""
        pattern_counts = {f"node_{i}": i for i in range(500)}
        self.graph_builder.build_graph(pattern_counts)

        start_time = time.time()
        with patch('matplotlib.pyplot.savefig') as mock_savefig:
            self.visualizer.render_graph(self.graph_builder.graph, show=False, filename='dynamic_large_graph.png')
            mock_savefig.assert_called_once_with('dynamic_large_graph.png')
        elapsed_time = time.time() - start_time

        self.assertLess(elapsed_time, 5)

    @patch('matplotlib.pyplot')
    def test_interactive_graph(self, mock_plt):
        """Test rendering an interactive graph (with zoom and pan)."""
        pattern_counts = {'A': 1, 'B': 1, 'C': 1}
        self.graph_builder.build_graph(pattern_counts)

        with patch('matplotlib.pyplot.Figure') as mock_figure:
            mock_figure.canvas.mpl_connect.return_value = None  # Mock user interaction events

            self.visualizer.render_graph(self.graph_builder.graph, interactive=True, show=False)

            # Verify that interactivity events are enabled
            mock_figure.canvas.mpl_connect.assert_any_call('scroll_event', unittest.mock.ANY)
            mock_figure.canvas.mpl_connect.assert_any_call('button_press_event', unittest.mock.ANY)
            mock_plt.show.assert_not_called()

    def test_multi_graph_rendering(self):
        """Test rendering multiple graphs simultaneously."""
        pattern_counts1 = {'A': 1, 'B': 1}
        pattern_counts2 = {'X': 1, 'Y': 1}
        self.graph_builder.build_graph(pattern_counts1)
        graph1 = self.graph_builder.graph.copy()  # Copy to preserve state

        self.graph_builder.build_graph(pattern_counts2)
        graph2 = self.graph_builder.graph.copy()  # Copy to preserve state

        with patch('matplotlib.pyplot.savefig') as mock_savefig:
            self.visualizer.render_graph(graph1, filename="graph1_output.png", show=False)
            self.visualizer.render_graph(graph2, filename="graph2_output.png", show=False)

            # Ensure both graphs are rendered without interference
            self.assertEqual(mock_savefig.call_count, 2)
            mock_savefig.assert_any_call("graph1_output.png")
            mock_savefig.assert_any_call("graph2_output.png")

    def test_color_coded_severity(self):
        """Test rendering a graph with color-coded nodes based on malware severity."""
        nodes = [
            ('malware_critical', {'severity': 'critical'}),
            ('malware_high', {'severity': 'high'}),
            ('malware_medium', {'severity': 'medium'}),
            ('malware_low', {'severity': 'low'})
        ]
        edges = [('malware_critical', 'malware_high'), ('malware_high', 'malware_medium')]

        graph = nx.Graph()
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)

        severity_colors = {
            'critical': 'red',
            'high': 'orange',
            'medium': 'yellow',
            'low': 'green'
        }

        with patch('matplotlib.pyplot.savefig') as mock_savefig:
            self.visualizer.render_graph(graph, severity_colors=severity_colors, show=False, filename="severity_graph.png")
            mock_savefig.assert_called_once_with("severity_graph.png")

    def test_render_graph_performance(self):
        """Test the performance of the graph rendering process."""
        pattern_counts = {f"node{i}": i for i in range(1000)}
        self.graph_builder.build_graph(pattern_counts)

        start_time = time.time()
        self.visualizer.render_graph(self.graph_builder.graph, show=False)
        elapsed_time = time.time() - start_time

        self.assertLess(elapsed_time, 2)

    def test_graph_export_as_svg(self):
        """Test exporting graph visualization as SVG."""
        pattern_counts = {'A': 1, 'B': 1}
        self.graph_builder.build_graph(pattern_counts)
        
        with patch('matplotlib.pyplot.savefig') as mock_savefig:
            self.visualizer.render_graph(self.graph_builder.graph, filename="output_graph.svg", show=False)
            mock_savefig.assert_called_once_with("output_graph.svg")

    def test_logging_during_rendering(self):
        """Test logging during the graph rendering process."""
        pattern_counts = {'A': 1, 'B': 1}
        self.graph_builder.build_graph(pattern_counts)

        with patch('src.utils.logger.Logger.log_event') as mock_log_event:
            self.visualizer.render_graph(self.graph_builder.graph, show=False)
            mock_log_event.assert_called_with("Graph rendered and saved to graph_output.png")

    def test_empty_graph_rendering(self):
        """Test rendering an empty graph."""
        empty_graph = self.graph_builder.build_graph({})
        with self.assertRaises(ValueError):
            self.visualizer.render_graph(empty_graph, show=False)

if __name__ == '__main__':
    unittest.main()
