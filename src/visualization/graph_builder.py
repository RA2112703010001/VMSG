import pandas as pd
import plotly.graph_objects as go
import networkx as nx
import logging
import os
from typing import Dict, List

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class GraphBuilder:
    def __init__(self):
        self.graph = nx.Graph()

    def build_graph(self, pattern_counts: Dict[str, int], title: str = "Pattern Frequency Graph") -> None:
        """Build a graph from pattern counts."""
        logger.info("Building graph from pattern counts.")

        # Adding nodes with default coordinates (0,0) if not specified
        for pattern, count in pattern_counts.items():
            self.graph.add_node(pattern, count=count, x=0, y=0)  # Assign default x and y
            logger.debug(f"Added node: {pattern} with count: {count}")

        # Connect nodes based on counts (for example purposes, simply connect adjacent)
        patterns = list(pattern_counts.keys())
        for i in range(len(patterns) - 1):
            self.graph.add_edge(patterns[i], patterns[i + 1])

        self.plot_graph(title)

    def plot_graph(self, title: str) -> None:
        """Plot the built graph using NetworkX and Plotly."""
        logger.info("Plotting the graph.")
        edge_x = []
        edge_y = []

        # Iterate through edges and construct edge coordinates
        for edge in self.graph.edges():
            # Safely get x and y, using default values if not present
            x0 = self.graph.nodes[edge[0]].get('x', 0)
            y0 = self.graph.nodes[edge[0]].get('y', 0)
            x1 = self.graph.nodes[edge[1]].get('x', 0)
            y1 = self.graph.nodes[edge[1]].get('y', 0)

            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        node_x = []
        node_y = []
        node_text = []

        # Prepare node data for plotting
        for node in self.graph.nodes():
            x = self.graph.nodes[node].get('x', 0)  # Default to 0 if missing
            y = self.graph.nodes[node].get('y', 0)  # Default to 0 if missing
            node_x.append(x)
            node_y.append(y)
            node_text.append(f"{node}: {self.graph.nodes[node]['count']}")

        # Create Plotly figure
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='black'), hoverinfo='none', mode='lines'))
        fig.add_trace(go.Scatter(x=node_x, y=node_y, mode='markers+text', text=node_text, textposition="top center",
                                 marker=dict(showscale=True, colorscale='YlGnBu', size=10, color=node_y,
                                             colorbar=dict(thickness=15, title='Node Count', xanchor='left', titleside='right'))))

        fig.update_layout(title=title, showlegend=False, hovermode='closest', margin=dict(l=0, r=0, t=40, b=0))
        fig.show()

    def export_graph(self, filename: str, format: str = 'png') -> None:
        """Export the current graph to a file in specified format."""
        logger.info(f"Exporting graph to {filename}.{format}")
        # Save the graph using NetworkX
        if format not in ['png', 'svg', 'pdf', 'html']:
            logger.error("Unsupported format. Please use 'png', 'svg', 'pdf', or 'html'.")
            return

        # Here you could add actual saving code for different formats
        try:
            import matplotlib.pyplot as plt  # Make sure matplotlib is imported for exporting
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(self.graph)
            nx.draw(self.graph, pos, with_labels=True, node_color='skyblue', node_size=2000, font_size=15)
            plt.title("Exported Pattern Frequency Graph")
            plt.axis('off')
            plt.savefig(f"{filename}.{format}", format=format)
            plt.close()
            logger.info(f"Graph exported successfully to {filename}.{format}")
        except Exception as e:
            logger.error(f"Error exporting graph: {e}")

    def dynamic_legend(self, pattern_counts: Dict[str, int]) -> None:
        """Create a dynamic legend showing counts of each pattern."""
        logger.info("Generating dynamic legend.")
        legend_data = "\n".join([f"{pattern}: {count}" for pattern, count in pattern_counts.items()])
        print("Legend:\n", legend_data)  # Replace with actual UI implementation if needed

    def filter_nodes_by_range(self, min_count: int, max_count: int) -> List[str]:
        """Filter nodes based on a count range."""
        logger.info(f"Filtering nodes with count between {min_count} and {max_count}.")
        filtered_nodes = [node for node in self.graph.nodes if min_count <= self.graph.nodes[node]['count'] <= max_count]
        logger.info(f"Filtered nodes: {filtered_nodes}")
        return filtered_nodes

    def load_data_from_csv(self, filepath: str) -> Dict[str, int]:
        """Load pattern counts from a CSV file."""
        logger.info(f"Loading pattern counts from {filepath}.")
        if not os.path.exists(filepath):
            logger.error("File does not exist.")
            return {}

        try:
            df = pd.read_csv(filepath)
            if 'pattern' not in df.columns or 'count' not in df.columns:
                logger.error("CSV must contain 'pattern' and 'count' columns.")
                return {}
            pattern_counts = dict(zip(df['pattern'], df['count']))
            logger.info("Data loaded successfully.")
            return pattern_counts
        except Exception as e:
            logger.error(f"Error loading CSV data: {e}")
            return {}

if __name__ == "__main__":
    # Example usage
    pattern_counts = {
        'malicious_string_1': 5,
        'malicious_string_2': 3,
        'benign_string_1': 2,
        'malicious_string_3': 4
    }
    
    graph_builder = GraphBuilder()
    graph_builder.build_graph(pattern_counts)
    graph_builder.dynamic_legend(pattern_counts)
    filtered_nodes = graph_builder.filter_nodes_by_range(3, 5)
    print("Filtered Nodes:", filtered_nodes)
