import plotly.graph_objects as go
import networkx as nx
from networkx.algorithms import community
import pandas as pd
import logging

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class Visualizer:
    def __init__(self):
        self.graph = nx.Graph()

    def set_graph(self, graph: nx.Graph) -> None:
        """Set the graph to be visualized."""
        self.graph = graph
        logger.info("Graph has been set for visualization.")

    def visualize_graph(self, title: str = "Malware Signature Patterns", layout: str = "spring", highlight_node: str = None) -> None:
        """Visualize the graph with customizable layouts and interactive tooltips."""
        logger.info("Visualizing the graph.")
        pos = self.get_layout(layout)

        # Extract edge positions for Plotly
        edge_x = []
        edge_y = []
        for edge in self.graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.append(x0)
            edge_x.append(x1)
            edge_x.append(None)  # Break line
            edge_y.append(y0)
            edge_y.append(y1)
            edge_y.append(None)  # Break line

        # Extract node positions and text for Plotly
        node_x = []
        node_y = []
        node_text = []
        colors = []
        for node in self.graph.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            count = self.graph.nodes[node]['count']
            node_type = self.graph.nodes[node]['type']
            node_text.append(f"{node}<br>Type: {node_type}<br>Count: {count}")

            # Determine color based on type
            colors.append('red' if node_type == 'malicious' else 'green')

            # Highlight selected node
            if highlight_node and node == highlight_node:
                colors[-1] = 'blue'  # Highlight color

        # Create Plotly figure
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='gray'),
            hoverinfo='none', mode='lines'))

        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_text,
            textposition="top center",
            marker=dict(size=10, color=colors, line=dict(width=2, color='black'))))

        # Add legend
        fig.add_trace(go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=10, color='red'),
            name='Malicious'))
        fig.add_trace(go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=10, color='green'),
            name='Benign'))

        fig.update_layout(title=title, showlegend=True,
                          hovermode='closest', margin=dict(l=0, r=0, t=40, b=0))
        fig.show()

    def get_layout(self, layout: str) -> dict:
        """Get positions for nodes based on the specified layout."""
        logger.info(f"Using layout: {layout}")
        if layout == 'spring':
            return nx.spring_layout(self.graph)
        elif layout == 'circular':
            return nx.circular_layout(self.graph)
        elif layout == 'hierarchical':
            return nx.multipartite_layout(self.graph)
        else:
            logger.error("Invalid layout specified, defaulting to spring layout.")
            return nx.spring_layout(self.graph)

    def export_to_csv(self, filename: str) -> None:
        """Export the graph data to a CSV file."""
        logger.info(f"Exporting graph data to {filename}.csv")
        node_data = [(node, self.graph.nodes[node]['count'], self.graph.nodes[node]['type']) for node in self.graph.nodes()]
        edge_data = [(edge[0], edge[1]) for edge in self.graph.edges()]

        # Create DataFrames
        nodes_df = pd.DataFrame(node_data, columns=['Node', 'Count', 'Type'])
        edges_df = pd.DataFrame(edge_data, columns=['Source', 'Target'])

        # Save to CSV
        nodes_df.to_csv(f"{filename}_nodes.csv", index=False)
        edges_df.to_csv(f"{filename}_edges.csv", index=False)
        logger.info("Export completed.")

    def highlight_connections(self, node: str) -> None:
        """Highlight connections for a specific node."""
        logger.info(f"Highlighting connections for node: {node}")
        if node in self.graph.nodes():
            connected_nodes = list(self.graph.neighbors(node))
            return connected_nodes
        else:
            logger.error("Node not found in the graph.")
            return []

    def cluster_nodes(self) -> None:
        """Cluster nodes using the Louvain method and visualize."""
        logger.info("Clustering nodes using the Louvain method.")
        partition = community.louvain_communities(self.graph)
        colors = {}
        for i, comm in enumerate(partition):
            for node in comm:
                colors[node] = f'rgba({i*50 % 255}, {i*100 % 255}, {i*200 % 255}, 0.6)'

        pos = nx.spring_layout(self.graph)
        edge_x = []
        edge_y = []
        for edge in self.graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.append(x0)
            edge_x.append(x1)
            edge_x.append(None)  # Break line
            edge_y.append(y0)
            edge_y.append(y1)
            edge_y.append(None)  # Break line

        node_x = []
        node_y = []
        node_text = []
        for node in self.graph.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            count = self.graph.nodes[node]['count']
            node_text.append(f"{node}<br>Count: {count}")

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='gray'),
            hoverinfo='none', mode='lines'))

        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=node_text,
            textposition="top center",
            marker=dict(size=10, color=[colors[node] for node in self.graph.nodes()],
                        line=dict(width=2, color='black'))))

        fig.update_layout(title="Clustered Malware Signature Patterns", showlegend=False,
                          hovermode='closest', margin=dict(l=0, r=0, t=40, b=0))
        fig.show()

if __name__ == "__main__":
    # Example usage
    graph = nx.Graph()
    graph.add_nodes_from([
        ('malicious_string_1', {'count': 5, 'type': 'malicious'}),
        ('malicious_string_2', {'count': 3, 'type': 'malicious'}),
        ('benign_string_1', {'count': 2, 'type': 'benign'}),
        ('malicious_string_3', {'count': 4, 'type': 'malicious'})
    ])
    
    graph.add_edges_from([
        ('malicious_string_1', 'malicious_string_2'),
        ('malicious_string_2', 'benign_string_1'),
        ('benign_string_1', 'malicious_string_3'),
        ('malicious_string_1', 'malicious_string_3')
    ])

    visualizer = Visualizer()
    visualizer.set_graph(graph)
    visualizer.visualize_graph(title="Malware Signature Patterns", layout='circular')
    
    # Example to highlight connections for a specific node
    connections = visualizer.highlight_connections('malicious_string_1')
    logger.info(f"Connections for 'malicious_string_1': {connections}")
    
    # Example to export graph to CSV
    visualizer.export_to_csv("malware_graph")
