import json
import re
import os
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils import resample
from sklearn.pipeline import make_pipeline

file_path = 'data/combined_cve.json'

with open(file_path, 'r', encoding='utf-8') as file:
    data = json.load(file)

def clean_transform_data(data):
    records = []
    for item in data['CVE_Items']:
        cve_id = item['cveMetadata']['cveId']
        descriptions = item['containers']['cna'].get('descriptions', [])
        description = descriptions[0]['value'] if descriptions else 'No description available'
        metrics = item['containers']['cna'].get('metrics', [])
        impact = metrics[0].get('cvssV3_1', {}).get('baseSeverity', 'Unknown') if metrics else 'Unknown'
        records.append((cve_id, description, impact))
    df = pd.DataFrame(records, columns=['CVE_ID', 'Description', 'Impact'])
    return df


df = clean_transform_data(data)

def balance_classes(df):
    df_majority = df[df.Impact == 'MEDIUM']
    df_minority = df[df.Impact != 'MEDIUM']

    df_minority_upsampled = resample(df_minority,
                                     replace=True, 
                                     n_samples=len(df_majority), 
                                     random_state=123) 
    df_balanced = pd.concat([df_majority, df_minority_upsampled])
    return df_balanced


df_balanced = balance_classes(df)

def build_knowledge_graph(df):
    G = nx.Graph()
    for _, row in df.iterrows():
        weakness_node = f"Weakness {row['CVE_ID']}"
        G.add_node(weakness_node, type='CVE', description=row['Description'])
        G.add_node(row['Impact'], type='Impact')
        G.add_edge(weakness_node, row['Impact'])
    return G


def visualize_graph(G):
    pos = nx.spring_layout(G, k=0.15)
    plt.figure(figsize=(12, 12))

    cve_nodes = [node for node in G.nodes if G.nodes[node]['type'] == 'CVE']
    impact_nodes = [node for node in G.nodes if G.nodes[node]['type'] == 'Impact']

    nx.draw_networkx_nodes(G, pos, nodelist=cve_nodes, node_color='skyblue', node_size=500, label='CVE')
    nx.draw_networkx_nodes(G, pos, nodelist=impact_nodes, node_color='lightgreen', node_size=300, label='Impact')
    nx.draw_networkx_edges(G, pos, edgelist=G.edges, edge_color='gray')
    nx.draw_networkx_labels(G, pos, font_size=10)

    plt.title('Knowledge Graph of CVEs and Impacts')
    plt.legend(scatterpoints=1)
    plt.axis('off')
    plt.show()

def train_classification_model(df):
    X = df['Description']
    y = df['Impact']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = make_pipeline(TfidfVectorizer(), RandomForestClassifier(random_state=42))
    param_grid = {
        'randomforestclassifier__n_estimators': [100, 200, 300],
        'randomforestclassifier__max_depth': [None, 10, 20, 30],
    }
    grid = GridSearchCV(model, param_grid, cv=5)
    grid.fit(X_train, y_train)

    y_pred = grid.predict(X_test)
    print(classification_report(y_test, y_pred))
    print("Accuracy:", accuracy_score(y_test, y_pred))
    return grid

def security_decision(model, new_data):
    predictions = model.predict(new_data['Description'])
    new_data['Predicted_Impact'] = predictions
    return new_data


# Function for dynamic clustering of events
def dynamic_clustering(events):
    clusters = []
    for event in events:
        cluster = find_cluster(event, clusters)
        if cluster:
            cluster.append(event)
        else:
            clusters.append([event])
    return clusters


def find_cluster(event, clusters):
    for cluster in clusters:
        if is_similar(event, cluster):
            return cluster
    return None


def is_similar(event, cluster):
    for existing_event in cluster:
        if event['Impact'] == existing_event['Impact']:
            return True
    return False


def parse_log_line(line):
    log_pattern = re.compile(r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"')
    match = log_pattern.match(line)
    if match:
        return match.groups()
    return None


def read_logs(log_file_path):
    logs = []
    with open(log_file_path, 'r') as file:
        for line in file:
            parsed_line = parse_log_line(line)
            if parsed_line:
                logs.append(parsed_line)
    return logs


# Function to preprocess parsed logs into a DataFrame
def preprocess_logs(logs):
    df = pd.DataFrame(logs, columns=[
        'ip', 'identity', 'user', 'timestamp', 'request', 'status', 'size', 'referer', 'user_agent'
    ])
    # Split request into method, URL, and protocol
    df[['method', 'url', 'protocol']] = df['request'].str.split(' ', expand=True)
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    return df


# Function to generate results from logs and predictions
def generate_results(df_logs, vuln_predictions, stage_predictions):
    df_logs['Predicted_Vulnerability'] = vuln_predictions
    df_logs['Predicted_Kill_Chain_Stage'] = stage_predictions
    results_dict = df_logs.to_dict(orient='records')
    return df_logs, results_dict


def main():
    G = build_knowledge_graph(df_balanced)
    visualize_graph(G)

    # Train the classification model
    model = train_classification_model(df_balanced)

    # Example new data for security decision making
    new_data = [
        {'CVE_ID': 'CVE-2024-901', 'Description': 'description de l attaque', 'Impact': 'Unknown'},
        # Add more new data as needed
    ]
    new_df = pd.DataFrame(new_data)

    decisions = security_decision(model, new_df)
    print(decisions)


# Example usage
if __name__ == "__main__":
    main()

