import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
from scipy.sparse import hstack

# Chemin vers les fichiers de log
log_files = {
    'SQLi': 'accessSQLi.log',
    'XSS': 'accessXSS.log',
    'Recon': 'accessReconNikto.log',
    'Exec': 'Exec.log'
}

# Fonction pour parser les lignes de log Apache
log_pattern = re.compile(r'(\S+) (\S+) (\S+) \[(.*?)] "(.*?)" (\d+) (\d+|-) "(.*?)" "(.*?)"')


def parse_log_line(line):
    match = log_pattern.match(line)
    if match:
        return match.groups()
    return None


def read_logs(log_file_path, label):
    logs = []
    with open(log_file_path, 'r') as file:
        for line in file:
            parsed_line = parse_log_line(line)
            if parsed_line:
                logs.append(parsed_line + (label,))
    return logs


labeled_logs = []
for label, file_path in log_files.items():
    labeled_logs.extend(read_logs(file_path, label))


def split_request(request):
    parts = request.split(' ', 2)
    if len(parts) == 1:
        parts.extend(['UNKNOWN', 'UNKNOWN'])
    elif len(parts) == 2:
        parts.append('UNKNOWN')
    return parts


def preprocess_logs_with_features(logs):
    df = pd.DataFrame(logs, columns=[
        'ip', 'identity', 'user', 'timestamp', 'request', 'status', 'size', 'referer', 'user_agent', 'vulnerability'
    ])

    df[['method', 'url', 'protocol']] = df['request'].apply(lambda x: pd.Series(split_request(x)))
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    df['request_length'] = df['request'].apply(len)
    df['status'] = df['status'].astype(int)
    df['size'] = df['size'].apply(lambda x: 0 if x == '-' else int(x))
    df['url_parts'] = df['url'].apply(lambda x: len(x.split('/')))
    df['user_agent_length'] = df['user_agent'].apply(len)

    return df


df_logs = preprocess_logs_with_features(labeled_logs)

df_logs['vulnerability'].value_counts().plot(kind='bar')
plt.title('Class Distribution')
plt.xlabel('Vulnerability')
plt.ylabel('Count')
plt.show()

X = df_logs[['request', 'request_length', 'status', 'size', 'url_parts', 'user_agent_length']]
y = df_logs['vulnerability']

vectorizer = TfidfVectorizer()
X_request = vectorizer.fit_transform(X['request'])
X_additional = X[['request_length', 'status', 'size', 'url_parts', 'user_agent_length']].values

X_combined = hstack([X_request, X_additional])
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_combined, y)
X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.3, random_state=42)
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [None, 10, 20, 30],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'ccp_alpha': [0.0, 0.01, 0.1]
}

grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5, n_jobs=-1, verbose=2)
grid_search.fit(X_train, y_train)
best_rf = grid_search.best_estimator_
y_pred = best_rf.predict(X_test)
print("Vulnerability Classification Report After Hyperparameter Tuning:")
print(classification_report(y_test, y_pred))
# Cross-validation
scores = cross_val_score(best_rf, X_combined, y, cv=5)
print(f'Cross-Validation Scores: {scores}')
print(f'Mean Cross-Validation Score: {scores.mean()}')
def process_individual_logs(log_files, model, vectorizer):
    for label, file_path in log_files.items():
        logs = read_logs(file_path, label)
        df_logs = preprocess_logs_with_features(logs)

        X = df_logs[['request', 'request_length', 'status', 'size', 'url_parts', 'user_agent_length']]
        X_request = vectorizer.transform(X['request'])
        X_additional = X[['request_length', 'status', 'size', 'url_parts', 'user_agent_length']].values
        X_combined = hstack([X_request, X_additional])

        y_pred = model.predict(X_combined)


        df_logs['Predicted_Vulnerability'] = y_pred
        print(f"Results for {label}:")
        print(df_logs[['request', 'Predicted_Vulnerability']].head())


        output_file = f'predicted_vulnerabilities_{label}.csv'
        df_logs.to_csv(output_file, index=False)
        print(f'Results saved to {output_file}\n')

process_individual_logs(log_files, best_rf, vectorizer)
