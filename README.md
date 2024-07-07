# sec202

## Overview
This repository contains two main components: 
1. **Knowledge Graph for CVE and Random Forest Model for CVE Severity Prediction**
2. **Machine Learning Model for Apache Log Vulnerability Detection**

## Features
### 1. Knowledge Graph and CVE Severity Prediction
- **Knowledge Graph**: Constructs a knowledge graph for Common Vulnerabilities and Exposures (CVE).
- **Random Forest Model**: Trains a model using Random Forest and Cross-Validation Grid Search.
- **Severity Prediction**: Takes a new CVE as input and predicts its severity level.

### 2. Apache Log Vulnerability Detection
- **Training on Logs**: Trains a model on Apache logs with defined vulnerabilities (SQL Injection, XSS, and Exploitation).
- **Log Classification**: Takes a file with multiple logs as input and redistributes them into four files, one for each vulnerability type.

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/shmuel-bitan/sec202.git
    cd sec202
    ```
2. Install required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage
### Knowledge Graph and CVE Severity Prediction
1. **Construct the Knowledge Graph adn Predict CVE Severity**:
    ```sh
    python k_graph.py
    ```
3. ****:
    

### Apache Log Vulnerability Detection
1. **Train the Model and classify the logs**:
    ```sh
    python algo_completing.py
    ```

## Files and Directories
- `k_graph.py`: Script to create the knowledge graph for CVEs.
- `algo_completing.py`: Script to train the Random Forest model for thelogs analysis.
- `requirements.txt`: Contains the list of dependencies required for the project.
- `data.zip`: Contains sample data for training and testing.

## Contribution
Contributions are welcome! Please fork the repository and submit pull requests for any enhancements or bug fixes.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a new Pull Request.

## Information 
this project was made for my cnam course of cybercecurity SEC201 

