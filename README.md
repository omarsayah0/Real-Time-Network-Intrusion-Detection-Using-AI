# Real Time Network Intrusion Detection Using AI


## About
This project implements a real-time network anomaly detection system using a deep learning Autoencoder model.
The model is trained on normal network traffic features extracted from flow-based data and learns to reconstruct normal behavior patterns.

During live execution, network packets are captured in real time using Scapy, relevant flow features are extracted, normalized using a pre-trained scaler, and passed to the autoencoder.
An anomaly score is calculated based on the reconstruction error, and traffic is flagged as normal or suspicious when the error exceeds a predefined threshold.

The system is designed for lightweight intrusion detection and abnormal traffic monitoring in real-time network environments.

---

## Files
- `main.py` → Captures live network packets, extracts flow features, and performs real-time anomaly detection using the trained autoencoder.
- `model.py` → Trains the autoencoder model on normal network traffic data and computes the anomaly detection threshold.
- `input_monitor.py` → This script is used for debugging and monitoring purposes, printing the real-time feature values extracted from network traffic in the exact format fed into the model, without performing prediction or anomaly detection.
- `model.keras` → The trained autoencoder neural network used to reconstruct normal traffic patterns.
- `scaler.pkl` → Saved MinMaxScaler used to normalize input features consistently during training and real-time detection.

---

## Dataset Description

This project uses the CIC-IDS-2017 Network Intrusion Dataset, a widely used benchmark dataset for evaluating intrusion detection systems. The dataset is publicly available on Kaggle at:
https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset

The CIC-IDS-2017 dataset consists of multiple CSV files, each corresponding to network traffic captured on different days, where each day represents specific network behaviors and attack scenarios. These files contain flow-based features extracted using the CICFlowMeter tool.

In this project, the Monday-WorkingHours.pcap_ISCX.csv file was selected for training. This file contains only benign (normal) network traffic, making it suitable for unsupervised learning approaches such as autoencoders, which are designed to learn normal behavior patterns and detect deviations as anomalies.

Due to the large size of the original dataset file, it is not included in this GitHub repository. For consistency and simplicity within the codebase, the selected file was renamed to data.csv and used as the input for model training.

The choice of the Monday dataset ensures that the autoencoder is trained exclusively on normal traffic, allowing the model to effectively identify abnormal or suspicious network behavior during real-time monitoring.

Dataset Features Description

The CIC-IDS-2017 dataset contains a large number of flow-based features (more than 80 features) describing network traffic characteristics. These features capture statistical, temporal, and packet-level properties of network flows.

In this project, a subset of relevant features was selected to balance model simplicity, computational efficiency, and suitability for real-time anomaly detection.

## Selected Features Used in This Project

The following features were extracted and used as input to the autoencoder model:

- **Destination Port**  
  Represents the destination port number of the network flow and helps distinguish different services and communication patterns.

- **Flow Duration**  
  The total duration of the network flow. Abnormal traffic often exhibits unusually short or long flow durations.

- **Total Fwd Packets**  
  The total number of packets sent from the source to the destination.

- **Total Backward Packets**  
  The total number of packets sent from the destination back to the source.

- **Total Length of Fwd Packets**  
  The total size (in bytes) of packets sent in the forward direction.

- **Total Length of Bwd Packets**  
  The total size (in bytes) of packets sent in the backward direction.

- **Fwd Packet Length Mean**  
  The average size of forward packets.

- **Fwd Packet Length Std**  
  The standard deviation of forward packet sizes.

- **Fwd Packet Length Min**  
  The minimum packet size in the forward direction.

- **Fwd Packet Length Max**  
  The maximum packet size in the forward direction.

- **Flow Bytes/s**  
  The data transfer rate in bytes per second.

- **Flow Packets/s**  
  The number of packets transmitted per second.

## Features Not Used in This Project

The CIC-IDS-2017 dataset also includes many additional features such as:

- TCP flag counts (SYN, ACK, FIN, RST, etc.)
- Inter-arrival time statistics
- Header-related features
- Active and idle time features
- Label and attack type columns

These features were not included for the following reasons:

- **Real-Time Constraints**  
  Some features require observing the full flow lifecycle or complex calculations, which are not suitable for real-time packet analysis.

- **Model Simplicity**  
  Reducing the number of features helps prevent overfitting and improves the stability of unsupervised models like autoencoders.

- **Protocol Dependency**  
  Certain features are protocol-specific (e.g., TCP flags) and may limit generalization across different network environments.

- **Unsupervised Learning Design**  
  Label-related features were intentionally excluded since the model is trained in an unsupervised manner using normal traffic only.

---

In summary, the selected features focus on flow duration, packet statistics, and traffic rates, which are sufficient to characterize normal network behavior while remaining efficient for real-time anomaly detection. Additional features available in the dataset were excluded to maintain scalability, simplicity, and real-time applicability.


---

## Steps Included

### 1️⃣ Data Preprocessing

- **Feature Selection**  
  Only a subset of relevant flow-based features was selected from the original dataset to reduce complexity and improve real-time performance.

- **Handling Invalid Values**  
  Infinite values (`+inf`, `-inf`) were replaced with `NaN`, and rows containing missing values were removed to ensure data consistency.

- **Feature Scaling (Normalization)**  
  All selected features were normalized using **Min-Max Scaling** to scale values into the range `[0, 1]`.  
  This step is essential for neural networks to ensure stable and efficient training.

- **Saving the Scaler**  
  The fitted MinMaxScaler was saved (`scaler.pkl`) and reused during real-time detection to ensure consistent preprocessing between training and inference.

These preprocessing steps ensure that the input data is clean, normalized, and suitable for training an unsupervised autoencoder model.

---

### 2️⃣ Model Training


The model used in this project is an **Autoencoder neural network**, trained in an unsupervised manner to learn normal network traffic behavior.

During training, the input data and the target output are the same, allowing the autoencoder to learn how to accurately reconstruct normal traffic patterns. Any significant reconstruction error during inference is treated as an anomaly.

### Model Architecture
The autoencoder consists of fully connected (Dense) layers arranged as follows:

- Input layer with a size equal to the number of selected features
- Encoder layers with decreasing dimensions to compress the input data
- Decoder layers with increasing dimensions to reconstruct the original input
- Sigmoid activation function in the output layer to match the normalized feature range

### Training Configuration
The model was trained using the following settings:

- **Optimizer:** Adam  
- **Loss Function:** Mean Squared Error (MSE)  
- **Batch Size:** 32  
- **Epochs:** 5  
- **Validation Split:** 10% of the training data  
- **Data Shuffle:** Enabled

### Training Process
The training process minimizes the reconstruction error between the input and output.  
Training and validation loss values are monitored across epochs to ensure stable learning and avoid overfitting.

After training, the model is saved as `model.keras` and used for real-time anomaly detection.

## Anomaly Threshold Calculation

Once training is completed, the reconstruction error is calculated for each training sample using the Mean Squared Error (MSE) between the original input and the reconstructed output.

An anomaly detection threshold is defined as:

threshold = mean_reconstruction_error + 3 × standard_deviation

This threshold represents the upper bound of normal reconstruction error learned during training.

During real-time inference, each network flow is passed through the trained autoencoder and its reconstruction error is computed:
- If the reconstruction error exceeds the threshold, the traffic is flagged as **anomalous**.
- If the reconstruction error is below the threshold, the traffic is considered **normal**.

This statistical thresholding approach enables effective detection of abnormal network behavior without requiring labeled attack data.


---


## How to Run

1- Install Dependencies:
  ```bash
pip install pandas numpy scikit-learn tensorflow scapy matplotlib

```

2- Make sure data file exists in the root of your work:
  ```bash
data.csv

```
input_monitor.py
3-Run :

  ```bash
python heart_disease.py
```

The main script used for real-time network traffic monitoring and anomaly detection.  
It analyzes live packets and classifies network flows as normal or anomalous.

  ```bash
python heart_disease.py
```
A debugging script used to display the raw feature values extracted from live network traffic.  
It helps verify the data being fed into the model without performing prediction or detection.


3- Application Preview :

<p align="center">
<img width="1698" height="1143" alt="download" src="https://github.com/user-attachments/assets/e0f3ed74-0561-4b78-89b8-514666237cec" />
</p>

This figure shows the system during the real-time monitoring phase before anomaly detection is applied. The model is actively processing live network traffic and printing the extracted feature values for each observed flow.
At this stage, all traffic is within the normal behavior range, and no anomaly alerts are triggered. The output is used to verify and inspect the input data being fed into the model.


---



<p align="center">
<img width="2047" height="1416" alt="cf3b2101-9e78-44ab-b0e1-c09ffa7617d9" src="https://github.com/user-attachments/assets/b3ff0032-7d59-4c68-aaba-cea708427d3b" />
</p>


This figure shows the real-time anomaly detection phase of the system. While monitoring live network traffic, the model detects abnormal behavior and triggers alerts when the reconstruction error exceeds the predefined threshold.
The highlighted alert messages indicate suspicious network flows that deviate from normal traffic patterns, demonstrating the system’s ability to identify anomalies in real time.


---


 ## Author
  
  Omar Alethamat

  LinkedIn : https://www.linkedin.com/in/omar-alethamat-8a4757314/

  ## License

  This project is licensed under the MIT License — feel free to use, modify, and share with attribution.
