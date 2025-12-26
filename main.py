import numpy as np
import time
import pickle
from scapy.all import sniff, IP, TCP, UDP
import tensorflow as tf
from tensorflow.keras.models import load_model
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

model = load_model("model.keras")

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

threshold = 0.0029992137266807834 #You get this value when you run model.py it will be printed 

flow_data = {}
EXPECTED_NUM_FEATURES = 12

def extract_features(packet):
    try:
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)

        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            return None
        
        timestamp = time.time()
        if flow_key not in flow_data:
            flow_data[flow_key] = {
                'start_time': timestamp,
                'total_fwd_packets': 0,
                'total_bwd_packets': 0,
                'total_fwd_length': 0,
                'total_bwd_length': 0,
                'packet_lengths_fwd': [],
                'packet_lengths_bwd': []
            }

        flow_info = flow_data[flow_key]
        flow_duration = timestamp - flow_info['start_time']

        if packet[IP].src == src_ip:
            flow_info['total_fwd_packets'] += 1
            flow_info['packet_lengths_fwd'].append(len(packet))
            flow_info['total_fwd_length'] += len(packet)
        else:
            flow_info['total_bwd_packets'] += 1
            flow_info['packet_lengths_bwd'].append(len(packet))
            flow_info['total_bwd_length'] += len(packet)

        total_fwd_packets = flow_info['total_fwd_packets']
        total_bwd_packets = flow_info['total_bwd_packets']
        total_fwd_length = flow_info['total_fwd_length']
        total_bwd_length = flow_info['total_bwd_length']

        fwd_lengths = flow_info['packet_lengths_fwd']
        if len(fwd_lengths) > 0:
            fwd_mean = np.mean(fwd_lengths)
            fwd_std = np.std(fwd_lengths)
            fwd_min = np.min(fwd_lengths)
            fwd_max = np.max(fwd_lengths)
        else:
            fwd_mean, fwd_std, fwd_min, fwd_max = 0, 0, 0, 0

        if flow_duration > 0:
            flow_bytes_per_sec = (total_fwd_length + total_bwd_length) / flow_duration
            flow_packets_per_sec = (total_fwd_packets + total_bwd_packets) / flow_duration
        else:
            flow_bytes_per_sec = 0
            flow_packets_per_sec = 0

        features = [
            dport,
            flow_duration,
            total_fwd_packets,
            total_bwd_packets,
            total_fwd_length,
            total_bwd_length,
            fwd_mean,
            fwd_std,
            fwd_min,
            fwd_max,
            flow_bytes_per_sec,
            flow_packets_per_sec
        ]

        return features

    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def analyze_packet(packet):
    features = extract_features(packet)
    if features is None:
        return
    if len(features) != EXPECTED_NUM_FEATURES:
        print(f"Feature count mismatch. Got {len(features)} instead of {EXPECTED_NUM_FEATURES}.")
        return

    features_array = np.array(features, dtype=np.float32).reshape(1, -1)
    features_array_scaled = scaler.transform(features_array)

    reconstructed = model.predict(features_array_scaled)

    error = np.mean((features_array_scaled - reconstructed)**2)

    if error > threshold:
        print(f"🚨 alert {error:.5f}")
    else:
        print(f"normal {error:.5f}")

print("🔍 Starting packet sniffing ...")

sniff(filter="ip", prn=analyze_packet, store=0)
