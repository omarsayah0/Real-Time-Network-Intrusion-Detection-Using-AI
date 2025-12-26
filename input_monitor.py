import numpy as np
import time
from scapy.all import sniff, IP, TCP, UDP

flow_data = {}

EXPECTED_NUM_FEATURES = 12

def extract_features(packet):
    try:
        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)

        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            return

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

        flow_info['total_fwd_packets'] += 1
        flow_info['packet_lengths_fwd'].append(len(packet))
        flow_info['total_fwd_length'] += len(packet)

        total_bwd_packets = flow_info['total_bwd_packets']
        total_bwd_length = flow_info['total_bwd_length']

        total_fwd_packets = flow_info['total_fwd_packets']
        total_fwd_length = flow_info['total_fwd_length']

        fwd_lengths = flow_info['packet_lengths_fwd']
        fwd_mean = np.mean(fwd_lengths) if fwd_lengths else 0
        fwd_std = np.std(fwd_lengths) if fwd_lengths else 0
        fwd_min = np.min(fwd_lengths) if fwd_lengths else 0
        fwd_max = np.max(fwd_lengths) if fwd_lengths else 0

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

        if len(features) == EXPECTED_NUM_FEATURES:
            print([float(x) for x in features])

    except Exception as e:
        pass


sniff(filter="ip", prn=extract_features, store=0)
