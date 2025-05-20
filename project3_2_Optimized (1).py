#!/usr/bin/env python3
"""
PCAP DDoS Attack Analyzer
This program reads PCAP files (including from directories) and analyzes them for potential DDoS attacks
by examining packet statistics across different time quantums.
"""

import os
import gzip
import tempfile
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import dpkt
import socket
from tqdm import tqdm

def ip_to_str(inet):
    """Convert inet object to a string"""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def parse_pcap_file(file_path):
    """Parse a PCAP file and extract packet information"""
    packets = []
    
    # Check if the file is gzipped
    is_gzipped = file_path.endswith('.gz')
    
    # Create a temporary file if the input is gzipped
    if is_gzipped:
        with gzip.open(file_path, 'rb') as f_in:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(f_in.read())
        
        open_file = open(temp_file_path, 'rb')
    else:
        open_file = open(file_path, 'rb')
    
    try:
        pcap = dpkt.pcap.Reader(open_file)
        
        for timestamp, buf in pcap:
            try:
                # Convert timestamp to datetime
                dt = datetime.fromtimestamp(timestamp)
                
                # Get packet size
                packet_size = len(buf)
                
                # Try to extract Ethernet frames
                eth = dpkt.ethernet.Ethernet(buf)
                
                # Check if IP packet
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    
                    # Get source and destination IP
                    src_ip = ip_to_str(ip.src)
                    dst_ip = ip_to_str(ip.dst)
                    
                    # Get protocol
                    protocol = ip.p
                    
                    # Try to get port information if TCP or UDP
                    src_port = None
                    dst_port = None
                    
                    if protocol == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                    elif protocol == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                    
                    packets.append({
                        'timestamp': dt,
                        'size': packet_size,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': protocol,
                        'src_port': src_port,
                        'dst_port': dst_port
                    })
            
            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue
    
    finally:
        open_file.close()
        if is_gzipped and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
    
    return packets

from collections import defaultdict

def analyze_packets_by_quantum(packets, quantum_minutes):
    """Efficiently analyze packets grouped by time quantum using a single pass."""
    quantum = timedelta(minutes=quantum_minutes)
    results = defaultdict(list)

    if not packets:
        return {}

    # Align starting time to quantum
    start_time = min(p['timestamp'] for p in packets)
    start_time = start_time.replace(
        minute=(start_time.minute // quantum_minutes) * quantum_minutes,
        second=0, microsecond=0
    )

    # Bin packets in one pass
    for p in tqdm(packets, desc=f"Binning packets into {quantum_minutes}-minute quanta"):
        delta = p['timestamp'] - start_time
        bin_index = int(delta.total_seconds() // (quantum_minutes * 60))
        quantum_start = start_time + timedelta(minutes=quantum_minutes * bin_index)
        results[quantum_start].append(p)

    # Compute statistics
    final_results = {}
    for t in tqdm(sorted(results.keys()), desc="Computing quantum stats"):
        group = results[t]
        total_volume = sum(p['size'] for p in group)
        packet_count = len(group)
        avg_packet_size = total_volume / packet_count if packet_count else 0

        final_results[t] = {
            'packet_count': packet_count,
            'total_volume': total_volume,
            'avg_packet_size': avg_packet_size,
            'packets': group
        }

    return final_results

def identify_anomalies(quantum_results):
    """Identify potential DDoS attack anomalies in the results"""
    timestamps = list(quantum_results.keys())
    packet_counts = [r['packet_count'] for r in quantum_results.values()]
    volumes = [r['total_volume'] for r in quantum_results.values()]
    avg_sizes = [r['avg_packet_size'] for r in quantum_results.values()]
    
    mean_count = np.mean(packet_counts)
    std_count = np.std(packet_counts)
    
    mean_volume = np.mean(volumes)
    std_volume = np.std(volumes)
    
    threshold_multiplier = 2.0
    anomalies = []
    
    for i, timestamp in enumerate(timestamps):
        is_anomaly = False
        reasons = []
        
        if packet_counts[i] > mean_count + threshold_multiplier * std_count:
            is_anomaly = True
            reasons.append(f"High packet count: {packet_counts[i]:.0f} (mean: {mean_count:.0f}, threshold: {mean_count + threshold_multiplier * std_count:.0f})")
        
        if volumes[i] > mean_volume + threshold_multiplier * std_volume:
            is_anomaly = True
            reasons.append(f"High traffic volume: {volumes[i]/1024/1024:.2f} MB (mean: {mean_volume/1024/1024:.2f} MB, threshold: {(mean_volume + threshold_multiplier * std_volume)/1024/1024:.2f} MB)")
        
        if is_anomaly:
            anomalies.append({
                'timestamp': timestamp,
                'reasons': reasons,
                'metrics': {
                    'packet_count': packet_counts[i],
                    'volume': volumes[i],
                    'avg_packet_size': avg_sizes[i]
                }
            })
    
    return anomalies

def analyze_attack_patterns(anomalies, quantum_results):
    """Analyze attack patterns for identified anomalies"""
    attack_patterns = []
    
    for anomaly in anomalies:
        timestamp = anomaly['timestamp']
        packets = quantum_results[timestamp]['packets']
        
        # Count packets by destination IP
        dst_ip_counts = {}
        for packet in packets:
            dst_ip_counts[packet['dst_ip']] = dst_ip_counts.get(packet['dst_ip'], 0) + 1
        
        top_targets = sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        protocol_counts = {}
        for packet in packets:
            proto = packet['protocol']
            if proto == dpkt.ip.IP_PROTO_TCP:
                protocol_name = "TCP"
            elif proto == dpkt.ip.IP_PROTO_UDP:
                protocol_name = "UDP"
            else:
                protocol_name = "Other"
            protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
        
        port_counts = {}
        for packet in packets:
            if packet['dst_port'] is not None:
                port_counts[packet['dst_port']] = port_counts.get(packet['dst_port'], 0) + 1
        
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        attack_patterns.append({
            'timestamp': timestamp,
            'top_targets': top_targets,
            'protocol_distribution': protocol_counts,
            'top_ports': top_ports
        })
    
    return attack_patterns

def plot_results(quantum_results, quantum_minutes, anomalies=None):
    """Create plots for visualization"""
    timestamps = list(quantum_results.keys())
    packet_counts = [r['packet_count'] for r in quantum_results.values()]
    volumes = [r['total_volume'] / (1024 * 1024) for r in quantum_results.values()]  # MB conversion
    avg_sizes = [r['avg_packet_size'] for r in quantum_results.values()]
    
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 15), sharex=True)
    
    ax1.plot(timestamps, packet_counts, 'b-', linewidth=1.5)
    ax1.set_title(f'Packet Count per {quantum_minutes}-Minute Quantum')
    ax1.set_ylabel('Packet Count')
    ax1.grid(True)
    
    if anomalies:
        anomaly_timestamps = [a['timestamp'] for a in anomalies]
        anomaly_counts = [quantum_results[ts]['packet_count'] for ts in anomaly_timestamps]
        ax1.scatter(anomaly_timestamps, anomaly_counts, color='red', s=50, zorder=5, label='Anomalies')
        ax1.legend()
    
    ax2.plot(timestamps, volumes, 'g-', linewidth=1.5)
    ax2.set_title(f'Traffic Volume per {quantum_minutes}-Minute Quantum')
    ax2.set_ylabel('Volume (MB)')
    ax2.grid(True)
    
    if anomalies:
        anomaly_volumes = [quantum_results[ts]['total_volume'] / (1024 * 1024) for ts in anomaly_timestamps]
        ax2.scatter(anomaly_timestamps, anomaly_volumes, color='red', s=50, zorder=5, label='Anomalies')
        ax2.legend()
    
    ax3.plot(timestamps, avg_sizes, 'm-', linewidth=1.5)
    ax3.set_title(f'Average Packet Size per {quantum_minutes}-Minute Quantum')
    ax3.set_ylabel('Size (bytes)')
    ax3.set_xlabel('Time')
    ax3.grid(True)
    
    
    
    plt.tight_layout()
    plot_filename = f'packet_analysis_{quantum_minutes}min.png'
    plt.savefig(plot_filename)
    plt.close()
    
    return plot_filename

def process_pcap_files(file_paths, quantum_minutes_list):
    """Process multiple PCAP files and analyze them with different time quantums"""
    all_packets = []
    
    # Parse all PCAP files
    for file_path in file_paths:
        print(f"Parsing file: {file_path}")
        packets = parse_pcap_file(file_path)
        all_packets.extend(packets)
        print(f"Extracted {len(packets)} packets")
    
    all_packets.sort(key=lambda p: p['timestamp'])
    print(f"Total packets: {len(all_packets)}")
    
    results = {}
    anomalies_by_quantum = {}
    attack_patterns_by_quantum = {}
    plot_files = {}
    
    for quantum_minutes in quantum_minutes_list:
        print(f"\nAnalyzing with {quantum_minutes}-minute quantum...")
        quantum_results = analyze_packets_by_quantum(all_packets, quantum_minutes)
        anomalies = identify_anomalies(quantum_results)
        attack_patterns = analyze_attack_patterns(anomalies, quantum_results)
        plot_file = plot_results(quantum_results, quantum_minutes, anomalies)
        
        results[quantum_minutes] = quantum_results
        anomalies_by_quantum[quantum_minutes] = anomalies
        attack_patterns_by_quantum[quantum_minutes] = attack_patterns
        plot_files[quantum_minutes] = plot_file
        
        print(f"Found {len(anomalies)} potential anomalies with {quantum_minutes}-minute quantum")
    
    return {
        'results': results,
        'anomalies': anomalies_by_quantum,
        'attack_patterns': attack_patterns_by_quantum,
        'plot_files': plot_files
    }

def main():
    parser = argparse.ArgumentParser(description='Analyze PCAP files for potential DDoS attacks')
    parser.add_argument('paths', nargs='+', help='PCAP files or directories containing PCAP files (files can be gzipped)')
    parser.add_argument('--quantum', type=int, nargs='+', default=[1, 5, 10], 
                        help='Time quantum in minutes for analysis (default: 1, 5, 10)')
    args = parser.parse_args()
    
    # Collect all PCAP file paths from the provided paths (files or directories)
    file_paths = []
    for path in args.paths:
        if os.path.isdir(path):
            # Walk the directory and select files ending in .pcap or .pcap.gz
            for entry in os.listdir(path):
                full_entry = os.path.join(path, entry)
                if os.path.isfile(full_entry) and (full_entry.endswith('.pcap') or full_entry.endswith('.pcap.gz')):
                    file_paths.append(full_entry)
        elif os.path.isfile(path):
            file_paths.append(path)
        else:
            print(f"Warning: {path} is not a valid file or directory and will be skipped.")
    
    if not file_paths:
        print("No valid PCAP files found. Exiting.")
        return
    
    # Process the collected PCAP files
    analysis_results = process_pcap_files(file_paths, args.quantum)
    
    print("\n=== ANALYSIS SUMMARY ===")
    for quantum in args.quantum:
        anomalies = analysis_results['anomalies'][quantum]
        attack_patterns = analysis_results['attack_patterns'][quantum]
        
        print(f"\n{quantum}-minute quantum analysis:")
        print(f"- Plot saved to: {analysis_results['plot_files'][quantum]}")
        print(f"- Found {len(anomalies)} potential DDoS attacks")
        
        if anomalies:
            print("\nPotential DDoS attacks:")
            for i, anomaly in enumerate(anomalies):
                print(f"\n  Attack #{i+1} at {anomaly['timestamp']}")
                for reason in anomaly['reasons']:
                    print(f"  - {reason}")
                
                if i < len(attack_patterns):
                    pattern = attack_patterns[i]
                    print("  Attack pattern:")
                    print("  - Top targets:")
                    for ip, count in pattern['top_targets']:
                        print(f"    * {ip}: {count} packets")
                    print("  - Protocol distribution:")
                    for proto, count in pattern['protocol_distribution'].items():
                        print(f"    * {proto}: {count} packets")
                    print("  - Top ports:")
                    for port, count in pattern['top_ports']:
                        print(f"    * Port {port}: {count} packets")

if __name__ == "__main__":
    main()

