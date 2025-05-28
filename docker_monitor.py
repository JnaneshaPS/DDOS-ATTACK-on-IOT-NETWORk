#!/usr/bin/env python3
import subprocess
import time
import json
import requests
import argparse
import re
from datetime import datetime

# Configuration
DASHBOARD_URL = "http://localhost:8080"

def get_container_ips():
    """Get IP addresses of Docker containers"""
    container_ips = {}
    try:
        # Get container IDs first
        container_ids = subprocess.check_output("docker ps -q", shell=True, text=True).strip().split('\n')
        
        for container_id in container_ids:
            if not container_id:
                continue
                
            # Get container info one by one (more compatible with Windows)
            cmd = f'docker inspect -f "{{{{.Name}}}} - {{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}" {container_id}'
            output = subprocess.check_output(cmd, shell=True, text=True).strip()
        
            # Process each container output individually
            if ' - ' in output:
                parts = output.split(' - ')
                if len(parts) == 2:
                    name = parts[0].strip('/')  # Remove leading slash
                    ip = parts[1]
                    container_ips[name] = ip
                    print(f"Found container: {name} with IP: {ip}")
                
        return container_ips
    except Exception as e:
        print(f"Error getting container IPs: {e}")
        return {}

def monitor_traffic(duration=30, interval=5):
    """Monitor Docker network traffic and send data to dashboard"""
    print(f"Starting Docker network traffic monitoring for {duration} seconds...")
    
    # Get container IPs
    container_ips = get_container_ips()
    ip_to_name = {ip: name for name, ip in container_ips.items()}
    
    end_time = time.time() + duration
    
    while time.time() < end_time:
        # Monitor traffic for each container
        for name, ip in container_ips.items():
            if 'attacker' in name:
                continue  # Skip monitoring attacker directly
                
            try:
                # Get traffic stats for the container
                stats = get_container_stats(name, ip)
                
                # Check if this looks like an attack
                if stats['packets_per_sec'] > 100:  # Threshold for attack detection
                    # Report potential attack
                    report_attack(stats, ip_to_name)
            except Exception as e:
                print(f"Error monitoring container {name}: {e}")
        
        # Wait before next check
        print(f"Traffic checked. Waiting {interval} seconds...")
        time.sleep(interval)
    
    print("Docker traffic monitoring complete.")

def get_container_stats(container_name, container_ip):
    """Get network traffic statistics for a container"""
    # Use docker stats to get network I/O
    cmd = f"docker stats --no-stream --format \"{{{{.NetIO}}}}\" {container_name}"
    output = subprocess.check_output(cmd, shell=True, text=True).strip()
    
    # Parse network I/O (format: 1.45kB / 1.45kB)
    in_traffic, out_traffic = output.split(' / ')
    
    # Convert to bytes
    def convert_to_bytes(size_str):
        match = re.match(r'([\d.]+)([kMGT]?B)', size_str)
        if not match:
            return 0
        
        value, unit = match.groups()
        unit_multipliers = {'B': 1, 'kB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}
        return float(value) * unit_multipliers.get(unit, 1)
    
    in_bytes = convert_to_bytes(in_traffic)
    out_bytes = convert_to_bytes(out_traffic)
    
    # Get packet counts using container inspect
    # Note: This is an approximation as Docker doesn't expose packet counts directly
    packets_per_sec = 0
    try:
        # Use process substitution to get a more accurate packet count
        cmd = f"docker exec {container_name} cat /proc/net/dev"
        output = subprocess.check_output(cmd, shell=True, text=True)
        
        # Find the eth0 line
        for line in output.strip().split('\n'):
            if 'eth0:' in line:
                # Extract packet counts
                parts = line.split()
                rx_packets = int(parts[2])
                tx_packets = int(parts[10])
                packets_per_sec = (rx_packets + tx_packets) / 5  # rough estimate
                break
    except:
        packets_per_sec = in_bytes / 1000  # Rough approximation if can't get real data
    
    return {
        'container_name': container_name,
        'ip': container_ip,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'in_bytes': in_bytes,
        'out_bytes': out_bytes,
        'bytes_per_sec': (in_bytes + out_bytes) / 5,  # Rough estimate
        'packets_per_sec': packets_per_sec
    }

def report_attack(stats, ip_to_name):
    """Report attack to dashboard and trigger mitigation"""
    try:
        # Get attacker info
        attacker_ip = ip_to_name.get('attacker', '192.168.1.100')  # Default if not found
        
        # Prepare attack data
        attack_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'source_ip': attacker_ip,
            'target_ip': stats['ip'],
            'target_name': stats['container_name'],
            'is_attack': True,
            'type': 'ATTACK',
            'confidence': 0.95,  # High confidence since we're detecting actual traffic
            'packet_rate': stats['packets_per_sec']
        }
        
        # Send to dashboard
        print(f"Detected attack! Attacker: {attacker_ip}, Target: {stats['container_name']} ({stats['ip']})")
        print(f"Packet rate: {stats['packets_per_sec']:.2f} packets/sec")
        
        # Send alert to dashboard
        response = requests.post(f"{DASHBOARD_URL}/api/report_attack", json=attack_data)
        print(f"Report sent to dashboard. Status: {response.status_code}")
        
        # Trigger mitigation
        mitigate_attack(attacker_ip, stats['container_name'])
        
    except Exception as e:
        print(f"Error reporting attack: {e}")
        
def mitigate_attack(attacker_ip, target_container):
    """Trigger mitigation measures against the attack"""
    try:
        print(f"\n=== TRIGGERING AUTOMATED MITIGATION ===")
        print(f"Mitigating attack from {attacker_ip} targeting {target_container}")
        
        # Call the mitigation script
        mitigation_cmd = f"mitigate_docker_attack.bat {attacker_ip} {target_container}"
        subprocess.Popen(mitigation_cmd, shell=True)
        
        print(f"Mitigation process started. Check the dashboard for status.\n")
        return True
    except Exception as e:
        print(f"Error triggering mitigation: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Monitor Docker network for DDoS attacks')
    parser.add_argument('-d', '--duration', type=int, default=60, 
                        help='Duration to monitor (seconds)')
    parser.add_argument('-i', '--interval', type=int, default=5, 
                        help='Check interval (seconds)')
    
    args = parser.parse_args()
    
    print("IoT DDoS Detection: Docker Network Monitor")
    print("=========================================")
    
    monitor_traffic(args.duration, args.interval)

if __name__ == "__main__":
    main()
