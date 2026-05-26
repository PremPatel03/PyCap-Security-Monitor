import time
from scapy.all import sniff, TCP, IP
import sqlite3
from datetime import datetime

# Database Setup
def setup_database():
    conn = sqlite3.connect('network_alerts.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            alert_type TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    return conn

conn = setup_database()
cursor = conn.cursor()


# State Tracking for Port Scans

# Format: { 'ip_address': {'start_time': float, 'ports': set()} }
scan_tracker = {}
SCAN_THRESHOLD = 5    # Number of unique ports hit
TIME_WINDOW = 3.0     # Timeframe in seconds

def log_alert(src_ip, dst_ip, alert_type, details):
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, alert_type, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (time_now, src_ip, dst_ip, alert_type, details))
    conn.commit()
    print(f"[!] {time_now} | {alert_type} | {src_ip} -> {dst_ip} | {details}")

# Packet Processing Logic
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dest_port = packet[TCP].dport
        current_time = time.time()

        #  Rule A & B: Insecure Protocols
        if dest_port == 80:
            log_alert(src_ip, dst_ip, "Insecure Protocol", "Unencrypted HTTP traffic (Port 80).")
        elif dest_port == 21:
            log_alert(src_ip, dst_ip, "Insecure Protocol", "Cleartext FTP traffic (Port 21).")

        # Rule C: Port Scan Detection 
        if src_ip not in scan_tracker:
            scan_tracker[src_ip] = {'start_time': current_time, 'ports': set()}
        
        tracker = scan_tracker[src_ip]

        # Check if the time window has expired
        if current_time - tracker['start_time'] > TIME_WINDOW:
            tracker['start_time'] = current_time
            tracker['ports'] = set()

        # Record the port hit
        tracker['ports'].add(dest_port)

        # Trigger alert if threshold is breached
        if len(tracker['ports']) >= SCAN_THRESHOLD:
            log_alert(
                src_ip=src_ip, 
                dst_ip="Multiple", 
                alert_type="Port Scan", 
                details=f"Hit {len(tracker['ports'])} unique ports within {TIME_WINDOW} seconds."
            )
            # Reset tracker to avoid spamming the log for this IP
            tracker['ports'] = set()
            tracker['start_time'] = current_time


# 4. Start the Sniffer

if __name__ == "__main__":
    print("Starting Lightweight IDS...")
    print(f"Monitoring for insecure protocols and port scans (>{SCAN_THRESHOLD} ports in {TIME_WINDOW}s).")
    print("Press Ctrl+C to stop.\n")
    
    try:
        sniff(prn=process_packet, filter="tcp", store=False)
    except KeyboardInterrupt:
        print("\nStopping IDS. Alerts saved to 'network_alerts.db'.")
    finally:
        conn.close()
