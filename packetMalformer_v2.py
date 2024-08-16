"""
Script Name: packetMalformer_v2.py
Author: Jason Bisnette
Email: bisnettj@gdls.com

Description:
This script generates and sends malformed packets over specified network interfaces on Windows,
allowing for testing network security or analyzing network behavior under abnormal conditions.

Usage:
1. Ensure Python 3.x and necessary packages (e.g., scapy, psutil) are installed.
2. Run the script with administrator privileges.
3. Follow the prompts to select a network interface, specify protocol (TCP/UDP), destination IP,
   destination port, and choose the type of malformation to apply to the packets.

Command-line Arguments:
- `-d` or `--dest-ip`: Destination IP address for the packet.
- `-p` or `--dest-port`: Destination port for the packet.

Dependencies:
- Python 3.x
- scapy (install via pip install scapy)
- psutil (install via pip install psutil)

Changes: Initial version.
"""

from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import psutil
import random
import logging
import ctypes  # For Windows admin checker
import argparse

# Configure logging
logging.basicConfig(filename='packetMalformerLog.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Logs packet details
def log_packet(packet, description):
    if isinstance(packet, list):
        for fragment in packet:
            logging.info(f'{description}: {fragment.summary()}')
    else:
        logging.info(f'{description}: {packet.summary()}')

# Function to generate and return malformed packets
def generate_malformed_packet(protocol, flags, malform_type, dst_ip, dst_port):
    packet = None
    
    if protocol == "TCP":
        # Creating a basic IP packet
        ip_packet = IP(dst=dst_ip)
        # Creating a TCP packet with random source port and specified flags
        tcp_packet = TCP(sport=random.randint(1024, 65535), dport=dst_port, flags=flags)
        # Combine IP and TCP packet
        packet = ip_packet / tcp_packet
        
    elif protocol == "UDP":
        # Creating a basic IP packet
        ip_packet = IP(dst=dst_ip)
        # Creating a UDP packet with random source port
        udp_packet = UDP(sport=random.randint(1024, 65535), dport=dst_port)
        # Combine IP and UDP packet
        packet = ip_packet / udp_packet

    # Apply the selected malformation
    if malform_type == "invalid_length":
        if protocol == "TCP":
            packet[TCP].window = 0  # Invalid window size
        elif protocol == "UDP":
            packet[UDP].len = 0  # Invalid length
    elif malform_type == "checksum_error":
        if protocol == "TCP":
            packet[TCP].chksum = 0xFFFF  # Invalid checksum
        elif protocol == "UDP":
            packet[UDP].chksum = 0xFFFF  # Invalid checksum
    elif malform_type == "ip_fragmentation":
        packet = fragment(packet, fragsize=8)  # Fragment the IP packet
    elif malform_type == "payload_error":
        # Erroneously large payload
        large_payload = "A" * 9999
        packet = packet / Raw(load=large_payload)
    
    return packet

# Check if running as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Check active interfaces
def get_active_interfaces_with_traffic():
    interfaces = get_windows_if_list()
    active_interfaces = []
    net_io = psutil.net_io_counters(pernic=True)

    for iface in interfaces:
        name = iface['name']
        if name in net_io and net_io[name].bytes_recv > 0 and net_io[name].bytes_sent > 0:
            active_interfaces.append(iface)
    
    return active_interfaces

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Generate and send malformed packets over specified network interfaces.')
    parser.add_argument('-d', '--dest-ip', required=True, help='Destination IP address for the packet')
    parser.add_argument('-p', '--dest-port', type=int, required=True, help='Destination port for the packet')
    args = parser.parse_args()

    # Check for admin privileges
    if not is_admin():
        print("Please run this script as administrator.")
        return

    # List active interfaces with traffic
    interfaces = get_active_interfaces_with_traffic()
    if not interfaces:
        print("No active interfaces with traffic found.")
        return

    # Select interface
    print("Active interfaces with traffic:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface['name']}")
    iface_index = int(input("Select the interface to use (number): "))
    iface = interfaces[iface_index]['name']

    protocol = input("Enter the protocol (TCP/UDP): ").upper()
    if protocol == "TCP":
        while True:
            flags = input("Enter the TCP flags (e.g., S for SYN, A for ACK, F for FIN, R for RST): ").upper()
            valid_flags = "FSRPAUEC"
            if all(flag in valid_flags for flag in flags):
                break
            else:
                print("Invalid flags. Please enter a combination of F, S, R, P, A, U, E, C.")
    elif protocol == "UDP":
        flags = ""
    else:
        print("Invalid protocol")
        return

    malform_options = {
        "1": "invalid_length",
        "2": "checksum_error",
        "3": "ip_fragmentation",
        "4": "payload_error"
    }

    print("Select the type of malformation:")
    print("1: Invalid length")
    print("2: Checksum error")
    print("3: IP fragmentation")
    print("4: Payload error")
    print("5: All sequentially")
    malform_choice = input("Enter the number corresponding to your choice: ")
    
    if malform_choice == "5":
        for malform_type in malform_options.values():
            try:
                packet = generate_malformed_packet(protocol, flags, malform_type, args.dest_ip, args.dest_port)
                description = f'Sent {protocol} packet with {malform_type} malformation'
                print(description)
                send(packet, iface=iface)
                log_packet(packet, description)
            except Exception as e:
                print(f"Failed to send packet with {malform_type} malformation: {e}")
    else:
        malform_type = malform_options.get(malform_choice, "")
        if malform_type:
            try:
                packet = generate_malformed_packet(protocol, flags, malform_type, args.dest_ip, args.dest_port)
                description = f'Sent {protocol} packet with {malform_type} malformation'
                print(description)
                send(packet, iface=iface)
                log_packet(packet, description)
            except Exception as e:
                print(f"Failed to send packet with {malform_type} malformation: {e}")
        else:
            print("Invalid malformation type selected.")

if __name__ == "__main__":
    main()
