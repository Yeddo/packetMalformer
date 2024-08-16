from scapy.all import *
import random
import logging
import os

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def log_packet(packet, description):
    """Logs the details of a packet with a description."""
    logging.info(f'{description}: {packet.summary()}')

def generate_malformed_packet(protocol, flags, malform_type):
    packet = None
    
    if protocol == "TCP":
        # Creating a basic IP packet
        ip_packet = IP(dst="192.168.122.2") # Change this to your destination IP
        # Creating a TCP packet with random source port and specified flags
        tcp_packet = TCP(sport=random.randint(1024, 65535), dport=80, flags=flags)
        # Combine IP and TCP packet
        packet = ip_packet / tcp_packet
        
    elif protocol == "UDP":
        # Creating a basic IP packet
        ip_packet = IP(dst="192.168.122.2") # Change this to your destination IP
        # Creating a UDP packet with random source port
        udp_packet = UDP(sport=random.randint(1024, 65535), dport=80)
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
        packet = packet / Raw(load="A" * 1500)  # Payload too large for standard MTU
    
    return packet

def main():
    protocol = input("Enter the protocol (TCP/UDP): ").upper()
    if protocol == "TCP":
        flags = input("Enter the TCP flags (e.g., S for SYN, A for ACK, F for FIN, R for RST): ")
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
            packet = generate_malformed_packet(protocol, flags, malform_type)
            description = f'Sent {protocol} packet with {malform_type} malformation'
            print(description)
            if malform_type == "ip_fragmentation":
                send(packet)
                for fragment in packet:
                    log_packet(fragment, description)
            else:
                send(packet)
                log_packet(packet, description)
    else:
        malform_type = malform_options.get(malform_choice, "")
        if malform_type:
            packet = generate_malformed_packet(protocol, flags, malform_type)
            description = f'Sent {protocol} packet with {malform_type} malformation'
            print(description)
            if malform_type == "ip_fragmentation":
                send(packet)
                for fragment in packet:
                    log_packet(fragment, description)
            else:
                send(packet)
                log_packet(packet, description)
        else:
            print("Invalid malformation type selected.")

if __name__ == "__main__":
    main()