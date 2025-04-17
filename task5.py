from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Analyze protocol-specific information
        if ip_layer.proto == 6:  # TCP
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Sequence Number: {tcp_layer.seq}")
            print(f"Acknowledgment Number: {tcp_layer.ack}")
        elif ip_layer.proto == 17:  # UDP
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        elif ip_layer.proto == 1:  # ICMP
            icmp_layer = packet[ICMP]
            print(f"ICMP Type: {icmp_layer.type}")
            print(f"ICMP Code: {icmp_layer.code}")

        # Display payload data
        if ip_layer.payload:
            print(f"Payload: {ip_layer.payload}")
        print("\n")

# Start sniffing
print("Starting packet capture...")
sniff(prn=packet_callback, count=10)  # Captures 10 packets, remove 'count' to capture indefinitely