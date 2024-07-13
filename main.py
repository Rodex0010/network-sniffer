from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")

        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{tcp_src_port} -> {ip_dst}:{tcp_dst_port}")

        elif UDP in packet:
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            print(f"UDP Packet: {ip_src}:{udp_src_port} -> {ip_dst}:{udp_dst_port}")


def start_sniffing(interface=None):
    if interface:
        sniff(prn=packet_callback, iface=interface, store=False)
    else:
        sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    # Replace 'eth0' with your network interface name
    start_sniffing(interface="eth0")
