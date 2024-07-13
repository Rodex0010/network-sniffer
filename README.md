
# Packet Sniffer

This Python script is a basic packet sniffer that captures and displays network packets in real time. It uses the `scapy` library to sniff packets on a specified network interface and prints out information about IP, TCP, and UDP packets.

## Prerequisites

- Python 3.x
- `scapy` library

You can install `scapy` using pip:

```sh
pip install scapy
```

## Usage

1. **Clone or Download the Script**

   Clone the repository or download the script file (`main.py`) to your local machine.

2. **Run the Script**

   Open a terminal and navigate to the directory containing `main.py`. Run the script with the following command:

   ```sh
   python main.py
   ```

   By default, the script is set to sniff packets on the `eth0` interface. If you want to specify a different interface, modify the `interface` parameter in the `start_sniffing` function call:

   ```python
   if __name__ == "__main__":
       # Replace 'eth0' with your network interface name
       start_sniffing(interface="eth0")
   ```

3. **Packet Information**

   The script will print information about the captured packets to the console. It identifies and prints the source and destination IP addresses, protocol type, and for TCP/UDP packets, the source and destination ports.

## Example Output

```sh
IP Packet: 192.168.1.2 -> 192.168.1.1, Protocol: 6
TCP Packet: 192.168.1.2:12345 -> 192.168.1.1:80
UDP Packet: 192.168.1.3:54321 -> 192.168.1.4:53
```

## Disclaimer

This script is intended for educational and testing purposes only. Unauthorized use of this script to capture network traffic on networks where you do not have permission is illegal and unethical. Always ensure you have proper authorization before using this tool on a network.
