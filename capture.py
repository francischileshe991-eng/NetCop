#welcome to NetCop a simple cli network sniffer and analyer

from scapy.all import *
from datetime import datetime
import psutil
import threading
import queue

# Define a class for network sniffer

class NetworkSniffer:
    def __init__(self, interface=None, capture_filter=""):
        self.interface = interface or self.get_default_interface()
        self.filter = capture_filter
        self.packets = []
        self.packet_queue = queue.Queue()
        self.running = False
        
    def get_default_interface(self):
        """Auto-detect active network interface"""
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface in stats:
            if stats[iface].isup and not iface.startswith('lo'):
                return iface
        return "eth0" 

    def packet_callback(self, packet):
        """Process each captured packet"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            size = len(packet)
            
            # Extract transport layer
            sport = dport = None
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                proto_name = "TCP"
            elif packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                proto_name = "UDP"
            elif packet.haslayer(ICMP):
                proto_name = "ICMP"
            else:
                proto_name = "Other"
            
            record = {
                'timestamp': datetime.now(), 
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto_name,
                'src_port': sport,
                'dst_port': dport,
                'size': size,
                'raw': packet
            }
            
            self.packet_queue.put(record)

    def start(self):
        print(f"[+] Starting capture on interface: {self.interface}")
        self.running = True
        thread = threading.Thread(target=self._capture)
        thread.daemon = True
        thread.start()

    def _capture(self):
        sniff(
            iface=self.interface,
            filter=self.filter,
            prn=self.packet_callback,
            store=False, 
            stop_filter=lambda x: not self.running
        )

    def stop(self):
        self.running = False
        print("[+] Capture stopped.")

    def get_packets(self, count=100):
        """Get latest packets (non-blocking)"""
        packets = []
        while len(packets) < count and not self.packet_queue.empty():
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets


    
# Main execution 
               
if __name__ == "__main__":
    print("NetCop sniffer starting...")

    sniffer = NetworkSniffer(interface=r"---------------") # Specify your interface here if needrd
    sniffer.start()

    try:
        while True:
            packets = sniffer.get_packets(100)
            for p in packets:
                print(f"{p['timestamp']}  {p['src_ip']}:{p['src_port'] or ''} → {p['dst_ip']}:{p['dst_port'] or ''}  {p['protocol']}  {p['size']} bytes")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        sniffer.stop()
    print("NetCop sniffer stopped. Peace out😊")

#yet to use pandas to create a better one
