from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        proto = packet['IP'].proto
        payload = packet.payload if packet.payload else None
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}, Payload: {payload}")

# Sniff packets on the network interface 'Ethernet 3'
sniff(iface='Ethernet 3', prn=packet_callback, store=0)
