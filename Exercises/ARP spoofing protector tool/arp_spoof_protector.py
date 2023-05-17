"""
Author: Gal Gabay
ARP spoofing protector tool
"""

import argparse
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from colorama import Fore


class ArpSpoofProtector:
    def __init__(self, p):
        self.is_prevent_mode = p
        self.attacks_counter = 0
        self.dup_at_flag = False
        self.mac_ip_pairs = []
        self.replys_frequency = {}

    def replys_sniffing(self):
        """
        sniff incoming ARP replys (is at packets)
        :return:
        """
        sniff(iface=conf.iface,
              store=False,
              filter='arp',
              lfilter=lambda p: p[ARP].psrc != get_if_addr(conf.iface) and p[ARP].op == 2,
              prn=self.handle_arp_reply)

    def handle_arp_reply(self, pkt):
        """
        Checks if there are any suspicious arp packets - according to 3 indicators:
        1. Checking if there is same mac address associated with 2 or more ip addresses in the ARP table.
        2. Comparing the received packet to a normal arp reply packet.
        3. Check frequency of a packet - if there is a packet that sent 3 times at last 30 seconds - suspicious!

        If the 2 indicators are correct, it means that the device is under attack - and the user is notified.
        In addition, if the prevention mode is on, try restart the network.
        :param pkt: packet to check
        :return:
        """
        if (self.dup_at_flag or self.suspicious_arp_table()) and \
                (self.suspicious_replys_frequency(pkt) or self.suspicious_mac(pkt)):
            print(f'{Fore.LIGHTRED_EX}[-] Your device is under ARP spoofing attack{Fore.RESET}')
            self.dup_at_flag = False
            if self.is_prevent_mode:
                subprocess.run("arp -d " + pkt[ARP].psrc, shell=True)
                print(f'{Fore.LIGHTGREEN_EX}[+] Faked-Line {pkt[ARP].psrc} is at {pkt[ARP].hwsrc} '
                      f'deleted from your ARP table{Fore.RESET}')
                sendp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=pkt[ARP].psrc, op=1), verbose=False)
                self.attacks_counter += 1
                if self.attacks_counter == 3:
                    self.attacks_counter = 0
                    self.cutting_network_connection(conf.iface)

    def suspicious_replys_frequency(self, pkt):
        pkt = pkt.summary()
        if pkt not in self.replys_frequency.keys():
            self.replys_frequency[pkt] = []
        if len(self.replys_frequency[pkt]) < 3:
            self.replys_frequency[pkt].append(time.time())
        else:
            self.replys_frequency[pkt] = self.replys_frequency[pkt][1:] + [time.time()]
            if time.time() - self.replys_frequency[pkt][0] < 30:
                print(f'{Fore.LIGHTYELLOW_EX}[!] Warning: 3 similar ARP replies at last 30 seconds{Fore.RESET}')
                self.replys_frequency[pkt] = []
                return True
        return False

    def suspicious_arp_table(self):
        """
        Checking if there is the same mac address associated with 2 or more ip addresses.
        :return:
            If there is a mac address associated with 2 or more ip addresses - true.
            Otherwise - False.
        """
        self.update_arp_table()
        if len(self.mac_ip_pairs) > len(dict(self.mac_ip_pairs)):  # there is a duplicated mac address
            print(f'{Fore.LIGHTYELLOW_EX}[!] Warning: duplicated MAC address in ARP table{Fore.RESET}')
            self.dup_at_flag = True
            return True
        return False

    def update_arp_table(self):
        """
        Extracts the arp table, and puts in the list the ip addresses with the mac associated with each address.
        :return:
        """
        if os.name == 'posix':  # If the operating system is UNIX
            self.mac_ip_pairs = [[x.split()[1], x.split()[0].strip('()')] for x in
                                 os.popen('arp -a|cut -d " " -f "2,4"')]
        elif os.name == 'nt':  # If the operating system is windows
            arp_table = os.popen(f'arp -a -N {get_if_addr(conf.iface)}').read()
            dynamic_lines = [x for x in arp_table.split('\n') if 'dynamic' in x]
            self.mac_ip_pairs = [x.split()[-2::-1] for x in dynamic_lines]
        else:
            print("Your operating system is not supported, goodbye.\n")
            sys.exit(0)

    def suspicious_mac(self, pkt):
        """
        Comparing the received packet to a normal arp reply packet.
        :param pkt:
        :return:
            If the packet received is different from a normal arp reply packet - true.
            Otherwise - False.
        """
        real_reply = srp1(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=pkt[ARP].psrc, op=1), timeout=1, verbose=False)
        if real_reply and real_reply.haslayer(ARP) and real_reply[ARP].hwsrc != pkt[ARP].hwsrc:
            print(f'{Fore.LIGHTYELLOW_EX}[!] Warning: ARP reply source MAC is incorrect{Fore.RESET}')
            return True
        return False

    def cutting_network_connection(self, interface):
        """
        Cutting the network the device is on, and finally calling the function that renews the network back.
        :param interface: The interface of the network that is being cut.
        :return:
        """
        if os.name == "posix":  # If the operating system is UNIX
            subprocess.run("ifconfig " + interface + " down", shell=True)
        elif os.name == "nt":  # If the operating system is windows
            subprocess.run("netsh interface set interface " + interface + " disable", shell=True)
        else:
            print("Your operating system is not supported, goodbye.\n")
            sys.exit(0)

        print(f'{Fore.LIGHTRED_EX}[-] Someone is monitoring your network.'
              f' Your connection will restored in seconds{Fore.RESET}')
        time.sleep(15)
        self.restore_network(interface)

    def restore_network(self, interface):
        """
        Renewing the network that the attacked device is in.
        :param interface: The interface of the network that is being renewed
        :return:
        """
        if os.name == 'posix':  # If the operating system is UNIX
            subprocess.run("ifconfig " + interface + " up", shell=True)
        elif os.name == "nt":  # If the operating system is windows
            subprocess.run("netsh interface set interface " + interface + " enable", shell=True)
        else:
            print("Your operating system is not supported, goodbye.\n")
            sys.exit(0)

        print(f'{Fore.LIGHTGREEN_EX}[+] Restored Connection...{Fore.RESET}')
        print(
            f'{Fore.LIGHTGREEN_EX}[+] If you still be attacked then network will be disconnected again{Fore.RESET}')
        self.replys_sniffing()


def args_parser():
    """
    Parse the user's file args
    :return: parsed arguments
    """
    parser = argparse.ArgumentParser(description='ARP Spoof protector')
    parser.add_argument('-p', default=False, action='store_true', help='should prevent mode be used')
    return parser.parse_args()


def main():
    print(f"""{Fore.LIGHTBLUE_EX}                                                                          
=========================================================================================================                                                    
           _____  _____       _____                    __     _____           _            _             
     /\   |  __ \|  __ \     / ____|                  / _|   |  __ \         | |          | |            
    /  \  | |__) | |__) |   | (___  _ __   ___   ___ | |_    | |__) | __ ___ | |_ ___  ___| |_ ___  _ __ 
   / /\ \ |  _  /|  ___/     \___ \| '_ \ / _ \ / _ \|  _|   |  ___/ '__/ _ \| __/ _ \/ __| __/ _ \| '__|
  / ____ \| | \ \| |         ____) | |_) | (_) | (_) | |     | |   | | | (_) | ||  __/ (__| || (_) | |   
 /_/    \_\_|  \_\_|        |_____/| .__/ \___/ \___/|_|     |_|   |_|  \___/ \__\___|\___|\__\___/|_|   
                                   | |                                                                   
                                   |_|                                                                   
=========================================================================================================                                                    
    {Fore.RESET}""")
    try:
        arp_spoof_protector = ArpSpoofProtector(args_parser().p)
        threading.Thread(target=arp_spoof_protector.replys_sniffing(), args=()).start()
    except KeyboardInterrupt:
        print("Spoofing detection stopped by ctrl+c.\nGoodbye :)")
        arp_spoof_protector.restore_network(conf.iface)
        sys.exit(0)


if __name__ == '__main__':
    main()
