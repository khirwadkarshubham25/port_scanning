import concurrent.futures
import ipaddress
import logging
import socket

import ping3
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort


class Commons:
    def __init__(self, start_port, end_port):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.timeout = 2
        self.max_workers = 50
        self.ports = list(range(start_port, end_port))

    def scan_port(self, host, port):
        try:
            self.logger.debug("Initializing the socket")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)

            self.logger.debug("Sending the connection.")
            result = s.connect_ex((host, port))

            if result == 0:
                return True

            else:
                return False

        except socket.gaierror as e:
            self.logger.debug(f"Hostname could not be resolved. Exiting\nError:\n{e}.")
            return -1

        except socket.error as e:
            self.logger.debug(f"Could not connect to server. Exiting\nError:\n{e}")
            return -1

        finally:
            self.logger.debug("Closing the socket")
            s.close()

    def resolve_domain_name(self, domain):
        try:
            self.logger.debug("Getting the hostname using the socket.")
            ip_address = socket.gethostbyname(domain)
            return ip_address

        except socket.gaierror as e:
            self.logger.debug(f"Domain name {domain} could not be resolved. Exiting\nError:\n{e}.")
            return -1

        except Exception as e:
            self.logger.debug(f"An unexcepted error occurred. Exiting\nError:\n{e}")
            return -1

    def get_ip_list(self, ip, start_ip, end_ip):
        ip_list = []
        if ip is not None and "/" in ip:
            try:
                network = ipaddress.ip_network(ip, strict=False)
                for _ip in network.hosts():
                    ip_list.append(str(_ip))

                self.logger.debug(f"Returning the list of IP Addresses based on the input {ip}")
                return ip_list
            except ValueError as e:
                self.logger.debug(f"Invalid Input. Error:\n{e}")

        elif ip is not None and "/" not in ip:
            try:
                ip = ipaddress.ip_address(ip)

                self.logger.debug(f"Returning the single IP Address based on the input {ip}")
                return [ip]
            except ValueError as e:
                self.logger.debug(f"Invalid Input. Error:\n{e}")
                return []

        elif start_ip is not None and end_ip is not None:
            try:
                start_ip = ipaddress.ip_network(start_ip.strip())
                end_ip = ipaddress.ip_network(end_ip.strip())

                if start_ip > end_ip:
                    start_ip, end_ip = end_ip, start_ip

                while start_ip <= end_ip:
                    ip_list.append(str(start_ip))
                    start_ip = ipaddress.ip_address(int(start_ip) + 1)

                self.logger.debug(f"Returning the list of IP Addresses between start ip: {start_ip} and end ip: {end_ip}")
                return ip_list

            except ValueError as e:
                self.logger.debug(f"Invalid Input. Error:\n{e}")

        else:
            self.logger.debug("No input provided. Please provide input")
            return -1

    def send_pings(self, target_ips):
        hosts = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as exec:
            ping_all_ips = {exec.submit(self.ping_ip, ip) : ip for ip in target_ips}

            for ping in ping_all_ips:
                ip, is_reachable = ping.result()

                if is_reachable:
                    hosts.append(ip)
        return hosts

    def ping_ip(self, ip):
        try:
            self.logger.debug(f"Sending Ping to {ip}")
            delay = ping3.ping(ip, timeout=self.timeout)

            is_reachable = isinstance(delay, float)
            self.logger.debug(f"Ping to IP Address: {ip} is {'reachable.' if is_reachable else 'not reachable.'}")

            return ip, is_reachable

        except Exception as e:
            self.logger.debug(f"Error in ping {ip}. Error\n{e}")
            return  -1, False

    def port_scan_stealth_check(self, ip):
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as exec:
            future_to_port = {
                exec.submit(self.syn_scan_port, ip, port): port
                for port in self.ports
            }

            for future in future_to_port:
                port, status = future.result()
                results[port] = status
        return results

    def syn_scan_port(self, ip, port):
        ip_layer = IP(dst=ip)
        tcp_layer = TCP(dport=port, sport=RandShort(), flags='S')

        packet = ip_layer / tcp_layer

        try:
            self.logger.debug(f"Sending packet with ip: {ip} and port:{port}")
            res = sr1(packet, timeout=self.timeout, verbose=0)

            if res is None:
                self.logger.debug("The port status is filtered")
                return port, "filtered"

            if res.haslayer(TCP):
                tcp_flags = res[TCP].flags

                if tcp_flags == 0x12:
                    sr1(IP(dst=ip)/TCP(dport=port, flags='R'), timeout=0, verbose=0)
                    self.logger.debug("The port status is open")
                    return port, "open"

                elif tcp_flags == 0x14:
                    self.logger.debug("The port status is close")
                    return port, "closed"
            self.logger.debug("The port status is filtered")
            return port, "filtered"

        except Exception as e:
            self.logger.debug(f"Scapy exception during scan of {ip}:{port}: {e}")
            self.logger.debug("The port status is error")
            return port, "error"

    def perform_xmas_fin_null_scan(self, ip, flag):
        open_ports, closed_ports, filter_ports, error_ports = [], [], [], []
        for port in self.ports:
            self.logger.debug(f"Sending the packets to {ip}:{port} and with {flag}")
            xmas_packet = IP(dst=ip) / TCP(dport=port, flags=flag)

            response = sr1(xmas_packet, timeout=self.timeout)

            if response is None:
                open_ports.append(port)
                self.logger.debug(f"[Open | Filtered]: Port {port}")

            elif response.haslayer(TCP):
                if response[TCP].flags == 0x04:
                    self.logger.debug(f"[Closed]          : Port {port}")
                    closed_ports.append(port)
                else:
                    self.logger.debug(f"[Unexpected Flag] : Port {port} (Flags: {response[TCP].flags})")
                    error_ports.append(port)

            elif response.haslayer(ICMP):
                icmp_type = response[ICMP].type
                icmp_code = response[ICMP].code
                self.logger.debug(f"[Filtered (ICMP)] : Port {port} (ICMP Type {icmp_type}, Code {icmp_code})")
                filter_ports.append(port)

        return open_ports, closed_ports, filter_ports, error_ports

    def icmp_sweep(self, target_ips):
        hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all check_host tasks to the executor
            future_to_ip = {executor.submit(self.check_host, ipaddress.IPv4Address(ip)): ip for ip in target_ips}

            for future in future_to_ip:
                ip, is_alive = future.result()
                if is_alive:
                    hosts.append(ip)
        return hosts

    def check_host(self, ip):
        self.logger.debug(f"Sending ICMP packets to {ip}")
        packet = IP(dst=str(ip)) / ICMP()
        response = sr1(packet, timeout=self.timeout)

        if response:
            if response.haslayer(ICMP) and response[ICMP].type == 0:
                self.logger.debug(f"ICMP packets to IP Address: {ip} is reachable.")
                return str(ip), True

        self.logger.debug(f"ICMP packets to IP Address: {ip} is not reachable.")
        return str(ip), False