import concurrent.futures
import ipaddress
import socket

import ping3


class Commons:
    def __init__(self):
        self.timeout = 2
        self.max_workers = 50

    def scan_port(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)

            result = s.connect_ex((host, port))

            if result == 0:
                return True

            else:
                return False

        except socket.gaierror as e:
            print(f"Hostname could not be resolved. Exiting\nError:\n{e}.")
            return -1

        except socket.error as e:
            print(f"Could not connect to server. Exiting\nError:\n{e}")
            return -1

        finally:
            s.close()

    @staticmethod
    def resolve_domain_name(domain):
        try:
            ipaddress = socket.gethostbyname(domain)
            return ipaddress

        except socket.gaierror as e:
            print(f"Domain name {domain} could not be resolved. Exiting\nError:\n{e}.")
            return -1

        except Exception as e:
            print(f"An unexcepted error occurred. Exiting\nError:\n{e}")
            return -1

    @staticmethod
    def get_ip_list(ip, start_ip, end_ip):
        ip_list = []
        if ip is not None and "/" in ip:
            try:
                network = ipaddress.ip_network(ip, strict=False)
                for ip in network.hosts():
                    ip_list.append(str(ip))

                return ip_list
            except ValueError as e:
                print(f"Invalid Input. Error:\n{e}")

        elif ip is not None and "/" not in ip:
            try:
                ip = ipaddress.ip_address(ip)
                return [ip]
            except ValueError as e:
                print(f"Invalid Input. Error:\n{e}")
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

                return ip_list

            except ValueError as e:
                print(f"Invalid Input. Error:\n{e}")

        else:
            print("No input provided. Please provide input")
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
            delay = ping3.ping(ip, timeout=self.timeout)

            is_reachable = isinstance(delay, float)

            return ip, is_reachable

        except Exception as e:
            print(f"Error in ping {ip}. Error\n{e}")
            return  -1, False