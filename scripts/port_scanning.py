import argparse
import ipaddress
import os
import platform
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.commons import Commons

class PortFiltering(Commons):
    def __init__(self):
        super().__init__()
        self.ports = list(range(1, 65535))

    def main(self):
        self.clear_cli()
        cli_args = self.take_cli_options()
        option = self.show_all_options()

        if option == 0:
            print('Exiting the scanning')

        if option == 1:
            self.scan_all_ports(**cli_args)

        if option == 2:
            self.resolve_domain(**cli_args)

        if option == 3:
            self.ping_scan(**cli_args)

    @staticmethod
    def clear_cli():
        if platform.system() == 'Windows':
            os.system("cls")

        elif platform.system() == 'Linux' or platform.system() == 'Darwin':
            os.system("clear")

        else:
            print(f"Unknown operating system: {platform.system()}")

    @staticmethod
    def take_cli_options():
        parser = argparse.ArgumentParser(description="This script is user for scanning the ports")

        parser.add_argument(
            "-ip", "--ipaddress",
            dest="ip",
            type=str
        )

        parser.add_argument(
            "-d", "--domain",
            dest="domain",
            type=str,
            default="www.google.com"
        )

        parser.add_argument(
            "-s", "--startIp",
            dest="start_ip",
            type=str
        )

        parser.add_argument(
            "-e", "--endIp",
            dest="end_ip",
            type=str
        )

        args = parser.parse_args()

        args_dict = vars(args)

        return args_dict

    def show_all_options(self):
        print('Select the type of operation you would like to perform:\n'
              '0: Exit\n'
              '1: Scan All Ports or Vanilla Scan\n'
              '2: Resolve\n'
              '3: Ping Scan\n'
              '4: ')
        user_scan_choice = input("Your choice: ")
        choices = ["0", "1", "2", "3"]
        if user_scan_choice in choices:
            return int(user_scan_choice)

        else:
            print('Invalid Choice. Choose again')
            self.show_all_options()

        return None

    def scan_all_ports(self, *args, **kwargs):
        host = kwargs.get("ip")
        if "/" in host:
            host = host.split("/")[0]

        open_ports = []
        closed_ports = []
        for port in self.ports:
            scan = self.scan_port(host, port)
            if scan == -1:
                print("Error in scanning")

            elif scan:
                open_ports.append(port)

            else:
                closed_ports.append(port)

    def resolve_domain(self, *args, **kwargs):
        ip_address = self.resolve_domain_name(kwargs.get("domain"))
        if ip_address == -1:
            print("Error in resolving domain")

        elif ip_address:
            print(f"Domain Name: {kwargs.get('domain')}")
            print(f"IP Address (IPv4): {ip_address}")

        else:
            print(f"Resolution failed for domain {kwargs.get('domain')}")

    def ping_scan(self, *args, **kwargs):
        target_ips = self.get_ip_list(kwargs.get("ip"), kwargs.get("start_ip"), kwargs.get("end_ip"))

        if target_ips == -1:
            print("Incorrect inputs")

        else:
            hosts = self.send_pings(target_ips)

            print(f"Scan finished. Total targets: {len(target_ips)}")
            print(f"Total live hosts found: {len(hosts)}")

            for host in sorted(hosts, key=ipaddress.ip_address):
                print(host)



if __name__ == '__main__':
    PortFiltering().main()