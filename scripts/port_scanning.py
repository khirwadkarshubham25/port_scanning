import argparse
import ipaddress
import logging
import os
import platform
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.commons import Commons

class PortFiltering(Commons):
    def __init__(self):
        super().__init__("Commons Class")
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.debug("Initializing the port scanning script")


    def main(self):
        self.clear_cli()
        cli_args = self.take_cli_options()
        option = self.show_all_options()

        if option == 0:
            self.logger.debug(f"Option chosen: {option}. Exiting the port scanning script.")
            print("Exiting the scanning")

        if option == 1:
            self.logger.debug(f"Option chosen: {option}. Scanning all the ports in the system, also known as Vanilla Scan")
            self.scan_all_ports(**cli_args)

        if option == 2:
            self.logger.debug(f"Option chosen: {option}. Resolving the domain name")
            self.resolve_domain(**cli_args)

        if option == 3:
            self.logger.debug(f"Option chosen: {option}. Performing Ping scan")
            self.ping_scan(**cli_args)

        if option == 4:
            self.logger.debug(f"Option chosen: {option}. Performing SYN Scan also know as TCP health scan")
            self.syn_port_scan_stealth_check(**cli_args)

    def clear_cli(self):
        if platform.system() == 'Windows':
            self.logger.debug(f"Operating system is {platform.system()}")
            os.system("cls")
            self.logger.debug("Cleared cli using command: cls")

        elif platform.system() == 'Linux' or platform.system() == 'Darwin':
            self.logger.debug(f"Operating system is {platform.system()}")
            os.system("clear")
            self.logger.debug("Cleared cli using command: clear")

        else:
            self.logger.debug(f"Unknown operating system {platform.system()}")

    def take_cli_options(self):
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
        self.logger.debug(f"Arguments Passed: {args_dict}")
        return args_dict

    def show_all_options(self):
        print('Select the type of operation you would like to perform:\n'
              '0: Exit\n'
              '1: Scan All Ports or Vanilla Scan\n'
              '2: Resolve\n'
              '3: Ping Scan\n'
              '4: SYN Scan or TCP stealth scan')

        user_scan_choice = input("Your choice: ")
        choices = ["0", "1", "2", "3", "4"]
        if user_scan_choice in choices:
            self.logger.debug(f"The operation that you have decided to perform is {user_scan_choice}")
            return int(user_scan_choice)

        else:
            self.logger.debug("Invalid Choice. Choose again.")
            print('Invalid Choice. Choose again')
            self.show_all_options()

        return None

    def scan_all_ports(self, *args, **kwargs):
        host = kwargs.get("ip")
        self.logger.debug(f"Host: {host}")
        if "/" in host:
            host = host.split("/")[0]

        open_ports = []
        closed_ports = []
        self.logger.debug("Starting the port scan")
        for port in self.ports:
            self.logger.debug(f"Port: {port}")
            scan = self.scan_port(host, port)
            if scan == -1:
                self.logger.debug("Error occurred during scanning.")

            elif scan:
                open_ports.append(port)
            else:
                closed_ports.append(port)

        self.logger.debug(f"Open Port: {open_ports}")
        self.logger.debug(f"Closed Port: {closed_ports}")

    def resolve_domain(self, *args, **kwargs):
        self.logger.debug(f"Domain name: {kwargs.get('domain')}")
        ip_address = self.resolve_domain_name(kwargs.get("domain"))
        if ip_address == -1:
            self.logger.debug("Error in resolving domain")

        elif ip_address:
            self.logger.debug(f"Domain Name: {kwargs.get('domain')}")
            self.logger.debug(f"IP Address (IPv4): {ip_address}")

        else:
            self.logger.debug(f"Resolution failed for domain {kwargs.get('domain')}")

    def ping_scan(self, *args, **kwargs):
        self.logger.debug(f"IP Address: {kwargs.get('ip')}")
        self.logger.debug(f"Start IP Address: {kwargs.get('start_ip')} | End IP Address: {kwargs.get('end_ip')}")
        self.logger.debug("Getting IPs based on inputs")
        target_ips = self.get_ip_list(kwargs.get("ip"), kwargs.get("start_ip"), kwargs.get("end_ip"))
        self.logger.debug(f"The Target IP Addresses are: {target_ips}")

        if target_ips == -1:
            self.logger.debug("Incorrect inputs")
        else:
            self.logger.info("Starting sending IP ping")
            hosts = self.send_pings(target_ips)

            self.logger.debug(f"Scan finished. Total targets: {len(target_ips)}")
            self.logger.debug(f"Total live hosts found: {len(hosts)}")

            self.logger.debug(f"Hosts found : {','.join(sorted(hosts, key=ipaddress.ip_address))}")

    def syn_port_scan_stealth_check(self, **kwargs):
        self.logger.debug("Starting the SYN Scan or TCP health check")
        results = self.port_scan_stealth_check(kwargs.get("ip"))
        open_ports = [p for p, s in results.items() if s == 'open']
        closed_ports = [p for p, s in results.items() if s == 'closed']
        filtered_ports = [p for p, s in results.items() if s == 'filtered']

        self.logger.debug(f"Total ports scanned: {len(self.ports)}")

        if open_ports:
            self.logger.debug(f"OPEN Ports ({len(open_ports)}): {', '.join(map(str, sorted(open_ports)))}")

        if filtered_ports:
            self.logger.debug(f"FILTERED Ports ({len(filtered_ports)}): {', '.join(map(str, sorted(filtered_ports)))} Firewall likely dropping packets")

        self.logger.debug(f"CLOSED Ports ({len(closed_ports)}): Displayed only if necessary or requested.")


def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s | %(levelname)-8s | %(name)-15s | Line %(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler("Port_Scanning.log", mode="w")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | Line %(lineno)d | %(message)s"))

    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)

if __name__ == '__main__':
    setup_logging()
    PortFiltering().main()