import argparse
import logging
import os
import platform
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.operating_systems.linux_port_scanning import LinuxPortFiltering

class PortFiltering:
    def __init__(self):
        pass

    def run(self):
        options = self.take_cli_options()
        system_name = platform.system()
        if system_name == 'Windows':
            print("This is a Windows machine.")
            # Example command: os.system('dir')
        elif system_name == 'Darwin':
            print("This is a macOS machine.")
            # Example command: os.system('ls')
        elif system_name == 'Linux':
            print("This is a Linux machine.")
            LinuxPortFiltering(**options).run()
        else:
            print(f"Unknown operating system: {system_name}")

    @staticmethod
    def take_cli_options():
        parser = argparse.ArgumentParser(description="This script is user for scanning the ports")

        parser.add_argument(
            "-t_ip", "--target_ipaddress",
            dest="target_ip_address",
            type=str,
            default='localhost'
        )

        args = parser.parse_args()

        args_dict = vars(args)

        return args_dict

if __name__ == '__main__':
    PortFiltering().run()