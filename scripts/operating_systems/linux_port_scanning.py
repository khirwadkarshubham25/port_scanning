from scripts.commons import Commons


class LinuxPortFiltering:
    def __init__(self, *args, **kwargs):
        print(args, kwargs)
        self.ports = list(range(1, 10001))
        self.target_ip = kwargs.get('target_ip_address')

    def run(self):
        option = self.show_all_options()

        if option == 0:
            print('Exiting the scanning')

        self.select_option(option)

    def show_all_options(self):
        print('Select the type of scan you would like to perform:\n1: Scan All Ports\n0: Exit\n')
        user_scan_choice = input("Your choice: ")
        choices = ["0", "1"]
        if user_scan_choice in choices:
            return user_scan_choice

        else:
            print('Invalid Choice. Choose again')
            self.show_all_options()

        return None


    def select_option(self, option):
        if option == "1":
            self.scan_all_ports()


    def scan_all_ports(self):
        for port in self.ports:
            if Commons.scan_port(self.target_ip, port):
                print(f'Port {port} : Open')

            else:
                print(f'Port {port} : Close')

