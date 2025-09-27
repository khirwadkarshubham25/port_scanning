import socket


class Commons:
    def __init__(self):
        pass

    @staticmethod
    def scan_port(host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)

            result = s.connect_ex((host, port))

            if result == 0:
                return True

            else:
                return False

        except socket.gaierror:
            print("Hostname could not be resolved. Exiting.")
            return -1

        except socket.error:
            print("Could not connect to server")
            return -1

        finally:
            s.close()
