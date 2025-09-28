# Port Scanning

--------------------------------------------------------------------------
Port scanning is a fundamental network reconnaissance technique used to systematically probe a network range 
or host to determine the status of its communication ports. For security professionals this process is essential for 
mapping a system's attack surface and identifying potential vulnerabilities.

### Port Status Definitions
When a port is scanned, it will typically return one of three states:
1. Open: A service is actively listening on the port.
2. Closed: The host received the probe, but no service is listening on that port.
3. Filtered: The host did not respond to the probe, indicating that a firewall (or port filter) is dropping the packets.

### The Role of Port Filtering
Port filtering is used by firewalls and routers to control data traffic based on its port number. Its critical purpose is 
to block inbound traffic to thousands of unused ports, enforcing organizational rules and preventing automated 
discovery and exploitation of internal services.

### Common Scan Types
Security analysts use various scan types, often automated, to audit network defenses and verify security policies:
1. TCP Connect Scan (Full-Open)
2. TCP SYN Scan (Stealth/Half-Open)
3. FIN, NULL, and Xmas Scans (Stealth Evasion Techniques)
4. Sweep Scan

This project is an automation of different types of port scanning operations. In this project we are performing 
following operations
1. Full Scan
2. Resolve
3. Ping Scan
4. SYN Scan or TCP stealth scan
5. XMAS Scan 
6. FIN Scan
7. NULL Scan 
8. Sweep Scan

-------------------------------------------------------------------------------

## How To Run

1. Open Terminal and clone the git repository

    
    git clone https://github.com/khirwadkarshubham25/cybersec.git

2. Move to the working directory

    
    cd cybersec

3. Install Requirements


    pip install -r requirements.txt

4. To perform operations use below commands


    sudo python scripts/port_scanning.py -ip 192.168.1.0/24
    sudo python scripts/port_scanning.py -ip 192.168.1.0
    sudo python scripts/port_scanning.py -d www.google.com
    sudo python scripts/port_scanning.py -s 192.168.1.0 -e 192.168.1.20
    sudo python scripts/port_scanning.py -sp 20 -ep 100


-------------------------------------------------------------------------------
### References

https://www.fortinet.com/resources/cyberglossary/what-is-port-scan