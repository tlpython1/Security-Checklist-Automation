import nmap
import socket
import time
import subprocess
import re

def get_common_ports():
    """
    Return list of commonly familiar ports
    """
    return [
        # Web Services
        80,    # HTTP
        443,   # HTTPS
        8080,  # HTTP Alternative
        8070,  # HTTP Alternative
        8443,  # HTTPS Alternative
        8000,  # HTTP Development
        3000,  # Node.js/React Development
        4000,  # Development
        5000,  # Flask/Development
        9000,  # Various web services
        8009, #Python Commission,
        7000, #Php MyAdmin,
        
        # Remote Access
        22,    # SSH
        23,    # Telnet
        3389,  # RDP (Windows Remote Desktop)
        5900,  # VNC
        5901,  # VNC
        
        # Mail Services
        25,    # SMTP
        110,   # POP3
        143,   # IMAP
        993,   # IMAPS
        995,   # POP3S
        587,   # SMTP Submission
        465,   # SMTPS
        
        # Database Services
        3306,  # MySQL
        5432,  # PostgreSQL
        1521,  # Oracle
        1433,  # MS SQL Server
        27017, # MongoDB
        6379,  # Redis
        11211, # Memcached
        
        # File Transfer
        21,    # FTP
        20,    # FTP Data
        69,    # TFTP
        989,   # FTPS Data
        990,   # FTPS
        
        # Network Services
        53,    # DNS
        67,    # DHCP Server
        68,    # DHCP Client
        123,   # NTP
        161,   # SNMP
        162,   # SNMP Trap
        
        # Windows/SMB Services
        135,   # RPC
        139,   # NetBIOS
        445,   # SMB
        
        # Directory Services
        389,   # LDAP
        636,   # LDAPS
        
        # Other Common Services
        111,   # RPC
        113,   # Ident
        119,   # NNTP
        1723,  # PPTP
        1194,  # OpenVPN
        4444,  # Metasploit
        8888,  # Alternative HTTP
        9090,  # Various services
        10000, # Webmin
    ]

def check_ufw_status():
    """
    Check UFW firewall status and get all rules
    """
    try:
        result = subprocess.run(['ufw', 'status', 'numbered'], 
                              capture_output=True, text=True, check=True)
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def check_iptables_rules():
    """
    Check iptables rules for port access
    """
    try:
        result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], 
                              capture_output=True, text=True, check=True)
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def parse_ufw_rules_for_port(port):
    """
    Parse UFW rules for a specific port
    """
    ufw_output = check_ufw_status()
    if not ufw_output:
        return {"status": "ufw_not_available", "rules": []}
    
    port_rules = []
    lines = ufw_output.split('\n')
    
    for line in lines:
        line = line.strip()
        if str(port) in line and ('ALLOW' in line or 'DENY' in line):
            # Parse UFW rule
            if 'ALLOW' in line:
                action = 'ALLOW'
            elif 'DENY' in line:
                action = 'DENY'
            else:
                continue
            
            # Extract source IP/network
            parts = line.split()
            source = "Anywhere"
            
            # Look for IP addresses or networks in the rule
            for part in parts:
                if '/' in part and any(c.isdigit() for c in part):  # CIDR notation
                    source = part
                    break
                elif re.match(r'\d+\.\d+\.\d+\.\d+', part):  # IP address
                    source = part
                    break
            
            port_rules.append({
                'action': action,
                'source': source,
                'full_rule': line
            })
    
    return {
        "status": "active" if "Status: active" in ufw_output else "inactive",
        "rules": port_rules
    }

def check_port_accessibility(host, port):
    """
    Check which IPs can access a specific port
    """
    accessibility = {
        'globally_accessible': False,
        'restricted_ips': [],
        'firewall_rules': [],
        'firewall_type': 'none'
    }
    
    # Check UFW rules
    ufw_rules = parse_ufw_rules_for_port(port)
    
    if ufw_rules['status'] == 'active':
        accessibility['firewall_type'] = 'ufw'
        accessibility['firewall_rules'] = ufw_rules['rules']
        
        for rule in ufw_rules['rules']:
            if rule['action'] == 'ALLOW':
                if rule['source'] == 'Anywhere' or rule['source'] == '0.0.0.0/0':
                    accessibility['globally_accessible'] = True
                else:
                    accessibility['restricted_ips'].append(rule['source'])
    
    # If no UFW rules found, check if port is generally accessible
    if not ufw_rules['rules']:
        # Assume globally accessible if no firewall rules found
        accessibility['globally_accessible'] = True
        accessibility['firewall_rules'].append({
            'action': 'ALLOW',
            'source': 'Anywhere (No specific firewall rule found)',
            'note': 'Default behavior - verify manually'
        })
    
    return accessibility

def get_listening_ports_fast(host):
    """
    Fast scan using nmap - common familiar ports only with accessibility check
    """
    common_ports = get_common_ports()
    port_list = ','.join(map(str, common_ports))
    
    print(f"Fast scanning {host} ({len(common_ports)} common ports)...")
    start_time = time.time()
    
    try:
        # Resolve hostname to IP
        host_ip = socket.gethostbyname(host)
        print(f"Resolved {host} to {host_ip}")
    except socket.gaierror:
        return {"error": f"Unable to resolve host: {host}"}
    
    try:
        # Initialize nmap scanner
        nm = nmap.PortScanner()
        
        # Fast scan of specific common ports
        scan_result = nm.scan(host_ip, arguments=f'-p {port_list} -T4 -sV')
        
        # Extract open ports
        open_ports = []
        port_details = {}
        
        if host_ip in nm.all_hosts():
            for protocol in nm[host_ip].all_protocols():
                ports = nm[host_ip][protocol].keys()
                for port in ports:
                    port_info = nm[host_ip][protocol][port]
                    if port_info['state'] == 'open':
                        open_ports.append(port)
                        
                        # Check port accessibility
                        print(f"Checking accessibility for port {port}...")
                        accessibility = check_port_accessibility(host, port)
                        
                        port_details[port] = {
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'service_description': get_port_description(port),
                            'accessibility': accessibility
                        }
        
        # Check overall firewall status
        ufw_status = check_ufw_status()
        firewall_info = {
            'ufw_active': "Status: active" in ufw_status if ufw_status else False,
            'firewall_detected': ufw_status is not None
        }
        
        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)
        
        result = {
            'host': host,
            'host_ip': host_ip,
            'scan_type': f'Fast ({len(common_ports)} Common Ports)',
            'total_ports_scanned': len(common_ports),
            'open_ports': sorted(open_ports),
            'total_open_ports': len(open_ports),
            'port_details': port_details,
            'firewall_info': firewall_info,
            'scan_duration_seconds': scan_duration,
            'scanned_ports': common_ports
        }
        
        print(f"Fast scan completed in {scan_duration} seconds")
        print(f"Found {len(open_ports)} open ports: {sorted(open_ports)}")
        
        return result
        
    except Exception as e:
        return {"error": f"Nmap scan failed: {str(e)}"}

def scan_host(host, scan_type='fast'):
    """
    Scan the host based on the specified scan type.
    """
    if scan_type == 'fast':
        return get_listening_ports_fast(host)
    else:
        return {"error": f"Unsupported scan type: {scan_type}"}

def get_port_description(port):
    """
    Get description for common ports
    """
    descriptions = {
        20: 'FTP Data Transfer',
        21: 'File Transfer Protocol (FTP)',
        22: 'Secure Shell (SSH)',
        23: 'Telnet',
        25: 'Simple Mail Transfer Protocol (SMTP)',
        53: 'Domain Name System (DNS)',
        67: 'DHCP Server',
        68: 'DHCP Client',
        69: 'Trivial File Transfer Protocol (TFTP)',
        80: 'Hypertext Transfer Protocol (HTTP)',
        110: 'Post Office Protocol v3 (POP3)',
        111: 'Remote Procedure Call (RPC)',
        113: 'Ident Protocol',
        119: 'Network News Transfer Protocol (NNTP)',
        123: 'Network Time Protocol (NTP)',
        135: 'Microsoft RPC',
        139: 'NetBIOS Session Service',
        143: 'Internet Message Access Protocol (IMAP)',
        161: 'Simple Network Management Protocol (SNMP)',
        162: 'SNMP Trap',
        389: 'Lightweight Directory Access Protocol (LDAP)',
        443: 'HTTP Secure (HTTPS)',
        445: 'Server Message Block (SMB)',
        465: 'SMTP Secure (SMTPS)',
        587: 'SMTP Submission',
        636: 'LDAP Secure (LDAPS)',
        989: 'FTP Data Secure',
        990: 'FTP Secure (FTPS)',
        993: 'IMAP Secure (IMAPS)',
        995: 'POP3 Secure (POP3S)',
        1194: 'OpenVPN',
        1433: 'Microsoft SQL Server',
        1521: 'Oracle Database',
        1723: 'Point-to-Point Tunneling Protocol (PPTP)',
        3000: 'Development Server (Node.js/React)',
        3306: 'MySQL Database',
        3389: 'Remote Desktop Protocol (RDP)',
        4000: 'Development Server',
        4444: 'Metasploit/Various Services',
        5000: 'Development Server (Flask/Python)',
        5432: 'PostgreSQL Database',
        5900: 'Virtual Network Computing (VNC)',
        5901: 'VNC Server',
        6379: 'Redis Database',
        8000: 'HTTP Development Server',
        8080: 'HTTP Alternative',
        8443: 'HTTPS Alternative',
        8888: 'HTTP Alternative',
        9000: 'Various Web Services',
        9090: 'Various Services',
        10000: 'Webmin Administration',
        11211: 'Memcached',
        27017: 'MongoDB Database'
    }
    return descriptions.get(port, 'Unknown Service')

def print_scan_results_with_accessibility(scan_result):
    """
    Print formatted scan results including accessibility information
    """
    if 'error' in scan_result:
        print(f"Error: {scan_result['error']}")
        return
    
    print(f"\n{'='*80}")
    print(f"PORT SCAN RESULTS WITH ACCESSIBILITY FOR {scan_result['host']}")
    print(f"{'='*80}")
    print(f"Host IP: {scan_result['host_ip']}")
    print(f"Scan Type: {scan_result['scan_type']}")
    print(f"Total Ports Scanned: {scan_result['total_ports_scanned']}")
    print(f"Open Ports Found: {scan_result['total_open_ports']}")
    print(f"Firewall Detected: {scan_result['firewall_info']['firewall_detected']}")
    print(f"UFW Active: {scan_result['firewall_info']['ufw_active']}")
    print(f"Scan Duration: {scan_result['scan_duration_seconds']} seconds")
    
    if scan_result['open_ports']:
        print(f"\nOPEN PORTS WITH ACCESSIBILITY DETAILS:")
        print("-" * 80)
        
        for port in scan_result['open_ports']:
            details = scan_result['port_details'][port]
            accessibility = details['accessibility']
            
            # Service info
            service_info = f"{details['service']}"
            if details['version']:
                service_info += f" {details['version']}"
            if details['product']:
                service_info += f" ({details['product']})"
            
            print(f"\nPort {port:5d}/{details['protocol']:3s} - {service_info}")
            print(f"  Description: {details['service_description']}")
            
            # Accessibility info
            if accessibility['globally_accessible']:
                print(f"  🌐 GLOBALLY ACCESSIBLE (0.0.0.0/0)")
            else:
                print(f"  🔒 RESTRICTED ACCESS")
            
            if accessibility['restricted_ips']:
                print(f"  Allowed IPs/Networks: {', '.join(accessibility['restricted_ips'])}")
            
            # Firewall rules
            if accessibility['firewall_rules']:
                print(f"  Firewall Rules ({accessibility['firewall_type'].upper()}):")
                for rule in accessibility['firewall_rules']:
                    print(f"    - {rule['action']} from {rule['source']}")
                    if 'note' in rule:
                        print(f"      Note: {rule['note']}")
            else:
                print(f"  ⚠️  No specific firewall rules found")
    else:
        print("\nNo open ports found.")

# Enhanced utility function
def get_port_accessibility_summary(host, scan_type='fast'):
    """
    Get summary of port accessibility
    """
    result = scan_host(host, scan_type)
    
    if 'error' in result:
        return result
    
    summary = {
        'host': result['host'],
        'total_open_ports': result['total_open_ports'],
        'globally_accessible_ports': [],
        'restricted_ports': [],
        'firewall_protected_ports': []
    }
    
    for port, details in result['port_details'].items():
        accessibility = details['accessibility']
        
        if accessibility['globally_accessible']:
            summary['globally_accessible_ports'].append(port)
        
        if accessibility['restricted_ips']:
            summary['restricted_ports'].append({
                'port': port,
                'allowed_ips': accessibility['restricted_ips']
            })
        
        if accessibility['firewall_rules']:
            summary['firewall_protected_ports'].append(port)
    
    return summary