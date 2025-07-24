import nmap
import socket
import time
import subprocess
import re

def get_common_ports():
    """
    Return list of most critical ports for fast scanning (24 essential ports)
    """
    return [
        # Essential Web Services (9 ports)
        80,    # HTTP
        443,   # HTTPS
        8080,  # HTTP Alternative
        8000,  # HTTP Development
        3000,  # Node.js/Laravel
        5000,  # Flask/Development
        8009,  # Python Commission
        8001,  # MySQL in Docker
        7000,  # PhpMyAdmin
        
        # Critical Remote Access (2 ports)
        22,    # SSH
        3389,  # RDP (Windows Remote Desktop)
        
        # Essential Database Services (4 ports)
        3306,  # MySQL
        5432,  # PostgreSQL
        27017, # MongoDB
        6379,  # Redis
        
        # Critical Mail Services (2 ports)
        25,    # SMTP
        587,   # SMTP Submission
        
        # File Transfer (1 port)
        21,    # FTP
        
        # Network Services (1 port)
        53,    # DNS
        
        # Windows/SMB Services (1 port)
        445,   # SMB
        
        # Additional common ports (4 ports)
        23,    # Telnet
        4000,  # Development/Ecom
        9000,  # Various web services
        8443,  # HTTPS Alternative
    ]

def get_all_ports():
    """
    Return extended list of ports for comprehensive scanning
    """
    return [
        # Web Services
        80, 443, 8080, 8070, 8443, 8000, 3000, 4000, 5000, 9000, 8009, 8001, 7000,
        
        # Remote Access
        22, 23, 3389, 5900, 5901,
        
        # Mail Services
        25, 110, 143, 993, 995, 587, 465,
        
        # Database Services
        3306, 5432, 1521, 1433, 27017, 6379, 6383, 11211,
        
        # File Transfer
        21, 20, 69, 989, 990,
        
        # Network Services
        53, 67, 68, 123, 161, 162,
        
        # Windows/SMB Services
        135, 139, 445,
        
        # Directory Services
        389, 636,
        
        # Other Common Services
        111, 113, 119, 1723, 1194, 4444, 8888, 9090, 10000,
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
    Fast scan using nmap - essential ports only with optimized scanning
    """
    common_ports = get_common_ports()
    port_list = ','.join(map(str, common_ports))
    
    print(f"Fast scanning {host} ({len(common_ports)} essential ports)...")
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
        
        # Fast scan without service version detection for speed
        # Using -T5 for fastest timing and removing -sV for speed
        scan_result = nm.scan(host_ip, arguments=f'-p {port_list} -T5 --min-rate=1000')
        
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
                        
                        port_details[port] = {
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'service_description': get_port_description(port),
                            # Skip individual accessibility checks for speed, but provide basic structure
                            'accessibility': {
                                'globally_accessible': True,  # Default assumption for fast scan
                                'restricted_ips': [],
                                'firewall_rules': [],
                                'firewall_type': 'none',
                                'note': 'Fast scan mode - use comprehensive scan for detailed accessibility analysis'
                            }
                        }
        
        # Get overall firewall status once (not per port)
        ufw_status = check_ufw_status()
        firewall_info = {
            'ufw_active': "Status: active" in ufw_status if ufw_status else False,
            'firewall_detected': ufw_status is not None,
            'ufw_output': ufw_status if ufw_status else "UFW not available"
        }
        
        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)
        
        result = {
            'host': host,
            'host_ip': host_ip,
            'scan_type': f'Fast ({len(common_ports)} Essential Ports)',
            'total_ports_scanned': len(common_ports),
            'open_ports': sorted(open_ports),
            'total_open_ports': len(open_ports),
            'port_details': port_details,
            'firewall_info': firewall_info,
            'scan_duration_seconds': scan_duration,
            'scanned_ports': common_ports,
            'note': 'Fast scan mode - use comprehensive scan for detailed analysis'
        }
        
        print(f"Fast scan completed in {scan_duration} seconds")
        print(f"Found {len(open_ports)} open ports: {sorted(open_ports)}")
        
        return result
        
    except Exception as e:
        return {"error": f"Nmap scan failed: {str(e)}"}

def get_listening_ports_comprehensive(host):
    """
    Comprehensive scan with full service detection and accessibility analysis
    """
    all_ports = get_all_ports()
    port_list = ','.join(map(str, all_ports))
    
    print(f"Comprehensive scanning {host} ({len(all_ports)} ports)...")
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
        
        # Comprehensive scan with service version detection
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
                        
                        # Check port accessibility for comprehensive scan
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
            'firewall_detected': ufw_status is not None,
            'ufw_output': ufw_status if ufw_status else "UFW not available"
        }
        
        end_time = time.time()
        scan_duration = round(end_time - start_time, 2)
        
        result = {
            'host': host,
            'host_ip': host_ip,
            'scan_type': f'Comprehensive ({len(all_ports)} Ports)',
            'total_ports_scanned': len(all_ports),
            'open_ports': sorted(open_ports),
            'total_open_ports': len(open_ports),
            'port_details': port_details,
            'firewall_info': firewall_info,
            'scan_duration_seconds': scan_duration,
            'scanned_ports': all_ports
        }
        
        print(f"Comprehensive scan completed in {scan_duration} seconds")
        print(f"Found {len(open_ports)} open ports: {sorted(open_ports)}")
        
        return result
        
    except Exception as e:
        return {"error": f"Nmap scan failed: {str(e)}"}

def scan_host(host, scan_type='fast'):
    """
    Scan the host based on the specified scan type.
    - fast: Quick scan of essential ports only (22-25 ports)
    - comprehensive: Detailed scan with service detection and accessibility analysis
    """
    if scan_type == 'fast':
        return get_listening_ports_fast(host)
    elif scan_type == 'comprehensive':
        return get_listening_ports_comprehensive(host)
    else:
        return {"error": f"Unsupported scan type: {scan_type}. Use 'fast' or 'comprehensive'."}

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
        accessibility = details.get('accessibility', {})
        
        # Safely check for globally_accessible with default fallback
        if accessibility.get('globally_accessible', False):
            summary['globally_accessible_ports'].append(port)
        
        # Safely check for restricted_ips
        restricted_ips = accessibility.get('restricted_ips', [])
        if restricted_ips:
            summary['restricted_ports'].append({
                'port': port,
                'allowed_ips': restricted_ips
            })
        
        # Safely check for firewall_rules
        firewall_rules = accessibility.get('firewall_rules', [])
        if firewall_rules:
            summary['firewall_protected_ports'].append(port)
    
    return summary