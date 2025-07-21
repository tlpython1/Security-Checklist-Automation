import socket
import nmap

def scan_ports(host):
    open_ports = []
    # Extended common ports including AWS/cloud services
    common_ports = [
        # Standard ports
        22, 80, 443, 8080, 3306, 5432, 6379, 27017,
        # AWS common ports
        8443, 9200, 9300, 5601, 3000, 8000, 8888, 9000,
        # Database ports
        1433, 3389, 5984, 6379, 11211, 50070,
        # Application ports
        4000, 5000, 6000, 7000, 8001, 8002, 8003, 8004, 8005,
        9001, 9002, 9003, 9004, 9005, 9090, 9091, 9092, 9093
    ]
    try:
        host_ip = socket.gethostbyname(host)  # Resolve hostname to IP
    except socket.gaierror:
        return f"Unable to resolve host: {host}"

    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host_ip, port))
            if result == 0:
                open_ports.append(port)
    return f"Open ports on {host} ({host_ip}): {open_ports}"


def get_open_ports(host):
    try:
        host_ip = socket.gethostbyname(host)  # Resolve hostname to IP
    except socket.gaierror:
        return f"Unable to resolve host: {host}"

    scanner = nmap.PortScanner()
    # Scan broader range including high ports
    scanner.scan(host, arguments='-p 1-65535')  # Full port range
    open_ports = []

    for proto in scanner[host].all_protocols():
        lport = scanner[host][proto].keys()
        for port in sorted(lport):
            state = scanner[host][proto][port]['state']
            if state == 'open':
                open_ports.append(port)
    return f"Open ports on {host} ({host_ip}): {open_ports}"


def get_open_ports_with_remote_ips(host):
    try:
        host_ip = socket.gethostbyname(host)  # Resolve hostname to IP
    except socket.gaierror:
        return f"Unable to resolve host: {host}"

    scanner = nmap.PortScanner()
    # Scan broader range including high ports commonly used in cloud environments
    scanner.scan(host, arguments='-p 1-65535 --top-ports 1000')  # Scan top 1000 most common ports
    open_ports = {}

    for proto in scanner[host].all_protocols():
        lport = scanner[host][proto].keys()
        for port in sorted(lport):
            state = scanner[host][proto][port]['state']
            if state == 'open':
                # Use nmap scripts to detect accessible IPs (if supported)
                try:
                    script_results = scanner[host][proto][port].get('script', {})
                    accessible_ips = script_results.get('firewall-bypass', '0.0.0.0/0 (assumed - verify manually)')
                except KeyError:
                    accessible_ips = '0.0.0.0/0 (assumed - verify manually)'
                open_ports[port] = accessible_ips

    return open_ports


def get_comprehensive_port_scan(host):
    """
    Comprehensive port scan for cloud environments like AWS
    """
    try:
        host_ip = socket.gethostbyname(host)  # Resolve hostname to IP
    except socket.gaierror:
        return f"Unable to resolve host: {host}"

    scanner = nmap.PortScanner()
    # More aggressive scan for cloud environments
    scanner.scan(host, arguments='-p- -T4 --max-retries 2')  # Scan all 65535 ports with faster timing
    open_ports = {}

    for proto in scanner[host].all_protocols():
        lport = scanner[host][proto].keys()
        for port in sorted(lport):
            state = scanner[host][proto][port]['state']
            if state == 'open':
                # Try to get service information
                service_info = scanner[host][proto][port].get('name', 'unknown')
                version_info = scanner[host][proto][port].get('version', '')
                
                # Use nmap scripts to detect accessible IPs (if supported)
                try:
                    script_results = scanner[host][proto][port].get('script', {})
                    accessible_ips = script_results.get('firewall-bypass', '0.0.0.0/0 (assumed - verify manually)')
                except KeyError:
                    accessible_ips = '0.0.0.0/0 (assumed - verify manually)'
                
                open_ports[port] = {
                    'service': service_info,
                    'version': version_info,
                    'accessible_from': accessible_ips
                }

    return open_ports