import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from utils.logger import logger

# Office IP that should have access to all ports
OFFICE_IP = "103.103.174.106"
PUBLIC_PORTS = [80, 443]  # Ports that should be publicly accessible

def check_firewall_rules(conn, target_host, open_ports):
    """
    Check firewall rules and port accessibility from different IPs
    """
    firewall_results = {
        'target_host': target_host,
        'office_ip': OFFICE_IP,
        'public_ports': PUBLIC_PORTS,
        'total_ports_checked': len(open_ports),
        'port_accessibility': {},
        'security_issues': [],
        'warnings': [],
        'recommendations': [],
        'firewall_status': 'unknown',
        'iptables_rules': [],
        'ufw_status': None
    }
    
    try:
        logger.info(f"Checking firewall rules for {target_host} with office IP {OFFICE_IP}")
        
        # Get server's own IP address
        server_local_ip = get_server_local_ip(conn)
        firewall_results['server_local_ip'] = server_local_ip
        
        # Check firewall configuration
        firewall_results['iptables_rules'] = get_iptables_rules(conn)
        firewall_results['ufw_status'] = get_ufw_status(conn)
        
        # Test port accessibility from different sources
        if open_ports:
            firewall_results['port_accessibility'] = test_port_accessibility(
                target_host, open_ports, server_local_ip
            )
            
            # Analyze the results for security issues
            analyze_port_security(firewall_results)
        
        logger.info(f"Firewall check completed for {target_host}")
        
    except Exception as e:
        logger.error(f"Error checking firewall rules: {e}", exc_info=True)
        firewall_results['error'] = str(e)
    
    return firewall_results

def get_server_local_ip(conn):
    """Get the server's local IP address"""
    try:
        # Try multiple methods to get the server's IP
        methods = [
            "hostname -I | awk '{print $1}'",  # Primary IP
            "ip route get 8.8.8.8 | awk '{print $7; exit}'",  # Route to external
            "ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1"  # Interface IP
        ]
        
        for method in methods:
            try:
                result = conn.run(method, hide=True, warn=True)
                if result.ok and result.stdout.strip():
                    ip = result.stdout.strip()
                    # Validate it's a proper IP
                    ipaddress.ip_address(ip)
                    logger.info(f"Server local IP detected: {ip}")
                    return ip
            except:
                continue
        
        logger.warning("Could not determine server's local IP")
        return "unknown"
        
    except Exception as e:
        logger.error(f"Error getting server local IP: {e}", exc_info=True)
        return "unknown"

def get_iptables_rules(conn):
    """Get current iptables rules"""
    try:
        result = conn.run("iptables -L -n -v 2>/dev/null || echo 'IPTABLES_NOT_AVAILABLE'", hide=True, warn=True)
        if result.ok and 'IPTABLES_NOT_AVAILABLE' not in result.stdout:
            rules = result.stdout.strip().split('\n')
            logger.info(f"Found {len(rules)} iptables rules")
            return rules
        else:
            logger.info("iptables not available or no permission")
            return []
    except Exception as e:
        logger.error(f"Error getting iptables rules: {e}", exc_info=True)
        return []

def get_ufw_status(conn):
    """Get UFW (Uncomplicated Firewall) status"""
    try:
        result = conn.run("ufw status verbose 2>/dev/null || echo 'UFW_NOT_AVAILABLE'", hide=True, warn=True)
        if result.ok and 'UFW_NOT_AVAILABLE' not in result.stdout:
            status = result.stdout.strip()
            logger.info("UFW status retrieved")
            return status
        else:
            logger.info("UFW not available")
            return None
    except Exception as e:
        logger.error(f"Error getting UFW status: {e}", exc_info=True)
        return None

def test_port_accessibility(target_host, open_ports, server_local_ip):
    """
    Test port accessibility from different IP addresses
    """
    port_results = {}
    
    # Define test sources
    test_sources = [
        {'name': 'office', 'ip': OFFICE_IP, 'description': 'Office IP'},
        {'name': 'external', 'ip': '8.8.8.8', 'description': 'External IP (Google DNS)'},
    ]
    
    if server_local_ip != "unknown":
        test_sources.append({
            'name': 'local', 'ip': server_local_ip, 'description': 'Server Local IP'
        })
    
    logger.info(f"Testing accessibility for {len(open_ports)} ports from {len(test_sources)} sources")
    
    # Test each port from each source
    with ThreadPoolExecutor(max_workers=10) as executor:
        for port in open_ports:
            port_results[port] = {
                'port': port,
                'is_public_port': port in PUBLIC_PORTS,
                'accessibility': {},
                'security_status': 'unknown'
            }
            
            for source in test_sources:
                try:
                    # Test if port is accessible from this source
                    accessible = test_port_from_source(target_host, port, source['ip'])
                    
                    port_results[port]['accessibility'][source['name']] = {
                        'source_ip': source['ip'],
                        'description': source['description'],
                        'accessible': accessible,
                        'tested': True
                    }
                    
                except Exception as e:
                    logger.warning(f"Could not test port {port} from {source['description']}: {e}")
                    port_results[port]['accessibility'][source['name']] = {
                        'source_ip': source['ip'],
                        'description': source['description'],
                        'accessible': False,
                        'tested': False,
                        'error': str(e)
                    }
    
    return port_results

def test_port_from_source(target_host, port, source_ip):
    """
    Test if a port is accessible from a specific source IP
    Note: This is a simplified test. In reality, you'd need to run this from the actual source IP
    """
    try:
        # For demonstration, we'll use a basic connectivity test
        # In a real implementation, you might need to use nmap or actual network testing
        
        # Simple socket test (this tests from the current machine)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target_host, port))
        sock.close()
        
        # If we can connect, the port is accessible
        accessible = (result == 0)
        
        logger.debug(f"Port {port} accessibility from {source_ip}: {'accessible' if accessible else 'not accessible'}")
        return accessible
        
    except Exception as e:
        logger.warning(f"Error testing port {port} from {source_ip}: {e}")
        return False

def analyze_port_security(firewall_results):
    """
    Analyze port accessibility results for security issues
    """
    port_accessibility = firewall_results.get('port_accessibility', {})
    security_issues = []
    warnings = []
    recommendations = []
    
    for port, port_data in port_accessibility.items():
        is_public_port = port_data.get('is_public_port', False)
        accessibility = port_data.get('accessibility', {})
        
        # Check office access
        office_access = accessibility.get('office', {}).get('accessible', False)
        
        # Check external access
        external_access = accessibility.get('external', {}).get('accessible', False)
        
        # Check local access
        local_access = accessibility.get('local', {}).get('accessible', True)  # Assume local access is OK
        
        if is_public_port:
            # Ports 80 and 443 should be publicly accessible
            port_data['security_status'] = 'public'
            
            if not external_access:
                warnings.append(f"Public port {port} may not be accessible from external sources")
            
            if not office_access:
                warnings.append(f"Public port {port} may not be accessible from office IP {OFFICE_IP}")
                
        else:
            # Non-public ports should only be accessible from office and local IPs
            if external_access and not office_access:
                # Port is accessible externally but not from office - major security issue
                security_issues.append(f"CRITICAL: Port {port} is accessible from external IPs but should only be accessible from office IP {OFFICE_IP}")
                port_data['security_status'] = 'critical'
                
            elif external_access and office_access:
                # Port is accessible from both - might be intended or security issue
                security_issues.append(f"WARNING: Port {port} is publicly accessible - should only be accessible from office IP {OFFICE_IP}")
                port_data['security_status'] = 'warning'
                
            elif not office_access and not external_access:
                # Port is not accessible from office or external - check if it's properly restricted
                if local_access:
                    port_data['security_status'] = 'secure'
                else:
                    warnings.append(f"Port {port} may not be accessible from authorized sources")
                    port_data['security_status'] = 'warning'
                    
            elif office_access and not external_access:
                # Ideal state: accessible from office, not from external
                port_data['security_status'] = 'secure'
                
            else:
                port_data['security_status'] = 'unknown'
    
    # Generate recommendations
    if security_issues:
        recommendations.append("Review firewall rules to restrict non-public ports to authorized IPs only")
        recommendations.append(f"Configure firewall to allow access from office IP {OFFICE_IP} only for management ports")
    
    if not firewall_results.get('iptables_rules') and not firewall_results.get('ufw_status'):
        recommendations.append("Install and configure a firewall (iptables or UFW) to control port access")
    
    # Update results
    firewall_results['security_issues'].extend(security_issues)
    firewall_results['warnings'].extend(warnings)
    firewall_results['recommendations'].extend(recommendations)
    
    # Determine overall firewall status
    if security_issues:
        firewall_results['firewall_status'] = 'critical'
    elif warnings:
        firewall_results['firewall_status'] = 'warning'
    else:
        firewall_results['firewall_status'] = 'secure'
    
    logger.info(f"Firewall analysis complete: {len(security_issues)} critical issues, {len(warnings)} warnings")

def generate_firewall_recommendations(firewall_results):
    """
    Generate specific firewall configuration recommendations
    """
    recommendations = []
    target_host = firewall_results.get('target_host')
    office_ip = firewall_results.get('office_ip')
    
    # UFW recommendations
    recommendations.append("# UFW (Uncomplicated Firewall) Configuration:")
    recommendations.append("sudo ufw --force reset")
    recommendations.append("sudo ufw default deny incoming")
    recommendations.append("sudo ufw default allow outgoing")
    
    # Allow public web ports
    recommendations.append("sudo ufw allow 80/tcp")
    recommendations.append("sudo ufw allow 443/tcp")
    
    # Allow SSH from office IP only
    recommendations.append(f"sudo ufw allow from {office_ip} to any port 22")
    
    # Allow other management ports from office IP
    management_ports = [3306, 5432, 6379, 27017, 9000, 8080]  # Common management ports
    for port in management_ports:
        recommendations.append(f"sudo ufw allow from {office_ip} to any port {port}")
    
    recommendations.append("sudo ufw --force enable")
    
    # iptables recommendations
    recommendations.append("\n# Alternative iptables Configuration:")
    recommendations.append("# Flush existing rules")
    recommendations.append("iptables -F")
    recommendations.append("iptables -X")
    recommendations.append("iptables -tnat -F")
    recommendations.append("iptables -t nat -X")
    
    # Default policies
    recommendations.append("iptables -P INPUT DROP")
    recommendations.append("iptables -P FORWARD DROP")
    recommendations.append("iptables -P OUTPUT ACCEPT")
    
    # Allow loopback
    recommendations.append("iptables -A INPUT -i lo -j ACCEPT")
    
    # Allow established connections
    recommendations.append("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    
    # Allow public web ports
    recommendations.append("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")
    recommendations.append("iptables -A INPUT -p tcp --dport 443 -j ACCEPT")
    
    # Allow office IP for management
    recommendations.append(f"iptables -A INPUT -s {office_ip} -j ACCEPT")
    
    # Save rules
    recommendations.append("iptables-save > /etc/iptables/rules.v4")
    
    firewall_results['configuration_recommendations'] = recommendations
    
    return recommendations
