from fabric import Connection
from scanner.port_scanner import get_listening_ports_fast, get_port_accessibility_summary
from scanner.file_checker import check_sensitive_files
from scanner.docker_checker import check_docker_security
from scanner.report_generator import generate_pdf_report
from utils.logger import logger
import time
# security_checker.py


#Security Checker Module
#This module provides functionality to perform a full security scan on a server. It connects to the server via SSH, scans for open ports, checks for sensitive files, and evaluates Docker security configurations. Finally, it generates a PDF report of the findings.
def run_full_scan(host, port, username, password=None, ssh_key_path=None, key_passphrase=None, comprehensive_scan=False, project_path='/www/wwwroot/team1/damon/'):
    try:
        # Set up connection parameters based on authentication method
        connect_kwargs = {}
        
        if password:
            # Password authentication
            connect_kwargs["password"] = password
            logger.info(f"Using password authentication for {username}@{host}")
        
        elif ssh_key_path:
            # SSH key authentication
            connect_kwargs["key_filename"] = ssh_key_path
            if key_passphrase:
                connect_kwargs["passphrase"] = key_passphrase
            logger.info(f"Using SSH key authentication for {username}@{host}")
        
        else:
            logger.error("No authentication method provided")
            return {"error": "No authentication method provided (password or SSH key required)"}
        
        # Initialize scan results
        scan_results = {
            'status': 'success',
            'host': host,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'connection_method': 'SSH Key' if ssh_key_path else 'Password',
            'open_ports': {},
            'sensitive_files': [],
            'docker_issues': [],
            'system_info': {},
            'security_summary': {}
        }
        
        # Establish connection
        with Connection(
            host=host,
            user=username,
            port=port,
            connect_kwargs=connect_kwargs
        ) as conn:
            # 🔐 Test connection
            conn.run("echo 'Connection successful'", hide=True)
            logger.info(f"Connected to {host} successfully.")

        # 1. Port scanning
        logger.info("Starting port scan...")
        comprehensive_scan = True
        open_ports = get_listening_ports_fast(host)
        
        # Get accessibility summary
        summary = get_port_accessibility_summary(host, 'fast')
        logger.info(f"Globally accessible ports: {summary.get('globally_accessible_ports', [])}")
        logger.info(f"Restricted ports: {summary.get('restricted_ports', [])}")

        scan_results['open_ports'] = open_ports

      
            
        # scan_results['open_ports'] = open_ports
       
            
        # 2. System information gathering
        logger.info("Gathering system information...")
        try:
            # Get OS information
            os_info = conn.run("uname -a", hide=True).stdout.strip()
            scan_results['system_info']['os'] = os_info
            
            # Get kernel version
            kernel_version = conn.run("uname -r", hide=True).stdout.strip()
            scan_results['system_info']['kernel'] = kernel_version
            
            # Get distribution info
            try:
                distro_info = conn.run("cat /etc/os-release", hide=True).stdout.strip()
                scan_results['system_info']['distribution'] = distro_info
            except:
                scan_results['system_info']['distribution'] = "Unknown"
            
            # Get uptime
            uptime = conn.run("uptime", hide=True).stdout.strip()
            scan_results['system_info']['uptime'] = uptime
            
            logger.info("System information gathered successfully")
        except Exception as e:
            logger.error(f"Error gathering system info: {e}")
            scan_results['system_info']['error'] = str(e)
            
        # 3. Check for sensitive files
        logger.info("Checking for sensitive files...")
        try:
            sensitive_files = check_sensitive_files(conn, project_path=project_path)
            scan_results['sensitive_files'] = sensitive_files
            
            # Log security status summary
            secure_count = sum(1 for f in sensitive_files if f.get('security_status') == 'secure')
            warning_count = sum(1 for f in sensitive_files if f.get('security_status') == 'warning')
            critical_count = sum(1 for f in sensitive_files if f.get('security_status') == 'critical')
            
            logger.info(f"Sensitive files found: {len(sensitive_files)} (Secure: {secure_count}, Warning: {warning_count}, Critical: {critical_count})")
        except Exception as e:
            logger.error(f"Error checking sensitive files: {e}")
            scan_results['sensitive_files'] = [f"Error: {str(e)}"]

        # 4. Check Docker security
        logger.info("Checking Docker security...")
        try:
            docker_issues = check_docker_security(conn)
            scan_results['docker_issues'] = docker_issues
            logger.info(f"Docker issues found: {len(docker_issues)}")
        except Exception as e:
            logger.error(f"Error checking Docker security: {e}")
            scan_results['docker_issues'] = [f"Error: {str(e)}"]

        # 5. Security summary
        scan_results['security_summary'] = {
            'total_open_ports': len(open_ports.get('open_ports', [])) if isinstance(open_ports, dict) else 0,
            'high_risk_ports': [port for port in (open_ports.get('open_ports', []) if isinstance(open_ports, dict) else []) if port in [22, 23, 80, 443, 3389, 5900]],
            'sensitive_files_count': len(scan_results['sensitive_files']),
            'docker_issues_count': len(scan_results['docker_issues']) if isinstance(scan_results['docker_issues'], list) else 0,
            'scan_type': 'Comprehensive' if comprehensive_scan else 'Standard'
        }

        # 6. Generate report
        # try:
        #     logger.info("Generating PDF report...")
        #     report_path = generate_pdf_report(scan_results)
        #     scan_results['report_path'] = report_path
        #     logger.info(f"Report generated at: {report_path}")
        # except Exception as e:
        #     logger.error(f"Error generating report: {e}")
        #     scan_results['report_error'] = str(e)
            
        return scan_results
            
    except Exception as e:
        logger.error(f"Failed to connect or scan: {e}",exc_info=True)
        return {
            "error": f"Failed to connect to the server: {e}",
            "status": "failed",
            "host": host,
            "scan_timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }


def run_quick_scan(host, port, username, password=None, ssh_key_path=None, key_passphrase=None):
    """
    Quick scan focusing only on port scanning and basic system info
    """
    try:
        # Set up connection parameters based on authentication method
        connect_kwargs = {}
        
        if password:
            connect_kwargs["password"] = password
        elif ssh_key_path:
            connect_kwargs["key_filename"] = ssh_key_path
            if key_passphrase:
                connect_kwargs["passphrase"] = key_passphrase
        else:
            return {"error": "No authentication method provided"}
        
        with Connection(
            host=host,
            user=username,
            port=port,
            connect_kwargs=connect_kwargs
        ) as conn:
            # Test connection
            conn.run("echo 'Connection successful'", hide=True)
            logger.info(f"Connected to {host} successfully for quick scan.")

            # Quick port scan
            logger.info("Running quick port scan...")
            open_ports = get_open_ports_with_remote_ips(host)
            
            # Basic system info
            os_info = conn.run("uname -a", hide=True).stdout.strip()
            
            return {
                'status': 'success',
                'host': host,
                'scan_type': 'quick',
                'open_ports': open_ports,
                'os_info': os_info,
                'connection_method': 'SSH Key' if ssh_key_path else 'Password'
            }
            
    except Exception as e:
        logger.error(f"Quick scan failed: {e}")
        return {"error": f"Quick scan failed: {e}"}