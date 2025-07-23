from fabric import Connection
from scanner.port_scanner import get_listening_ports_fast, get_port_accessibility_summary
from scanner.file_checker import check_sensitive_files
from scanner.docker_checker import check_docker_security
from scanner.laravel_checker import check_laravel_security
from scanner.node_checker import check_nodejs_security
from scanner.python_checker import check_python_security
from scanner.firewall_checker import check_firewall_rules
from scanner.report_generator import generate_pdf_report
from utils.logger import logger
import time
# security_checker.py


#Security Checker Module
#This module provides functionality to perform a full security scan on a server. It connects to the server via SSH, scans for open ports, checks for sensitive files, and evaluates Docker security configurations. Finally, it generates a PDF report of the findings.
def run_full_scan(host, port, username, password=None, ssh_key_path=None, key_passphrase=None, comprehensive_scan=False, project_path='/www/wwwroot/team1/damon/', stack_name=None, progress_callback=None):
    def update_progress(message, step_name=None):
        """Helper function to update progress if callback is provided"""
        if progress_callback:
            progress_callback.update('running', message, step_name)
    
    try:
        # Extract stack name from project path if not provided
        if not stack_name and project_path:
            # Extract the last directory name from the path
            path_parts = project_path.rstrip('/').split('/')
            if path_parts:
                extracted_name = path_parts[-1]
                # Convert to uppercase as stack names are in capital letters
                stack_name = extracted_name.upper()
                logger.info(f"Extracted stack name from project path: {stack_name}")
        
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
            'laravel_security': {},
            'nodejs_security': {},
            'python_security': {},
            'firewall_security': {},
            'docker_issues': [],
            'system_info': {},
            'security_summary': {}
        }
        
        # Establish connection
        update_progress(f'🔌 Connecting to {host}:{port}...', 'connection')
        
        with Connection(
            host=host,
            user=username,
            port=port,
            connect_kwargs=connect_kwargs
        ) as conn:
            # 🔐 Test connection
            auth_method = "SSH Key" if ssh_key_path else "Password"
            update_progress(f'🔐 Authenticating with {auth_method}...', 'authentication')
            conn.run("echo 'Connection successful'", hide=True)
            logger.info(f"Connected to {host} successfully.")
            
            # Show successful connection
            update_progress(f'✅ Connected to {host} successfully!', 'connection_established')

            # 1. Port scanning
            update_progress('🔍 Port scanning - Scanning for open ports...', 'port_scan')
            logger.info("Starting port scan...")
            comprehensive_scan = True
            open_ports = get_listening_ports_fast(host)
            
            # Get accessibility summary
            summary = get_port_accessibility_summary(host, 'fast')
            logger.info(f"Globally accessible ports: {summary.get('globally_accessible_ports', [])}")
            logger.info(f"Restricted ports: {summary.get('restricted_ports', [])}")

            scan_results['open_ports'] = open_ports
       
            # 2. System information gathering
            update_progress('🖥️ System Info - Gathering system information...', 'system_info')
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
            update_progress('📄 File Analysis - Analyzing sensitive files...', 'file_analysis')
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

            # 3.5. Check Laravel-specific security
            update_progress('🔧 Framework Security - Checking Laravel/Node.js/Python security...', 'framework_security')
            logger.info("Checking Laravel security configurations...")
            try:
                laravel_security = check_laravel_security(conn, project_path=project_path)
                scan_results['laravel_security'] = laravel_security
                
                if laravel_security.get('laravel_found', False):
                    critical_issues = len(laravel_security.get('security_summary', {}).get('critical_issues', []))
                    warnings = len(laravel_security.get('security_summary', {}).get('warnings', []))
                    recommendations = len(laravel_security.get('security_summary', {}).get('recommendations', []))
                    
                    logger.info(f"Laravel security check completed - Critical: {critical_issues}, Warnings: {warnings}, Recommendations: {recommendations}")
                else:
                    logger.info("No Laravel project detected")
            except Exception as e:
                logger.error(f"Error checking Laravel security: {e}")
                scan_results['laravel_security'] = {'error': str(e)}

            # 3.6. Check Node.js-specific security
            logger.info("Checking Node.js security configurations...")
            try:
                nodejs_security = check_nodejs_security(conn, project_path=project_path, stack_name=stack_name)
                scan_results['nodejs_security'] = nodejs_security
                
                if nodejs_security.get('nodejs_found', False):
                    critical_issues = len(nodejs_security.get('security_summary', {}).get('critical_issues', []))
                    warnings = len(nodejs_security.get('security_summary', {}).get('warnings', []))
                    recommendations = len(nodejs_security.get('security_summary', {}).get('recommendations', []))
                    
                    logger.info(f"Node.js security check completed - Critical: {critical_issues}, Warnings: {warnings}, Recommendations: {recommendations}")
                    
                    # Log Docker/Swarm specific findings
                    if stack_name and nodejs_security.get('swarm_config', {}).get('stack_deployed', False):
                        logger.info(f"Docker Swarm stack '{stack_name}' detected and analyzed")
                    elif nodejs_security.get('docker_config', {}).get('container_running', False):
                        logger.info("Docker container(s) detected and analyzed")
                else:
                    logger.info("No Node.js project detected")
            except Exception as e:
                logger.error(f"Error checking Node.js security: {e}")
                scan_results['nodejs_security'] = {'error': str(e)}

            # 3.7. Check Python-specific security
            logger.info("Checking Python security configurations...")
            try:
                python_security = check_python_security(conn, project_path=project_path, stack_name=stack_name)
                scan_results['python_security'] = python_security
                
                if python_security.get('python_found', False):
                    critical_issues = len(python_security.get('security_summary', {}).get('critical_issues', []))
                    warnings = len(python_security.get('security_summary', {}).get('warnings', []))
                    recommendations = len(python_security.get('security_summary', {}).get('recommendations', []))
                    
                    logger.info(f"Python security check completed - Critical: {critical_issues}, Warnings: {warnings}, Recommendations: {recommendations}")
                    
                    # Log Docker/Swarm specific findings for Python
                    if stack_name and python_security.get('swarm_config', {}).get('stack_deployed', False):
                        python_services = python_security.get('swarm_config', {}).get('python_services', [])
                        logger.info(f"Docker Swarm Python services found: {python_services}")
                    elif python_security.get('docker_config', {}).get('container_running', False):
                        logger.info("Python Docker container(s) detected and analyzed")
                else:
                    logger.info("No Python project detected")
            except Exception as e:
                logger.error(f"Error checking Python security: {e}")
                scan_results['python_security'] = {'error': str(e)}

            # 3.8. Check Firewall and Port Security
            update_progress('🔥 Firewall Analysis - Analyzing firewall rules and port security...', 'firewall_analysis')
            logger.info("Checking firewall rules and port accessibility...")
            try:
                # Extract open ports list from the port scan results
                open_ports_list = []
                if isinstance(open_ports, dict) and 'open_ports' in open_ports:
                    open_ports_list = [int(port) for port in open_ports['open_ports'] if str(port).isdigit()]
                elif isinstance(open_ports, list):
                    open_ports_list = [int(port) for port in open_ports if str(port).isdigit()]
                
                firewall_security = check_firewall_rules(conn, host, open_ports_list)
                scan_results['firewall_security'] = firewall_security
                
                critical_issues = len(firewall_security.get('security_issues', []))
                warnings = len(firewall_security.get('warnings', []))
                firewall_status = firewall_security.get('firewall_status', 'unknown')
                
                logger.info(f"Firewall security check completed - Status: {firewall_status}, Critical: {critical_issues}, Warnings: {warnings}")
                
                if critical_issues > 0:
                    logger.warning(f"Found {critical_issues} critical firewall security issues")
                
            except Exception as e:
                logger.error(f"Error checking firewall security: {e}")
                scan_results['firewall_security'] = {'error': str(e)}

            # 4. Check Docker security
            if stack_name:
                update_progress(f'🐳 Docker Analysis - Analyzing Docker Swarm stack: {stack_name}...', 'docker_analysis')
            else:
                update_progress('🐳 Docker Analysis - Checking Docker configuration...', 'docker_analysis')
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
                'laravel_security_issues': len(scan_results.get('laravel_security', {}).get('security_summary', {}).get('critical_issues', [])),
                'nodejs_security_issues': len(scan_results.get('nodejs_security', {}).get('security_summary', {}).get('critical_issues', [])),
                'python_security_issues': len(scan_results.get('python_security', {}).get('security_summary', {}).get('critical_issues', [])),
                'firewall_security_issues': len(scan_results.get('firewall_security', {}).get('security_issues', [])),
                'firewall_status': scan_results.get('firewall_security', {}).get('firewall_status', 'unknown'),
                'docker_issues_count': len(scan_results['docker_issues']) if isinstance(scan_results['docker_issues'], list) else 0,
                'scan_type': 'Comprehensive' if comprehensive_scan else 'Standard'
            }

        # 6. Generate report (outside connection context)
        update_progress('📊 Report Generation - Generating security report...', 'report_generation')
        try:
            logger.info("Generating PDF report...")
            report_path = generate_pdf_report(scan_results)
            scan_results['report_path'] = report_path
            logger.info(f"Report generated at: {report_path}")
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            scan_results['report_error'] = str(e)
            
        # Mark scan as complete
        if progress_callback:
            progress_callback.update('completed', '✅ Completed - Security scan completed successfully!', 'completed')
            
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
            open_ports = get_listening_ports_fast(host)
            
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