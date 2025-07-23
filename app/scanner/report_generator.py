from fpdf import FPDF
import uuid
import os
import json
from datetime import datetime

def sanitize_text(text):
    """
    Sanitize text to remove Unicode characters that can't be encoded in latin-1
    """
    if isinstance(text, str):
        # Replace common Unicode characters with ASCII alternatives
        replacements = {
            # Warning and status symbols
            '⚠': '[WARNING]',
            '⚠️': '[WARNING]',
            '✓': '[OK]',
            '✔': '[OK]',
            '✔️': '[OK]',
            '✗': '[FAIL]',
            '✘': '[FAIL]',
            '❌': '[FAIL]',
            '❯': '>',
            '→': '->',
            '←': '<-',
            '↑': '^',
            '↓': 'v',
            
            # Bullet points and list markers
            '•': '*',
            '◦': '-',
            '▪': '*',
            '▫': '-',
            '‣': '>',
            '⁃': '-',
            '◯': 'o',
            '●': '*',
            '○': 'o',
            
            # Emojis and symbols
            '📄': '[PDF]',
            '🔒': '[SECURE]',
            '🔓': '[UNSECURE]',
            '⚡': '[FAST]',
            '🐳': '[DOCKER]',
            '🔧': '[CONFIG]',
            '📊': '[DATA]',
            '🚀': '[ROCKET]',
            '⭐': '[STAR]',
            '🔥': '[FIRE]',
            '💡': '[IDEA]',
            '🛡️': '[SHIELD]',
            '🛡': '[SHIELD]',
            '🔑': '[KEY]',
            '🚨': '[ALERT]',
            '📈': '[CHART]',
            '📉': '[CHART]',
            '💻': '[COMPUTER]',
            '🌐': '[WEB]',
            '📱': '[MOBILE]',
            '🖥️': '[DESKTOP]',
            '🖥': '[DESKTOP]',
            
            # Quotation marks
            ''': "'",
            ''': "'",
            '"': '"',
            '"': '"',
            '„': '"',
            '‚': "'",
            '‹': '<',
            '›': '>',
            '«': '<<',
            '»': '>>',
            
            # Dashes and hyphens
            '–': '-',
            '—': '--',
            '―': '--',
            '‐': '-',
            '‑': '-',
            '‒': '-',
            '−': '-',
            
            # Mathematical and special symbols
            '×': 'x',
            '÷': '/',
            '±': '+/-',
            '≠': '!=',
            '≤': '<=',
            '≥': '>=',
            '∞': 'infinity',
            '°': ' degrees',
            '™': 'TM',
            '©': '(C)',
            '®': '(R)',
            '§': 'section',
            '¶': 'paragraph',
            
            # Currency symbols
            '€': 'EUR',
            '£': 'GBP',
            '¥': 'YEN',
            '¢': 'cents',
            
            # Fractions
            '½': '1/2',
            '¼': '1/4',
            '¾': '3/4',
            '⅓': '1/3',
            '⅔': '2/3',
            
            # Other common symbols
            '…': '...',
            '‰': 'per mille',
            '‱': 'per ten thousand',
            '№': 'No.',
            '℃': 'C',
            '℉': 'F',
        }
        
        # Apply replacements
        for unicode_char, ascii_replacement in replacements.items():
            text = text.replace(unicode_char, ascii_replacement)
        
        # Handle any remaining non-latin-1 characters by encoding/decoding
        try:
            # First try to encode as latin-1 to catch remaining problematic characters
            text.encode('latin-1')
        except UnicodeEncodeError:
            # If that fails, convert to ASCII and ignore problematic characters
            text = text.encode('ascii', 'ignore').decode('ascii')
    
    return text

def sanitize_scan_data(data):
    """
    Recursively sanitize all text data in the scan results dictionary
    """
    if isinstance(data, dict):
        return {key: sanitize_scan_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_scan_data(item) for item in data]
    elif isinstance(data, str):
        return sanitize_text(data)
    else:
        return data

class SecurityReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.set_margins(20, 20, 20)  # Better margins
        
    def header(self):
        # Add a colored header background
        self.set_fill_color(41, 128, 185)  # Blue background
        self.rect(0, 0, 210, 30, 'F')
        
        # White text on blue background
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 18)
        self.ln(8)
        self.cell(0, 10, 'Server Security Assessment Report', 0, 1, 'C')
        
        # Reset text color
        self.set_text_color(0, 0, 0)
        self.ln(8)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - Page {self.page_no()}', 0, 0, 'C')
        self.set_text_color(0, 0, 0)
    
    def add_title(self, title):
        self.ln(5)
        # Add background color for titles
        self.set_fill_color(52, 73, 94)  # Dark blue-gray
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 14)
        title = sanitize_text(str(title))
        self.cell(0, 12, f"  {title}", 0, 1, 'L', True)
        self.set_text_color(0, 0, 0)
        self.ln(3)
    
    def add_subtitle(self, subtitle):
        self.ln(2)
        # Light gray background for subtitles
        self.set_fill_color(236, 240, 241)  # Light gray
        self.set_text_color(52, 73, 94)  # Dark blue-gray text
        self.set_font('Arial', 'B', 12)
        subtitle = sanitize_text(str(subtitle))
        self.cell(0, 10, f"  {subtitle}", 0, 1, 'L', True)
        self.set_text_color(0, 0, 0)
        self.ln(2)
    
    def add_text(self, text, indent=0):
        self.set_font('Arial', '', 10)
        text = sanitize_text(str(text))
        
        # Better line spacing and indentation
        left_margin = 20 + indent
        
        # Handle multi-line text properly
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                self.ln(3)
                continue
                
            # Word wrap for long lines
            if len(line) > 90:
                words = line.split(' ')
                current_line = ''
                for word in words:
                    test_line = current_line + word + ' '
                    if len(test_line) <= 90:
                        current_line = test_line
                    else:
                        if current_line:
                            self.set_x(left_margin)
                            self.cell(0, 6, current_line.strip(), 0, 1, 'L')
                        current_line = word + ' '
                
                if current_line:
                    self.set_x(left_margin)
                    self.cell(0, 6, current_line.strip(), 0, 1, 'L')
            else:
                self.set_x(left_margin)
                self.cell(0, 6, line, 0, 1, 'L')
        
        self.ln(1)  # Small spacing after text
    
    def add_bullet_point(self, text, indent=0, bullet_char='*'):
        """Add a properly formatted bullet point"""
        self.set_font('Arial', '', 10)
        text = sanitize_text(str(text))
        left_margin = 25 + indent
        
        # Ensure bullet character is ASCII-safe
        bullet_char = sanitize_text(str(bullet_char))
        if not bullet_char or len(bullet_char) == 0:
            bullet_char = '*'
        
        # Add bullet character
        self.set_x(left_margin)
        self.cell(5, 6, bullet_char, 0, 0, 'L')
        
        # Handle long bullet text with proper wrapping
        if len(text) > 85:
            words = text.split(' ')
            current_line = ''
            first_line = True
            
            for word in words:
                test_line = current_line + word + ' '
                if len(test_line) <= 85:
                    current_line = test_line
                else:
                    if current_line:
                        if first_line:
                            self.cell(0, 6, current_line.strip(), 0, 1, 'L')
                            first_line = False
                        else:
                            self.set_x(left_margin + 5)  # Indent continuation lines
                            self.cell(0, 6, current_line.strip(), 0, 1, 'L')
                    current_line = word + ' '
            
            if current_line:
                if first_line:
                    self.cell(0, 6, current_line.strip(), 0, 1, 'L')
                else:
                    self.set_x(left_margin + 5)
                    self.cell(0, 6, current_line.strip(), 0, 1, 'L')
        else:
            self.cell(0, 6, text, 0, 1, 'L')
        
        self.ln(1)
    
    def add_status_badge(self, status, text):
        """Add a colored status badge with text"""
        self.set_font('Arial', 'B', 10)
        
        # Set badge colors
        if status == 'critical':
            self.set_fill_color(231, 76, 60)  # Red
            self.set_text_color(255, 255, 255)
            badge_text = "CRITICAL"
        elif status == 'warning':
            self.set_fill_color(230, 126, 34)  # Orange
            self.set_text_color(255, 255, 255)
            badge_text = "WARNING"
        elif status == 'secure' or status == 'good':
            self.set_fill_color(39, 174, 96)  # Green
            self.set_text_color(255, 255, 255)
            badge_text = "SECURE"
        elif status == 'info':
            self.set_fill_color(52, 152, 219)  # Blue
            self.set_text_color(255, 255, 255)
            badge_text = "INFO"
        else:
            self.set_fill_color(149, 165, 166)  # Gray
            self.set_text_color(255, 255, 255)
            badge_text = "UNKNOWN"
        
        # Draw badge
        self.set_x(25)
        self.cell(18, 6, badge_text, 0, 0, 'C', True)
        
        # Add the text next to the badge
        self.set_text_color(0, 0, 0)
        self.set_font('Arial', '', 10)
        self.cell(5, 6, '', 0, 0)  # Small spacing
        self.cell(0, 6, sanitize_text(str(text)), 0, 1, 'L')
        self.ln(1)
    
    def add_security_status(self, status):
        """Set text color based on security status"""
        if status == 'critical':
            self.set_text_color(231, 76, 60)  # Red
        elif status == 'warning':
            self.set_text_color(230, 126, 34)  # Orange
        elif status == 'secure':
            self.set_text_color(39, 174, 96)  # Green
        else:
            self.set_text_color(0, 0, 0)  # Black
    
    def reset_text_color(self):
        self.set_text_color(0, 0, 0)

def generate_pdf_report(scan_data):
    """
    Generate a comprehensive PDF report for security scan results
    """
    # Sanitize all scan data before processing
    scan_data = sanitize_scan_data(scan_data)
    
    pdf = SecurityReportPDF()
    pdf.add_page()
    
    # Report Header Information
    pdf.add_title("Executive Summary")
    
    # Basic scan information
    host = scan_data.get('host', 'Unknown')
    scan_time = scan_data.get('scan_timestamp', 'Unknown')
    connection_method = scan_data.get('connection_method', 'Unknown')
    
    pdf.add_text(f"Target Host: {host}")
    pdf.add_text(f"Scan Time: {scan_time}")
    pdf.add_text(f"Connection Method: {connection_method}")
    pdf.ln(8)
    
    # Security Summary
    security_summary = scan_data.get('security_summary', {})
    if security_summary:
        pdf.add_subtitle("Security Overview")
        for key, value in security_summary.items():
            pdf.add_text(f"{key.replace('_', ' ').title()}: {value}")
        pdf.ln(5)
    
    # Open Ports Section
    pdf.add_page()
    pdf.add_title("Port Analysis")
    open_ports = scan_data.get('open_ports', {})
    if isinstance(open_ports, dict):
        if open_ports.get('open_ports'):
            pdf.add_subtitle("Open Ports Detected")
            for port in open_ports['open_ports']:
                pdf.add_bullet_point(f"Port {port}")
        
        if open_ports.get('globally_accessible_ports'):
            pdf.add_subtitle("Globally Accessible Ports")
            for port in open_ports['globally_accessible_ports']:
                pdf.add_status_badge('critical', f"Port {port} - Accessible from anywhere")
        
        if open_ports.get('restricted_ports'):
            pdf.add_subtitle("Restricted Ports")
            for port in open_ports['restricted_ports']:
                pdf.add_status_badge('secure', f"Port {port} - Access restricted")
    
    # Sensitive Files Section
    pdf.add_page()
    pdf.add_title("Sensitive Files Analysis")
    sensitive_files = scan_data.get('sensitive_files', [])
    if sensitive_files:
        for file_info in sensitive_files:
            if isinstance(file_info, dict):
                filename = file_info.get('filename', 'Unknown')
                full_path = file_info.get('full_path', 'Unknown')
                security_status = file_info.get('security_status', 'unknown')
                
                pdf.add_subtitle(f"File: {filename}")
                pdf.add_text(f"Path: {full_path}")
                
                # Status badge for security status
                if security_status == 'critical':
                    pdf.add_status_badge('critical', f"Security Status: {security_status.upper()}")
                elif security_status == 'warning':
                    pdf.add_status_badge('warning', f"Security Status: {security_status.upper()}")
                else:
                    pdf.add_status_badge('secure', f"Security Status: {security_status.upper()}")
                
                # File permissions
                permissions = file_info.get('permissions', {})
                if permissions:
                    pdf.add_text(f"Permissions: {permissions.get('octal', 'Unknown')}")
                    if permissions.get('world_readable'):
                        pdf.add_status_badge('warning', "File is world-readable")
                    if permissions.get('world_writable'):
                        pdf.add_status_badge('critical', "File is world-writable")
                
                # Public accessibility
                public_access = file_info.get('public_accessible', {})
                if public_access and public_access.get('potentially_public'):
                    pdf.add_status_badge('critical', "File may be publicly accessible via web server")
                
                pdf.ln(5)
    else:
        pdf.add_text("No sensitive files detected or error occurred during scan.")
    
    # Laravel Security Section
    laravel_security = scan_data.get('laravel_security', {})
    if laravel_security.get('laravel_found'):
        pdf.add_page()
        pdf.add_title("Laravel Security Analysis")
        
        # Environment file checks
        env_checks = laravel_security.get('env_file_checks', {})
        if env_checks:
            pdf.add_subtitle("Environment Configuration")
            
            app_debug = env_checks.get('app_debug', {})
            if not app_debug.get('secure', False):
                pdf.add_status_badge('critical', f"APP_DEBUG = {app_debug.get('value', 'Unknown')} (Should be false)")
            else:
                pdf.add_status_badge('secure', f"APP_DEBUG properly configured")
            
            app_env = env_checks.get('app_env', {})
            if not app_env.get('secure', False):
                pdf.add_status_badge('warning', f"APP_ENV = {app_env.get('value', 'Unknown')} (Should be production)")
            else:
                pdf.add_status_badge('secure', f"APP_ENV set to production")
            
            app_key = env_checks.get('app_key', {})
            if not app_key.get('secure', False):
                pdf.add_status_badge('critical', "APP_KEY is missing or insecure")
            else:
                pdf.add_status_badge('secure', "APP_KEY properly configured")
        
        # Cache status
        cache_checks = laravel_security.get('cache_checks', {})
        if cache_checks:
            pdf.add_subtitle("Performance Optimization")
            
            view_cache = cache_checks.get('view_cache', {})
            if not view_cache.get('cached', False):
                pdf.add_bullet_point("View caching not enabled - Run: php artisan view:cache")
            else:
                pdf.add_status_badge('secure', "View caching enabled")
            
            config_cache = cache_checks.get('config_cache', {})
            if not config_cache.get('cached', False):
                pdf.add_bullet_point("Config caching not enabled - Run: php artisan config:cache")
            else:
                pdf.add_status_badge('secure', "Config caching enabled")
            
            route_cache = cache_checks.get('route_cache', {})
            if not route_cache.get('cached', False):
                pdf.add_bullet_point("Route caching not enabled - Run: php artisan route:cache")
            else:
                pdf.add_status_badge('secure', "Route caching enabled")
        
        # Security summary
        security_summary = laravel_security.get('security_summary', {})
        if security_summary:
            pdf.add_subtitle("Laravel Security Summary")
            
            critical_issues = security_summary.get('critical_issues', [])
            if critical_issues:
                pdf.add_subtitle("Critical Issues")
                for issue in critical_issues:
                    pdf.add_status_badge('critical', issue)
            
            warnings = security_summary.get('warnings', [])
            if warnings:
                pdf.add_subtitle("Warnings")
                for warning in warnings:
                    pdf.add_status_badge('warning', warning)
            
            recommendations = security_summary.get('recommendations', [])
            if recommendations:
                pdf.add_subtitle('Recommendations')
                for rec in recommendations:
                    pdf.add_bullet_point(rec)
    
    # Node.js Security Section
    nodejs_security = scan_data.get('nodejs_security', {})
    if nodejs_security.get('nodejs_found'):
        pdf.add_page()
        pdf.add_title("Node.js Security Analysis")
        
        # Package.json checks
        package_checks = nodejs_security.get('package_checks', {})
        if package_checks:
            pdf.add_subtitle("Package Configuration")
            
            dependencies = package_checks.get('dependencies', {})
            pdf.add_text(f"Dependencies: {dependencies.get('count', 0)}")
            pdf.add_text(f"Dev Dependencies: {dependencies.get('dev_dependencies', 0)}")
            
            if not package_checks.get('private', {}).get('set', False):
                pdf.add_status_badge('warning', 'Package not marked as private')
            else:
                pdf.add_status_badge('secure', 'Package properly marked as private')
            
            if not package_checks.get('engines', {}).get('specified', False):
                pdf.add_bullet_point('Recommendation: Specify Node.js engine version')
            else:
                node_version = package_checks.get('node_version', {}).get('version', 'Unknown')
                pdf.add_status_badge('secure', f'Node.js engine specified: {node_version}')
        
        # Environment checks
        env_checks = nodejs_security.get('env_file_checks', {})
        if env_checks:
            pdf.add_subtitle("Environment Configuration")
            
            node_env = env_checks.get('node_env', {})
            if not node_env.get('secure', False):
                pdf.add_status_badge('critical', f"NODE_ENV = {node_env.get('value', 'Unknown')} (Should be production)")
            else:
                pdf.add_status_badge('secure', f"NODE_ENV properly set to production")
            
            jwt_secret = env_checks.get('jwt_secret', {})
            if jwt_secret.get('exists') and not jwt_secret.get('secure', False):
                pdf.add_status_badge('critical', "JWT secret is weak or default")
            elif jwt_secret.get('exists') and jwt_secret.get('secure', False):
                pdf.add_status_badge('secure', "JWT secret is properly configured")
            
            cors_origin = env_checks.get('cors_origin', {})
            if cors_origin.get('value') == '*':
                pdf.add_status_badge('warning', "CORS origin set to wildcard (*)")
            elif cors_origin.get('value'):
                pdf.add_status_badge('secure', f"CORS origin configured: {cors_origin.get('value')}")
        
        # Security packages
        security_packages = nodejs_security.get('security_packages', {})
        if security_packages:
            pdf.add_subtitle("Security Packages")
            
            helmet = security_packages.get('helmet_installed', {})
            if not helmet.get('installed', False):
                pdf.add_bullet_point("Helmet security middleware not installed")
            else:
                pdf.add_status_badge('secure', "Helmet security middleware installed")
            
            bcrypt = security_packages.get('bcrypt_installed', {})
            if not bcrypt.get('installed', False):
                pdf.add_bullet_point("bcrypt password hashing not installed")
            else:
                pdf.add_status_badge('secure', "bcrypt password hashing installed")
            
            rate_limiting = security_packages.get('rate_limiting', {})
            if not rate_limiting.get('installed', False):
                pdf.add_bullet_point("Rate limiting middleware not installed")
            else:
                pdf.add_status_badge('secure', "Rate limiting middleware installed")
            
            audit_result = security_packages.get('security_audit', {})
            if audit_result.get('vulnerabilities', 0) > 0:
                pdf.add_status_badge('critical', f"{audit_result['vulnerabilities']} security vulnerabilities found")
            elif audit_result.get('run', False):
                pdf.add_status_badge('secure', "No security vulnerabilities found")
        
        # Docker configuration
        docker_config = nodejs_security.get('docker_config', {})
        if docker_config and (docker_config.get('dockerfile_exists') or docker_config.get('container_running')):
            pdf.add_subtitle("Docker Configuration")
            
            if docker_config.get('container_running'):
                pdf.add_status_badge('info', f"Docker containers are running")
                
                # Show Node.js containers if found
                nodejs_containers = docker_config.get('nodejs_containers', [])
                if nodejs_containers:
                    pdf.add_text(f"Node.js Containers: {', '.join(nodejs_containers)}")
                
            if not docker_config.get('user_config', {}).get('non_root', False):
                pdf.add_status_badge('critical', "Docker container running as root user")
            else:
                pdf.add_status_badge('secure', "Docker container running as non-root user")
            
            if not docker_config.get('health_check', {}).get('configured', False):
                pdf.add_bullet_point("Docker health check not configured")
            else:
                pdf.add_status_badge('secure', "Docker health check configured")
            
            security_issues = docker_config.get('security_issues', [])
            if security_issues:
                pdf.add_subtitle("Docker Security Issues")
                for issue in security_issues:
                    pdf.add_status_badge('critical', issue)
        
        # Swarm configuration
        swarm_config = nodejs_security.get('swarm_config', {})
        if swarm_config and swarm_config.get('stack_deployed'):
            pdf.add_subtitle("Docker Swarm Configuration")
            
            services = swarm_config.get('services', [])
            if services:
                pdf.add_text(f"Total Services: {len(services)}")
            
            nodejs_services = swarm_config.get('nodejs_services', [])
            if nodejs_services:
                pdf.add_status_badge('secure', f"Node.js Services Found: {', '.join(nodejs_services)}")
            else:
                pdf.add_status_badge('warning', "No Node.js services (user_backend*) found")
            
            nodejs_containers = swarm_config.get('nodejs_containers', [])
            if nodejs_containers:
                pdf.add_text(f"Node.js Containers: {', '.join(nodejs_containers)}")
                
                # Show Node.js versions if available
                for container in nodejs_containers:
                    version_key = f'nodejs_version_{container}'
                    if version_key in swarm_config:
                        pdf.add_text(f"  {container}: {swarm_config[version_key]}")
            
            secrets = swarm_config.get('secrets', [])
            if not secrets:
                pdf.add_status_badge('warning', "No Docker secrets configured")
            else:
                pdf.add_status_badge('secure', f"Docker secrets configured: {', '.join(secrets)}")
            
            networks = swarm_config.get('networks', [])
            if not networks:
                pdf.add_bullet_point("Recommendation: Use custom networks for isolation")
            else:
                pdf.add_status_badge('secure', f"Custom networks configured: {', '.join(networks)}")
            
            # Show security issues from Swarm
            swarm_security_issues = swarm_config.get('security_issues', [])
            if swarm_security_issues:
                pdf.add_subtitle("Swarm Security Issues")
                for issue in swarm_security_issues:
                    pdf.add_status_badge('warning', issue)
        
        # Node.js Security summary
        security_summary = nodejs_security.get('security_summary', {})
        if security_summary:
            pdf.add_subtitle("Node.js Security Summary")
            
            critical_issues = security_summary.get('critical_issues', [])
            if critical_issues:
                pdf.add_subtitle("Critical Issues")
                for issue in critical_issues:
                    pdf.add_status_badge('critical', issue)
            
            warnings = security_summary.get('warnings', [])
            if warnings:
                pdf.add_subtitle("Warnings")
                for warning in warnings:
                    pdf.add_status_badge('warning', warning)
            
            recommendations = security_summary.get('recommendations', [])
            if recommendations:
                pdf.add_subtitle("Recommendations")
                for rec in recommendations:
                    pdf.add_bullet_point(rec)
    
    # Python Security Section
    python_security = scan_data.get('python_security', {})
    if python_security.get('python_found'):
        pdf.add_page()
        pdf.add_title("Python Security Analysis")
        
        # Requirements checks
        requirements_checks = python_security.get('requirements_checks', {})
        if requirements_checks.get('requirements_exists'):
            pdf.add_subtitle("Python Requirements Analysis")
            
            packages = requirements_checks.get('packages', {})
            pdf.add_text(f"Total packages: {packages.get('count', 0)}")
            
            versions = requirements_checks.get('versions', {})
            pinned_count = versions.get('pinned', 0)
            unpinned_count = versions.get('unpinned', 0)
            
            if pinned_count > 0:
                pdf.add_status_badge('secure', f"Pinned versions: {pinned_count}")
            
            if unpinned_count > 0:
                pdf.add_status_badge('warning', f"Unpinned versions: {unpinned_count}")
            
            # Security packages check
            security_packages = requirements_checks.get('security_packages', {})
            if security_packages.get('django'):
                pdf.add_status_badge('secure', "Django framework detected")
            if security_packages.get('flask'):
                pdf.add_status_badge('secure', "Flask framework detected")
            if security_packages.get('fastapi'):
                pdf.add_status_badge('secure', "FastAPI framework detected")
            
            vulnerable_packages = requirements_checks.get('vulnerable_packages', [])
            if vulnerable_packages:
                pdf.add_subtitle("Packages Requiring Attention")
                for package in vulnerable_packages:
                    pdf.add_status_badge('warning', f"Check for updates: {package}")
        
        # Environment file checks
        env_checks = python_security.get('env_file_checks', {})
        if env_checks.get('env_file_exists'):
            pdf.add_subtitle("Python Environment Configuration")
            
            django_settings = env_checks.get('django_settings', {})
            if django_settings.get('debug') == 'true':
                pdf.add_status_badge('critical', "Django DEBUG mode enabled - disable in production")
            elif django_settings.get('debug') == 'false':
                pdf.add_status_badge('secure', "Django DEBUG mode properly disabled")
            
            if not django_settings.get('secret_key', False):
                pdf.add_status_badge('critical', "Django/Flask SECRET_KEY is weak or missing")
            else:
                pdf.add_status_badge('secure', "Strong SECRET_KEY configured")
            
            flask_config = env_checks.get('flask_config', {})
            if flask_config.get('debug') == 'true':
                pdf.add_status_badge('critical', "Flask DEBUG mode enabled - disable in production")
            elif flask_config.get('debug') == 'false':
                pdf.add_status_badge('secure', "Flask DEBUG mode properly disabled")
            
            if env_checks.get('database_config', {}).get('exposed', False):
                pdf.add_status_badge('warning', "Database credentials may be using weak values")
            
            if env_checks.get('api_keys', {}).get('exposed', False):
                pdf.add_status_badge('warning', "API keys detected - ensure they are secure")
            
            if not env_checks.get('ssl_config', {}).get('enabled', False):
                pdf.add_bullet_point("Recommendation: Enable SSL/TLS configuration")
        
        # Security packages analysis
        security_packages = python_security.get('security_packages', {})
        if security_packages:
            pdf.add_subtitle("Security Package Analysis")
            
            packages = security_packages.get('security_packages', {})
            security_count = sum(1 for v in packages.values() if v)
            
            if security_count > 0:
                pdf.add_status_badge('secure', f"Security packages detected: {security_count}")
            else:
                pdf.add_status_badge('warning', "No security packages detected")
            
            vulnerability_scan = security_packages.get('vulnerability_scan', {})
            if vulnerability_scan.get('run'):
                issues = vulnerability_scan.get('issues', 0)
                if issues == 0:
                    pdf.add_status_badge('secure', "No pip dependency issues found")
                else:
                    pdf.add_status_badge('warning', f"Found {issues} pip dependency issues")
            
            outdated_packages = security_packages.get('outdated_packages', {})
            outdated_count = outdated_packages.get('count', 0)
            if outdated_count > 0:
                pdf.add_status_badge('warning', f"{outdated_count} outdated packages found")
        
        # Performance checks
        performance_checks = python_security.get('performance_checks', {})
        if performance_checks:
            pdf.add_subtitle("Performance & Configuration")
            
            if not performance_checks.get('wsgi_server', {}).get('configured', False):
                pdf.add_status_badge('warning', "Production WSGI server not configured")
            else:
                wsgi_file = performance_checks.get('wsgi_server', {}).get('file', '')
                pdf.add_status_badge('secure', f"WSGI server configured: {wsgi_file}")
            
            if not performance_checks.get('caching', {}).get('configured', False):
                pdf.add_bullet_point("Recommendation: Configure caching (Redis/Memcached)")
            else:
                pdf.add_status_badge('secure', "Caching configured")
            
            if not performance_checks.get('health_check', {}).get('exists', False):
                pdf.add_bullet_point("Recommendation: Implement health check endpoints")
            else:
                pdf.add_status_badge('secure', "Health check endpoints found")
        
        # Permission checks
        permission_checks = python_security.get('permission_checks', {})
        if permission_checks:
            pdf.add_subtitle("File & Directory Permissions")
            
            if not permission_checks.get('env_file_permissions', {}).get('secure', False):
                pdf.add_status_badge('critical', ".env file has insecure permissions")
            else:
                pdf.add_status_badge('secure', ".env file permissions are secure")
            
            if not permission_checks.get('venv_permissions', {}).get('secure', False):
                pdf.add_status_badge('warning', "Virtual environment has world-readable permissions")
            
            if permission_checks.get('logs_directory', {}).get('exists', False):
                if not permission_checks.get('logs_directory', {}).get('writable', False):
                    pdf.add_status_badge('warning', "Logs directory is not writable")
                else:
                    pdf.add_status_badge('secure', "Logs directory is properly configured")
        
        # Docker configuration for Python
        docker_config = python_security.get('docker_config', {})
        if docker_config.get('dockerfile_exists') or docker_config.get('container_running'):
            pdf.add_subtitle("Python Docker Configuration")
            
            if docker_config.get('dockerfile_exists'):
                pdf.add_status_badge('secure', "Dockerfile found")
                
                if not docker_config.get('user_config', {}).get('non_root', False):
                    pdf.add_status_badge('critical', "Docker container running as root user")
                else:
                    pdf.add_status_badge('secure', "Docker container running as non-root user")
                
                if not docker_config.get('health_check', {}).get('configured', False):
                    pdf.add_bullet_point("Docker health check not configured")
                else:
                    pdf.add_status_badge('secure', "Docker health check configured")
                
                security_issues = docker_config.get('security_issues', [])
                if security_issues:
                    pdf.add_subtitle("Docker Security Issues")
                    for issue in security_issues:
                        pdf.add_status_badge('critical', issue)
        
        # Swarm configuration for Python
        swarm_config = python_security.get('swarm_config', {})
        if swarm_config and swarm_config.get('stack_deployed'):
            pdf.add_subtitle("Python Docker Swarm Configuration")
            
            services = swarm_config.get('services', [])
            if services:
                pdf.add_text(f"Total Services: {len(services)}")
            
            python_services = swarm_config.get('python_services', [])
            if python_services:
                pdf.add_status_badge('secure', f"Python Services Found: {', '.join(python_services)}")
            else:
                pdf.add_status_badge('warning', "No Python services (commission*) found")
            
            python_containers = swarm_config.get('python_containers', [])
            if python_containers:
                pdf.add_text(f"Python Containers: {', '.join(python_containers)}")
                
                # Show Python versions if available
                for container in python_containers:
                    version_key = f'python_version_{container}'
                    if version_key in swarm_config:
                        pdf.add_text(f"  {container}: {swarm_config[version_key]}")
            
            secrets = swarm_config.get('secrets', [])
            if not secrets:
                pdf.add_status_badge('warning', "No Docker secrets configured")
            else:
                pdf.add_status_badge('secure', f"Docker secrets configured: {', '.join(secrets)}")
            
            networks = swarm_config.get('networks', [])
            if not networks:
                pdf.add_bullet_point("Recommendation: Use custom networks for isolation")
            else:
                pdf.add_status_badge('secure', f"Custom networks configured: {', '.join(networks)}")
            
            # Show security issues from Swarm
            swarm_security_issues = swarm_config.get('security_issues', [])
            if swarm_security_issues:
                pdf.add_subtitle("Swarm Security Issues")
                for issue in swarm_security_issues:
                    pdf.add_status_badge('warning', issue)
        
        # Python Security summary
        security_summary = python_security.get('security_summary', {})
        if security_summary:
            pdf.add_subtitle("Python Security Summary")
            
            critical_issues = security_summary.get('critical_issues', [])
            if critical_issues:
                pdf.add_subtitle("Critical Issues")
                for issue in critical_issues:
                    pdf.add_status_badge('critical', issue)
            
            warnings = security_summary.get('warnings', [])
            if warnings:
                pdf.add_subtitle("Warnings")
                for warning in warnings:
                    pdf.add_status_badge('warning', warning)
            
            recommendations = security_summary.get('recommendations', [])
            if recommendations:
                pdf.add_subtitle("Recommendations")
                for rec in recommendations:
                    pdf.add_bullet_point(rec)
    
    # Firewall Security Section
    firewall_security = scan_data.get('firewall_security', {})
    if firewall_security and not firewall_security.get('error'):
        pdf.add_page()
        pdf.add_title("Firewall & Port Security Analysis")
        
        # Firewall overview
        target_host = firewall_security.get('target_host', 'Unknown')
        office_ip = firewall_security.get('office_ip', 'Unknown')
        firewall_status = firewall_security.get('firewall_status', 'unknown')
        
        pdf.add_subtitle("Firewall Configuration Overview")
        pdf.add_text(f"Target Host: {target_host}")
        pdf.add_text(f"Office IP: {office_ip}")
        
        # Firewall status
        if firewall_status == 'secure':
            pdf.add_status_badge('secure', "Firewall configuration is secure")
        elif firewall_status == 'warning':
            pdf.add_status_badge('warning', "Firewall configuration has warnings")
        elif firewall_status == 'critical':
            pdf.add_status_badge('critical', "Firewall configuration has critical issues")
        else:
            pdf.add_status_badge('info', "Firewall status unknown")
        
        # Server local IP
        server_local_ip = firewall_security.get('server_local_ip', 'Unknown')
        if server_local_ip != 'unknown':
            pdf.add_text(f"Server Local IP: {server_local_ip}")
        
        # Firewall rules summary
        iptables_rules = firewall_security.get('iptables_rules', [])
        ufw_status = firewall_security.get('ufw_status')
        
        if iptables_rules:
            pdf.add_status_badge('info', f"iptables rules found: {len(iptables_rules)} rules")
        
        if ufw_status:
            if 'Status: active' in ufw_status:
                pdf.add_status_badge('secure', "UFW firewall is active")
            else:
                pdf.add_status_badge('warning', "UFW firewall status unclear")
        
        if not iptables_rules and not ufw_status:
            pdf.add_status_badge('warning', "No firewall configuration detected")
        
        # Port accessibility analysis
        port_accessibility = firewall_security.get('port_accessibility', {})
        if port_accessibility:
            pdf.add_subtitle("Port Accessibility Analysis")
            
            public_ports = firewall_security.get('public_ports', [])
            pdf.add_text(f"Public ports (should be accessible from anywhere): {', '.join(map(str, public_ports))}")
            
            # Analyze each port
            secure_ports = 0
            warning_ports = 0
            critical_ports = 0
            
            for port, port_data in port_accessibility.items():
                is_public_port = port_data.get('is_public_port', False)
                security_status = port_data.get('security_status', 'unknown')
                accessibility = port_data.get('accessibility', {})
                
                port_info = f"Port {port}"
                if is_public_port:
                    port_info += " (Public)"
                
                if security_status == 'secure':
                    pdf.add_status_badge('secure', f"{port_info}: Properly configured")
                    secure_ports += 1
                elif security_status == 'warning':
                    pdf.add_status_badge('warning', f"{port_info}: Configuration warning")
                    warning_ports += 1
                elif security_status == 'critical':
                    pdf.add_status_badge('critical', f"{port_info}: Security issue")
                    critical_ports += 1
                elif security_status == 'public':
                    pdf.add_status_badge('info', f"{port_info}: Public access (expected)")
                else:
                    pdf.add_status_badge('info', f"{port_info}: Status unknown")
                
                # Show accessibility details
                office_access = accessibility.get('office', {}).get('accessible', False)
                external_access = accessibility.get('external', {}).get('accessible', False)
                local_access = accessibility.get('local', {}).get('accessible', True)
                
                access_details = []
                if office_access:
                    access_details.append("Office ✓")
                if external_access:
                    access_details.append("External ✓")
                if local_access:
                    access_details.append("Local ✓")
                
                if access_details:
                    pdf.add_text(f"  Access from: {', '.join(access_details)}")
            
            # Port security summary
            pdf.add_subtitle("Port Security Summary")
            total_ports = len(port_accessibility)
            pdf.add_text(f"Total ports analyzed: {total_ports}")
            
            if secure_ports > 0:
                pdf.add_status_badge('secure', f"Secure ports: {secure_ports}")
            if warning_ports > 0:
                pdf.add_status_badge('warning', f"Ports with warnings: {warning_ports}")
            if critical_ports > 0:
                pdf.add_status_badge('critical', f"Ports with critical issues: {critical_ports}")
        
        # Security issues
        security_issues = firewall_security.get('security_issues', [])
        if security_issues:
            pdf.add_subtitle("Critical Security Issues")
            for issue in security_issues:
                pdf.add_status_badge('critical', issue)
        
        # Warnings
        warnings = firewall_security.get('warnings', [])
        if warnings:
            pdf.add_subtitle("Security Warnings")
            for warning in warnings:
                pdf.add_status_badge('warning', warning)
        
        # Firewall recommendations
        recommendations = firewall_security.get('recommendations', [])
        if recommendations:
            pdf.add_subtitle("Firewall Recommendations")
            for rec in recommendations:
                pdf.add_bullet_point(rec)
        
        # Configuration recommendations
        config_recommendations = firewall_security.get('configuration_recommendations', [])
        if config_recommendations:
            pdf.add_subtitle("Firewall Configuration Commands")
            pdf.add_text("Run these commands to improve firewall security:")
            
            # Group commands by firewall type
            ufw_commands = [cmd for cmd in config_recommendations if 'ufw' in cmd and not cmd.startswith('#')]
            iptables_commands = [cmd for cmd in config_recommendations if 'iptables' in cmd and not cmd.startswith('#')]
            
            if ufw_commands:
                pdf.add_text("UFW Commands:")
                for cmd in ufw_commands[:10]:  # Limit to first 10 commands
                    pdf.add_text(f"  {cmd}")
            
            if iptables_commands:
                pdf.add_text("iptables Commands:")
                for cmd in iptables_commands[:10]:  # Limit to first 10 commands
                    pdf.add_text(f"  {cmd}")
    
    # Docker Issues Section
    docker_issues = scan_data.get('docker_issues', [])
    if docker_issues:
        pdf.add_page()
        pdf.add_title("Docker Security Issues")
        for issue in docker_issues:
            if isinstance(issue, dict):
                pdf.add_status_badge('warning', issue.get('description', str(issue)))
            else:
                pdf.add_status_badge('warning', str(issue))
    
    # System Information
    system_info = scan_data.get('system_info', {})
    if system_info:
        pdf.add_page()
        pdf.add_title("System Information")
        for key, value in system_info.items():
            if key != 'error':
                pdf.add_text(f"{key.replace('_', ' ').title()}: {value}")
    
    # Recommendations Section
    pdf.add_page()
    pdf.add_title("Security Recommendations")
    
    all_recommendations = []
    
    # Collect all recommendations
    if laravel_security.get('security_summary', {}).get('recommendations'):
        all_recommendations.extend([f"Laravel: {rec}" for rec in laravel_security['security_summary']['recommendations']])
    
    if nodejs_security.get('security_summary', {}).get('recommendations'):
        all_recommendations.extend([f"Node.js: {rec}" for rec in nodejs_security['security_summary']['recommendations']])
    
    python_security = scan_data.get('python_security', {})
    if python_security.get('security_summary', {}).get('recommendations'):
        all_recommendations.extend([f"Python: {rec}" for rec in python_security['security_summary']['recommendations']])
    
    firewall_security = scan_data.get('firewall_security', {})
    if firewall_security.get('recommendations'):
        all_recommendations.extend([f"Firewall: {rec}" for rec in firewall_security['recommendations']])
    
    # General recommendations
    general_recommendations = [
        "Regularly update all software packages and dependencies",
        "Implement proper backup and disaster recovery procedures",
        "Use strong, unique passwords and enable two-factor authentication",
        "Regularly monitor system logs for suspicious activities",
        "Keep the operating system and all software up to date",
        "Implement network segmentation and firewall rules",
        "Use HTTPS/TLS for all web communications",
        "Regularly perform security assessments and penetration testing"
    ]
    
    if all_recommendations:
        pdf.add_subtitle("Project-Specific Recommendations")
        for i, rec in enumerate(all_recommendations, 1):
            pdf.add_bullet_point(f"{i}. {rec}")
        
        pdf.ln(5)
        pdf.add_subtitle("General Security Best Practices")
        for i, rec in enumerate(general_recommendations, 1):
            pdf.add_bullet_point(f"{i}. {rec}")
    else:
        pdf.add_subtitle("General Security Best Practices")
        for i, rec in enumerate(general_recommendations, 1):
            pdf.add_bullet_point(f"{i}. {rec}")
        
        pdf.ln(5)
        pdf.add_status_badge('info', "No specific security issues found. Continue monitoring and following best practices.")
    
    # Generate unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{host}_{timestamp}.pdf"
    
    # Ensure reports directory exists
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    filepath = os.path.join(reports_dir, filename)
    pdf.output(filepath)
    
    return filepath