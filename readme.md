# Security Checklist Automation

A comprehensive security scanning tool that automates server security assessments, including port scanning, sensitive file detection, and Docker security evaluation.

## 🔒 Features

- **Port Scanning**: Fast scanning of common ports with accessibility analysis
- **Sensitive File Detection**: Identifies and checks security status of sensitive configuration files
- **Docker Security**: Evaluates Docker container and image security configurations
- **Firewall Analysis**: Checks UFW and iptables rules for port accessibility
- **PDF Reports**: Generates detailed security assessment reports
- **SSH/Password Authentication**: Supports both SSH key and password authentication
- **Web Interface**: RESTful API with comprehensive scanning endpoints

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- nmap (for port scanning)
- SSH access to target servers

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd security-checklist-automation
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

4. Start the application:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8081
```

5. Access the API documentation:
```
http://localhost:8081/docs
```

## 📋 API Endpoints

### Security Scanning

- `POST /scan/full` - Complete security scan
- `POST /scan/quick` - Quick port and system scan
- `POST /scan/ports` - Port scanning only
- `POST /scan/files` - Sensitive file detection
- `POST /scan/docker` - Docker security assessment

### Example Request

```json
{
  "host": "192.168.1.100",
  "port": 22,
  "username": "admin",
  "password": "your_password",
  "project_path": "/var/www/html"
}
```

## 🔧 Configuration

### Sensitive Files Monitored

- `.env` - Environment configuration files
- `config.php` - PHP configuration files
- `settings.py` - Python settings files

### Port Categories

**Web Services**: 80, 443, 8080, 8443, 3000, 5000
**Remote Access**: 22, 23, 3389, 5900
**Databases**: 3306, 5432, 27017, 6379
**Mail Services**: 25, 110, 143, 587, 993, 995

## 📊 Security Checks

### File Security Assessment
- **Permissions**: Checks world-readable/writable status
- **Public Accessibility**: Verifies if files are web-accessible
- **Protection Rules**: Analyzes .htaccess and nginx configurations
- **Security Status**: Categorizes as secure, warning, or critical

### Port Accessibility Analysis
- **Firewall Rules**: UFW and iptables rule analysis
- **Global Access**: Identifies publicly accessible ports
- **Restricted Access**: Lists IP-restricted services
- **Service Detection**: Identifies running services and versions

## 🏗️ Project Structure

```
security-checklist-automation/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── scanner/
│   │   ├── port_scanner.py     # Port scanning functionality
│   │   ├── file_checker.py     # Sensitive file detection
│   │   ├── docker_checker.py   # Docker security checks
│   │   ├── security_checker.py # Main security scanner
│   │   └── report_generator.py # PDF report generation
│   └── utils/
│       └── logger.py           # Logging configuration
├── requirements.txt            # Python dependencies
└── readme.md                  # This file
```

## 🔐 Security Considerations

- Never store credentials in plaintext
- Use SSH keys when possible
- Limit scanner access to necessary systems
- Review firewall rules regularly
- Monitor for suspicious file permissions

## 📝 Output Examples

### Scan Results
```json
{
  "status": "success",
  "host": "192.168.1.100",
  "open_ports": [22, 80, 443],
  "sensitive_files": [
    {
      "filename": ".env",
      "full_path": "/var/www/.env",
      "security_status": "critical",
      "permissions": {"octal": "644"},
      "public_accessible": {"potentially_public": true}
    }
  ],
  "security_summary": {
    "total_open_ports": 3,
    "sensitive_files_count": 1,
    "scan_type": "Comprehensive"
  }
}
```

## 🐳 Docker Support

The scanner can evaluate Docker security including:
- Container privilege escalation
- Volume mount security
- Network configuration
- Image vulnerability scanning

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security assessments only. Users are responsible for ensuring they have proper authorization before scanning any systems.

## 🆘 Support

For issues and questions:
- Create an issue in the repository
- Check the API documentation at `/docs`
- Review the logs for detailed error information

## 🔄 Version History

- **v1.0.0** - Initial release with basic scanning capabilities
- **v1.1.0** - Added Docker security checks
- **v1.2.0** - Enhanced file security analysis
- **v1.3.0** - Improved firewall rule parsing