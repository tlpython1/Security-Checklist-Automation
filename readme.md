# Security Checklist Automation

A comprehensive security scanning tool that automates server security assessments, including port scanning, sensitive file detection, and Docker security evaluation.

## 🔒 Features

- **Port Scanning**: Fast scanning of common ports with accessibility analysis
- **Sensitive File Detection**: Identifies and checks security status of sensitive configuration files
- **Laravel Security Analysis**: Comprehensive checks for Laravel applications (environment, caching, permissions)
- **Node.js Security Analysis**: Complete security assessment for Node.js applications including Docker/Swarm support
- **Docker Security**: Evaluates Docker container and image security configurations
- **Docker Swarm Support**: Analyzes Docker Swarm stacks, services, secrets, and networks
- **Firewall Analysis**: Checks UFW and iptables rules for port accessibility
- **PDF Reports**: Generates detailed, professional security assessment reports
- **SSH/Password Authentication**: Supports both SSH key and password authentication
- **Web Interface**: RESTful API with comprehensive scanning endpoints and report downloads

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

**Option 1: Using the startup script (Recommended)**
```bash
# Linux/Mac
./run_server.sh

# Windows
run_server.bat

# Cross-platform Python script
python3 start_server.py
```

**Option 2: Manual startup**
```bash
# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate.bat  # Windows

# Start the server
cd app
uvicorn main:app --reload --host 0.0.0.0 --port 8081
```

5. Access the API documentation:
```
http://localhost:8081/docs
```

## �️ Startup Scripts

The project includes several startup scripts for convenience:

### Linux/Mac Shell Script (`run_server.sh`)
- Automatically creates and activates virtual environment
- Installs dependencies if missing
- Starts the FastAPI server with proper configuration
- Provides colored output for better visibility

### Windows Batch Script (`run_server.bat`)
- Windows equivalent of the shell script
- Handles virtual environment creation and activation
- Installs missing dependencies automatically

### Cross-Platform Python Script (`start_server.py`)
- Works on all platforms (Linux, Mac, Windows)
- Python-based startup with comprehensive error handling
- Automatic dependency management
- Colored terminal output for better user experience

**Features of all startup scripts:**
- ✅ Automatic virtual environment creation
- ✅ Dependency installation and verification
- ✅ Server configuration validation
- ✅ Graceful error handling
- ✅ Clean shutdown and cleanup

## �📋 API Endpoints

### Security Scanning

- `POST /scan` - Complete security scan with PDF report generation
- `GET /download-report/{filename}` - Download generated PDF report
- `GET /reports` - List all available security reports
- `GET /` - Web interface for easy scanning

### Example Request

```json
{
  "host": "192.168.1.100",
  "port": 22,
  "username": "admin",
  "password": "your_password",
  "project_path": "/var/www/html/myapp",
  "stack_name": "myapp-production"
}
```

### Example Response

```json
{
  "status": "success",
  "host": "192.168.1.100",
  "scan_timestamp": "2025-07-23 12:30:45",
  "report_path": "/path/to/reports/security_report_192.168.1.100_20250723_123045.pdf",
  "report_download_url": "/download-report/security_report_192.168.1.100_20250723_123045.pdf",
  "report_filename": "security_report_192.168.1.100_20250723_123045.pdf",
  "security_summary": {
    "sensitive_files_count": 2,
    "laravel_security_issues": 1,
    "nodejs_security_issues": 3,
    "docker_issues_count": 0
  }
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

## 📊 Security Report Features

### Comprehensive PDF Reports
- **Executive Summary**: Overview of scan results and security status
- **Port Analysis**: Detailed breakdown of open ports and accessibility
- **Sensitive Files**: Security assessment of configuration files
- **Laravel Analysis**: Framework-specific security checks and recommendations
- **Node.js Analysis**: JavaScript runtime security evaluation
- **Docker Assessment**: Container and orchestration security review
- **System Information**: Server details and configuration
- **Security Recommendations**: Actionable steps to improve security

### Report Sections Include:
- Color-coded security status (Critical/Warning/Secure)
- Detailed vulnerability descriptions
- Step-by-step remediation instructions
- Performance optimization recommendations
- Docker and Swarm configuration analysis
- Environment variable security checks
- Package vulnerability assessments

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
│   │   ├── laravel_checker.py  # Laravel security analysis
│   │   ├── node_checker.py     # Node.js security analysis
│   │   └── report_generator.py # PDF report generation
│   ├── templates/
│   │   └── index.html          # Web interface
│   └── utils/
│       └── logger.py           # Logging configuration
├── reports/                    # Generated PDF reports (auto-created)
├── venv/                       # Virtual environment (auto-created)
├── run_server.sh              # Linux/Mac startup script
├── run_server.bat             # Windows startup script
├── start_server.py            # Cross-platform Python startup script
├── requirements.txt           # Python dependencies
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