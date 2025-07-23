#!/usr/bin/env python3
"""
Security Checklist Automation - Python Startup Script
This script automatically sets up and starts the FastAPI server
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'  # No Color

def print_colored(message, color=Colors.NC):
    """Print colored message to terminal"""
    print(f"{color}{message}{Colors.NC}")

def print_header():
    """Print application header"""
    print_colored("\n" + "="*60, Colors.BLUE)
    print_colored("🚀 Security Checklist Automation Server", Colors.BLUE)
    print_colored("="*60, Colors.BLUE)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print_colored("❌ Python 3.8+ is required", Colors.RED)
        sys.exit(1)
    print_colored(f"✅ Python {sys.version.split()[0]} detected", Colors.GREEN)

def check_venv_exists():
    """Check if virtual environment exists"""
    venv_path = Path("venv")
    if not venv_path.exists():
        print_colored("⚠️  Virtual environment not found. Creating one...", Colors.YELLOW)
        try:
            subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
            print_colored("✅ Virtual environment created successfully", Colors.GREEN)
        except subprocess.CalledProcessError:
            print_colored("❌ Failed to create virtual environment", Colors.RED)
            sys.exit(1)
    else:
        print_colored("✅ Virtual environment found", Colors.GREEN)

def get_venv_python():
    """Get the path to Python executable in virtual environment"""
    script_dir = Path(__file__).parent
    if os.name == 'nt':  # Windows
        return script_dir / "venv/Scripts/python.exe"
    else:  # Unix-like
        return script_dir / "venv/bin/python"

def get_venv_uvicorn():
    """Get the path to uvicorn executable in virtual environment"""
    script_dir = Path(__file__).parent
    if os.name == 'nt':  # Windows
        return script_dir / "venv/Scripts/uvicorn.exe"
    else:  # Unix-like
        return script_dir / "venv/bin/uvicorn"

def install_dependencies():
    """Install dependencies from requirements.txt"""
    venv_python = get_venv_python()
    
    # Check if FastAPI and uvicorn are installed
    try:
        result = subprocess.run([str(venv_python), "-c", "import fastapi, uvicorn"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print_colored("✅ Dependencies are already installed", Colors.GREEN)
            return
    except:
        pass
    
    print_colored("📦 Installing dependencies...", Colors.BLUE)
    
    if not Path("requirements.txt").exists():
        print_colored("❌ requirements.txt not found", Colors.RED)
        sys.exit(1)
    
    try:
        # Upgrade pip first
        subprocess.run([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        
        # Install requirements
        subprocess.run([str(venv_python), "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True)
        print_colored("✅ Dependencies installed successfully", Colors.GREEN)
    except subprocess.CalledProcessError as e:
        print_colored(f"❌ Failed to install dependencies: {e}", Colors.RED)
        sys.exit(1)

def check_main_file():
    """Check if main.py exists in app directory"""
    main_file = Path("app/main.py")
    if not main_file.exists():
        print_colored("❌ main.py not found in app directory", Colors.RED)
        sys.exit(1)
    print_colored("✅ main.py found", Colors.GREEN)

def start_server():
    """Start the FastAPI server"""
    venv_python = get_venv_python()
    venv_uvicorn = get_venv_uvicorn()
    
    print_colored("\n🌐 Server Configuration:", Colors.BLUE)
    print_colored("   Host: 0.0.0.0", Colors.CYAN)
    print_colored("   Port: 8081", Colors.CYAN)
    print_colored("   URL:  http://localhost:8081", Colors.CYAN)
    print_colored("   Docs: http://localhost:8081/docs", Colors.CYAN)
    print_colored("   API:  http://localhost:8081/redoc", Colors.CYAN)
    
    print_colored("\n🚀 Starting FastAPI server...", Colors.BLUE)
    print_colored("📝 Press Ctrl+C to stop the server", Colors.YELLOW)
    print_colored("-" * 60, Colors.BLUE)
    
    try:
        # Change to app directory and start server
        original_dir = os.getcwd()
        os.chdir("app")
        
        # Try uvicorn executable first
        if venv_uvicorn.exists():
            subprocess.run([
                str(venv_uvicorn),
                "main:app",
                "--reload",
                "--host", "0.0.0.0",
                "--port", "8081"
            ])
        else:
            # Fallback to using Python module
            subprocess.run([
                str(venv_python), "-m", "uvicorn",
                "main:app",
                "--reload",
                "--host", "0.0.0.0",
                "--port", "8081"
            ])
    except KeyboardInterrupt:
        print_colored("\n🛑 Server stopped by user", Colors.YELLOW)
    except subprocess.CalledProcessError as e:
        print_colored(f"\n❌ Server failed to start: {e}", Colors.RED)
        sys.exit(1)
    except FileNotFoundError as e:
        print_colored(f"\n❌ Server executable not found: {e}", Colors.RED)
        print_colored("💡 Try: pip install uvicorn[standard]", Colors.YELLOW)
        sys.exit(1)
    finally:
        # Return to original directory
        try:
            os.chdir(original_dir)
        except:
            pass

def main():
    """Main function"""
    print_header()
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    try:
        check_python_version()
        check_venv_exists()
        install_dependencies()
        check_main_file()
        start_server()
    except KeyboardInterrupt:
        print_colored("\n🛑 Startup cancelled by user", Colors.YELLOW)
    except Exception as e:
        print_colored(f"\n❌ Unexpected error: {e}", Colors.RED)
        sys.exit(1)
    finally:
        print_colored("\n✅ Cleanup completed", Colors.GREEN)

if __name__ == "__main__":
    main()
