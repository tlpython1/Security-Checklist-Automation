from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from scanner.security_checker import run_full_scan
import os
import tempfile
import json
import asyncio
import time
from typing import Generator

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Global dictionary to store scan progress
scan_progress = {}

def generate_progress_stream(scan_id: str) -> Generator[str, None, None]:
    """Generate Server-Sent Events for scan progress"""
    import time
    
    while True:
        if scan_id in scan_progress:
            progress_data = scan_progress[scan_id]
            yield f"data: {json.dumps(progress_data)}\n\n"
            
            # If scan is complete, clean up and break
            if progress_data.get('status') in ['completed', 'error']:
                break
        
        time.sleep(0.5)  # Check every 500ms

@app.get("/debug/progress")
async def debug_progress():
    """Debug endpoint to see all scan progress"""
    return {
        "current_scans": scan_progress,
        "total_scans": len(scan_progress)
    }

@app.get("/progress/{scan_id}")
async def get_scan_progress(scan_id: str):
    """Get current scan progress as JSON"""
    if scan_id in scan_progress:
        progress_data = scan_progress[scan_id]
        print(f"DEBUG: Returning progress for {scan_id}: {progress_data}")
        return progress_data
    else:
        print(f"DEBUG: Scan ID {scan_id} not found in progress dict. Available IDs: {list(scan_progress.keys())}")
        return {'status': 'not_found', 'message': 'Scan not found'}

class ProgressCallback:
    """Callback class to update scan progress"""
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.current_step = 0
        self.total_steps = 11  # Updated: connection + authentication + connection_established + 8 scan steps
    
    def update(self, status: str, message: str, step_name: str = None):
        """Update progress with current status and message"""
        if step_name:
            self.current_step += 1
        
        progress_percent = min(int((self.current_step / self.total_steps) * 100), 100)
        
        # Debug logging
        print(f"DEBUG: Progress update - Step {self.current_step}/{self.total_steps} ({progress_percent}%): {message}")
        
        scan_progress[self.scan_id] = {
            'status': status,
            'message': message,
            'step': self.current_step,
            'total_steps': self.total_steps,
            'progress_percent': progress_percent,
            'current_operation': step_name or 'Processing...'
        }

def run_scan_with_progress(scan_id: str, *args, **kwargs):
    """Run scan with progress updates"""
    callback = ProgressCallback(scan_id)
    
    try:
        # Update progress throughout the scan
        callback.update('running', '🔍 Initializing security scan...', 'initialization')
        
        # Note: We'll need to modify the security checker to accept callbacks
        # For now, we'll simulate progress updates
        result = run_full_scan(*args, **kwargs)
        
        if result.get('status') == 'success':
            callback.update('completed', f'✅ Scan completed successfully! Report generated.', 'completed')
        else:
            callback.update('error', f'❌ Scan failed: {result.get("error", "Unknown error")}', 'error')
        
        return result
        
    except Exception as e:
        callback.update('error', f'❌ Scan failed with error: {str(e)}', 'error')
        return {'status': 'failed', 'error': str(e)}

@app.get("/", response_class=HTMLResponse)
def read_form(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def scan_server(
    request: Request,
    host: str = Form(...),
    port: int = Form(...),
    username: str = Form(...),
    auth_method: str = Form('password'),  # "password" or "key"
    password: str = Form(None),
    ssh_key: UploadFile = File(None),
    key_passphrase: str = Form(None),
    project_path: str = Form('/www/wwwroot/team1/damon/'),
    stack_name: str = Form(None)  # Docker Swarm stack name (optional)
):
    # Generate unique scan ID
    import time
    scan_id = f"scan_{int(time.time() * 1000)}"
    
    # Initialize progress
    scan_progress[scan_id] = {
        'status': 'starting',
        'message': '🚀 Starting security scan...',
        'step': 0,
        'total_steps': 11,
        'progress_percent': 0,
        'current_operation': 'Initializing'
    }
    
    print(f"DEBUG: Initial progress set for {scan_id}: {scan_progress[scan_id]}")
    
    # Add small delay to ensure progress is set before polling starts
    import asyncio
    await asyncio.sleep(0.1)
    
    try:
        # Handle authentication based on method
        if auth_method == "password":
            if not password:
                scan_progress[scan_id] = {
                    'status': 'error',
                    'message': '❌ Password is required for password authentication',
                    'step': 0,
                    'total_steps': 11,
                    'progress_percent': 0,
                    'current_operation': 'Error'
                }
                return {"error": "Password is required for password authentication", "scan_id": scan_id}
            
            # Run scan in background with progress updates
            result = await asyncio.get_event_loop().run_in_executor(
                None, 
                run_scan_with_progress,
                scan_id, host, port, username,
                password, None, None, project_path, stack_name
            )
        
        elif auth_method == "key":
            if not ssh_key:
                scan_progress[scan_id] = {
                    'status': 'error',
                    'message': '❌ SSH key file is required for key authentication',
                    'step': 0,
                    'total_steps': 11,
                    'progress_percent': 0,
                    'current_operation': 'Error'
                }
                return {"error": "SSH key file is required for key authentication", "scan_id": scan_id}
            
            # Save uploaded SSH key to temporary file
            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as temp_key:
                content = await ssh_key.read()
                temp_key.write(content)
                temp_key_path = temp_key.name
            
            try:
                # Set proper permissions for SSH key
                os.chmod(temp_key_path, 0o600)
                
                # Run scan in background with progress updates
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    run_scan_with_progress,
                    scan_id, host, port, username,
                    None, temp_key_path, key_passphrase, project_path, stack_name
                )
            finally:
                # Clean up temporary key file
                if os.path.exists(temp_key_path):
                    os.unlink(temp_key_path)
        
        else:
            scan_progress[scan_id] = {
                'status': 'error',
                'message': '❌ Invalid authentication method',
                'step': 0,
                'total_steps': 11,
                'progress_percent': 0,
                'current_operation': 'Error'
            }
            return {"error": "Invalid authentication method. Use 'password' or 'key'", "scan_id": scan_id}
        
        # Add download link to the response if report was generated
        if result.get('report_path'):
            report_filename = os.path.basename(result['report_path'])
            result['report_download_url'] = f"/download-report/{report_filename}"
            result['report_filename'] = report_filename
        
        result['scan_id'] = scan_id
        return result
        
    except Exception as e:
        scan_progress[scan_id] = {
            'status': 'error',
            'message': f'❌ Unexpected error: {str(e)}',
            'step': 0,
            'total_steps': 11,
            'progress_percent': 0,
            'current_operation': 'Error'
        }
        return {"error": str(e), "scan_id": scan_id}

def run_scan_with_progress(scan_id: str, host, port, username, password=None, ssh_key_path=None, key_passphrase=None, project_path=None, stack_name=None):
    """Run scan with detailed progress updates"""
    callback = ProgressCallback(scan_id)
    
    try:
        # Initialize scan
        callback.update('running', '� Initializing security scan...', 'initialization')
        
        # Run the actual scan with progress callback
        result = run_full_scan(
            host, port, username,
            password=password,
            ssh_key_path=ssh_key_path,
            key_passphrase=key_passphrase,
            project_path=project_path,
            stack_name=stack_name,
            progress_callback=callback  # Pass the callback to the scanner
        )
        
        # Progress completion is now handled inside the security checker
        return result
        
    except Exception as e:
        callback.update('error', f'❌ Scan failed: {str(e)}', 'error')
        return {'status': 'failed', 'error': str(e)}

@app.get("/download-report/{report_filename}")
async def download_report(report_filename: str):
    """
    Download the generated security report PDF
    """
    reports_dir = os.path.join(os.getcwd(), "reports")
    report_path = os.path.join(reports_dir, report_filename)
    
    if os.path.exists(report_path):
        return FileResponse(
            path=report_path,
            filename=report_filename,
            media_type='application/pdf'
        )
    else:
        return {"error": "Report file not found"}

@app.get("/reports")
async def list_reports():
    """
    List all available security reports
    """
    reports_dir = os.path.join(os.getcwd(), "reports")
    if not os.path.exists(reports_dir):
        return {"reports": []}
    
    reports = []
    for filename in os.listdir(reports_dir):
        if filename.endswith('.pdf'):
            filepath = os.path.join(reports_dir, filename)
            file_stats = os.stat(filepath)
            reports.append({
                "filename": filename,
                "size": file_stats.st_size,
                "created": file_stats.st_ctime,
                "download_url": f"/download-report/{filename}"
            })
    
    return {"reports": reports}