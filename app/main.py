from fastapi import FastAPI, Request, Form, File, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from scanner.security_checker import run_full_scan
import os
import tempfile

app = FastAPI()
templates = Jinja2Templates(directory="templates")

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
    # Handle authentication based on method
    if auth_method == "password":
        if not password:
            return {"error": "Password is required for password authentication"}
        result = run_full_scan(host, port, username, password=password, project_path=project_path, stack_name=stack_name)
    
    elif auth_method == "key":
        if not ssh_key:
            return {"error": "SSH key file is required for key authentication"}
        
        # Save uploaded SSH key to temporary file
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem") as temp_key:
            content = await ssh_key.read()
            temp_key.write(content)
            temp_key_path = temp_key.name
        
        try:
            # Set proper permissions for SSH key
            os.chmod(temp_key_path, 0o600)
            result = run_full_scan(host, port, username, ssh_key_path=temp_key_path, key_passphrase=key_passphrase, project_path=project_path, stack_name=stack_name)
        finally:
            # Clean up temporary key file
            if os.path.exists(temp_key_path):
                os.unlink(temp_key_path)
    
    else:
        return {"error": "Invalid authentication method. Use 'password' or 'key'"}
    
    # Add download link to the response if report was generated
    if result.get('report_path'):
        report_filename = os.path.basename(result['report_path'])
        result['report_download_url'] = f"/download-report/{report_filename}"
        result['report_filename'] = report_filename
    
    return result

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