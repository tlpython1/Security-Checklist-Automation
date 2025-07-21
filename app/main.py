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
    key_passphrase: str = Form(None)
):
    # Handle authentication based on method
    if auth_method == "password":
        if not password:
            return {"error": "Password is required for password authentication"}
        result = run_full_scan(host, port, username, password=password)
    
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
            result = run_full_scan(host, port, username, ssh_key_path=temp_key_path, key_passphrase=key_passphrase)
        finally:
            # Clean up temporary key file
            if os.path.exists(temp_key_path):
                os.unlink(temp_key_path)
    
    else:
        return {"error": "Invalid authentication method. Use 'password' or 'key'"}
    
    return result