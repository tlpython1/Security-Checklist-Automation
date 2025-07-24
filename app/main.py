from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import json
import uuid
import queue
import threading
import time
from scanner.security_checker import run_full_scan

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Mount static files for reports
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

# Store progress queues for active scans
active_scans = {}

class ScanProgressManager:
    def __init__(self):
        self.scans = {}
        # Define scan stages for progress calculation
        self.scan_stages = [
            'connection',      # 1. Establishing connection
            'port_scan',       # 2. Port scanning  
            'firewall',        # 3. Firewall analysis
            'laravel',         # 4. Laravel security check
            'node',            # 5. Node.js security check
            'python',          # 6. Python security check
            'docker',          # 7. Docker security check
            'file_check',      # 8. File permission check
            'report',          # 9. Generating report
            'complete'         # 10. Completion
        ]
    
    def create_scan(self, scan_id: str):
        """Create a new scan progress queue"""
        self.scans[scan_id] = {
            'queue': queue.Queue(),
            'status': 'running',
            'result': None,
            'current_stage': 0,
            'total_stages': len(self.scan_stages)
        }
    
    def update_progress(self, scan_id: str, message: str, stage: str):
        """Add progress update to scan queue with percentage calculation"""
        if scan_id in self.scans:
            scan_data = self.scans[scan_id]
            
            # Update current stage index
            if stage in self.scan_stages:
                stage_index = self.scan_stages.index(stage)
                scan_data['current_stage'] = max(scan_data['current_stage'], stage_index)
            
            # Calculate progress percentage
            progress_percentage = (scan_data['current_stage'] / scan_data['total_stages']) * 100
            
            progress_data = {
                "stage": stage,
                "message": message,
                "timestamp": time.strftime('%H:%M:%S'),
                "status": "progress",
                "percentage": round(progress_percentage, 1),
                "current_stage": scan_data['current_stage'] + 1,
                "total_stages": scan_data['total_stages']
            }
            self.scans[scan_id]['queue'].put(progress_data)
    
    def complete_scan(self, scan_id: str, result: dict):
        """Mark scan as complete"""
        if scan_id in self.scans:
            self.scans[scan_id]['status'] = 'complete'
            self.scans[scan_id]['result'] = result
            
            # Add download URL if report path exists
            if 'report_path' in result:
                import os
                report_filename = os.path.basename(result['report_path'])
                result['report_download_url'] = f"/download-report/{report_filename}"
            
            completion_data = {
                "stage": "complete",
                "message": "✅ Scan completed successfully!",
                "timestamp": time.strftime('%H:%M:%S'),
                "status": "complete",
                "percentage": 100,
                "current_stage": len(self.scan_stages),
                "total_stages": len(self.scan_stages),
                "result": result
            }
            self.scans[scan_id]['queue'].put(completion_data)
    
    def error_scan(self, scan_id: str, error: str):
        """Mark scan as failed"""
        if scan_id in self.scans:
            self.scans[scan_id]['status'] = 'error'
            
            scan_data = self.scans[scan_id]
            current_percentage = (scan_data['current_stage'] / scan_data['total_stages']) * 100
            
            error_data = {
                "stage": "error",
                "message": f"❌ Scan failed: {error}",
                "timestamp": time.strftime('%H:%M:%S'),
                "status": "error",
                "percentage": round(current_percentage, 1),
                "current_stage": scan_data['current_stage'],
                "total_stages": scan_data['total_stages']
            }
            self.scans[scan_id]['queue'].put(error_data)
    
    def cleanup_scan(self, scan_id: str):
        """Remove scan data after completion"""
        if scan_id in self.scans:
            del self.scans[scan_id]

# Global progress manager
progress_manager = ScanProgressManager()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/start-scan")
async def start_scan(
    host: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    password: str = Form(None),
    ssh_key_path: str = Form(None),
    key_passphrase: str = Form(None),
    comprehensive_scan: bool = Form(False),
    project_path: str = Form("/var/www/html"),
    stack_name: str = Form(None)
):
    """
    Start a new scan and return scan ID for progress tracking
    """
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Create progress tracking for this scan
    progress_manager.create_scan(scan_id)
    
    def progress_callback(message: str, stage: str):
        """Callback function to update progress"""
        progress_manager.update_progress(scan_id, message, stage)
    
    def run_scan_thread():
        """Run scan in background thread"""
        try:
            result = run_full_scan(
                host=host,
                port=port,
                username=username,
                password=password,
                ssh_key_path=ssh_key_path,
                key_passphrase=key_passphrase,
                comprehensive_scan=comprehensive_scan,
                project_path=project_path,
                stack_name=stack_name,
                progress_callback=progress_callback
            )
            
            progress_manager.complete_scan(scan_id, result)
            
        except Exception as e:
            progress_manager.error_scan(scan_id, str(e))
            # Also log the error with traceback for debugging
            import logging
            logging.getLogger(__name__).error(f"Scan failed for {scan_id}: {e}", exc_info=True)
    
    # Start scan in background thread
    scan_thread = threading.Thread(target=run_scan_thread, daemon=True)
    scan_thread.start()
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan started successfully",
        "progress_url": f"/scan-progress/{scan_id}"
    }

@app.get("/scan-progress/{scan_id}")
async def scan_progress(scan_id: str):
    """
    Server-Sent Events endpoint for real-time scan progress
    """
    async def event_generator():
        if scan_id not in progress_manager.scans:
            yield f"data: {json.dumps({'error': 'Scan not found', 'status': 'error'})}\n\n"
            return
        
        scan_data = progress_manager.scans[scan_id]
        
        # Send initial connection message
        yield f"data: {json.dumps({'message': 'Connected to scan progress', 'stage': 'connection', 'status': 'connected'})}\n\n"
        
        while scan_data['status'] == 'running':
            try:
                # Check for new progress updates (non-blocking)
                try:
                    progress_update = scan_data['queue'].get_nowait()
                    yield f"data: {json.dumps(progress_update)}\n\n"
                    
                    # If scan is complete, break the loop
                    if progress_update.get('status') in ['complete', 'error']:
                        break
                        
                except queue.Empty:
                    # No new updates, send heartbeat
                    yield f"data: {json.dumps({'status': 'heartbeat'})}\n\n"
                
                await asyncio.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e), 'status': 'error'})}\n\n"
                break
        
        # Send any remaining messages in queue
        while not scan_data['queue'].empty():
            try:
                progress_update = scan_data['queue'].get_nowait()
                yield f"data: {json.dumps(progress_update)}\n\n"
            except queue.Empty:
                break
        
        # Clean up after 30 seconds
        await asyncio.sleep(30)
        progress_manager.cleanup_scan(scan_id)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "text/event-stream"
        }
    )

@app.get("/scan-status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get current scan status"""
    if scan_id not in progress_manager.scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = progress_manager.scans[scan_id]
    return {
        "scan_id": scan_id,
        "status": scan_data['status'],
        "result": scan_data.get('result')
    }

@app.get("/download-report/{filename}")
async def download_report(filename: str):
    """Download generated PDF report"""
    import os
    report_path = os.path.join("reports", filename)
    
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        path=report_path,
        filename=filename,
        media_type="application/pdf"
    )

@app.get("/debug/progress")
async def debug_progress():
    """Debug endpoint to see all scan progress"""
    return {
        "current_scans": progress_manager.scans,
        "total_scans": len(progress_manager.scans)
    }