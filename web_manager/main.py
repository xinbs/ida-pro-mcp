import os
import shutil
import subprocess
import signal
import sys
import psutil
import re
import json
from typing import Optional, List
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import asyncio
import logging

# Configuration
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploaded_files")
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

def load_ida_path():
    # 1. Environment variable has highest priority
    if os.environ.get("IDADIR"):
        return os.environ["IDADIR"]
    
    # 2. Config file
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                if "ida_path" in config and config["ida_path"]:
                    return config["ida_path"]
        except Exception as e:
            print(f"[WARN] Failed to load config.json: {e}")

    # 3. Default fallback
    return r"C:\Program Files\IDA Professional 9.2"

IDA_DIR = load_ida_path()
print(f"[INFO] Using IDA path: {IDA_DIR}")

# Files to ignore in the file list (IDA temporary/intermediate files)
IGNORED_EXTENSIONS = {".id0", ".id1", ".id2", ".nam", ".til", ".dmp", ".i64"}

# Global State
class ProcessState:
    def __init__(self):
        self.process: Optional[asyncio.subprocess.Process] = None
        self.filename: Optional[str] = None
        self.port: int = 8745
        self.start_time: float = 0
        self.pid: Optional[int] = None

current_process = ProcessState()

# Log Manager
class LogManager:
    def __init__(self, max_lines=2000):
        self.active_connections: List[WebSocket] = []
        self.logs: List[str] = []
        self.max_lines = max_lines

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # Send existing logs
        for log in self.logs:
            try:
                await websocket.send_text(log)
            except Exception:
                pass

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        self.logs.append(message)
        if len(self.logs) > self.max_lines:
            self.logs.pop(0)
            
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

    def clear(self):
        self.logs = []

log_manager = LogManager()

# Initialize App
app = FastAPI(title="IDA MCP Manager")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Models
class FileInfo(BaseModel):
    filename: str
    size: int
    path: str

class ProcessStatus(BaseModel):
    running: bool
    filename: Optional[str]
    pid: Optional[int]
    port: int
    uptime_seconds: float
    mcp_url: Optional[str]

class StartRequest(BaseModel):
    filename: str

# Global Event Loop for Sync-to-Async logging
main_loop: Optional[asyncio.AbstractEventLoop] = None

@app.on_event("startup")
async def startup_event():
    global main_loop
    main_loop = asyncio.get_running_loop()

def log_message(message: str):
    """Log to stdout and broadcast to Web UI"""
    print(message, flush=True)
    if main_loop and log_manager:
        asyncio.run_coroutine_threadsafe(log_manager.broadcast(message), main_loop)

# Helper Functions
def get_files() -> List[FileInfo]:
    files = []
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            # Skip ignored extensions
            if any(f.lower().endswith(ext) for ext in IGNORED_EXTENSIONS):
                continue
                
            path = os.path.join(UPLOAD_DIR, f)
            if os.path.isfile(path):
                files.append(FileInfo(
                    filename=f,
                    size=os.path.getsize(path),
                    path=path
                ))
    return sorted(files, key=lambda x: x.filename)

def kill_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.kill()
        parent.kill()
    except psutil.NoSuchProcess:
        pass

async def read_stream(stream, prefix):
    while True:
        line = await stream.readline()
        if not line:
            break
        message = f"[{prefix}] {line.decode('utf-8', errors='replace').rstrip()}"
        await log_manager.broadcast(message)

# Routes
@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await log_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        log_manager.disconnect(websocket)
    except Exception:
        log_manager.disconnect(websocket)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/files", response_model=List[FileInfo])
async def list_files():
    return get_files()

@app.post("/api/upload")
def upload_file(file: UploadFile = File(...)):
    log_message(f"[UPLOAD] Starting upload: {file.filename}")
    
    # Sanitize filename: replace spaces, parentheses and other special chars with underscores
    # agent_windows (2).exe -> agent_windows_2_.exe
    filename = re.sub(r'[ \(\)]+', '_', file.filename)
    # Remove any other potentially dangerous characters, keep only alphanumeric, dot, dash, underscore
    filename = re.sub(r'[^a-zA-Z0-9\._\-]', '', filename)
    
    # Security: Append "_" to executable extensions to prevent accidental execution
    executable_exts = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".com", ".scr", ".pif"}
    ext = os.path.splitext(filename)[1].lower()
    if ext in executable_exts:
        filename += "_"
        
    file_path = os.path.join(UPLOAD_DIR, filename)
    try:
        # Use manual chunked copy to monitor progress and avoid memory issues
        with open(file_path, "wb") as buffer:
            # 1MB chunks
            chunk_size = 1024 * 1024
            bytes_read = 0
            while True:
                chunk = file.file.read(chunk_size)
                if not chunk:
                    break
                buffer.write(chunk)
                bytes_read += len(chunk)
                # Print progress every ~10MB
                if bytes_read % (10 * 1024 * 1024) < chunk_size:
                    log_message(f"[UPLOAD] Processed {bytes_read / 1024 / 1024:.1f} MB...")
                    
        log_message(f"[UPLOAD] Successfully saved to: {file_path}")
        return {"filename": filename, "status": "uploaded"}
    except Exception as e:
        log_message(f"[UPLOAD] Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/files/{filename}")
async def delete_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/api/status", response_model=ProcessStatus)
async def get_status():
    is_running = False
    uptime = 0.0
    
    if current_process.process:
        if current_process.process.returncode is None:
            is_running = True
            uptime = asyncio.get_event_loop().time() - current_process.start_time
        else:
            # Process died unexpectedly
            current_process.process = None
            current_process.pid = None
            current_process.filename = None

    return ProcessStatus(
        running=is_running,
        filename=current_process.filename,
        pid=current_process.pid,
        port=current_process.port,
        uptime_seconds=uptime if is_running else 0,
        mcp_url=f"http://{get_local_ip()}:{current_process.port}/sse" if is_running else None
    )

@app.post("/api/start")
async def start_process(req: StartRequest):
    global current_process
    
    # Check if already running
    if current_process.process and current_process.process.returncode is None:
        raise HTTPException(status_code=400, detail="A process is already running. Please stop it first.")

    file_path = os.path.join(UPLOAD_DIR, req.filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # Verify IDA_DIR
    if not os.path.exists(IDA_DIR):
        raise HTTPException(status_code=500, detail=f"IDA Directory not found at: {IDA_DIR}. Please set IDADIR environment variable to your IDA installation path.")

    # Prepare environment
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC_DIR
    env["IDADIR"] = IDA_DIR
    
    # Construct command
    cmd = [
        sys.executable,
        "-m", "ida_pro_mcp.idalib_server",
        "--host", "0.0.0.0",
        "--port", str(current_process.port),
        file_path
    ]
    
    try:
        log_manager.clear()
        await log_manager.broadcast(f"Starting analysis for {req.filename}...")
        await log_manager.broadcast(f"Command: {' '.join(cmd)}")
        
        # Start process asynchronously
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=SRC_DIR,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        current_process.process = process
        current_process.pid = process.pid
        current_process.filename = req.filename
        current_process.start_time = asyncio.get_event_loop().time()
        
        # Start background tasks to read logs
        asyncio.create_task(read_stream(process.stdout, "STDOUT"))
        asyncio.create_task(read_stream(process.stderr, "STDERR"))
        
        return {"status": "started", "pid": process.pid}
    except Exception as e:
        await log_manager.broadcast(f"[ERROR] Failed to start process: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start process: {str(e)}")

@app.post("/api/stop")
async def stop_process():
    global current_process
    
    if not current_process.process:
        return {"status": "already_stopped"}

    try:
        await log_manager.broadcast("Stopping process...")
        # Kill the process tree (IDA spawns children)
        kill_process_tree(current_process.pid)
        
        try:
            current_process.process.terminate()
            await asyncio.sleep(0.1)
        except Exception:
            pass
            
        current_process.process = None
        current_process.pid = None
        current_process.filename = None
        
        await log_manager.broadcast("Process stopped.")
        return {"status": "stopped"}
    except Exception as e:
        await log_manager.broadcast(f"[ERROR] Failed to stop process: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to stop process: {str(e)}")

def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    import uvicorn
    # Listen on 0.0.0.0 to be accessible from LAN
    uvicorn.run(app, host="0.0.0.0", port=8001)
