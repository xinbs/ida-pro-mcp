import os
import shutil
import subprocess
import signal
import sys
import psutil
import re
import json
from urllib.parse import unquote
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

import hashlib
from typing import Optional, List, Dict

# ... (existing imports)

# Simple in-memory cache for MD5 hashes to avoid re-reading large files constantly
# Key: file_path, Value: (mtime, md5_hash)
md5_cache: Dict[str, tuple[float, str]] = {}

def calculate_md5(file_path: str) -> str:
    """Calculate MD5 of a file with caching based on modification time"""
    try:
        stat = os.stat(file_path)
        mtime = stat.st_mtime
        
        # Check cache
        if file_path in md5_cache:
            cached_mtime, cached_md5 = md5_cache[file_path]
            if cached_mtime == mtime:
                return cached_md5
        
        # Calculate fresh
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        
        digest = hash_md5.hexdigest()
        md5_cache[file_path] = (mtime, digest)
        return digest
    except Exception:
        return "error"

# Models
class FileInfo(BaseModel):
    filename: str
    size: int
    path: str
    md5: str
    has_intermediate_files: bool = False

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
def has_intermediate_files(filename: str) -> bool:
    """Check if any intermediate files exist for a given filename"""
    base_path = os.path.join(UPLOAD_DIR, filename)
    exts = [".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".dmp"]
    
    root, _ = os.path.splitext(base_path)
    for ext in exts:
        # Check binary.id0
        if os.path.exists(root + ext):
            return True
        # Check binary.exe.id0
        if os.path.exists(base_path + ext):
            return True
    return False

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
                    path=path,
                    md5=calculate_md5(path),
                    has_intermediate_files=has_intermediate_files(f)
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
async def upload_file(request: Request):
    # Get filename from header
    raw_filename = request.headers.get("X-Filename")
    if not raw_filename:
        raise HTTPException(status_code=400, detail="Missing X-Filename header")
    
    # Decode URL-encoded filename (from frontend encodeURIComponent)
    raw_filename = unquote(raw_filename)
    
    # Check for simple obfuscation
    is_xor = request.headers.get("X-Obfuscation") == "xor"
    
    log_message(f"[UPLOAD] Starting upload: {raw_filename} (XOR: {is_xor})")
    
    # Sanitize filename: replace spaces, parentheses and other special chars with underscores
    # agent_windows (2).exe -> agent_windows_2_.exe
    filename = re.sub(r'[ \(\)]+', '_', raw_filename)
    # Remove any other potentially dangerous characters, keep only alphanumeric, dot, dash, underscore
    # NOTE: This regex strips non-ASCII characters. If filename becomes empty, we generate a fallback name.
    filename = re.sub(r'[^a-zA-Z0-9\._\-]', '', filename)
    
    # Fallback if filename became empty (e.g. was all unicode)
    if not filename:
        import uuid
        filename = f"upload_{uuid.uuid4().hex[:8]}"
        log_message(f"[UPLOAD] Filename sanitized to empty, using fallback: {filename}")
    
    # Security: Append "_" to executable extensions to prevent accidental execution
    executable_exts = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".com", ".scr", ".pif"}
    ext = os.path.splitext(filename)[1].lower()
    if ext in executable_exts:
        filename += "_"
        
    file_path = os.path.join(UPLOAD_DIR, filename)
    try:
        # Use manual chunked copy to monitor progress and avoid memory issues
        with open(file_path, "wb") as buffer:
            # 64KB chunks for smoother progress and responsiveness
            chunk_size = 64 * 1024
            bytes_read = 0
            loop = asyncio.get_running_loop()
            
            async for chunk in request.stream():
                if is_xor:
                    # De-obfuscate (XOR 0x42)
                    # We can use numpy or simple list comp, but for chunks standard bytes loop is fine or bytes.translate
                    # Creating a translation table is fastest
                    # 0x42 = 66
                    chunk = bytes(b ^ 0x42 for b in chunk)
                
                # Run blocking write in executor to avoid blocking the event loop
                await loop.run_in_executor(None, buffer.write, chunk)
                
                bytes_read += len(chunk)
                # Print progress every ~5MB
                if bytes_read % (5 * 1024 * 1024) < chunk_size:
                    log_message(f"[UPLOAD] Processed {bytes_read / 1024 / 1024:.1f} MB...")
                    
        log_message(f"[UPLOAD] Successfully saved to: {file_path}")
        return {"filename": filename, "status": "uploaded"}
    except Exception as e:
        import traceback
        traceback.print_exc()
        error_msg = f"{type(e).__name__}: {str(e)}"
        log_message(f"[UPLOAD] Error: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

@app.delete("/api/files/{filename}")
async def delete_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        # Also try to clean up intermediate files
        try:
            clean_intermediate_files(filename)
        except:
            pass
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="File not found")

@app.post("/api/cleanup/{filename}")
async def cleanup_intermediate_files_endpoint(filename: str):
    """Manually clean up IDA intermediate files (.id0, .id1, .nam, etc)"""
    if clean_intermediate_files(filename):
        return {"status": "cleaned"}
    else:
        # Not finding files is also a success (already clean)
        return {"status": "cleaned", "message": "No intermediate files found"}

def clean_intermediate_files(filename: str) -> bool:
    """Helper to remove .id0, .id1, .nam, .til, .i64, .dmp files"""
    cleaned = False
    base_path = os.path.join(UPLOAD_DIR, filename)
    
    # Extensions to clean
    exts = [".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".dmp"]
    
    # 1. Check exact matches (e.g. binary.exe -> binary.id0) - IDA < 7 style or some settings
    # 2. Check appended matches (e.g. binary.exe -> binary.exe.id0) - Common IDA style
    
    # Case A: binary.id0 (replacing extension)
    root, _ = os.path.splitext(base_path)
    for ext in exts:
        p = root + ext
        if os.path.exists(p):
            try:
                os.remove(p)
                log_message(f"[CLEANUP] Removed {os.path.basename(p)}")
                cleaned = True
            except Exception as e:
                log_message(f"[CLEANUP] Failed to remove {os.path.basename(p)}: {e}")

    # Case B: binary.exe.id0 (appending extension)
    for ext in exts:
        p = base_path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
                log_message(f"[CLEANUP] Removed {os.path.basename(p)}")
                cleaned = True
            except Exception as e:
                log_message(f"[CLEANUP] Failed to remove {os.path.basename(p)}: {e}")
                
    return cleaned

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
    
    # Force output buffering off to ensure real-time logs
    env["PYTHONUNBUFFERED"] = "1"
    
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
