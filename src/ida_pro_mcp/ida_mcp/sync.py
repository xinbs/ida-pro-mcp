import logging
import queue
import functools
from enum import IntEnum
import idaapi
import ida_kernwin
import idc
from .rpc import McpToolError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


logger = logging.getLogger(__name__)


class IDASafety(IntEnum):
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE


call_stack = queue.LifoQueue()

# --- Headless Mode Support ---
HEADLESS_MODE = False
HEADLESS_QUEUE = queue.Queue()
# -----------------------------

import uuid
import time

# Task Store for Async Operations
# { task_id: { "status": "pending"|"done"|"error", "result": ..., "error": ..., "created_at": ... } }
TASK_STORE = {}

# Global Busy Flag for Heavy Operations
IS_BUSY_WITH_HEAVY_TASK = False

def check_busy():
    """Check if server is busy with a heavy task."""
    if IS_BUSY_WITH_HEAVY_TASK:
        raise IDAError("Server is busy with a heavy background task (e.g. decompile). Please wait.")

def submit_task(func, *args, is_heavy: bool = False, **kwargs) -> str:
    """Submit a task to the headless queue and return a Task ID immediately."""
    task_id = str(uuid.uuid4())
    TASK_STORE[task_id] = {
        "status": "pending", 
        "created_at": time.time()
    }
    
    def wrapper():
        if is_heavy:
            global IS_BUSY_WITH_HEAVY_TASK
            IS_BUSY_WITH_HEAVY_TASK = True
        try:
            # Execute with write safety
            res = func(*args, **kwargs)
            TASK_STORE[task_id]["status"] = "done"
            TASK_STORE[task_id]["result"] = res
        except Exception as e:
            TASK_STORE[task_id]["status"] = "error"
            TASK_STORE[task_id]["error"] = str(e)
        finally:
            if is_heavy:
                IS_BUSY_WITH_HEAVY_TASK = False
            
    if HEADLESS_MODE:
        HEADLESS_QUEUE.put(wrapper)
    else:
        # GUI mode: execute in main thread via request_ui_thread (MFF_WRITE)
        idaapi.execute_sync(wrapper, idaapi.MFF_WRITE)
        
    return task_id

def get_task_result(task_id: str) -> dict:
    """Get the result of an async task."""
    return TASK_STORE.get(task_id, {"status": "not_found"})

import threading

def _sync_wrapper(ff, safety_mode: IDASafety):
    """Call a function ff with a specific IDA safety_mode."""
    # Fast-fail if server is busy with a heavy task
    check_busy()
    
    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = f"Invalid safety mode {safety_mode} over function {ff.__name__}"
        logger.error(error_str)
        raise IDASyncError(error_str)

    # NOTE: This is not actually a queue, there is one item in it at most
    res_container = queue.Queue()

    def runned():
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = f"Call stack is not empty while calling the function {ff.__name__} from {last_func_name}"
            # In Headless mode, if we are on the main thread, we might be recursively calling.
            # But the original logic forbids this. We should respect it, OR modify it.
            # For now, let's keep the error, but if we are on main thread in headless mode,
            # we should avoid the DEADLOCK first. The Error is better than Deadlock.
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()

    if HEADLESS_MODE:
        # Check if we are already on the main thread
        if threading.current_thread() is threading.main_thread():
            # If we are on the main thread, we MUST execute directly to avoid deadlock.
            # Calling HEADLESS_QUEUE.put() and waiting for ourselves would block forever.
            runned()
            res = res_container.get()
        else:
            # We are on a worker thread (HTTP request handler), so we queue it.
            HEADLESS_QUEUE.put(runned)
            res = res_container.get()
    else:
        idaapi.execute_sync(runned, safety_mode)
        res = res_container.get()

    if isinstance(res, Exception):
        raise res
    return res


def sync_wrapper(ff, safety_mode: IDASafety):
    """Wrapper to enable batch mode during IDA synchronization."""
    old_batch = idc.batch(1)
    try:
        return _sync_wrapper(ff, safety_mode)
    finally:
        idc.batch(old_batch)


def idasync(f):
    """Run the function on the IDA main thread in write mode."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)

    return wrapper

# Backward compatibility aliases
idawrite = idasync
idaread = idasync


def is_window_active():
    """Returns whether IDA is currently active"""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    try:
        if using_pyside6:
            import PySide6.QtWidgets as QApplication
        else:
            import PyQt5.QtWidgets as QApplication

        app = QApplication.instance()
        if app is None:
            return False

        for widget in app.topLevelWidgets():
            if widget.isActiveWindow():
                return True
    except Exception:
        # Headless mode or other error (this is not a critical feature)
        pass
    return False
