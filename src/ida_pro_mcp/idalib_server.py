import sys
import signal
import logging
import argparse
from pathlib import Path

# idapro must go first to initialize idalib
import idapro
import ida_auto

from ida_pro_mcp.ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on, default: 127.0.0.1",
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port to listen on, default: 8745"
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "input_path", type=Path, help="Path to the input file to analyze."
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    if not args.input_path.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_path}")

    # TODO: add a tool for specifying the idb/input file (sandboxed)
    logger.info("opening database: %s", args.input_path)
    if idapro.open_database(str(args.input_path), run_auto_analysis=True):
        raise RuntimeError("failed to analyze input file")

    logger.debug("idalib: waiting for analysis...")
    ida_auto.auto_wait()

    # Setup signal handlers to ensure IDA database is properly closed on shutdown.
    # When a signal arrives, our handlers execute first, allowing us to close the
    # IDA database cleanly before the process terminates.
    def cleanup_and_exit(signum, frame):
        logger.info("Closing IDA database...")
        idapro.close_database()
        logger.info("IDA database closed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    # NOTE: npx -y @modelcontextprotocol/inspector for debugging
    # TODO: with background=True the main thread (this one) does not fake any
    # work from @idaread, so we deadlock.
    
    # Enable headless mode in sync module
    from ida_pro_mcp.ida_mcp import sync
    import queue
    import time
    
    sync.HEADLESS_MODE = True
    
    # Start server in background thread
    MCP_SERVER.serve(host=args.host, port=args.port, background=True)
    
    # Main thread becomes the task executor
    logger.info("Entering headless event loop...")
    
    # Try to find a way to pump IDA's loop
    import ctypes
    
    last_heartbeat = time.time()
    
    while True:
        try:
            # Heartbeat every 60 seconds (keep it quiet)
            if time.time() - last_heartbeat > 60:
                logger.debug("Main loop heartbeat: IDA is responsive")
                last_heartbeat = time.time()

            # Poll for tasks from the sync module
            # We use a short timeout to allow signal handlers to interrupt if needed
            task = sync.HEADLESS_QUEUE.get(timeout=0.001)
            try:
                task()
            except Exception as e:
                logger.error(f"Error executing task: {e}")
        except queue.Empty:
            # We need to let IDA breathe. In idalib, the main thread IS IDA's thread.
            # We are blocking it with this while loop.
            # We need to yield control back to IDA occasionally if possible, 
            # or ensure we are not preventing internal processing.
            pass
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
