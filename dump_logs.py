import asyncio
import websockets
import sys

async def dump_logs():
    uri = "ws://localhost:8001/ws/logs"
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to Log WebSocket")
            # It sends history immediately
            try:
                while True:
                    message = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    print(message)
            except asyncio.TimeoutError:
                print("--- End of History ---")
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(dump_logs())
