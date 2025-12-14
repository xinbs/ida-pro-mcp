import asyncio
import aiohttp
import sys

async def start_service():
    base_url = "http://localhost:8001"
    filename = "core.62382"
    
    async with aiohttp.ClientSession() as session:
        # Stop
        print("Stopping any existing service...")
        async with session.post(f"{base_url}/api/stop") as resp:
            print(f"Stop status: {resp.status}")
            
        await asyncio.sleep(2)
        
        print(f"Starting service for {filename}...")
        async with session.post(f"{base_url}/api/start", json={"filename": filename}) as resp:
            print(f"Start status: {resp.status}")
            print(await resp.text())

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(start_service())
