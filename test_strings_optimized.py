import time
import json
import asyncio
import aiohttp
import sys

# Simple SSE Client implementation
class SimpleSseClient:
    def __init__(self, url):
        self.url = url
        self.session_id = None
        self.post_url = None
        self.pending_requests = {}
        self.running = False

    async def connect(self):
        print(f"Connecting to SSE: {self.url}")
        self.running = True
        # Start listener task
        asyncio.create_task(self._listen())
        
        # Wait for connection
        for _ in range(100): # Wait up to 10 seconds for big files to load
            if self.session_id:
                return True
            await asyncio.sleep(0.1)
        return False

    async def _listen(self):
        timeout = aiohttp.ClientTimeout(total=None) # No timeout for SSE stream
        # Increase line length limit for big JSON payloads
        async with aiohttp.ClientSession(timeout=timeout, read_bufsize=10*1024*1024) as session:
            try:
                async with session.get(self.url) as response:
                    async for line in response.content:
                        if not self.running:
                            break
                        line = line.decode('utf-8').strip()
                        if line.startswith("event: endpoint"):
                            # Next line is data
                            pass
                        elif line.startswith("data:"):
                            data = line[5:].strip()
                            if not data:
                                continue
                                
                            # Check for endpoint data
                            if "?session=" in data and not self.session_id:
                                self.post_url = data
                                self.session_id = data.split("=")[1]
                                print(f"Connected! Session ID: {self.session_id}")
                                continue
                            
                            # Check for JSON-RPC response
                            try:
                                msg = json.loads(data)
                                if "id" in msg and msg["id"] in self.pending_requests:
                                    self.pending_requests[msg["id"]].set_result(msg)
                                    del self.pending_requests[msg["id"]]
                            except json.JSONDecodeError:
                                pass
            except Exception as e:
                print(f"Connection error: {e}")
                self.running = False

    async def call_tool(self, base_url, tool_name, args):
        if not self.post_url:
            raise Exception("Not connected")
        
        full_post_url = f"{base_url}{self.post_url}"
        print(f"Calling tool {tool_name} at {full_post_url}")
        
        req_id = int(time.time() * 1000)
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            },
            "id": req_id
        }
        
        # Create future for response
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.pending_requests[req_id] = future
        
        async with aiohttp.ClientSession() as session:
            async with session.post(full_post_url, json=payload) as response:
                # We ignore the POST response body as it's just an echo/ack
                if response.status not in (200, 202):
                    raise Exception(f"POST failed with status {response.status}")
        
        # Wait for SSE response
        return await asyncio.wait_for(future, timeout=60.0)

async def main():
    web_manager_url = "http://localhost:8001"
    
    # 1. Check Status
    print("Checking status from Web Manager...")
    mcp_url = None
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{web_manager_url}/api/status") as resp:
                if resp.status == 200:
                    status = await resp.json()
                    if status['running'] and status['mcp_url']:
                        mcp_url = status['mcp_url']
                        print(f"Found running MCP service: {mcp_url}")
                    else:
                        print("Service is NOT running according to Web Manager.")
                        return
    except Exception as e:
        print(f"Could not contact Web Manager: {e}")
        return

    mcp_base = mcp_url.replace("/sse", "")

    # 2. Test Strings with Optimization
    client = SimpleSseClient(mcp_url)
    
    try:
        connected = await client.connect()
        if connected:
            # Test 1: Search for specific string "shopee" using strings tool (should be optimized)
            targets = "shopee"
            print(f"\nTest 1: strings(pattern='{targets}') - Should trigger optimization")
            start_time = time.time()
            res = await client.call_tool(mcp_base, "analyze_strings", {
                "filters": [{"pattern": targets}]
            })
            duration = time.time() - start_time
            
            # Print raw result for debugging
            # print(f"Raw result: {json.dumps(res, indent=2)}")

            # Check for tool result
            if "result" in res:
                tool_res = res["result"]
                if not tool_res.get("isError"):
                    if "content" in tool_res:
                        content_text = tool_res["content"][0]["text"]
                        try:
                            content = json.loads(content_text)
                            if isinstance(content, list):
                                for item in content:
                                    count = item.get("count", 0)
                                    print(f"Found: {count} matches")
                                    if count > 0:
                                        print(f"Matches: {item['matches'][:5]} ...")
                            else:
                                print(f"Unexpected content format: {type(content)}")
                        except json.JSONDecodeError:
                            print(f"Could not parse content JSON: {content_text}")
                    else:
                        print("No content in tool result")
                else:
                    print("Tool execution error:", tool_res)
            else:
                print("Unexpected response format")
            
            print(f"Time taken: {duration:.4f}s")
            
    except Exception as e:
        print(f"Test failed: {e}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
