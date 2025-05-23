import http.server
import socketserver
import json
import threading
import time
import requests
import os
import subprocess
from datetime import datetime

class DetectionAgent(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/topics/fail2ban":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode("utf-8"))
            except json.JSONDecodeError as e:
                print(f"Error: JSON parsing failed: {e}")
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid JSON")
                return
            banned_ip = data.get("banned_ip", "")
            if banned_ip:
                api_key = os.getenv("NVIDIA_API_KEY")
                if not api_key:
                    print("Error: NVIDIA_API_KEY not set")
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"API key missing")
                    return
                url = "https://integrate.api.nvidia.com/v1/chat/completions"
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                prompt = (
                    f"Analyze an SSH attack from IP {banned_ip} detected by Fail2ban after multiple failed login attempts. "
                    f"Assume it’s likely a brute-force attempt unless evidence suggests otherwise. "
                    f"Provide a brief threat report in this format:\n"
                    f"- Risk Level: [High/Medium/Low]\n"
                    f"- Recommended Action: [Block/Log]\n"
                    f"- Explanation: [Short explanation of the analysis]"
                )
                data = {
                    "model": "meta/llama-3.1-8b-instruct",
                    "messages": [{"role": "user", "content": prompt}]
                }
                try:
                    response = requests.post(url, headers=headers, json=data)
                    response.raise_for_status()
                    nim_response = response.json().get("choices", [{}])[0].get("message", {}).get("content", "NIM failed")
                    print(f"Detected attack from IP: {banned_ip}. NIM says:\n{nim_response}")

                    # Parse NIM response for decision
                    should_block = "block" in nim_response.lower() or "brute-force" in nim_response.lower() or "high" in nim_response.lower()

                    # Log to mitigation.txt with threat report
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    threat_report = (
                        f"[{timestamp}] SSH Attack from {banned_ip}\n"
                        f"NIM Analysis: {nim_response}\n"
                        f"Action: {'Blocked' if should_block else 'Logged'}\n"
                        f"{'-'*50}\n"
                    )
                    with open("mitigation.txt", "a") as f:
                        f.write(threat_report)

                    # Mitigate if NIM recommends blocking
                    if should_block:
                        try:
                            subprocess.run(["/home/xfp13/selfheal-mitigate.sh", banned_ip], check=True)
                            print(f"Mitigated IP: {banned_ip}")
                        except subprocess.CalledProcessError as e:
                            print(f"Failed to mitigate IP {banned_ip}: {e}")
                    else:
                        print(f"IP {banned_ip} logged but not blocked per NIM's recommendation")

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                except requests.RequestException as e:
                    print(f"NIM error: {e}")
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"NIM request failed")
                    return
            else:
                print("Error: No IP in message")
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No IP provided")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

def run_server():
    with socketserver.TCPServer(("", 8000), DetectionAgent) as httpd:
        print("DetectionAgent running on port 8000...")
        httpd.serve_forever()

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
