import os
import subprocess
import time
import requests
import sys

def check_ngrok_installed():
    try:
        subprocess.run(["ngrok", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def launch_ngrok(port=8000):
    print(f"[*] Starting ngrok on port {port}...")
    # --log=stdout is to prevent opening a window if we're in a headless env
    ngrok_proc = subprocess.Popen(["ngrok", "http", str(port)], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE)
    
    # Wait for the tunnel to establish
    time.sleep(2)
    
    try:
        # ngrok local API to get the public URL
        res = requests.get("http://127.0.0.1:4040/api/tunnels")
        res_data = res.json()
        public_url = res_data['tunnels'][0]['public_url']
        print(f"[+] Tunnel Ready!")
        print(f"[+] Public URL: {public_url}")
        print(f"[+] Swagger UI: {public_url}/docs")
        return public_url, ngrok_proc
    except Exception as e:
        print(f"[-] Could not retrieve ngrok tunnel info: {e}")
        ngrok_proc.kill()
        return None, None

if __name__ == "__main__":
    if not check_ngrok_installed():
        print("[-] Error: ngrok is not installed or not in PATH.")
        print("Install it from: https://ngrok.com/download")
        sys.exit(1)
        
    url, proc = launch_ngrok()
    if url:
        try:
            print("[*] Keep this process running to maintain the tunnel.")
            print("[*] Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping ngrok...")
            proc.kill()
