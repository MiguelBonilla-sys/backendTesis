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
    print(f"[*] Starting ngrok on port {port}...", flush=True)
    ngrok_proc = subprocess.Popen(["ngrok", "http", str(port)], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE)
    time.sleep(3)
    try:
        res = requests.get("http://127.0.0.1:4040/api/tunnels")
        res_data = res.json()
        public_url = res_data['tunnels'][0]['public_url']
        print(f"[+] Tunnel Ready!", flush=True)
        print(f"[+] Public URL: {public_url}", flush=True)
        print(f"[+] Swagger UI: {public_url}/docs", flush=True)
        with open("ngrok_url.txt", "w") as f:
            f.write(public_url)
        return public_url, ngrok_proc
    except Exception as e:
        print(f"[-] Could not retrieve ngrok tunnel info: {e}", flush=True)
        ngrok_proc.kill()
        return None, None

if __name__ == "__main__":
    if not check_ngrok_installed():
        print("[-] Error: ngrok is not installed or not in PATH.", flush=True)
        sys.exit(1)
        
    url, proc = launch_ngrok()
    if url:
        try:
            print("[*] Keep this process running to maintain the tunnel.", flush=True)
            while True:
                # keep checking if ngrok is alive
                if proc.poll() is not None:
                    print("[-] ngrok process died unexpectedly.", flush=True)
                    break
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[*] Stopping ngrok...", flush=True)
            proc.kill()
            if os.path.exists("ngrok_url.txt"):
                os.remove("ngrok_url.txt")
