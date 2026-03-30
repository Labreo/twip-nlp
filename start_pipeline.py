import subprocess
import time
import sys

print("[*] Initializing TWIP: DarkWeb Intelligence Platform...")

processes = []

try:
    print("[*] Starting Data Watcher...")
    processes.append(subprocess.Popen([sys.executable, "data_watcher.py"]))

    print("[*] Starting Auto Ingester...")
    processes.append(subprocess.Popen([sys.executable, "pipeline/auto_ingester.py"]))

    print("[*] Starting Flask Orchestrator...")
    processes.append(subprocess.Popen([sys.executable, "pipeline/orchestrator.py"]))

    print("[*] Starting OpenCTI Pusher Daemon...")
    processes.append(subprocess.Popen([sys.executable, "pipeline/opencti_pusher.py"]))

    print("[*] Waiting for API to initialize...")
    time.sleep(5)

    print("[*] Starting Input Pusher...")
    processes.append(subprocess.Popen([sys.executable, "pipeline/input_pusher.py"]))

    print("------------------------------------------------------")
    print("[✓] All pipeline services are live!")
    print("[✓] Watching Downloads folder for incoming crawler drops...")
    print("[!] Press CTRL+C to gracefully stop all services.")
    print("------------------------------------------------------")

    # Keep the main thread alive so the background processes keep running
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[!] CTRL+C detected. Shutting down TWIP pipeline...")
    for p in processes:
        p.terminate()
        p.wait()
    print("[✓] All background services safely stopped.")
    sys.exit(0)