#!/bin/bash

echo "[*] Initializing TWIP: DarkWeb Intelligence Platform..."

# 1. Activate the Conda environment
# (Ensures conda is available in the non-interactive script shell)
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate twip

# 2. Start the Data Watcher Daemon (Downloads/ -> twip-nlp/data/)
echo "[*] Starting Data Watcher..."
python pipeline/data_watcher.py &
WATCHER_PID=$!

# 3. Start the Auto Ingester Pre-filter (data/ -> input/)
echo "[*] Starting Auto Ingester..."
python pipeline/auto_ingester.py &
INGESTER_PID=$!

# 4. Start the Flask Orchestrator
echo "[*] Starting Flask Orchestrator..."
python pipeline/orchestrator.py &
ORCH_PID=$!

# 5. Start the OpenCTI Pusher Daemon (output/ -> OpenCTI)
echo "[*] Starting OpenCTI Pusher Daemon..."
python pipeline/opencti_pusher.py &
CTI_PUSHER_PID=$!

# 6. Give the Flask API a few seconds to fully boot up
echo "[*] Waiting for API to initialize..."
sleep 5

# 7. Start the Input Pusher (input/ -> Orchestrator)
echo "[*] Starting Input Pusher..."
python input_pusher.py &
INPUT_PUSHER_PID=$!

echo "------------------------------------------------------"
echo "[✓] All pipeline services are live!"
echo "[✓] Watching Downloads folder for incoming crawler drops..."
echo "[!] Press CTRL+C to gracefully stop all services."
echo "------------------------------------------------------"

# Trap CTRL+C (SIGINT) to kill all background processes cleanly
trap "echo -e '\n[!] Shutting down TWIP pipeline...'; kill $WATCHER_PID $INGESTER_PID $ORCH_PID $CTI_PUSHER_PID $INPUT_PUSHER_PID; exit" SIGINT SIGTERM

# Keep script running to maintain background processes
wait