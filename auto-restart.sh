#!/bin/bash
# Auto-restart script for Observer Protocol API
# Runs continuously and restarts server if it dies

API_DIR="/media/nvme/observer-protocol/api"
LOG_FILE="/media/nvme/observer-protocol/api/auto-restart.log"

echo "$(date): Starting auto-restart monitor" >> $LOG_FILE

while true; do
    # Check if server is running
    if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "$(date): Server down, restarting..." >> $LOG_FILE
        
        # Kill any existing processes on port 8000
        lsof -ti:8000 | xargs kill -9 2>/dev/null
        
        # Start server
        cd $API_DIR
        nohup /usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 > api.log 2>&1 &
        
        echo "$(date): Server restarted with PID $!" >> $LOG_FILE
    fi
    
    # Check every 10 seconds
    sleep 10
done
