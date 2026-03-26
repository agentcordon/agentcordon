#!/bin/bash
set -e

# Signal handling: forward signals to server process
cleanup() {
    local exit_code=$?
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
    fi
    exit $exit_code
}

trap cleanup SIGTERM SIGINT SIGQUIT

echo "Starting AgentCordon server..."

# Ensure root password is available
if [ -z "$AGTCRDN_ROOT_PASSWORD" ]; then
    if [ -f /data/.root_password ]; then
        export AGTCRDN_ROOT_PASSWORD=$(cat /data/.root_password)
        echo "Using persisted root password from /data/.root_password"
    else
        export AGTCRDN_ROOT_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -d '=/+' | head -c 32)
        echo "$AGTCRDN_ROOT_PASSWORD" > /data/.root_password
        chmod 600 /data/.root_password
        echo "Auto-generated root password: $AGTCRDN_ROOT_PASSWORD"
        echo "Save this password — it will not be shown again."
    fi
fi

# Start server
agent-cordon-server &
SERVER_PID=$!

echo "Server (PID $SERVER_PID) is running."

# Wait for server to exit
wait $SERVER_PID
EXIT_CODE=$?

echo "Server exited with code $EXIT_CODE."
exit $EXIT_CODE
