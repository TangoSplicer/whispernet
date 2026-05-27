#!/bin/bash

NODE_DIR="$HOME/whispernet-node"
BINARY_PATH="$NODE_DIR/whispernet"
DB_PATH="$NODE_DIR/whispernet.db"
LOG_PATH="$NODE_DIR/node.log"

# Ensure the node directory exists
mkdir -p "$NODE_DIR"

print_help() {
    echo "WhisperNet Termux Control Script"
    echo "Usage: ./whisper.sh [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup    Install required Termux packages (gh, sqlite, procps)."
    echo "  pull     Download the latest aarch64 binary from GitHub Actions."
    echo "  start    Launch the node in the background."
    echo "  stop     Hard-kill any running WhisperNet instances."
    echo "  logs     Tail the live output of the node."
    echo "  wipe     Delete the local encrypted database ledger (whispernet.db)."
    echo "  status   Check if the node is currently running."
}

check_auth() {
    if ! command -v gh &> /dev/null; then
        echo "Error: GitHub CLI (gh) is not installed. Run './whisper.sh setup' first."
        exit 1
    fi
    if ! gh auth status &> /dev/null; then
        echo "Error: Not authenticated with GitHub. Run 'gh auth login' first."
        exit 1
    fi
}

case "$1" in
    setup)
        echo "[*] Updating Termux packages..."
        pkg update && pkg upgrade -y
        echo "[*] Installing dependencies..."
        pkg install gh procps sqlite -y
        echo "[*] Setup complete. Please run 'gh auth login' if you haven't already."
        ;;
    
    pull)
        check_auth
        echo "[*] Fetching latest build from GitHub..."
        # Download artifact to a temporary directory to avoid clutter
        TMP_DIR=$(mktemp -d)
        gh run download -n whispernet-aarch64-binary -D "$TMP_DIR"
        
        # Move the binary to the node directory and cleanup
        mv "$TMP_DIR/whispernet" "$BINARY_PATH"
        chmod +x "$BINARY_PATH"
        rm -rf "$TMP_DIR"
        
        echo "[*] WhisperNet binary updated and ready at $BINARY_PATH"
        ;;
    
    start)
        if pgrep -f "$BINARY_PATH" > /dev/null; then
            echo "[-] WhisperNet is already running."
        else
            echo "[*] Starting WhisperNet..."
            cd "$NODE_DIR" || exit
            nohup "$BINARY_PATH" > "$LOG_PATH" 2>&1 &
            echo "[+] Node active in the background. Use './whisper.sh logs' to monitor."
        fi
        ;;
    
    stop)
        echo "[*] Terminating WhisperNet nodes..."
        pkill -9 -f whispernet
        echo "[+] Node stopped."
        ;;
    
    logs)
        if [ -f "$LOG_PATH" ]; then
            tail -f "$LOG_PATH"
        else
            echo "[-] No log file found. Has the node been started?"
        fi
        ;;
    
    wipe)
        echo "[!] WARNING: This will permanently delete your cryptographic keys and message history."
        read -p "Are you sure? (y/N): " confirm
        if [[ "$confirm" == [yY] || "$confirm" == [yY][eE][sS] ]]; then
            pkill -9 -f whispernet 2>/dev/null
            rm -f "$DB_PATH"
            echo "[+] Ledger wiped cleanly."
        else
            echo "[-] Wipe cancelled."
        fi
        ;;
    
    status)
        if pgrep -f "$BINARY_PATH" > /dev/null; then
            echo "[+] Status: ACTIVE"
        else
            echo "[-] Status: OFFLINE"
        fi
        ;;
    
    *)
        print_help
        ;;
esac
