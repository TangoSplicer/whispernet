#!/bin/bash
NODE_DIR="$HOME/whispernet-node"
BINARY_PATH="$NODE_DIR/whispernet"
# Use a local folder instead of /tmp to avoid permission errors
TMP_DIR="./tmp_dl"

case "$1" in
    pull)
        mkdir -p "$TMP_DIR"
        echo "[*] Downloading build artifact..."
        gh run download -n whispernet-aarch64-binary -D "$TMP_DIR"
        
        # Ensure the node directory exists
        mkdir -p "$NODE_DIR"
        
        # Move the binary
        mv "$TMP_DIR/whispernet" "$BINARY_PATH"
        chmod +x "$BINARY_PATH"
        
        # Cleanup
        rm -rf "$TMP_DIR"
        echo "[+] Pull complete."
        ;;
    run)
        mkdir -p "$NODE_DIR"
        cd "$NODE_DIR" && "$BINARY_PATH"
        ;;
    *)
        echo "Use: ./whisper.sh [pull|run]"
        ;;
esac
