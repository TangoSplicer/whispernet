# WhisperNet: Tactical Edge Node Operations Guide

WhisperNet is a decentralized, offline-first secure messenger running a headless Tor V3 hidden service. It is explicitly engineered for `aarch64` mobile environments (Termux), utilizing zero-trust cryptographic protocols and encrypted local persistence.

## Architecture & Current Capabilities

* **Network Layer:** Multithreaded Tor V3 Hidden Service (`arti-client` 0.42.0).
* **Concurrency:** Asynchronous background network listener with a decoupled foreground interactive CLI (`tokio`).
* **Cryptography (X3DH):** * Node Identity: `ed25519` master key generation and signature verification.
  * Ephemeral Exchange: `x25519` throwaway keys for forward-secret handshake initialization.
* **Persistence:** Local `SQLite` ledger, AES-256 encrypted at rest via bundled `SQLCipher` and vendored `OpenSSL`.
* **CI/CD:** Automated cloud cross-compilation pipeline utilizing `cargo-ndk` to bypass mobile OS-level file locking and compilation bottlenecks.

---

## 1. Environment Preparation (Termux)

WhisperNet requires specific packages to handle process management, database inspection, and pulling build artifacts directly from GitHub.

```bash
# Update local package repositories
pkg update && pkg upgrade -y

# Install required operational tooling
pkg install gh procps sqlite -y

# Authenticate with GitHub (Required to pull CI/CD artifacts)
# gh auth login2. Cloud Compilation (GitHub Actions)
# ​Because compiling cryptographic C-dependencies (OpenSSL, SQLCipher) and the Arti network stack natively on Android causes memory exhaustion and OS lock errors, all builds are offloaded to GitHub Actions.
# ​The repository utilizes cargo-ndk targeting Android API 24 (arm64-v8a) to correctly link the required libunwind libraries for modern Android execution. Pushing code to the main branch automatically triggers this pipeline and uploads the compiled binary as an artifact.

## ​3. Deployment & The Control Script
​WhisperNet is managed via a dedicated bash script (whisper.sh) that handles fetching cloud artifacts, directory management, and process execution.
​Ensure the script is executable in your project directory:

```bash
chmod +x whisper.sh

Script Commands
./whisper.sh pull : Downloads the latest compiled aarch64 binary from GitHub.
./whisper.sh run : Launches the node in the foreground and attaches the interactive CLI.
./whisper.sh start : Launches the node silently in the background (Daemon mode).
./whisper.sh stop : Hard-kills any running WhisperNet Tor processes.
./whisper.sh logs : Tails the live output of the background node.
./whisper.sh wipe : Permanently deletes the local SQLCipher database, destroying keys and history.
4. Boot Sequence & Node Identity
When WhisperNet boots via ./whisper.sh run, it initiates the following sequence:
Database Initialization: Opens whispernet.db using the secure SQLCipher passphrase.
Identity Verification: Checks the local_config table for a saved ed25519 Master Identity Key.
Key Generation (Cold Boot): If no key is found, it generates a fresh cryptographic identity, saves it to the encrypted ledger, and displays the public key.
Network Bootstrap: Connects to the Tor network and binds the hidden service port.
Thread Splitting: Backgrounds the listener to accept incoming rendezvous requests, while dropping the user into the whisper> prompt.
5. Interactive CLI Usage
The foreground terminal accepts commands to interact with the mesh network.
/help
Displays the available commands.
/id
Prints your node's permanent hexadecimal public identity key. This is the address peers need to verify your signatures.
/connect <onion_address>
Initiates the Extended Triple Diffie-Hellman (X3DH) handshake.
The node generates a random x25519 ephemeral key.
It signs this ephemeral key using your permanent ed25519 master identity.
The payload is serialized and pushed across the Tor circuit to the target peer.
/quit
Cleanly terminates the tokio runtime, shutting down the Tor client and closing database connections.
6. Security & Ledger Management
Your cryptographic material and message history are stored in ~/whispernet-node/whispernet.db.

Zero-Trust Handshakes: When a peer connects to your node, the background listener intercepts the payload, mathematically verifies the ed25519 signature against the ephemeral key, and drops the connection immediately if the signature is invalid. Verified peers are logged to the database.

Wiping the Node: If the mobile device is compromised or you need to cycle your identity, execute:

```bash
./whisper.sh wipe

This immediately unlinks and shreds the SQLCipher ledger. The next boot will generate a completely new network identity.