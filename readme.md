<div align="center">
<pre>
##\       ##\   ##\               ##\                  ##\     
## |      \__|  ## |              ## |                 ## |    
#######\  ##\ ######\    #######\ #######\   ######\ ######\   
##  __##\ ## |\_##  _|  ##  _____|##  __##\  \____##\\_##  _|  
## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |    
## |  ## |## |  ## |##\ ## |      ## |  ## |##  __## | ## |##\ 
#######  |## |  \####  |\#######\ ## |  ## |\####### | \####  |
\_______/ \__|   \____/  \_______|\___|  \__| \_______|  \____/ 
</pre>

**_bitch@ the terminal v1.0.0_**

**Decentralized • Encrypted • Peer-to-Peer • Open Source | Written in Python**

</div>

---
# BitChat Terminal - Python Implementation

Python implementation of BitChat Terminal - a decentralized, encrypted, peer-to-peer chat application over Bluetooth LE.

## Features

- **Decentralized**: No central server required
- **End-to-end Encryption**: Uses X25519 + Ed25519 + ChaCha20-Poly1305
- **Peer-to-Peer**: Direct connection via Bluetooth LE
- **Cross-platform**: Compatible with Rust, iOS and Android versions
- **Password-protected Channels**: Support for private channels
- **Message Fragmentation**: Handles large messages
- **Delivery Confirmation**: Message delivery acknowledgments
- **Terminal Interface**: Simple command-line interface

## Installation

### System Requirements

- Python 3.11 or newer
- Bluetooth LE hardware
- Windows 10/11, macOS or Linux

### Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -e .
```

## Usage

### Launch Application

```bash
# Run normally
python -m src.main

# Or with debug mode
python -m src.main -d      # Basic debug
python -m src.main -dd     # Verbose debug
```

### Basic Commands

#### Chat Commands
- `/help` - Show help
- `/exit` - Exit application
- `/clear` - Clear screen
- `/status` - Show connection status

#### User Management
- `/name <nickname>` - Change nickname
- `/online` - See who's online
- `/block @user` - Block user
- `/unblock @user` - Unblock user

#### Channels
- `/j #channel` - Join public channel
- `/j #channel <password>` - Join password-protected channel
- `/channels` - List discovered channels
- `/leave` - Leave current channel
- `/pass <password>` - Set channel password (owner only)
- `/transfer @user` - Transfer channel ownership

#### Private Messages
- `/dm <nickname>` - Start DM with user
- `/dm <nickname> <message>` - Send direct private message
- `/reply` - Reply to last private message

#### Conversation Management
- `/list` - Show active conversations
- `/switch` - Interactive conversation switching
- `1`, `2`, `3`... - Quick switch by number

#### Sending Messages
Simply type your message and press Enter to send to current context (public, channel, or DM).

## Project Structure

```
src/
├── __init__.py           # Package initialization
├── main.py              # Entry point and main logic
├── encryption.py        # Encryption handling (X25519, Ed25519, ChaCha20)
├── compression.py       # Data compression (Zstandard)
├── fragmentation.py     # Large message fragmentation
├── terminal_ux.py       # Terminal interface and chat context
└── persistence.py       # Settings and state storage
```

## Protocol Compatibility

This Python version is 100% compatible with:
- Original Rust version
- iOS BitChat app
- Android BitChat app

All use the same:
- Bluetooth LE service UUID: `F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C`
- Characteristic UUID: `A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D`
- Binary protocol format
- Encryption algorithms

## Dependencies

### Core Dependencies
- `bleak` - Bluetooth LE library
- `cryptography` - Cryptographic operations
- `pynacl` - NaCl cryptography (Ed25519, X25519)
- `pybloom-live` - Bloom filter implementation
- `zstandard` - Fast compression
- `colorama` - Terminal colors

### Development Dependencies
- `pytest` - Testing framework
- `black` - Code formatter
- `flake8` - Linting
- `mypy` - Type checking

## Configuration

The application automatically saves settings at:
- **Windows**: `%APPDATA%\BitChat\state.json`
- **macOS/Linux**: `~/.config/bitchat/state.json`

### Saved Data
- Nickname
- Blocked users (by fingerprint)
- Channel creators and settings
- Password-protected channels (passwords encrypted)
- Identity key for encryption

## Security Features

### Encryption
- **X25519** for key exchange
- **Ed25519** for digital signatures
- **ChaCha20-Poly1305** for symmetric encryption
- **HKDF** for key derivation

### Privacy
- Message padding to hide message length
- Cover traffic for iOS compatibility
- Local storage with encrypted passwords
- No telemetry or analytics

### Network Security
- Peer authentication via public key cryptography
- Message replay protection with bloom filters
- TTL-based message propagation
- Forward secrecy for ephemeral keys

## Troubleshooting

### Bluetooth Issues
```bash
# Linux: Ensure user has bluetooth permissions
sudo usermod -a -G bluetooth $USER

# Check Bluetooth service
systemctl status bluetooth
```

### Permission Issues
- **Windows**: Run as Administrator if needed
- **macOS**: Allow app to access Bluetooth in System Preferences
- **Linux**: Ensure user is in `bluetooth` group

### Debug Mode
```bash
# Basic debug - shows connection info
python -m src.main -d

# Verbose debug - shows all packet info
python -m src.main -dd
```

## Development

### Setup Development Environment
```bash
git clone <repository>
cd py-bitchat
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Testing
```bash
pytest tests/
```

### Code Formatting
```bash
black src/
flake8 src/
mypy src/
```

## Roadmap

- [ ] GUI wrapper with tkinter/PyQt
- [ ] File transfer support
- [ ] Voice message support
- [ ] Group calls
- [ ] Mobile notifications
- [ ] Plugin system

## License

MIT License - see LICENSE file

## Contributing

All contributions are welcome! Please:

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## Support

- GitHub Issues: [Link to issues]
- Documentation: [Link to docs]
- Community: [Link to community] 
