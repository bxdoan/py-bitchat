"""
Persistence module for BitChat Terminal

Handles saving and loading application state, including:
- User preferences
- Channel configurations
- Blocked users
- Encrypted passwords
Compatible with the Rust implementation.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict, field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64


@dataclass
class EncryptedPassword:
    """Encrypted password data structure"""
    ciphertext: str  # Base64 encoded
    nonce: str      # Base64 encoded


@dataclass
class AppState:
    """Application state data structure"""
    nickname: Optional[str] = None
    blocked_peers: Set[str] = field(default_factory=set)
    channel_creators: Dict[str, str] = field(default_factory=dict)
    joined_channels: List[str] = field(default_factory=list)
    password_protected_channels: Set[str] = field(default_factory=set)
    channel_key_commitments: Dict[str, str] = field(default_factory=dict)
    favorites: List[str] = field(default_factory=list)
    identity_key: Optional[str] = None  # Base64 encoded private key
    encrypted_channel_passwords: Dict[str, EncryptedPassword] = field(default_factory=dict)


def get_config_dir() -> Path:
    """
    Get the configuration directory for BitChat
    
    Returns:
        Path to config directory
    """
    if os.name == 'nt':  # Windows
        config_dir = Path(os.environ.get('APPDATA', '~')).expanduser() / 'BitChat'
    else:  # Unix-like
        config_dir = Path(os.environ.get('XDG_CONFIG_HOME', '~/.config')).expanduser() / 'bitchat'
    
    # Create directory if it doesn't exist
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_state_file_path() -> Path:
    """Get the path to the state file"""
    return get_config_dir() / 'state.json'


def generate_identity_key() -> ed25519.Ed25519PrivateKey:
    """Generate a new identity key for encryption"""
    return ed25519.Ed25519PrivateKey.generate()


def serialize_identity_key(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Serialize identity key to base64 string"""
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(private_bytes).decode('utf-8')


def deserialize_identity_key(key_data: str) -> ed25519.Ed25519PrivateKey:
    """Deserialize identity key from base64 string"""
    private_bytes = base64.b64decode(key_data.encode('utf-8'))
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)


def derive_encryption_key(identity_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Derive encryption key from identity key"""
    private_bytes = identity_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Use HKDF to derive encryption key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"bitchat-persistence",
        info=b"password-encryption",
    ).derive(private_bytes)
    
    return derived_key


def encrypt_password(password: str, identity_key_str: str) -> EncryptedPassword:
    """
    Encrypt a password using the identity key
    
    Args:
        password: Password to encrypt
        identity_key_str: Base64 encoded identity key
        
    Returns:
        EncryptedPassword object
        
    Raises:
        ValueError: If encryption fails
    """
    try:
        # Deserialize identity key
        identity_key = deserialize_identity_key(identity_key_str)
        
        # Derive encryption key
        encryption_key = derive_encryption_key(identity_key)
        
        # Encrypt password
        cipher = ChaCha20Poly1305(encryption_key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, password.encode('utf-8'), None)
        
        return EncryptedPassword(
            ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
            nonce=base64.b64encode(nonce).decode('utf-8')
        )
        
    except Exception as e:
        raise ValueError(f"Failed to encrypt password: {e}")


def decrypt_password(encrypted_password: EncryptedPassword, identity_key_str: str) -> str:
    """
    Decrypt a password using the identity key
    
    Args:
        encrypted_password: EncryptedPassword object
        identity_key_str: Base64 encoded identity key
        
    Returns:
        Decrypted password string
        
    Raises:
        ValueError: If decryption fails
    """
    try:
        # Deserialize identity key
        identity_key = deserialize_identity_key(identity_key_str)
        
        # Derive encryption key
        encryption_key = derive_encryption_key(identity_key)
        
        # Decrypt password
        cipher = ChaCha20Poly1305(encryption_key)
        nonce = base64.b64decode(encrypted_password.nonce.encode('utf-8'))
        ciphertext = base64.b64decode(encrypted_password.ciphertext.encode('utf-8'))
        
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
        
    except Exception as e:
        raise ValueError(f"Failed to decrypt password: {e}")


def save_state(app_state: AppState) -> None:
    """
    Save application state to disk
    
    Args:
        app_state: Application state to save
        
    Raises:
        OSError: If file write fails
    """
    try:
        state_file = get_state_file_path()
        
        # Convert sets to lists for JSON serialization
        state_dict = asdict(app_state)
        state_dict['blocked_peers'] = list(app_state.blocked_peers)
        state_dict['password_protected_channels'] = list(app_state.password_protected_channels)
        
        # Convert EncryptedPassword objects to dicts
        encrypted_passwords = {}
        for channel, encrypted_pw in app_state.encrypted_channel_passwords.items():
            encrypted_passwords[channel] = asdict(encrypted_pw)
        state_dict['encrypted_channel_passwords'] = encrypted_passwords
        
        # Write to file with pretty formatting
        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump(state_dict, f, indent=2, ensure_ascii=False)
            
        print(f"[PERSISTENCE] State saved to {state_file}")
        
    except Exception as e:
        raise OSError(f"Failed to save state: {e}")


def load_state() -> AppState:
    """
    Load application state from disk
    
    Returns:
        Loaded AppState or default state if file doesn't exist
    """
    try:
        state_file = get_state_file_path()
        
        if not state_file.exists():
            print("[PERSISTENCE] No saved state found, creating new state")
            # Generate new identity key for new installations
            identity_key = generate_identity_key()
            return AppState(identity_key=serialize_identity_key(identity_key))
        
        with open(state_file, 'r', encoding='utf-8') as f:
            state_dict = json.load(f)
        
        # Convert lists back to sets
        blocked_peers = set(state_dict.get('blocked_peers', []))
        password_protected_channels = set(state_dict.get('password_protected_channels', []))
        
        # Convert encrypted password dicts back to EncryptedPassword objects
        encrypted_passwords = {}
        for channel, encrypted_dict in state_dict.get('encrypted_channel_passwords', {}).items():
            encrypted_passwords[channel] = EncryptedPassword(**encrypted_dict)
        
        # Generate identity key if not present (for backwards compatibility)
        identity_key_str = state_dict.get('identity_key')
        if not identity_key_str:
            identity_key = generate_identity_key()
            identity_key_str = serialize_identity_key(identity_key)
        
        app_state = AppState(
            nickname=state_dict.get('nickname'),
            blocked_peers=blocked_peers,
            channel_creators=state_dict.get('channel_creators', {}),
            joined_channels=state_dict.get('joined_channels', []),
            password_protected_channels=password_protected_channels,
            channel_key_commitments=state_dict.get('channel_key_commitments', {}),
            favorites=state_dict.get('favorites', []),
            identity_key=identity_key_str,
            encrypted_channel_passwords=encrypted_passwords
        )
        
        print(f"[PERSISTENCE] State loaded from {state_file}")
        return app_state
        
    except Exception as e:
        print(f"[PERSISTENCE] Failed to load state: {e}")
        print("[PERSISTENCE] Using default state")
        # Generate new identity key for error cases
        identity_key = generate_identity_key()
        return AppState(identity_key=serialize_identity_key(identity_key))


def clear_state() -> None:
    """
    Clear saved state (useful for testing or reset)
    """
    try:
        state_file = get_state_file_path()
        if state_file.exists():
            state_file.unlink()
            print("[PERSISTENCE] State cleared")
        else:
            print("[PERSISTENCE] No state file to clear")
    except Exception as e:
        print(f"[PERSISTENCE] Failed to clear state: {e}")


def backup_state() -> Path:
    """
    Create a backup of the current state
    
    Returns:
        Path to backup file
        
    Raises:
        OSError: If backup fails
    """
    try:
        state_file = get_state_file_path()
        if not state_file.exists():
            raise OSError("No state file to backup")
        
        import time
        timestamp = int(time.time())
        backup_file = get_config_dir() / f"state_backup_{timestamp}.json"
        
        # Copy state file to backup
        import shutil
        shutil.copy2(state_file, backup_file)
        
        print(f"[PERSISTENCE] State backed up to {backup_file}")
        return backup_file
        
    except Exception as e:
        raise OSError(f"Failed to backup state: {e}")


def export_settings(export_file: Path) -> None:
    """
    Export settings to a specified file (excluding sensitive data)
    
    Args:
        export_file: Path to export file
    """
    try:
        app_state = load_state()
        
        # Create export data without sensitive information
        export_data = {
            "nickname": app_state.nickname,
            "joined_channels": app_state.joined_channels,
            "favorites": app_state.favorites,
            "channel_creators": app_state.channel_creators,
            "password_protected_channels": list(app_state.password_protected_channels),
            # Note: blocked_peers, identity_key, and encrypted_passwords are NOT exported
        }
        
        with open(export_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
            
        print(f"[PERSISTENCE] Settings exported to {export_file}")
        
    except Exception as e:
        raise OSError(f"Failed to export settings: {e}")


def import_settings(import_file: Path) -> None:
    """
    Import settings from a file (merges with existing state)
    
    Args:
        import_file: Path to import file
    """
    try:
        # Load current state
        app_state = load_state()
        
        # Load import data
        with open(import_file, 'r', encoding='utf-8') as f:
            import_data = json.load(f)
        
        # Merge import data with current state
        if 'nickname' in import_data:
            app_state.nickname = import_data['nickname']
        
        if 'joined_channels' in import_data:
            # Merge channels
            for channel in import_data['joined_channels']:
                if channel not in app_state.joined_channels:
                    app_state.joined_channels.append(channel)
        
        if 'favorites' in import_data:
            # Merge favorites
            for favorite in import_data['favorites']:
                if favorite not in app_state.favorites:
                    app_state.favorites.append(favorite)
        
        if 'channel_creators' in import_data:
            # Merge channel creators
            app_state.channel_creators.update(import_data['channel_creators'])
        
        if 'password_protected_channels' in import_data:
            # Merge password-protected channels
            app_state.password_protected_channels.update(import_data['password_protected_channels'])
        
        # Save merged state
        save_state(app_state)
        
        print(f"[PERSISTENCE] Settings imported from {import_file}")
        
    except Exception as e:
        raise OSError(f"Failed to import settings: {e}") 