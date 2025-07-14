"""
Encryption module for BitChat Terminal

Handles all cryptographic operations including:
- X25519 key exchange  
- Ed25519 signatures
- ChaCha20-Poly1305 encryption
- Key derivation and management
"""

import hashlib
import os
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import nacl.secret
import nacl.public
import nacl.signing
import nacl.encoding


class EncryptionService:
    """
    Manages all encryption operations for BitChat
    
    Provides X25519 key exchange, Ed25519 signatures, and ChaCha20-Poly1305 encryption
    compatible with the Rust implementation.
    """
    
    def __init__(self):
        # Generate identity keys (Ed25519 for signing)
        self.identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self.identity_public_key = self.identity_private_key.public_key()
        
        # Generate exchange keys (X25519 for ECDH)
        self.exchange_private_key = x25519.X25519PrivateKey.generate()
        self.exchange_public_key = self.exchange_private_key.public_key()
        
        # Store peer keys: peer_id -> public_keys
        self.peer_exchange_keys: Dict[str, x25519.X25519PublicKey] = {}
        self.peer_identity_keys: Dict[str, ed25519.Ed25519PublicKey] = {}
        
        # Store shared secrets: peer_id -> shared_secret
        self.shared_secrets: Dict[str, bytes] = {}
        
    def get_combined_public_key_data(self) -> bytes:
        """
        Get combined public key data for key exchange
        
        Returns 96 bytes: 32 bytes X25519 + 32 bytes Ed25519 + 32 bytes identity
        Compatible with Rust implementation format.
        """
        # X25519 public key (32 bytes)
        exchange_bytes = self.exchange_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Ed25519 public key (32 bytes) 
        identity_bytes = self.identity_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Additional identity data (32 bytes) - using hash of identity key
        identity_hash = hashlib.sha256(identity_bytes).digest()
        
        return exchange_bytes + identity_bytes + identity_hash
    
    def add_peer_public_key(self, peer_id: str, combined_key_data: bytes) -> bool:
        """
        Add a peer's public keys from combined key exchange data
        
        Args:
            peer_id: Peer identifier
            combined_key_data: 96 bytes of combined public key data
            
        Returns:
            True if keys were added successfully
        """
        try:
            if len(combined_key_data) != 96:
                return False
                
            # Extract keys from combined data
            exchange_bytes = combined_key_data[:32]
            identity_bytes = combined_key_data[32:64]
            # identity_hash = combined_key_data[64:96]  # Not used for verification yet
            
            # Create public key objects
            exchange_key = x25519.X25519PublicKey.from_public_bytes(exchange_bytes)
            identity_key = ed25519.Ed25519PublicKey.from_public_bytes(identity_bytes)
            
            # Store keys
            self.peer_exchange_keys[peer_id] = exchange_key
            self.peer_identity_keys[peer_id] = identity_key
            
            # Generate shared secret
            shared_secret = self.exchange_private_key.exchange(exchange_key)
            self.shared_secrets[peer_id] = shared_secret
            
            return True
            
        except Exception as e:
            print(f"[CRYPTO] Failed to add peer key: {e}")
            return False
    
    def has_peer_key(self, peer_id: str) -> bool:
        """Check if we have keys for a peer"""
        return peer_id in self.shared_secrets
    
    def get_peer_fingerprint(self, peer_id: str) -> Optional[str]:
        """
        Get fingerprint of peer's identity key
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            Hex fingerprint of peer's identity key or None if not found
        """
        if peer_id not in self.peer_identity_keys:
            return None
            
        identity_key = self.peer_identity_keys[peer_id]
        identity_bytes = identity_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Hash and return first 8 bytes as hex
        hash_digest = hashlib.sha256(identity_bytes).digest()
        return hash_digest[:8].hex()
    
    def encrypt(self, data: bytes, peer_id: str) -> bytes:
        """
        Encrypt data for a specific peer
        
        Args:
            data: Plaintext data to encrypt
            peer_id: Target peer identifier
            
        Returns:
            Encrypted data
            
        Raises:
            ValueError: If no shared secret exists for peer
        """
        if peer_id not in self.shared_secrets:
            raise ValueError(f"No shared secret for peer {peer_id}")
            
        shared_secret = self.shared_secrets[peer_id]
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"bitchat-encryption",
        ).derive(shared_secret)
        
        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(derived_key)
        nonce = os.urandom(12)  # ChaCha20-Poly1305 uses 12-byte nonce
        
        ciphertext = cipher.encrypt(nonce, data, None)
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes, peer_id: str) -> bytes:
        """
        Decrypt data from a specific peer
        
        Args:
            encrypted_data: Encrypted data (nonce + ciphertext)
            peer_id: Source peer identifier
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            ValueError: If decryption fails or no shared secret exists
        """
        if peer_id not in self.shared_secrets:
            raise ValueError(f"No shared secret for peer {peer_id}")
            
        if len(encrypted_data) < 12:
            raise ValueError("Encrypted data too short")
            
        shared_secret = self.shared_secrets[peer_id]
        
        # Derive decryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"bitchat-encryption",
        ).derive(shared_secret)
        
        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Decrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(derived_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        return plaintext
    
    def encrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data with a specific key (for channel encryption)
        
        Args:
            data: Plaintext data
            key: 32-byte encryption key
            
        Returns:
            Encrypted data (nonce + ciphertext)
        """
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def decrypt_with_key(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data with a specific key (for channel decryption)
        
        Args:
            encrypted_data: Encrypted data (nonce + ciphertext)
            key: 32-byte decryption key
            
        Returns:
            Decrypted plaintext data
        """
        if len(encrypted_data) < 12:
            raise ValueError("Encrypted data too short")
            
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext
    
    def encrypt_for_peer(self, peer_id: str, data: bytes) -> bytes:
        """Convenience method for encrypting data for a peer"""
        return self.encrypt(data, peer_id)
    
    def sign(self, data: bytes) -> bytes:
        """
        Sign data with our identity key
        
        Args:
            data: Data to sign
            
        Returns:
            64-byte signature
        """
        signature = self.identity_private_key.sign(data)
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, peer_id: str) -> bool:
        """
        Verify a signature from a peer
        
        Args:
            data: Original data
            signature: Signature to verify
            peer_id: Peer who signed the data
            
        Returns:
            True if signature is valid
        """
        if peer_id not in self.peer_identity_keys:
            return False
            
        try:
            public_key = self.peer_identity_keys[peer_id]
            public_key.verify(signature, data)
            return True
        except Exception:
            return False
    
    @staticmethod
    def derive_channel_key(password: str, channel: str) -> bytes:
        """
        Derive a channel encryption key from password and channel name
        
        Args:
            password: Channel password
            channel: Channel name
            
        Returns:
            32-byte encryption key
        """
        # Combine password and channel name
        combined = f"{password}:{channel}".encode('utf-8')
        
        # Use HKDF to derive key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"bitchat-channel",
            info=channel.encode('utf-8'),
        ).derive(combined)
        
        return derived_key 