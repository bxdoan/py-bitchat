#!/usr/bin/env python3
"""
BitChat Terminal - Python Implementation

Decentralized encrypted peer-to-peer chat over Bluetooth LE
"""

import asyncio
import os
import sys
import time
import uuid
import hashlib
import random
import json
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import logging

# Third-party imports
import bleak
from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from pybloom_live import BloomFilter

# Local imports
from .encryption import EncryptionService
from .compression import decompress, CompressionError
from .fragmentation import FragmentCollector, parse_fragment_payload, should_fragment, create_fragments, serialize_fragment
from .terminal_ux import (
    ChatContext, ChatMode, format_message_display, print_help, 
    print_logo, clear_terminal, format_connection_status
)
from .persistence import (
    AppState, load_state, save_state, encrypt_password, decrypt_password
)

# --- Constants ---

VERSION = "v1.0.0"

# UUIDs for BitChat service
BITCHAT_SERVICE_UUID = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
BITCHAT_CHARACTERISTIC_UUID = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"

# Cover traffic prefix used by iOS for dummy messages
COVER_TRAFFIC_PREFIX = "☂DUMMY☂"

# Packet header flags
FLAG_HAS_RECIPIENT = 0x01
FLAG_HAS_SIGNATURE = 0x02
FLAG_IS_COMPRESSED = 0x04

# Message payload flags (matching Swift's toBinaryPayload)
MSG_FLAG_IS_RELAY = 0x01
MSG_FLAG_IS_PRIVATE = 0x02
MSG_FLAG_HAS_ORIGINAL_SENDER = 0x04
MSG_FLAG_HAS_RECIPIENT_NICKNAME = 0x08
MSG_FLAG_HAS_SENDER_PEER_ID = 0x10
MSG_FLAG_HAS_MENTIONS = 0x20
MSG_FLAG_HAS_CHANNEL = 0x40
MSG_FLAG_IS_ENCRYPTED = 0x80

SIGNATURE_SIZE = 64  # Ed25519 signature size

# Swift's SpecialRecipients.broadcast = Data(repeating: 0xFF, count: 8)
BROADCAST_RECIPIENT = bytes([0xFF] * 8)

# --- Debug Levels ---

class DebugLevel(Enum):
    CLEAN = 0    # Default - minimal output
    BASIC = 1    # Connection info, key exchanges
    FULL = 2     # All debug output


# Global debug level
debug_level = DebugLevel.CLEAN


def debug_println(*args, **kwargs):
    """Debug print for basic debug (level 1+)"""
    if debug_level.value >= DebugLevel.BASIC.value:
        print(*args, **kwargs)


def debug_full_println(*args, **kwargs):
    """Debug print for full debug (level 2)"""
    if debug_level.value >= DebugLevel.FULL.value:
        print(*args, **kwargs)


# --- Protocol Structs and Enums ---

class MessageType(Enum):
    """Message type enumeration"""
    ANNOUNCE = 0x01
    KEY_EXCHANGE = 0x02
    LEAVE = 0x03
    MESSAGE = 0x04
    FRAGMENT_START = 0x05
    FRAGMENT_CONTINUE = 0x06
    FRAGMENT_END = 0x07
    CHANNEL_ANNOUNCE = 0x08
    CHANNEL_RETENTION = 0x09
    DELIVERY_ACK = 0x0A
    DELIVERY_STATUS_REQUEST = 0x0B
    READ_RECEIPT = 0x0C


@dataclass
class Peer:
    """Peer information"""
    nickname: Optional[str] = None


@dataclass
class BitchatPacket:
    """Parsed BitChat packet"""
    msg_type: MessageType
    sender_id: bytes
    sender_id_str: str
    recipient_id: Optional[bytes]
    recipient_id_str: Optional[str]
    payload: bytes
    ttl: int


@dataclass
class BitchatMessage:
    """Parsed BitChat message"""
    id: str
    content: str
    channel: Optional[str]
    is_encrypted: bool
    encrypted_content: Optional[bytes] = None


@dataclass
class DeliveryAck:
    """Delivery acknowledgment structure"""
    original_message_id: str
    ack_id: str
    recipient_id: str
    recipient_nickname: str
    timestamp: int
    hop_count: int


class DeliveryTracker:
    """Track sent messages awaiting delivery confirmation"""
    
    def __init__(self):
        self.pending_messages: Dict[str, Tuple[str, float, bool]] = {}  # message_id -> (content, sent_time, is_private)
        self.sent_acks: Set[str] = set()  # Track ACK IDs we've already sent
    
    def track_message(self, message_id: str, content: str, is_private: bool):
        """Track a message for delivery confirmation"""
        self.pending_messages[message_id] = (content, time.time(), is_private)
    
    def mark_delivered(self, message_id: str) -> bool:
        """Mark message as delivered"""
        return self.pending_messages.pop(message_id, None) is not None
    
    def should_send_ack(self, ack_id: str) -> bool:
        """Check if we should send an ACK (returns True if this is the first time)"""
        if ack_id in self.sent_acks:
            return False
        self.sent_acks.add(ack_id)
        return True


# --- Utility Functions ---

def generate_peer_id() -> str:
    """Generate a 4-byte peer ID as hex string (matching Swift)"""
    peer_id_bytes = random.randbytes(4)
    return peer_id_bytes.hex()


def unpad_message(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data"""
    if not data:
        return data
    
    # Last byte tells us how much padding to remove
    padding_length = data[-1]
    
    debug_full_println(f"[PADDING] Data size: {len(data)}, padding length indicated: {padding_length}")
    
    # Validate padding
    if padding_length == 0 or padding_length > len(data) or padding_length > 255:
        debug_full_println("[PADDING] Invalid padding length, returning data as-is")
        return data
    
    # Remove padding
    unpadded_len = len(data) - padding_length
    debug_full_println(f"[PADDING] Removing {padding_length} bytes of padding, resulting size: {unpadded_len}")
    
    return data[:unpadded_len]


def should_send_ack(is_private: bool, channel: Optional[str], mentions: Optional[List[str]], 
                   my_nickname: str, active_peer_count: int) -> bool:
    """Check if we should send an ACK for this message (matching iOS logic)"""
    if is_private:
        # Always ACK private messages
        return True
    elif channel:
        # For room messages, ACK if:
        # 1. Less than 10 active peers, OR
        # 2. We're mentioned
        if active_peer_count < 10:
            return True
        elif mentions and my_nickname in mentions:
            return True
        else:
            return False
    else:
        # Public broadcast messages - no ACK
        return False


# --- Packet Parsing and Creation ---

def parse_bitchat_packet(data: bytes) -> BitchatPacket:
    """
    Parse BitChat packet from raw bytes
    
    Packet format (Swift BinaryProtocol):
    - Version: 1 byte
    - Type: 1 byte
    - TTL: 1 byte
    - Timestamp: 8 bytes (UInt64)
    - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    - PayloadLength: 2 bytes (UInt16)
    - SenderID: 8 bytes
    - RecipientID: 8 bytes (if hasRecipient flag set)
    - Payload: Variable length
    - Signature: 64 bytes (if hasSignature flag set)
    """
    HEADER_SIZE = 13
    SENDER_ID_SIZE = 8
    RECIPIENT_ID_SIZE = 8
    
    if len(data) < HEADER_SIZE + SENDER_ID_SIZE:
        raise ValueError("Packet too small")
    
    offset = 0
    
    # 1. Version (1 byte)
    version = data[offset]
    offset += 1
    if version != 1:
        raise ValueError("Unsupported version")
    
    # 2. Type (1 byte)
    msg_type_raw = data[offset]
    offset += 1
    try:
        msg_type = MessageType(msg_type_raw)
    except ValueError:
        raise ValueError("Unknown message type")
    
    # 3. TTL (1 byte)
    ttl = data[offset]
    offset += 1
    
    # 4. Timestamp (8 bytes) - skip for now
    offset += 8
    
    # 5. Flags (1 byte)
    flags = data[offset]
    offset += 1
    has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0
    has_signature = (flags & FLAG_HAS_SIGNATURE) != 0
    is_compressed = (flags & FLAG_IS_COMPRESSED) != 0
    
    # 6. Payload length (2 bytes, big-endian)
    if len(data) < offset + 2:
        raise ValueError("Packet too small for payload length")
    payload_len = int.from_bytes(data[offset:offset + 2], 'big')
    offset += 2
    
    # Calculate expected total size
    expected_size = HEADER_SIZE + SENDER_ID_SIZE + payload_len
    if has_recipient:
        expected_size += RECIPIENT_ID_SIZE
    if has_signature:
        expected_size += SIGNATURE_SIZE
    
    if len(data) < expected_size:
        raise ValueError("Packet data shorter than expected")
    
    # 7. Sender ID (8 bytes)
    sender_id = data[offset:offset + SENDER_ID_SIZE]
    sender_id_str = sender_id.decode('utf-8', errors='ignore').rstrip('\x00')
    offset += SENDER_ID_SIZE
    
    # 8. Recipient ID (8 bytes if hasRecipient flag set)
    recipient_id = None
    recipient_id_str = None
    if has_recipient:
        recipient_id = data[offset:offset + RECIPIENT_ID_SIZE]
        recipient_id_str = recipient_id.decode('utf-8', errors='ignore').rstrip('\x00')
        debug_full_println(f"[PACKET] Recipient ID raw bytes: {recipient_id}")
        debug_full_println(f"[PACKET] Recipient ID as string: '{recipient_id_str}'")
        offset += RECIPIENT_ID_SIZE
    
    # 9. Payload
    payload = data[offset:offset + payload_len]
    offset += payload_len
    
    # 10. Signature (skip for now)
    if has_signature:
        # signature = data[offset:offset + SIGNATURE_SIZE]
        offset += SIGNATURE_SIZE
    
    # Decompress if needed
    if is_compressed:
        try:
            payload = decompress(payload)
        except CompressionError:
            raise ValueError("Failed to decompress payload")
    
    return BitchatPacket(
        msg_type=msg_type,
        sender_id=sender_id,
        sender_id_str=sender_id_str,
        recipient_id=recipient_id,
        recipient_id_str=recipient_id_str,
        payload=payload,
        ttl=ttl
    )


def parse_bitchat_message_payload(data: bytes) -> BitchatMessage:
    """Parse message payload to extract message content"""
    debug_full_println(f"[PARSE] Parsing message payload, size: {len(data)} bytes")
    debug_full_println(f"[PARSE] First 32 bytes hex: {data[:min(32, len(data))].hex()}")
    
    offset = 0
    
    if len(data) < 1:
        raise ValueError("Payload too short for flags")
    
    flags = data[offset]
    debug_full_println(f"[PARSE] Flags: 0x{flags:02X}")
    offset += 1
    
    has_channel = (flags & MSG_FLAG_HAS_CHANNEL) != 0
    is_encrypted = (flags & MSG_FLAG_IS_ENCRYPTED) != 0
    has_original_sender = (flags & MSG_FLAG_HAS_ORIGINAL_SENDER) != 0
    has_recipient_nickname = (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0
    has_sender_peer_id = (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0
    has_mentions = (flags & MSG_FLAG_HAS_MENTIONS) != 0
    
    if len(data) < offset + 8:
        raise ValueError("Payload too short for timestamp")
    
    # Skip timestamp
    offset += 8
    
    if len(data) < offset + 1:
        raise ValueError("Payload too short for ID length")
    
    id_len = data[offset]
    offset += 1
    
    if len(data) < offset + id_len:
        raise ValueError("Payload too short for ID")
    
    message_id = data[offset:offset + id_len].decode('utf-8')
    offset += id_len
    
    if len(data) < offset + 1:
        raise ValueError("Payload too short for sender length")
    
    sender_len = data[offset]
    offset += 1
    
    if len(data) < offset + sender_len:
        raise ValueError("Payload too short for sender")
    
    # Skip sender name
    offset += sender_len
    
    if len(data) < offset + 2:
        raise ValueError("Payload too short for content length")
    
    content_len = int.from_bytes(data[offset:offset + 2], 'big')
    offset += 2
    
    if len(data) < offset + content_len:
        raise ValueError("Payload too short for content")
    
    if is_encrypted:
        # For encrypted messages, store raw bytes
        content = ""
        encrypted_content = data[offset:offset + content_len]
    else:
        # For normal messages, parse as UTF-8 string
        content = data[offset:offset + content_len].decode('utf-8')
        encrypted_content = None
    
    offset += content_len
    
    # Handle optional fields based on flags
    if has_original_sender:
        if len(data) < offset + 1:
            raise ValueError("Payload too short for original sender length")
        orig_sender_len = data[offset]
        offset += 1
        if len(data) < offset + orig_sender_len:
            raise ValueError("Payload too short for original sender")
        offset += orig_sender_len
    
    if has_recipient_nickname:
        if len(data) < offset + 1:
            raise ValueError("Payload too short for recipient nickname length")
        recipient_len = data[offset]
        offset += 1
        if len(data) < offset + recipient_len:
            raise ValueError("Payload too short for recipient nickname")
        offset += recipient_len
    
    if has_sender_peer_id:
        if len(data) < offset + 1:
            raise ValueError("Payload too short for sender peer ID length")
        peer_id_len = data[offset]
        offset += 1
        if len(data) < offset + peer_id_len:
            raise ValueError("Payload too short for sender peer ID")
        offset += peer_id_len
    
    # Parse mentions array (iOS compatibility)
    if has_mentions:
        if len(data) < offset + 2:
            raise ValueError("Payload too short for mentions count")
        mentions_count = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 2
        
        # Skip each mention
        for _ in range(mentions_count):
            if len(data) < offset + 1:
                raise ValueError("Payload too short for mention length")
            mention_len = data[offset]
            offset += 1
            if len(data) < offset + mention_len:
                raise ValueError("Payload too short for mention")
            offset += mention_len
    
    channel = None
    if has_channel:
        if len(data) < offset + 1:
            raise ValueError("Payload too short for channel length")
        
        channel_len = data[offset]
        offset += 1
        
        if len(data) < offset + channel_len:
            raise ValueError("Payload too short for channel")
        
        channel = data[offset:offset + channel_len].decode('utf-8')
    
    return BitchatMessage(
        id=message_id,
        content=content,
        channel=channel,
        is_encrypted=is_encrypted,
        encrypted_content=encrypted_content
    )


# --- Packet Creation Functions ---

def create_bitchat_packet(sender_id_str: str, msg_type: MessageType, payload: bytes, 
                         recipient_id_str: Optional[str] = None, signature: Optional[bytes] = None) -> bytes:
    """Create a BitChat packet with the specified parameters"""
    debug_full_println(f"[PACKET] Creating packet: type={msg_type} (0x{msg_type.value:02X}), sender_id={sender_id_str}, payload_len={len(payload)}")
    
    data = bytearray()
    
    # 1. Version (1 byte)
    data.append(1)
    
    # 2. Type (1 byte)
    data.append(msg_type.value)
    
    # 3. TTL (1 byte)
    data.append(7)  # Maximum reach
    
    # 4. Timestamp (8 bytes, big-endian)
    timestamp_ms = int(time.time() * 1000)
    data.extend(timestamp_ms.to_bytes(8, 'big'))
    
    # 5. Flags (1 byte)
    flags = 0
    
    # For fragments, don't set recipient flag
    has_recipient = msg_type not in [MessageType.FRAGMENT_START, MessageType.FRAGMENT_CONTINUE, MessageType.FRAGMENT_END]
    
    if has_recipient:
        flags |= FLAG_HAS_RECIPIENT
    if signature is not None:
        flags |= FLAG_HAS_SIGNATURE
    # No compression for now
    
    data.append(flags)
    
    # 6. Payload length (2 bytes, big-endian)
    data.extend(len(payload).to_bytes(2, 'big'))
    
    # 7. Sender ID (8 bytes) - Use ASCII bytes directly, pad with zeros
    sender_id_bytes = sender_id_str.encode('utf-8')[:8]
    sender_id_bytes = sender_id_bytes.ljust(8, b'\x00')
    data.extend(sender_id_bytes)
    
    # 8. Recipient ID (8 bytes) - only if hasRecipient flag is set
    if has_recipient:
        if recipient_id_str:
            # Private message - use specific recipient
            recipient_bytes = recipient_id_str.encode('utf-8')[:8]
            recipient_bytes = recipient_bytes.ljust(8, b'\x00')
            data.extend(recipient_bytes)
        else:
            # Broadcast message
            data.extend(BROADCAST_RECIPIENT)
    
    # 9. Payload (variable)
    data.extend(payload)
    
    # 10. Signature (64 bytes if present)
    if signature is not None:
        data.extend(signature)
    
    debug_full_println(f"[PACKET] Final packet size: {len(data)} bytes")
    
    return bytes(data)


def create_bitchat_message_payload(sender: str, content: str, channel: Optional[str] = None,
                                  is_private: bool = False, sender_peer_id: str = "f453f3e0") -> Tuple[bytes, str]:
    """Create a BitChat message payload"""
    return create_bitchat_message_payload_full(sender, content, channel, is_private, sender_peer_id)


def create_bitchat_message_payload_full(sender: str, content: str, channel: Optional[str] = None,
                                       is_private: bool = False, sender_peer_id: str = "f453f3e0") -> Tuple[bytes, str]:
    """Create a complete BitChat message payload with all flags"""
    data = bytearray()
    
    # Message flags
    flags = MSG_FLAG_HAS_SENDER_PEER_ID  # Always include sender peer ID
    
    if channel:
        flags |= MSG_FLAG_HAS_CHANNEL
    
    if is_private:
        flags |= MSG_FLAG_IS_PRIVATE
    
    data.append(flags)
    
    # Timestamp (8 bytes, big-endian)
    timestamp_ms = int(time.time() * 1000)
    data.extend(timestamp_ms.to_bytes(8, 'big'))
    
    # Message ID
    message_id = str(uuid.uuid4())
    data.append(len(message_id))
    data.extend(message_id.encode('utf-8'))
    
    # Sender name
    data.append(len(sender))
    data.extend(sender.encode('utf-8'))
    
    # Content
    content_bytes = content.encode('utf-8')
    data.extend(len(content_bytes).to_bytes(2, 'big'))
    data.extend(content_bytes)
    
    # Sender peer ID (since we always set MSG_FLAG_HAS_SENDER_PEER_ID)
    data.append(len(sender_peer_id))
    data.extend(sender_peer_id.encode('utf-8'))
    
    # Channel name (if present)
    if channel:
        data.append(len(channel))
        data.extend(channel.encode('utf-8'))
    
    return bytes(data), message_id


def create_encrypted_channel_message_payload(sender: str, content: str, channel: str, 
                                           channel_key: bytes, encryption_service: EncryptionService,
                                           sender_peer_id: str) -> Tuple[bytes, str]:
    """Create an encrypted channel message payload"""
    data = bytearray()
    flags = MSG_FLAG_HAS_CHANNEL | MSG_FLAG_IS_ENCRYPTED | MSG_FLAG_HAS_SENDER_PEER_ID
    
    data.append(flags)
    
    # Timestamp
    timestamp_ms = int(time.time() * 1000)
    data.extend(timestamp_ms.to_bytes(8, 'big'))
    
    # Message ID
    message_id = str(uuid.uuid4())
    data.append(len(message_id))
    data.extend(message_id.encode('utf-8'))
    
    # Sender name
    data.append(len(sender))
    data.extend(sender.encode('utf-8'))
    
    # Encrypt the content
    try:
        encrypted_content = encryption_service.encrypt_with_key(content.encode('utf-8'), channel_key)
    except Exception as e:
        print(f"[!] Failed to encrypt message: {e}")
        # Fall back to unencrypted
        return create_bitchat_message_payload_full(sender, content, channel, False, sender_peer_id)
    
    # Content length and encrypted content
    data.extend(len(encrypted_content).to_bytes(2, 'big'))
    data.extend(encrypted_content)
    
    # Sender peer ID
    data.append(len(sender_peer_id))
    data.extend(sender_peer_id.encode('utf-8'))
    
    # Channel name
    data.append(len(channel))
    data.extend(channel.encode('utf-8'))
    
    return bytes(data), message_id


def create_delivery_ack(original_message_id: str, recipient_id: str, 
                       recipient_nickname: str, hop_count: int = 1) -> bytes:
    """Create delivery ACK matching iOS format"""
    ack = {
        "originalMessageID": original_message_id,
        "ackID": str(uuid.uuid4()),
        "recipientID": recipient_id,
        "recipientNickname": recipient_nickname,
        "timestamp": int(time.time() * 1000),
        "hopCount": hop_count,
    }
    
    return json.dumps(ack).encode('utf-8')


# --- Bluetooth Functions ---

async def find_bitchat_device() -> Optional[bleak.BLEDevice]:
    """Scan for BitChat devices"""
    devices = await BleakScanner.discover(timeout=5.0)
    
    for device in devices:
        if device.name and "bitchat" in device.name.lower():
            return device
        
        # Check services if available
        if hasattr(device, 'metadata') and device.metadata:
            uuids = device.metadata.get('uuids', [])
            if BITCHAT_SERVICE_UUID.lower() in [u.lower() for u in uuids]:
                return device
    
    return None


async def send_packet_with_fragmentation(client: BleakClient, char_uuid: str, 
                                       packet: bytes, my_peer_id: str) -> bool:
    """Send packet with automatic fragmentation if needed"""
    if len(packet) > 500:  # Fragment if larger than 500 bytes
        print(f"[FRAG] Packet size {len(packet)} bytes requires fragmentation")
        
        # Create fragments
        fragments = create_fragments(packet, MessageType.MESSAGE.value, fragment_size=150)
        
        if not fragments:
            # Fallback to direct send
            try:
                await client.write_gatt_char(char_uuid, packet, response=False)
                return True
            except Exception as e:
                print(f"[!] Failed to send packet: {e}")
                return False
        
        # Send fragments with timing
        for i, fragment in enumerate(fragments):
            fragment_type = MessageType.FRAGMENT_START if i == 0 else (
                MessageType.FRAGMENT_END if i == len(fragments) - 1 else MessageType.FRAGMENT_CONTINUE
            )
            
            fragment_payload = serialize_fragment(fragment)
            fragment_packet = create_bitchat_packet(my_peer_id, fragment_type, fragment_payload)
            
            try:
                await client.write_gatt_char(char_uuid, fragment_packet, response=False)
                print(f"[FRAG] Sent fragment {i + 1}/{len(fragments)}")
                
                if i < len(fragments) - 1:
                    await asyncio.sleep(0.02)  # 20ms delay between fragments
                    
            except Exception as e:
                print(f"[!] Failed to send fragment {i + 1}: {e}")
                return False
        
        return True
    else:
        # Send directly
        try:
            response = len(packet) > 512
            await client.write_gatt_char(char_uuid, packet, response=response)
            return True
        except Exception as e:
            print(f"[!] Failed to send packet: {e}")
            return False


# --- Main Function ---

async def main():
    """Main entry point"""
    global debug_level
    
    # Parse command line arguments
    if "-dd" in sys.argv or "--debug-full" in sys.argv:
        debug_level = DebugLevel.FULL
        print("🐛 Debug mode: FULL (verbose output)")
    elif "-d" in sys.argv or "--debug" in sys.argv:
        debug_level = DebugLevel.BASIC
        print("🐛 Debug mode: BASIC (connection info)")
    
    # Display logo
    print_logo()
    
    # Initialize state
    my_peer_id = generate_peer_id()
    debug_full_println(f"[DEBUG] My peer ID: {my_peer_id}")
    
    # Load persisted state
    app_state = load_state()
    nickname = app_state.nickname or "my-python-client"
    
    # Create encryption service
    encryption_service = EncryptionService()
    
    # Initialize chat context and other state
    chat_context = ChatContext()
    peers: Dict[str, Peer] = {}
    bloom = BloomFilter(capacity=500, error_rate=0.01)
    fragment_collector = FragmentCollector()
    delivery_tracker = DeliveryTracker()
    
    # Channel management
    channel_keys: Dict[str, bytes] = {}
    blocked_peers = app_state.blocked_peers.copy()
    channel_creators = app_state.channel_creators.copy()
    password_protected_channels = app_state.password_protected_channels.copy()
    channel_key_commitments = app_state.channel_key_commitments.copy()
    discovered_channels: Set[str] = set()
    
    # Auto-restore channel keys from saved passwords
    if app_state.identity_key:
        for channel, encrypted_password in app_state.encrypted_channel_passwords.items():
            try:
                password = decrypt_password(encrypted_password, app_state.identity_key)
                key = EncryptionService.derive_channel_key(password, channel)
                channel_keys[channel] = key
                debug_println(f"[CHANNEL] Restored key for password-protected channel: {channel}")
            except Exception as e:
                debug_println(f"[CHANNEL] Failed to restore key for {channel}: {e}")
    
    # Helper function to create app state for saving
    def create_app_state_for_saving() -> AppState:
        return AppState(
            nickname=nickname,
            blocked_peers=blocked_peers,
            channel_creators=channel_creators,
            joined_channels=chat_context.active_channels.copy(),
            password_protected_channels=password_protected_channels,
            channel_key_commitments=channel_key_commitments,
            favorites=app_state.favorites,
            identity_key=app_state.identity_key,
            encrypted_channel_passwords=app_state.encrypted_channel_passwords
        )
    
    # Scan for BitChat devices
    print("» Scanning for bitchat service...")
    debug_println("[1] Scanning for bitchat service...")
    
    device = await find_bitchat_device()
    if not device:
        print("\n❌ No BitChat device found")
        print("Please check:")
        print("  • Your device has Bluetooth hardware")
        print("  • Bluetooth is enabled in system settings")
        print("  • Another BitChat device is nearby and discoverable")
        return
    
    print("» Found bitchat service! Connecting...")
    debug_println("[1] Match Found! Connecting...")
    
    # Connect to device
    try:
        async with BleakClient(device) as client:
            print("» Connected! Discovering services...")
            
            # Find the characteristic
            char = None
            for service in client.services:
                if service.uuid.upper() == BITCHAT_SERVICE_UUID.upper():
                    for characteristic in service.characteristics:
                        if characteristic.uuid.upper() == BITCHAT_CHARACTERISTIC_UUID.upper():
                            char = characteristic
                            break
                    break
            
            if not char:
                print("❌ BitChat characteristic not found")
                return
            
            debug_println("[2] Connection established.")
            
            # Set up notifications
            def notification_handler(sender: BleakGATTCharacteristic, data: bytearray):
                # Handle notifications in the background
                asyncio.create_task(handle_notification(
                    bytes(data), my_peer_id, encryption_service, peers, bloom,
                    fragment_collector, delivery_tracker, chat_context, channel_keys,
                    blocked_peers, channel_creators, password_protected_channels,
                    channel_key_commitments, discovered_channels, nickname, client, char.uuid
                ))
            
            await client.start_notify(char.uuid, notification_handler)
            
            # Perform handshake
            debug_println("[3] Performing handshake...")
            
            # Generate and send key exchange
            key_exchange_payload = encryption_service.get_combined_public_key_data()
            key_exchange_packet = create_bitchat_packet(my_peer_id, MessageType.KEY_EXCHANGE, key_exchange_payload)
            await client.write_gatt_char(char.uuid, key_exchange_packet, response=False)
            
            # Delay between key exchange and announce
            await asyncio.sleep(0.5)
            
            # Send announce packet
            announce_packet = create_bitchat_packet(my_peer_id, MessageType.ANNOUNCE, nickname.encode('utf-8'))
            await client.write_gatt_char(char.uuid, announce_packet, response=False)
            
            debug_println("[3] Handshake sent. You can now chat.")
            if app_state.nickname:
                print(f"» Using saved nickname: {nickname}")
            print("» Type /status to see connection info")
            
            # Main input loop
            print("> ", end="", flush=True)
            
            try:
                while True:
                    # Get user input
                    line = await asyncio.get_event_loop().run_in_executor(None, input)
                    
                    if line == "/exit":
                        break
                    elif line == "/help":
                        print_help()
                    elif line == "/status":
                        peer_count = len(peers)
                        channel_count = len(chat_context.active_channels)
                        dm_count = len(chat_context.active_dms)
                        status = format_connection_status(peer_count, channel_count, dm_count, nickname, my_peer_id)
                        print(status)
                    elif line.startswith("/name "):
                        new_name = line[6:].strip()
                        if new_name and len(new_name) <= 20:
                            nickname = new_name
                            announce_packet = create_bitchat_packet(my_peer_id, MessageType.ANNOUNCE, nickname.encode('utf-8'))
                            await client.write_gatt_char(char.uuid, announce_packet, response=False)
                            print(f"» Nickname changed to: {nickname}")
                            
                            # Save state
                            state_to_save = create_app_state_for_saving()
                            try:
                                save_state(state_to_save)
                            except Exception as e:
                                print(f"Warning: Could not save nickname: {e}")
                        else:
                            print("⚠ Invalid nickname (max 20 characters)")
                    elif line == "/clear":
                        clear_terminal()
                        print_logo()
                    else:
                        # Send message
                        if line.strip():
                            current_channel = None
                            if chat_context.current_mode == ChatMode.CHANNEL:
                                current_channel = chat_context.current_channel
                            
                            # Create message payload
                            if current_channel and current_channel in channel_keys:
                                # Encrypted channel message
                                channel_key = channel_keys[current_channel]
                                message_payload, message_id = create_encrypted_channel_message_payload(
                                    nickname, line, current_channel, channel_key, encryption_service, my_peer_id
                                )
                            else:
                                # Regular message
                                message_payload, message_id = create_bitchat_message_payload(
                                    nickname, line, current_channel, False, my_peer_id
                                )
                            
                            # Sign and send
                            signature = encryption_service.sign(message_payload)
                            message_packet = create_bitchat_packet(my_peer_id, MessageType.MESSAGE, message_payload, signature=signature)
                            
                            if await send_packet_with_fragmentation(client, char.uuid, message_packet, my_peer_id):
                                # Show sent message
                                timestamp = datetime.now()
                                display = format_message_display(
                                    timestamp, nickname, line, False,
                                    current_channel is not None, current_channel, None, nickname
                                )
                                print(f"\r\x1b[K{display}")
                            else:
                                print("❌ Failed to send message")
                    
                    print("> ", end="", flush=True)
                    
            except KeyboardInterrupt:
                pass
            
            # Save state before exiting
            try:
                state_to_save = create_app_state_for_saving()
                save_state(state_to_save)
            except Exception as e:
                print(f"Warning: Could not save state: {e}")
            
    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        print("Please check:")
        print("  • Bluetooth is enabled")
        print("  • The other device is running BitChat")
        print("  • You're within range")


async def handle_notification(data: bytes, my_peer_id: str, encryption_service: EncryptionService,
                            peers: Dict[str, Peer], bloom: BloomFilter, fragment_collector: FragmentCollector,
                            delivery_tracker: DeliveryTracker, chat_context: ChatContext,
                            channel_keys: Dict[str, bytes], blocked_peers: Set[str],
                            channel_creators: Dict[str, str], password_protected_channels: Set[str],
                            channel_key_commitments: Dict[str, str], discovered_channels: Set[str],
                            nickname: str, client: BleakClient, char_uuid: str):
    """Handle incoming Bluetooth notifications"""
    try:
        if len(data) >= 2:
            msg_type = data[1]
            debug_full_println(f"[PACKET] Received {len(data)} bytes, type: 0x{msg_type:02X}")
        
        packet = parse_bitchat_packet(data)
        
        # Ignore our own messages
        if packet.sender_id_str == my_peer_id:
            return
        
        if packet.msg_type == MessageType.ANNOUNCE:
            peer_nickname = packet.payload.decode('utf-8', errors='ignore').strip()
            
            is_new_peer = packet.sender_id_str not in peers
            if packet.sender_id_str not in peers:
                peers[packet.sender_id_str] = Peer()
            
            peers[packet.sender_id_str].nickname = peer_nickname
            
            if is_new_peer:
                print(f"\r\x1b[K\x1b[33m{peer_nickname} connected\x1b[0m")
                print("> ", end="", flush=True)
            
            debug_println(f"[<-- RECV] Announce: Peer {packet.sender_id_str} is now known as '{peer_nickname}'")
        
        elif packet.msg_type == MessageType.KEY_EXCHANGE:
            public_key = packet.payload
            debug_println(f"[<-- RECV] Key exchange from {packet.sender_id_str} (key: {len(public_key)} bytes)")
            
            if encryption_service.add_peer_public_key(packet.sender_id_str, public_key):
                debug_println(f"[+] Successfully added encryption keys for peer {packet.sender_id_str}")
                
                # Send our key exchange back if we haven't already
                if packet.sender_id_str not in peers:
                    debug_full_println(f"[CRYPTO] Sending key exchange response to {packet.sender_id_str}")
                    key_exchange_payload = encryption_service.get_combined_public_key_data()
                    key_exchange_packet = create_bitchat_packet(my_peer_id, MessageType.KEY_EXCHANGE, key_exchange_payload)
                    await client.write_gatt_char(char_uuid, key_exchange_packet, response=False)
            else:
                print(f"[!] Failed to add peer public key from {packet.sender_id_str}")
        
        elif packet.msg_type == MessageType.MESSAGE:
            # Handle regular messages (simplified version)
            try:
                message = parse_bitchat_message_payload(packet.payload)
                
                if message.id not in bloom:
                    bloom.add(message.id)
                    
                    sender_nick = peers.get(packet.sender_id_str, Peer()).nickname or packet.sender_id_str
                    
                    # Display message
                    timestamp = datetime.now()
                    display = format_message_display(
                        timestamp, sender_nick, message.content, False,
                        message.channel is not None, message.channel, None, nickname
                    )
                    print(f"\r\x1b[K{display}")
                    print("> ", end="", flush=True)
                    
            except Exception as e:
                debug_println(f"[!] Failed to parse message: {e}")
        
        # Handle other message types as needed...
        
    except Exception as e:
        debug_println(f"[!] Error handling notification: {e}")


def main_cli():
    """CLI entry point"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n» Goodbye!")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main_cli() 