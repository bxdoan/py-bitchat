"""
Fragmentation module for BitChat Terminal

Handles message fragmentation and reassembly for large packets
Compatible with the Rust implementation.
"""

import os
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


class FragmentType(Enum):
    """Fragment type enumeration"""
    START = 0
    CONTINUE = 1
    END = 2


@dataclass
class Fragment:
    """
    Represents a single fragment of a larger message
    """
    fragment_id: bytes  # 8 bytes unique identifier
    index: int         # Fragment index (0-based)
    total: int         # Total number of fragments
    original_type: int # Original message type
    data: bytes        # Fragment payload data
    fragment_type: FragmentType


class FragmentCollector:
    """
    Collects and reassembles message fragments
    
    Compatible with the Rust implementation's fragment format:
    - Fragment ID: 8 bytes
    - Index: 2 bytes (big-endian)
    - Total: 2 bytes (big-endian) 
    - Original type: 1 byte
    - Data: variable length
    """
    
    def __init__(self):
        # fragment_id_hex -> {index -> data}
        self.fragments: Dict[str, Dict[int, bytes]] = {}
        # fragment_id_hex -> (total, original_type, sender_id)
        self.metadata: Dict[str, Tuple[int, int, str]] = {}
    
    def add_fragment(
        self, 
        fragment_id: bytes, 
        index: int, 
        total: int, 
        original_type: int, 
        data: bytes, 
        sender_id: str
    ) -> Optional[Tuple[bytes, str]]:
        """
        Add a fragment and attempt reassembly
        
        Args:
            fragment_id: 8-byte unique fragment identifier
            index: Fragment index (0-based)
            total: Total number of fragments
            original_type: Original message type
            data: Fragment data
            sender_id: Sender identifier
            
        Returns:
            Tuple of (complete_data, sender_id) if reassembly is complete, None otherwise
        """
        # Convert fragment ID to hex string (matching Rust implementation)
        fragment_id_hex = fragment_id.hex()
        
        print(f"[COLLECTOR] Adding fragment {index + 1}/{total} for ID {fragment_id_hex[:8]}")
        
        # Initialize if first fragment
        if fragment_id_hex not in self.fragments:
            print(f"[COLLECTOR] Creating new fragment collection for ID {fragment_id_hex[:8]}")
            self.fragments[fragment_id_hex] = {}
            self.metadata[fragment_id_hex] = (total, original_type, sender_id)
        
        # Add fragment data at index
        if fragment_id_hex in self.fragments:
            fragment_map = self.fragments[fragment_id_hex]
            fragment_map[index] = data
            print(f"[COLLECTOR] Fragment {index + 1} stored. Have {len(fragment_map)}/{total} fragments")
            
            # Check if we have all fragments
            if len(fragment_map) == total:
                print("[COLLECTOR] ✓ All fragments received! Reassembling...")
                
                # Reassemble in order
                complete_data = bytearray()
                for i in range(total):
                    if i in fragment_map:
                        fragment_data = fragment_map[i]
                        print(f"[COLLECTOR] Appending fragment {i + 1} ({len(fragment_data)} bytes)")
                        complete_data.extend(fragment_data)
                    else:
                        print(f"[COLLECTOR] ✗ Missing fragment {i + 1}")
                        return None
                
                print(f"[COLLECTOR] ✓ Reassembly complete: {len(complete_data)} bytes total")
                
                # Get sender from metadata
                _, _, sender = self.metadata.get(fragment_id_hex, (0, 0, "Unknown"))
                
                # Clean up
                del self.fragments[fragment_id_hex]
                del self.metadata[fragment_id_hex]
                
                return bytes(complete_data), sender
            else:
                print(f"[COLLECTOR] Waiting for more fragments ({len(fragment_map)}/{total} received)")
        
        return None


def should_fragment(data: bytes, max_size: int = 500) -> bool:
    """
    Determine if data should be fragmented
    
    Args:
        data: Data to check
        max_size: Maximum size before fragmentation is needed
        
    Returns:
        True if data should be fragmented
    """
    return len(data) > max_size


def create_fragments(
    data: bytes, 
    original_type: int, 
    fragment_size: int = 150
) -> List[Fragment]:
    """
    Fragment large data into smaller chunks
    
    Args:
        data: Data to fragment
        original_type: Original message type
        fragment_size: Size of each fragment's data portion
        
    Returns:
        List of Fragment objects
    """
    if len(data) <= fragment_size:
        # Data is small enough, no fragmentation needed
        return []
    
    # Generate random 8-byte fragment ID
    fragment_id = os.urandom(8)
    
    # Split data into chunks
    chunks = [data[i:i + fragment_size] for i in range(0, len(data), fragment_size)]
    total_fragments = len(chunks)
    
    fragments = []
    for index, chunk in enumerate(chunks):
        # Determine fragment type
        if index == 0:
            fragment_type = FragmentType.START
        elif index == total_fragments - 1:
            fragment_type = FragmentType.END
        else:
            fragment_type = FragmentType.CONTINUE
        
        fragment = Fragment(
            fragment_id=fragment_id,
            index=index,
            total=total_fragments,
            original_type=original_type,
            data=chunk,
            fragment_type=fragment_type
        )
        fragments.append(fragment)
    
    print(f"[FRAG] Created {total_fragments} fragments from {len(data)} bytes")
    print(f"[FRAG] Fragment ID: {fragment_id.hex()}")
    print(f"[FRAG] Fragment size: {fragment_size} bytes")
    
    return fragments


def serialize_fragment(fragment: Fragment) -> bytes:
    """
    Serialize a fragment to the wire format
    
    Wire format:
    - Fragment ID: 8 bytes
    - Index: 2 bytes (big-endian)
    - Total: 2 bytes (big-endian)
    - Original type: 1 byte
    - Data: variable length
    
    Args:
        fragment: Fragment to serialize
        
    Returns:
        Serialized fragment data
    """
    payload = bytearray()
    
    # Fragment ID (8 bytes)
    payload.extend(fragment.fragment_id)
    
    # Index as 2 bytes (big-endian)
    payload.extend(fragment.index.to_bytes(2, 'big'))
    
    # Total as 2 bytes (big-endian)
    payload.extend(fragment.total.to_bytes(2, 'big'))
    
    # Original message type (1 byte)
    payload.append(fragment.original_type)
    
    # Fragment data
    payload.extend(fragment.data)
    
    # Debug logging for first and last fragments
    if fragment.index == 0 or fragment.index == fragment.total - 1:
        print(f"[DEBUG] Fragment {fragment.index + 1}/{fragment.total} metadata: "
              f"ID={fragment.fragment_id[:4].hex()} "
              f"index_bytes={fragment.index >> 8:02X}{fragment.index & 0xFF:02X} "
              f"total_bytes={fragment.total >> 8:02X}{fragment.total & 0xFF:02X} "
              f"type={fragment.original_type:02X}")
    
    return bytes(payload)


def parse_fragment_payload(payload: bytes) -> Optional[Tuple[bytes, int, int, int, bytes]]:
    """
    Parse fragment payload from wire format
    
    Args:
        payload: Raw fragment payload
        
    Returns:
        Tuple of (fragment_id, index, total, original_type, data) or None if invalid
    """
    if len(payload) < 13:  # Minimum size: 8 + 2 + 2 + 1 = 13 bytes
        return None
    
    try:
        offset = 0
        
        # Fragment ID (8 bytes)
        fragment_id = payload[offset:offset + 8]
        offset += 8
        
        # Index (2 bytes, big-endian)
        index = int.from_bytes(payload[offset:offset + 2], 'big')
        offset += 2
        
        # Total (2 bytes, big-endian)
        total = int.from_bytes(payload[offset:offset + 2], 'big')
        offset += 2
        
        # Original type (1 byte)
        original_type = payload[offset]
        offset += 1
        
        # Fragment data (remaining bytes)
        data = payload[offset:]
        
        return fragment_id, index, total, original_type, data
        
    except Exception as e:
        print(f"[FRAG] Failed to parse fragment payload: {e}")
        return None


def calculate_fragment_overhead() -> int:
    """
    Calculate the overhead bytes added by fragmentation
    
    Returns:
        Number of overhead bytes per fragment
    """
    # Fragment header: 8 + 2 + 2 + 1 = 13 bytes
    # Plus packet header overhead
    return 13 + 21  # 21 bytes for packet header 