"""
Compression module for BitChat Terminal

Handles data compression/decompression using Zstandard
Compatible with the Rust implementation.
"""

import zstandard as zstd
from typing import Union


class CompressionError(Exception):
    """Custom exception for compression-related errors"""
    pass


def compress(data: Union[str, bytes], level: int = 3) -> bytes:
    """
    Compress data using Zstandard compression
    
    Args:
        data: Data to compress (string or bytes)
        level: Compression level (1-22, default 3 for speed/size balance)
        
    Returns:
        Compressed data as bytes
        
    Raises:
        CompressionError: If compression fails
    """
    try:
        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Create compressor with specified level
        compressor = zstd.ZstdCompressor(level=level)
        
        # Compress the data
        compressed = compressor.compress(data)
        
        return compressed
        
    except Exception as e:
        raise CompressionError(f"Compression failed: {e}")


def decompress(compressed_data: bytes, max_size: int = 10 * 1024 * 1024) -> bytes:
    """
    Decompress Zstandard compressed data
    
    Args:
        compressed_data: Compressed data to decompress
        max_size: Maximum decompressed size (default 10MB for safety)
        
    Returns:
        Decompressed data as bytes
        
    Raises:
        CompressionError: If decompression fails
    """
    try:
        # Create decompressor
        decompressor = zstd.ZstdDecompressor()
        
        # Decompress with size limit for safety
        decompressed = decompressor.decompress(compressed_data, max_output_size=max_size)
        
        return decompressed
        
    except Exception as e:
        raise CompressionError(f"Decompression failed: {e}")


def should_compress(data: Union[str, bytes], min_size: int = 100) -> bool:
    """
    Determine if data should be compressed based on size
    
    Args:
        data: Data to check
        min_size: Minimum size in bytes to consider compression
        
    Returns:
        True if data should be compressed
    """
    if isinstance(data, str):
        data_size = len(data.encode('utf-8'))
    else:
        data_size = len(data)
        
    return data_size >= min_size


def get_compression_ratio(original_data: Union[str, bytes], compressed_data: bytes) -> float:
    """
    Calculate compression ratio
    
    Args:
        original_data: Original uncompressed data
        compressed_data: Compressed data
        
    Returns:
        Compression ratio (original_size / compressed_size)
    """
    if isinstance(original_data, str):
        original_size = len(original_data.encode('utf-8'))
    else:
        original_size = len(original_data)
        
    compressed_size = len(compressed_data)
    
    if compressed_size == 0:
        return float('inf')
        
    return original_size / compressed_size


def compress_if_beneficial(data: Union[str, bytes], min_ratio: float = 1.1) -> tuple[bytes, bool]:
    """
    Compress data only if it provides a good compression ratio
    
    Args:
        data: Data to potentially compress
        min_ratio: Minimum compression ratio to make compression worthwhile
        
    Returns:
        Tuple of (final_data, was_compressed)
    """
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
        
    # Don't compress very small data
    if not should_compress(data_bytes):
        return data_bytes, False
        
    try:
        compressed = compress(data_bytes)
        ratio = get_compression_ratio(data_bytes, compressed)
        
        # Only use compressed version if we achieve good compression
        if ratio >= min_ratio:
            return compressed, True
        else:
            return data_bytes, False
            
    except CompressionError:
        # If compression fails, return original data
        return data_bytes, False 