# entropy.py
"""
Entropy Calculation Module

Calculates Shannon entropy of binary data to detect compression/encryption.

Entropy interpretation:
- 0: All bytes identical (extremely compressed/repeated)
- 3-5: Normal uncompressed code/data
- 5-7: Possibly compressed
- 7-8: Likely compressed/encrypted (malware indicators)
- 8: Maximum entropy (random/encrypted data)
"""

import math
from collections import Counter

def calc_entropy(data):
    """
    Calculate Shannon entropy of binary data.
    
    Args:
        data: Bytes object or bytearray to analyze
    
    Returns:
        float: Entropy value between 0.0 and 8.0
            - 0: Completely uniform/constant data
            - 8: Maximum entropy (random data)
            - 7+: Strong indication of compression/encryption
    
    Formula:
        H = -Σ(pi * log2(pi)) where pi is probability of byte i
    
    Examples:
        >>> calc_entropy(b'\x00' * 100)  # All zeros
        0.0
        >>> calc_entropy(os.urandom(256))  # Random data
        7.9+
        >>> # Normal code typically has entropy 4-6
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())
