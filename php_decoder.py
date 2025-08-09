#!/usr/bin/env python3
"""
PHP Obfuscation Decoder
Analyzes and decodes various PHP obfuscation techniques
"""

import urllib.parse
import base64
import codecs
import gzip
import io

def decode_url_encoded(encoded_string):
    """Decode URL-encoded strings"""
    return urllib.parse.unquote(encoded_string)

def decode_base64(encoded_string):
    """Decode base64 encoded strings"""
    try:
        return base64.b64decode(encoded_string).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error decoding base64: {e}"

def decode_rot13(encoded_string):
    """Decode ROT13 encoded strings"""
    return codecs.decode(encoded_string, 'rot13')

def decode_gzinflate(encoded_string):
    """Decode gzinflate compressed strings"""
    try:
        return gzip.decompress(encoded_string.encode('latin1')).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error decompressing: {e}"

def analyze_aa_php_obfuscation():
    """Analyze the aa.php obfuscation pattern"""
    encoded = '%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64'
    decoded = decode_url_encoded(encoded)
    print(f"URL-encoded string: {encoded}")
    print(f"Decoded: {decoded}")
    print(f"Character array: {list(decoded)}")
    
    # Simulate the variable construction from aa.php
    chars = decoded
    if len(chars) >= 17:
        # $OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000000{3}.$OOO000000{5};
        func1 = chars[4] + chars[9] + chars[3] + chars[5]
        print(f"First function: {func1}")
        
        # Additional constructions would follow similar patterns
        print("This creates dynamic function names for code execution")

def decode_multi_layer(payload):
    """Decode multi-layer obfuscated payload (base64 -> rot13 -> gzinflate)"""
    print("Decoding multi-layer payload...")
    
    # Step 1: Base64 decode
    step1 = decode_base64(payload)
    print(f"After base64 decode: {step1[:100]}..." if len(step1) > 100 else step1)
    
    # Step 2: ROT13 decode
    step2 = decode_rot13(step1)
    print(f"After ROT13 decode: {step2[:100]}..." if len(step2) > 100 else step2)
    
    # Step 3: gzinflate
    step3 = decode_gzinflate(step2)
    print(f"After gzinflate: {step3[:200]}..." if len(step3) > 200 else step3)
    
    return step3

def extract_strings_from_php(php_content):
    """Extract potentially obfuscated strings from PHP content"""
    import re
    
    # Find base64 patterns
    base64_pattern = r"base64_decode\(['\"]([A-Za-z0-9+/=]+)['\"]\)"
    base64_matches = re.findall(base64_pattern, php_content)
    
    # Find URL-encoded patterns
    url_pattern = r"urldecode\(['\"]([%A-Fa-f0-9]+)['\"]\)"
    url_matches = re.findall(url_pattern, php_content)
    
    return {
        'base64_strings': base64_matches,
        'url_encoded_strings': url_matches
    }

if __name__ == "__main__":
    print("=== PHP Obfuscation Analysis ===\n")
    
    # Analyze aa.php pattern
    print("1. Analyzing aa.php URL-encoded obfuscation:")
    analyze_aa_php_obfuscation()
    print()
    
    # Demonstrate multi-layer decoding
    print("2. Multi-layer decoding example:")
    print("This would process: eval(gzinflate(str_rot13(base64_decode('...'))))")
    print("Each layer must be processed in reverse order of encoding")
    print()
    
    print("3. Detection patterns:")
    patterns = [
        "eval(",
        "base64_decode(",
        "gzinflate(",
        "str_rot13(",
        "urldecode(",
        "system(",
        "exec(",
        "shell_exec(",
        "fsockopen("
    ]
    print("Suspicious function calls to monitor:")
    for pattern in patterns:
        print(f"  - {pattern}")