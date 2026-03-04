import random, re, os, sys, argparse

def encode(data, source_path, key, use_xor):
    if not os.path.exists(source_path):
        sys.exit(f"[-] Source missing: {source_path}")

    with open(source_path, "rb") as f:
        source_data = f.read()

    byte_map = {}
    for offset, byte in enumerate(source_data):
        byte_map.setdefault(byte, []).append(offset)

    indices = []
    xor_val = key if use_xor else 0

    for b in data:
        if b not in byte_map:
            sys.exit(f"[-] Byte {hex(b)} not found in source!")
        indices.append(random.choice(byte_map[b]) ^ xor_val)

    # Prepend the key so the C++ knows what to do
    final_output = [xor_val] + indices

    print(f"// Total Elements: {len(final_output)} (Key + {len(indices)} bytes)")
    print("unsigned long long alphabetSoup[] = {")
    for i in range(0, len(final_output), 12):
        print("    " + ", ".join(map(str, final_output[i:i+12])) + ",")
    print("};")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="File with \\x00 style shellcode")
    parser.add_argument("-t", "--text", help="Plain text string")
    parser.add_argument("-s", "--source", required=True)
    parser.add_argument("-k", "--key", default="0")
    parser.add_argument("--xor", action="store_true")
    args = parser.parse_args()

    # Determine input data
    if args.text:
        # Encode string + null terminator
        raw_data = args.text.encode() + b'\x00'
    elif args.input:
        with open(args.input, "r") as f:
            # Matches \xHH or 0xHH
            hex_pts = re.findall(r'(?:\\x|0x)([0-9a-fA-F]{2})', f.read())
            raw_data = bytes([int(h, 16) for h in hex_pts])
    else:
        sys.exit("[-] Use --input or --text")

    encode(raw_data, args.source, int(args.key, 0), args.xor)

if __name__ == "__main__":
    main()