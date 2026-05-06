import random
import os
import sys
import argparse

def encode(data, source_path, key, use_xor, output_path=None):
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
            sys.exit(f"[-] Byte {hex(b)} not found in source dictionary!")
        indices.append(random.choice(byte_map[b]) ^ xor_val)

    final_output = [xor_val] + indices

    # Prepare the string content
    header = f"// Total Elements: {len(final_output)} (Key: {hex(xor_val)} + {len(indices)} indices)\n"
    array_start = "unsigned long long alphabetSoup[] = {\n"
    array_body = ""
    for i in range(0, len(final_output), 12):
        array_body += "    " + ", ".join(map(str, final_output[i:i+12])) + ",\n"
    array_end = "};\n"
    
    full_payload = header + array_start + array_body + array_end

    if output_path:
        try:
            with open(output_path, "w") as f:
                f.write(full_payload)
            print(f"[+] Alphabet Soup written to: {output_path}")
        except Exception as e:
            sys.exit(f"[-] Failed to write to file: {e}")
    else:
        print(full_payload)

def main():
    parser = argparse.ArgumentParser(description="AlphabetSoup Encoder")
    parser.add_argument("-i", "--input", help="Path to raw .bin shellcode file")
    parser.add_argument("-t", "--text", help="Plain text string to encode")
    parser.add_argument("-s", "--source", required=True, help="System file (e.g. cliconf.chm)")
    parser.add_argument("-k", "--key", default="0x0", help="XOR key (int or hex)")
    parser.add_argument("-o", "--output", help="Save output to a specific file (e.g. soup.h)")
    parser.add_argument("--xor", action="store_true", help="Enable XOR encoding of indices")
    args = parser.parse_args()

    if args.text:
        raw_data = args.text.encode() + b'\x00'
    elif args.input:
        if not os.path.exists(args.input):
            sys.exit(f"[-] Input file not found: {args.input}")
        with open(args.input, "rb") as f:
            raw_data = f.read()
    else:
        sys.exit("[-] Use --input (for .bin) or --text")

    encode(raw_data, args.source, int(args.key, 0), args.xor, args.output)

if __name__ == "__main__":
    main()