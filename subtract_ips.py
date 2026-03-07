#!/usr/bin/env python3
"""Subtract one IP list from another: A - B"""

import sys


def subtract_ips(file_a, file_b, output_file):
    with open(file_a) as f:
        ips_a = set(line.strip() for line in f if line.strip())
    with open(file_b) as f:
        ips_b = set(line.strip() for line in f if line.strip())

    result = sorted(ips_a - ips_b)

    with open(output_file, "w") as f:
        f.write("\n".join(result) + "\n")

    print(f"A: {len(ips_a)} IPs, B: {len(ips_b)} IPs, A-B: {len(result)} IPs")
    print(f"Result saved to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <file_A> <file_B> <output_file>")
        sys.exit(1)
    subtract_ips(sys.argv[1], sys.argv[2], sys.argv[3])
