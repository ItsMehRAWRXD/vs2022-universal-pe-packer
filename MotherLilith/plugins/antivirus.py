#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
from pathlib import Path

def scan_cpp(target):
    print(f"\n[Scanning C++: {target}]")
    result = subprocess.run(["cppcheck", "--enable=all", "--quiet", str(target)], capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if not result.stdout and not result.stderr:
        print("No issues found.")

def scan_python(target):
    print(f"\n[Scanning Python: {target}]")
    result = subprocess.run(["flake8", str(target)], capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if not result.stdout and not result.stderr:
        print("No issues found.")

def scan_path(path):
    path = Path(path)
    if path.is_file():
        if path.suffix in [".cpp", ".hpp", ".cc", ".cxx", ".c", ".h"]:
            scan_cpp(path)
        elif path.suffix == ".py":
            scan_python(path)
        else:
            print(f"[Skipping unsupported file: {path}]")
    elif path.is_dir():
        for root, dirs, files in os.walk(path):
            for file in files:
                scan_path(Path(root) / file)
    else:
        print(f"[Path not found: {path}]")

def main():
    parser = argparse.ArgumentParser(description="Mother Lilith Antivirus Plug-in: Static Code Scanner (C++/Python)")
    parser.add_argument("target", help="File or directory to scan")
    args = parser.parse_args()
    scan_path(args.target)
    print("\n[Scan complete]")

if __name__ == "__main__":
    main()