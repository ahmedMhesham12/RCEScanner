#!/usr/bin/env python3
"""
Author     : Mohammad Askar | @mohammadaskar2
Updated by : Ahmed | @ahmedMhesham12

Description:
    Scan PHP files for potential Remote Code Execution (RCE) vulnerabilities
    by detecting usage of dangerous PHP functions.

Requirements:
    pip install termcolor tabulate
"""

import os
import sys
import re
import argparse
from termcolor import cprint
from tabulate import tabulate

# Dangerous PHP functions that can lead to RCE
RCE_FUNCTIONS = [
    "eval",
    "assert",
    "create_function",
    "preg_replace",  # only dangerous if /e modifier is used
    "system",
    "exec",
    "passthru",
    "shell_exec",
    "popen",
    "proc_open",
    "call_user_func",
    "call_user_func_array",
    "unserialize"
]


def parse_arguments():
    parser = argparse.ArgumentParser(description="PHP RCE Scanner")
    parser.add_argument("path", help="Directory path to scan")
    parser.add_argument("extension", help="File extension to filter (e.g. php)")
    return parser.parse_args()


def find_php_files(path, extension):
    if not os.path.isdir(path):
        cprint("[-] Error: Provided path does not exist or is not a directory.", "red")
        sys.exit(1)

    cprint("[+] Scanning for PHP files...", "green")

    php_files = []
    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(f".{extension}"):
                full_path = os.path.join(root, file)
                php_files.append(full_path)

    cprint(f"[+] Found {len(php_files)} '.{extension}' files.", "green")
    return php_files


def scan_file_for_rce(file_path):
    results = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, 1):
            for func in RCE_FUNCTIONS:
                if func == "preg_replace":
                    # Check if /e modifier is used
                    if re.search(r'preg_replace\s*\(.*?[\'"].*?/e[\'"]', line):
                        results.append([file_path, "preg_replace /e", idx])
                else:
                    pattern = rf'{func}\s*\((.*?)\)'
                    if re.search(pattern, line):
                        results.append([file_path, func, idx])
    except Exception as e:
        cprint(f"[!] Error reading file {file_path}: {e}", "red")

    return results


def main():
    args = parse_arguments()
    files = find_php_files(args.path, args.extension)

    all_rce_hits = []
    for file in files:
        hits = scan_file_for_rce(file)
        all_rce_hits.extend(hits)

    if all_rce_hits:
        print(tabulate(
            all_rce_hits,
            headers=["File", "RCE Function", "Line Number"],
            tablefmt="psql",
            stralign="center"
        ))
    else:
        cprint("[+] No RCE-prone function calls detected.", "yellow")


if __name__ == "__main__":
    main()
