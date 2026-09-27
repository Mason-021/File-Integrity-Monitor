#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Baselines directory states using SHA-256 and monitors for changes.
"""

# os: provides a portable way of using operating system-dependent functionality.
# purpose: used for filesystem interactions like directory traversal  -  (os.walk)
# file path joining (os.path.join), and chcking file existence (os.path.exists)
import os

# sys: system-specific parameters and functions.
# purpose: provides access to command-line arguments (sys.argv), standard error stream output (sys.stderr),
# and clean script termination mechanisms (sys.exit)
import sys

# json: python interface for reading and writing JSON
# PURPOSE: used to serialize (dump) python dictionary data into a persistent file on disk
# and deserialize (load) the JSON baseline file back into memory.
import json

# time: provides various time-related functions.
# purpose: used to generate human-readable timestamps for audit logs via time, strftime
# and to pause execution loops using time.sleep.
import time

# hashlib: implements a common interface to many different secure hash and digest algorithm
# purpose: core cryptographic utility used to compute the SHA-256 cryptographic checksums (hashes)
# of file contents to verify integrity
import hashlib

# path: object-oriented filesystem path manipulation utility from pathlib
# purpose: used to handle file path validation and resolve relative path strings into fully 
# qualified, absolute system path objects ( .resolve())
from pathlib import Path

## GLOBAL CONSTANT
# CHUNK_SIZE: defiens buffer size (64 KiB) for reading files in binary blocks.
# purpose: to prevent system exhaustion that may be caused by reading large files entirey inside RAM.
CHUNK_SIZE = 65536 # FOR efficient memory streaming

## CORE UTILITY FUNCTIONS

def calculate_sha256(filepath: str) -> str | None:
    """
    calculates the SHA-256 digest f a file in binary chunks to prevent RAM exhaustion.
    - hashlib.sha256()   : instructs a new SHA-256 hashing context.
    - open(..., "rb")    : opens file in binary read mode ('rb') to ensure raw byte array are read without
    text decoding or line-ending conversions.
    - iter(callable, sentinel) : continously calls 'lambda: f.read(CHUNK_SIZE)' untill it returns
    'b""' (empty byte object signifying End-Of-File)
    - hasher.update(chunk): streams byte chunks sequentially into the hash object.
    - hasher.hexdigest(): calculats final hash digest as a hexadecimal string.
    - try/except block : gracefully handles PermissionError (e.g., restricted system files)
      and FileNotFoundError (e.g. broken symlinks or deleted files during scan),
      writing warnings to sys.stderr rather than crashing.
    """
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError) as err:
        print(f"[!] Warning: Cannot read {filepath}: {err}", files=sys.stderr)
        return None

def scan_directory(target_dir: str) -> dict[str, str]:
    """
    Recursively walks target_dir and returns a dict mapping file path to SHA-256 hash.
    - path(target_dir).resolve():  converts string path to an absolute path object,
    resolving symlinks, relative references(..), and current working dir paths.
    - target_path.exists() && is_dir(): guards against invalid target directories.
    - sys.exit(1): aborts execution with error exit code 1 ifdirectory is invalid.
    - os.walk(target_path): generates file and directory names in a directory tree by walking
    top-down recursively. returns tuples of (root, dirs, files).
    - os.path.join(root, file): constructs valid OS-specific absolute file path.
    - "baseline.json" check: excludes the baseline databasefile itself to avoid false 
    positives when storing the baseline inside the target directory being monitored.
    - Dict accumulation (file_map): maps absolute file paths to cryptographic hashes
    """
    file_map = {}
    target_path = Path(target_dir).resolve()

    if not target_path.exists() or not target_path.is_dir():
        print(f"[!] Error: Target directory {target_dir} does not exists or is not a directory.")
        sys.exit(1)
    for root, _, files in os.walk(target_path):
        for file in files:
            full_path = os.path.join(root, file)

            # skip baseline storage file itself if stored in target_dir
            if file == "baseline.json":
                continue
            file_hash = calculate_sha256(full_path)

            if file_hash:
                file_map[full_path] = file_hash

    return file_map 

def generate_baseline(target_dir: str, db_path: str = "baseline.json") -> None:
    """
    scans the target diectory and saves the current state to a JSON baseline file.
    - scan_directory(): acquires current file system state (paths an SHA-256 hashes).
    - open(db_path, "w", encoding="utf-8"): opens JSON destination file writing.
    json.dump(..., indent=4): serializes python dictionary to JSON formatting on disk
    with 4-space indentation for human readability.
    """
    print(f"[*] Generating baseline snapshot for: {target_dir}")
    baseline_data = scan_directory(target_dir)

    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=4)

    print(f"[+] Baseline saved to {db_path} ({len(baseline_data)} files tracked).")

# -> None: explicitly tellls devs and static analysis tools that the function does not explicitly retrna value.
def audit_integrity(target_dir: str, db_path: str = "baseline.json") -> None:
    """
    compares current state against saved baseline and reports anomalies.
    - os.path.exists(db_path): verifies that baseline file exists before attempting audit.
    json.load(f): parses JSON file into a python dictionary containing known good baseline state.
    - scan_directory(): obtains real-time snapshot of target filesystem.
    - set operations (set logic for high performance delta analysis):
        - created = current_paths - baseline_paths (Elements in current but not in baseline)
        - deleted = baseline_paths - current_paths (elements in baseline but missing from current).
        - common = baseline+paths & current_paths (elements present in both states).
    - list comprehension for modified files : Iterates through 'common' elements and compares
    SHA-256 strings between baseline dict and current state dict.
    - time.strftime('%Y-%m-%d %H:%M:%S'): Formats current system time into ISO format.
    """
    if not os.path.exists(db_path):
        print(f"[!] Baseline file '{db_path}' not found. Run baseline mode first.")
        sys.exit()

    with open(db_path, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    current_state = scan_directory(target_dir)

    # set(...): converts the list of file paths into python sets. lookups and comparisons in sets
    # run in 0(1) constant time, making comparsons 000's time FASTER than comparing lists.
    baseline_paths = set(baseline.keys())
    current_paths = set(current_state.keys())

    created = current_paths - baseline_paths
    deleted = baseline_paths - current_paths

    # &: compares both sets and returns a set containingONLY the paths present in both
    # baseline_paths AND current_paths.
    common = baseline_paths & current_paths

    modified = [path for path in common if baseline[path] != current_state[path]]

    print(f"\n" + "=" * 60)
    print(f" INTEGRITY AUDIT REPORT: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    if not (created or deleted or modified):
        print("[+] System Intact. No unauthorized file changes detected.")
        return

    for path in created:
        print(f"[ALERT - CREATED]  :  {path}")

    for path in deleted:
        print(f"[ALERT - DELETED]  :  {path}")

    for path in modified:
        print(f"[ALERT - MODIFIED] : {path}")
        print(f"    Baseline Hash: {baseline[path]}")
        print(f"    Current  Hash: {current_state[path]}")


def continuous_monitor(target_dir: str, db_path: str = "baseline.json", interval: int = 10) -> None:
    """
    continuously runs the integrity chec at periodic intervals
    - while True loop: Infinite execution loop turning the script into a polling deamon.
    - audit_integrity(): Invokes execution audit routine on each cycle.
    - time.sleep(interval): Pauses execution thread for specified seconds to reduce CPU overhead.
    - try / except KeyboardInterrupt: Intercepts SIGINT signals (e.g pressing Ctrl + C in terminal)
      to exit cleanly without printing raw stack traces.
    """

    print(f"[*] Starting continuous FIM daemon (Interval: {interval}s). Press Ctrl + C to stop.")
    try:
        while True:
            audit_integrity(target_dir, db_path)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] FIM daemon stopped.")


# ==============================
# MAIN ENTRY POINT & CLI PARSING
#===============================

if __name__ == "__main__":
    """
    Main Script Entry Guard ('if __name__ == '__main__':')
    Ensures this block runs only when executed directly, now when imported as a module.

    - sys.argv: list containing command-line arguments. 'sys.argv[0]' is script name,
    'sys.argv[1]' is operation flag, 'sys.argv[2]' is target path, 'sys.argv[3]' is
    optional interval.

    - command parsing logic:
        - '--init': Triggers 'generate_baseline()' to snapshot system state.
        - '--check': Triggers 'audit_integrity()' for a single pass scan.
        -'--monitor': Triggers 'continuous_monitor()' loop with optional timing delay.
    """
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 fim.py --init <directory>")
        print("  python3 fim.py --check <directory>")
        print("  python3 fim.py --monitor <directory> [interval_sec]")
        sys.exit()

    mode = sys.argv[1]
    directory = sys.argv[2]

    if mode == "--init":
        generate_baseline(directory)
    elif mode == "--check":
        audit_integrity(directory)
    elif mode == "--monitor":
        sec = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        continuous_monitor(directory, "baseline.json", sec)
    else:
        print(f"[!] Unknown mode: {mode}")

    # sys.argv is a list of command-line arguments passed to the script.
    # sys.argv[0] = script name 
    # sys.argv[1] = mode flag
    # sys.argv[2] = target directory
    # sys.argv[3] = optional monitoring interval in seconds
    # sec(...) checks if the user provided the 3rd argument - len(sys.argv) > 3 .
    # if Yes, it converts that argument from a string to an integer - int(...)
    # if no argument was provided, it defaults sec to 10 seconds.