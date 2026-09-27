# File Integrity Monitor (FIM)

A lightweight Python-based **File Integrity Monitoring (FIM)** tool that detects unauthorized changes to files by creating a cryptographic baseline using **SHA-256 hashes** and comparing the baseline against the current state of a monitored directory.

The project is designed as a practical cybersecurity and digital forensics learning project demonstrating file integrity verification, cryptographic hashing, filesystem monitoring, change detection, and command-line automation.

---

## Overview

File Integrity Monitoring is a security mechanism used to detect changes to files and directories.

A file can be altered without its filename or location changing. Therefore, simply checking whether a file exists is not sufficient to determine whether its contents have been tampered with.

This project addresses that problem by generating a **SHA-256 cryptographic hash** for each monitored file.

For example:

```text
document.txt
     |
     v
SHA-256
     |
     v
3a7bd3e2360a3d29eea436fcfb7e44c7...
```

The resulting hashes are stored in a baseline database.

During a subsequent integrity check, the program:

1. Recursively scans the monitored directory.
2. Calculates the SHA-256 hash of each file.
3. Compares the current filesystem state with the saved baseline.
4. Identifies created, deleted, and modified files.
5. Reports detected integrity violations.

---

## Features

### SHA-256 File Hashing

The monitor calculates SHA-256 hashes for monitored files using Python's `hashlib` module.

SHA-256 is used because even a small modification to a file normally results in a significantly different digest.

For example:

```text
Original file
    |
    v
SHA-256
    |
    v
Original hash
```

After modification:

```text
Modified file
    |
    v
SHA-256
    |
    v
Different hash
```

The difference allows the monitor to detect content modifications.

---

### Memory-Efficient File Processing

Files are processed in **64 KiB chunks** rather than being loaded completely into memory.

The project defines:

```python
CHUNK_SIZE = 65536
```

This allows large files to be hashed without requiring the entire file to be loaded into RAM.

Conceptually:

```text
Large file
    |
    +--> 64 KB chunk --> SHA-256
    |
    +--> 64 KB chunk --> SHA-256
    |
    +--> 64 KB chunk --> SHA-256
    |
    +--> ...
    |
    v
Final SHA-256 digest
```

---

### Recursive Directory Scanning

The monitor uses `os.walk()` to recursively traverse the target directory and its subdirectories.

For example:

```text
test_dir/
├── document.txt
├── application.bin
└── config/
    ├── settings.conf
    └── database.conf
```

The monitor can scan files throughout the directory tree rather than only files located directly inside the target directory.

---

### Baseline Generation

The `--init` operation creates a snapshot of the current filesystem state.

The baseline records:

```text
File path -> SHA-256 hash
```

Example:

```json
{
    "/home/user/fim_project/test_dir/document.txt": "a8f5f167f44f4964e6c998dee827110c...",
    "/home/user/fim_project/test_dir/application.bin": "9f86d081884c7d659a2feaa0c55ad015..."
}
```

---

### Created File Detection

If a file exists during a subsequent scan but did not exist when the baseline was created, the program reports:

```text
[ALERT - CREATED] : /path/to/file
```

---

### Deleted File Detection

If a file existed when the baseline was created but no longer exists during the current scan, the program reports:

```text
[ALERT - DELETED] : /path/to/file
```

---

### Modified File Detection

If a file exists in both the baseline and current scan but its SHA-256 hash has changed, the program reports:

```text
[ALERT - MODIFIED] : /path/to/file
    Baseline Hash: ...
    Current  Hash: ...
```

This allows the investigator to see exactly which cryptographic value changed.

---

### Continuous Monitoring

The `--monitor` mode repeatedly performs integrity checks at a configurable interval.

Example:

```bash
python3 fim.py --monitor test_dir 10
```

This performs an integrity audit every 10 seconds until the program is stopped with:

```text
Ctrl+C
```

---

## Detection Model

The integrity comparison is based on three sets:

```text
Baseline files
       |
       |--------------------|
       |                    |
       v                    v
Current files          Current files
       |                    |
       v                    v
    CREATED              DELETED
```

More formally:

### Created Files

```text
created = current_paths - baseline_paths
```

These files exist now but were not present in the baseline.

### Deleted Files

```text
deleted = baseline_paths - current_paths
```

These files existed in the baseline but are no longer present.

### Existing Files

```text
common = baseline_paths & current_paths
```

These files exist in both states.

Their hashes are then compared to identify modifications:

```text
baseline[path] != current_state[path]
```

---

## Requirements

### Python

Python **3.10 or newer** is recommended.

The project uses modern Python type-hint syntax such as:

```python
str | None
dict[str, str]
```

which requires a modern Python version.

### Operating System

The project is primarily designed for Unix/Linux environments but uses Python's standard filesystem APIs and can be adapted to other operating systems.

### Dependencies

No third-party Python packages are required.

The project uses only Python standard-library modules:

```text
os
sys
json
time
hashlib
pathlib
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/file-integrity-monitor.git
```

Change into the project directory:

```bash
cd file-integrity-monitor
```

Verify Python:

```bash
python3 --version
```

---

## Usage

The program supports three primary modes:

```text
--init
--check
--monitor
```

---

## 1. Create a Baseline

First create a directory that you want to monitor.

Example:

```bash
mkdir test_dir
```

Create some test files:

```bash
echo "Initial payload" > test_dir/conf.txt
```

```bash
echo "Binary binary" > test_dir/app.bin
```

Generate the baseline:

```bash
python3 fim.py --init test_dir
```

Expected output:

```text
[*] Generating baseline snapshot for: test_dir
[+] Baseline saved to baseline.json (2 files tracked).
```

The resulting `baseline.json` contains the paths and SHA-256 hashes of the files present when the baseline was created.

---

## 2. Check File Integrity

After generating a baseline, run:

```bash
python3 fim.py --check test_dir
```

If nothing has changed:

```text
============================================================
 INTEGRITY AUDIT REPORT: 2026-09-27 16:00:00
============================================================
[+] System intact. No unauthorized file changes detected.
```

---

## 3. Test a Modified File

Modify an existing file:

```bash
echo "Hacked!" >> test_dir/conf.txt
```

Run the integrity check:

```bash
python3 fim.py --check test_dir
```

The monitor should report:

```text
[ALERT - MODIFIED] : /path/to/test_dir/conf.txt
    Baseline Hash: <original-hash>
    Current  Hash: <new-hash>
```

The file is classified as **MODIFIED** because its path existed in the original baseline but its SHA-256 digest changed.

---

## 4. Test a Created File

Create a new file after generating the baseline:

```bash
touch test_dir/malware.sh
```

Run:

```bash
python3 fim.py --check test_dir
```

The monitor reports:

```text
[ALERT - CREATED] : /path/to/test_dir/malware.sh
```

The file is classified as created because it was not present when the baseline was generated.

---

## 5. Test a Deleted File

Remove a file that existed in the baseline:

```bash
rm test_dir/app.bin
```

Run:

```bash
python3 fim.py --check test_dir
```

The monitor reports:

```text
[ALERT - DELETED] : /path/to/test_dir/app.bin
```

---

## 6. Continuous Monitoring

The monitoring mode continuously performs integrity checks.

```bash
python3 fim.py --monitor test_dir
```

The default interval is 10 seconds.

A custom interval can be specified:

```bash
python3 fim.py --monitor test_dir 5
```

This performs an integrity check every 5 seconds.

Stop continuous monitoring with:

```text
Ctrl+C
```

---

## Command Reference

| Command                                          | Purpose                                         |
| ------------------------------------------------ | ----------------------------------------------- |
| `python3 fim.py --init <directory>`              | Generate a SHA-256 baseline                     |
| `python3 fim.py --check <directory>`             | Perform one integrity audit                     |
| `python3 fim.py --monitor <directory>`           | Continuously monitor using a 10-second interval |
| `python3 fim.py --monitor <directory> <seconds>` | Continuously monitor using a custom interval    |

---

## Example Workflow

A typical investigation workflow looks like this:

```text
                    ┌─────────────────────┐
                    │  Target Directory   │
                    └──────────┬──────────┘
                               │
                               v
                    ┌─────────────────────┐
                    │ Generate Baseline   │
                    │     --init          │
                    └──────────┬──────────┘
                               │
                               v
                    ┌─────────────────────┐
                    │    baseline.json    │
                    │                     │
                    │ File -> SHA-256     │
                    └──────────┬──────────┘
                               │
                               v
                    ┌─────────────────────┐
                    │ Current File Scan   │
                    │     --check         │
                    └──────────┬──────────┘
                               │
                  ┌────────────┼────────────┐
                  │            │            │
                  v            v            v
             CREATED       DELETED      MODIFIED
```

---

## Project Architecture

The project is intentionally implemented as a single Python file to keep the codebase lightweight and easy to study.

### `calculate_sha256()`

Responsible for:

* Opening files in binary mode.
* Reading files in chunks.
* Updating the SHA-256 hash.
* Returning the hexadecimal digest.
* Handling inaccessible or deleted files gracefully.

---

### `scan_directory()`

Responsible for:

* Validating the target directory.
* Recursively traversing the directory.
* Calculating hashes for discovered files.
* Building the current filesystem state.

Returns a dictionary:

```python
{
    "file_path": "sha256_hash"
}
```

---

### `generate_baseline()`

Responsible for:

* Performing an initial directory scan.
* Saving the resulting file/hash mapping to `baseline.json`.

---

### `audit_integrity()`

Responsible for:

* Loading the baseline.
* Performing a new filesystem scan.
* Identifying created files.
* Identifying deleted files.
* Identifying modified files.
* Printing an integrity report.

---

### `continuous_monitor()`

Responsible for:

* Running integrity checks repeatedly.
* Waiting for the configured interval.
* Handling `Ctrl+C` gracefully.

---

## Security Concepts Demonstrated

This project demonstrates several important cybersecurity concepts.

### Cryptographic Hashing

SHA-256 is used to generate a deterministic digest from file contents.

A change to file contents produces a different digest, allowing content integrity to be checked.

### File Integrity Monitoring

The project demonstrates the fundamental workflow behind FIM systems:

```text
Baseline → Monitor → Compare → Detect → Report
```

### Change Detection

The monitor distinguishes between:

* Created files
* Deleted files
* Modified files
* Unchanged files

### Digital Forensics

File integrity verification is relevant to forensic investigations because investigators may need to determine whether files have changed between two points in time.

### Defensive Security

The tool can help identify unexpected filesystem changes that may warrant further investigation.

---

## Important Security Considerations

This project is an educational FIM implementation and should not be considered a production-grade host intrusion detection system.

### Protect the Baseline

The integrity of the baseline is critical.

If an attacker can modify both the monitored files and `baseline.json`, they could potentially alter the baseline to hide changes.

For production environments, the baseline should be stored in a protected location or on a separate trusted system.

### Baseline Authentication

This project stores hashes in a JSON file but does not cryptographically authenticate the baseline database itself.

A production implementation could introduce mechanisms such as:

* Digital signatures
* HMAC-based authentication
* Remote baseline storage
* Access-controlled databases
* Write-once or append-only storage
* Centralized security monitoring

### Real-Time Monitoring

The current `--monitor` implementation uses periodic polling.

It does not use operating-system-specific filesystem event mechanisms such as Linux `inotify`.

Consequently, there can be a delay between a filesystem change and its detection.

---

## Limitations

The current implementation has several intentional limitations:

* The baseline is stored as a local JSON file.
* The baseline itself is not cryptographically authenticated.
* Monitoring uses periodic polling.
* There is no centralized alerting system.
* There is no email/SMS/SIEM integration.
* There is no database backend.
* There is no user authentication or role-based access control.
* File metadata such as permissions and ownership is not currently included in the baseline.
* Symbolic-link handling is not designed as a hardened production feature.
* The program reports changes but does not automatically remediate them.

These limitations provide opportunities for future development.

---

## Future Improvements

Potential improvements include:

* [ ] Add `argparse`-based command-line parsing.
* [ ] Add configurable baseline locations.
* [ ] Add cryptographic authentication of the baseline.
* [ ] Add digital signatures for baseline verification.
* [ ] Add Linux `inotify` support for event-driven monitoring.
* [ ] Add file permission monitoring.
* [ ] Add ownership monitoring.
* [ ] Add file metadata monitoring.
* [ ] Add centralized logging.
* [ ] Add JSON/CSV audit report export.
* [ ] Add log rotation.
* [ ] Add email alerts.
* [ ] Add SIEM integration.
* [ ] Add configuration files.
* [ ] Add unit tests.
* [ ] Add automated testing with GitHub Actions.
* [ ] Add structured logging.
* [ ] Add an installation package.
* [ ] Add support for monitoring multiple directories.

---

## Project Learning Objectives

This project was developed to reinforce practical understanding of:

1. Python filesystem operations.
2. Cryptographic hashing.
3. SHA-256 integrity verification.
4. Directory traversal.
5. JSON serialization and deserialization.
6. Set-based comparison.
7. Command-line interfaces.
8. Exception handling.
9. Continuous monitoring.
10. Defensive cybersecurity concepts.
11. Digital forensics fundamentals.
12. Security-oriented software design.

---

## Example Detection Scenario

Suppose the baseline contains:

```text
conf.txt   -> SHA256_A
app.bin    -> SHA256_B
```

An attacker or unauthorized process subsequently:

```text
1. Modifies conf.txt
2. Deletes app.bin
3. Creates malware.sh
```

The next integrity check produces:

```text
[ALERT - CREATED]  : malware.sh

[ALERT - DELETED]  : app.bin

[ALERT - MODIFIED] : conf.txt
    Baseline Hash: SHA256_A
    Current  Hash: SHA256_C
```

The investigator can therefore establish that:

```text
conf.txt  → contents changed
app.bin   → disappeared
malware.sh → appeared
```

The FIM does not determine *why* a change occurred; it identifies the filesystem state difference so that further investigation can be performed.

---

## Repository Structure

```text
file-integrity-monitor/
│
├── fim.py
├── README.md
├── .gitignore
└── LICENSE
```

Generated runtime/testing files should not normally be committed:

```text
baseline.json
test_dir/
__pycache__/
```

---

## License

This project is intended for educational and cybersecurity learning purposes.

If a license is added to the repository, see the accompanying `LICENSE` file for the applicable terms.

---

## Disclaimer

This project is provided for educational and defensive cybersecurity purposes.

It is intended to demonstrate the fundamental concepts behind file integrity monitoring and should be tested only on systems and directories that you own or are authorized to monitor.

---

## Author

**Mason-021**

GitHub:

`https://github.com/Mason-021`

---

## Summary

The File Integrity Monitor demonstrates a fundamental defensive security workflow:

```text
             ┌──────────────────┐
             │ Filesystem State  │
             └────────┬─────────┘
                      │
                      v
             ┌──────────────────┐
             │   SHA-256 Hash   │
             └────────┬─────────┘
                      │
                      v
             ┌──────────────────┐
             │ Baseline Storage │
             └────────┬─────────┘
                      │
                      v
             ┌──────────────────┐
             │ Current Scan     │
             └────────┬─────────┘
                      │
                      v
             ┌──────────────────┐
             │ Compare Hashes   │
             └────────┬─────────┘
                      │
          ┌───────────┼───────────┐
          v           v           v
       CREATED     DELETED     MODIFIED
          │           │           │
          └───────────┼───────────┘
                      v
             ┌──────────────────┐
             │ Integrity Alert  │
             └──────────────────┘
```

The project provides a compact implementation of the core principles behind File Integrity Monitoring while leaving room for future enhancements toward a more production-oriented security monitoring system.

