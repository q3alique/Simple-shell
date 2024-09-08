# Simple-Shell Script

This script generates reverse shell commands for multiple programming languages, making it easier to quickly create reverse shells for penetration testing or exploit development.

## Description

The reverse shell generator provides support for a wide variety of shells, including Bash, Python (both Linux and Windows versions), Perl, PHP (Linux and Windows versions), Java, and PowerShell. It allows users to easily generate a reverse shell payload for their target platform.

The script supports PowerShell payloads with optional Base64 encoding for bypassing security restrictions on certain systems.

### Features:
- Generates reverse shell commands for various platforms.
- Supports PowerShell reverse shells with Base64 encoding for obfuscation.
- Lists available shell types with descriptions to aid in selecting the most suitable option.

## Installation

Clone this repository and install the required dependencies:
```bash
git clone https://github.com/your-repo/simple-shell.git
cd simple-shell
```

Ensure Python is installed on your system.

## Usage

Run the script with the required options:
```bash
python simple-shell.py --ip <IP_ADDRESS> --port <PORT> --type <SHELL_TYPE>
```

### Options:
- `--ip`: Specify the IP address of the listener (required).
- `--port`: Specify the port of the listener (required).
- `--type`: Choose the type of reverse shell to generate (required). The available types are listed below.
- `--list-shells`: List available shell types with descriptions.

### Example:
```bash
python simple-shell.py --ip 192.168.1.87 --port 4444 --type bash
```

### Listing Shell Types:
To see a list of available shell types and their descriptions:
```bash
python simple-shell.py --list-shells
```

## Supported Shell Types and Descriptions:

- **Bash**: Uses Bash's built-in features to create a reverse shell. Commonly used on Linux systems.
- **Python (Linux)**: Leverages Python's socket and subprocess libraries to establish a reverse shell on Unix-based systems.
- **Python (Windows)**: Uses Python to interact with `cmd.exe` for reverse shell functionality on Windows systems.
- **Perl**: A lightweight reverse shell option using Perl, often found on Unix-based systems.
- **PHP (Linux)**: Uses PHP's `fsockopen()` to create a reverse shell. Commonly used for web-based exploits on Linux servers.
- **PHP (Windows)**: A PHP-based reverse shell for Windows that spawns `cmd.exe`.
- **Java**: Uses Java's `Runtime` and `Process` APIs to open a reverse shell. Requires Java to be installed on the target system.
- **AWK**: A minimalist reverse shell for Unix-based systems using AWK.
- **Go**: Creates and runs a Go program that establishes a reverse shell. Useful for systems with Go installed.
- **R**: Utilizes R's `socketConnection()` to open a reverse shell. Suitable for data science environments.
- **PowerShell 1**: A standard PowerShell reverse shell that communicates over TCP using PowerShell's `TCPClient`.
- **PowerShell 2**: Similar to PowerShell 1 but with more controlled input/output handling via `StreamWriter`.
- **PowerShell 3**: A PowerShell reverse shell with a Base64-encoded payload, commonly used for bypassing security restrictions.
- **PowerShell 4**: A lightweight PowerShell reverse shell with a minimal encoded payload.


