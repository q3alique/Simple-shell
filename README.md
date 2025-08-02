# Simple-Shell Script

This utility generates reverse-shell command strings for multiple platforms and languages. It’s intended for authorized security testing, training in controlled labs, and research on systems you own or are permitted to test.

>Legal & Ethical Notice
Use only on systems where you have explicit permission. You are responsible for complying with all applicable laws and policies.

## Description

The reverse shell generator provides support for a wide variety of shells, including Bash, Python (both Linux and Windows versions), Perl, PHP (Linux and Windows versions), Java, Go, R, AWK, and PowerShell.
It allows users to easily generate a reverse shell payload for their target platform, with various levels of obfuscation available for PowerShell payloads.

The script supports PowerShell payloads with optional Base64 encoding and multiple obfuscation levels to bypass detection and security restrictions.

### Features:
- Generates reverse-shell payload strings for Linux/Unix and Windows targets.
- Multiple languages and tools supported (Bash, Python, PHP, Perl, Java, AWK, Go, R, PowerShell).
- PowerShell variants include Base64-encoded output for compatibility and transport safety.
- `--list-shells` option prints all available types with brief descriptions.

## Installation

Clone this repository and install the required dependencies:
```bash
git clone https://github.com/q3alique/simple-shell.git
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

- **bash**: Bash reverse shell using TCP sockets and file descriptors (Linux/Unix).
- **python-linux**: Python reverse shell for Linux using the socket and subprocess modules.
- **python-windows**: Python reverse shell for Windows using socket and subprocess with full stdin/stdout redirection.
- **php-linux**: PHP reverse shell for Linux using fsockopen and /bin/sh.
- **php-windows**: PHP reverse shell for Windows using fsockopen and proc_open with cmd.exe.
- **perl**: Perl reverse shell leveraging low-level socket functions to execute /bin/sh.
- **java**: Java reverse shell spawning a bash process through Runtime.exec (must be embedded in a Java class).
- **awk**: Awk reverse shell using TCP socket and interactive loop to execute commands.
- **go**: Go reverse shell — Uses Golang to compile and run a reverse shell. Requires Go to be installed on the target system. Useful for quickly creating executable reverse shells.
- **r**: R reverse shell executing bash through a system() call (Linux).
- **powershell1**: Classic PowerShell reverse shell using New-Object and GetStream to establish a TCP connection.
- **powershell2**: Compact version of PowerShell reverse shell with shorter syntax but same functionality.
- **powershell3**: PowerShell reverse shell encoded in Base64 (UTF-16LE) to bypass command-line detection.
- **powershell-obf**: PowerShell reverse shell with randomized variables + Base64 encoding to evade detection.
- **powershell-obf2**: Heavily obfuscated PowerShell reverse shell using charcode array and decoding at runtime, then Base64 encoded for stealth.

## Troubleshooting
- **Nothing returns / connection refused**: Confirm your listener (e.g., nc -lvnp <port>) is running and reachable from the target, and that host firewalls allow outbound traffic to the listener.
- **PowerShell errors about policy**: Run in an approved test environment and use proper administrative/organizational procedures.
- **Copy/paste issues**: Encoded variants help avoid newline/quoting problems. Prefer the Base64 options (powershell3, powershell-obf, powershell-obf2) when transporting via terminals or scripts that mangle characters.
