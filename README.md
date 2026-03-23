# AD-Enum 

A lightweight Active Directory enumeration and credential spraying tool designed to streamline common enumeration workflows during penetration testing.

> This tool is hard-coded (not the best and has had many issues) and is primarily built for my practice and preparation for the **OSCP+** exam.
---

##  Features

- Anonymous enumeration (SMB, LDAP, RPC, FTP)
- Credential spraying across multiple services
- NTLM hash authentication support (Pass-the-Hash)
- Default multi-tool scan automation
- SMB brute-force mode
- Built-in output filtering for quick result identification
- Supports multiple targets (IP ranges like `192.168.1.10-20`)

---

## Requirements

Make sure the following tools are installed and available in your `$PATH`:

- `crackmapexec`
- `smbmap`
- `rpcclient`
- `ldapsearch`
- `impacket-wmiexec`
- `impacket-psexec`

---

## Usage

```bash
python3 ad-enum.py -i <target-ip> [options]
```

---

## Options

| Option | Description |
|------|-------------|
| `-i, --ip` | Target IP address (required) |
| `-u, --user` | Username |
| `-p, --password` | Password |
| `-H, --hash` | NTLM hash |
| `--no-creds` | Use anonymous / null authentication |
| `--scan` | Run default enumeration scan |
| `--brute-smb` | Perform SMB brute-force |
| `service` | Target specific service (optional) |

---

##  Examples

### Anonymous/guest Credentials spraying
```bash
python3 ad-enum.py -i 10.10.10.10 --no-creds
```

### Default Scan (no creds)
```bash
python3 ad-enum.py -i 10.10.10.10 --scan
```

### Authenticated Scan
```bash
python3 ad-enum.py -i 10.10.10.10 -u user -p password123 --scan
```

### Test Credentials Across All Services
```bash
python3 ad-enum.py -i 10.10.10.10 -u administrator -p password123
```

### Pass-the-Hash
```bash
python3 ad-enum.py -i 10.10.10.10 -u administrator -H <ntlm_hash>
```

### SMB Brute-force
```bash
python3 ad-enum.py -i 10.10.10.10 -u users.txt -p passwords.txt --brute-smb
```

---

## Supported Services

- SMB
- LDAP
- FTP
- SSH
- RPC
- WinRM
- RDP
- MSSQL
- WMI
- PsExec

---


## Disclaimer

This tool is intended **only for legal penetration testing environments**, labs, and certification practice (e.g., OSCP).  
Do **not** use it against systems without proper authorization.

---



## 👤 Author

Created as part of personal preparation for OSCP and hands-on AD exploitation practice.
