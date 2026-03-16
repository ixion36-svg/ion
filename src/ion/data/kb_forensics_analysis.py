"""Built-in KB data: Digital Forensics — Disk, Memory & Malware Analysis."""

# ============================================================
# COLLECTION 1: DISK & FILE SYSTEM FORENSICS
# ============================================================

DISK_FORENSICS = [
    {
        "title": "NTFS Fundamentals — MFT, Alternate Data Streams & Timestamps",
        "tags": ["ntfs", "mft", "ads", "timestamps", "disk-forensics", "windows"],
        "content": r"""# NTFS Fundamentals — MFT, Alternate Data Streams & Timestamps

## Overview

The NT File System (NTFS) is the default file system for modern Windows operating systems and one of the most frequently examined file systems in digital forensics. Understanding NTFS internals — particularly the Master File Table, Alternate Data Streams, and the four NTFS timestamps — is foundational for any disk forensics investigation.

## The Master File Table (MFT)

The MFT is the central metadata structure of NTFS. Every file and directory on an NTFS volume has at least one entry (record) in the MFT, including the MFT itself (`$MFT`, record 0).

**Key MFT attributes:**

| Attribute Type | Name | Purpose |
|---|---|---|
| 0x10 | `$STANDARD_INFORMATION` | Timestamps, permissions, flags |
| 0x30 | `$FILE_NAME` | File name, parent reference, timestamps |
| 0x40 | `$OBJECT_ID` | Unique object identifier |
| 0x80 | `$DATA` | File content (resident or non-resident) |
| 0x90 | `$INDEX_ROOT` | Directory index B-tree root |
| 0xA0 | `$INDEX_ALLOCATION` | Directory index allocation |
| 0xB0 | `$BITMAP` | Allocation bitmap for indexes |

**Resident vs. non-resident data:** Files smaller than approximately 700 bytes can be stored directly within the MFT record itself (resident). Larger files are stored in clusters on disk, with the MFT entry pointing to data runs.

## NTFS Timestamps (MACE)

NTFS stores four timestamps in both `$STANDARD_INFORMATION` (SI) and `$FILE_NAME` (FN) attributes:

- **M** — Modified: last time file content was changed
- **A** — Accessed: last time file was read
- **C** — Changed (MFT): last time the MFT entry was modified
- **E** — Entry Created (Birth): when the file was first created

**Forensic significance:** The SI timestamps are easily modifiable by user-mode programs (timestomping). The FN timestamps are updated only by the kernel and are much harder to manipulate. Discrepancies between SI and FN timestamps are strong indicators of anti-forensic activity.

```
# Detecting timestomping: compare $SI and $FN timestamps
# If $SI Created is earlier than $FN Created, timestomping is likely
analyzeMFT.py -f $MFT -o mft_analysis.csv
# Look for entries where SI_Created < FN_Created
```

## Alternate Data Streams (ADS)

ADS allow multiple data streams to be associated with a single file. The default (unnamed) stream holds the visible file content. Named streams are hidden from standard directory listings.

**Forensic relevance:** Attackers use ADS to hide payloads, scripts, or exfiltrated data within legitimate-looking files. The Zone.Identifier ADS is automatically created by browsers and email clients, recording the origin URL of downloaded files.

```powershell
# List all ADS on a file
Get-Item -Path C:\suspect.txt -Stream *

# Extract the Zone.Identifier stream
Get-Content -Path C:\suspect.txt -Stream Zone.Identifier
# Output: [ZoneTransfer] ZoneId=3 ReferrerUrl=https://...

# Search for ADS recursively
gci -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } |
    Where-Object Stream -ne ':$DATA'
```

## Analyst Checklist

1. Extract and parse `$MFT` with tools like `analyzeMFT` or `MFTECmd`
2. Compare `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps for all suspicious files
3. Check for Alternate Data Streams, especially on files in user-writable directories
4. Review the Zone.Identifier ADS on downloaded files to establish provenance
5. Correlate MFT sequence numbers with `$UsnJrnl` entries for a complete timeline
""",
    },
    {
        "title": "Ext4 Forensics — Inodes, Journals & Deleted File Recovery",
        "tags": ["ext4", "linux", "inodes", "journal", "disk-forensics", "file-recovery"],
        "content": r"""# Ext4 Forensics — Inodes, Journals & Deleted File Recovery

## Overview

Ext4 (Fourth Extended File System) is the default file system for most Linux distributions. Forensic analysis of ext4 volumes requires understanding its inode-based architecture, journaling mechanisms, and the artifacts that persist after file deletion.

## Ext4 Architecture

**Superblock:** The superblock contains metadata about the file system including block size, total blocks, inode count, mount counts, and timestamps. Backup copies exist at predictable block group boundaries.

**Inodes:** Each file and directory has an inode storing metadata but not the file name. The inode contains:

- File type and permissions
- Owner UID and GID
- File size
- Timestamps: atime, ctime, mtime, crtime (creation time, ext4 only)
- Pointers to data blocks (direct, indirect, or extents)

**Extents:** Ext4 replaced the traditional indirect block pointer scheme with extents — contiguous ranges of blocks described by a starting block number and length — improving performance and reducing metadata overhead.

## Key Forensic Artifacts

**Deleted file recovery:** When a file is deleted on ext4, the directory entry is removed and the inode is marked as unused, but the data blocks may not be immediately overwritten. The inode's deletion timestamp is recorded.

```bash
# Use extundelete for file recovery
extundelete /dev/sda1 --restore-all --after $(date -d '2026-03-01' +%s)

# Use icat from Sleuth Kit to extract file content by inode number
icat -o 2048 disk.img 12345 > recovered_file.bin

# List deleted entries from a directory inode
fls -d -r /dev/sda1
```

**Journal analysis:** Ext4's journal (`/dev/sda1:.journal` or external) records metadata changes before committing them to the main file system. Older journal transactions may contain previous versions of inodes, directory entries, and indirect blocks.

```bash
# Dump the journal
jls disk.img
jcat disk.img <journal_block>

# Use Sleuth Kit for timeline
fls -r -m "/" disk.img > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv
```

## Timestamps in Ext4

Ext4 stores timestamps with nanosecond precision (unlike ext3's one-second precision). The four timestamps are:

| Timestamp | Description | Updated When |
|---|---|---|
| atime | Access time | File read (mount option dependent) |
| mtime | Modification time | File content changed |
| ctime | Change time | Inode metadata changed |
| crtime | Creation time | File first created (ext4 only) |

**Mount options affecting timestamps:** The `relatime` mount option (default since Linux 2.6.30) only updates atime if it is older than mtime or ctime, reducing disk I/O. The `noatime` option disables atime updates entirely.

## Analyst Checklist

1. Image the volume with write-blocking before any analysis
2. Parse the superblock to identify file system parameters and mount history
3. Build a timeline using `fls` and `mactime` from The Sleuth Kit
4. Check the journal for residual inode data from deleted or modified files
5. Attempt recovery of deleted files using `extundelete` or `photorec`
6. Compare crtime (creation) against other timestamps for anomaly detection
""",
    },
    {
        "title": "Disk Imaging — Forensic Acquisition with FTK Imager, dd & EWFACQUIRE",
        "tags": ["disk-imaging", "ftk-imager", "dd", "ewf", "evidence-acquisition", "chain-of-custody"],
        "content": r"""# Disk Imaging — Forensic Acquisition with FTK Imager, dd & EWFACQUIRE

## Overview

Forensic disk imaging is the process of creating a bit-for-bit copy of a storage device in a manner that preserves data integrity and maintains the chain of custody. A forensically sound image must be verifiable (hash-validated), repeatable, and created without modifying the source media.

## Write Blocking

Before any acquisition, the source media must be protected from modification using a hardware or software write blocker.

**Hardware write blockers** (Tableau, CRU WiebeTech) physically intercept write commands at the interface level. They are considered the gold standard for court-admissible evidence.

**Software write blockers** alter the OS driver stack to prevent write operations. On Linux, mounting with `mount -o ro,noload` prevents journal replay. On Windows, registry-based write blocking can be applied but is less reliable than hardware solutions.

## Acquisition Methods

### dd / dc3dd

The `dd` utility creates a raw (bit-for-bit) image. `dc3dd` is a forensics-enhanced version with built-in hashing, logging, and progress reporting.

```bash
# Basic dd acquisition with hashing
dd if=/dev/sda of=/evidence/case001.raw bs=4M status=progress
md5sum /dev/sda > /evidence/case001.md5
sha256sum /dev/sda >> /evidence/case001.sha256

# dc3dd with built-in verification
dc3dd if=/dev/sda of=/evidence/case001.raw hash=sha256 log=/evidence/case001.log
```

### FTK Imager

FTK Imager (AccessData/Exterro) is a widely used GUI tool that supports multiple output formats:

- **E01 (EnCase/EWF):** Compressed, segmented, with embedded case metadata and hash verification
- **Raw (dd):** Uncompressed bit-for-bit copy
- **AFF4:** Advanced Forensic Format with metadata and compression support

FTK Imager can also perform logical acquisitions, capturing specific files or directories rather than full disk images.

### ewfacquire (libewf)

```bash
# Create an E01 image with compression and case metadata
ewfacquire /dev/sda -t /evidence/case001 -c fast -C "Case 2026-001" \
    -D "Suspect workstation HDD" -e "Analyst: J.Smith" -N "Evidence Item 1"
```

## Verification & Documentation

**Hash verification** must be performed immediately after acquisition and documented:

```bash
# Verify the image matches the source
ewfverify /evidence/case001.E01
# Or for raw images
sha256sum /evidence/case001.raw
# Compare against the source hash
```

**Chain of custody documentation** should record: date/time of acquisition, analyst name, tool and version used, source device serial number, hash values (MD5 + SHA-256 minimum), and any anomalies encountered during imaging.

## Analyst Checklist

1. Document the source device (make, model, serial, capacity) before acquisition
2. Apply write blocking (hardware preferred) and verify it is functioning
3. Acquire using an appropriate format (E01 for long-term storage, raw for tool compatibility)
4. Compute and record both MD5 and SHA-256 hashes at acquisition time
5. Verify the image hash matches the source hash
6. Store the image on a separate, secure evidence drive with access controls
7. Complete chain of custody paperwork with all acquisition details
""",
    },
    {
        "title": "Evidence Preservation & Chain of Custody Best Practices",
        "tags": ["evidence-preservation", "chain-of-custody", "legal", "disk-forensics", "best-practices"],
        "content": r"""# Evidence Preservation & Chain of Custody Best Practices

## Overview

Digital evidence must be collected, preserved, and documented with the same rigor as physical evidence. Failure to maintain a proper chain of custody or to preserve evidence integrity can render forensic findings inadmissible in legal proceedings and undermine the credibility of an investigation.

## Principles of Digital Evidence Handling

The Association of Chief Police Officers (ACPO) guidelines and NIST SP 800-86 establish core principles:

1. **No action should change data on a device** that may subsequently be relied upon in court
2. **Competent persons** must carry out all work — the analyst must be able to explain their methods
3. **An audit trail** must exist so an independent third party can reproduce the results
4. **The person in charge** of the investigation is responsible for ensuring these principles are adhered to

## Chain of Custody Documentation

A chain of custody form must accompany every piece of evidence and record every transfer, access, and action:

| Field | Description |
|---|---|
| Case number | Unique investigation identifier |
| Evidence item number | Sequential item identifier |
| Description | Device type, make, model, serial number |
| Date/time collected | When the evidence was seized or received |
| Collected by | Name, title, organization |
| Location collected from | Physical location or network address |
| Hash values | MD5 and SHA-256 of original media |
| Storage location | Secure evidence locker/room identifier |
| Transfer log | Date, time, from, to, purpose for each transfer |

## Volatile Data Collection Order

When responding to a live incident, collect evidence in order of volatility (most volatile first):

1. **Registers and cache** — CPU state (rarely captured manually)
2. **Memory (RAM)** — Running processes, network connections, encryption keys
3. **Network state** — Active connections, routing tables, ARP cache
4. **Running processes** — Process list, open files, loaded modules
5. **Disk** — File system, swap space, temporary files
6. **Remote logging** — Syslog servers, SIEM, cloud audit logs
7. **Physical configuration** — Network topology, hardware inventory
8. **Archival media** — Backups, optical media, offline storage

## Secure Storage Requirements

- Evidence storage must be in a physically secured location with access controls
- Digital evidence should be stored on encrypted, dedicated evidence drives
- Environmental controls should protect against heat, humidity, and electromagnetic interference
- Multiple verified copies should be maintained in separate locations
- Original media should be preserved unaltered; all analysis performed on forensic copies

## Legal Considerations

- Obtain proper authorization (warrant, consent, or corporate policy) before acquisition
- Document the legal authority under which evidence was collected
- Understand jurisdictional requirements — rules vary between countries and even states
- Preserve potentially exculpatory evidence alongside incriminating evidence
- Be prepared to testify about your methods, tools, and findings

## Analyst Checklist

1. Verify legal authority exists before touching any device
2. Photograph the scene and document all connected devices and cables
3. Record device details (serial numbers, asset tags, physical condition)
4. Collect volatile data before powering down, when safe to do so
5. Apply write blocking and create forensic images with hash verification
6. Complete chain of custody forms at every step
7. Store originals securely and work only on verified forensic copies
""",
    },
    {
        "title": "File Carving — Recovering Files from Unallocated Space",
        "tags": ["file-carving", "data-recovery", "unallocated-space", "scalpel", "photorec", "disk-forensics"],
        "content": r"""# File Carving — Recovering Files from Unallocated Space

## Overview

File carving is the process of recovering files from disk images or raw data without relying on file system metadata. When files are deleted, the file system marks the space as available but rarely overwrites the data immediately. Carving tools search through raw bytes for file signatures (headers and footers) to reconstruct files, even when the file system is damaged or reformatted.

## How File Carving Works

Carving operates on the principle that most file formats have identifiable signatures:

| File Type | Header (Hex) | Footer (Hex) |
|---|---|---|
| JPEG | `FF D8 FF E0` or `FF D8 FF E1` | `FF D9` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` |
| PDF | `25 50 44 46` (`%PDF`) | `25 25 45 4F 46` (`%%EOF`) |
| ZIP/DOCX | `50 4B 03 04` | `50 4B 05 06` |
| PE/EXE | `4D 5A` (`MZ`) | — (size from header) |
| SQLite | `53 51 4C 69 74 65` | — |

**Header-footer carving** searches for a known header signature and then scans forward for the corresponding footer. This works well for formats with clear delimiters (JPEG, PDF).

**Header-size carving** reads the file size from internal metadata (PE headers, ZIP central directory) to determine the extent of the file without needing a footer.

**Fragment recovery** is the most challenging scenario. When a file is fragmented across non-contiguous clusters, simple carving will produce a corrupt result. Advanced tools use content-aware techniques (validating internal structure) to detect and reassemble fragments.

## Carving Tools

### Scalpel

Scalpel is a high-performance carver configured via a rules file:

```bash
# Configure carving rules
# Edit /etc/scalpel/scalpel.conf to enable desired file types

# Run carving against a disk image
scalpel -c /etc/scalpel/scalpel.conf -o /evidence/carved/ disk_image.raw
```

### PhotoRec

PhotoRec uses file format-aware parsing to recover files with high accuracy:

```bash
# Run PhotoRec against a disk image (interactive mode)
photorec disk_image.raw

# Or use the command-line interface
photorec /cmd disk_image.raw fileopt,jpg,enable,pdf,enable search
```

### bulk_extractor

`bulk_extractor` is not a traditional carver but extracts structured data (email addresses, URLs, credit card numbers, EXIF data) from raw disk images:

```bash
bulk_extractor -o /evidence/bulk_output/ disk_image.raw
# Produces histogram files and feature files for analysis
```

## Challenges and Limitations

- **Fragmentation** can produce corrupt carved files — validate recovered files before relying on them
- **Overwritten data** is unrecoverable — if new data has been written to the same sectors, the original content is gone
- **Encryption** prevents carving — encrypted volumes yield only random-looking data
- **Embedded files** (e.g., images inside Office documents) may be carved as standalone files, losing context
- **False positives** are common — header signatures can appear in unrelated data

## Analyst Checklist

1. Always carve from a forensic image, never the original media
2. Configure carving rules for file types relevant to the investigation
3. Validate recovered files (open them, check internal structure, verify hashes)
4. Cross-reference carved files with file system metadata when available
5. Document the carving tool, version, and configuration used
6. Be aware that carved files may lack original file names and directory context
""",
    },
    {
        "title": "Windows Registry Forensics — SAM, SYSTEM & SOFTWARE Hives",
        "tags": ["registry", "windows", "sam", "system", "software", "disk-forensics", "artifacts"],
        "content": r"""# Windows Registry Forensics — SAM, SYSTEM & SOFTWARE Hives

## Overview

The Windows Registry is a hierarchical database storing OS configuration, user settings, application data, and hardware information. For forensic analysts, the registry is one of the richest sources of evidence, containing user activity traces, program execution artifacts, USB device history, network connections, and much more.

## Registry Hive Locations

| Hive | Path | Key Contents |
|---|---|---|
| SAM | `C:\Windows\System32\config\SAM` | Local user accounts and password hashes |
| SYSTEM | `C:\Windows\System32\config\SYSTEM` | Hardware config, services, boot settings |
| SOFTWARE | `C:\Windows\System32\config\SOFTWARE` | Installed programs, OS settings |
| SECURITY | `C:\Windows\System32\config\SECURITY` | Security policies, LSA secrets |
| NTUSER.DAT | `C:\Users\<user>\NTUSER.DAT` | Per-user settings, MRU lists |
| UsrClass.dat | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shellbags, COM objects |

## SAM Hive — User Account Forensics

The SAM hive contains local user account information:

- **Account names, SIDs, and creation dates**
- **Login counts and last login timestamps**
- **Password policy settings**
- **Account lockout and disabled status**
- **Group memberships** (Administrators, Remote Desktop Users, etc.)

```
# Parse SAM hive with RegRipper
rip.pl -r SAM -p samparse

# Extract account data with Eric Zimmerman's tools
RECmd.exe --bn SAMBatch -f SAM --csv output/
```

## SYSTEM Hive — System Configuration

Key forensic artifacts in the SYSTEM hive:

- **ComputerName:** `SYSTEM\ControlSet001\Control\ComputerName\ComputerName`
- **TimeZone:** `SYSTEM\ControlSet001\Control\TimeZoneInformation`
- **Network interfaces:** `SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces`
- **USB device history:** `SYSTEM\ControlSet001\Enum\USBSTOR` — records vendor, product, serial, first/last connected times
- **Services:** `SYSTEM\ControlSet001\Services\` — malware often installs as a service
- **Current ControlSet:** `SYSTEM\Select\Current` identifies which ControlSet is active

## SOFTWARE Hive — Application Artifacts

- **Installed programs:** `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- **Run keys (persistence):** `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`
- **Network profiles:** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures`
- **Autoruns:** Multiple locations used by malware for persistence

## NTUSER.DAT — User Activity

- **Recent documents:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
- **Typed URLs:** `NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs`
- **Run dialog history:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
- **UserAssist:** ROT-13 encoded execution history with run counts and timestamps

## Analysis Tools

- **Registry Explorer** (Eric Zimmerman): GUI-based hive viewer with bookmarks for common forensic locations
- **RECmd**: Command-line batch processing of registry hives
- **RegRipper**: Plugin-based registry parser with hundreds of forensic plugins
- **Autopsy**: Integrated registry analysis within a full forensic suite

## Analyst Checklist

1. Extract all registry hives from the forensic image (including user hives)
2. Identify the active ControlSet from `SYSTEM\Select\Current`
3. Parse SAM for user account details and last login times
4. Check Run/RunOnce keys and services for persistence mechanisms
5. Review USB device history in USBSTOR for data exfiltration indicators
6. Examine UserAssist and RecentDocs for evidence of user activity
7. Cross-reference timestamps across registry and file system for timeline construction
""",
    },
    {
        "title": "NTFS Journal Analysis — $UsnJrnl & $LogFile Forensics",
        "tags": ["usnjrnl", "logfile", "ntfs", "journal", "disk-forensics", "timeline"],
        "content": r"""# NTFS Journal Analysis — $UsnJrnl & $LogFile Forensics

## Overview

NTFS maintains two journal mechanisms that record file system changes: the Update Sequence Number Journal (`$UsnJrnl`) and the transactional log (`$LogFile`). These journals are invaluable forensic artifacts because they capture evidence of file creation, modification, deletion, and renaming — even for files that no longer exist on the volume.

## $UsnJrnl (Change Journal)

The USN Journal records high-level file system operations. Each entry contains:

| Field | Description |
|---|---|
| USN | Monotonically increasing sequence number |
| Timestamp | When the change occurred (UTC) |
| Reason | Bitmask of change reasons (create, delete, rename, data extend, etc.) |
| File name | Name of the affected file |
| File reference number | MFT record number + sequence number |
| Parent file reference | MFT record of the parent directory |

**Reason codes** are cumulative — a single operation may set multiple flags:

- `USN_REASON_FILE_CREATE` (0x00000100)
- `USN_REASON_FILE_DELETE` (0x00000200)
- `USN_REASON_DATA_EXTEND` (0x00000002)
- `USN_REASON_RENAME_NEW_NAME` (0x00002000)
- `USN_REASON_CLOSE` (0x80000000)

```bash
# Extract $UsnJrnl from a forensic image using icat (Sleuth Kit)
icat -o <partition_offset> image.raw <mft_record_for_$Extend> > UsnJrnl_raw

# Parse with MFTECmd (Eric Zimmerman)
MFTECmd.exe -f "$J" --csv output/ --csvf usnjrnl.csv

# Parse with usn.py (Python)
usn.py -f $UsnJrnl:$J -o usnjrnl_parsed.csv
```

**Forensic use cases:**

- **Detect file anti-forensics:** If a file was created, renamed, or deleted, the USN Journal often retains a record even after the MFT entry is reused
- **Track malware staging:** Tool transfer → rename → execute → delete sequences leave a clear trail in the journal
- **Establish timelines:** Correlate USN entries with MFT timestamps to detect timestomping

## $LogFile (Transactional Log)

The `$LogFile` is NTFS's write-ahead log, ensuring file system consistency after crashes. It records lower-level metadata changes than `$UsnJrnl`:

- MFT record modifications (attribute changes)
- Index entry insertions and deletions (directory changes)
- Bitmap allocation changes

**Forensic value:** `$LogFile` can contain previous versions of MFT records, including records for deleted files. When `$UsnJrnl` has rolled over (it has a fixed size), `$LogFile` may still contain relevant transaction data.

```bash
# Parse $LogFile with LogFileParser
LogFileParser.exe -l $LogFile -o output/

# Combine $LogFile and $UsnJrnl analysis
# LogFileParser can correlate transactions with USN entries
```

## Journal Limitations

- **$UsnJrnl is circular:** Older entries are overwritten when the journal reaches its maximum size (typically 32-64 MB). On busy systems, this may cover only hours or days of activity.
- **$LogFile is also circular:** Typically much smaller than $UsnJrnl, covering minutes to hours of metadata changes.
- **Both can be cleared** by an attacker with administrative privileges, though this itself leaves evidence (the journal starts fresh with a new USN).

## Analyst Checklist

1. Extract `$UsnJrnl:$J` and `$LogFile` from the forensic image early — they are overwritten quickly
2. Parse `$UsnJrnl` entries and filter by reason codes relevant to the investigation
3. Correlate USN timestamps with MFT `$STANDARD_INFORMATION` timestamps
4. Look for create → rename → close sequences that indicate staging activity
5. Check `$LogFile` for residual MFT records of deleted files
6. Build a unified timeline combining journal data, MFT timestamps, and event logs
7. Document journal size and estimated coverage period for the investigation report
""",
    },
    {
        "title": "Volume Shadow Copies — VSS Forensics & Recovery",
        "tags": ["vss", "volume-shadow-copy", "windows", "disk-forensics", "recovery", "snapshots"],
        "content": r"""# Volume Shadow Copies — VSS Forensics & Recovery

## Overview

Volume Shadow Copy Service (VSS) is a Windows framework that creates consistent point-in-time snapshots of volumes. These shadow copies can contain previous versions of files, registry hives, and system state — making them a critical forensic resource for recovering deleted or modified evidence and establishing historical timelines.

## How VSS Works

VSS creates copy-on-write snapshots: when a block on the volume is about to be modified, the original block is saved to the shadow copy storage area before the write proceeds. This means shadow copies contain the state of changed blocks at the time the snapshot was created.

**Shadow copies are created by:**

- System Restore points (automatic, before updates)
- Windows Backup
- Application-aware VSS writers (SQL Server, Exchange, etc.)
- Scheduled tasks or administrative scripts

## Enumerating Shadow Copies

### On a Live System

```powershell
# List all shadow copies
vssadmin list shadows

# PowerShell alternative
Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName

# Create a symbolic link to access a shadow copy
mklink /d C:\shadow_mount \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

### On a Forensic Image

```bash
# Use libvshadow to enumerate shadow copies in an image
vshadowinfo image.raw

# Mount shadow copies for analysis
vshadowmount image.raw /mnt/vss/
# This creates virtual files: /mnt/vss/vss1, /mnt/vss/vss2, etc.

# Mount individual shadow copy
mount -o ro,loop,show_sys_files /mnt/vss/vss1 /mnt/shadow1/
```

## Forensic Use Cases

### Recovering Deleted Files

Shadow copies may contain files that have since been deleted from the active volume. By mounting multiple shadow copies chronologically, analysts can observe when a file appeared and when it was removed.

### Detecting Anti-Forensics

Attackers who delete files from the active volume often forget (or are unable) to delete shadow copies. Comparing the active volume against shadow copies can reveal:

- Files that existed previously but were deleted (evidence destruction)
- Registry hives with different values (configuration changes)
- Log files that were cleared (event log tampering)

### Timeline Analysis

By examining the same file across multiple shadow copies, analysts can reconstruct the modification history without relying on file system timestamps:

```bash
# Compare a registry hive across shadow copies
sha256sum /mnt/shadow1/Windows/System32/config/SAM
sha256sum /mnt/shadow2/Windows/System32/config/SAM
sha256sum /mnt/active/Windows/System32/config/SAM
# Different hashes indicate the hive was modified between snapshots
```

### Recovering Previous Registry State

Shadow copies preserve complete registry hives, allowing analysts to examine account configurations, installed programs, and persistence mechanisms as they existed at each snapshot point.

## VSS Anti-Forensics

Sophisticated attackers may attempt to delete shadow copies:

```powershell
# Common anti-forensic commands (for awareness — not for use)
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
# Ransomware frequently deletes shadow copies to prevent recovery
```

Detection: Event ID 8194 in the VSS event log records shadow copy creation; absence of expected snapshots or gaps in the snapshot timeline suggest deliberate deletion.

## Analyst Checklist

1. Enumerate all shadow copies in the forensic image using `vshadowinfo`
2. Mount each shadow copy read-only and catalog available snapshots by date
3. Compare critical files (registry hives, event logs, user documents) across shadow copies
4. Look for files present in shadow copies but absent from the active volume
5. Check for evidence of shadow copy deletion (Event ID 8194 gaps, anti-forensic tool artifacts)
6. Document shadow copy IDs, creation times, and volume GUIDs in case notes
7. Use differential analysis to establish when specific changes occurred
""",
    },
]

# ============================================================
# COLLECTION 2: MEMORY FORENSICS & ANALYSIS
# ============================================================

MEMORY_FORENSICS = [
    {
        "title": "Memory Acquisition — WinPmem, LiME & DumpIt",
        "tags": ["memory-acquisition", "winpmem", "lime", "dumpit", "volatile-data", "memory-forensics"],
        "content": r"""# Memory Acquisition — WinPmem, LiME & DumpIt

## Overview

Memory acquisition is the process of capturing the contents of a system's physical RAM for forensic analysis. Because memory is volatile — its contents are lost when power is removed — acquisition must be performed on live systems and is often the first step in incident response. The quality and completeness of the memory dump directly impacts the success of subsequent analysis.

## Why Acquire Memory?

Memory contains evidence that does not exist on disk:

- **Running processes** including those injected or hollowed
- **Network connections** including established sessions with remote hosts
- **Encryption keys** for full-disk encryption (BitLocker, LUKS) and application encryption
- **Loaded DLLs and drivers** including rootkit components
- **Command history** and console buffers
- **Credentials** in plaintext or hashed form (lsass.exe, web browsers)
- **Malware** that never touches disk (fileless attacks)

## Windows Acquisition Tools

### WinPmem

WinPmem is an open-source memory acquisition tool from the Rekall project:

```powershell
# Acquire physical memory to a raw file
winpmem_mini_x64.exe output.raw

# Acquire with specific method (try different methods if one fails)
winpmem_mini_x64.exe --format raw --output memory.raw
```

WinPmem works by loading a signed kernel driver that maps physical memory into user space. It supports raw and AFF4 output formats.

### DumpIt (Magnet/Comae)

DumpIt is a widely used commercial tool known for its simplicity:

```powershell
# Simply run DumpIt — it creates a dump in the current directory
DumpIt.exe
# Output: <hostname>-<date>-<time>.raw
```

DumpIt requires minimal interaction, making it suitable for non-technical responders. It can be placed on a USB drive alongside a batch file for one-click acquisition.

### WinPMEM vs. DumpIt vs. FTK Imager

| Feature | WinPmem | DumpIt | FTK Imager |
|---|---|---|---|
| Cost | Free / Open Source | Commercial | Free |
| Output formats | Raw, AFF4 | Raw | Raw |
| Ease of use | Moderate | Very Easy | Easy (GUI) |
| Kernel driver | Yes (signed) | Yes | Yes |
| Footprint | Small | Very Small | Larger |

## Linux Acquisition — LiME

LiME (Linux Memory Extractor) is a loadable kernel module (LKM) for Linux memory acquisition:

```bash
# Build LiME for the target kernel
cd LiME/src && make

# Acquire memory to a file
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Acquire directly over the network (to minimize target disk writes)
insmod lime-$(uname -r).ko "path=tcp:4444 format=lime"
# On the forensic workstation:
nc <target_ip> 4444 > memory.lime
```

**Key considerations for LiME:**
- The kernel module must be compiled for the exact kernel version of the target
- Pre-compile modules for your organization's standard Linux builds
- Network acquisition avoids writing to the target's disk, reducing evidence contamination

## Best Practices

1. **Acquire memory before disk** — memory is more volatile and changes every moment
2. **Use a trusted, tested tool** from removable media — do not install software on the target
3. **Write the dump to external media** (USB drive, network share) to avoid overwriting evidence on the target disk
4. **Hash the memory dump immediately** after acquisition for chain of custody
5. **Document the system state** — screenshot running applications, note date/time, record uptime
6. **Capture memory before shutting down** — powering off destroys all volatile data
7. **Test your acquisition workflow** regularly on lab systems before you need it in an incident

## Analyst Checklist

1. Prepare acquisition tools on a clean USB drive before responding
2. Document the system state (uptime, logged-in users, running applications)
3. Run the acquisition tool from external media, writing output to external storage
4. Verify the dump size matches expected RAM size (e.g., 16 GB system should produce approximately 16 GB dump)
5. Hash the dump file immediately (SHA-256) and record in case notes
6. Label and secure the dump file with chain of custody documentation
""",
    },
    {
        "title": "Volatility 3 Framework Overview — Plugins, Profiles & Workflow",
        "tags": ["volatility", "volatility3", "memory-analysis", "framework", "memory-forensics", "plugins"],
        "content": r"""# Volatility 3 Framework Overview — Plugins, Profiles & Workflow

## Overview

Volatility 3 is the premier open-source framework for memory forensics. It provides a plugin-based architecture for analyzing memory dumps from Windows, Linux, and macOS systems. Volatility 3 is a complete rewrite of the original Volatility framework, with improved performance, automatic symbol resolution, and a more modular design.

## Key Differences from Volatility 2

| Aspect | Volatility 2 | Volatility 3 |
|---|---|---|
| Profiles | Required (pre-built or custom) | Automatic via symbol tables (ISF) |
| Language | Python 2 (later ported to 3) | Python 3 native |
| Architecture | Monolithic address spaces | Layered architecture (stacking) |
| Performance | Slower | Significantly faster |
| Configuration | Command-line only | Programmatic + CLI |

## Installation

```bash
# Install from PyPI
pip install volatility3

# Or install from source for latest plugins
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip install -e .

# Download symbol tables (required for Windows analysis)
# Download ISF symbol packs from the Volatility 3 releases page
# Place them in volatility3/symbols/
```

## Symbol Tables

Volatility 3 uses Intermediate Symbol Format (ISF) files instead of profiles. These JSON files describe kernel data structures for specific OS builds. The framework can:

1. **Automatically download** matching symbol tables from the Volatility symbol server
2. **Use locally cached** symbol tables from the `symbols/` directory
3. **Generate symbols** from PDB files (Windows) or kernel debug packages (Linux)

## Core Plugins

### Information Gathering

```bash
# Identify the OS and kernel version from the memory dump
vol -f memory.raw windows.info
vol -f memory.raw linux.info

# List available plugins
vol --help
```

### Process Analysis

```bash
# List running processes
vol -f memory.raw windows.pslist

# Display process tree (parent-child relationships)
vol -f memory.raw windows.pstree

# Scan for hidden/terminated processes
vol -f memory.raw windows.psscan
```

### Network Analysis

```bash
# List network connections and listening ports
vol -f memory.raw windows.netscan

# Linux network connections
vol -f memory.raw linux.sockstat
```

### File System

```bash
# Scan for file objects in memory
vol -f memory.raw windows.filescan

# Dump a file from memory by virtual address
vol -f memory.raw windows.dumpfiles --virtaddr 0x...
```

## Workflow for Memory Analysis

1. **Identify the OS:** Run `windows.info` or `linux.info` to determine the operating system, kernel version, and architecture
2. **Process survey:** Run `pslist`, `pstree`, and `psscan` to identify all processes (including hidden ones found only by `psscan`)
3. **Network review:** Run `netscan` to identify active and recently closed network connections
4. **Suspicious process deep-dive:** For any suspicious process, examine its DLLs (`dlllist`), handles (`handles`), memory sections (`malfind`), and command line (`cmdline`)
5. **Artifact extraction:** Dump suspicious executables, injected code sections, or cached files for further analysis
6. **Timeline construction:** Correlate process creation times, network activity, and file modifications

## Analyst Checklist

1. Verify the memory dump integrity (hash comparison) before analysis
2. Run `info` first to confirm OS identification and symbol resolution
3. Compare `pslist` vs `psscan` output — processes in `psscan` but not `pslist` may be hidden or terminated
4. Cross-reference process PIDs with network connections from `netscan`
5. Document all plugin commands and output for reproducibility
6. Export findings in structured format (CSV, JSON) for timeline integration
""",
    },
    {
        "title": "Process Analysis — pslist, pstree & Hidden Process Detection",
        "tags": ["process-analysis", "pslist", "pstree", "psscan", "hidden-processes", "memory-forensics"],
        "content": r"""# Process Analysis — pslist, pstree & Hidden Process Detection

## Overview

Process analysis is typically the first substantive step in memory forensics after OS identification. By examining running processes, their relationships, command-line arguments, and associated metadata, analysts can identify malicious activity, lateral movement tools, and persistence mechanisms. Detecting hidden processes — those deliberately removed from normal enumeration — is a critical capability for uncovering rootkits and advanced malware.

## Process Listing Plugins

### windows.pslist

`pslist` walks the doubly-linked list of `EPROCESS` structures maintained by the Windows kernel. This is the same method used by Task Manager and the `tasklist` command.

```bash
vol -f memory.raw windows.pslist
# Output columns: PID, PPID, ImageFileName, Offset, Threads, Handles, CreateTime, ExitTime
```

**Limitation:** Malware that unlinks its `EPROCESS` structure from this list (Direct Kernel Object Manipulation — DKOM) will not appear in `pslist` output.

### windows.pstree

`pstree` uses the same data source as `pslist` but displays processes in a parent-child hierarchy:

```bash
vol -f memory.raw windows.pstree
```

**Forensic value:** The process tree reveals anomalous parent-child relationships. For example:

- `cmd.exe` or `powershell.exe` spawned by `w3wp.exe` (web server) suggests web shell activity
- `svchost.exe` with a parent other than `services.exe` is suspicious
- `lsass.exe` spawned by anything other than `wininit.exe` is abnormal

### windows.psscan

`psscan` performs a brute-force scan of physical memory for `EPROCESS` structure signatures (pool tag scanning). It finds processes regardless of whether they are linked into the active process list.

```bash
vol -f memory.raw windows.psscan
```

**Forensic value:** Processes found by `psscan` but NOT by `pslist` fall into three categories:

1. **Terminated processes** — `ExitTime` is set; the process ended but its memory has not been reclaimed
2. **DKOM-hidden processes** — actively running but unlinked from the process list by a rootkit
3. **Artifacts** — residual process structures from previous boot sessions (less common)

## Detecting Anomalous Processes

### Expected Process Hierarchy (Windows)

| Process | Expected Parent | Notes |
|---|---|---|
| `System` (PID 4) | None (PID 0) | Kernel process |
| `smss.exe` | `System` | Session Manager |
| `csrss.exe` | `smss.exe` | Client/Server Runtime (one per session) |
| `wininit.exe` | `smss.exe` | Session 0 initialization |
| `winlogon.exe` | `smss.exe` | Session 1+ logon |
| `services.exe` | `wininit.exe` | Service Control Manager |
| `lsass.exe` | `wininit.exe` | Local Security Authority |
| `svchost.exe` | `services.exe` | Service host (multiple instances) |
| `explorer.exe` | `userinit.exe` | User shell |

### Red Flags

- **Misspelled process names:** `scvhost.exe`, `lssas.exe`, `csrs.exe`
- **Wrong parent:** `svchost.exe` not under `services.exe`
- **Wrong path:** System processes running from locations other than `C:\Windows\System32`
- **Unusual process count:** Only one `svchost.exe` instance (should be many) or duplicates of processes that should be unique (`lsass.exe`)
- **Suspicious creation times:** Processes created at unusual hours or clustered at the time of suspected compromise

## Command-Line Analysis

```bash
# Display command-line arguments for each process
vol -f memory.raw windows.cmdline
```

Look for encoded PowerShell commands (`-enc`, `-EncodedCommand`), scripts executed from temp directories, or living-off-the-land binaries (LOLBins) with suspicious arguments.

## Analyst Checklist

1. Run both `pslist` and `psscan` — compare results to identify hidden or terminated processes
2. Review `pstree` for anomalous parent-child relationships
3. Verify process names and paths against the expected Windows process hierarchy
4. Examine command-line arguments for suspicious patterns (encoding, temp paths, LOLBins)
5. Note process creation times and correlate with known incident timeline
6. Investigate any process found by `psscan` but not `pslist` as a potential rootkit indicator
""",
    },
    {
        "title": "DLL & Handle Analysis — Detecting Injected Libraries",
        "tags": ["dll-analysis", "handles", "dlllist", "ldrmodules", "memory-forensics", "injection"],
        "content": r"""# DLL & Handle Analysis — Detecting Injected Libraries

## Overview

Dynamic-Link Libraries (DLLs) are shared code modules loaded into process address spaces at runtime. Analyzing which DLLs are loaded by each process, and how they were loaded, is essential for detecting malicious code injection, DLL hijacking, and reflective loading techniques. Handle analysis complements this by revealing which system resources (files, registry keys, mutexes, events) a process has open.

## DLL Listing with dlllist

```bash
# List DLLs loaded by all processes
vol -f memory.raw windows.dlllist

# Filter to a specific process
vol -f memory.raw windows.dlllist --pid 1234
```

`dlllist` walks the `InLoadOrderModuleList` in the Process Environment Block (PEB). Each entry contains the DLL path, base address, size, and load time.

**What to look for:**

- DLLs loaded from unusual paths (`C:\Temp\`, `C:\Users\Public\`, `AppData\`)
- DLLs with names mimicking legitimate system libraries
- DLLs without full path information (may indicate reflective loading)
- Unexpected DLLs in processes that should not need them (e.g., cryptographic libraries in notepad.exe)

## Detecting Unlinked DLLs with ldrmodules

```bash
vol -f memory.raw windows.ldrmodules --pid 1234
```

Windows maintains three DLL lists in the PEB, and `ldrmodules` compares all three. A DLL present in the memory-mapped sections (VAD) but missing from one or more PEB lists may have been:

- **Manually unmapped** from the PEB by malware to hide its presence
- **Reflectively loaded** (never registered with the loader in the first place)

| InLoad | InInit | InMem | Interpretation |
|---|---|---|---|
| True | True | True | Normal — DLL properly loaded |
| False | False | False | Suspicious — mapped but unlisted (potential injection) |
| True | False | True | Possibly legitimate — some DLLs skip init |

## Handle Analysis

```bash
# List all handles for a process
vol -f memory.raw windows.handles --pid 1234

# Filter by handle type
vol -f memory.raw windows.handles --pid 1234 --type File
vol -f memory.raw windows.handles --pid 1234 --type Key
vol -f memory.raw windows.handles --pid 1234 --type Mutant
```

**Forensically interesting handles:**

- **File handles:** Open files reveal what the process is reading or writing — look for access to sensitive files, staging directories, or exfiltration paths
- **Registry key handles:** Open registry keys may indicate persistence mechanism configuration
- **Mutant (mutex) handles:** Many malware families create named mutexes to prevent multiple instances — these names are often documented in threat intelligence
- **Section handles:** Memory-mapped files and shared memory regions
- **Process/Thread handles:** Cross-process handles may indicate injection or debugging

## DLL Hijacking Detection

DLL hijacking exploits the Windows DLL search order to load a malicious DLL instead of the legitimate one. Key indicators:

- A DLL with a system library name (`version.dll`, `dbghelp.dll`) loaded from the application directory instead of `System32`
- Multiple copies of the same DLL name loaded at different paths
- DLLs in the current working directory that shadow system DLLs

```bash
# Compare loaded DLL paths against known-good baselines
vol -f memory.raw windows.dlllist | grep -v "C:\\Windows\\System32"
```

## Analyst Checklist

1. Run `dlllist` for suspicious processes and review loaded library paths
2. Use `ldrmodules` to detect DLLs hidden from the PEB loader lists
3. Check for DLLs loaded from non-standard directories (user temp, downloads, public folders)
4. Examine handles for access to sensitive files, registry keys, and named mutexes
5. Compare loaded DLLs against known-good baselines for the application
6. Cross-reference mutex names with threat intelligence databases
7. Document all suspicious DLL paths and base addresses for deeper analysis
""",
    },
    {
        "title": "Network Connections from Memory — netscan & Connection Analysis",
        "tags": ["netscan", "network-connections", "memory-forensics", "c2-detection", "lateral-movement"],
        "content": r"""# Network Connections from Memory — netscan & Connection Analysis

## Overview

Analyzing network connections preserved in memory dumps provides a snapshot of a system's communication state at the time of acquisition. Unlike packet captures that show traffic over time, memory forensics reveals the actual socket and connection objects maintained by the kernel, including connections that may have been hidden from user-mode tools by rootkits.

## Using netscan

```bash
# Windows — scan for network artifacts
vol -f memory.raw windows.netscan

# Output includes:
# Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created
```

`netscan` scans physical memory for `_TCP_ENDPOINT`, `_UDP_ENDPOINT`, and related kernel structures. It finds both active and recently closed connections.

## Connection States

| State | Meaning | Forensic Relevance |
|---|---|---|
| ESTABLISHED | Active bidirectional connection | Active C2, data exfiltration |
| LISTENING | Port open, waiting for connections | Backdoor, bind shell |
| CLOSE_WAIT | Remote side closed, local still open | Recently terminated connection |
| TIME_WAIT | Connection recently closed | Historical connection evidence |
| SYN_SENT | Outbound connection initiated | Scanning or connection attempt |

## Identifying Suspicious Connections

### Command & Control (C2) Indicators

- Connections to external IPs on unusual ports (4444, 8080, 8443, 1337)
- ESTABLISHED connections from unexpected processes (notepad.exe, calc.exe, svchost.exe connecting to external IPs)
- Connections to known-bad IP ranges or hosting providers commonly used by threat actors
- Multiple connections to the same foreign address from different processes

### Lateral Movement Indicators

- SMB connections (port 445) to internal hosts from unexpected processes
- WinRM connections (port 5985/5986) between workstations
- RDP connections (port 3389) at unusual times or from service accounts
- PsExec-style connections (`services.exe` spawning a child that connects to another internal host)

### Data Exfiltration Indicators

- Large outbound connections (check with netstat-like tools on live systems, memory shows connection existence but not volume)
- Connections to cloud storage IPs (check against known ranges for major providers)
- DNS over non-standard ports (anything other than 53)
- Connections to external IPs from processes that handle sensitive data

## Correlating Connections with Processes

The key advantage of memory-based network analysis is the ability to map connections directly to processes:

```bash
# Get network connections
vol -f memory.raw windows.netscan

# Then investigate suspicious process
vol -f memory.raw windows.pslist --pid <suspicious_pid>
vol -f memory.raw windows.cmdline --pid <suspicious_pid>
vol -f memory.raw windows.dlllist --pid <suspicious_pid>
```

This correlation is often impossible with network logs alone, which typically only record source/destination IPs and ports without process attribution.

## Linux Network Analysis

```bash
# Linux network connections from memory
vol -f memory.lime linux.sockstat

# Alternative for older kernels
vol -f memory.lime linux.netstat
```

## Comparing with Disk-Based Evidence

Memory network artifacts should be cross-referenced with:

- **Firewall logs** for connection timestamps and byte counts
- **Proxy logs** for HTTP/HTTPS connection details
- **DNS logs** for domain resolution history
- **PCAP** captures if available

Connections visible in memory but absent from logs may indicate log tampering or logging gaps.

## Analyst Checklist

1. Run `netscan` and sort results by process to identify unexpected network activity
2. Flag connections from system processes to external IP addresses
3. Identify LISTENING ports that do not match expected services
4. Correlate suspicious connections with process details (cmdline, DLLs, parent process)
5. Check foreign addresses against threat intelligence feeds and known-bad indicators
6. Document all connections including state, process owner, and timestamps
7. Cross-reference with network logs to identify discrepancies
""",
    },
    {
        "title": "Code Injection Detection — malfind & VAD Analysis",
        "tags": ["malfind", "code-injection", "vad", "process-hollowing", "memory-forensics", "shellcode"],
        "content": r"""# Code Injection Detection — malfind & VAD Analysis

## Overview

Code injection is a technique used by malware to execute arbitrary code within the address space of another process. By injecting into legitimate processes, malware can evade process-based detection, inherit the target process's permissions and network access, and blend into normal system activity. Memory forensics is one of the most effective methods for detecting code injection because injected code must ultimately reside in memory.

## Common Injection Techniques

| Technique | Description | Key Indicators |
|---|---|---|
| DLL Injection | LoadLibrary called in target process via CreateRemoteThread | Unexpected DLL in process, cross-process handle |
| Reflective DLL Injection | DLL loaded manually without Windows loader | No file on disk, missing from PEB lists |
| Process Hollowing | Legitimate process started suspended, code replaced | Image path mismatch, unmapped original sections |
| APC Injection | Code queued via QueueUserAPC | Injected code in alertable thread context |
| Thread Hijacking | Existing thread's context modified to execute injected code | Thread start address outside known modules |
| Atom Bombing | Code stored in global atom table, retrieved by target | Unusual atom table entries |

## Using malfind

The `malfind` plugin is the primary tool for detecting injected code in memory:

```bash
vol -f memory.raw windows.malfind
# Output: Process, PID, Address, Protection, Hexdump, Disassembly
```

`malfind` examines the Virtual Address Descriptors (VADs) for each process and flags memory regions that are:

1. **Marked as executable** (`PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY`)
2. **Not backed by a file on disk** (no mapped file path)
3. **Contain potential code** (determined by examining the first bytes for valid instructions)

**Interpreting malfind output:**

- `PAGE_EXECUTE_READWRITE` (RWX) — Memory that is both writable and executable is suspicious; legitimate code is typically `PAGE_EXECUTE_READ` after loading
- The hexdump shows the first bytes of the suspicious region — look for PE headers (`MZ`), shellcode patterns, or encoded payloads
- The disassembly shows the first instructions — legitimate code will have coherent instruction sequences

## VAD Analysis

The Virtual Address Descriptor tree describes all memory regions in a process's address space:

```bash
# Dump full VAD information
vol -f memory.raw windows.vadinfo --pid 1234

# Dump suspicious memory regions to files
vol -f memory.raw windows.malfind --pid 1234 --dump
```

**VAD protection flags to investigate:**

| Protection | Hex | Suspicious? |
|---|---|---|
| PAGE_EXECUTE_READWRITE | 0x40 | Yes — code should not be writable |
| PAGE_EXECUTE_WRITECOPY | 0x80 | Moderate — used for some legitimate DLLs |
| PAGE_EXECUTE_READ | 0x20 | Normal for loaded code |
| PAGE_READWRITE | 0x04 | Normal for data |

## Process Hollowing Detection

Process hollowing creates a process in a suspended state, unmaps the legitimate executable, writes malicious code into the process space, and resumes execution. Detection involves:

```bash
# Compare the in-memory image against the on-disk file
vol -f memory.raw windows.malfind --pid <hollowed_pid>

# Check for PEB manipulation
vol -f memory.raw windows.pebinfo --pid <hollowed_pid>
```

Indicators of hollowing:
- The process's base address does not match the expected base for the executable named in the PEB
- `malfind` detects executable code at the process base that does not match the file on disk
- The `psscan` entry shows a legitimate process name but the actual code is entirely different

## Reducing False Positives

Not all `malfind` hits are malicious. Common false positives include:

- **JIT-compiled code** from .NET, Java, and JavaScript engines
- **Packed executables** that decompress code into RWX memory
- **Security software** (AV, EDR) that uses injection for hooking
- **Graphics drivers** that allocate executable memory for shaders

Compare findings against known-good baselines for the system's software stack.

## Analyst Checklist

1. Run `malfind` across all processes and review each hit
2. Focus on `PAGE_EXECUTE_READWRITE` regions in processes that should not have them
3. Dump suspicious regions and examine for PE headers, shellcode, or encoded content
4. Compare `pslist` process names against the actual code at the process base address
5. Check for cross-process handles that may indicate injection relationships
6. Cross-reference with `ldrmodules` to find DLLs hidden from loader lists
7. Submit dumped samples to sandbox or static analysis for classification
""",
    },
    {
        "title": "Rootkit Detection in Memory — DKOM, SSDT Hooks & Driver Analysis",
        "tags": ["rootkit", "dkom", "ssdt", "drivers", "kernel", "memory-forensics", "detection"],
        "content": r"""# Rootkit Detection in Memory — DKOM, SSDT Hooks & Driver Analysis

## Overview

Rootkits are malicious software designed to maintain persistent, privileged access while hiding their presence from security tools and system administrators. Kernel-mode rootkits operate at the highest privilege level, allowing them to manipulate core operating system data structures. Memory forensics is often the only reliable method for detecting these threats because the rootkit controls what user-mode tools can observe.

## Types of Rootkits

| Type | Ring Level | Technique | Detection Difficulty |
|---|---|---|---|
| User-mode | Ring 3 | API hooking, IAT patching | Moderate |
| Kernel-mode | Ring 0 | DKOM, SSDT hooks, IRP hooks | High |
| Bootkits | Pre-boot | MBR/VBR modification | Very High |
| Hypervisor | Ring -1 | Hardware virtualization | Extremely High |

## Direct Kernel Object Manipulation (DKOM)

DKOM rootkits modify kernel data structures to hide processes, drivers, or connections from enumeration APIs:

**Process hiding:** The rootkit unlinks a process's `EPROCESS` structure from the `ActiveProcessLinks` doubly-linked list. Tools that walk this list (Task Manager, `pslist`) will not see the hidden process.

**Detection with Volatility:**

```bash
# Compare linked list (pslist) vs pool scanning (psscan)
vol -f memory.raw windows.pslist > pslist_output.txt
vol -f memory.raw windows.psscan > psscan_output.txt
# Processes in psscan but not pslist are potentially DKOM-hidden

# Alternative: psxview in Volatility 2 compared multiple sources
# In Vol3, manual comparison of pslist vs psscan is required
```

## SSDT Hook Detection

The System Service Descriptor Table (SSDT) maps system call numbers to kernel function addresses. Rootkits can replace legitimate function pointers with pointers to their own code:

```bash
# Check SSDT for hooks (functions pointing outside ntoskrnl)
vol -f memory.raw windows.ssdt

# Hooked entries will show function addresses outside the expected
# kernel module address range (ntoskrnl.exe, win32k.sys)
```

**Normal:** All SSDT entries should point to addresses within `ntoskrnl.exe` (or `win32k.sys` for GUI-related calls).

**Suspicious:** SSDT entries pointing to unknown modules or untagged memory regions indicate hooks.

## Driver and Module Analysis

```bash
# List loaded kernel modules (drivers)
vol -f memory.raw windows.modules

# Scan for driver objects in memory (finds unlinked drivers)
vol -f memory.raw windows.driverscan

# Compare results — drivers in driverscan but not modules may be hidden
```

**What to look for:**

- Drivers loaded from unusual paths (not `System32\drivers\`)
- Drivers with no associated service in the registry
- Drivers found by `driverscan` but not in the `modules` list (DKOM-hidden)
- Unsigned drivers (check against known-good driver lists)

## IRP Hook Detection

I/O Request Packet (IRP) hooks intercept device I/O operations. A rootkit can hook the IRP dispatch table of a file system driver to hide files or a network driver to hide connections:

```bash
# Check for IRP hooks on device objects
vol -f memory.raw windows.driverirp --driver \FileSystem\NTFS
```

**Normal:** IRP handler addresses should point within the driver's own code.

**Suspicious:** IRP handlers pointing to other modules or unallocated memory indicate hooking.

## Callback Detection

Windows provides several kernel callback mechanisms that rootkits abuse for persistence and monitoring:

- **PsSetCreateProcessNotifyRoutine** — notified when processes are created
- **PsSetLoadImageNotifyRoutine** — notified when images (DLLs/drivers) are loaded
- **CmRegisterCallback** — notified of registry operations
- **ObRegisterCallbacks** — notified of handle operations

Rootkits register callbacks to monitor and interfere with system activity.

## Analyst Checklist

1. Compare `pslist` vs `psscan` results to detect DKOM-hidden processes
2. Compare `modules` vs `driverscan` to detect hidden kernel drivers
3. Check SSDT entries for hooks pointing outside expected kernel modules
4. Examine IRP dispatch tables for major device drivers
5. Review loaded driver paths and verify against known-good baselines
6. Check for unsigned or unusually named kernel modules
7. Document all anomalies with memory offsets for evidence preservation
""",
    },
    {
        "title": "Credential Artifacts in Memory — LSASS, Cached Hashes & Tokens",
        "tags": ["credentials", "lsass", "mimikatz", "tokens", "memory-forensics", "credential-theft"],
        "content": r"""# Credential Artifacts in Memory — LSASS, Cached Hashes & Tokens

## Overview

Windows stores credential material in memory for single sign-on convenience, and these artifacts are prime targets for attackers. Understanding where credentials reside in memory, how they can be extracted, and what artifacts credential theft leaves behind is essential for both forensic analysis and detection engineering.

## LSASS Process — The Credential Store

The Local Security Authority Subsystem Service (`lsass.exe`) is the central process for Windows authentication. It holds credential material for all interactive logon sessions:

| Credential Type | Description | Present In LSASS? |
|---|---|---|
| NTLM hashes | NT hash of user password | Yes |
| Kerberos tickets | TGTs and service tickets | Yes |
| WDigest plaintext | Cleartext passwords (pre-Win10) | Depends on configuration |
| DPAPI master keys | Data protection keys | Yes |
| SSP credentials | Security Support Provider data | Yes |
| Cached domain creds | MSCACHEv2 hashes | In SAM/SECURITY hive |

### WDigest Plaintext Passwords

On Windows 7/2008R2 and earlier, WDigest authentication stored plaintext passwords in LSASS by default. Starting with Windows 8.1/2012R2, this is disabled by default but can be re-enabled by attackers:

```
Registry key: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
Value: UseLogonCredential = 1 (plaintext enabled)
```

**Detection:** Check the registry for this modification — if `UseLogonCredential` is set to 1 on a modern Windows system, an attacker may have enabled it for credential harvesting.

## Forensic Analysis of LSASS

### Extracting LSASS from Memory Dump

```bash
# Dump the LSASS process memory from a full memory image
vol -f memory.raw windows.memmap --pid <lsass_pid> --dump

# Or target LSASS specifically
vol -f memory.raw windows.pslist | grep lsass
# Note the PID and offset, then dump
```

### Analyzing Credential Artifacts

Forensic tools can parse LSASS memory to identify credential structures without extracting usable credentials (analysis vs. exploitation):

```bash
# List processes that accessed LSASS (handle analysis)
vol -f memory.raw windows.handles --pid <lsass_pid> --type Process

# Check for suspicious DLLs loaded into LSASS
vol -f memory.raw windows.dlllist --pid <lsass_pid>
```

**Indicators of credential theft:**

- Unexpected processes holding handles to LSASS
- Unknown DLLs loaded into the LSASS process (SSP injection)
- `procdump.exe`, `comsvcs.dll`, or `MiniDump` references in process command lines
- `sekurlsa` module artifacts in memory (tool-specific signatures)

## Access Token Analysis

Windows access tokens define the security context of processes and threads. Token manipulation is used for privilege escalation and impersonation:

```bash
# List process tokens and privileges
vol -f memory.raw windows.privileges --pid 1234

# Check for token impersonation
vol -f memory.raw windows.getsids
```

**Suspicious token indicators:**

- A low-privilege process holding `SeDebugPrivilege` or `SeImpersonatePrivilege`
- Processes running with SYSTEM token that should not have elevated privileges
- Token SIDs that do not match the expected user for the process

## Detection in Memory

Look for these artifacts that indicate credential harvesting occurred:

1. **LSASS access patterns:** Multiple processes with handles to LSASS, especially non-standard tools
2. **LSASS memory dumps on disk:** Files named `lsass.dmp`, `lsass.zip`, or similar
3. **Credential tool artifacts:** String references to known tools in process memory
4. **SSP DLL injection:** Unknown DLLs in LSASS that are not part of the standard Windows installation
5. **WDigest modification:** Registry change enabling plaintext credential storage

## Analyst Checklist

1. Identify the LSASS process PID and verify it is genuine (single instance, correct parent)
2. Check for unexpected handles to LSASS from other processes
3. Review DLLs loaded into LSASS for unauthorized SSP modules
4. Check the WDigest `UseLogonCredential` registry value
5. Look for evidence of LSASS memory dumping (procdump, comsvcs.dll, task manager)
6. Examine access tokens for privilege escalation indicators
7. Correlate credential access times with lateral movement activity in network logs
""",
    },
]

# ============================================================
# COLLECTION 3: MALWARE ANALYSIS FUNDAMENTALS
# ============================================================

MALWARE_ANALYSIS = [
    {
        "title": "Static Analysis Workflow — Triage to Deep Inspection",
        "tags": ["static-analysis", "triage", "malware-analysis", "workflow", "methodology"],
        "content": r"""# Static Analysis Workflow — Triage to Deep Inspection

## Overview

Static analysis examines a suspicious file without executing it. This approach is safe (no risk of infection), repeatable, and can reveal significant information about a sample's capabilities, origin, and intent. A structured workflow ensures thorough analysis while managing time efficiently — most samples can be triaged in minutes, with deep analysis reserved for novel or high-priority threats.

## Phase 1 — Initial Triage (5-10 minutes)

The goal of triage is to quickly determine whether a sample warrants deeper analysis and to gather basic classification data.

### File Identification

```bash
# Determine file type (don't trust the extension)
file suspicious.exe
# Output: PE32+ executable (GUI) x86-64, for MS Windows

# Calculate cryptographic hashes
sha256sum suspicious.exe
md5sum suspicious.exe

# Check file size
ls -la suspicious.exe
```

### Hash Lookup

Before investing time in analysis, check if the sample is already known:

- **VirusTotal:** Upload hash (NOT the file, to avoid tipping off the attacker) to check against 70+ AV engines
- **MalwareBazaar:** Community-shared malware samples with tags and reports
- **Hybrid Analysis:** Automated sandbox reports for known hashes
- **MISP/OpenCTI:** Internal threat intelligence platforms

### Initial Indicators

```bash
# Quick string extraction for obvious indicators
strings -n 8 suspicious.exe | head -100

# Check for known packers/protectors
die (Detect It Easy) or PEiD

# Entropy analysis (high entropy = packed/encrypted)
rabin2 -H suspicious.exe
```

## Phase 2 — Structural Analysis (15-30 minutes)

### File Format Parsing

For PE files, examine the structure for anomalies:

- **Section table:** Unusual section names, high entropy sections, executable data sections
- **Timestamps:** Compile timestamp (may be forged but sometimes reveals timezone or compiler)
- **Import table:** APIs the sample claims to use
- **Export table:** Functions the sample exposes
- **Resources:** Embedded files, icons, version info, strings

### String Analysis

Extract and categorize strings:

- **Network indicators:** URLs, IP addresses, domain names, user agents
- **File system references:** Paths, filenames, registry keys
- **System API references:** Function names that suggest capabilities
- **Error messages and debug strings:** May reveal development language or intent
- **Encrypted/encoded blobs:** Base64, XOR patterns, high-entropy regions

## Phase 3 — Deep Static Analysis (1-4 hours)

### Disassembly and Decompilation

Use IDA Pro, Ghidra, or Binary Ninja to examine the code:

- **Entry point analysis:** What happens when the sample starts executing?
- **Function identification:** Map out the major code functions
- **API call tracing:** Follow the sequence of Windows API calls to understand behavior
- **Control flow analysis:** Identify decision points, loops, and error handling
- **String decryption:** Identify and reverse string obfuscation routines

### Code Patterns

Look for patterns that indicate specific capabilities:

- **Network communication:** Socket creation, HTTP requests, DNS resolution
- **File manipulation:** Create, read, write, delete operations
- **Registry modification:** Persistence, configuration storage
- **Process manipulation:** Injection, hollowing, privilege escalation
- **Anti-analysis checks:** Debugger detection, VM detection, timing checks

## Documentation

Maintain a structured analysis report:

1. **Sample identification:** Hashes, file type, size, names
2. **Classification:** Malware family, variant, type
3. **Indicators of compromise:** Network, file system, registry
4. **Capabilities assessment:** What the malware can do
5. **MITRE ATT&CK mapping:** Techniques used

## Analyst Checklist

1. Never analyze malware on a production system — use an isolated analysis environment
2. Hash the sample and check against known databases before deep analysis
3. Document all findings as you go — do not rely on memory
4. Extract IOCs for immediate detection rule creation even during early triage
5. Classify the sample type and family to guide your analysis focus
6. Time-box each phase to ensure efficient use of analyst resources
""",
    },
    {
        "title": "PE File Format Overview — Headers, Sections & Data Directories",
        "tags": ["pe-format", "headers", "sections", "malware-analysis", "windows", "executable"],
        "content": r"""# PE File Format Overview — Headers, Sections & Data Directories

## Overview

The Portable Executable (PE) format is the standard file format for executables, DLLs, and drivers on Windows. Understanding PE structure is fundamental to malware analysis — the headers reveal compiler information, the import table shows API usage, sections contain code and data, and anomalies in any of these areas can indicate malicious intent, packing, or anti-analysis techniques.

## PE Structure Overview

A PE file is organized in the following order:

```
+---------------------------+
| DOS Header (MZ)           | ← Legacy DOS compatibility
| DOS Stub                  | ← "This program cannot be run in DOS mode"
+---------------------------+
| PE Signature (PE\0\0)     | ← Offset from e_lfanew in DOS header
+---------------------------+
| COFF File Header          | ← Machine type, section count, timestamp
+---------------------------+
| Optional Header           | ← Entry point, image base, subsystem
|   - Data Directories      | ← Import/Export tables, resources, etc.
+---------------------------+
| Section Headers           | ← .text, .data, .rdata, .rsrc, etc.
+---------------------------+
| Section Data              | ← Actual code and data
+---------------------------+
```

## DOS Header

The DOS header begins with the magic bytes `4D 5A` ("MZ"). The critical field is `e_lfanew` (offset 0x3C), which points to the PE signature.

**Forensic note:** Some malware modifies the DOS stub to contain additional code or data, or uses the space between the DOS header and PE header for hiding data.

## COFF File Header

| Field | Size | Description |
|---|---|---|
| Machine | 2 bytes | Target architecture (0x14C = x86, 0x8664 = x64) |
| NumberOfSections | 2 bytes | Count of section headers |
| TimeDateStamp | 4 bytes | Compile timestamp (Unix epoch) |
| PointerToSymbolTable | 4 bytes | Usually 0 for executables |
| Characteristics | 2 bytes | Flags: executable, DLL, large address aware |

**Timestamp analysis:** While easily forged, the compile timestamp can reveal patterns — consistent timestamps across related samples suggest a common build environment.

## Optional Header

Despite its name, the Optional Header is required for executables. Key fields:

- **AddressOfEntryPoint:** RVA where execution begins — an unusual entry point (outside `.text`, inside a non-standard section) is suspicious
- **ImageBase:** Preferred load address (0x00400000 for EXE, 0x10000000 for DLL)
- **SectionAlignment / FileAlignment:** Must be consistent; unusual values may indicate packing
- **SizeOfImage / SizeOfHeaders:** Used for memory mapping validation
- **Subsystem:** Console (3), GUI (2), Native (1), etc.
- **DllCharacteristics:** ASLR, DEP/NX, SEH — absence of security features in modern binaries is notable

## Sections

| Section | Purpose | Typical Characteristics |
|---|---|---|
| `.text` | Executable code | Read, Execute |
| `.data` | Initialized global data | Read, Write |
| `.rdata` | Read-only data, imports | Read |
| `.bss` | Uninitialized data | Read, Write |
| `.rsrc` | Resources (icons, strings) | Read |
| `.reloc` | Relocation information | Read |

**Suspicious section indicators:**

- **Unusual names:** UPX0, .packed, .vmp, or random characters
- **Executable data sections:** `.data` or `.rsrc` marked as executable
- **High entropy sections:** Entropy > 7.0 suggests encryption or compression
- **Size mismatches:** Large difference between raw size and virtual size may indicate unpacking

## Data Directories

The 16 data directories point to important structures within the PE:

```
# Key data directories for malware analysis:
[0]  Export Table      — Functions exported by the PE
[1]  Import Table      — Functions imported from other DLLs
[2]  Resource Table    — Embedded resources
[5]  Base Relocation   — Relocation entries for ASLR
[6]  Debug Directory   — Debug information (may contain PDB path)
[11] Bound Import      — Bound import descriptors
[12] IAT               — Import Address Table
[14] CLR Runtime       — .NET metadata header
```

## Tools for PE Analysis

```bash
# PE-bear: GUI PE viewer with visual section analysis
# CFF Explorer: Detailed PE structure editor
# pefile (Python): Programmatic PE parsing

python3 -c "
import pefile
pe = pefile.PE('suspicious.exe')
print(f'Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}')
print(f'Sections: {len(pe.sections)}')
for s in pe.sections:
    print(f'  {s.Name.decode().strip(chr(0)):8s} Entropy: {s.get_entropy():.2f}')
"
```

## Analyst Checklist

1. Verify the MZ and PE signatures are present and properly linked via `e_lfanew`
2. Check the compile timestamp and machine architecture
3. Examine the entry point — is it within the `.text` section?
4. Review section names, permissions, and entropy values
5. Parse the import and export tables for capability assessment
6. Check DllCharacteristics for missing security features (ASLR, DEP)
7. Look for debug directory entries that may contain the PDB build path
""",
    },
    {
        "title": "String Extraction & YARA Rules for Malware Classification",
        "tags": ["strings", "yara", "classification", "malware-analysis", "detection", "signatures"],
        "content": r"""# String Extraction & YARA Rules for Malware Classification

## Overview

String extraction and YARA rule writing are complementary skills central to malware analysis. Strings embedded in executables can reveal network infrastructure, capabilities, debug messages, and campaign identifiers. YARA rules codify these patterns into reusable detection signatures that can be applied across file systems, memory dumps, and network traffic.

## String Extraction

### Basic Extraction

```bash
# Extract ASCII strings (minimum 8 characters)
strings -n 8 suspicious.exe > strings_ascii.txt

# Extract Unicode (wide) strings
strings -n 8 -el suspicious.exe > strings_unicode.txt

# Combine both
strings -n 6 suspicious.exe > all_strings.txt
strings -n 6 -el suspicious.exe >> all_strings.txt
```

### FLOSS — FLARE Obfuscated String Solver

FLOSS (by Mandiant/FLARE) automatically deobfuscates strings that are encrypted, encoded, or constructed at runtime:

```bash
# Run FLOSS for static + decoded strings
floss suspicious.exe

# Output includes:
# - Static strings (same as strings command)
# - Decoded strings (XOR, stack strings, etc.)
# - Tight strings (short strings built character-by-character)
```

### Categorizing Extracted Strings

Organize strings by type for analysis:

- **Network:** URLs, IP addresses, domains, ports, HTTP verbs, user agents
- **File paths:** Installation directories, dropped files, config locations
- **Registry:** Persistence keys, configuration storage
- **Commands:** Shell commands, PowerShell scripts, WMI queries
- **Credentials:** Usernames, password patterns, authentication tokens
- **Debug/Error:** Developer messages, function names, error handling text
- **Crypto:** Key material patterns, algorithm identifiers, certificate references

## YARA Rule Fundamentals

YARA rules consist of three sections: metadata, strings, and conditions.

```yara
rule Example_MalwareFamily {
    meta:
        author = "SOC Analyst"
        description = "Detects Example malware family based on unique strings"
        date = "2026-03-15"
        reference = "Internal Case #2026-042"
        tlp = "amber"
        severity = "high"

    strings:
        $mutex = "Global\\ExampleMutex_v2" ascii wide
        $config_marker = { 45 78 43 6F 6E 66 69 67 ?? ?? ?? ?? 00 }
        $api_1 = "VirtualAllocEx" ascii
        $api_2 = "WriteProcessMemory" ascii
        $api_3 = "CreateRemoteThread" ascii
        $c2_pattern = /https?:\/\/[a-z0-9]{8,12}\.(xyz|top|tk)\// ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $mutex and
        2 of ($api_*) and
        ($config_marker or $c2_pattern)
}
```

### String Types in YARA

| Type | Syntax | Use Case |
|---|---|---|
| Text | `"string"` | Exact ASCII match |
| Wide | `"string" wide` | UTF-16LE encoded |
| Hex | `{ 4D 5A 90 }` | Exact byte sequence |
| Wildcard | `{ 4D 5A ?? 00 }` | Bytes with wildcards |
| Regex | `/pattern/` | Regular expression match |
| XOR | `"string" xor` | String XOR'd with any single-byte key |

### Condition Logic

```yara
condition:
    # File type check
    uint16(0) == 0x5A4D                    // PE file (MZ header)

    # String matching
    all of ($required_*)                    // All strings matching prefix
    2 of ($optional_*)                      // At least 2 of group
    any of them                             // Any defined string

    # File properties
    filesize < 5MB                          // Size constraint
    #string_name > 3                        // String appears more than 3 times
```

## Best Practices for YARA Rules

1. **Always include a file type check** (MZ header, PDF magic, etc.) to reduce false positives
2. **Combine multiple indicators** — a single string is rarely sufficient for reliable detection
3. **Use metadata** for attribution, dating, and sharing context
4. **Test against clean file sets** before deployment to identify false positives
5. **Version your rules** and track performance (true positives, false positives) over time
6. **Use hex patterns for binary signatures** — they are more precise than text strings
7. **Avoid overly broad regex** — patterns like `/.{1,100}/` will match almost anything

## Analyst Checklist

1. Extract both ASCII and Unicode strings from every sample
2. Run FLOSS to recover obfuscated and stack-constructed strings
3. Categorize strings and flag network indicators for immediate blocking
4. Write YARA rules for unique identifiers (mutexes, config markers, C2 patterns)
5. Test rules against a clean corpus before production deployment
6. Share rules with the team via the organization's YARA rule repository
""",
    },
    {
        "title": "Import Analysis — API Calls & Capability Assessment",
        "tags": ["imports", "api-analysis", "iat", "malware-analysis", "capability-assessment"],
        "content": r"""# Import Analysis — API Calls & Capability Assessment

## Overview

The Import Address Table (IAT) of a PE file lists the Windows API functions the executable uses. Analyzing imports provides a rapid capability assessment — revealing what a sample can do (file manipulation, network communication, process injection) without executing it. However, sophisticated malware often hides its true imports through dynamic resolution, requiring deeper analysis techniques.

## Reading the Import Table

```bash
# Using pefile (Python)
python3 -c "
import pefile
pe = pefile.PE('suspicious.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f'\n{entry.dll.decode()}:')
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else f'Ordinal {imp.ordinal}'
        print(f'  {name}')
"

# Using PE-bear, CFF Explorer, or pestudio (GUI tools)
# Using dumpbin (Visual Studio)
dumpbin /imports suspicious.exe
```

## API Categories and Capabilities

### Process Manipulation

| API Function | Capability |
|---|---|
| `CreateProcess` | Launch new processes |
| `OpenProcess` | Access other processes (injection prerequisite) |
| `VirtualAllocEx` | Allocate memory in another process |
| `WriteProcessMemory` | Write code into another process |
| `CreateRemoteThread` | Execute code in another process |
| `NtUnmapViewOfSection` | Process hollowing (unmap legitimate code) |

### File System Operations

| API Function | Capability |
|---|---|
| `CreateFile` / `ReadFile` / `WriteFile` | File I/O |
| `DeleteFile` | File deletion (cleanup, anti-forensics) |
| `FindFirstFile` / `FindNextFile` | Directory enumeration |
| `MoveFile` / `CopyFile` | File staging |
| `GetTempPath` | Locate temp directory for staging |

### Network Communication

| API Function | Capability |
|---|---|
| `WSAStartup` / `socket` / `connect` | Raw socket communication |
| `InternetOpen` / `HttpOpenRequest` | HTTP communication (WinINet) |
| `WinHttpOpen` / `WinHttpConnect` | HTTP communication (WinHTTP) |
| `URLDownloadToFile` | Download files from URL |
| `DnsQuery` | DNS resolution (may indicate DNS tunneling) |

### Registry Manipulation

| API Function | Capability |
|---|---|
| `RegCreateKeyEx` / `RegSetValueEx` | Create/modify registry values |
| `RegOpenKeyEx` / `RegQueryValueEx` | Read registry values |
| `RegDeleteKey` / `RegDeleteValue` | Remove registry entries |

### Credential and Security

| API Function | Capability |
|---|---|
| `LookupPrivilegeValue` / `AdjustTokenPrivileges` | Privilege escalation |
| `LogonUser` / `ImpersonateLoggedOnUser` | Credential use / impersonation |
| `CryptEncrypt` / `CryptDecrypt` | Encryption (ransomware, C2 encryption) |
| `LsaRetrievePrivateData` | Credential access |

### Anti-Analysis

| API Function | Capability |
|---|---|
| `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` | Debugger detection |
| `GetTickCount` / `QueryPerformanceCounter` | Timing checks (sandbox detection) |
| `NtQueryInformationProcess` | Various anti-debug checks |
| `FindWindow` | Detect analysis tool windows |

## Dynamic Import Resolution

Malware frequently resolves API addresses at runtime to avoid revealing capabilities in the static import table:

```c
// Common pattern: GetProcAddress + LoadLibrary
HMODULE hMod = LoadLibraryA("kernel32.dll");
FARPROC pFunc = GetProcAddress(hMod, "VirtualAllocEx");
```

**Detection:** If `GetProcAddress` and `LoadLibrary` are the only notable imports, the sample is almost certainly resolving additional APIs dynamically. String extraction may reveal the function names being resolved.

**API hashing:** Advanced malware hashes API names and resolves them by comparing hashes rather than strings. This technique requires reversing the hash function to determine which APIs are being loaded.

## Analyst Checklist

1. Parse the import table and categorize APIs by capability
2. Flag high-risk API combinations (e.g., `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` = injection)
3. Note if `GetProcAddress` / `LoadLibrary` are prominent — suggests dynamic resolution
4. Check for anti-analysis APIs that indicate sandbox/debugger awareness
5. Compare imports against known malware families for classification hints
6. If imports are minimal or absent, suspect packing or dynamic resolution
7. Correlate import capabilities with observed behavior from dynamic analysis
""",
    },
    {
        "title": "Packer Detection — Identifying & Unpacking Protected Executables",
        "tags": ["packers", "upx", "unpacking", "obfuscation", "malware-analysis", "entropy"],
        "content": r"""# Packer Detection — Identifying & Unpacking Protected Executables

## Overview

Packers are tools that compress, encrypt, or otherwise transform executable files to reduce their size, protect intellectual property, or evade detection. In malware analysis, packed samples present a significant challenge because the actual malicious code is hidden until runtime when the packer's stub decompresses or decrypts it into memory. Identifying and unpacking these protections is often a prerequisite for meaningful static analysis.

## How Packers Work

A typical packing process:

1. **Original code and data** are compressed or encrypted
2. **A decompression/decryption stub** is prepended to the packed data
3. **The entry point** is set to the stub, not the original code
4. **At runtime:** The stub allocates memory, unpacks the original code into it, fixes imports, and transfers execution to the original entry point (OEP)

```
Packed PE:
+---------------------------+
| PE Headers (modified)     |
| Packer Stub (.text)       | ← Entry Point here
| Packed Data (.rsrc/custom)| ← Compressed/encrypted original
+---------------------------+

After unpacking in memory:
+---------------------------+
| Original PE Headers       |
| Original .text            | ← OEP here
| Original .data            |
| Original imports restored |
+---------------------------+
```

## Identifying Packed Executables

### Entropy Analysis

Entropy measures the randomness of data. Uncompressed code typically has entropy of 5.0-6.5, while packed/encrypted data approaches 7.5-8.0 (maximum).

```bash
# Calculate per-section entropy
python3 -c "
import pefile, math
pe = pefile.PE('suspicious.exe')
for s in pe.sections:
    print(f'{s.Name.decode().strip(chr(0)):8s} '
          f'Entropy: {s.get_entropy():.2f}  '
          f'Raw: {s.SizeOfRawData:>8d}  '
          f'Virtual: {s.Misc_VirtualSize:>8d}')
"
```

**Indicators of packing:**

- One or more sections with entropy > 7.0
- Large discrepancy between raw size and virtual size (data will expand when unpacked)
- Very few imports (only `LoadLibrary`, `GetProcAddress`, and `VirtualAlloc` needed for unpacking)
- Unusual section names (UPX0, UPX1, .packed, .vmp0)

### Packer Identification Tools

| Tool | Description |
|---|---|
| Detect It Easy (DiE) | Signature-based packer detection with scripting |
| PEiD | Classic packer identifier (legacy but still useful) |
| Exeinfo PE | Packer, compiler, and protector detection |
| YARA rules | Custom signatures for known packer patterns |

### Common Packers

| Packer | Type | Difficulty to Unpack |
|---|---|---|
| UPX | Open-source compressor | Easy (built-in unpacker) |
| ASPack | Commercial packer | Moderate |
| Themida/WinLicense | Commercial protector | Hard |
| VMProtect | Virtualization-based protector | Very Hard |
| Custom packers | Malware-specific | Variable |

## Unpacking Techniques

### Static Unpacking (UPX)

```bash
# UPX includes a built-in unpacker
upx -d packed_sample.exe -o unpacked_sample.exe

# Verify the unpacked file
file unpacked_sample.exe
strings unpacked_sample.exe | wc -l  # Should show many more strings
```

### Dynamic Unpacking (Generic Approach)

When static unpacking is not possible:

1. **Load the sample in a debugger** (x64dbg, OllyDbg) in an isolated VM
2. **Set breakpoints** on `VirtualAlloc`, `VirtualProtect` (memory allocation for unpacked code)
3. **Run until the packer allocates and fills memory** with the unpacked code
4. **Find the Original Entry Point (OEP)** — often a `JMP` or `CALL` to the unpacked code region
5. **Dump the process memory** at the OEP using tools like Scylla or OllyDump
6. **Fix the import table** — the dumped executable needs its IAT rebuilt (Scylla's IAT auto-fix)

### Automated Unpacking

- **unipacker:** Open-source automated unpacker for common packers
- **CAPE Sandbox:** Automatically dumps unpacked payloads during dynamic analysis
- **PE-sieve / HollowsHunter:** Detect and dump unpacked code from running processes

## Analyst Checklist

1. Calculate entropy for each section — values above 7.0 suggest packing
2. Check for packer signatures using Detect It Easy or similar tools
3. Note the import count — very few imports suggest the real IAT is hidden
4. Try static unpacking first (UPX, known packer-specific tools)
5. Fall back to dynamic unpacking in an isolated environment if static methods fail
6. After unpacking, verify the result by checking that strings, imports, and sections look normal
7. Re-analyze the unpacked sample using the full static analysis workflow
""",
    },
    {
        "title": "Dynamic Analysis Methodology — Behavioral Observation in Sandboxes",
        "tags": ["dynamic-analysis", "sandbox", "behavioral-analysis", "malware-analysis", "methodology"],
        "content": r"""# Dynamic Analysis Methodology — Behavioral Observation in Sandboxes

## Overview

Dynamic analysis involves executing malware in a controlled environment to observe its runtime behavior. While static analysis reveals what a sample could do based on its code, dynamic analysis shows what it actually does — including behaviors that are obfuscated, encrypted, or conditionally triggered. A structured approach maximizes the intelligence gathered while minimizing risk to the analyst and organization.

## Sandbox Environment Setup

### Isolated Analysis VMs

The analysis environment must be completely isolated from production networks:

- **Network isolation:** Use host-only or isolated virtual networks; route external traffic through INetSim or FakeNet-NG for simulated internet services
- **Snapshot management:** Take a clean snapshot before each analysis; revert after every run
- **Shared folders disabled:** Prevent malware from escaping to the host via shared directories
- **Clipboard isolation:** Disable clipboard sharing between host and guest

### Recommended Platforms

| Platform | OS | Purpose |
|---|---|---|
| FlareVM | Windows 10/11 | Mandiant's pre-built analysis VM with 140+ tools |
| REMnux | Ubuntu-based | Linux-based malware analysis distribution |
| CAPE Sandbox | Multi-OS | Automated analysis with unpacking and config extraction |
| ANY.RUN | Cloud | Interactive cloud sandbox with real-time analysis |
| Joe Sandbox | Cloud/On-prem | Automated with extensive behavioral analysis |

### Network Simulation

```bash
# INetSim — simulate DNS, HTTP, HTTPS, SMTP, FTP, etc.
inetsim --bind-address 10.0.0.1

# FakeNet-NG — Windows-native network simulation
FakeNet-NG.exe

# Wireshark/tcpdump for traffic capture
tcpdump -i eth0 -w malware_traffic.pcap
```

## Monitoring Tools

### Process Monitoring

```powershell
# Process Monitor (ProcMon) — real-time file, registry, process, network activity
# Set filters before execution:
# Process Name contains "suspicious"
# Operation: CreateFile, RegSetValue, Process Create, TCP Connect

# Process Hacker — real-time process inspection
# Monitor: new processes, DLL loads, network connections, handles
```

### File System Monitoring

Watch for file creation, modification, and deletion:

- **Dropped files:** Payloads, configuration files, additional tools
- **Modified files:** Host file changes, browser settings, document encryption
- **Deleted files:** Self-deletion, log clearing, evidence removal

### Registry Monitoring

Key registry locations to watch:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — persistence
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` — user-level persistence
- `HKLM\SYSTEM\CurrentControlSet\Services` — service installation
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` — logon hooks

### Network Monitoring

```bash
# Capture all traffic from the analysis VM
tcpdump -i vmnet1 -w analysis.pcap

# DNS queries reveal C2 domains even with encrypted C2
# HTTP/HTTPS connections show staging, C2, and exfiltration
# Watch for unusual protocols (DNS tunneling, ICMP covert channels)
```

## Execution Workflow

1. **Prepare the environment:** Clean VM snapshot, start monitoring tools, begin network capture
2. **Stage the sample:** Copy the malware to the VM (disable real-time AV if it interferes)
3. **Execute and observe:** Run the sample and monitor for 5-15 minutes of initial behavior
4. **Interact if needed:** Some malware requires user interaction (click through dialogs, open documents)
5. **Extended observation:** Leave running for 30-60 minutes to capture delayed behaviors (beaconing, scheduled tasks)
6. **Collect artifacts:** Save ProcMon logs, PCAP, screenshots, and any dropped files
7. **Revert:** Return the VM to the clean snapshot

## Triggering Conditional Behavior

Some malware only activates under specific conditions:

- **Date/time triggers:** Set the VM clock to different dates
- **Domain/workgroup membership:** Join the VM to a test domain
- **Internet connectivity:** Provide (simulated) internet access vs. no access
- **Specific software:** Install targeted applications (browsers, Office, specific enterprise software)
- **Geographic checks:** Configure IP geolocation simulation

## Analyst Checklist

1. Verify VM isolation (no shared folders, no host network access, no clipboard sharing)
2. Take a clean snapshot before every analysis session
3. Start all monitoring tools before executing the sample
4. Document the execution method (double-click, command-line, script invocation)
5. Monitor for at least 15 minutes of initial behavior and up to 60 minutes for beaconing
6. Capture all network traffic for protocol analysis
7. Export monitoring logs and dropped files for archival before reverting the VM
""",
    },
    {
        "title": "Behavior Monitoring & Sandbox Evasion Awareness",
        "tags": ["behavior-monitoring", "evasion", "anti-analysis", "sandbox-detection", "malware-analysis"],
        "content": r"""# Behavior Monitoring & Sandbox Evasion Awareness

## Overview

Modern malware frequently incorporates techniques to detect analysis environments and alter its behavior accordingly — appearing benign in sandboxes while executing malicious payloads on real victim systems. Understanding these evasion techniques is essential for analysts to configure their environments to avoid triggering them and to recognize when a sample may be withholding its true behavior.

## Common Anti-Analysis Techniques

### Virtual Machine Detection

Malware checks for VM artifacts to determine if it is running in an analysis environment:

**Hardware fingerprints:**
- VM-specific MAC address prefixes (VMware: `00:0C:29`, VirtualBox: `08:00:27`)
- VM guest tools processes (`vmtoolsd.exe`, `VBoxService.exe`)
- VM-specific registry keys (`HKLM\SOFTWARE\VMware, Inc.`)
- CPUID instruction returns hypervisor-present bit
- BIOS strings containing "VBOX", "VMWARE", "QEMU"

**Resource checks:**
- Low RAM (< 4 GB), few CPU cores (< 2), small disk (< 60 GB)
- No USB devices connected
- Limited screen resolution or color depth
- No printers installed

### Debugger Detection

- `IsDebuggerPresent()` and `CheckRemoteDebuggerPresent()` API calls
- `NtQueryInformationProcess` with `ProcessDebugPort`
- Timing checks: `GetTickCount()`, `QueryPerformanceCounter()`, `RDTSC` — debugger stepping introduces measurable delays
- INT 3 (breakpoint) and INT 2D exception handling tricks
- Process name checks for known debuggers (x64dbg, ollydbg, ida)

### Sandbox Detection

- **Username/hostname checks:** Sandboxes often use default names ("sandbox", "malware", "analyst", "John Doe")
- **Recent file checks:** Real systems have recently accessed documents; fresh VMs do not
- **Uptime checks:** Real systems have been running for days; analysis VMs were just booted
- **Installed software:** Real systems have browsers, Office, media players with usage history
- **Mouse movement:** Automated sandboxes rarely generate realistic mouse movement patterns
- **User interaction:** Some malware waits for a mouse click or keystroke before executing

### Time-Based Evasion

- **Sleep calls:** `Sleep(600000)` — sleep for 10 minutes hoping the sandbox times out
- **Date checks:** Only execute after a specific date or during business hours
- **Delayed execution:** Use scheduled tasks or WMI event subscriptions for delayed activation

## Countermeasures for Analysts

### Making VMs Look Real

```powershell
# Increase VM resources
# - Set RAM >= 8 GB
# - Assign 4+ CPU cores
# - Create a 120+ GB virtual disk

# Rename the VM hostname and username to realistic values
Rename-Computer -NewName "DESKTOP-A7B3C9D"
Rename-LocalUser -Name "User" -NewName "sarah.johnson"

# Install common software (browsers, Office, media players)
# Create realistic browsing history and recent documents
# Add dummy files to Desktop and Documents folders

# Remove VM tools (if feasible) or rename their processes
# Modify VM-specific registry keys
```

### Defeating Time-Based Evasion

```bash
# In the sandbox, accelerate API-level sleep calls
# CAPE and Cuckoo can patch Sleep() to return immediately

# Set the VM clock to a future date if date-triggered behavior is suspected
# Monitor for sleep/delay API calls in ProcMon
```

### Detecting Evasion in Analysis

Signs that a sample is performing environment checks:

- **CPUID instructions** early in execution
- **Registry queries** for VM-related keys
- **WMI queries** for system information (`Win32_ComputerSystem`, `Win32_BIOS`)
- **Abnormally short execution** — sample exits quickly without observable behavior
- **No network activity** from a sample that should be communicating
- **Environment variable checks** for sandbox-specific values

## Behavior Monitoring Best Practices

1. **Baseline your environment:** Know what normal looks like in your analysis VM so you can distinguish malware behavior from background noise
2. **Use API-level monitoring:** Tools like API Monitor or sandbox hooking capture every API call, not just file/registry changes
3. **Monitor child processes:** Malware often spawns secondary processes for payload execution
4. **Track network DNS queries:** Even if the C2 is down, DNS queries reveal the intended infrastructure
5. **Watch for encoded commands:** Base64-encoded PowerShell, certutil downloads, mshta executions

## Analyst Checklist

1. Configure analysis VMs with realistic hardware specs, usernames, and installed software
2. Pre-populate the VM with dummy documents, browser history, and recent files
3. Be aware of common evasion techniques and watch for their artifacts during execution
4. If a sample exits quickly or shows no behavior, suspect anti-analysis checks
5. Try re-running with modified environment settings (different date, domain-joined, internet access)
6. Monitor for VM detection API calls (CPUID, WMI queries, registry reads)
7. Document any evasion techniques observed for threat intelligence sharing
""",
    },
    {
        "title": "Document Malware — Macro Analysis, OLE Streams & VBA Extraction",
        "tags": ["document-malware", "macros", "ole", "vba", "maldoc", "malware-analysis", "office"],
        "content": r"""# Document Malware — Macro Analysis, OLE Streams & VBA Extraction

## Overview

Malicious documents (maldocs) remain one of the most prevalent initial access vectors. Attackers embed malicious macros, OLE objects, DDE fields, or exploits within Office documents (Word, Excel, PowerPoint) and PDFs to execute code when the document is opened. Analyzing these documents safely requires specialized tools and techniques to extract and examine the embedded payloads without executing them.

## Document Formats

| Format | Extension | Structure | Macro Support |
|---|---|---|---|
| OLE2 (Legacy) | .doc, .xls, .ppt | Compound File Binary | VBA macros in storage streams |
| OOXML | .docx, .xlsx, .pptx | ZIP archive with XML | VBA in vbaProject.bin (if .docm/.xlsm) |
| RTF | .rtf | Text-based markup | OLE objects, no native macros |
| PDF | .pdf | Cross-reference table | JavaScript, embedded files |

## OLE Analysis with olevba and oletools

The `oletools` suite by Philippe Lagadec is the standard for document malware analysis:

```bash
# Install oletools
pip install oletools

# Detect VBA macros and suspicious patterns
olevba suspicious.doc
# Output: macro source code, suspicious keywords, IOCs

# Analyze OLE streams
oleid suspicious.doc
# Output: container format, VBA macros present, encrypted, external relationships

# List OLE streams
olebrowse suspicious.doc
# Interactive stream browser

# Extract embedded OLE objects
oleobj suspicious.doc
# Extracts embedded executables, scripts, or other objects

# Detect DDE (Dynamic Data Exchange) fields
msodde suspicious.docx
```

### Suspicious VBA Patterns

`olevba` flags keywords by category:

| Category | Keywords | Significance |
|---|---|---|
| AutoExec | `AutoOpen`, `Document_Open`, `Workbook_Open` | Automatic execution triggers |
| Suspicious | `Shell`, `WScript.Shell`, `PowerShell` | Command execution |
| IOC | `http://`, `https://`, IP addresses | Network indicators |
| Obfuscation | `Chr()`, `Environ()`, string concatenation | Evasion techniques |
| File Write | `Open...For Output`, `SaveToFile` | Payload dropping |

### Common Macro Techniques

**Download and execute:**
```vba
' Typical pattern (for analysis reference only):
' 1. Use PowerShell, WScript, or XMLHTTP to download payload
' 2. Save to %TEMP% or %APPDATA%
' 3. Execute via Shell, WMI, or scheduled task
```

**String obfuscation:**
- Character-by-character construction using `Chr()` and `ChrW()`
- String reversal with `StrReverse()`
- Environment variable concatenation
- Array-based string building

## RTF Analysis

RTF files can embed OLE objects and have been used with exploits (e.g., Equation Editor vulnerabilities):

```bash
# Analyze RTF structure
rtfobj suspicious.rtf
# Lists embedded OLE objects with hashes and types

# Extract embedded objects
rtfobj -s all suspicious.rtf
# Saves extracted objects for further analysis
```

## PDF Analysis

```bash
# Analyze PDF structure
pdfid suspicious.pdf
# Shows counts of: /JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFile, etc.

# Extract JavaScript from PDF
pdf-parser -s javascript suspicious.pdf

# Detailed object analysis
pdf-parser -o <object_number> suspicious.pdf
```

**Suspicious PDF indicators:**
- `/JavaScript` or `/JS` — embedded JavaScript
- `/OpenAction` or `/AA` — automatic actions on open
- `/Launch` — launch external applications
- `/EmbeddedFile` — embedded files (potential payloads)
- `/URI` — external URL references

## Safe Handling Practices

1. **Never open suspicious documents on production systems** — use isolated analysis VMs
2. **Disable macros by default** in Office applications
3. **Use command-line tools** (oletools, pdfid) for initial analysis rather than opening documents
4. **Extract and analyze macros** before considering dynamic analysis
5. **Check for exploits** — some maldocs exploit vulnerabilities rather than using macros

## Analyst Checklist

1. Identify the document format (OLE2, OOXML, RTF, PDF) using `file` and `oleid`
2. Run `olevba` to extract and display any VBA macro code
3. Review AutoExec triggers — does the macro run automatically when opened?
4. Identify obfuscation techniques and manually deobfuscate key strings
5. Extract IOCs (URLs, IPs, file paths, registry keys) from macro code
6. Use `oleobj` and `rtfobj` to extract embedded OLE objects
7. For PDFs, use `pdfid` and `pdf-parser` to identify JavaScript and embedded files
8. Document the full attack chain: open document -> macro executes -> downloads payload -> persistence
""",
    },
]

# ============================================================
# COLLECTIONS MANIFEST
# ============================================================

COLLECTIONS = [
    ("Disk & File System Forensics", "Comprehensive guides to disk imaging, file system analysis (NTFS/ext4), evidence preservation, file carving, registry forensics, journal analysis, and Volume Shadow Copy investigation.", DISK_FORENSICS),
    ("Memory Forensics & Analysis", "In-depth coverage of memory acquisition tools, Volatility 3 framework usage, process and DLL analysis, network connection extraction, code injection detection, rootkit hunting, and credential artifact recovery from memory dumps.", MEMORY_FORENSICS),
    ("Malware Analysis Fundamentals", "Foundational malware analysis skills including static and dynamic analysis workflows, PE file format internals, string extraction, YARA rules, import analysis, packer detection, sandbox methodology, anti-analysis awareness, and document malware examination.", MALWARE_ANALYSIS),
]
