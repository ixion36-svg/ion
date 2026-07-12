/*
 * ION default YARA ruleset for files carved from PCAP traffic.
 * Intentionally small and high-signal — extend with vetted rules as needed.
 * Air-gapped friendly: rules ship with ION, no feed download required.
 */

rule PE_Executable_DOS_Stub
{
    meta:
        description = "Windows PE executable (DOS stub present)"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $dos = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $dos
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell download/exec cradle in transferred content"
        severity = "high"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX" nocase
        $c = "FromBase64String" nocase
        $d = "-EncodedCommand" nocase
        $e = "Net.WebClient" nocase
    condition:
        2 of them
}

rule Mimikatz_Strings
{
    meta:
        description = "Mimikatz credential-theft tool strings"
        severity = "critical"
    strings:
        $a = "sekurlsa" nocase
        $b = "mimikatz" nocase
        $c = "gentilkiwi" nocase
        $d = "logonpasswords" nocase
    condition:
        any of them
}

rule CobaltStrike_Beacon_Markers
{
    meta:
        description = "Cobalt Strike beacon configuration / stager markers"
        severity = "critical"
    strings:
        $a = "%s as %s\\%s: %d"
        $b = "beacon.dll" nocase
        $c = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%s"
        $d = "ReflectiveLoader"
    condition:
        any of them
}
