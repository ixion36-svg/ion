# Real PCAP regression corpus

Genuine packet captures from external sources — **never** synthetic/self-generated.
Used by `tests/integration/test_pcap_real_corpus.py`, which asserts on evidence
surfaced by the analyser (finding categories/severities, MITRE techniques).

Why real only: ION's earlier synthetic `test_pcaps/` seeds were mislabeled
(`malicious_portscan.pcapng` held no scan, just a DCE/RPC endpoint-mapper
lookup), which gave false confidence. Detection quality is only trustworthy when
proven against real traffic.

## Captures (all from the Wireshark SampleCaptures wiki)

| File | Exercises |
|------|-----------|
| `smb-on-windows-10.pcapng` | SMB2/3, SMB1 hygiene, SMB2 CREATE filename, DCE/RPC srvsvc |
| `smbtorture.cap` | SMB1, carver false-positive guard, DCE/RPC lsarpc (**gitignored, 12 MB — fetch below**) |
| `smb3-aes-128-ccm.pcap` | encrypted SMB3 session |
| `arp-storm.pcap` | ARP spoofing (one MAC claiming many IPs) |
| `dns-remoteshell.pcap` | cleartext services riding the DNS port |
| `kpasswd_tcp.cap` | Kerberos password change (TCP/464) |
| `krb-816.cap` | Kerberos domain logon |
| `slammer.pcap` | Slammer worm DCE/RPC exploit (single packet) |

Tests skip gracefully if a capture is absent.

## Attack captures (`attack/` subdirectory)

Real adversary-tool captures from [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)
(MIT-licensed, MITRE-ATT&CK-mapped). These are the ground truth crafted PDUs
cannot provide — they exposed that WMI/DCSync ride a **dynamic** RPC port, not 135/445.

| File | Exercises |
|------|-----------|
| `LM_psexec_smb_dcerpc_epm_svcctl.pcapng` | PsExec: svcctl bind + service binary over SMB → Needs Investigation |
| `LM_smbexec_smb_dcerpc_svcctl_epm.pcapng` | smbexec: svcctl bind |
| `LM_WMI_ProcessCallCreate.pcapng` | WMI lateral movement (IWbemServices on a dynamic port) |
| `DCSync_krbtgt_dcerpc_smb.pcapng` | DCSync over **encrypted** RPC — documented blind spot (UUID not in cleartext) |
| `CA_kerbrute_passwordspray_kerberos_AS-REQ.pcapng` | Kerberos AS-REQ password spray (future #13) |
| `lm_mimikazt_skeleton_kerberos_rc4_etype.pcapng` | Kerberos RC4 etype / skeleton key (future #13) |

## Fetch the large / all captures

```sh
base="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures"
cd test_pcaps/real
curl -sL -o smbtorture.cap.gz "$base/smbtorture.cap.gz" && gunzip -f smbtorture.cap.gz
# the smaller captures are committed; re-fetch any of them the same way, e.g.:
# curl -sL -o arp-storm.pcap "$base/arp-storm.pcap"
```
