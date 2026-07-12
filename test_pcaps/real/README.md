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

## Fetch the large / all captures

```sh
base="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures"
cd test_pcaps/real
curl -sL -o smbtorture.cap.gz "$base/smbtorture.cap.gz" && gunzip -f smbtorture.cap.gz
# the smaller captures are committed; re-fetch any of them the same way, e.g.:
# curl -sL -o arp-storm.pcap "$base/arp-storm.pcap"
```
