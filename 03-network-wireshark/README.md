# Network Traffic Analysis with Wireshark

Hands-on packet analysis from a SOC Level 1 perspective. The project starts by learning what **normal** DNS, TCP and HTTP traffic looks like, then moves on to recognising the **attacks** an analyst sees day to day.

## Lab environment

| Component | Details |
|---|---|
| Analysis / attacker machine | Kali Linux VM (VirtualBox) |
| Adapter 1 (`eth0`) | NAT, `10.0.2.15`, internet access, used for the captures below |
| Adapter 2 (`eth1`) | Host-only, used for attack tasks between VMs |
| Target for later tasks | Ubuntu Server VM (nginx, SSH) |
| Tools | Wireshark, nslookup, curl 8.19.0 |

> All attack simulations (Tasks 4 to 9) are run only against my own VMs on an isolated Host-only network.

## Roadmap

| # | Task | Status |
|---|---|---|
| 1 | DNS (baseline) | Done |
| 2 | TCP handshake and teardown (baseline) | Done |
| 3 | HTTP (baseline) | Done |
| 4 | Port scan (nmap SYN scan) | Planned |
| 5 | Brute force (SSH / HTTP login) | Planned |
| 6 | Cleartext credentials | Planned |
| 7 | DNS tunneling / exfiltration | Planned |
| 8 | ARP spoofing / MITM | Planned |
| 9 | SYN flood (DoS) | Planned |
| 10 | C2 beaconing (real malware PCAP) | Planned |

---

## Task 1: DNS

### Objective
Capture DNS lookups and identify the structure of a query and response, so that abnormal DNS (tunneling, exfiltration) can be recognised later.

### Method
1. Started a Wireshark capture on `eth0`.
2. Ran lookups from the Kali terminal:
   ```
   nslookup google.com
   nslookup -type=MX google.com
   ```
3. Stopped the capture, applied the `dns` filter and exported the displayed packets to `captures/dns.pcapng` (8 packets).

### Filters used

| Filter / feature | Purpose |
|---|---|
| `dns` | Show only DNS packets |
| `udp.stream eq 0` (right-click > Follow > UDP Stream) | Isolate one query/response conversation |

### Findings

| Packets | Query | Result |
|---|---|---|
| 1-2 | `A google.com` (ID `0xb308`) | `142.251.42.110` |
| 3-4 | `AAAA google.com` (ID `0xe20c`) | `2404:6800:4006:805::200e` |
| 5-6 | `MX` lookup (second MX query) | Response returned |
| 7-8 | `MX google.com` (ID `0xa393`) | `10 smtp.google.com` |

- **Transport:** UDP, destination port 53, random high source port (for example 58147 and 40412).
- **Resolver:** the home router at `192.168.1.1`, reached through the VirtualBox NAT. nslookup reported **"Non-authoritative answer"**, meaning the recursive resolver answered, not the domain's own nameserver.
- **Query header:** flags `0x0100` (standard query, recursion desired), 1 question, and 0 answer, authority and additional records.
- **Response time:** about 30 to 37 ms per lookup.
- **Response size:** the `MX` response is 283 bytes, against 86 to 98 bytes for A and AAAA, because it also carries the address records of the mail server.
- **Follow UDP Stream:** 1 client packet, 1 server packet, 72 bytes, with the domain name visible in plain text. Standard DNS is unencrypted, so anyone on the path can see which names a host looks up.

### Analyst notes
This is a clean baseline: short names, mostly A, AAAA and MX records, low volume, answers returned. Things that would stand out against it:
- Very long or random-looking subdomains (tunneling, see Task 7)
- Unusually high query volume to a single domain
- Many TXT queries
- Bursts of `NXDOMAIN` responses (domain generation algorithms)
- Hosts querying a resolver other than the corporate one

---

## Task 2: TCP handshake and teardown

### Objective
Observe a complete TCP connection lifecycle, and an abandoned one, to build the baseline for spotting scans and floods.

### Method
1. Started a capture on `eth0`.
2. Ran `curl -I http://google.com`, which opens a connection to port 80, sends a `HEAD` request and closes.
3. Stopped the capture (41 packets in total).

### Filters used

| Filter / feature | Purpose |
|---|---|
| `tcp.port == 80` | All HTTP-port traffic from the command |
| `tcp.port == 45066` | The complete IPv6 connection |
| `tcp.stream eq 1` | The abandoned IPv4 connection |
| Statistics > Flow Graph (with "Limit to display filter") | Visual handshake and teardown |

### Findings: connection A (IPv6, source port 45066, complete)

| Time (s) | Packet | Flags |
|---|---|---|
| 0.0366 | Client to server | **SYN**, Seq=0, Win=64800 |
| 0.2438 | Server to client | **SYN, ACK**, Seq=0, Ack=1, Win=65535 |
| 0.2442 | Client to server | **ACK**, Seq=1, Ack=1 (connection established) |
| 0.2447 | Client to server | `HEAD / HTTP/1.1` (75 bytes) |
| 0.2457 | Server to client | ACK, Ack=76 |
| 0.4570 | Server to client | `HTTP/1.1 301 Moved Permanently` (554 bytes) |
| 0.4572 | Client to server | ACK, Ack=555 |
| 0.4580 | Client to server | **FIN, ACK** |
| 0.4589 | Server to client | ACK |
| 0.4920 | Server to client | **FIN, ACK** |
| 0.4920 | Client to server | ACK (connection closed) |

- Three-way handshake: **SYN, SYN-ACK, ACK**, with relative sequence numbers starting at 0. Time from SYN to SYN-ACK was about 207 ms.
- Four-way teardown: **FIN-ACK, ACK, FIN-ACK, ACK**.
- Sequence and acknowledgment numbers track the bytes sent: 75 bytes of request moved Ack from 1 to 76, and 554 bytes of response moved it from 1 to 555.

### Findings: connection B (IPv4, source port 43704, abandoned)

| Time (s) | Packet | Flags |
|---|---|---|
| 0.2426 | Client to server | **SYN**, Win=64240, MSS=1460, SACK_PERM |
| 0.2703 | Server to client | **SYN, ACK**, Win=65535, MSS=1460 |
| 0.2704 | Client to server | **RST**, Seq=1, Win=0 |

curl started the IPv4 attempt about 200 ms after the IPv6 SYN (the "Happy Eyeballs" fallback), kept whichever connected first, and reset the other. This is legitimate behaviour, but it produces the same SYN, SYN-ACK, RST pattern that a port scan does.

### Analyst notes
- One reset after a SYN-ACK is routine noise. The same SYN, SYN-ACK, RST pattern repeated across many ports from one source is the signature of a half-open SYN scan (Task 4).
- A healthy connection closes with FIN/ACK exchanges. Frequent RSTs, or many SYNs with no completed handshake, are worth investigating.

---

## Task 3: HTTP

### Objective
Read an HTTP request and response in the capture and note what cleartext HTTP exposes.

### Method
Same capture as Task 2. Followed the HTTP stream of the `HEAD` request.

### Filters used

| Filter / feature | Purpose |
|---|---|
| `http` | Show only HTTP messages |
| `tcp.stream eq 0` (right-click > Follow > HTTP Stream) | Show the whole request and response as text |

### Findings

**Request**
```
HEAD / HTTP/1.1
Host: google.com
User-Agent: curl/8.19.0
Accept: */*
```

**Response (headers)**
```
HTTP/1.1 301 Moved Permanently
Location: http://www.google.com/
Content-Type: text/html; charset=UTF-8
Server: gws
Content-Length: 219
Cache-Control: public, max-age=2592000
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
```
Plus `Date`, `Expires` and a report-only `Content-Security-Policy` header.

- `HEAD` asks for headers only, so no body was transferred.
- `301` is a permanent redirect to `www.google.com`.
- Total conversation: 629 bytes, all readable as plain text.
- The `User-Agent` reveals the client software (curl 8.19.0), and the `Server` header reveals the server software.

### Analyst notes
- Everything above, including headers, cookies and form data, is visible to anyone on the network path. This is why cleartext credentials over HTTP (Task 6) are such a common finding.
- Useful fields when triaging HTTP: `User-Agent` (scripted tools often show `curl`, `python-requests` or empty values), `Host`, URI, response code and size.

---

## Filter reference

| Filter | Meaning |
|---|---|
| `dns` | All DNS traffic |
| `udp.stream eq N` | One UDP conversation |
| `tcp.port == 80` | TCP traffic to or from port 80 |
| `tcp.port == N` | One specific connection by port |
| `tcp.stream eq N` | One TCP conversation |
| `http` | HTTP messages only |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | SYN-only packets (used for scan detection in Task 4) |
| `tcp.flags.reset==1` | Reset packets |

## Repository layout

```
03-network-wireshark/
├── README.md
├── captures/
│   ├── dns.pcapng
│   └── tcp-http.pcapng
└── screenshots/
```

## Screenshots

| Task | Screenshot |
|---|---|
| 1 | ![nslookup output](screenshots/01-nslookup-terminal.png) |

| 1 | ![DNS packet list](screenshots/02-dns-packet-list.png) |

| 1 | ![DNS query detail](screenshots/03-dns-query-detail.png) | 

| 1 | ![Follow UDP stream](screenshots/04-dns-follow-udp-stream.png) |

| 2 | ![curl command](screenshots/05-curl-head-terminal.png) |

| 2 | ![tcp.port == 80](screenshots/06-tcp-port-80.png) |

| 2 | ![Abandoned IPv4 connection](screenshots/07-tcp-rst-ipv4-stream.png) |

| 2 | ![Complete handshake and teardown](screenshots/08-tcp-handshake-teardown.png) |

| 2 | ![Flow graph](screenshots/09-tcp-flow-graph.png) |

| 3 | ![Follow HTTP stream](screenshots/10-http-follow-stream.png) 

