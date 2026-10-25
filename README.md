# Dataplane Router

The forwarding part (data plane) of an IPv4 router, written in C on top of raw Ethernet frames. It parses and builds Ethernet, ARP, IPv4 and ICMP headers by hand. It does longest-prefix-match routing with a binary trie, resolves next hops with ARP and queues packets while it waits, and sends the ICMP replies and errors a real router would.

## Why this matters for security

Network pentesting comes down to understanding packets at the byte level. This router builds and checks every header itself:

- **ARP from both sides.** It answers ARP requests for its own interfaces, sends broadcast requests for unknown next hops, and learns MAC addresses from replies. Trusting unsolicited ARP replies like this is exactly what **ARP spoofing / MITM** attacks abuse.
- **Header integrity.** IPv4 checksums are verified on every packet and recomputed after the TTL is decremented. Bad packets are dropped.
- **TTL and ICMP Time Exceeded.** Packets with an expired TTL are dropped and answered with ICMP type 11. This is the mechanism `traceroute` uses to map network paths.
- **ICMP Destination Unreachable and Echo.** Packets with no route get ICMP type 3, and pings to the router get an Echo Reply. These are the responses that host discovery and network mapping tools rely on.
- **Raw packet crafting.** Every reply is built byte by byte (Ethernet, IP and ICMP headers plus the quoted original header), the same work as crafting packets with Scapy or raw sockets.

## Features

- **Longest-prefix match with a binary trie.** The routing table is loaded into a 32-level binary trie, one level per address bit. A lookup walks the destination address bit by bit and remembers the deepest matching prefix, taking O(32) time instead of a linear scan over the table.
- **ARP resolution with a packet queue.** Packets whose next-hop MAC is unknown are queued, an ARP request is broadcast, and the queue is flushed when the reply arrives.
- **Forwarding.** Checks checksum and TTL, finds the route, rewrites the Ethernet source and destination, and sends the packet out the right interface.
- **ICMP.** Echo Reply, Destination Unreachable (no route) and Time Exceeded (TTL expired).

## Build

```sh
make
```

Requirements: `gcc`, `make`.

The router is meant to run inside an emulated network (Mininet) with hosts and a routing table file:

```sh
./router rtable0.txt rr-0-1 r-0 r-1
```

The Mininet topology and routing tables came from the course and are not included here. The implementation scored **100/100** on the course test suite, which covers forwarding, LPM, ARP, ICMP and checksum and TTL handling.

## Layout

```
router.c        packet processing, trie, ARP and ICMP
include/        protocol header structs and helpers
lib/            interface I/O, queue and list helpers
```

## Context

Built for the Communication Protocols course at the National University of Science and Technology POLITEHNICA Bucharest. The packet I/O library and header definitions come from the course; `router.c` is my own work.
