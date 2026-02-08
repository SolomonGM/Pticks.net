# Pticks

A small C# console app that shows live IPv4 network traffic from a selected network adapter.

> Use only on networks/devices you own or have permission to monitor.

---

## What it does
- Lets you pick a network adapter
- Captures IPv4 packets in real time
- Displays a live table of recent packets:
  - time, IN/OUT direction, protocol (TCP/UDP/ICMP), IPs/ports, packet size, ping (if available)
- Tracks simple stats (total packets/bytes + top talkers)

---

## Requirements
- .NET 6+  
- NuGet packages:
  - `SharpPcap`
  - `PacketDotNet`
- Windows: install **Npcap** (recommended)

---

## Install & Run
```bash
dotnet new console -n PacketMonitorAdvanced
cd PacketMonitorAdvanced
dotnet add package SharpPcap
dotnet add package PacketDotNet
dotnet run
