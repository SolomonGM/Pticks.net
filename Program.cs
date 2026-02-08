using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;

namespace PacketMonitorAdvanced
{
    internal static class Program
    {
        // Keep the last N packets for display
        private const int PacketBufferCapacity = 200;
        private const int DisplayLastNPackets = 25;

        private static readonly FixedSizeConcurrentQueue<PacketRow> PacketBuffer =
            new(capacity: PacketBufferCapacity);

        private static readonly ConcurrentDictionary<string, TalkerStats> Talkers =
            new(StringComparer.OrdinalIgnoreCase);

        private static readonly ConcurrentDictionary<string, PingCacheEntry> PingCache =
            new(StringComparer.OrdinalIgnoreCase);

        private static readonly StatsCounters Counters = new();

        // Background ping queue (rate-limited / cached)
        private static readonly Channel<string> PingQueue = Channel.CreateUnbounded<string>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });

        private static async Task Main()
        {
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            try
            {
                var devices = CaptureDeviceList.Instance;
                if (devices.Count == 0)
                {
                    Console.WriteLine("No capture devices found. Ensure Npcap/libpcap is installed.");
                    return;
                }

                Console.WriteLine("Available network capture devices:");
                for (int i = 0; i < devices.Count; i++)
                {
                    Console.WriteLine($"[{i}] {devices[i].Description}");
                }

                int selectedIndex = ReadDeviceIndex(devices.Count);
                var device = devices[selectedIndex];

                // Determine local IPv4 on this adapter
                var localIp = TryGetLocalIPv4ForDevice(device);
                if (localIp is null)
                {
                    Console.WriteLine("Could not determine a local IPv4 address for this adapter.");
                    Console.WriteLine("You can still capture, but the default 'local only' filter cannot be applied.");
                }

                // Open in Normal mode (non-promiscuous) by default for safer/cleaner behaviour.
                // If you genuinely need promiscuous mode for authorised troubleshooting, change to DeviceModes.Promiscuous.
                device.Open(mode: DeviceModes.Normal, read_timeout: 1000);

                // Apply a safe default BPF filter: ONLY traffic to/from local IP (IPv4 only).
                // This avoids unintentionally capturing other hosts' traffic.
                if (localIp is not null)
                {
                    string filter = $"ip and (src host {localIp} or dst host {localIp})";
                    device.Filter = filter;
                }

                Console.Clear();
                Console.WriteLine("Capturing... Press Ctrl+C to stop.");
                Console.WriteLine(localIp is null
                    ? "Filter: (none)"
                    : $"Filter: IPv4 traffic to/from {localIp}");

                // Start background workers
                var pingWorker = RunPingWorkerAsync(cts.Token);
                var uiWorker = RunUiAsync(localIp, cts.Token);

                // Wire capture handler
                device.OnPacketArrival += (_, e) => OnPacketArrival(e, localIp);

                // Start capture
                device.StartCapture();

                // Wait until cancelled
                while (!cts.IsCancellationRequested)
                    await Task.Delay(250, cts.Token).ContinueWith(_ => { });

                // Stop capture cleanly
                device.StopCapture();
                device.Close();

                // Complete ping queue and await workers
                PingQueue.Writer.TryComplete();
                await Task.WhenAll(pingWorker, uiWorker);
            }
            catch (OperationCanceledException)
            {
                // normal shutdown
            }
            catch (Exception ex)
            {
                Console.WriteLine("Fatal error:");
                Console.WriteLine(ex);
            }
        }

        private static int ReadDeviceIndex(int deviceCount)
        {
            while (true)
            {
                Console.Write("Select device index: ");
                var input = Console.ReadLine();
                if (int.TryParse(input, out int idx) && idx >= 0 && idx < deviceCount)
                    return idx;

                Console.WriteLine("Invalid index. Try again.");
            }
        }

        private static IPAddress? TryGetLocalIPv4ForDevice(ICaptureDevice device)
        {
            // Best-effort: use SharpPcap addresses if available (works well on many setups)
            try
            {
                var addrs = device.Addresses;
                foreach (var a in addrs)
                {
                    var ip = a.Addr?.ipAddress;
                    if (ip is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetwork })
                        return ip;
                }
            }
            catch
            {
                // ignore and fall back
            }

            // Fallback: pick first non-loopback IPv4 from NetworkInterfaces
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;

                    var props = nic.GetIPProperties();
                    var ipv4 = props.UnicastAddresses
                        .Select(u => u.Address)
                        .FirstOrDefault(a =>
                            a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                            !IPAddress.IsLoopback(a));

                    if (ipv4 != null)
                        return ipv4;
                }
            }
            catch
            {
                // ignore
            }

            return null;
        }

        private static void OnPacketArrival(PacketCapture capture, IPAddress? localIp)
        {
            try
            {
                var raw = capture.GetPacket();
                var time = raw.Timeval.Date;
                var length = raw.Data.Length;

                var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

                // Ethernet
                var eth = packet.Extract<EthernetPacket>();
                var srcMac = eth?.SourceHardwareAddress?.ToString() ?? "?";
                var dstMac = eth?.DestinationHardwareAddress?.ToString() ?? "?";

                // IPv4
                var ipv4 = packet.Extract<IPv4Packet>();
                if (ipv4 == null)
                {
                    Counters.NonIpv4Packets.Add(1);
                    Counters.TotalPackets.Add(1);
                    Counters.TotalBytes.Add(length);
                    return;
                }

                string srcIp = ipv4.SourceAddress.ToString();
                string dstIp = ipv4.DestinationAddress.ToString();

                // Identify L4
                var tcp = packet.Extract<TcpPacket>();
                var udp = packet.Extract<UdpPacket>();
                var icmp = packet.Extract<IcmpV4Packet>();

                string proto;
                int? srcPort = null;
                int? dstPort = null;

                if (tcp != null)
                {
                    proto = "TCP";
                    srcPort = tcp.SourcePort;
                    dstPort = tcp.DestinationPort;
                    Counters.TcpPackets.Add(1);
                }
                else if (udp != null)
                {
                    proto = "UDP";
                    srcPort = udp.SourcePort;
                    dstPort = udp.DestinationPort;
                    Counters.UdpPackets.Add(1);
                }
                else if (icmp != null)
                {
                    proto = "ICMP";
                    Counters.IcmpPackets.Add(1);
                }
                else
                {
                    proto = "IP";
                    Counters.OtherIpPackets.Add(1);
                }

                // Direction (best-effort)
                var direction = "UNK";
                if (localIp != null)
                {
                    if (srcIp == localIp.ToString()) direction = "OUT";
                    else if (dstIp == localIp.ToString()) direction = "IN";
                }

                // Update aggregates
                Counters.TotalPackets.Add(1);
                Counters.TotalBytes.Add(length);

                Talkers.AddOrUpdate(
                    key: srcIp,
                    addValueFactory: _ => new TalkerStats(packets: 1, bytes: length),
                    updateValueFactory: (_, cur) => cur.AddPacket(length));

                // Queue ping (cached + rate-limited in worker)
                MaybeEnqueuePing(srcIp);

                // Attach ping if we have cached result
                long pingUs = GetCachedPingMicroseconds(srcIp);

                // Buffer for UI
                PacketBuffer.Enqueue(new PacketRow(
                    time: time,
                    direction: direction,
                    protocol: proto,
                    srcMac: srcMac,
                    dstMac: dstMac,
                    srcIp: srcIp,
                    dstIp: dstIp,
                    srcPort: srcPort,
                    dstPort: dstPort,
                    bytes: length,
                    pingUs: pingUs
                ));
            }
            catch
            {
                // Swallow per-packet errors to keep capture running
            }
        }

        private static void MaybeEnqueuePing(string ip)
        {
            // Don’t ping private/loopback/multicast/invalid addresses, and don’t spam pings.
            if (!IPAddress.TryParse(ip, out var addr)) return;
            if (IPAddress.IsLoopback(addr)) return;
            if (addr.IsIPv6Multicast) return;

            var now = DateTime.UtcNow;
            var entry = PingCache.GetOrAdd(ip, _ => new PingCacheEntry(lastAttemptUtc: DateTime.MinValue, rttMs: null));

            // Ping at most once every 10 seconds per IP
            if ((now - entry.LastAttemptUtc).TotalSeconds < 10) return;

            PingCache[ip] = entry with { LastAttemptUtc = now };

            // Best effort enqueue
            PingQueue.Writer.TryWrite(ip);
        }

        private static long GetCachedPingMicroseconds(string ip)
        {
            if (!PingCache.TryGetValue(ip, out var entry)) return -1;
            if (entry.RttMs is null) return -1;
            return entry.RttMs.Value * 1000L;
        }

        private static async Task RunPingWorkerAsync(CancellationToken ct)
        {
            // Single reader, so we control ping rate centrally.
            using var ping = new Ping();

            while (await PingQueue.Reader.WaitToReadAsync(ct))
            {
                while (PingQueue.Reader.TryRead(out var ip))
                {
                    if (ct.IsCancellationRequested) return;

                    int? rtt = null;
                    try
                    {
                        var reply = await ping.SendPingAsync(ip, 800);
                        if (reply.Status == IPStatus.Success)
                            rtt = (int)reply.RoundtripTime;
                    }
                    catch
                    {
                        // ignore
                    }

                    if (PingCache.TryGetValue(ip, out var existing))
                    {
                        PingCache[ip] = existing with { RttMs = rtt };
                    }
                    else
                    {
                        PingCache[ip] = new PingCacheEntry(DateTime.UtcNow, rtt);
                    }

                    // Gentle global rate limit
                    await Task.Delay(50, ct);
                }
            }
        }

        private static async Task RunUiAsync(IPAddress? localIp, CancellationToken ct)
        {
            // Refresh once per second
            while (!ct.IsCancellationRequested)
            {
                RenderConsole(localIp);
                await Task.Delay(1000, ct).ContinueWith(_ => { });
            }
        }

        private static void RenderConsole(IPAddress? localIp)
        {
            Console.SetCursorPosition(0, 0);

            var totalPackets = Counters.TotalPackets.Value;
            var totalBytes = Counters.TotalBytes.Value;

            // Top talkers by bytes
            var topTalkers = Talkers
                .OrderByDescending(kv => kv.Value.Bytes)
                .Take(5)
                .Select(kv => $"{kv.Key} ({kv.Value.Bytes}B/{kv.Value.Packets}p)")
                .ToList();

            string header =
                $"Packet Monitor (local-only filter: {(localIp?.ToString() ?? "none")})\n" +
                $"Total: {totalPackets:n0} packets | {totalBytes:n0} bytes\n" +
                $"IPv4 breakdown: TCP {Counters.TcpPackets.Value:n0} | UDP {Counters.UdpPackets.Value:n0} | ICMP {Counters.IcmpPackets.Value:n0} | OtherIP {Counters.OtherIpPackets.Value:n0} | Non-IPv4 {Counters.NonIpv4Packets.Value:n0}\n" +
                $"Top talkers: {(topTalkers.Count == 0 ? "—" : string.Join(" | ", topTalkers))}\n" +
                new string('-', 140) + "\n";

            Console.Write(header);

            Console.WriteLine(
                $"{Pad("Time", 12)} {Pad("Dir", 3)} {Pad("Proto", 5)} {Pad("SrcIP:Port", 28)} {Pad("DstIP:Port", 28)} {Pad("Bytes", 7)} {Pad("Ping(µs)", 10)}  SrcMAC -> DstMAC");
            Console.WriteLine(new string('-', 140));

            var rows = PacketBuffer.Snapshot().TakeLast(DisplayLastNPackets).ToList();
            foreach (var r in rows)
            {
                string time = r.Time.ToString("HH:mm:ss.fff");
                string src = r.SrcPort.HasValue ? $"{r.SrcIp}:{r.SrcPort}" : r.SrcIp;
                string dst = r.DstPort.HasValue ? $"{r.DstIp}:{r.DstPort}" : r.DstIp;
                string ping = r.PingUs < 0 ? "—" : r.PingUs.ToString();

                Console.WriteLine(
                    $"{Pad(time, 12)} {Pad(r.Direction, 3)} {Pad(r.Protocol, 5)} {Pad(src, 28)} {Pad(dst, 28)} {Pad(r.Bytes.ToString(), 7)} {Pad(ping, 10)}  {r.SrcMac} -> {r.DstMac}");
            }

            // Clear remaining lines if the previous frame was longer
            Console.WriteLine("\nPress Ctrl+C to stop.");
        }

        private static string Pad(string s, int width)
        {
            if (s.Length == width) return s;
            if (s.Length > width) return s.Substring(0, width);
            return s.PadRight(width);
        }

        // ---- Models / helpers ----

        private readonly record struct PacketRow(
            DateTime Time,
            string Direction,
            string Protocol,
            string SrcMac,
            string DstMac,
            string SrcIp,
            string DstIp,
            int? SrcPort,
            int? DstPort,
            int Bytes,
            long PingUs
        );

        private readonly record struct TalkerStats(long Packets, long Bytes)
        {
            public TalkerStats AddPacket(int bytes) => this with { Packets = Packets + 1, Bytes = Bytes + bytes };
        }

        private readonly record struct PingCacheEntry(DateTime LastAttemptUtc, int? RttMs);

        private sealed class StatsCounters
        {
            public AtomicLong TotalPackets { get; } = new();
            public AtomicLong TotalBytes { get; } = new();

            public AtomicLong TcpPackets { get; } = new();
            public AtomicLong UdpPackets { get; } = new();
            public AtomicLong IcmpPackets { get; } = new();
            public AtomicLong OtherIpPackets { get; } = new();
            public AtomicLong NonIpv4Packets { get; } = new();
        }

        private sealed class AtomicLong
        {
            private long _value;
            public long Value => Interlocked.Read(ref _value);
            public void Add(long delta) => Interlocked.Add(ref _value, delta);
        }

        private sealed class FixedSizeConcurrentQueue<T>
        {
            private readonly ConcurrentQueue<T> _q = new();
            private readonly int _capacity;

            public FixedSizeConcurrentQueue(int capacity)
            {
                if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
                _capacity = capacity;
            }

            public void Enqueue(T item)
            {
                _q.Enqueue(item);
                while (_q.Count > _capacity && _q.TryDequeue(out _)) { }
            }

            public IReadOnlyList<T> Snapshot()
            {
                // Snapshot for UI (safe enough for display purposes)
                return _q.ToArray();
            }
        }
    }
}
