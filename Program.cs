using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using PcapDotNet.Core;
using PcapDotNet.Packets;

namespace PacketMonitor
{
    class Program
    {
        private static List<PacketInfo> packetInfos = new List<PacketInfo>();
        private static DateTime startTime;

        static void Main(string[] args)
        {
            startTime = DateTime.Now;

            StartPacketCapture();
        }

        private static void StartPacketCapture()
        {
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            if (allDevices.Count == 0)
            {
                Console.WriteLine("No network devices found.");
                return;
            }

            var device = allDevices[0]; // Use the first device for simplicity
            using (var communicator = device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                Console.WriteLine("Listening on " + device.Description + "...");

                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        private static void PacketHandler(Packet packet)
        {
            // Check if the packet is an Ethernet packet
            var ethernetPacket = packet.Ethernet.IpV4; // Get the Ethernet layer directly
            if (ethernetPacket != null)
            {
                var senderMac = ethernetPacket.Source.ToString();
                var receiverMac = ethernetPacket.Destination.ToString();
                var dataSize = packet.Length;

                // Extract sender IP address
                var senderIp = ethernetPacket.Source.ToString();

                // Measure ping to the sender's IP
                long pingTime = PingNetwork(senderIp);

                // Convert ping time from ms to µs
                long pingTimeMicroseconds = pingTime >= 0 ? pingTime * 1000 : -1;

                // Categorize packet size
                string sizeCategory = CategorizePacketSize(dataSize);

                // Create a new packet info entry
                var packetInfo = new PacketInfo
                {
                    SenderMAC = senderMac,
                    ReceiverMAC = receiverMac,
                    DataSize = dataSize,
                    PingTime = pingTimeMicroseconds,
                    SizeCategory = sizeCategory
                };

                // Add packet info to the list
                packetInfos.Add(packetInfo);
                PrintPacketInfo(packetInfo);
            }
        }

        private static string CategorizePacketSize(int size)
        {
            // Define size thresholds (in bytes)
            const int smallThreshold = 64;  // Small packet size threshold
            const int bigThreshold = 1500;   // Big packet size threshold

            if (size < smallThreshold)
                return "Small";
            else if (size > bigThreshold)
                return "Big";
            else
                return "Normal";
        }

        private static long PingNetwork(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return -1; // Return -1 if IP address is null or empty

            using (var ping = new Ping())
            {
                try
                {
                    var reply = ping.Send(ipAddress);
                    return reply.RoundtripTime; // Return the ping time in milliseconds
                }
                catch (Exception)
                {
                    return -1; // Return -1 if the ping fails
                }
            }
        }

        private static void PrintPacketInfo(PacketInfo packetInfo)
        {
            Console.Clear(); // Clear console for fresh output
            Console.WriteLine("Sender MAC Address | Receiver MAC Address | Data Size (bytes) | Ping Time (µs) | Category");
            Console.WriteLine(new string('-', 100));

            foreach (var info in packetInfos)
            {
                Console.WriteLine($"{info.SenderMAC,-20} | {info.ReceiverMAC,-20} | {info.DataSize,-18} | {info.PingTime,-14} | {info.SizeCategory}");
            }
        }
    }

    public class PacketInfo
    {
        public string SenderMAC { get; set; }
        public string ReceiverMAC { get; set; }
        public int DataSize { get; set; }
        public long PingTime { get; set; } // Updated to represent microseconds
        public string SizeCategory { get; set; }
    }
}
