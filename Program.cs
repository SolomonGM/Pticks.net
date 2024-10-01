using System;
using System.Collections.Generic;
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
                var elapsedTime = (DateTime.Now - startTime).TotalSeconds;

                // Placeholder for error information
                string errorInfo = ""; // Replace with actual error checking logic if needed

                // Create a new packet info entry
                var packetInfo = new PacketInfo
                {
                    SenderMAC = senderMac,
                    ReceiverMAC = receiverMac,
                    DataSize = dataSize,
                    TimeElapsed = Math.Round(elapsedTime, 2),
                    Errors = errorInfo
                };

                // Add packet info to the list
                packetInfos.Add(packetInfo);
                PrintPacketInfo(packetInfo);
            }
        }

        private static void PrintPacketInfo(PacketInfo packetInfo)
        {
            Console.Clear(); // Clear console for fresh output
            Console.WriteLine("Sender MAC Address | Receiver MAC Address | Data Size (bytes) | Time Elapsed (s) | Errors/Buffer Region");
            Console.WriteLine(new string('-', 100));

            foreach (var info in packetInfos)
            {
                Console.WriteLine($"{info.SenderMAC,-20} | {info.ReceiverMAC,-20} | {info.DataSize,-18} | {info.TimeElapsed,-16} | {info.Errors}");
            }
        }
    }

    public class PacketInfo
    {
        public string SenderMAC { get; set; }
        public string ReceiverMAC { get; set; }
        public int DataSize { get; set; }
        public double TimeElapsed { get; set; }
        public string Errors { get; set; }
    }
}
