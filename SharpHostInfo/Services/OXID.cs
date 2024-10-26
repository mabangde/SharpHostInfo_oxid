using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

namespace SharpHostInfo.Services
{
    public class OXID
    {
        const int TIME_OUT = 5000; // 5 seconds timeout
        static Dictionary<string, string> MACDict = new Dictionary<string, string>();

        public static Dictionary<string, List<string>> GetAddresses(string ip, byte[] buffer_v1, byte[] buffer_v2)
        {
            var result = new Dictionary<string, List<string>> { { ip, new List<string>() } };

            try
            {
                using (var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.ReceiveTimeout = TIME_OUT;
                    sock.SendTimeout = TIME_OUT;
                    sock.Connect(ip, 135);
                    //'[*] Used smb to detect 192.168.8.51:445'
                    //Console.WriteLine($"[*] {ip}");
                    Console.WriteLine($"[*] Used oxid to detect {ip}:135");

                    byte[] packet = new byte[1024];

                    // Send first buffer and receive response
                    sock.Send(buffer_v1);
                    int length = sock.Receive(packet);

                    // Send second buffer and receive response
                    sock.Send(buffer_v2);
                    packet = new byte[4096];
                    length = sock.Receive(packet);

                    // Process only if data length is sufficient
                    if (length > 42)
                    {
                        // Extract relevant part of the packet
                        byte[] packet_v2 = new byte[length - 42];
                        Array.Copy(packet, 42, packet_v2, 0, length - 42);

                        // Find the position of the end delimiter
                        int endPos = Array.IndexOf(packet_v2, (byte)0x09, 0);
                        if (endPos > 0 && endPos + 5 < packet_v2.Length &&
                            packet_v2[endPos + 1] == 0x00 &&
                            packet_v2[endPos + 2] == 0xFF &&
                            packet_v2[endPos + 3] == 0xFF &&
                            packet_v2[endPos + 4] == 0x00 &&
                            packet_v2[endPos + 5] == 0x00)
                        {
                            Array.Resize(ref packet_v2, endPos);
                        }

                        string packetStr = Encoding.ASCII.GetString(packet_v2);

                        // Split the data by double null characters
                        var hostnameList = packetStr.Split(new[] { "\x00\x00" }, StringSplitOptions.RemoveEmptyEntries);

                        foreach (var h in hostnameList)
                        {
                            string cleanedEntry = h.Replace("\x07\x00", "").Replace("\x00", "");
                            if (!string.IsNullOrEmpty(cleanedEntry))
                            {
                                result[ip].Add(cleanedEntry);
                                Console.WriteLine($"  [>] {cleanedEntry}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"Error connecting to {ip}: {ex.Message}");
                return null;
            }

            return result;
        }

        internal bool Execute(string ip, int port, int timeout)
        {
            byte[] buffer_v1 = new byte[] { 0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };
            byte[] buffer_v2 = new byte[] { 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00 };

            try
            {
                var addresses = GetAddresses(ip, buffer_v1, buffer_v2);
                if (addresses != null && addresses.ContainsKey(ip) && addresses[ip].Count > 0)
                {
                    // Here, you can convert the result to the appropriate format if needed
                    foreach (var address in addresses[ip])
                    {
                        // Assuming you want to store the first address as a string in MACDict
                        if (!MACDict.ContainsKey(ip))
                        {
                            MACDict[ip] = address;
                        }
                    }
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                // Console.WriteLine("[!] Error: {0} {1}", ip, ex.Message);
                return false;
            }
        }
    }
}
