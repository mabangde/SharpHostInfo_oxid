using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using SharpHostInfo.Argument;
using SharpHostInfo.Helpers;
using SharpHostInfo.Lib;
using SharpHostInfo.Services;

namespace SharpHostInfo
{
    class Program
    {
        private static void MainExecute(ParserContent parsedArgs)
        {
            Info.ShowLogo();
            Writer.Info($"Detect target: {parsedArgs.Target}");
            Writer.Info($"Detect Service: {parsedArgs.Service}");
            Writer.Info($"Detect thread: {parsedArgs.Thread}");
            Writer.Info($"Detect timeout: {parsedArgs.Timeout}ms");

            int timeout = Convert.ToInt32(parsedArgs.Timeout);
            HashSet<string> ips = TargetParser.Parser(parsedArgs.Target);
            if (ips.Count < 1)
            {
                Writer.Error("The parsed detection target is empty");
                return;
            }
            string service = parsedArgs.Service.ToLower();
            Dictionary<string, string> macdict = Options.GetMACDict();

            ThreadPool.SetMaxThreads(Options.SetMaxThreads(parsedArgs), 1);

            // NBNS服务探测
            if (service.Contains("nbns"))
            {
                var nbnsCount = new CountdownEvent(ips.Count);
                Console.WriteLine("");
                Writer.Info("Start NBNS service detection\r\n");
                foreach (string ip in ips)
                {
                    ThreadPool.QueueUserWorkItem(status =>
                    {
                        NBNS nbns = new NBNS();
                        nbns.Execute(ip, 137, timeout, macdict);
                        nbnsCount.Signal();
                    });
                }
                nbnsCount.Wait();
            }

            // SMB服务探测
            var failedSet = new HashSet<string>(ips);
            if (service.Contains("smb"))
            {
                var smbCount = new CountdownEvent(ips.Count);
                Console.WriteLine("");
                Writer.Info("Start SMB service detection\r\n");
                foreach (string ip in ips)
                {
                    ThreadPool.QueueUserWorkItem(status =>
                    {
                        SMB smb = new SMB();
                        bool success = smb.Execute(ip, 445, timeout);
                        if (success)
                        {
                            lock (failedSet)
                            {
                                failedSet.Remove(ip);
                            }
                        }
                        smbCount.Signal();
                    });
                }
                smbCount.Wait();
            }

            // WMI服务探测 - 仅对在 SMB 探测中失败的地址执行
            if (service.Contains("wmi") && failedSet.Count > 0)
            {
                var WMICount = new CountdownEvent(failedSet.Count);
                Console.WriteLine("");
                Writer.Info("Start WMI service detection\r\n");
                foreach (string ip in failedSet)
                {
                    ThreadPool.QueueUserWorkItem(status =>
                    {
                        WMI wmi = new WMI();
                        wmi.Execute(ip, 135, timeout);
                        WMICount.Signal();
                    });
                }
                WMICount.Wait();
            }

            // OXID服务探测 - 无论前面的服务是否成功，始终执行 OXID 检测
            if (service.Contains("oxid"))
            {
                var OXIDCount = new CountdownEvent(ips.Count);
                Console.WriteLine("");
                Writer.Info("Start OXID detection\r\n");

                foreach (string ip in ips)
                {
                    ThreadPool.QueueUserWorkItem(status =>
                    {
                        OXID oxid = new OXID();
                        oxid.Execute(ip, 135, timeout);
                        OXIDCount.Signal();
                    });
                }
                OXIDCount.Wait();
            }
        }

        static void Main(string[] args)
        {
            if (args.Length < 1 || args.Contains("-h") || args.Contains("--help"))
            {
                Info.ShowLogo();
                Info.ShowUsage();
                return;
            }

            var parsed = Parser.Parse(args);
            if (!parsed.ParsedOk)
            {
                Info.ShowLogo();
                Info.ShowUsage();
                return;
            }

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            MainExecute(parsed.Arguments);
            stopwatch.Stop();
            TimeSpan timespan = stopwatch.Elapsed;
            Writer.Info($"Time taken: {timespan.TotalSeconds}s");
        }
    }
}
