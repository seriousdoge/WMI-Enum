using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;


namespace WMIConnect
{
    class Program
    {
        static void Main(string[] args)
        {
            if(args.Length != 4)
            {
                Console.WriteLine("Usage: enum_wmi.exe <username> <password> <IP> <domain_name>");
                return; 
            }
            
            Dictionary<string, string> edr = new Dictionary<string, string>();

            Dictionary<string, string> dlp = new Dictionary<string, string>();
            

            edr.Add("CylanceUI.exe", "Cylance");
            edr.Add("SylanceSvc.exe", "Cylance");
            edr.Add("WindowSsensor.exe", "Falcon");
            edr.Add("csagent.exe", "Falcon");
            edr.Add("Cb.exe", "Carbon Black");
            edr.Add("FSM32.exe", "F-Secure");
            edr.Add("SentinelAgent.exe", "Sentinel One");
            edr.Add("CyveraConsole.exe", "Palo Alto");
            edr.Add("kavss.exe", "KasperSky");
            edr.Add("MsMpEng.exe", "Windows Defender");
            edr.Add("dsa.exe", "Trend Micro");
            edr.Add("socar.exe", "Symantec");
            edr.Add("dsa_agent.exe", "Trend Micro");
            edr.Add("SMC.exe", "Symantec");
            edr.Add("SMCGui.exe", "Symantec");
            edr.Add("bdss.exe", "Bitdefender");
            
            // to do
            // dlp.Add("svchost.exe", "");         


            ConnectionOptions con = new ConnectionOptions();
            con.EnablePrivileges = true;
            con.Impersonation = ImpersonationLevel.Impersonate;
            con.Authentication = AuthenticationLevel.Packet;
            con.Authority = $"NTLMDOMAIN:{args[3]}";
            con.Username = args[0];
            con.Password = args[1];
            var remote_host = args[2];

            ManagementScope mscope= new ManagementScope($"\\\\{remote_host}\\root\\CIMV2", con);

            mscope.Connect();

            if (mscope.IsConnected == true)
            {
                System.Console.WriteLine("Connection Successful!");
            }
            else
            {
                System.Console.WriteLine("Connection Failed!");
            }

            ObjectQuery query = new ObjectQuery("Select * FROM Win32_Process");


            ManagementObjectSearcher searcher = new ManagementObjectSearcher(mscope, query);

            ManagementObjectCollection querycollection = searcher.Get();
            
            
            foreach(ManagementBaseObject q in querycollection)
            {
                
                foreach(var c in edr)
                {
                    
                    bool match = c.Key.Equals(q["Name"]);
                    
                    if(match)
                    {
                        Console.WriteLine($"Found EDR:{c.Value}, Process Name:{c.Key}, Process ID:{q["ProcessID"]}");
                        
                    }

                }

                /* to do foreach(var d in dlp.First().Value)
                {
                    bool match = d.Equals(q["Name"]);
                    

                    if(match)
                    {
                        Console.WriteLine($"Found DLP: {d}");
                    }

                } */

                System.Console.WriteLine($"{q["Name"]}, {q["ProcessID"]}");

            }
  
        }
    }
}
