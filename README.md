# DareDevil
Stealthy Loader-cum-dropper/stage-1/stager targeting Windows10

# DOs:
Remove Looper.....


### Technology behind Insider:
![](<img>)

### Ability:
Apart from the shown diagram other abilties are:
1. Sensitive string Obfuscation: Needed ! => Dinvoke and dll names (Update encrypt.cs)
2. All function call obfuscation => loadlibrary and GetProcAddress => DInvoke
3. Abilty to detect and detach from debugger by using, NtQueryInformationProcess() and NtRemoveProcessDebug() respectively.

### Tools usage:

- Obfuscator/encrypt.cs:
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

- stage2/remotewrite.cs:
Why I made RemoteWrite.cs?
```
1. If I wanted to make this loader_cum_dropper invisible (compilation: csc.exe /target:winexe /platform:x64 /out:Insider.exe  .\Insider.cs), the enumerated process name and process id, made by it, can't be seen by me.
2. I also can't create a file on disk, it will not be OPSEC safe.
3. So, I exfiltrate those enumerated process names and ids via Gmail's SMTP server, by sending a string (full of process names and process ids, all appended together).
4. After getting the gmail, the operator will choose the pid, he/she want to victimise.
5. Then he/she will create a `pid.txt` file with target pid written in it and then host it in payload server/ C2 server of his/her choice.
6. Until our loader_cum_dropper gets pid from url containing pid.txt, it will keep on retrying.
7. From there, our dropper will read those pid and perform injection.
```
In this way, I made un-interactive program, interactive.

- stage2/mscorlib.cs:
It is the re-implementation of AMSI and ETW bypass done in [SharpSploit](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/ETW.cs) and [AmsiScanBufferBypass](https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/main/AmsiBypass.cs) by [@RastaMouse](https://twitter.com/_rastamouse?lang=en). It was actually covered by [@Jean_Maes_1994](https://twitter.com/jean_maes_1994) in his workshop in <ins>SANS Offensive</ins>.

- stage1/{ }/Insider.cs:
Usage:
```
1. I have used Developer Powershell/cmd for VS 2019
2. cmd> git clone https://github.com/reveng007/DareDevil
3. Compile: Obfuscator/encrypt.cs with compile.bat, stage2/remotewrite.cs with compile_remotewrite.bat (but at first write the credentials of sender's and receiver's/Operator's gmail) and stage2/mscorlib.cs with compile_mscorlib.bat.
4. Now upload/ host those two stage2 in payload server/ github(github: because it will not be considered as malicious as it is considered to be a legitimate website. So, malware traffic from github will not be considered as creepy stuff, instead of that, it would be considered as legitimate).
5. Encrypt those two urls using "Obfuscator/encrypt.exe" file with the previously mentioned flags and use those in "stage1/{ }/Insider.cs".
6. Encrypt your shellcode, by following my previously mentioned flags in "Obfuscator/encrypt.exe" section and paste the encrypted shellcode in a text file host it in payload server/ github. Then again encrypt that url with "Obfuscator/encrypt.exe" and paste that in "stage1/{ }/Insider.cs".
7. Now, compile the "stage1/{ }/Insider.cs" with compile.bat and put it in an antivirus enabled windows 10 nad test it.
```
#### NOTE:
I have named AMSI&ETW bypass .NET Assembly as mscorlib because if by chance, it is seen by an Blue Teamer and if that particular member is less experienced, the name `"mscorlib"` can bamboozle, making them think, "Hey, yes!! a .NET binary always loads up something called, mscorlib. It contains the core implementation of the .NET framework." Though there is very little chance of our mscorlib.exe of getting caught running as a process in memory as it is visible a very little amount of time in process memory unless our dropper is getting debugged ;(.

### Video:
[video]

### Internal Noticing:

- Only ProcessHacker:

[processhacker0: Video]

I saw that even after providing Read-Execute permission to the allocated shellcode memory region, it wasn't shown as RX in ProcessHacker. Strangely enough, the bool value for VirtualProtectEx was also ***True*** while protecting target process memory with 0x20 (PAGE_EXECUTE_READ)[https://docs.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants#constants].

- Moneta:
But with moneta, we can see it. 

[moneta]

But without knowing the actual address, it is not getting shown by Process Hacker. It only not be visible from outside. It can bypass BlueTeam, unless the BlueTeamer isn't aware of this particular process memory address.

[processHacker_addr1_addr2]

- Floss:

- AV Bypass [Antiscan.me]():


### Resources and Credits:

1. I learned Reflective loader implementation from watching the _[<ins>SANS Offensive WorkShop</ins>](https://www.sans.org/offensive-operations/): ['From zero to hero: Creating a reflective loader in C#'](https://www.youtube.com/watch?v=qeOCZGuVsi4)_ by [@Jean_Maes_1994](https://twitter.com/jean_maes_1994). Also thanks to him, for answering my questions in DM, so patiently :smile:!
2. Other basics and offensive side of C# by following offensive tradecraft basics from _[<ins>DEFCON 29 Adversary Village</ins>](https://adversaryvillage.org/): ['Tradecraft Development in Adversary Simulations`](https://youtu.be/KJsVVEn4fFw)_ by [@fozavci](https://twitter.com/fozavci).
3. PInvoke:
    - [pinvoke](http://www.pinvoke.net/)
    - [specterops:Matt Hand](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d)
4. delegate:
5. DInvoke:
6. [@_winterknife_](https://twitter.com/_winterKnife_): For clearly making me understand the difference between stage-0, stage-1, stage-2, stage-3, etc payloads.
7. Took reference from [FalconStrike](https://slaeryan.github.io/posts/falcon-zero-alpha.html) by [@_winterknife_](https://twitter.com/_winterKnife_).
8. [@SoumyadeepBas12](https://twitter.com/SoumyadeepBas12): For helping me to succesfully evade the last AV, to get a clean sheet from [antiscan.me](https://antiscan.me/), it was really a pain to get over this AV, but  I did it ;).
