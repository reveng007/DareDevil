# DareDevil

[![](https://img.shields.io/badge/Category-Defense%20Evasion-green)](https://github.com/reveng007/) [![](https://img.shields.io/badge/Language-C%23-green)](https://github.com/reveng007/)

A stealthy Loader-cum-dropper/stage-1/stager targeting Windows10 (FUD till now, according to antiscan.me)

### Technology behind Insider:

![Insider](https://user-images.githubusercontent.com/61424547/187096696-25093d56-4552-45d1-bcc7-168fe251b2ff.png)

### Ability:
Apart from the above shown diagram other abilties are:
1. Sensitive string Obfuscation using Environmental Keying [TTP ID: T1480.00](https://attack.mitre.org/techniques/T1480/001/). I became aware of this concept from _[<ins>SANS Offensive WorkShop</ins>](https://www.sans.org/offensive-operations/): ['From zero to hero: Creating a reflective loader in C#'](https://www.youtube.com/watch?v=qeOCZGuVsi4)_ by [@Jean_Maes_1994](https://twitter.com/jean_maes_1994) and from [FalconStrike](https://slaeryan.github.io/posts/falcon-zero-alpha.html) by [@_winterknife_](https://twitter.com/_winterKnife_).
2. All function calls are Obfuscated using delegate, except `LoadLibrary()` and `GetProcAddress()`.\
Tried using DInvoke to Obfuscate `LoadLibrary()` and `GetProcAddress()` but instead, it got detected by 5 more AV engines ;(
4. Ability to **Detect** and **Detach** from **debugger** by using, `NtQueryInformationProcess()` and `NtRemoveProcessDebug()` respectively.
5. Ability to **Determine** by **checking** whether the targeted machine is the intended/valid target machine (i.e. within the engagement contract domain) or not.

### Tools: Usage

- Obfuscator/encrypt.cs:
1. [For shellcode extraction and encryption]: place it in the directory in which .bin file is present.
2. [For url and string encryption]: Nothing! Just paste and run.

Example:
```
It can encrypt 'shellcode', 'url' and string:

// Creating .bin file and Extracting shellcode from .bin file:
// Creating: https://ivanitlearning.wordpress.com/2018/10/14/shellcoding-with-msfvenom/
// Extract: 
cmd> encrypt.exe /file:file.bin /xor_key:<usernameoftarget> /out:xor_b64

// paste the output b64 bytes into a .txt file and upload it to payload server.
// cmd: "mv .\obfuscator\"
cmd> encrypt.exe /shellcodeurl:<url> /xor_key:<usernameoftarget> /out:xor_b64

cmd> encrypt.exe /mscorliburl:<url> /xor_key:<usernameoftarget> /out:xor_b64

// For Sending/ exfiltrating Victim process name and Ids to Operator Gmail via SMTP server
cmd> encrypt.exe /remotewriteurl:<url> /xor_key:<usernameoftarget> /out:xor_b64

// For reading pid from pid.txt from payload server/ remote c2 server
cmd>  encrypt.exe /remotereadurl:<url> /xor_key:<usernameoftarget> /out:xor_b64

// Sensitive strings Obfuscation
cmd> encrypt.exe /string:<string1,string2,...,stringn> /xor_key:<usernameoftarget> /out:xor_b64
```

- stage2/remotewrite.cs:\
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

- stage2/mscorlib.cs:\
It is the re-implementation of AMSI and ETW bypass done in [SharpSploit](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Evasion/ETW.cs) and [AmsiScanBufferBypass](https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/main/AmsiBypass.cs) by [@RastaMouse](https://twitter.com/_rastamouse?lang=en). It was actually covered by [@Jean_Maes_1994](https://twitter.com/jean_maes_1994) in his workshop in <ins>SANS Offensive</ins>.

- stage1/Insider.cs:
Usage:
```
1. I have used Developer Powershell/cmd for VS 2019
2. cmd> git clone https://github.com/reveng007/DareDevil
3. Compile: Obfuscator/encrypt.cs with compile.bat, stage2/remotewrite.cs with compile_remotewrite.bat (but at first write the credentials of sender's and receiver's/Operator's gmail) and stage2/mscorlib.cs with compile_mscorlib.bat.
4. Now upload/ host those two stage2 in payload server/ github(github: because it will not be considered as malicious as it is considered to be a legitimate website. So, malware traffic from github will not be considered as creepy stuff, instead of that, it would be considered as legitimate).
5. Encrypt those two urls using "Obfuscator/encrypt.exe" file with the previously mentioned flags and use those in "stage1/Insider.cs".
6. Encrypt your shellcode, by following my previously mentioned flags in "Obfuscator/encrypt.exe" section and paste the encrypted shellcode in a text file. Host it in payload server/ github. Then again encrypt that url with "Obfuscator/encrypt.exe" and paste that in "stage1/Insider.cs".
7. Now, compile the "stage1/Insider.cs" with compile.bat and put it in an antivirus enabled windows 10 and test it.
```
#### NOTE:
I have named AMSI&ETW bypass .NET Assembly as "_mscorlib_" because if by chance, it is seen by a Blue Teamer and if that particular member is less experienced, the name `"mscorlib"` can bamboozle, making them think, "Hey, yes!! a .NET binary always loads up something called, mscorlib. It contains the core implementation of the .NET framework." Though there is a very little chance of our "_mscorlib.exe_" of getting caught running as a process in memory, as it is visible only a very little amount of time (probably in ms) in our dropper process memory, unless our dropper is getting debugged ;(.\
BTW, this bamboozle thing was also told by Jean Maes :smile:.

### Ability to recognise target by checking username in the form of xor key:

As discussed before in [Ability](https://github.com/reveng007/DareDevil/edit/main/README.md#ability) section, utilizing environmental keying factor, I hardcoded a test string encrypted with xor key (username of target) and then decrypted the teststring using the username of the target machine retrieved in run time, then compared the decrypted text with the original one. If the condition is true then, our dropper is allowed to run else it turns off.

![image](https://user-images.githubusercontent.com/61424547/177057832-1b9c1eae-317b-496c-baaf-80dc871a3748.png)

### Video:

https://user-images.githubusercontent.com/61424547/177029414-1b3b09e0-d00c-4b96-882f-aa614f2a44ec.mp4

### <ins>Internal Noticing</ins>:

#### ProcessHacker (only):

https://user-images.githubusercontent.com/61424547/176947727-e37a484c-db28-495f-8cb2-0ab6eb1a3c81.mp4

I saw that even after providing Read-Execute permission to the allocated shellcode memory region, it wasn't shown as RX in ProcessHacker. Strangely enough, the bool value for VirtualProtectEx was also ***True*** while protecting target process memory with 0x20 [PAGE_EXECUTE_READ](https://docs.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants#constants).
I think this is happening because we applied page RW memory protection with `VirtualAllocEx()`. Then before creating the remote thread, we are allocating RX memory protection with `VirtualProtectEx()`. Not that sure of. If anybody seeing this, know about this, please correct me ;(

#### <ins>[Moneta](https://github.com/forrest-orr/moneta)</ins>:
But with moneta, we can see it. 

![moneta](https://user-images.githubusercontent.com/61424547/176948027-7bdc8c7e-7773-48a1-ae9f-06ea54b700be.png)

But without knowing the actual address, it is not getting shown by Process Hacker. It is only not be visible from outside. It can bypass BlueTeam, until the BlueTeamer isn't aware of this particular process memory address.

![processHacker](https://user-images.githubusercontent.com/61424547/176948132-1ffce1c6-ac63-472d-b8bc-a217791ab911.png)

#### <ins>[Floss](https://github.com/mandiant/flare-floss)</ins>:

Yes, encrypted strings are getting tracked by _Floss_ but that doesn't matter as long as they don't have the xor key (for decryption ofc!), which they don't.
I am able to bypass more or less all sensitive strings except, _Kernel32.dll_ as it is getting used by unobfuscated function call named, `LoadLibrary()` and `GetProcAddress()`. Other strings which caught my eyes were, _PROCESS_BASIC_INFORMATION_ and _PROCESSSINFOCLASS_, but I don't really think those things matter. But if those do, please do correct me.\
As again, I'm learning :)

#### WireShark Capture:

![SMTP_wireshark](https://user-images.githubusercontent.com/61424547/176946689-09192c06-6894-4d3b-a034-1a641d7c4de4.png)

We can see that the text(process infos) sent out are all encrypted by Gmail's TLS encryption. On top of that, the ip address (marked) isn't suspicious at all, or in other words are OPSEC safe.

![MailServer_iplookup](https://user-images.githubusercontent.com/61424547/176946957-60f1dce9-983e-4314-9fd8-6f54cbc04de7.PNG)

#### Quick Scan: 
1. Using [@matterpreter](https://twitter.com/matterpreter)'s [DefenderCheck](https://github.com/matterpreter/DefenderCheck)

![image](https://user-images.githubusercontent.com/61424547/187219202-7a8aad87-50bc-4876-939e-d3b1c7e81000.png)

2. Using [Antiscan.me](https://antiscan.me/):

![](https://antiscan.me/images/result/FQd8SUKDSr10.png)

Yupp! A clean sheet!
After a long period of TrialnError\
I did it...\
***Eset NOD32!***\
No matter what I do, this was flagging me :worried:.

When I commented out Loader code part, I got this: [loader](https://antiscan.me/scan/new/result?id=ixWtfrWl0H3u)\
When I commented out Dropper code part, I got this: [dropper](https://antiscan.me/scan/new/result?id=nhjBNvvssumL)\
When I used the whole binary, I got the above detection stats same as loader portion :woozy_face:. \
According to mathematics, I  should have got 4 detections, why one ? and why that particular AV only?\
I was really not getting it.\
But when I used Environmental keying, for some reason or other I bypassed their stored signatures :smile:!
> ***UPDATE***: I found out that in the case of _Evasion_ of Signatured Based AV, concept of normal mathematics fails. In here, to De-Signature signaturized malicious pattern, we have to change the **Entropy** of the already signatured malicious pattern. De-signaturization does not work like normal addition and substraction.

### To-Do list 👨‍🔧:
1. Try using DInvoke to Obfuscate `LoadLibrary()` and `GetProcAddress()` WinApi, taking reference from [SharpSploit](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Execution/DynamicInvoke/Native.cs), to hide them from getting detected from static analysis. [Change the name of the functions taken from _SharpSploit_ project]
2. Adding PPID Spoofing
3. Adding other Process Injection Types into it.
4. Try Creating a shellcode/PIC blob, which talks to server via smtp, imap, or other protocols which are not that much highlighted as suspicious IOC, like socket creation alert!

### NOTE:
1. If anyone viewing this find out something wrong or if you think, I haven't credited your or work of someone else, please contact me via my socials. I didn't intensionally mean to do that but sometimes I simply forget, sorry! :sweat_smile:

2. Please don't submit the samples to VirusTotal :cry:

### DISCLAIMER: This Project Only performs Signature based Evasion. Heuristics and behaviourial based Detection evasion is not Implemented in this Project.

### Resources and Credits:

1. I learned Reflective loader implementation from watching the _[<ins>SANS Offensive WorkShop</ins>](https://www.sans.org/offensive-operations/): ['From zero to hero: Creating a reflective loader in C#'](https://www.youtube.com/watch?v=qeOCZGuVsi4)_ by [@Jean_Maes_1994](https://twitter.com/jean_maes_1994). Also thanks to him, for answering my questions in DM, so patiently :smile:!
2. Other basics and offensive side of C# by following offensive tradecraft basics from _[<ins>DEFCON 29 Adversary Village</ins>](https://adversaryvillage.org/): ['Tradecraft Development in Adversary Simulations`](https://youtu.be/KJsVVEn4fFw)_ by [@fozavci](https://twitter.com/fozavci).
3. PInvoke:
    - [pinvoke](http://www.pinvoke.net/)
    - [specterops:Matt Hand](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d)
4. delegate: [YT:Tech69](https://www.youtube.com/c/Tech69YT). He is also a amaizing dude!
5. Obviously, the infamous [RTO:MalwareDevelopmentEssentials](https://institute.sektor7.net/red-team-operator-malware-development-essentials) course by [@SEKTOR7net](https://twitter.com/sektor7net).
6. [@_winterknife_](https://twitter.com/_winterKnife_): For clearly making me understand the difference between stage-0, stage-1, stage-2, stage-3, etc payloads.
7. Took reference from [FalconStrike](https://slaeryan.github.io/posts/falcon-zero-alpha.html) by [@_winterknife_](https://twitter.com/_winterKnife_).
8. [@SoumyadeepBas12](https://twitter.com/SoumyadeepBas12): For helping me out when I got stuck doing this project :+1:.

### Author: @reveng007 (Soumyanil Biswas)
---
[![](https://img.shields.io/badge/Twitter-@reveng007-1DA1F2?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/reveng007)
[![](https://img.shields.io/badge/LinkedIn-@SoumyanilBiswas-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/soumyanil-biswas/)
[![](https://img.shields.io/badge/Github-@reveng007-0077B5?style=flat-square&logo=github&logoColor=black)](https://github.com/reveng007/)
