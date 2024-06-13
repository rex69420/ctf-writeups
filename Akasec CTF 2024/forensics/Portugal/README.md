# Akasec CTF 2024 – Portugal

- **Category:** Forensics
- **Points:** 100
- **Solves:** 116

## Challenge

> I accidentally left my computer unlocked at the coffee shop while I stepped away. I'm sure that someone took advantage of the opportunity and was searching for something.
>
> Author: d33znu75
>
> Attachment: [memdump1.mem](https://we.tl/t-SRYyC4mGLQ)

## Solution

Upon seeing a memory dump, the first thing that comes to mind is to use `volatility` to analyze it. So, let's start by running `volatility` with the `windows.info` plugin to get some information about the memory dump.

```
└─$ python3 vol.py -f memdump1.mem windows.info
# ...
Kernel Base     0x81a7d000
DTB     0x1a8000
Symbols file:///mnt/d/ctf/volatility3/volatility3/symbols/windows/ntkrpamp.pdb/3A51F333EC3E4943A617AFC47C95C475-1.json.xz
Is64Bit False
IsPAE   True
layer_name      0 WindowsIntelPAE
memory_layer    1 FileLayer
KdDebuggerDataBlock     0x81c71820
NTBuildLab      10586.0.x86fre.th2_release.15102
# ...
```

From the output, we can see that volatility has detected the profile automatically, and fetched the information about the memory dump. Now, let's list the processes using the `windows.pslist` plugin.

```
└─$ python3 vol.py -f memdump1.mem windows.pslist
# ...
728     2228    OneDrive.exe    0xa2e47c40      22      -       1       False   2024-05-28 10:35:55.000000      N/A    Disabled
1240    2228    chrome.exe      0x9d7d7c40      40      -       1       False   2024-05-28 10:35:56.000000      N/A    Disabled
1272    1240    chrome.exe      0xa2ec2840      8       -       1       False   2024-05-28 10:35:56.000000      N/A    Disabled
2316    1240    chrome.exe      0x9d787340      14      -       1       False   2024-05-28 10:35:58.000000      N/A    Disabled
# ...
```

From the output, we can see the `chrome.exe` process that stands out. The first thing that comes to mind is the Chrome History, stored at `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\History`. So, let's dump the `History` using the `dumpfiles` plugin, after obtaining the `virtaddr` using the `filescan` plugin.

```
└─$ python3 vol.py -f memdump1.mem windows.filescan | grep History
# ...
0x81595680	\Users\d33znu75\AppData\Local\Google\Chrome\User Data\Default\History	128
# ...
```

```
└─$ python3 vol.py -f memdump1.mem windows.dumpfiles --virtaddr 0x81595680
# ...
DataSectionObject       0x81595680      History file.0x81595680.0x98570f60.DataSectionObject.History.dat
SharedCacheMap  0x81595680      History file.0x81595680.0xa2ee6968.SharedCacheMap.History.vacb
```

Running `strings` on it gives us the flag, broken up in pieces.

```
└─$ strings file.0x81595680.0x98570f60.DataSectionObject.History.dat
# ...
look !! its here yay*
22- y}
21- 0r
20- st
19- h1
18- h_
17- rc
16- 34
15- _s
14- m3
13- r0
12- ch
11- r_
10- f0
9- Y_
8- 1T
7- 1L
6- 4T
5- 0L
4- {V
3- EC
2- AS
1- AK
# ...

# AKASEC{V0L4T1L1TY_f0r_chr0m3_s34rch_h1st0ry}
```
