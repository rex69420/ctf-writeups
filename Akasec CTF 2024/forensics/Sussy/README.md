# Akasec CTF 2024 – Sussy

- **Category:** Forensics
- **Points:** 100
- **Solves:** 74

## Challenge

> Something Fishy's Going on in Our Network
>
> Author: d33znu75
>
> Attachment: [packet.pcapng](https://we.tl/t-1kqcKFwxTQ)

## Solution

The first part of the challenge was solved by my teammate `@47gg`. He noticed that all the DNS Queries sent to `*.akasec.ma` were hex encoded. So, he wrote a simple script to decode them, into a file.

```bash
└─$ tshark -r packet.pcapng -Y 'dns.qry.name contains "akasec"' -T fields -e dns.qry.name | uniq | sed 's/\.akasec\.ma//' | tr -d '\n' | xxd -r -p > flag.7z
```

The command above extracts all the DNS Queries containing `akasec` from the pcap, filters only the unique ones, removes the domain name, and decodes the hex into a file named [flag.7z](solution/flag.7z). Upon trying to extract the archive, it asks for a password. So, we need to find the password. I used `john` with the `rockyou.txt` wordlist to crack the password.

```
└─$ 7z2john flag.7z > 7z.hash && john 7z.hash --wordlist=rockyou.txt
# ...
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 256/256 AVX2 8x AES])
hellokitty       (flag.7z)
1g 0:00:00:02 DONE (2024-06-11 19:08) 0.4149g/s 99.58p/s 99.58c/s 99.58C/s alyssa..chris
# ...
```

On extracting the [flag.7z](solution/flag.7z) with the password `hellokitty`, we get a file called [flag](solution/flag) which is an encrypted PDF. So, I used `john` again to crack the password for the PDF.

```
└─$ 7z x flag.7z -phellokitty && pdf2john flag > pdf.hash && john pdf.hash --wordlist=rockyou.txt
# ...
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
meow             (flag)
1g 0:00:00:00 DONE (2024-06-11 19:11) 1.388g/s 44533p/s 44533c/s 44533C/s vivis..lucky05
# ...
```

On opening the PDF with the password `meow`, we get the flag.

```
└─$ qpdf -password=meow -decrypt flag flag.pdf
```

```
└─$ pdf2txt flag.pdf
congs buddy here’s the flag

AKASEC{PC4P_DNS_3xf1ltr4t10n_D0n3!!}
```
