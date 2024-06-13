# Akasec CTF 2024 – Snooz

- **Category:** Forensics
- **Points:** 436
- **Solves:** 21

## Challenge

> don't wake me up, I want a snooze u will find everything on my laptop!!
>
> Author: samaqlo
>
> Attachments: [snooz_chall.zip](https://we.tl/t-66EoXGwbVQ)

## Solution

The provided zip file contains the following files,

```
└── snooz_chall
    ├── memdump.mem
    └── snooz.pcapng
```

Starting off with the `snooz.pcapng` file, we notice that it contains a TCP stream with a base64 encoded payload at packet 56. We can extract the payload using `tshark` and decode it using `base64` to get the `.exe` file.

```bash
└─$ tshark -r snooz.pcapng -Y "frame.number == 56" -T fields -e data | xxd -r -p | base64 -d > download.exe
```

The `.exe` file is a .NET binary, so we can decompile it using `ILSpy`. Below is the decompiled and deobfuscated code from the binary.

```csharp
// snooz, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// a
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

internal class Snooz {
  private
  const int Port = 1337;
  private
  const string EncryptionKey = "fr33___p4l3571n3";

  private static void StartServer() {
    TcpListener tcpListener = new TcpListener(IPAddress.Any, Port);
    tcpListener.Start();

    while (true) {
      try {
        using(TcpClient tcpClient = tcpListener.AcceptTcpClient())
        using(NetworkStream stream = tcpClient.GetStream()) {
          byte[] buffer = new byte[1024];
          int bytesRead = stream.Read(buffer, 0, buffer.Length);

          if (bytesRead > 0) {
            byte[] receivedData = new byte[bytesRead];
            Array.Copy(buffer, 0, receivedData, 0, bytesRead);

            byte[] decryptedData = DecryptData(receivedData, EncryptionKey);
            string message = Encoding.UTF8.GetString(TrimPadding(decryptedData));

            Console.WriteLine("Received: " + message);
          }
        }
      } catch (Exception ex) {
        Console.WriteLine("Error: " + ex.Message);
      }
    }
  }

  private static byte[] DecryptData(byte[] data, string key) {
    using(Aes aes = Aes.Create()) {
      aes.Key = Encoding.UTF8.GetBytes(key);
      aes.Mode = CipherMode.ECB;
      aes.Padding = PaddingMode.None;

      using(ICryptoTransform decryptor = aes.CreateDecryptor()) {
        return decryptor.TransformFinalBlock(data, 0, data.Length);
      }
    }
  }

  private static byte[] TrimPadding(byte[] data) {
    int paddingLength = data[data.Length - 1];
    byte[] trimmedData = new byte[data.Length - paddingLength];
    Array.Copy(data, trimmedData, trimmedData.Length);
    return trimmedData;
  }

  public static void Main() {
    StartServer();
  }
}
```

To summarize, the binary listens on port 1337 for incoming TCP connections. It reads data from the client, decrypts it using AES in ECB mode, with the key `fr33___p4l3571n3`, and trims the padding to get the decrypted message.

We can decrypt the encrypted data from the `snooz.pcapng` file using the following Python script.

```python
# decrypt.py
import pyshark
from Crypto.Cipher import AES

ENCRYPTION_KEY = "fr33___p4l3571n3"


def decrypt_aes(encrypted_data, key):
    cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data[: -decrypted_data[-1]]


def main(file_path):
    cap = pyshark.FileCapture(
        file_path, display_filter="tcp.port == 1337 or tcp.dstport == 1337"
    )

    for packet in cap:
        try:
            encrypted_payload = bytes.fromhex(packet.tcp.payload.replace(":", ""))
            decrypted_message = decrypt_aes(encrypted_payload, ENCRYPTION_KEY).decode(
                "utf-8"
            )
            print(f"{packet.number}: {decrypted_message}")

        except Exception as e:
            pass

    cap.close()


if __name__ == "__main__":
    main("snooz.pcapng")
```

Running the script, we get the decrypted messages from the pcap file.

```
└─$ python3 decrypt.py
122: hello
161: hello
6368: Yo snooz
6405: Got the new pass to open the pastecode. It's 5n00zm3m3rbr0z now. Ditch the old one. Keep it on the down-low.
6423: good luck
```

Now, we can move our focus to the `memdump.mem` file. We can use `volatility` to analyze the memory dump. But, before we do that, we know we have to look for a `pastecode` link, so we can try using `strings` to extract the link from the memory dump.

```bash
└─$ strings memdump.mem | grep pastecode
\id=d58faa36-fd6c-4d85-832a-0fef9b5b7025 https://pastecode.io/s/9oz9u9h4
# ...
```

Opening the pastecode link and decrypting it with the password `5n00zm3m3rbr0z`, we get a huge base64 encoded string. Upon decoding it, we can see that it's a [zip file](solution/flag.zip) containing `flag.jpg`, but it's password protected.

This is where we got stuck, and we couldn't find the password for the [zip file](solution/flag.zip). The intended solution was to extract the password from the memory dump using `volatility`, by noticing the running `notepad.exe` process and dumping its memory to extract the password. For this, we could have used the [notepad](https://github.com/spitfirerxf/vol3-plugins/blob/main/notepad.py) plugin.

```
└─$ python3 vol.py -f memdump.mem windows.notepad
# ...
This is the password for the zip containing all the importante data : Samaqlo@Akasex777
# ...
```

With the password, we can extract the [flag.jpg](solution/flag.jpg) file, but we still don't get the flag. After trying a few stegenography tools, we found that the flag could be extracted using `stegseek`.

```bash
└─$ stegseek flag.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "palestine4life"
[i] Original filename: "flag.txt".
[i] Extracting to "flag.jpg.out".
```

```bash
└─$ cat flag.jpg.out
AKASEC{05-10-2023_free_palestine}
```
