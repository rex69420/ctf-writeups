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
