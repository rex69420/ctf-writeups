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
