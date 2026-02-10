import socket
import json
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AliceClient:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.session_key = None

    def load_keys(self):
        """Загрузка ключей Алисы"""
        with open("alice_private.pem", "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open("bob_public.pem", "rb") as f:
            self.peer_public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    def rsa_encrypt(self, data):
        """Шифрование RSA"""
        return self.peer_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def sign_data(self, data):
        """Создание подписи"""
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

    def verify_signature(self, data, signature):
        """Проверка подписи Боба"""
        try:
            self.peer_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except:
            return False

    def aes_encrypt(self, data):
        """Шифрование AES-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def aes_decrypt(self, encrypted_data):
        """Расшифровка AES-GCM"""
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def start(self, server_ip="127.0.0.1", port=12345):
        """Запуск клиента"""
        print("🔑 Загружаю ключи Алисы...")
        self.load_keys()

        # Подключаемся к серверу
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print(f"🔗 Подключаюсь к {server_ip}:{port}...")
            client.connect((server_ip, port))
            print("✅ Подключено!")

            # 1. Получаем данные для аутентификации Боба
            size_data = client.recv(4)
            auth_size = int.from_bytes(size_data, "big")
            auth_data = client.recv(auth_size)

            message = json.loads(auth_data.decode())
            nonce = bytes.fromhex(message["nonce"])
            signature = bytes.fromhex(message["signature"])

            # Проверяем подпись Боба
            if not self.verify_signature(nonce, signature):
                print("❌ Ошибка: Неверная подпись Боба!")
                client.close()
                return

            print("✅ Боб аутентифицирован")

            # 2. Отправляем сессионный ключ
            self.session_key = os.urandom(32)  # AES-256
            encrypted_key = self.rsa_encrypt(self.session_key)
            signature = self.sign_data(encrypted_key)

            key_data = json.dumps(
                {"encrypted_key": encrypted_key.hex(), "signature": signature.hex()}
            ).encode()

            client.send(len(key_data).to_bytes(4, "big"))
            client.send(key_data)
            print("✅ Сессионный ключ отправлен")

            # 3. Защищенное общение
            print("\n💬 ЗАЩИЩЕННЫЙ КАНАЛ УСТАНОВЛЕН")
            print("==============================")

            while True:
                # Отправляем сообщение
                message = input("\n💬 Алиса: ")
                if message.lower() == "exit":
                    break

                # Шифруем и отправляем
                encrypted = self.aes_encrypt(message.encode())
                client.send(len(encrypted).to_bytes(4, "big"))
                client.send(encrypted)

                # Получаем ответ
                size_data = client.recv(4)
                if not size_data:
                    break

                resp_size = int.from_bytes(size_data, "big")
                encrypted_resp = client.recv(resp_size)

                # Расшифровываем ответ
                decrypted = self.aes_decrypt(encrypted_resp).decode()
                print(f"👤 Боб: {decrypted}")

        except ConnectionRefusedError:
            print(f"❌ Не удалось подключиться к {server_ip}:{port}")
        finally:
            client.close()
            print("\n👋 Соединение закрыто")


if __name__ == "__main__":
    AliceClient().start()
