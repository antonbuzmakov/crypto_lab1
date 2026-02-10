import socket
import json
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class BobServer:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.session_key = None

    def load_keys(self):
        """Загрузка ключей Боба"""
        with open("bob_private.pem", "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open("alice_public.pem", "rb") as f:
            self.peer_public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    def rsa_decrypt(self, ciphertext):
        """Расшифровка RSA"""
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def verify_signature(self, data, signature):
        """Проверка подписи"""
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

    def aes_decrypt(self, encrypted_data):
        """Расшифровка AES-GCM"""
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def start(self, host="0.0.0.0", port=12345):
        """Запуск сервера"""
        print("🔑 Загружаю ключи Боба...")
        self.load_keys()

        # Создаем сервер
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(1)

        print(f"🎯 Сервер запущен на {host}:{port}")
        print("Ожидаю подключения Алисы...")

        client, addr = server.accept()
        print(f"✅ Алиса подключилась: {addr}")

        # 1. Отправляем nonce и подпись (аутентификация)
        nonce = os.urandom(16)
        signature = self.private_key.sign(
            nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        auth_data = json.dumps(
            {"nonce": nonce.hex(), "signature": signature.hex()}
        ).encode()

        client.send(len(auth_data).to_bytes(4, "big"))
        client.send(auth_data)
        print("📤 Отправил данные для аутентификации")

        # 2. Получаем сессионный ключ от Алисы
        size_data = client.recv(4)
        key_size = int.from_bytes(size_data, "big")
        key_data = client.recv(key_size)

        message = json.loads(key_data.decode())
        encrypted_key = bytes.fromhex(message["encrypted_key"])
        signature = bytes.fromhex(message["signature"])

        # Проверяем подпись
        if not self.verify_signature(encrypted_key, signature):
            print("❌ Ошибка: Неверная подпись Алисы!")
            client.close()
            return

        # Расшифровываем сессионный ключ
        self.session_key = self.rsa_decrypt(encrypted_key)
        print("✅ Сессионный ключ получен и проверен")

        # 3. Защищенное общение
        print("\n💬 ЗАЩИЩЕННЫЙ КАНАЛ УСТАНОВЛЕН")
        print("==============================")

        while True:
            # Получаем сообщение
            size_data = client.recv(4)
            if not size_data:
                break

            msg_size = int.from_bytes(size_data, "big")
            encrypted_msg = client.recv(msg_size)

            # Расшифровываем
            decrypted = self.aes_decrypt(encrypted_msg).decode()
            print(f"\n👤 Алиса: {decrypted}")

            # Отправляем ответ
            response = input("💬 Боб: ")
            if response.lower() == "exit":
                break

            # Шифруем ответ
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_resp = (
                iv
                + encryptor.tag
                + encryptor.update(response.encode())
                + encryptor.finalize()
            )

            client.send(len(encrypted_resp).to_bytes(4, "big"))
            client.send(encrypted_resp)

        client.close()
        server.close()
        print("\n👋 Соединение закрыто")


if __name__ == "__main__":
    BobServer().start()
