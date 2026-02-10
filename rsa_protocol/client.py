import socket
import json
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AliceClient:
    def __init__(self):
        self.private_key = None
        self.peer_public_key = None
        self.session_key = None

    def load_my_keys(self):
        """Загрузка приватного ключа Алисы"""
        try:
            with open("alice_private.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            print("✅ Приватный ключ Алисы загружен")
        except FileNotFoundError:
            print("❌ Файл alice_private.pem не найден!")
            print("Сначала сгенерируй ключи: python generate_keys.py")
            sys.exit(1)

    def exchange_public_keys(self, client_socket):
        """Обмен публичными ключами по сети"""
        print("\n🔄 Обмен публичными ключами...")

        # 1. Получаем публичный ключ Боба
        print("⏳ Получаю публичный ключ Боба...")
        size_data = client_socket.recv(4)
        bob_key_size = int.from_bytes(size_data, "big")
        bob_pub_key_data = client_socket.recv(bob_key_size)

        # Сохраняем ключ Боба
        with open("bob_public_received.pem", "wb") as f:
            f.write(bob_pub_key_data)

        # Загружаем ключ в память
        self.peer_public_key = serialization.load_pem_public_key(
            bob_pub_key_data, backend=default_backend()
        )
        print("✅ Публичный ключ Боба получен")

        # 2. Отправляем публичный ключ Алисы
        print("📤 Отправляю публичный ключ Алисы...")
        with open("alice_public.pem", "rb") as f:
            alice_pub_key = f.read()

        client_socket.send(len(alice_pub_key).to_bytes(4, "big"))
        client_socket.send(alice_pub_key)
        print("✅ Публичный ключ Алисы отправлен")

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
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
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
        print("=" * 50)
        print("КЛИЕНТ АЛИСА - ЗАЩИЩЕННЫЙ ЧАТ")
        print("=" * 50)

        # Загружаем только свой приватный ключ
        self.load_my_keys()

        # Подключаемся к серверу
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print(f"\n🔗 Подключаюсь к {server_ip}:{port}...")
            client.connect((server_ip, port))
            print("✅ Подключено!")

            # Этап 1: Обмен публичными ключами
            self.exchange_public_keys(client)

            # Этап 2: Аутентификация Боба
            print("\n🔐 Аутентификация Боба...")
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

            # Этап 3: Отправляем сессионный ключ
            print("\n🔑 Создаю и отправляю сессионный ключ...")
            self.session_key = os.urandom(32)  # AES-256
            encrypted_key = self.rsa_encrypt(self.session_key)
            signature = self.sign_data(encrypted_key)

            key_data = json.dumps(
                {"encrypted_key": encrypted_key.hex(), "signature": signature.hex()}
            ).encode()

            client.send(len(key_data).to_bytes(4, "big"))
            client.send(key_data)
            print("✅ Сессионный ключ отправлен")

            # Этап 4: Защищенное общение
            print("\n" + "=" * 50)
            print("💬 ЗАЩИЩЕННЫЙ КАНАЛ УСТАНОВЛЕН")
            print("=" * 50)
            print("Введите 'exit' для выхода\n")

            while True:
                # Отправляем сообщение
                message = input("💬 Алиса: ")
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
            print("Проверьте:")
            print("1. Сервер запущен")
            print("2. Правильность IP адреса")
            print("3. Брандмауэр разрешает подключения")
        except Exception as e:
            print(f"❌ Ошибка: {e}")
        finally:
            client.close()
            print("\n👋 Соединение закрыто")


if __name__ == "__main__":
    client = AliceClient()
    # Для Hamachi используй: client.start("25.1.2.3", 12345)
    client.start()
