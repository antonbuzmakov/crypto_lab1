import socket
import json
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class BobServer:
    def __init__(self):
        self.private_key = None
        self.peer_public_key = None
        self.session_key = None

    def load_my_keys(self):
        """Загрузка приватного ключа Боба"""
        try:
            with open("bob_private.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            print("✅ Приватный ключ Боба загружен")
        except FileNotFoundError:
            print("❌ Файл bob_private.pem не найден!")
            print("Сначала сгенерируй ключи: python generate_keys.py")
            sys.exit(1)

    def exchange_public_keys(self, client_socket):
        """Обмен публичными ключами по сети"""
        print("\n🔄 Обмен публичными ключами...")

        # 1. Отправляем публичный ключ Боба
        print("📤 Отправляю публичный ключ Боба...")
        with open("bob_public.pem", "rb") as f:
            bob_pub_key = f.read()

        client_socket.send(len(bob_pub_key).to_bytes(4, "big"))
        client_socket.send(bob_pub_key)
        print("✅ Публичный ключ Боба отправлен")

        # 2. Получаем публичный ключ Алисы
        print("⏳ Ожидаю публичный ключ Алисы...")
        size_data = client_socket.recv(4)
        alice_key_size = int.from_bytes(size_data, "big")
        alice_pub_key_data = client_socket.recv(alice_key_size)

        # Сохраняем ключ Алисы
        with open("alice_public_received.pem", "wb") as f:
            f.write(alice_pub_key_data)

        # Загружаем ключ в память
        self.peer_public_key = serialization.load_pem_public_key(
            alice_pub_key_data, backend=default_backend()
        )
        print("✅ Публичный ключ Алисы получен")

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
        print("=" * 50)
        print("СЕРВЕР БОБА - ЗАЩИЩЕННЫЙ ЧАТ")
        print("=" * 50)

        # Загружаем только свой приватный ключ
        self.load_my_keys()

        # Создаем сервер
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind((host, port))
            server.listen(1)

            print(f"\n🎯 Сервер запущен на {host}:{port}")
            print("Ожидаю подключения Алисы...\n")

            client, addr = server.accept()
            print(f"✅ Алиса подключилась: {addr[0]}:{addr[1]}")

            # Этап 1: Обмен публичными ключами
            self.exchange_public_keys(client)

            # Этап 2: Аутентификация сервера (Боба)
            print("\n🔐 Аутентификация сервера...")
            nonce = os.urandom(16)
            signature = self.private_key.sign(
                nonce,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            auth_data = json.dumps(
                {"nonce": nonce.hex(), "signature": signature.hex()}
            ).encode()

            client.send(len(auth_data).to_bytes(4, "big"))
            client.send(auth_data)
            print("✅ Данные аутентификации отправлены")

            # Этап 3: Получаем сессионный ключ
            print("\n🔑 Ожидаю сессионный ключ...")
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

            # Этап 4: Защищенное общение
            print("\n" + "=" * 50)
            print("💬 ЗАЩИЩЕННЫЙ КАНАЛ УСТАНОВЛЕН")
            print("=" * 50)
            print("Введите 'exit' для выхода\n")

            while True:
                # Получаем сообщение
                size_data = client.recv(4)
                if not size_data:
                    break

                msg_size = int.from_bytes(size_data, "big")
                encrypted_msg = client.recv(msg_size)

                # Расшифровываем
                decrypted = self.aes_decrypt(encrypted_msg).decode()
                print(f"👤 Алиса: {decrypted}")

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

        except KeyboardInterrupt:
            print("\n\n🛑 Сервер остановлен пользователем")
        except Exception as e:
            print(f"❌ Ошибка: {e}")
        finally:
            try:
                client.close()
            except:
                pass
            server.close()
            print("\n👋 Сервер остановлен")


if __name__ == "__main__":
    server = BobServer()
    server.start()
