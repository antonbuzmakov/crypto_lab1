"""
Защищенный чат на основе RSA
Симметричный протокол: один и тот же код для обоих участников
"""

import socket
import json
import os
import sys
import threading
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class SecureChat:
    def __init__(self, username):
        self.username = username
        self.private_key = None
        self.peer_public_key = None
        self.session_key = None
        self.connection = None
        self.is_initiator = False  # Кто начинает общение
        self.running = True

    def load_keys(self):
        """Загрузка ключей пользователя"""
        try:
            # Загружаем свой приватный ключ
            with open(f"{self.username}_private.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            print(f"✅ Приватный ключ {self.username} загружен")

            # Загружаем публичный ключ собеседника
            try:
                with open("peer_public.pem", "rb") as f:
                    self.peer_public_key = serialization.load_pem_public_key(
                        f.read(), backend=default_backend()
                    )
                print("✅ Публичный ключ собеседника загружен")
                return True
            except FileNotFoundError:
                print("❌ Файл peer_public.pem не найден!")
                print("Сначала получи публичный ключ собеседника")
                return False

        except FileNotFoundError:
            print(f"❌ Файл {self.username}_private.pem не найден!")
            print("Сначала сгенерируй ключи: python generate_keys.py")
            return False

    def sign_data(self, data):
        """Создание подписи RSA"""
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
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
        except Exception as e:
            print(f"Ошибка проверки подписи: {e}")
            return False

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

    def send_message(self, sock, data):
        """Отправка сообщения с префиксом размера"""
        sock.send(len(data).to_bytes(4, "big"))
        sock.send(data)

    def receive_message(self, sock):
        """Получение сообщения с префиксом размера"""
        size_data = sock.recv(4)
        if not size_data:
            return None
        size = int.from_bytes(size_data, "big")
        return sock.recv(size)

    def initiator_protocol(self, sock):
        """Протокол для инициатора (кто первый начал)"""
        print("\n📞 Запуск протокола как инициатор...")

        # Шаг 1: Отправляем свой публичный ключ
        print("📤 Отправляю свой публичный ключ...")
        with open(f"{self.username}_public.pem", "rb") as f:
            my_pub_key = f.read()
        self.send_message(sock, my_pub_key)

        # Шаг 2: Получаем публичный ключ собеседника
        print("⏳ Ожидаю публичный ключ собеседника...")
        peer_pub_key = self.receive_message(sock)
        self.peer_public_key = serialization.load_pem_public_key(
            peer_pub_key, backend=default_backend()
        )
        print("✅ Публичный ключ собеседника получен")

        # Шаг 3: Аутентификация (двусторонняя)
        print("\n🔐 Двусторонняя аутентификация...")

        # Отправляем свой nonce с подписью
        my_nonce = os.urandom(16)
        my_signature = self.sign_data(my_nonce)
        auth_data = json.dumps(
            {"nonce": my_nonce.hex(), "signature": my_signature.hex()}
        ).encode()
        self.send_message(sock, auth_data)
        print("📤 Отправил свой nonce для аутентификации")

        # Получаем и проверяем nonce собеседника
        peer_auth = json.loads(self.receive_message(sock).decode())
        peer_nonce = bytes.fromhex(peer_auth["nonce"])
        peer_signature = bytes.fromhex(peer_auth["signature"])

        if not self.verify_signature(peer_nonce, peer_signature):
            print("❌ Ошибка: Неверная подпись собеседника!")
            return False
        print("✅ Собеседник аутентифицирован")

        # Шаг 4: Создание и отправка сессионного ключа
        print("\n🔑 Создание сессионного ключа...")
        self.session_key = os.urandom(32)  # AES-256

        # Шифруем ключ публичным ключом собеседника
        encrypted_key = self.rsa_encrypt(self.session_key)

        # Подписываем зашифрованный ключ
        key_signature = self.sign_data(encrypted_key)

        key_data = json.dumps(
            {"encrypted_key": encrypted_key.hex(), "signature": key_signature.hex()}
        ).encode()

        self.send_message(sock, key_data)
        print("✅ Сессионный ключ отправлен")

        # Ждем подтверждение
        confirm = self.receive_message(sock).decode()
        if confirm == "OK":
            print("✅ Собеседник подтвердил получение ключа")
            return True
        else:
            print("❌ Ошибка подтверждения")
            return False

    def responder_protocol(self, sock):
        """Протокол для отвечающего (кто принял соединение)"""
        print("\n📞 Запуск протокола как отвечающий...")

        # Шаг 1: Получаем публичный ключ инициатора
        print("⏳ Ожидаю публичный ключ инициатора...")
        peer_pub_key = self.receive_message(sock)
        self.peer_public_key = serialization.load_pem_public_key(
            peer_pub_key, backend=default_backend()
        )
        print("✅ Публичный ключ инициатора получен")

        # Шаг 2: Отправляем свой публичный ключ
        print("📤 Отправляю свой публичный ключ...")
        with open(f"{self.username}_public.pem", "rb") as f:
            my_pub_key = f.read()
        self.send_message(sock, my_pub_key)

        # Шаг 3: Аутентификация
        print("\n🔐 Двусторонняя аутентификация...")

        # Получаем и проверяем nonce инициатора
        initiator_auth = json.loads(self.receive_message(sock).decode())
        initiator_nonce = bytes.fromhex(initiator_auth["nonce"])
        initiator_signature = bytes.fromhex(initiator_auth["signature"])

        if not self.verify_signature(initiator_nonce, initiator_signature):
            print("❌ Ошибка: Неверная подпись инициатора!")
            return False
        print("✅ Инициатор аутентифицирован")

        # Отправляем свой nonce с подписью
        my_nonce = os.urandom(16)
        my_signature = self.sign_data(my_nonce)
        auth_data = json.dumps(
            {"nonce": my_nonce.hex(), "signature": my_signature.hex()}
        ).encode()
        self.send_message(sock, auth_data)
        print("📤 Отправил свой nonce для аутентификации")

        # Шаг 4: Получение сессионного ключа
        print("\n🔑 Ожидаю сессионный ключ...")
        key_data = json.loads(self.receive_message(sock).decode())
        encrypted_key = bytes.fromhex(key_data["encrypted_key"])
        key_signature = bytes.fromhex(key_data["signature"])

        # Проверяем подпись на ключе
        if not self.verify_signature(encrypted_key, key_signature):
            print("❌ Ошибка: Неверная подпись на сессионном ключе!")
            sock.send(b"ERROR")
            return False

        # Расшифровываем ключ
        self.session_key = self.rsa_decrypt(encrypted_key)
        print("✅ Сессионный ключ получен и проверен")

        # Отправляем подтверждение
        self.send_message(sock, b"OK")  # Добавить b перед строкой
        print("✅ Подтверждение отправлено")
        return True

    def chat_session(self, sock):
        """Защищенная сессия общения"""
        print("\n" + "=" * 50)
        print("💬 ЗАЩИЩЕННЫЙ КАНАЛ УСТАНОВЛЕН")
        print("=" * 50)
        print("Введите 'exit' для выхода\n")

        # Поток для получения сообщений
        def receive_messages():
            while self.running:
                try:
                    data = self.receive_message(sock)
                    if not data:
                        print("\n⚠  Соединение разорвано")
                        self.running = False
                        break

                    decrypted = self.aes_decrypt(data)
                    if decrypted == b"EXIT":
                        print("\n👋 Собеседник вышел из чата")
                        self.running = False
                        break

                    print(f"\n👤 Собеседник: {decrypted.decode()}")
                    print(f"💬 {self.username}: ", end="", flush=True)

                except Exception as e:
                    if self.running:
                        print(f"\n❌ Ошибка приема: {e}")
                        self.running = False
                    break

        # Запускаем поток приема
        receive_thread = threading.Thread(target=receive_messages)
        receive_thread.daemon = True
        receive_thread.start()

        # Основной цикл отправки сообщений
        try:
            while self.running:
                message = input(f"💬 {self.username}: ")

                if message.lower() == "exit":
                    # Отправляем сообщение о выходе
                    encrypted = self.aes_encrypt(b"EXIT")
                    self.send_message(sock, encrypted)
                    print("👋 Выход из чата...")
                    self.running = False
                    break

                # Шифруем и отправляем
                encrypted = self.aes_encrypt(message.encode())
                self.send_message(sock, encrypted)

        except KeyboardInterrupt:
            print("\n\n👋 Прерывание пользователя")
            self.running = False
        except Exception as e:
            print(f"\n❌ Ошибка: {e}")

    def start_server(self, port):
        """Запуск в режиме сервера (ожидание подключения)"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", port))
            server.listen(1)
            print(f"\n🎯 Ожидаю подключение на порту {port}...")

            self.connection, addr = server.accept()
            print(f"✅ Подключение от {addr[0]}:{addr[1]}")

            # Запускаем протокол как отвечающий
            if self.responder_protocol(self.connection):
                self.chat_session(self.connection)

        except Exception as e:
            print(f"❌ Ошибка сервера: {e}")
        finally:
            server.close()

    def start_client(self, peer_ip, port):
        """Запуск в режиме клиента (подключение к серверу)"""
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print(f"\n🔗 Подключаюсь к {peer_ip}:{port}...")
            client.connect((peer_ip, port))
            print("✅ Подключено!")

            # Запускаем протокол как инициатор
            if self.initiator_protocol(client):
                self.chat_session(client)

        except Exception as e:
            print(f"❌ Ошибка клиента: {e}")
        finally:
            client.close()

    def cleanup(self):
        """Очистка ресурсов"""
        self.running = False
        if self.connection:
            self.connection.close()


def main():
    print("=" * 50)
    print("🔐 ЗАЩИЩЕННЫЙ ЧАТ НА ОСНОВЕ RSA")
    print("=" * 50)

    # Запрашиваем имя пользователя
    username = input("\n👤 Введите ваше имя (alice/bob): ").strip().lower()
    if username not in ["alice", "bob"]:
        print("❌ Имя должно быть alice или bob")
        return

    # Создаем экземпляр чата
    chat = SecureChat(username)

    # Загружаем ключи
    if not chat.load_keys():
        return

    print("\n" + "=" * 50)
    print("📋 РЕЖИМ РАБОТЫ:")
    print("=" * 50)
    print("1. Ожидать подключение (сервер)")
    print("2. Подключиться к собеседнику (клиент)")

    mode = input("\nВыберите режим (1 или 2): ").strip()

    if mode == "1":
        # Режим сервера
        port = input("Порт (по умолчанию 12345): ").strip()
        port = int(port) if port else 12345
        chat.start_server(port)

    elif mode == "2":
        # Режим клиента
        peer_ip = input("IP адрес собеседника: ").strip()
        port = input("Порт (по умолчанию 12345): ").strip()
        port = int(port) if port else 12345
        chat.start_client(peer_ip, port)

    else:
        print("❌ Неверный выбор")
        return

    print("\n👋 Чат завершен")


if __name__ == "__main__":
    main()
