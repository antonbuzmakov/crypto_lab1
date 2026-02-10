"""
Генерация RSA ключей для Алисы и Боба
Запусти на каждом компьютере!
"""

import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_keys():
    print("=" * 50)
    print("ГЕНЕРАЦИЯ RSA КЛЮЧЕЙ ДЛЯ ЗАЩИЩЕННОГО ЧАТА")
    print("=" * 50)

    print("\n👤 Кто ты?")
    print("1. Алиса (клиент)")
    print("2. Боб (сервер)")

    choice = input("\nВыбери 1 или 2: ").strip()

    if choice == "1":
        role = "Алиса"
        priv_file = "alice_private.pem"
        pub_file = "alice_public.pem"
    elif choice == "2":
        role = "Боб"
        priv_file = "bob_private.pem"
        pub_file = "bob_public.pem"
    else:
        print("❌ Неверный выбор. Введите 1 или 2")
        sys.exit(1)

    print(f"\n🔑 Генерирую ключи для {role}...")

    # Генерация ключей RSA 2048 бит
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохраняем приватный ключ
    with open(priv_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Сохраняем публичный ключ
    with open(pub_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"✅ Приватный ключ сохранен: {priv_file}")
    print(f"✅ Публичный ключ сохранен: {pub_file}")

    print("\n" + "=" * 50)
    print("📋 ИНСТРУКЦИЯ ДЛЯ ЗАПУСКА:")
    print("=" * 50)

    if choice == "1":
        print("\n1. Запусти на Бобе: python server.py")
        print("2. Запусти здесь: python client.py")
        print("\n⚠  Публичный ключ будет автоматически отправлен Бобу")
    else:
        print("\n1. Запусти здесь: python server.py")
        print("2. Попроси Алису запустить: python client.py")
        print("\n⚠  Публичный ключ будет автоматически отправлен Алисе")

    print("\n🔧 Для работы через Hamachi:")
    print("   Алиса: python client.py 25.x.x.x 12345")
    print("   (замени 25.x.x.x на Hamachi IP Боба)")


if __name__ == "__main__":
    generate_keys()
