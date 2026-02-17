"""
Генерация RSA ключей для защищенного чата
Каждый участник генерирует свою пару ключей
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_keys(username):
    """Генерация ключей для пользователя"""
    print(f"\nГенерирую ключи для {username}...")

    # Генерация ключей RSA 2048 бит
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохраняем приватный ключ
    priv_file = f"{username}_private.pem"
    with open(priv_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Сохраняем публичный ключ
    pub_file = f"{username}_public.pem"
    with open(pub_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"Приватный ключ сохранен: {priv_file}")
    print(f"Публичный ключ сохранен: {pub_file}")
    return priv_file, pub_file


def main(username = ""):
    print("=" * 50)
    print("ГЕНЕРАЦИЯ RSA КЛЮЧЕЙ")
    print("=" * 50)

    if (not username):
        print("\nВведите ваше имя (например, alice или bob):")
        username = input("Имя: ").strip().lower()

    if not username:
        print("Имя не может быть пустым")
        return

    generate_keys(username)

    #print("\n" + "=" * 50)
    #print("ИНСТРУКЦИЯ:")
    #print("=" * 50)
    print(
        f"Твои ключи сгенерированы: {username}_private.pem и {username}_public.pem"
    )
    #print("2. Запусти основную программу: python secure_chat.py")


if __name__ == "__main__":
    main()
