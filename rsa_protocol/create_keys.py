"""
Создание RSA ключей для Алисы и Боба
Запусти этот скрипт на ОБОИХ компьютерах!
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def create_keys_for_alice():
    """Создает ключи для Алисы"""
    print("🔑 Создаю ключи для Алисы...")

    # Генерация ключей
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохранение приватного ключа
    with open("alice_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Сохранение публичного ключа
    with open("alice_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("✅ Созданы файлы:")
    print("   - alice_private.pem (НИКОМУ НЕ ПОКАЗЫВАТЬ!)")
    print("   - alice_public.pem (отдай Бобу)")


def create_keys_for_bob():
    """Создает ключи для Боба"""
    print("🔑 Создаю ключи для Боба...")

    # Генерация ключей
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохранение приватного ключа
    with open("bob_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Сохранение публичного ключа
    with open("bob_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("✅ Созданы файлы:")
    print("   - bob_private.pem (НИКОМУ НЕ ПОКАЗЫВАТЬ!)")
    print("   - bob_public.pem (отдай Алисе)")


def main():
    print("=" * 50)
    print("ГЕНЕРАЦИЯ RSA КЛЮЧЕЙ")
    print("=" * 50)

    print("\nКто ты?")
    print("1. Алиса (клиент)")
    print("2. Боб (сервер)")

    choice = input("\nВыбери 1 или 2: ").strip()

    if choice == "1":
        create_keys_for_alice()
    elif choice == "2":
        create_keys_for_bob()
    else:
        print("❌ Неверный выбор")
        return

    print("\n" + "=" * 50)
    print("📋 ЧТО ДЕЛАТЬ ДАЛЬШЕ:")
    print("=" * 50)
    print("\n1. Обменяйтесь публичными ключами:")
    print("   - Алиса отдает alice_public.pem Бобу")
    print("   - Боб отдает bob_public.pem Алисе")
    print("\n2. Положи полученные файлы в папку с программой")
    print("\n3. Запусти программу:")
    print("   - Боб: python server.py")
    print("   - Алиса: python client.py")
    print("\n⚠  ВНИМАНИЕ: *.private.pem НИКОМУ НЕ ПОКАЗЫВАТЬ!")


if __name__ == "__main__":
    main()
