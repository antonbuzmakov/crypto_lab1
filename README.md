# crypto_lab1

Лабораторная 1 Криптографические протоколы
ЗАЩИЩЕННЫЙ ЧАТ С RSA И AES
==========================

1. УСТАНОВКА ЗАВИСИМОСТЕЙ:
   pip install cryptography

2. ГЕНЕРАЦИЯ КЛЮЧЕЙ:
   На Алисе: python generate_keys.py → выбери 1
   На Бобе: python generate_keys.py → выбери 2

3. ЗАПУСК:
   На Бобе: python server.py
   На Алисе: python client.py

4. ДЛЯ РАБОТЫ ЧЕРЕЗ HAMACHI:
   - Установите Hamachi
   - Боб создает сеть, Алиса подключается
   - Боб говорит свой Hamachi IP (25.x.x.x)
   - Алиса запускает: python client.py 25.x.x.x 12345

5. ПРОТОКОЛ:
   1. Обмен публичными RSA ключами
   2. Аутентификация Боба (RSA подпись)
   3. Передача сессионного AES ключа
   4. Защищенное общение (AES шифрование)

6. СОЗДАННЫЕ ФАЙЛЫ:
   - alice_private.pem / bob_private.pem (секретные!)
   - alice_public.pem / bob_public.pem (отправляются)
   - \*\_received.pem (полученные ключи)
