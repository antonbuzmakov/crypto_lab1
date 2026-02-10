A - Алиса (клиент)
B - Боб (сервер)
Pub_X - публичный ключ X
Priv_X - приватный ключ X
K_AB - сессионный AES ключ
{N} - nonce (случайное число)
E(Pub_X, M) - шифрование M ключом Pub_X с RSA-OAEP
D(Priv_X, C) - расшифрование C ключом Priv_X
Sign(Priv_X, M) - подпись M ключом Priv_X с RSA-PSS
Verify(Pub_X, M, S) - проверка подписи S для M
AES-GCM(K, M, IV) - шифрование M ключом K в режиме GCM
