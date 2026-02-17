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

1.  A → B: TCP_Connect(B_IP, B_Port)

2.  B → A: Pub_B

3.  A → B: Pub_A

4.  B → A: {N_B}, Sign(Priv_B, {N_B})

5.  A: Verify(Pub_B, {N_B}, Signature)
    Если успешно → proceed, иначе → abort

6.  A → B: {N_A}, Sign(Priv_A, {N_A})

7.  B: Verify(Pub_A, {N_A}, Signature)
    Если успешно → proceed, иначе → abort

8.  A: K_AB ← Random(32 bytes)

9.  A → B: E(Pub_B, K_AB), Sign(Priv_A, Hash(E(Pub_B, K_AB)))

10. B: Verify(Pub_A, E(Pub_B, K_AB), Signature)
    Если успешно → D(Priv_B, E(Pub_B, K_AB)) → K_AB
    Иначе → abort

11. B → A: "OK"

12. A ↔ B: ∀ Message:
    A → B: AES-GCM(K_AB, Message, IV_A)
    B → A: AES-GCM(K_AB, Response, IV_B)
