# protocol.py
from __future__ import annotations
import hashlib
from des import DES


class MSCHAPv2:
    """
    Класс, реализующий MS-CHAPv2 challenge-response логику.
    Здесь NT-хеш упрощён: вместо настоящего MD4 используется любой готовый хеш.
    Для курсовой важен сам протокол, а не криптографическая точность NT-хеша.
    """

    # ---------- NT hash и ChallengeHash ----------

    @staticmethod
    def nt_password_hash(password: str) -> bytes:
        """
        Упрощённый NT-хеш
        """
        pw_bytes = password.encode("utf-16le")
        h = hashlib.md5()      # можно заменить на любой другой (sha1, sha256, и т.д.)
        h.update(pw_bytes)
        return h.digest()      # 16 байт, как и у настоящего NT-хеша

    @staticmethod
    def challenge_hash(peer_challenge: bytes, auth_challenge: bytes, username: str) -> bytes:
        """
        ChallengeHash = первые 8 байт SHA1(
            PeerChallenge || AuthenticatorChallenge || Username
        )
        RFC 2759.
        """
        if len(peer_challenge) != 16 or len(auth_challenge) != 16:
            raise ValueError("peer_challenge и auth_challenge должны быть по 16 байт")

        sha = hashlib.sha1()
        sha.update(peer_challenge)
        sha.update(auth_challenge)
        sha.update(username.encode("ascii"))  # в спецификации username в ASCII
        return sha.digest()[:8]  # 8 байт, которые идут в DES

    # ---------- Работа с DES-ключами (7 байт -> 8 байт с чётностью) ----------

    @staticmethod
    def _apply_des_parity_to_7bits(b7: int) -> int:
        """
        Берём 7-битное значение и добавляем 1 бит чётности DES.
        """
        b7 &= 0x7F
        ones = bin(b7).count("1")
        parity_bit = 1 if (ones % 2 == 0) else 0  # odd parity: если единиц чётное, добавляем 1
        return ((b7 << 1) | parity_bit) & 0xFF

    @classmethod
    def make_des_key_from_7_bytes(cls, seven: bytes) -> bytes:
        """
        Преобразует 7 байт (56 бит ключевого материала) в 8-байтовый DES-ключ
        с битами чётности.
        """
        if len(seven) != 7:
            raise ValueError("Нужно ровно 7 байт для DES-ключа")

        # интерпретируем 7 байт как один 56-битный big-endian integer
        key56 = int.from_bytes(seven, "big")

        out = bytearray(8)
        for i in range(8):
            # берём очередные 7 бит из key56 (слева направо)
            shift = 7 * (7 - i)
            segment = (key56 >> shift) & 0x7F
            out[i] = cls._apply_des_parity_to_7bits(segment)

        return bytes(out)

    # ---------- NT-Response (ядро MS-CHAPv2) ----------

    @classmethod
    def challenge_response(cls, challenge8: bytes, nt_hash: bytes) -> bytes:
        """
        NT-Response (24 байта) из RFC 2759:
        """
        if len(challenge8) != 8:
            raise ValueError("challenge8 должен быть 8 байт")
        if len(nt_hash) != 16:
            raise ValueError("NT hash должен быть 16 байт")

        # 1. 16 байт NT hash + 5 нулей = 21 байт
        z = nt_hash + b"\x00" * 5

        # 2–4. 3 * (7 байт -> DES-ключ -> DES(challenge8))
        resp = b""
        for i in range(3):
            seven = z[i * 7:(i + 1) * 7]          # 7 байт
            key8 = cls.make_des_key_from_7_bytes(seven)  # 8-байтовый DES-ключ
            block = DES.encrypt_block(challenge8, key8)  # один DES-блок
            resp += block

        return resp  # 24 байта

    # ---------- Функции для клиента и сервера ----------

    @classmethod
    def generate_nt_response(
        cls,
        auth_challenge: bytes,
        peer_challenge: bytes,
        username: str,
        password: str,
    ) -> bytes:
        """
        Клиентская функция: по паролю генерирует NT-Response (24 байта),
        который отправляется серверу.
        """
        nt_hash = cls.nt_password_hash(password)                 # 16 байт (упрощённый)
        chall8 = cls.challenge_hash(peer_challenge, auth_challenge, username)  # 8 байт
        return cls.challenge_response(chall8, nt_hash)           # 24 байта

    @classmethod
    def verify_nt_response(
        cls,
        auth_challenge: bytes,
        peer_challenge: bytes,
        username: str,
        stored_nt_hash: bytes,
        received_nt_response: bytes,
    ) -> bool:
        """
        Серверная функция: проверяет NT-Response от клиента, зная:
        - auth_challenge (который он сам выдавал),
        - peer_challenge (от клиента),
        - username,
        - stored_nt_hash
        """
        if len(received_nt_response) != 24:
            return False

        chall8 = cls.challenge_hash(peer_challenge, auth_challenge, username)
        expected = cls.challenge_response(chall8, stored_nt_hash)
        return expected == received_nt_response


if __name__ == "__main__":
    import os

    username = "User"
    password = "P@ssw0rd"

    auth_challenge = os.urandom(16)
    peer_challenge = os.urandom(16)

    # Имитация хранения NT-хеша в БД
    stored_nt = MSCHAPv2.nt_password_hash(password)

    # Клиент считает ответ
    client_resp = MSCHAPv2.generate_nt_response(auth_challenge, peer_challenge, username, password)
    print("NT-Response length:", len(client_resp))

    # Сервер проверяет
    ok = MSCHAPv2.verify_nt_response(auth_challenge, peer_challenge, username, stored_nt, client_resp)
    print("Verify:", ok)
