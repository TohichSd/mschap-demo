// src/crypto/MSCHAPCrypto.ts
import CryptoJS from 'crypto-js';
import { utf16leEncode, concatBytes } from './utils';

export class MSCHAPCrypto {
  /**
   * NT hash = MD5(UTF-16LE(password)) — так же, как на сервере.
   */
  public ntPasswordHash(password: string): Uint8Array {
    const pwBytes = utf16leEncode(password);
    const wordArray = CryptoJS.lib.WordArray.create(pwBytes as any);
    const md5 = CryptoJS.MD5(wordArray);
    const hex = md5.toString(CryptoJS.enc.Hex);
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  /**
   * ChallengeHash = первые 8 байт SHA1(peer || auth || username)
   */
  public challengeHash(peerChallenge: Uint8Array, authChallenge: Uint8Array, username: string): Uint8Array {
    const usernameBytes = new TextEncoder().encode(username); // ASCII
    const combined = concatBytes(peerChallenge, authChallenge, usernameBytes);
    const wordArray = CryptoJS.lib.WordArray.create(combined as any);
    const sha1 = CryptoJS.SHA1(wordArray);
    const hex = sha1.toString(CryptoJS.enc.Hex).slice(0, 16); // 8 байт = 16 hex
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  /**
   * Полный NT-Response (24 байта).
   */
  public challengeResponse(challenge8: Uint8Array, ntHash: Uint8Array): Uint8Array {
    if (challenge8.length !== 8) throw new Error('challenge8 must be 8 bytes');
    if (ntHash.length !== 16) throw new Error('ntHash must be 16 bytes');

    const z = new Uint8Array(21);
    z.set(ntHash); // оставшиеся 5 байт = 0

    const resp = new Uint8Array(24);
    for (let i = 0; i < 3; i++) {
      const seven = z.slice(i * 7, (i + 1) * 7);
      const key8 = this.makeDesKeyFrom7Bytes(seven);
      const block = this.desEncryptBlock(key8, challenge8);
      resp.set(block, i * 8);
    }
    return resp;
  }

  /**
   * Высокоуровневая обёртка: считает NT-Response целиком по всем параметрам.
   */
  public generateNtResponse(
    authChallenge: Uint8Array,
    peerChallenge: Uint8Array,
    username: string,
    password: string
  ): { ntHash: Uint8Array; challenge8: Uint8Array; ntResponse: Uint8Array } {
    const ntHash = this.ntPasswordHash(password);
    const challenge8 = this.challengeHash(peerChallenge, authChallenge, username);
    const ntResponse = this.challengeResponse(challenge8, ntHash);
    return { ntHash, challenge8, ntResponse };
  }

  // ---------- Внутренняя часть: DES и ключи ----------

  private applyDesParityTo7Bits(b7: number): number {
    b7 &= 0x7f;
    const ones = b7.toString(2).split('').filter(c => c === '1').length;
    const parityBit = (ones % 2 === 0) ? 1 : 0; // odd parity
    return ((b7 << 1) | parityBit) & 0xff;
  }

  private makeDesKeyFrom7Bytes(seven: Uint8Array): Uint8Array {
    if (seven.length !== 7) throw new Error('need 7 bytes for DES key');
    let key56 = 0n;
    for (let i = 0; i < 7; i++) {
      key56 = (key56 << 8n) | BigInt(seven[i]);
    }
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      const shift = BigInt(7 * (7 - i));
      const segment = Number((key56 >> shift) & 0x7fn);
      out[i] = this.applyDesParityTo7Bits(segment);
    }
    return out;
  }

  private desEncryptBlock(key8: Uint8Array, block8: Uint8Array): Uint8Array {
    if (key8.length !== 8 || block8.length !== 8) {
      throw new Error('DES key and block must be 8 bytes');
    }

    const keyWA = CryptoJS.lib.WordArray.create(key8 as any);
    const dataWA = CryptoJS.lib.WordArray.create(block8 as any);

    const encrypted = CryptoJS.DES.encrypt(dataWA, keyWA, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.NoPadding,
    });

    const hex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }
}
