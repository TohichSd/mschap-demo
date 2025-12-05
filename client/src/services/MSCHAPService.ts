// src/services/ProtocolDemoService.ts
import {ApiClient} from '../api/ApiClient';
import {MSCHAPCrypto} from '../crypto/MSCHAPCrypto';
import {base64ToBytes, bytesToBase64, randomBytes, toHex} from '../crypto/utils';

export interface ILogger {
    log(message: string): void;
}

export class ProtocolDemoService {
    constructor(
        private readonly api: ApiClient,
        private readonly crypto: MSCHAPCrypto,
    ) {
    }

    public async runDemo(username: string, password: string, logger: ILogger): Promise<boolean> {
        logger.log('Запрос challenge у сервера...');
        // 1. challenge
        const challenge = await this.api.getChallenge(username);
        logger.log(`Получен session_id = ${challenge.session_id}`);
        const authChallenge = base64ToBytes(challenge.auth_challenge);
        logger.log(`auth_challenge = ${toHex(authChallenge)}`);

        // 2. peer_challenge
        const peerChallenge = randomBytes(16);
        logger.log(`peer_challenge = ${toHex(peerChallenge)}`);

        // 3. NT-hash
        const ntHash = this.crypto.ntPasswordHash(password);
        logger.log(`NT hash= ${toHex(ntHash)}`);

        // 4. ChallengeHash (8 байт)
        const chall8 = this.crypto.challengeHash(peerChallenge, authChallenge, username);
        logger.log(`ChallengeHash = ${toHex(chall8)}`);

        // 5. NT-Response
        const ntResponse = this.crypto.challengeResponse(chall8, ntHash);
        logger.log(`NT-Response Клиента = ${toHex(ntResponse)}`);

        // 6. отправка результата
        const result = await this.api.sendAuthResponse({
            sessionId: challenge.session_id,
            username,
            peerChallengeB64: bytesToBase64(peerChallenge),
            ntResponseB64: bytesToBase64(ntResponse),
        });

        logger.log(`Состояние запроса: success = ${result.success}`);

        const serverNtResponseBytes = base64ToBytes(result.server_nt_response);
        logger.log(`NT-Response сервера = ${toHex(serverNtResponseBytes)}`);

        // Простая проверка совпадения
        const equal =
            serverNtResponseBytes.length === ntResponse.length &&
            serverNtResponseBytes.every((b, i) => b === ntResponse[i]);

        logger.log(
            equal
                ? 'Проверка: NT-Response клиента и сервера совпадают'
                : 'Проверка: NT-Response клиента и сервера НЕ совпадают'
        );

        return result.success;
    }
}
