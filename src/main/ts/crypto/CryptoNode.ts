/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import {
    CRYPTO_SYMMETRIC_KEY_LENGTH,
    Crypto,
    CryptoDsaEncoding,
    CryptoError,
    PrivateKey,
    CRYPTO_EC_CURVE
} from "@project-chip/matter.js/crypto";
import { Logger } from "@project-chip/matter.js/log";
import { ByteArray } from "@project-chip/matter.js/util";
import {
    toInt8,
    toUint8
} from "../utils"

declare const Java: any;
const CRYPTO_HASH_ALGORITHM = "SHA-256";
const crypto: any = Java.type('com.matterjs.crypto.Crypto');

const logger = Logger.get("CryptoNode");

export class CryptoNode extends Crypto {
    encrypt(key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray {
        //logger.debug(`encrypt: algorithm:  key: ${key} data: ${data} nonce: ${nonce} aad: ${aad}`);
        return toUint8(crypto.encrypt(toInt8(key), toInt8(data), toInt8(nonce), aad?.length ? toInt8(aad) : undefined));
    }

    decrypt(key: ByteArray, data: ByteArray, nonce: ByteArray, aad?: ByteArray): ByteArray {
        //logger.debug(`decrypt: algorithm:  key: ${key} data: ${data} nonce: ${nonce} aad: ${aad}`);
        return toUint8(crypto.decrypt(toInt8(key), toInt8(data), toInt8(nonce), aad?.length ? toInt8(aad) : undefined));
    }

    getRandomData(length: number): ByteArray {
        //logger.debug("randomBytes: size: " + length);
        return toUint8(crypto.getRandomData(length));
    }

    // the returned ecdh object is only used when calling ecdhGenerateSecret, so can be a native java object
    ecdhGeneratePublicKey(): { publicKey: ByteArray; ecdh: any } {
        //logger.debug("ecdhGeneratePublicKey");
        const ecdh = crypto.createECDH(CRYPTO_EC_CURVE);
        return { publicKey: toUint8(crypto.getPublicKey(ecdh)), ecdh: ecdh };
    }

    ecdhGenerateSecret(peerPublicKey: ByteArray, ecdh: any): ByteArray {
        //logger.debug(`ecdhGenerateSecret: ${peerPublicKey} `);
        return toUint8(crypto.ecdhGenerateSecret(toInt8(peerPublicKey), ecdh));
    }

    ecdhGeneratePublicKeyAndSecret(peerPublicKey: ByteArray): { publicKey: ByteArray; sharedSecret: ByteArray } {
        //logger.debug("ecdhGeneratePublicKeyAndSecret: algorithm: " + CRYPTO_EC_CURVE);
        const pair = crypto.ecdhGeneratePublicKeyAndSecret(toInt8(peerPublicKey));
        return { publicKey: toUint8(pair.publicKey), sharedSecret: toUint8(pair.sharedSecret) };
    }

    hash(data: ByteArray | ByteArray[]): ByteArray {
        //logger.debug(`hash: ${data}`);
        const hasher = crypto.createHash(CRYPTO_HASH_ALGORITHM);
        if (Array.isArray(data)) {
            data.forEach(chunk => hasher.update(toInt8(chunk)));
        } else {
            hasher.update(toInt8(data));
        }
        const hash = toUint8(hasher.digest())
        return hash;
    }

    pbkdf2(secret: ByteArray, salt: ByteArray, iteration: number, keyLength: number): Promise<ByteArray> {
        return new Promise<ByteArray>((resolver, rejecter) => {
            try {
                //logger.debug(`pbkdf2: secret: ${secret} salt: ${salt} iteration: ${iteration} keyLength: ${keyLength}`);
                const key = crypto.pbkdf2(toInt8(secret), toInt8(salt), iteration, keyLength, CRYPTO_HASH_ALGORITHM)
                const result = toUint8(key);
                resolver(result);
            } catch (error) {
                console.error(`pbkdf2: ${error}`);
                rejecter(error);
            }
        });
    }

    hkdf(
        secret: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: number = CRYPTO_SYMMETRIC_KEY_LENGTH,
    ): Promise<ByteArray> {
        return new Promise<ByteArray>((resolver, rejecter) => {
            try {
                //logger.debug(`hkdf: secret: ${secret} salt: ${salt} info: ${info} length: ${length}`);
                const key = crypto.hkdf(toInt8(secret), toInt8(salt), toInt8(info), length, CRYPTO_HASH_ALGORITHM)
                const result = toUint8(key);
                resolver(result);
            } catch (error) {
                rejecter(error);
            }
        });
    }

    hmac(key: ByteArray, data: ByteArray): ByteArray {
        try {
            //logger.debug(`hmac: key: ${key} data: ${data}`);
            return toUint8(crypto.hmac(toInt8(key), toInt8(data)));
        } catch (error) {
            console.error(`hmac: ${error}`);
            throw error;
        }
    }

    sign(
        privateKey: JsonWebKey,
        data: ByteArray | ByteArray[],
        dsaEncoding: CryptoDsaEncoding = "ieee-p1363",
    ): ByteArray {
        try {
            // logger.debug("sign dsaEncoding " + dsaEncoding, JSON.stringify(privateKey, null, 4));
            const signer = crypto.createSign(JSON.stringify(privateKey), dsaEncoding);
            if (Array.isArray(data)) {
                data.forEach(chunk => signer.update(toInt8(chunk)));
            } else {
                signer.update(toInt8(data));
            }
            return toUint8(signer.sign());
        } catch (error) {
            logger.debug(`sign: ${error}`);
            throw error;
        }
    }

    verify(
        publicKey: JsonWebKey,
        data: ByteArray,
        signature: ByteArray,
        dsaEncoding: CryptoDsaEncoding = "ieee-p1363",
    ) {
        try {
            //logger.debug("verify dsaEncoding " + dsaEncoding, JSON.stringify(publicKey, null, 4));
            const success = crypto.verify(publicKey.x, publicKey.y, dsaEncoding, toInt8(signature), toInt8(data));
            if (!success) throw new CryptoError("Signature verification failed");
        } catch (error) {
            console.log(`verify: ${error}`);
            throw new CryptoError("Signature verification failed");
        }
    }

    createKeyPair() {
        //logger.debug("createKeyPair: algorithm: " + CRYPTO_EC_CURVE);
        const ecdh = crypto.createECDH(CRYPTO_EC_CURVE);
        const privateKey = toUint8(crypto.getPrivateKey(ecdh));
        const publicKey = toUint8(crypto.getPublicKey(ecdh));
        return PrivateKey(privateKey, { publicKey: publicKey });
    }
}
