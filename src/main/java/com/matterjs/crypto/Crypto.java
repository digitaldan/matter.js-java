package com.matterjs.crypto;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Crypto {
    private static final String CRYPTO_EC_CURVE = "secp256r1";
    private static final int CRYPTO_AUTH_TAG_LENGTH = 128; // in bits
    private static final Logger logger = LoggerFactory.getLogger(Crypto.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] getRandomData(int length) throws Exception {
        byte[] data = new byte[length];
        SecureRandom.getInstanceStrong().nextBytes(data);
        return data;
    }

    public static byte[] hmac(byte[] key, byte[] data) throws Exception {
        // logger.debug("hmac: algorithm: HmacSHA256");
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            logger.debug("could not hmac", e);
            throw e;
        }
    }

    public static byte[] ecdhGenerateSecret(byte[] peerPublicKey, KeyPair ecdh) throws Exception {
        //logger.debug("ecdhGenerateSecret: algorithm: " + CRYPTO_EC_CURVE);
        try {
            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
            keyAgree.init(ecdh.getPrivate());
            keyAgree.doPhase(convertRawToPublicKey(peerPublicKey), true);
            return keyAgree.generateSecret();
        } catch (Exception e) {
            logger.debug("could not generate secret", e);
            throw e;
        }
    }

    public static EcdhPair ecdhGeneratePublicKeyAndSecret(byte[] peerPublicKey) {
        //logger.debug("ecdhGeneratePublicKeyAndSecret: algorithm: " + CRYPTO_EC_CURVE);
        try {
            KeyPair keyPair = createECDH(CRYPTO_EC_CURVE);
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(keyPair.getPrivate());
            // is this byte array really a raw public key? or is it in a specific format?
            keyAgreement.doPhase(convertRawToPublicKey(peerPublicKey), true);
            byte[] sharedSecret = keyAgreement.generateSecret();
            return new EcdhPair(Crypto.getPublicKey(keyPair), sharedSecret);
        } catch (Exception e) {
            logger.debug("could not generate public key and secret", e);
            throw new RuntimeException("Error generating public key and secret", e);
        }
    }

    public static class EcdhPair {
        public byte[] publicKey;
        public byte[] sharedSecret;

        public EcdhPair(byte[] publicKey, byte[] sharedSecret) {
            this.publicKey = publicKey;
            this.sharedSecret = sharedSecret;
        }
    }

    private static PublicKey convertRawToPublicKey(byte[] rawPublicKey) throws Exception {
        X9ECParameters ecParams = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(CRYPTO_EC_CURVE);
        ECCurve curve = ecParams.getCurve();

        org.bouncycastle.math.ec.ECPoint bcPoint = curve.decodePoint(rawPublicKey);

        ECPoint point = new ECPoint(bcPoint.getXCoord().toBigInteger(), bcPoint.getYCoord().toBigInteger());

        ECParameterSpec spec = new ECNamedCurveSpec(
                CRYPTO_EC_CURVE,
                curve,
                ecParams.getG(),
                ecParams.getN(),
                ecParams.getH(),
                ecParams.getSeed());

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, spec);

        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(pubKeySpec);
    }

    public static byte[] decrypt(byte[] key, byte[] data, byte[] nonce, byte[] add)
            throws RuntimeException {
        try {
            SecretKey secretKey = new SecretKeySpec(key, "AES");

            AESEngine aesEngine = new AESEngine();

            CipherParameters cipherParams = new KeyParameter(secretKey.getEncoded());
            aesEngine.init(false, cipherParams);

            CCMBlockCipher cipher = new CCMBlockCipher(aesEngine);

            AEADParameters aeadParams = new AEADParameters(new KeyParameter(secretKey.getEncoded()),
                    CRYPTO_AUTH_TAG_LENGTH, nonce, add);

            cipher.init(false, aeadParams);

            int outputLength = cipher.getOutputSize(data.length);
            byte[] output = new byte[outputLength];

            int outputOffset = cipher.processBytes(data, 0, data.length,
                    output, 0);

            outputOffset += cipher.doFinal(output, outputOffset);

            return output;
        } catch (Exception e) {
            logger.debug("could not decrypt", e);
            throw new RuntimeException(e.getLocalizedMessage(), e);
        }
    }

    public static byte[] encrypt(byte[] key, byte[] data, byte[] nonce, byte[] aad) {
        try {
            CCMBlockCipher ccmBlockCipher = new CCMBlockCipher(new AESEngine());

            CipherParameters params = new AEADParameters(new KeyParameter(key), 128,
                    nonce, aad);

            ccmBlockCipher.init(true, params);

            byte[] output = new byte[ccmBlockCipher.getOutputSize(data.length)];
            int len = ccmBlockCipher.processBytes(data, 0, data.length, output, 0);

            len += ccmBlockCipher.doFinal(output, len);
            // logger.debug("encrypt: final output length : " + output.length + " key len: "
            //         + len + " diff "
            //         + (output.length - len));
            return output;
        } catch (Exception e) {
            logger.error("Encryption failed", e);
            throw new RuntimeException("Error finalizing cipher data", e);
        }
    }

    public static byte[] randomBytes(int size) throws NoSuchAlgorithmException {
        byte[] bytes = new byte[size];
        SecureRandom.getInstanceStrong().nextBytes(bytes);
        return bytes;
    }

    public static KeyPair createECDH(String algorithm) throws Exception {
        //logger.debug("createECDH: algorithm: " + algorithm);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(algorithm);
            keyPairGenerator.initialize(ecGenParameterSpec);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            logger.debug("could not create ecdh", e);
            throw e;
        }
    }

    public static byte[] getPrivateKey(KeyPair keyPair) {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        BigInteger s = privateKey.getS();
        byte[] sBytes = s.toByteArray();
        //logger.debug("Private key length: {} key: {}", sBytes.length, sBytes);
        sBytes = stripLeadingZeroes(s.toByteArray());
        return sBytes;
    }

    public static byte[] getPublicKey(KeyPair keyPair) {
        try {
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            ECPoint ecPoint = publicKey.getW();

            byte[] x = stripLeadingZeroes(ecPoint.getAffineX().toByteArray());
            byte[] y = stripLeadingZeroes(ecPoint.getAffineY().toByteArray());

            byte[] uncompressedKey = new byte[1 + x.length + y.length];
            uncompressedKey[0] = 0x04; // Prepend the 0x04 prefix for uncompressed form

            System.arraycopy(x, 0, uncompressedKey, 1, x.length);
            System.arraycopy(y, 0, uncompressedKey, 1 + x.length, y.length);

            return uncompressedKey;
        } catch (Exception e) {
            logger.debug("could not get public key", e);
            throw e;
        }
    }

    private static byte[] stripLeadingZeroes(byte[] array) {
        if (array[0] == 0) {
            return Arrays.copyOfRange(array, 1, array.length);
        }
        return array;
    }

    public static MessageDigest createHash(String algorithm) throws NoSuchAlgorithmException {
        // logger.debug("createHash: algorithm: " + algorithm);
        return MessageDigest.getInstance(algorithm);
    }

    public static byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int keylen, String digest)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            PKCS5S2ParametersGenerator generator = null;
            switch (digest.toLowerCase().replace("-", "")) {
                case "sha1":
                    generator = new PKCS5S2ParametersGenerator();
                    generator.init(password, salt, iterations);
                    break;
                case "sha256":
                    generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
                    generator.init(password, salt, iterations);
                    break;
                case "sha512":
                    generator = new PKCS5S2ParametersGenerator(new SHA512Digest());
                    generator.init(password, salt, iterations);
                    break;
                default:
                    throw new NoSuchAlgorithmException("Digest " + digest + " not supported.");
            }
            
            KeyParameter key = (KeyParameter) generator.generateDerivedMacParameters(keylen * 8);
            return key.getKey();
        } catch (Exception e) {
            logger.debug("could not derive key", e);
            throw e;
        }
    }

    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length, String macAlgorithm) {
        // logger.debug("hkdf: ikm: " + Base64.getEncoder().encodeToString(ikm) + ", salt: "
        //         + Base64.getEncoder().encodeToString(salt) + ", info: " + Base64.getEncoder().encodeToString(info)
        //         + ", length: " + length + ", macAlgorithm: " + macAlgorithm);
        try {
            Digest digest = null;
            switch (macAlgorithm) {
                case "HMACSHA256":
                case "SHA-256":
                    digest = new SHA256Digest();
                    break;
                case "HMACSHA512":
                case "SHA-512":
                    digest = new SHA512Digest();
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported MAC algorithm: " + macAlgorithm);
            }
            if (salt.length == 0) {
                salt = null;
            }
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
            hkdf.init(new HKDFParameters(ikm, salt, info));
            byte[] okm = new byte[length];
            hkdf.generateBytes(okm, 0, length);
            return okm;
        } catch (Exception e) {
            logger.debug("could not derive key", e);
            throw e;
        }
    }

    public static CryptoSigner createSign(String jwt, String encoding) throws Exception {
        //logger.debug(encoding + " createSign: jwt: " + jwt);
        try {
            return new CryptoSigner(jwt, encoding);
        } catch (Exception e) {
            logger.debug("Error creating CryptoSigner", e);
            throw new Exception("Error creating CryptoSigner " + e.getMessage());
        }
    }

    public static boolean verify(String x, String y, String encoding, byte[] signature, byte[] data) throws Exception {
        try {
            ECDSASigner signer = new ECDSASigner(x, y, encoding);
            return signer.verify(data, signature);
        } catch (Exception e) {
            logger.debug("Error creating ECDSASigner", e);
            throw new Exception("Error creating ECDSASigner " + e.getMessage());
        }
    }
}
