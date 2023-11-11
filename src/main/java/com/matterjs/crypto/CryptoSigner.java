package com.matterjs.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Integer;
import java.security.Signature;
import java.security.Security;
import java.security.PrivateKey;
import java.util.Arrays;
import java.text.ParseException;
import java.math.BigInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoSigner {
    private static final Logger logger = LoggerFactory.getLogger(CryptoSigner.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    };

    private String dsaEncoding;
    private PrivateKey privateKey;
    private Signature signature;

    public CryptoSigner( String jwkJson, String dsaEncoding) throws ParseException, Exception {
        this.dsaEncoding = dsaEncoding;
        this.privateKey = convertJWKToPrivateKey(jwkJson);
        this.signature = Signature.getInstance("SHA256withECDSA", "BC");
        this.signature.initSign(privateKey);
    }

    public void update(byte[] data) throws Exception {
        //logger.debug("CryptoSigner.update: {}", data);
        try {
            signature.update(data);
        } catch (Exception e) {
            logger.error("CryptoSigner.update: {}", e);
            throw e;
        }
    }

    public byte[] sign() throws Exception {
        byte[] derSignature = signature.sign();

        if ("ieee-p1363".equals(dsaEncoding)) {
            return convertDerToP1363(derSignature);
        }
        return derSignature;
    }

    private byte[] convertDerToP1363(byte[] derSignature) throws Exception {
        ASN1Sequence sequence = ASN1Sequence.getInstance(derSignature);
        //logger.debug("CryptoSigner.convertDerToP1363: {}", sequence);
        BigInteger r = ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
        byte[] rBytes = bigIntegerToFixedLengthBytes(r);
        byte[] sBytes = bigIntegerToFixedLengthBytes(s);
        return CryptoSigner.concatenate(rBytes, sBytes);
    }

    private byte[] bigIntegerToFixedLengthBytes(BigInteger b) {
        //Biginteger will add an extra byte for signed numbers
        byte[] bytes = b.toByteArray();
        if (bytes.length > 32) {
            bytes = Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
        } else if (bytes.length < 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(bytes, 0, tmp, 32 - bytes.length, bytes.length);
            return tmp;
        }
        return bytes;
    }

    private PrivateKey convertJWKToPrivateKey(String jwkJson) throws ParseException, JOSEException {
        JWK jwk = JWK.parse(jwkJson);
        PrivateKey privateKey;

        if (jwk instanceof ECKey) {
            ECKey ecKey = (ECKey) jwk;
            privateKey = ecKey.toECPrivateKey();
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }

        return privateKey;
    }

    public static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length]; // create a new array
        System.arraycopy(a, 0, result, 0, a.length); // copy a into start of result
        System.arraycopy(b, 0, result, a.length, b.length); // copy b into result at offset of a.length
        return result;
    }
}
