package com.matterjs.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;


public class ECDSASigner {
    private final Signature ecdsaSign;
    private final ECNamedCurveParameterSpec spec;
    private PublicKey publicKey;
    private final String encoding;

    public ECDSASigner(String d, String encoding) throws GeneralSecurityException {
        this(null, null, d, encoding);
    }

    public ECDSASigner(String x, String y, String encoding) throws GeneralSecurityException {
        this(x, y, null, encoding);
    }

    public ECDSASigner(String x, String y, String d, String encoding) throws GeneralSecurityException {
        this.encoding = encoding;
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        this.spec = ECNamedCurveTable.getParameterSpec("P-256");
        ECParameterSpec ecSpec = new ECNamedCurveSpec("P-256", spec.getCurve(), spec.getG(), spec.getN());

        if (d != null && !d.isEmpty()) {
            byte[] dBytes = Base64.getUrlDecoder().decode(d);
            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, dBytes), ecSpec);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            ecdsaSign = Signature.getInstance("SHA256withECDSA");
            ecdsaSign.initSign(privateKey);
        } else {
            ecdsaSign = null;
        }

        if (x != null && !x.isEmpty() && y != null && !y.isEmpty()) {
            byte[] xBytes = Base64.getUrlDecoder().decode(x);
            byte[] yBytes = Base64.getUrlDecoder().decode(y);
            ECPoint ecPoint = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecPoint, ecSpec);
            publicKey = keyFactory.generatePublic(pubKeySpec);
        }
    }

    public void update(byte[] data) throws SignatureException {
        this.ecdsaSign.update(data);
    }

    public byte[] sign() throws SignatureException {
        byte[] derSignature = this.ecdsaSign.sign();

        if ("ieee-p1363".equalsIgnoreCase(this.encoding)) {
            return convertToIEEE_P1363(derSignature);
        } else if ("der".equalsIgnoreCase(this.encoding)) {
            return derSignature;
        } else {
            throw new IllegalArgumentException("Unsupported encoding: " + this.encoding);
        }
    }

    public boolean verify(byte[] data, byte[] signature) throws Exception {
        if (this.publicKey == null) {
            throw new InvalidKeyException("Public key not initialized for verification.");
        }

        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(data);

        if ("ieee-p1363".equalsIgnoreCase(this.encoding)) {
            signature = convertToDER(signature);
        }

        return ecdsaVerify.verify(signature);
    }

    private byte[] convertToIEEE_P1363(byte[] derSignature) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(derSignature);
        BigInteger r = ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();

        int size = (this.spec.getCurve().getFieldSize() + 7) / 8;
        byte[] ieeeP1363Signature = new byte[2 * size];

        byte[] rBytes = bigIntegerToBytes(r, size);
        byte[] sBytes = bigIntegerToBytes(s, size);
        System.arraycopy(rBytes, 0, ieeeP1363Signature, 0, size);
        System.arraycopy(sBytes, 0, ieeeP1363Signature, size, size);

        return ieeeP1363Signature;
    }

    private static byte[] bigIntegerToBytes(BigInteger rOrS, int size) {
        byte[] bytes = new byte[size];
        byte[] biBytes = rOrS.toByteArray();
        int start = (biBytes[0] == 0) ? 1 : 0;
        int length = biBytes.length - start;
        System.arraycopy(biBytes, start, bytes, size - length, length);
        return bytes;
    }

    public byte[] convertToDER(byte[] ieeeP1363Signature) throws IOException {
        if (ieeeP1363Signature.length % 2 != 0) {
            throw new IllegalArgumentException("Invalid IEEE P1363 signature length.");
        }

        int len = ieeeP1363Signature.length / 2;

        BigInteger r = new BigInteger(1, slice(ieeeP1363Signature, 0, len));
        BigInteger s = new BigInteger(1, slice(ieeeP1363Signature, len, len * 2));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // Write the ASN.1 SEQUENCE tag
        baos.write(0x30);

        // Placeholder for the length
        baos.write(0x00);

        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        writeAsn1Integer(baos, rBytes);
        writeAsn1Integer(baos, sBytes);

        byte[] derSignature = baos.toByteArray();
        // Correct the length
        derSignature[1] = (byte) (derSignature.length - 2);

        return derSignature;
    }

    private void writeAsn1Integer(ByteArrayOutputStream baos, byte[] value) throws IOException {
        // Write ASN.1 INTEGER tag
        baos.write(0x02);

        // Write length
        int length = value.length;
        if (value[0] == 0) { // Remove padding byte if present
            length--;
        }

        baos.write(length);

        // Write the integer if it is positive, skip the padding byte if present
        if (value[0] == 0) {
            baos.write(value, 1, value.length - 1);
        } else {
            baos.write(value);
        }
    }

    private byte[] slice(byte[] data, int start, int end) {
        byte[] slice = new byte[end - start];
        System.arraycopy(data, start, slice, 0, slice.length);
        return slice;
    }
}
