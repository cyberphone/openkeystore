package org.webpki.sks;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.util.ArrayUtil;

public class ASN1 {
    static final byte[] RSA_ALGORITHM_OID = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01};
    static final byte[] EC_ALGORITHM_OID = {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01};
    static final byte[] EC_NAMED_CURVE_P256 = {0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};

    static final int ASN1_SEQUENCE = 0x30;
    static final int ASN1_OBJECT_IDENTIFIER = 0x06;
    static final int ASN1_INTEGER = 0x02;
    static final int ASN1_NULL = 0x05;
    static final int ASN1_BITSTRING = 0x03;
    static final int ASN1_EXPLICIT_CONTEXT_0 = 0xA0;
    static final int ASN1_EXPLICIT_CONTEXT_1 = 0xA1;
    static final int ASN1_OCTET_STRING = 0x04;

    static final int MAX_BUFFER = 16000;

    static byte[] buffer = new byte[MAX_BUFFER];
    static int index;
    static int max_buflen;
    static int length;

    static class SKSPublicKey {
        boolean rsa;
        byte[] exp_or_y;
        byte[] mod_or_x;
    }

    static class SKSPrivateKey {
        boolean rsa;
        byte[] exp_or_y;
        byte[] mod_or_x;
    }

    static public void main(String[] args) {
        if (args.length != 2 || !(args[0].equals("rp") || args[0].equals("rc") || args[0].equals("rk") || args[0].equals("we") || args[0].equals("wrs"))) {
            System.out.println("ASN1 rp|rc|rk|we|wrs file\n" +
                    "      rp = read public key, rc = read certificate, rk = read private key\n" +
                    "      we = write EC private key, wrs = write simple RSA private key");
            System.exit(3);
        }
        try {
            if (args[0].equals("rp") || args[0].equals("rc")) {
                byte[] data = ArrayUtil.readFile(args[1]);
                System.out.println("KEY L=" + (args[0].equals("rp") ? getPublicKey(data) : getPublicKeyFromCertificate(data)).length);
            } else if (args[0].equals("rk")) {
                byte[] data = ArrayUtil.readFile(args[1]);
                System.out.println("KEY L=" + getPrivateKey(data).length);
            } else if (args[0].equals("we")) {
                CustomCryptoProvider.forcedLoad(true);
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec eccgen = new ECGenParameterSpec("secp256r1");
                generator.initialize(eccgen, new SecureRandom());
                KeyPair key_pair = generator.generateKeyPair();
                ArrayUtil.writeFile(args[1], key_pair.getPrivate().getEncoded());
            } else if (args[0].equals("wrs")) {
                CustomCryptoProvider.forcedLoad(true);
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair key_pair = kpg.generateKeyPair();
                ArrayUtil.writeFile(args[1], key_pair.getPrivate().getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static byte[] getPrivateKey(byte[] data) throws GeneralSecurityException {
        init(data);
        parsePrivateKey();
        return data;
    }

    static SKSPrivateKey parsePrivateKey() throws GeneralSecurityException {
        SKSPrivateKey privateKey = new SKSPrivateKey();
        getObject(ASN1_SEQUENCE);           // Outer SEQUENCE
        getObject(ASN1_INTEGER);              // PKCS #8 version
        if (length != 1 || buffer[index++] != 0x00)
            throw new GeneralSecurityException("Unknown PKCS #8 version");
        if (privateKey.rsa = parseAlgorithmID()) {
            getPrivateKeyPayload(0);
            for (int q = 0; q < 8; q++) {
                scanObject(ASN1_INTEGER);
            }
        } else {
            getPrivateKeyPayload(1);
            getObject(ASN1_OCTET_STRING);
            if (length != 32)
                throw new GeneralSecurityException("Unexpected EC private key blob length: " + length);
            index += length;
            if (index < max_buflen && buffer[index] == (byte) ASN1_EXPLICIT_CONTEXT_0) {
                scanObject(ASN1_EXPLICIT_CONTEXT_0);
            }
            if (index < max_buflen && buffer[index] == (byte) ASN1_EXPLICIT_CONTEXT_1) {
                scanObject(ASN1_EXPLICIT_CONTEXT_1);
            }
        }
        if (index != max_buflen) throw new GeneralSecurityException("Private key length error");
        return privateKey;
    }

    static void getPrivateKeyPayload(int version) throws GeneralSecurityException {
        getObject(ASN1_OCTET_STRING);
        getObject(ASN1_SEQUENCE);
        getObject(ASN1_INTEGER);
        if (length != 1 || version != buffer[index++])
            throw new GeneralSecurityException("Unsupported private key version");
    }

    static byte[] getPublicKeyFromCertificate(byte[] data) throws GeneralSecurityException {
        init(data);
        getObject(ASN1_SEQUENCE);           // Outer SEQUENCE
        getObject(ASN1_SEQUENCE);             // Inner SEQUENCE (TBSCertificate)
        scanObject(ASN1_EXPLICIT_CONTEXT_0);    // [0] Version - Just scan over
        scanObject(ASN1_INTEGER);               // Serial Number - Just scan over
        scanObject(ASN1_SEQUENCE);              // Signature - Just scan over
        scanObject(ASN1_SEQUENCE);              // Issuer - Just scan over
        scanObject(ASN1_SEQUENCE);              // Validity - Just scan over
        scanObject(ASN1_SEQUENCE);              // Subject - Just scan over
        return returnPublicKey();               // SubjectPublicKeyInfo
    }

    static void scanObject(int tag) throws GeneralSecurityException {
        getObject(tag);
        index += length;
    }

    static byte[] returnPublicKey() throws GeneralSecurityException {
        int i = index;
        parsePublicKey();
        byte[] publicKey = new byte[length = index - i];
        System.arraycopy(buffer, index - length, publicKey, 0, length);
        return publicKey;
    }

    static SKSPublicKey parsePublicKey() throws GeneralSecurityException {
        SKSPublicKey publicKey = new SKSPublicKey();
        getObject(ASN1_SEQUENCE);
        int i = index;
        int l = length;
        if (publicKey.rsa = parseAlgorithmID()) {
            getBitString();
            getObject(ASN1_SEQUENCE);
            getObject(ASN1_INTEGER);
            index += length;
            getObject(ASN1_INTEGER);
        } else {
            getBitString();
            if (length != 65) throw new GeneralSecurityException("Incorrect ECPoint length");
            if (buffer[index] != 0x04)
                throw new GeneralSecurityException("Only uncompressed EC support");
        }
        index += length;
        if (i != index - l) throw new GeneralSecurityException("Public key length error");
        return publicKey;
    }

    private static boolean parseAlgorithmID() throws GeneralSecurityException {
        getObject(ASN1_SEQUENCE);             // SEQUENCE (AlgorithmID)
        getObject(ASN1_OBJECT_IDENTIFIER);
        if (oidMatch(RSA_ALGORITHM_OID)) {
            getObject(ASN1_NULL);
            return true;
        } else if (oidMatch(EC_ALGORITHM_OID)) {
            getObject(ASN1_OBJECT_IDENTIFIER);
            if (!oidMatch(EC_NAMED_CURVE_P256))
                throw new GeneralSecurityException("P-256 OID expected");
            return false;
        } else {
            throw new GeneralSecurityException("Unexpected OID");
        }
    }

    private static void getBitString() throws GeneralSecurityException {
        getObject(ASN1_BITSTRING);
        if (buffer[index++] != 0x00)
            throw new GeneralSecurityException("Unexpectd bitfield unused bit");
        length--;
    }

    static boolean oidMatch(byte[] oid) {
        if (length != oid.length) return false;
        for (int q = 0; q < length; q++) {
            if (buffer[index + q] != oid[q]) {
                return false;
            }
        }
        index += length;
        return true;
    }

    static byte[] getPublicKey(byte[] data) throws GeneralSecurityException {
        init(data);
        return returnPublicKey();
    }

    static void init(byte[] data) throws GeneralSecurityException {
        if (data.length > MAX_BUFFER) throw new GeneralSecurityException("Object too long");
        System.arraycopy(data, 0, buffer, 0, max_buflen = data.length);
        index = 0;
    }

    static void getObject(int tag) throws GeneralSecurityException {
        if ((buffer[index++] & 0xFF) != tag)
            throw new GeneralSecurityException("Unexpected tag: " + tag);
        length = buffer[index++] & 0xFF;
        if ((length & 0x80) != 0) {
            int q = length & 0x7F;
            length = 0;
            while (q-- > 0) {
                length <<= 8;
                length += buffer[index++] & 0xFF;
            }
        }
        if (length < 0 || index + length > max_buflen)
            throw new GeneralSecurityException("Length range error: " + length);
        System.out.println("TAG=" + tag + " I=" + index + " L=" + length);
    }
}
