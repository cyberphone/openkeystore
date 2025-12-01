/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.crypto;


import java.util.Arrays;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Key;

import java.security.interfaces.XECKey;
import java.security.interfaces.EdECKey;

import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.HashMap;

import org.webpki.util.HexaDecimal;

// Source configured for JDK 17 and upwards.

/**
 * Support methods for "OKP" [<a href='https://datatracker.ietf.org/doc/html/rfc8037'>RFC8037</a>].
 */ 
public class OkpSupport {
    
    private OkpSupport() {}

    static byte[] addByteArrays(byte[]a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    static final HashMap<KeyAlgorithms,Integer> okpKeyLength = new HashMap<>();

    static {
        okpKeyLength.put(KeyAlgorithms.ED25519, 32);
        okpKeyLength.put(KeyAlgorithms.ED448,   57);
        okpKeyLength.put(KeyAlgorithms.X25519,  32);
        okpKeyLength.put(KeyAlgorithms.X448,    56);
    }

    static final HashMap<KeyAlgorithms,byte[]> pubKeyPrefix = new HashMap<>();
    
    static {
        pubKeyPrefix.put(KeyAlgorithms.ED25519, 
                         HexaDecimal.decode("302a300506032b6570032100"));
        pubKeyPrefix.put(KeyAlgorithms.ED448,
                         HexaDecimal.decode("3043300506032b6571033a00"));
        pubKeyPrefix.put(KeyAlgorithms.X25519,
                         HexaDecimal.decode("302a300506032b656e032100"));
        pubKeyPrefix.put(KeyAlgorithms.X448,
                         HexaDecimal.decode("3042300506032b656f033900"));
    }

    static final byte PRIV_KEY_LENGTH_INDEX = 15;

    static final HashMap<KeyAlgorithms,byte[]> privKeyPrefix = new HashMap<>();

    static {
        privKeyPrefix.put(KeyAlgorithms.ED25519, 
                          HexaDecimal.decode("302e020100300506032b657004220420"));
        privKeyPrefix.put(KeyAlgorithms.ED448,
                          HexaDecimal.decode("3047020100300506032b6571043b0439"));
        privKeyPrefix.put(KeyAlgorithms.X25519,
                          HexaDecimal.decode("302e020100300506032b656e04220420"));
        privKeyPrefix.put(KeyAlgorithms.X448,
                          HexaDecimal.decode("3046020100300506032b656f043a0438"));
    }

    public static byte[] public2RawKey(PublicKey publicKey, KeyAlgorithms keyAlgorithm) {
        byte[] encoded = publicKey.getEncoded();
        int prefixLength = pubKeyPrefix.get(keyAlgorithm).length;
        int keyLength = okpKeyLength.get(keyAlgorithm);
        if (keyLength != encoded.length - prefixLength) {
            throw new CryptoException("Wrong public key length for: " + keyAlgorithm.toString());
        }
        return Arrays.copyOfRange(encoded, prefixLength, prefixLength + keyLength);
    }

    public static PublicKey raw2PublicKey(byte[] x, KeyAlgorithms keyAlgorithm) {
        if (okpKeyLength.get(keyAlgorithm) != x.length) {
            throw new CryptoException("Wrong public key length for: " + keyAlgorithm.toString());
        }
        try {
            return KeyFactory.getInstance(keyAlgorithm.getJceName())
                    .generatePublic(new X509EncodedKeySpec(
                        addByteArrays(pubKeyPrefix.get(keyAlgorithm), x)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    public static byte[] private2RawKey(PrivateKey privateKey, KeyAlgorithms keyAlgorithm) {
        byte[] encoded = privateKey.getEncoded();
        int keyLength = okpKeyLength.get(keyAlgorithm);
        byte[] prefix = privKeyPrefix.get(keyAlgorithm);
        if (encoded.length <= prefix.length || encoded[PRIV_KEY_LENGTH_INDEX] != keyLength) {
            throw new CryptoException("Wrong private key length for: " + keyAlgorithm.toString());
        }
        return Arrays.copyOfRange(encoded, prefix.length, prefix.length + keyLength);
    }

    public static PrivateKey raw2PrivateKey(byte[] d, KeyAlgorithms keyAlgorithm) {
        if (okpKeyLength.get(keyAlgorithm) != d.length) {
            throw new CryptoException("Wrong private key length for: " + keyAlgorithm.toString());
        }
        try {
            return KeyFactory.getInstance(keyAlgorithm.getJceName())
                    .generatePrivate(new PKCS8EncodedKeySpec(
                        addByteArrays(privKeyPrefix.get(keyAlgorithm), d)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    public static KeyAlgorithms getKeyAlgorithm(Key key) {
        if (key instanceof XECKey xecKey) {
            return KeyAlgorithms.getKeyAlgorithmFromId(
                       ((NamedParameterSpec)xecKey.getParams()).getName(),
                       AlgorithmPreferences.JOSE);
        }
        if (key instanceof EdECKey edECKey) {
            return KeyAlgorithms.getKeyAlgorithmFromId(edECKey.getParams().getName(),
                                                       AlgorithmPreferences.JOSE);
        }
        throw new CryptoException("Unknown OKP key type: " + key.getClass().getName());
    }
}
