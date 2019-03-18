/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.json;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

/**
 * Testing public keys
 */
public class Keys {
    static final String CONTEXT = "http://keys/test";
    static final int ROUNDS = 1000;
    static JSONDecoderCache cache = new JSONDecoderCache();
    static KeyAlgorithms[] ec_curves;
    static int ec_index;

    static final byte[] EC_OID = {0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01};

    static {
        CustomCryptoProvider.conditionalLoad(true);
    }

    @SuppressWarnings("serial")
    public static class Reader extends JSONDecoder {
        PublicKey publicKey;

        PublicKey getPublicKey() throws IOException {
            return publicKey;
        }

        @Override
        protected void readJSONData(JSONObjectReader rd) throws IOException {
            publicKey = rd.getPublicKey(AlgorithmPreferences.JOSE_ACCEPT_PREFER);
        }

        @Override
        public String getContext() {
            return CONTEXT;
        }
    }

    @SuppressWarnings("serial")
    static class Writer extends JSONEncoder {
        PublicKey publicKey;
        AlgorithmPreferences jose_curve;

        Writer(PublicKey publicKey, AlgorithmPreferences jose_curve) {
            this.publicKey = publicKey;
            this.jose_curve = jose_curve;
        }

        @Override
        protected void writeJSONData(JSONObjectWriter wr) throws IOException {
            wr.setPublicKey(publicKey, jose_curve);
        }

        @Override
        public String getContext() {
            return CONTEXT;
        }
    }

    static void show() {
        System.out.println("logging-flag\n");
        System.exit(0);
    }

    static void Run(boolean rsa, boolean list, AlgorithmPreferences jose_curve) throws GeneralSecurityException, IOException {
        AlgorithmParameterSpec alg_par_spec = rsa ?
                new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)
                :
                new ECGenParameterSpec(ec_curves[ec_index % ec_curves.length].getJceName());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(rsa ? "RSA" : "EC");
        kpg.initialize(alg_par_spec, new SecureRandom());
        KeyPair key_pair = kpg.generateKeyPair();
        PublicKey publicKey = key_pair.getPublic();
        byte[] data = new Writer(publicKey, jose_curve).serializeJSONDocument(JSONOutputFormats.PRETTY_PRINT);
        Reader reader = (Reader) cache.parse(data);
        boolean ec_flag = false;
        byte[] gen_pk = publicKey.getEncoded();
        for (int j = 4; j < 11; j++) {
            ec_flag = true;
            for (int i = 0; i < EC_OID.length; i++) {
                if (gen_pk[j + i] != EC_OID[i]) {
                    ec_flag = false;
                }
            }
            if (ec_flag) break;
        }
        if (ec_flag == rsa) {
            throw new IOException("Failed to find EC");
        }
        if (!ArrayUtil.compare(reader.getPublicKey().getEncoded(), gen_pk)) {
            throw new IOException("Unmatching keys:" + publicKey.toString());
        }
        if (list) {
            System.out.println("\n" + new String(data, "UTF-8") + Base64URL.encode(reader.getPublicKey().getEncoded()));
        }
    }

    public static void main(String[] argc) {
        if (argc.length != 1) {
            show();
        }
        try {
            Vector<KeyAlgorithms> ecs = new Vector<KeyAlgorithms>();
            for (KeyAlgorithms ka : KeyAlgorithms.values()) {
                if (ka.isECKey()) {
                    ecs.add(ka);
                }
            }
            ec_curves = ecs.toArray(new KeyAlgorithms[0]);
            cache.addToCache(Reader.class);
            for (int i = 0; i < ROUNDS; i++) {
                Run(true, new Boolean(argc[0]), AlgorithmPreferences.SKS);
                Run(false, new Boolean(argc[0]), AlgorithmPreferences.SKS);
                Run(false, new Boolean(argc[0]), AlgorithmPreferences.JOSE_ACCEPT_PREFER);
                ec_index++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }
}
