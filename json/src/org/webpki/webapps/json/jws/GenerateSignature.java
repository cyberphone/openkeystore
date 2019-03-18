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
package org.webpki.webapps.json.jws;

import java.io.IOException;

import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;
import org.webpki.crypto.SymKeyVerifierInterface;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONX509Signer;

import org.webpki.util.ArrayUtil;

/**
 * Simple signature test generator
 */
public class GenerateSignature {

    static enum ACTION {SYM, EC, RSA, X509}

    static final String KEY_NAME = "mykey";

    static final byte[] SYMMETRIC_KEY = 
          { (byte) 0xF4, (byte) 0xC7, (byte) 0x4F, (byte) 0x33,
            (byte) 0x98, (byte) 0xC4, (byte) 0x9C, (byte) 0xF4,
            (byte) 0x6D, (byte) 0x93, (byte) 0xEC, (byte) 0x98,
            (byte) 0x18, (byte) 0x83, (byte) 0x26, (byte) 0x61,
            (byte) 0xA4, (byte) 0x0B, (byte) 0xAE, (byte) 0x4D,
            (byte) 0x20, (byte) 0x4D, (byte) 0x75, (byte) 0x50,
            (byte) 0x36, (byte) 0x14, (byte) 0x10, (byte) 0x20,
            (byte) 0x74, (byte) 0x34, (byte) 0x69, (byte) 0x09 };

    ACTION action;
    boolean keyInlining;

    GenerateSignature(ACTION action, boolean keyInlining) {
        this.action = action;
        this.keyInlining = keyInlining;
    }

    static class SymmetricOperations implements SymKeySignerInterface, SymKeyVerifierInterface {
        @Override
        public byte[] signData(byte[] data, MACAlgorithms algorithm) throws IOException {
            return algorithm.digest(SYMMETRIC_KEY, data);
        }

        @Override
        public MACAlgorithms getMacAlgorithm() throws IOException {
            return MACAlgorithms.HMAC_SHA256;
        }

        @Override
        public boolean verifyData(byte[] data, byte[] digest, MACAlgorithms algorithm, String keyId) throws IOException {
            if (KEY_NAME.equals(keyId)) {
                return ArrayUtil.compare(digest,
                        algorithm.digest(SYMMETRIC_KEY, data));
            }
            throw new IOException("Unknown key id: " + keyId);
        }
    }

    byte[] sign(JSONObjectWriter wr) throws IOException {
        if (action == ACTION.X509) {
            wr.setSignature(new JSONX509Signer(JWSService.clientkey_rsa.setExtendedCertPath(true)));
        } else if (action == ACTION.SYM) {
            wr.setSignature(new JSONSymKeySigner(new SymmetricOperations()).setKeyId(KEY_NAME));
        } else {
            wr.setSignature(new JSONAsymKeySigner(action == ACTION.RSA ? 
                    JWSService.clientkey_rsa : JWSService.clientkey_ec).setOutputPublicKeyInfo(keyInlining));
        }
        return wr.serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
    }
}
