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
package org.webpki.crypto;

import java.io.IOException;

public enum SymEncryptionAlgorithms implements EncryptionAlgorithms {

    AES128_CBC      ("http://www.w3.org/2001/04/xmlenc#aes128-cbc", 
                     "AES/CBC/PKCS5Padding", 16, true,  true, true, false),
            
    AES192_CBC      ("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                     "AES/CBC/PKCS5Padding", 24, true,  true, true, false),
                
    AES256_CBC      ("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                     "AES/CBC/PKCS5Padding", 32, true,  true, true, false),
                
    KW_AES128       ("http://www.w3.org/2001/04/xmlenc#kw-aes128",
                     "AESWrap",              16, false, false, false, true),
                
    KW_AES256       ("http://www.w3.org/2001/04/xmlenc#kw-aes256",
                     "AESWrap",              32, false, false, false, true),
                
    AES_ECB_NOPAD   ("http://xmlns.webpki.org/sks/algorithm#aes.ecb.nopad",
                     "AES/ECB/NoPadding",    0,  false, false, true,  true),  // SecurID
                
    AES_ECB_PAD     ("http://xmlns.webpki.org/sks/algorithm#aes.ecb",
                     "AES/ECB/PKCS5Padding", 0,  false, false, false, false),
                
    AES_CBC_NOPAD   ("http://xmlns.webpki.org/sks/algorithm#aes.cbc.nopad",
                     "AES/CBC/NoPadding",    0,  true,  false, false,  true),
                
    AES_CBC_PAD     ("http://xmlns.webpki.org/sks/algorithm#aes.cbc",
                     "AES/CBC/PKCS5Padding", 0,  true,  false, true,   false);

    private final String sksName;          // As expressed in SKS
    private final String jceName;          // As expressed for JCE
    private final int keyLength;           // 0 => 16, 24 and 32 are ok
    private final boolean ivMode;          // CBC
    private final boolean internalIv;      // XML Encryption
    private final boolean sksMandatory;    // If required
    private final boolean needsPadding;    // If that is the case

    private SymEncryptionAlgorithms(String sksName, 
                                    String jceName,
                                    int keyLength,
                                    boolean ivMode,
                                    boolean internalIv,
                                    boolean sksMandatory,
                                    boolean needsPadding) {
        this.sksName = sksName;
        this.jceName = jceName;
        this.keyLength = keyLength;
        this.ivMode = ivMode;
        this.internalIv = internalIv;
        this.sksMandatory = sksMandatory;
        this.needsPadding = needsPadding;
    }


    @Override
    public boolean isSymmetric() {
        return true;
    }


    @Override
    public boolean isMandatorySksAlgorithm() {
        return sksMandatory;
    }


    @Override
    public String getJceName() {
        return jceName;
    }


    @Override
    public String getOid() {
        return null;
    }


    public int getKeyLength() {
        return keyLength;
    }


    public boolean needsIv() {
        return ivMode;
    }


    public boolean internalIv() {
        return internalIv;
    }


    public boolean needsPadding() {
        return needsPadding;
    }


    public static SymEncryptionAlgorithms getAlgorithmFromId(String algorithmId) throws IOException {
        for (SymEncryptionAlgorithms alg : values()) {
            if (algorithmId.equals(alg.sksName)) {
                return alg;
            }
        }
        throw new IOException("Unknown algorithm: " + algorithmId);
    }


    @Override
    public String getAlgorithmId(AlgorithmPreferences algorithmPreferences) throws IOException {
        if (algorithmPreferences == AlgorithmPreferences.JOSE) {
            throw new IOException("There is no JOSE algorithm for: " + toString());
        }
        return sksName;
    }


    @Override
    public boolean isDeprecated() {
        return false;
    }
}
