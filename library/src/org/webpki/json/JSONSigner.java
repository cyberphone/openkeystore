/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.SignatureAlgorithms;

/**
 * Support class for signature generators.
 */
public abstract class JSONSigner extends JSONCryptoHelper.ExtensionsEncoder {

    JSONObjectReader extensionData;
    
    String[] excluded;

    String keyId;
    
    String provider;

    byte[] normalizedData;

    AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE_ACCEPT_PREFER;
    
    JSONSigner() {
    }
    
    abstract SignatureAlgorithms getAlgorithm() throws IOException, GeneralSecurityException;
    
    abstract byte[] signData(byte[] data) throws IOException, GeneralSecurityException;

    abstract void writeKeyData(JSONObjectWriter wr) throws IOException, GeneralSecurityException;

    /**
     * Set (object level) list of permitted extension elements.
     * This must only be done for the first signer in a multi-signature
     * scenario
     * @param names A list of permitted extensions 
     * @return this
     * @throws IOException
     */
    public JSONSigner setExtensionNames(String[] names) throws IOException {
        super.setExtensionNames(names, false);
        return this;
    }

    /**
     * Set specific extension data for this signature.
     * @param extensions JSON object holding the extension properties and associated values
     * @return this
     * @throws IOException
     */
    public JSONSigner setExtensionData(JSONObjectWriter extensions) throws IOException {
        this.extensionData = new JSONObjectReader(extensions);
        JSONCryptoHelper.checkExtensions(this.extensionData.getProperties(), false);
        return this;
    }

    /**
     * Set &quot;excl&quot; for this signature.
     * @param excluded Array holding the names of properties that must be excluded from the signature
     * @return this
     * @throws IOException
     */
    public JSONSigner setExcluded(String[] excluded) throws IOException {
        this.excluded = excluded;
        JSONSignatureDecoder.checkExcluded(excluded);
        return this;
    }

    /**
     * Set optional &quot;keyId&quot; for this signature.
     * Note: default <code>null</code>.
     * @param keyId The identifier. If null no KeyId is generated
     * @return this
     */
    public JSONSigner setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    public byte[] getNormalizedData() {
        return normalizedData;
    }
}
