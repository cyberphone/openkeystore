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
package org.webpki.cbor;

import java.io.IOException;

import java.security.GeneralSecurityException;

/**
 * Base class for creating CBOR signatures.
 */
public abstract class CBORSigner {

    public static final CBORInteger ALGORITHM_LABEL  = new CBORInteger(1);
    public static final CBORInteger PUBLIC_KEY_LABEL = new CBORInteger(2);
    public static final CBORInteger KEY_ID_LABEL     = new CBORInteger(3);
    public static final CBORInteger CERT_PATH_LABEL  = new CBORInteger(4);
    public static final CBORInteger SIGNATURE_LABEL  = new CBORInteger(5);
    
    String provider;

    CBORSigner() {}
    
    abstract byte[] signData(byte[] dataToSign) throws GeneralSecurityException, IOException;

    void sign(CBORObject key, CBORMapBase objectToSign) throws IOException, 
                                                               GeneralSecurityException {
        CBORMapBase signatureObject = new CBORIntegerMap();
        objectToSign.setObject(key, signatureObject);
        System.out.println(this.toString());
        signatureObject.keys.put(SIGNATURE_LABEL, 
                                 new CBORByteString(signData(objectToSign.encode())));
    }
}
