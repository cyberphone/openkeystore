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
package org.webpki.keygen2;

import java.io.Serializable;

import java.math.BigInteger;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyTypes;

public class KeySpecifier implements Serializable {

    private static final long serialVersionUID = 1L;

    byte[] keyParameters;

    KeyAlgorithms keyAlgorithm;

    public KeySpecifier(KeyAlgorithms keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }


    KeySpecifier(KeyAlgorithms keyAlgorithm, byte[] optionalParameter) {
        this(keyAlgorithm);
        if (optionalParameter != null) {
            if (!keyAlgorithm.hasParameters()) {
                throw new KeyGen2Exception("Algorithm '" + keyAlgorithm.toString() + "' does not use \"" + KeyGen2Constants.KEY_PARAMETERS_JSON + "\"");
            }
            if (keyAlgorithm.getKeyType() == KeyTypes.RSA) {
                keyParameters = optionalParameter;
            } else {
                throw new KeyGen2Exception("Algorithm '" + keyAlgorithm.toString() + "' not implemented");
            }
        }
    }


    public KeySpecifier(KeyAlgorithms keyAlgorithm, long parameter) {
        this(keyAlgorithm, BigInteger.valueOf(parameter).toByteArray());
    }


    public KeySpecifier(String uri, byte[] optionalParameters) {
        this(KeyAlgorithms.getKeyAlgorithmFromId(uri, AlgorithmPreferences.SKS), optionalParameters);
    }


    public byte[] getKeyParameters() {
        return keyParameters;
    }


    public KeyAlgorithms getKeyAlgorithm() {
        return keyAlgorithm;
    }
}
