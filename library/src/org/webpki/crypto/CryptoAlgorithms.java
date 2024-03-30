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

/**
 * Crypto algorithm base interface.
 */
public interface CryptoAlgorithms {

    boolean isMandatorySksAlgorithm();

    String getAlgorithmId(AlgorithmPreferences algorithmPreferences) 
            throws IllegalArgumentException;

    default String getJoseAlgorithmId() {
        return getAlgorithmId(AlgorithmPreferences.JOSE);
    }
    
    
    default int getCoseAlgorithmId() {
        throw new IllegalArgumentException("COSE algorithm not defined for " +  getJceName());
    }

    String getOid();

    String getJceName();
    
    KeyTypes getKeyType();

    default boolean isSymmetric() {
        return getKeyType() == KeyTypes.SYM;
    }
    
    boolean isDeprecated();
    
}
