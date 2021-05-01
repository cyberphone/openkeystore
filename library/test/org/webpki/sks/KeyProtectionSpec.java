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
package org.webpki.sks;

import java.io.Serializable;

public class KeyProtectionSpec implements Serializable {
    private static final long serialVersionUID = 1L;

    BiometricProtection biometricProtection = BiometricProtection.NONE;

    String pin;   // Default none
    
    PINPol pinPolicy;
    
    public KeyProtectionSpec() { }
    
    public KeyProtectionSpec(String pin, PINPol pinPolicy) {
        this.pin = pin;
        this.pinPolicy = pinPolicy;
     }
    
    public KeyProtectionSpec(BiometricProtection biometricProtection) {
        this.biometricProtection = biometricProtection;
    }

    public KeyProtectionSpec(BiometricProtection biometricProtection, String pin, PINPol pinPolicy) {
        this(pin, pinPolicy);
        this.biometricProtection = biometricProtection;
    }
}
