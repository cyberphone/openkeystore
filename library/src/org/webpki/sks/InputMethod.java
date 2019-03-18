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
package org.webpki.sks;

import java.io.IOException;

public enum InputMethod {

    ANY          ("any",          SecureKeyStore.INPUT_METHOD_ANY),
    PROGRAMMATIC ("programmatic", SecureKeyStore.INPUT_METHOD_PROGRAMMATIC),
    TRUSTED_GUI  ("trusted-gui",  SecureKeyStore.INPUT_METHOD_TRUSTED_GUI);

    private final String name;       // As expressed in protocols

    private final byte sksValue;    // As expressed in SKS

    private InputMethod(String name, byte sksValue) {
        this.name = name;
        this.sksValue = sksValue;
    }


    public String getProtocolName() {
        return name;
    }


    public byte getSksValue() {
        return sksValue;
    }


    public static InputMethod getInputMethodFromString(String name) throws IOException {
        for (InputMethod type : InputMethod.values()) {
            if (name.equals(type.name)) {
                return type;
            }
        }
        throw new IOException("Unknown \"" + SecureKeyStore.VAR_INPUT_METHOD + "\": " + name);
    }
}
