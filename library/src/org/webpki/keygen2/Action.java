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
package org.webpki.keygen2;

import java.io.IOException;

public enum Action {

    MANAGE ("manage", true),
    UNLOCK ("unlock", false);

    private final String jsonName;             // As expressed in JSON

    private final boolean keyInitAllowed;      // KeyInitialization permitted

    private Action(String jsonName, boolean keyInitAllowed) {
        this.jsonName = jsonName;
        this.keyInitAllowed = keyInitAllowed;
    }


    public String getJSONName() {
        return jsonName;
    }

    public boolean mayInitializeKeys() {
        return keyInitAllowed;
    }

    public static Action getActionFromString(String jsonName) throws IOException {
        for (Action action : Action.values()) {
            if (jsonName.equals(action.jsonName)) {
                return action;
            }
        }
        throw new IOException("Unknown action: " + jsonName);
    }
}
