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
package org.webpki.json;

public class Extension1 extends JSONCryptoHelper.Extension {
    
    String value;

    @Override
    protected void decode(JSONObjectReader rd) {
        value = rd.getString(getExtensionUri());
    }

    @Override
    public String getExtensionUri() {
        return "otherExt";
    }

    @Override
    public String toString() {
        return value;
    }
}
