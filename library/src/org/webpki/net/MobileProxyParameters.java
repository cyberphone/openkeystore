/*
 *  Copyright 2015-2018 WebPKI.org (httpwebpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      httpswww.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.net;

public interface MobileProxyParameters {

    // A proxy URI looks like: SCHEME + '//:' + HOST + data
    
    String HOST_SATURN       = "saturn";
    String HOST_KEYGEN2      = "keygen2";
    String HOST_MOBILEID     = "mobileid";
    
    String SCHEME_QRCODE     = "qrcode";
    String SCHEME_W3CPAY     = "w3cpay";
    String SCHEME_URLHANDLER = "intent";
    
    String ANDROID_PACKAGE_NAME = "org.webpki.mobile.android";
}
