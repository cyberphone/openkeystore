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
package org.webpki.asn1.cert;

public interface SubjectAltNameTypes {
    public static final int OTHER_NAME                  = 0;
    public static final int RFC822_NAME                 = 1;
    public static final int DNS_NAME                    = 2;
    public static final int X400_ADDRESS                = 3;
    public static final int DIRECTORY_NAME              = 4;
    public static final int EDI_PARTY_NAME              = 5;
    public static final int UNIFORM_RESOURCE_IDENTIFIER = 6;
    public static final int IP_ADDRESS                  = 7;
    public static final int REGISTERED_ID               = 8;
}
