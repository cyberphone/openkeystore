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

/**
 * Interface holding common crypto constants.
 */
public interface CBORCryptoConstants {
    
    ////////////////////////////////
    // From RFC 8152 and RFC 8230 //
    ////////////////////////////////

    /**
     * COSE "kty" label.
     */
    int COSE_KTY_LABEL          = 1;

    /**
     * COSE OKP "kty" identifier.
     */
    int COSE_OKP_KTY            = 1;

    /**
     * COSE OKP "crv" label.
     */
    int COSE_OKP_CRV_LABEL      = -1;

    /**
     * COSE OKP "x" label.
     */
    int COSE_OKP_X_LABEL        = -2;

    /**
     * COSE EC2 "kty" identifier.
     */
    int COSE_EC2_KTY            = 2;

    /**
     * COSE EC2 "crv" label.
     */
    int COSE_EC2_CRV_LABEL      = -1;

    /**
     * COSE EC2 "x" label.
     */
    int COSE_EC2_X_LABEL        = -2;

    /**
     * COSE EC2 "y" label.
     */
    int COSE_EC2_Y_LABEL        = -3;
    
    /**
     * COSE RSA "kty" identifier.
     */
    int COSE_RSA_KTY            = 3;

    /**
     * COSE RSA modulus label.
     */
    int COSE_RSA_N_LABEL        = -1;

    /**
     * COSE RSA exponent label.
     */
    int COSE_RSA_E_LABEL        = -2;
    
    /**
     * COSE "crv" identifier.
     */
    int COSE_CRV_NIST_P_256     = 1;

    /**
     * COSE "crv" identifier.
     */
    int COSE_CRV_NIST_P_384     = 2;

    /**
     * COSE "crv" identifier.
     */
    int COSE_CRV_NIST_P_521     = 3;

    /**
     * COSE "crv" identifier.
     */
    int COSE_CRV_X25519         = 4;

    /**
     * COSE "crv" identifier.
     */
    int COSE_CRV_X448           = 5;

    /**
     * COSE "crv" identifier.
     */
    int COSE_CRV_ED25519        = 6;

    /**
     * COSE "crv" identifier.
     */
    int COSE_CRV_ED448          = 7;
    
    /////////////////////////////////////////////////////////////////
    //                                                             //
    //                Common CSF and CEF labels                    //
    //                                                             //
    // The ordering of labels is based on a desire to receive them //
    // in a logical way both for CSF and CEF.  However, since they //
    // are shared, it creates certain jumps in the numbering.      //
    /////////////////////////////////////////////////////////////////
 
    /**
     * CSF/CEF "algorithm" label (1).
     * Note: This label is also used in key encryption sub-maps.
     */
    CBORInteger ALGORITHM_LABEL      = new CBORInteger(1);

    /**
     * CEF "keyEncryption" label (2).
     */
    CBORInteger KEY_ENCRYPTION_LABEL = new CBORInteger(2);

    /**
     * CSF/CEF "keyId" label (3).
     * Note: This label may also be used in key encryption sub-maps.
     */
    CBORInteger KEY_ID_LABEL         = new CBORInteger(3);

    /**
     * CSF/CEF "publicKey" label (4).
     */
    CBORInteger PUBLIC_KEY_LABEL     = new CBORInteger(4);

    /**
     * CEF "ephemeralKey" label (5).
     * Note: This label is only used in key encryption sub-maps.
     */
    CBORInteger EPHEMERAL_KEY_LABEL  = new CBORInteger(5);

    /**
     * CSF "certificatePath" label (6).
     */
    CBORInteger CERT_PATH_LABEL      = new CBORInteger(6);
    
    /**
     * CSF "signature" label (7).
     */
    CBORInteger SIGNATURE_LABEL      = new CBORInteger(7);

    /**
     * CEF "tag" label (8).
     */
    CBORInteger TAG_LABEL            = new CBORInteger(8);
 
    /**
     * CEF "iv" label (9).
     */
    CBORInteger IV_LABEL             = new CBORInteger(9);

    /**
     * CEF "cipherText" label (10).
     * Note: This label is also used in key encryption sub-maps using key-wrapping.
     */
    CBORInteger CIPHER_TEXT_LABEL    = new CBORInteger(10);

}