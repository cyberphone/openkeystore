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
     * COSE "kty" label (1).
     */
    CBORObject COSE_KTY_LABEL          = new CBORInteger(1);

    /**
     * COSE OKP "kty" identifier (1).
     */
    CBORObject COSE_OKP_KTY            = new CBORInteger(1);

    /**
     * COSE OKP "crv" label (-1).
     */
    CBORObject COSE_OKP_CRV_LABEL      = new CBORInteger(-1);

    /**
     * COSE OKP "x" label (-2).
     */
    CBORObject COSE_OKP_X_LABEL        = new CBORInteger(-2);

    /**
     * COSE EC2 "kty" identifier (2).
     */
    CBORObject COSE_EC2_KTY            = new CBORInteger(2);

    /**
     * COSE EC2 "crv" label (-1).
     */
    CBORObject COSE_EC2_CRV_LABEL      = new CBORInteger(-1);

    /**
     * COSE EC2 "x" label (-2).
     */
    CBORObject COSE_EC2_X_LABEL        = new CBORInteger(-2);

    /**
     * COSE EC2 "y" label (-3).
     */
    CBORObject COSE_EC2_Y_LABEL        = new CBORInteger(-3);
    
    /**
     * COSE RSA "kty" identifier (3).
     */
    CBORObject COSE_RSA_KTY            = new CBORInteger(3);

    /**
     * COSE RSA modulus label (-1).
     */
    CBORObject COSE_RSA_N_LABEL        = new CBORInteger(-1);

    /**
     * COSE RSA exponent label (-2).
     */
    CBORObject COSE_RSA_E_LABEL        = new CBORInteger(-2);
    
    /**
     * COSE "crv" identifier (1).
     */
    CBORObject COSE_CRV_P_256          = new CBORInteger(1);

    /**
     * COSE "crv" identifier (2).
     */
    CBORObject COSE_CRV_P_384          = new CBORInteger(2);

    /**
     * COSE "crv" identifier (3).
     */
    CBORObject COSE_CRV_P_521          = new CBORInteger(3);

    /**
     * COSE "crv" identifier (4).
     */
    CBORObject COSE_CRV_X25519         = new CBORInteger(4);

    /**
     * COSE "crv" identifier (5).
     */
    CBORObject COSE_CRV_X448           = new CBORInteger(5);

    /**
     * COSE "crv" identifier (6).
     */
    CBORObject COSE_CRV_ED25519        = new CBORInteger(6);

    /**
     * COSE "crv" identifier (7).
     */
    CBORObject COSE_CRV_ED448          = new CBORInteger(7);
    
    /////////////////////////////////////////////////////////////////
    //                                                             //
    //                Common CSF and CEF labels                    //
    //                                                             //
    // The ordering of labels is based on a desire to receive them //
    // in a logical way both for CSF and CEF.  However, since they //
    // are shared, it creates certain jumps in the numbering.      //
    /////////////////////////////////////////////////////////////////
 
    /**
     * CSF/CEF "customData" label (0).
     * Passes through <i>without any interpretation</i> and is protected by 
     * being a part of the signed data respectively AAD.
     */
    CBORObject CUSTOM_DATA_LABEL    = new CBORInteger(0);
    
    /**
     * CSF/CEF "algorithm" label (1).
     * Note: This label is also used in key encryption sub-maps.
     */
    CBORObject ALGORITHM_LABEL      = new CBORInteger(1);

    /**
     * CEF "keyEncryption" label (2).
     */
    CBORObject KEY_ENCRYPTION_LABEL = new CBORInteger(2);

    /**
     * CSF/CEF "keyId" label (3).
     * Note: This label may also be used in key encryption sub-maps.
     */
    CBORObject KEY_ID_LABEL         = new CBORInteger(3);

    /**
     * CSF/CEF "publicKey" label (4).
     */
    CBORObject PUBLIC_KEY_LABEL     = new CBORInteger(4);

    /**
     * CSF/CEF "certificatePath" label (5).
     */
    CBORObject CERT_PATH_LABEL      = new CBORInteger(5);

    /**
     * CSF "signature" label (6).
     */
    CBORObject SIGNATURE_LABEL      = new CBORInteger(6);
    
    /**
     * CEF "ephemeralKey" label (7).
     * Note: This label is only used in key encryption sub-maps.
     */
    CBORObject EPHEMERAL_KEY_LABEL  = new CBORInteger(7);

    /**
     * CEF "tag" label (8).
     */
    CBORObject TAG_LABEL            = new CBORInteger(8);
 
    /**
     * CEF "iv" label (9).
     */
    CBORObject IV_LABEL             = new CBORInteger(9);

    /**
     * CEF "cipherText" label (10).
     * Note: This label is also used in key encryption sub-maps using key-wrapping.
     */
    CBORObject CIPHER_TEXT_LABEL    = new CBORInteger(10);

}
