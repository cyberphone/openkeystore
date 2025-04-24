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
package org.webpki.cbor;

/**
 * Interface holding common crypto constants.
 */
public interface CBORCryptoConstants {
    
    ////////////////////////////////
    // From RFC 8152 and RFC 8230 //
    ////////////////////////////////

    
    /////////////////
    // COSE Labels //
    ///////////////// 
    
    /**
     * COSE "kty" label (1).
     */
    CBORInt COSE_KTY_LBL           = new CBORInt(1);

    /**
     * COSE "kid" label (2).
     */
    CBORInt COSE_KID_LBL           = new CBORInt(2);

    /**
     * COSE OKP "crv" label (-1).
     */
    CBORInt COSE_OKP_CRV_LBL       = new CBORInt(-1);

    /**
     * COSE OKP "x" label (-2).
     */
    CBORInt COSE_OKP_X_LBL         = new CBORInt(-2);

   /**
     * COSE EC2 "crv" label (-1).
     */
    CBORInt COSE_EC2_CRV_LBL       = new CBORInt(-1);

    /**
     * COSE EC2 "x" label (-2).
     */
    CBORInt COSE_EC2_X_LBL         = new CBORInt(-2);

    /**
     * COSE EC2 "y" label (-3).
     */
    CBORInt COSE_EC2_Y_LBL         = new CBORInt(-3);

    /**
     * COSE RSA modulus label (-1).
     */
    CBORInt COSE_RSA_N_LBL         = new CBORInt(-1);

    /**
     * COSE RSA exponent label (-2).
     */
    CBORInt COSE_RSA_E_LBL         = new CBORInt(-2);


    //////////////////////
    // COSE Identifiers //
    //////////////////////

    /**
     * COSE EC2 "kty" identifier (2).
     */
    CBORInt COSE_EC2_KTY_ID        = new CBORInt(2);
    
    /**
     * COSE OKP "kty" identifier (1).
     */
    CBORInt COSE_OKP_KTY_ID        = new CBORInt(1);

    /**
     * COSE RSA "kty" identifier (3).
     */
    CBORInt COSE_RSA_KTY_ID        = new CBORInt(3);

    /**
     * COSE "crv" identifier (1).
     */
    CBORInt COSE_CRV_P_256_ID      = new CBORInt(1);

    /**
     * COSE "crv" identifier (2).
     */
    CBORInt COSE_CRV_P_384_ID      = new CBORInt(2);

    /**
     * COSE "crv" identifier (3).
     */
    CBORInt COSE_CRV_P_521_ID      = new CBORInt(3);

    /**
     * COSE "crv" identifier (4).
     */
    CBORInt COSE_CRV_X25519_ID     = new CBORInt(4);

    /**
     * COSE "crv" identifier (5).
     */
    CBORInt COSE_CRV_X448_ID       = new CBORInt(5);

    /**
     * COSE "crv" identifier (6).
     */
    CBORInt COSE_CRV_ED25519_ID    = new CBORInt(6);

    /**
     * COSE "crv" identifier (7).
     */
    CBORInt COSE_CRV_ED448_ID      = new CBORInt(7);
    
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
    CBORInt CXF_CUSTOM_DATA_LBL    = new CBORInt(0);
    
    /**
     * CSF/CEF "algorithm" label (1).
     * Note: This label is also used in key encryption sub-maps.
     */
    CBORInt CXF_ALGORITHM_LBL      = new CBORInt(1);

    /**
     * CEF "keyEncryption" label (2).
     */
    CBORInt CEF_KEY_ENCRYPTION_LBL = new CBORInt(2);

    /**
     * CSF/CEF "keyId" label (3).
     * Note: This label may also be used in key encryption sub-maps.
     */
    CBORInt CXF_KEY_ID_LBL         = new CBORInt(3);

    /**
     * CSF/CEF "publicKey" label (4).
     */
    CBORInt CXF_PUBLIC_KEY_LBL     = new CBORInt(4);

    /**
     * CSF/CEF "certificatePath" label (5).
     */
    CBORInt CXF_CERT_PATH_LBL      = new CBORInt(5);

    /**
     * CSF "signature" label (6).
     */
    CBORInt CSF_SIGNATURE_LBL      = new CBORInt(6);
    
    /**
     * CEF "ephemeralKey" label (7).
     * Note: This label is only used in key encryption sub-maps.
     */
    CBORInt CEF_EPHEMERAL_KEY_LBL  = new CBORInt(7);

    /**
     * CEF "tag" label (8).
     */
    CBORInt CEF_TAG_LBL            = new CBORInt(8);
 
    /**
     * CEF "iv" label (9).
     */
    CBORInt CEF_IV_LBL             = new CBORInt(9);

    /**
     * CEF "cipherText" label (10).
     * Note: This label is also used in key encryption sub-maps using key-wrapping.
     */
    CBORInt CEF_CIPHER_TEXT_LBL    = new CBORInt(10);

    /**
     * Reserved label holding the CSF container object.
     */
    CBORSimple CSF_CONTAINER_LBL   = new CBORSimple(99) ;     

}
