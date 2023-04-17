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
package org.webpki.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.BeforeClass;
import org.junit.Test;
import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORObject;
import org.webpki.util.UTF8;


/**
 * ECDH tests.
 * <p>
 * ECDH is actually quite complicated due to the provider concept.
 * In practical terms: a private key used for key agreement may
 * come from different providers, depending on if the key represents
 * a static or an ephemeral key.
 * </p>
 *  
 */
public class ECDHTest {

    private static Logger logger = Logger.getLogger(CustomCryptoProvider.class.getCanonicalName());

    static final byte[] DATA_TO_ENCRYPT = 
            UTF8.encode("The quick brown fox jumps over the lazy bear");
    
    static final String ALT_PROVIDER = "BC";

    @BeforeClass
    public static void openFile() throws Exception {
        Provider bc = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance();
        if (Security.getProvider(bc.getName()) == null) {
            try {
                Security.addProvider(bc);
                logger.info("BouncyCastle successfully added to the list of providers");
            } catch (Exception e) {
                logger.log(Level.SEVERE, "BouncyCastle didn't load");
                throw new RuntimeException(e);
            }
        } else {
            throw new RuntimeException("BouncyCastle was already loaded");
        }
    }
    
    KeyPair generateKeyPair(String staticProvider, 
                            KeyAlgorithms keyAlgorithm) throws Exception {
        AlgorithmParameterSpec paramSpec; 
        KeyPairGenerator generator;
        if (keyAlgorithm.getKeyType() == KeyTypes.EC) {
            paramSpec = new ECGenParameterSpec(keyAlgorithm.getJceName());
            generator = staticProvider == null ?
                    KeyPairGenerator.getInstance("EC") 
                                              : 
                    KeyPairGenerator.getInstance("EC", staticProvider);
        } else {
            paramSpec = new NamedParameterSpec(keyAlgorithm.getJceName());
            generator = staticProvider == null ?
                    KeyPairGenerator.getInstance("XDH") 
                                              : 
                    KeyPairGenerator.getInstance("XDH", staticProvider);
        }
        generator.initialize(paramSpec, new SecureRandom());
        return generator.generateKeyPair();
    }

    private void oneShot(KeyAlgorithms ka,
                         KeyEncryptionAlgorithms kea,
                         ContentEncryptionAlgorithms cea,
                         String staticProvider,
                         String ephemeralProvider) throws Exception {
        KeyPair keyPair = generateKeyPair(staticProvider, ka);
        EncryptionCore.setEcProvider(staticProvider, ephemeralProvider);
        byte[] encrypted = new CBORAsymKeyEncrypter(keyPair.getPublic(), kea, cea)
            .encrypt(DATA_TO_ENCRYPT).encode();
        assertTrue("Enc", Arrays.equals(DATA_TO_ENCRYPT,
                                        new CBORAsymKeyDecrypter(keyPair.getPrivate())
            .decrypt(CBORObject.decode(encrypted))));
        encrypted = new CBORAsymKeyEncrypter(keyPair.getPublic(), kea, cea)
            .setPublicKeyOption(true)
            .encrypt(DATA_TO_ENCRYPT).encode();
        assertTrue("Enc2", Arrays.equals(DATA_TO_ENCRYPT,
                                         new CBORAsymKeyDecrypter(keyPair.getPrivate())
            .decrypt(CBORObject.decode(encrypted))));
    }
    
    private void providerShot(KeyAlgorithms ka,
                              KeyEncryptionAlgorithms kea,
                              ContentEncryptionAlgorithms cea) throws Exception {
        oneShot(ka, kea, cea, null,         null);
        oneShot(ka, kea, cea, null,         ALT_PROVIDER);
        oneShot(ka, kea, cea, ALT_PROVIDER, null);
        oneShot(ka, kea, cea, ALT_PROVIDER, ALT_PROVIDER);
    }
    
    @Test
    public void Testing() throws Exception {
        providerShot(KeyAlgorithms.P_256,
                     KeyEncryptionAlgorithms.ECDH_ES,
                     ContentEncryptionAlgorithms.A256GCM);
        providerShot(KeyAlgorithms.X25519,
                     KeyEncryptionAlgorithms.ECDH_ES,
                     ContentEncryptionAlgorithms.A256GCM);
    }
 }
