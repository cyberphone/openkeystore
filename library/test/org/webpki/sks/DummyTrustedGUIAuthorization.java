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

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.sks.AppUsage;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.SKSException;

import org.webpki.sks.ws.TrustedGUIAuthorization;
import org.webpki.util.ArrayUtil;

public class DummyTrustedGUIAuthorization implements TrustedGUIAuthorization {
    static final String GOOD_TRUSTED_GUI_PIN = "1234";

    private static final byte[] SHARED_SECRET_32 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 3, 2};

    protected byte[] convertToUTF8(PassphraseFormat format, String pin_code) throws SKSException {
        byte[] authorization = null;
        try {
            authorization = pin_code.getBytes("UTF-8");
            Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            crypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(SHARED_SECRET_32, "AES"), new IvParameterSpec(iv));
            authorization = ArrayUtil.add(iv, crypt.doFinal(authorization));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SHARED_SECRET_32, "RAW"));
            mac.update(authorization);
            authorization = ArrayUtil.add(mac.doFinal(), authorization);
        } catch (IOException e) {
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        }
        return authorization;
    }

    @Override
    public byte[] restoreTrustedAuthorization(byte[] value) throws SKSException {
        if (value == null || value.length < 64) {
            throw new SKSException("Malformed trusted GUI \"Authorization\" object");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SHARED_SECRET_32, "RAW"));
            mac.update(value, 32, value.length - 32);
            if (!ArrayUtil.compare(mac.doFinal(), value, 0, 32)) {
                throw new SKSException("MAC error on trusted GUI \"Authorization\" object");
            }
            Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            crypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(SHARED_SECRET_32, "AES"), new IvParameterSpec(value, 32, 16));
            value = crypt.doFinal(value, 48, value.length - 48);
        } catch (IOException e) {
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        }
        return value;
    }

    @Override
    public byte[] getTrustedAuthorization(PassphraseFormat format,
                                          Grouping grouping,
                                          AppUsage appUsage,
                                          String friendlyName) throws SKSException {
        return convertToUTF8(format, GOOD_TRUSTED_GUI_PIN);
    }

    @Override
    public String getImplementation() {
        return "Non-functional mockup version";
    }
}
