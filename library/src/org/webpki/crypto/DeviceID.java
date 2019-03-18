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
package org.webpki.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;

/**
 * Device ID generator.
 * <p>A Device ID is a cryptographically secured 36-character identifier where the last
 * 4 characters represent a (SHA1-based) checksum of the 160-bit SHA1 hash of the
 * argument which is the actual identity.  The identity used as input may be an IMEI-code,
 * Device Certificate, Apple-ID, etc.</p>
 * <p>The scheme also supports a truncated 20-character Device ID-variant which
 * presumably is sufficient for most real-world usages.</p>
 * <p>The checksum makes it easy verifying that the user has typed in the correct Device ID.</p>
 * <p>
 * To further reduce mistakes the character-set has been limited to 32 visually
 * distinguishable characters:<br><code>
 *     ABCDEFGHJKLMNPQRSTUVWXYZ23456789</code>
 * </p>
 * A user-display would typically show a 36-character Device ID like the following: <pre>
 *     CCCC-CCCC-CCCC-CCCC
 *     CCCC-CCCC-CCCC-CCCC
 *     CCCC</pre>
 */
public class DeviceID {

    private DeviceID() {}  // No instantiation

    private static final char[] MODIFIED_BASE32 = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                                   'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R',
                                                   'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                                                   '2', '3', '4', '5', '6', '7', '8', '9'};

    private static final char[] REVERSE_BASE32 = new char[256];

    static {
        for (int i = 0; i < 256; i++) {
            REVERSE_BASE32[i] = 256;
        }
        for (char i = 0; i < 32; i++) {
            REVERSE_BASE32[MODIFIED_BASE32[i]] = i;
        }
    }

    private static byte[] half(byte[] data) {
        if (data.length == 5) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(data, 0, 2);
            byte rnibble = 0;
            byte lnibble = (byte) (data[2] & 0xF0);
            for (int i = 2; i < 5; i++) {
                baos.write((byte) (lnibble | rnibble));
                lnibble = (byte) ((data[i] & 0xF) << 4);
                if (i < 4) {
                    rnibble = (byte) ((data[i + 1] & 0xF0) >> 4);
                }
            }
            baos.write(lnibble);
            data = baos.toByteArray();
        }
        int offset = data.length / 2;
        byte[] result = new byte[offset];
        for (int i = 0; i < offset; i++) {
            result[i] = (byte) (data[i] ^ data[i + offset]);
        }
        return result;
    }

    private static String getDeviceIdFromHash(byte[] hash) {
        try {
            if (hash.length != 20 && hash.length != 10) {
                throw new IllegalArgumentException("Hash length: " + hash.length);
            }
            int totalBits = hash.length == 20 ? 180 : 100;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(hash);
            hash = half(half(hash));
            baos.write(hash.length == 5 ? half(hash) : hash);
            byte[] data = baos.toByteArray();
            StringBuilder buffer = new StringBuilder();
            for (int bit_position = 0; bit_position < totalBits; bit_position += 5) {
                int bit_position_in_byte = bit_position % 8;
                int index = bit_position / 8;
                byte value = (byte) (bit_position_in_byte > 3
                        ?
                        ((data[index] << (bit_position_in_byte - 3)) & 0x1F) | ((data[index + 1] & 0xFF) >> (11 - bit_position_in_byte))
                        :
                        data[index] >>> (3 - bit_position_in_byte));
                buffer.append(MODIFIED_BASE32[value & 0x1F]);
            }
            return buffer.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getDeviceId(byte[] identityBlobOrNull, boolean longVersion) {
        if (identityBlobOrNull != null) {
            try {
                byte[] hash = HashAlgorithms.SHA1.digest(identityBlobOrNull);
                return getDeviceIdFromHash(longVersion ? hash : half(hash));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return "N/A";
    }

    public static String getDeviceId(X509Certificate deviceCertificateOrNull, boolean longVersion) {
        try {
            return getDeviceId(deviceCertificateOrNull == null ? null : deviceCertificateOrNull.getEncoded(), longVersion);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static void validateDeviceID(String deviceId) throws IOException {
        int bytes = 20;
        int characters = 32;
        if (deviceId.length() == 20) {
            bytes = 10;
            characters = 16;
        } else if (deviceId.length() != 36) {
            throw new IOException("DeviceID must be 20 or 36 characters");
        }
        byte[] hash = new byte[bytes];
        int q = 0;
        int bitPosition = 0;
        for (int i = 0; i < characters; i++) {
            char c = deviceId.charAt(i);
            if (c > 255 || (c = REVERSE_BASE32[c]) < 0) {
                throw new IOException("Illigal DeviceID character: " + c);
            }
            if (bitPosition < 4) {
                if (bitPosition == 0) {
                    hash[q] = 0;
                }
                hash[q] |= (byte) (c << (3 - bitPosition));
                if (bitPosition == 3) {
                    q++;
                }
            } else {
                hash[q] |= (byte) (c >> ((bitPosition + 5) % 8));
                hash[++q] = (byte) (c << (11 - bitPosition));
            }
            bitPosition = (bitPosition + 5) % 8;
        }
        if (!deviceId.equals(getDeviceIdFromHash(hash))) {
            throw new IOException("DeviceID checksum error");
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.out.println("\n" + DeviceID.class.getName() + " certificate-in-der-format long_version_expressed_as_true_or_false\n");
            System.exit(3);
        }
        System.out.println("Device ID=" + getDeviceId(ArrayUtil.readFile(args[0]), new Boolean(args[1])));
    }
}
