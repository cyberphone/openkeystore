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
package org.webpki.asn1;

import java.io.IOException;

import java.util.*;

import org.webpki.util.ArrayUtil;

/**
 * ASN.1 BitString.
 */
public final class ASN1BitString extends Binary {
    byte unusedBits;

    private void checkConsistensy() throws IOException {
        if (value.length <= 4) {
            int v = value[value.length - 1] & 0xFF;
            for (int i = 0; i < unusedBits % 8; i++) {
                if ((v & 1) != 0) throw new IOException("Bit string not padded with zeros");
                v >>= 1;
            }
            if ((v & 1) == 0) throw new IOException("Bit string contained spurious zeros");
        }
    }

    public ASN1BitString(byte[] value) throws IOException {
        super(BITSTRING, true, value);
        int v = value[value.length - 1] & 0xFF;
        int unusedBits = 0;
        if (value.length <= 4) {
            while (v != 0) {
                if ((v & 1) == 0) {
                    unusedBits++;
                    v >>= 1;
                } else {
                    break;
                }
            }
        }
        this.unusedBits = (byte) unusedBits;
        checkConsistensy();
    }

    public byte unusedBits() {
        return unusedBits;
    }

    public BaseASN1Object derDecodeValue() throws IOException {
        throw new IOException("Not applicable to bit strings (?).");
        //return DerDecoder.decode(value);
    }

    ASN1BitString(DerDecoder decoder) throws IOException {
        super(decoder);

        if (isPrimitive()) {
            unusedBits = decoder.current();
            value = new byte[decoder.length - 1];
            System.arraycopy(decoder.content(), 1, value, 0, decoder.length - 1);
        } else {
            Vector<BaseASN1Object> v = readComponents(decoder);

            ASN1BitString bs;

            int length = 0;

            for (int i = 0; i < v.size(); i++) {
                length += ((ASN1BitString) v.elementAt(i)).value.length;
            }

            value = new byte[length];

            int offset = 0;

            for (int i = 0; i < v.size() - 1; i++) {
                bs = (ASN1BitString) v.elementAt(i);
                if (bs.unusedBits != 0) {
                    throw new IOException("Unused bits in sub-bitstring (only allowed in last substring).");
                }
                System.arraycopy(bs.value, 0, value, offset, bs.value.length);
                offset += bs.value.length;
            }

            bs = (ASN1BitString) v.lastElement();
            System.arraycopy(bs.value, 0, value, offset, bs.value.length);
            unusedBits = bs.unusedBits;
        }
        checkConsistensy();
    }

    public void encode(Encoder encoder) throws IOException {
        encodeHeader(encoder, value.length + 1, true);
        encoder.write(unusedBits);
        encoder.write(value);
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) && ArrayUtil.compare(((ASN1BitString) o).value, value);
    }

    void toString(StringBuilder s, String prefix) {
        int bits = 8 * value.length - unusedBits;
        s.append(getByteNumber()).append(prefix).append("BIT STRING, ");
        if (bits > 32) {
            extractableStringData(s, prefix);
        } else {
            s.append(bits).append(" bits");
            if (unusedBits != 0) s.append(" (unused=" + unusedBits + ")");
            s.append(" '");
            int j = 0;
            int index = -1;
            for (int i = 0; i < bits; i++) {
                if (i % 8 == 0) {
                    index++;
                    j = 0x80;
                } else {
                    j >>= 1;
                }
                s.append(((int) value[index] & j) != 0 ? '1' : '0');
            }
            s.append("'B");
        }
    }
}
