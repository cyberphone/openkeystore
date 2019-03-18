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

import org.webpki.util.ArrayUtil;

public abstract class Simple extends BaseASN1Object {
    /**
     * Create object.
     */
    Simple(int tagNumber, boolean primitive) {
        super(UNIVERSAL, tagNumber, primitive);
    }

    Simple(int tagClass, int tagNumber, boolean primitive) {
        super(tagClass, tagNumber, primitive);
    }

    Simple(DerDecoder decoder) throws IOException {
        super(decoder);
    }

    /**
     * Decode object, testing primitive/constructed.
     */
    Simple(DerDecoder decoder, boolean primitive) throws IOException {
        super(decoder, primitive);
    }

    public abstract Object objValue();

    public boolean diff(BaseASN1Object o, StringBuilder s, String prefix) {
        if (!sameType(o) || !objValue().equals(((Simple) o).objValue())) {
            s.append(prefix).append("<-------    ");//.append('\n');
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("------->    ");//.append('\n');
            o.toString(s, prefix);
            s.append('\n');
            return true;
        }

        if (isPrimitive() != o.isPrimitive()) {
            s.append(prefix).append("<------- " + (isPrimitive() ? "primitive" : "contructed")).append("    ");
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("------->" + (o.isPrimitive() ? "primitive" : "contructed")).append("    ");
            o.toString(s, prefix);
            s.append('\n');
            return true;
        }
          
      /*    if(blob != null && o.blob != null &&
             encodedLength != o.encodedLength &&
             !ArrayUtil.compare(blob, blobOffset, o.blob, o.blobOffset, encodedLength)){
      System.out.println("kex");
            s.append(prefix).append("<------- length " + encodedLength).append("    ");
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("-------> length " + o.encodedLength).append("    ");
            o.toString(s, prefix);
            s.append('\n');
            return true;
          }*/

        if (blob != null && o.blob != null) {
            // We have encoded values to compare.
            int firstDiff = ArrayUtil.firstDiff(blob, blobOffset, o.blob, o.blobOffset, Math.min(encodedLength, o.encodedLength));
            if (encodedLength != o.encodedLength || firstDiff != -1) {
                if (encodedLength != o.encodedLength) {
                    // Encodings are of different length.
                    s.append(prefix).append("<------- length ").append(encodedLength).append("    length ").append(o.encodedLength).append(" ------->").append('\n');
                } else {
                    s.append(prefix).append("<-------> length ").append(encodedLength).append('\n');
                }
                s.append(prefix).append(firstDiff).append('\n');
                //s.append(prefix).append(blob[firstDiff]).append("     ").append(o.blob[firstDiff]).append('\n');
                s.append(prefix).append(ArrayUtil.toHexString(blob, blobOffset, Math.min(20, encodedLength))).append('\n');
                s.append(prefix).append(ArrayUtil.toHexString(o.blob, o.blobOffset, Math.min(20, o.encodedLength))).append('\n');
                toString(s, prefix);
                s.append('\n');
                return true;
            }
        }


        return false;
    }
}
