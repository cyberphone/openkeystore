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

import org.webpki.util.ISODateTime;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>tag</code> objects.
 * <p>
 * Tagged objects are based on CBOR major type 6.
 * This implementation accepts three variants of tags:
 * </p>
 * <div style='margin-left:4em'>
 * <code>nnn(</code><i>CBOR&nbsp;object&nbsp;</i><code>)</code><br>
 * <code>{@value #RESERVED_TAG_DATE}(</code><i>ISO&nbsp;date&nbsp;string</i><code>)</code><br>
 * <code>{@value #RESERVED_TAG_COTX}([</code><i>CBOR&nbsp;text&nbsp;string</i><code>,
 * </code><i>CBOR&nbsp;object&nbsp;</i><code>])</code>
 * </div>
 * <p>
 * The purpose of the last construct is to provide a
 * generic way of adding an object type identifier in the
 * form of a URL or other text data to CBOR objects.
 * The CBOR tag <b>must</b> in this case be <code>{@value #RESERVED_TAG_COTX}</code>. 
 * Example:
 * </p>
 * <div style='margin-left:4em'><code>
 * {@value #RESERVED_TAG_COTX}(["https://example.com/myobject", {<br>
 * &nbsp;&nbsp;"amount": "145.00",<br>
 * &nbsp;&nbsp;"currency": "USD"<br>
 * }])</code>
 * </div>
 * <p>
 * Note that the <code>bignum</code> type is dealt with
 * as a specific primitive, in spite of being a tagged object.
 * </p>
 */
public class CBORTag extends CBORObject {

    /**
     * CBOR representation.
     */
    long tagNumber;
    CBORObject object;
    
    /**
     * COTX tag: {@value #RESERVED_TAG_COTX}
     */
    public static final int RESERVED_TAG_COTX  = 1010;

    /**
     * DATE tag: {@value #RESERVED_TAG_DATE}
     */
    public static final int RESERVED_TAG_DATE  = 0;
    
    /**
     * Creates a COTX-tagged object.
     * 
     * @param typeUrl Type URL (or other string)
     * @param object Object
     */
    public CBORTag(String typeUrl, CBORObject object) {
        // Yeah, there will be a redundant test...
        this(RESERVED_TAG_COTX, new CBORArray()
                                    .add(new CBORString(typeUrl))
                                    .add(object));
    }

    /**
     * Creates a CBOR tagged object.
     * 
     * @param tagNumber Tag number
     * @param object Object
     */
    public CBORTag(long tagNumber, CBORObject object) {
        this.tagNumber = tagNumber;
        this.object = object;
        nullCheck(object);
        if (tagNumber == RESERVED_TAG_COTX) {
            if (object instanceof CBORArray) {
                CBORArray holder = object.getArray();
                if (holder.size() == 2 && holder.get(0) instanceof CBORString) {
                    return;
                }
            }
            cborError(STDERR_INVALID_COTX_OBJECT + object.toDiagnosticNotation(false));
        } else if (tagNumber == RESERVED_TAG_DATE) {
            if (object instanceof CBORString) {
                try {
                    ISODateTime.decode(object.getString(), ISODateTime.COMPLETE);
                    return;
                } catch (Exception e) {}
            }
            cborError(STDERR_ISO_DATE_ERROR + object.toDiagnosticNotation(false));
        }
    }

    /**
     * Get tagged CBOR object.
     * 
     * @return object
     */
    public CBORObject get() {
        return object;
    }

    /**
     * Update tagged CBOR object.
     * 
     * @param object New object
     * @return Previous object
     */
    public CBORObject update(CBORObject object) {
        immutableTest();
        CBORObject previous = this.object;
        this.object = object;
        return previous;
    }

    /**
     * Get tag number.
     * 
     * @return Tag number
     */
    public long getTagNumber() {
        return tagNumber;
    }

    @Override
    byte[] internalEncode() {
        return addByteArrays(encodeTagAndN(MT_TAG, tagNumber), object.encode());

    }
    
    @Override
    void internalToString(CborPrinter cborPrinter) {
         cborPrinter.append(Long.toUnsignedString(tagNumber)).append('(');
         object.internalToString(cborPrinter);
         cborPrinter.append(')');
    }

    static final String STDERR_INVALID_COTX_OBJECT =
            "Invalid COTX object: ";

    static final String STDERR_ISO_DATE_ERROR =
            "Invalid ISO date string: ";
}
