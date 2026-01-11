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

import static org.webpki.cbor.CBORInternal.*;

import java.time.Instant;

/**
 * Class for holding CBOR <code>#6.n</code> (tag) objects.
 * <p>
 * Tagged objects are based on CBOR major type 6.
 * This implementation accepts multiple variants of tags:
 * </p>
 * <div class='webpkifloat'>
 * <table class='webpkitable' style='margin-left:2em'>
 * <tr><th>Type</th><th>Diagnostic&nbsp;Notation</th><th>Comment</th></tr>
 * <tr><td>General Purpose</td>
 * <td><code>nnn(</code><i>CBOR&nbsp;object</i><code>)</code></td>
 * <td>Arbitrary CBOR tag</td></tr>
 * <tr><td><i>Reserved</i> <code>DateTime</code></td>
 * <td><code>{@value #RESERVED_TAG_DATE_TIME}(</code><i>ISO&nbsp;date&nbsp;string</i><code>)</code></td>
 * <td>See {@link #getDateTime()}</td></tr>
 * <tr><td><i>Reserved</i> <code>EpochTime</code></td>
 * <td><code>{@value #RESERVED_TAG_EPOCH_TIME}(</code><i>Time stamp</i><code>)</code></td>
 * <td>See {@link #getEpochTime()}</td></tr>
 * <tr><td><i>Reserved</i> <code>COTX</code></td>
 * <td><code>{@value #RESERVED_TAG_COTX}([</code><i>Text&nbsp;string</i><code>,
 * </code><i>CBOR&nbsp;object</i><code>])</code></td>
 * <td>See {@link #getCOTXObject()}</td></tr>
 * </table>
 * </div>
 * The <i>reserved</i> tags are verified for correctness during decoding as well
 * as when created programmatically. 
 * <p>
 * Note that the <code>bigint</code> type is dealt with
 * as a specific primitive, in spite of being a tagged object.
 * </p>
 */
public class CBORTag extends CBORObject {

    /**
     * Return object for COTX tags.
     */
    public static class COTXObject {

        /**
         * COTX String (Object ID)
         */
        public final String objectId;

        /**
         * COTX Object
         */
        public final CBORObject object;

        private COTXObject(String objectId, CBORObject object) {
            this.objectId = objectId;
            this.object = object;
        }
    }

    // General tag data.
    long tagNumber;
    CBORObject object;

    // Specialized tag data,
    Instant dateTime;
    Instant epochTime;
    COTXObject cotxObject;

    /**
     * DATE_TIME tag: {@value #RESERVED_TAG_DATE_TIME}
     */
    public static final int RESERVED_TAG_DATE_TIME  = 0;

    /**
     * EPOCH_TIME tag: {@value #RESERVED_TAG_EPOCH_TIME}
     */
    public static final int RESERVED_TAG_EPOCH_TIME = 1;

    /**
     * COTX tag: {@value #RESERVED_TAG_COTX}
     */
    public static final int RESERVED_TAG_COTX       = 1010;

    private static final int RESERVED_BIG_INT_UNSIGNED = 2;
    private static final int RESERVED_BIG_INT_NEGATIVE = 3;


    
    /**
     * Creates a <a href='https://www.ietf.org/archive/id/draft-rundgren-cotx-05.html' class='webpkilink'>COTX</a> object.
     * <p>
     * The purpose of the <code>COTX</code> tag is to provide a
     * generic way of adding an object type identifier in the
     * form of a URL or other text data to CBOR objects.
     * Example:
     * </p>
     * <div style='margin-left:2em'><code>
     * {@value #RESERVED_TAG_COTX}(["https://example.com/myobject", {<br>
     * &nbsp;&nbsp;"amount": "145.00",<br>
     * &nbsp;&nbsp;"currency": "USD"<br>
     * }])</code>
     * </div>
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

    private void tagSyntaxError(String tagError) {
        cborError(tagError + toDiagnostic(false));
    }

    /**
     * Creates a CBOR tagged object.
     * 
     * @param tagNumber Tag number
     * @param object Object
     * @throws CBORException
     * @throws IllegalArgumentException
     */
    @SuppressWarnings("this-escape")
    public CBORTag(long tagNumber, CBORObject object) {
        this.tagNumber = tagNumber;
        this.object = object;
        nullCheck(object);
        if (tagNumber < Integer.MAX_VALUE) switch ((int)tagNumber) {
            case RESERVED_BIG_INT_UNSIGNED, RESERVED_BIG_INT_NEGATIVE:
                cborError(STDERR_RESERVED_BIG_INT);
                break;

            case RESERVED_TAG_DATE_TIME:
                // Note: clone() because we have mot read it really.
                dateTime = object.clone().getDateTime();
                break;

            case RESERVED_TAG_EPOCH_TIME:
                // Note: clone() because we have mot read it really.
                epochTime = object.clone().getEpochTime();
                break;

            case RESERVED_TAG_COTX:
                if (object instanceof CBORArray) {
                    CBORArray holder = object.getArray();
                    if (holder.size() == 2 && holder.get(0) instanceof CBORString) {
                        cotxObject = new COTXObject(holder.get(0).getString(), holder.get(1));
                        return;
                    }
                }
                tagSyntaxError(STDERR_INVALID_COTX_OBJECT);
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
     * Get ISO <code>date/time</code> object.
     * <p>
     * This method assumes that a valid CBOR tag 0 has been found, 
     * otherwise a {@link CBORException} is thrown.
     * </p>
     * @return {@link Instant}
     * @see CBORObject#getDateTime()
     * @throws CBORException
     */
    @Override
    public Instant getDateTime() {
        if (dateTime == null) {
            tagSyntaxError(STDERR_ISO_DATE_TIME);
        }
        // We have read it.
        scan();
        return dateTime;
    }

    /**
     * Get UNIX <code>Epoch</code> time object.
     * <p>
     * This method assumes that a valid CBOR tag 1 has been found, 
     * otherwise a {@link CBORException} is thrown.
     * </p>
     * @return {@link Instant}
     * @see CBORObject#getEpochTime()
     * @throws CBORException
     */
    @Override
    public Instant getEpochTime() {
        if (epochTime == null) {
            tagSyntaxError(STDERR_EPOCH_TIME);
        }
        // We have read it.
        scan();
        return epochTime;
    }

    /**
     * Get <code>COTX</code> object.
     * <p>
     * This method assumes that a valid {@link CBORTag#CBORTag(String, CBORObject) COTX} tag has been found, 
     * otherwise a {@link CBORException} is thrown.
     * </p>
     * @return <code>COTXObject</code>
     * @throws CBORException
     * @see CBORTag#CBORTag(String, CBORObject)
     */
    public COTXObject getCOTXObject() {
        if (cotxObject == null) {
            tagSyntaxError(STDERR_INVALID_COTX_OBJECT);
        }
        return cotxObject;
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
        return CBORUtil.concatByteArrays(encodeTagAndN(MT_TAG, tagNumber), object.encode());

    }
    
    @Override
    void internalToString(CborPrinter cborPrinter) {
         cborPrinter.append(Long.toUnsignedString(tagNumber)).append('(');
         if (cotxObject == null) {
            object.internalToString(cborPrinter);
         } else {
            cborPrinter.append('[');
            object.getArray().get(0).internalToString(cborPrinter);
            cborPrinter.append(',').space();
            object.getArray().get(1).internalToString(cborPrinter);
            cborPrinter.append(']');
         }
         cborPrinter.append(')');
    }

    static final String STDERR_INVALID_COTX_OBJECT =
            "Invalid COTX object: ";

    static final String STDERR_ISO_DATE_TIME =
            "Invalid ISO date/time object: ";

    static final String STDERR_EPOCH_TIME =
            "Invalid Epoch time object: ";

    static final String STDERR_RESERVED_BIG_INT =
            "Reserved for 'bigint'";
}
