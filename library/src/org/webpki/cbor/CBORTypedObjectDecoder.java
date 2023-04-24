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
 * Base class for typed decoders.
 * <p>
 * Base class for CBOR object decoders that can be instantiated
 * through a {@link CBORTypedObjectDecoderCache}.
 * The system relies on that CBOR data is prepended by a mandatory COTX tag.
 * </p>
 * <p>
* See <a href='doc-files/typed-objects.html'>Typed Objects</a> for an example.
 * </p>
 */
public abstract class CBORTypedObjectDecoder {
    
    /**
     * Constructor.
     * <p>
     * Note: implementations <b>must</b> have a public
     * constructor (which they get by default if no
     * other constructor is defined).
     * </p>
     */
    public CBORTypedObjectDecoder() {
        
    }

    CBORObject root;  // Of decoded CBOR

    /**
     * INTERNAL USE ONLY.
     * <p>
     * Implementations <b>must</b> decode all elements
     * associated with the specific object decoder.
     * </p>
     * <p>
     * Note that "checked" exceptions <b>must</b> be wrapped in
     * an unchecked exception like {@link RuntimeException},
     * {@link CBORException}, or {@link org.webpki.crypto.CryptoException}.
     * </p>
     * <p>
     * Also see {@link CBORTypedObjectDecoderCache#setCheckForUnread(boolean)}.
     * </p>
     *
     * @param cborBody COTX argument of {@link CBORTypedObjectDecoder} instance
     */
    protected abstract void decode(CBORObject cborBody);

    /**
     * Returns typed object identifier.
     *
     * @return Object Id (COTX)
     */
    public abstract String getObjectId();


    /**
     * Returns root of decoded CBOR.
     * <p>
     * Including COTX.
     * </p>
     * 
     * @return CBORObject
     */
    public CBORObject getRoot() {
        return root;
    }
}
