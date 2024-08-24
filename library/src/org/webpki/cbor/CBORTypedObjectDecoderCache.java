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

import java.lang.reflect.InvocationTargetException;

import java.util.Hashtable;

/**
 * Cache for typed object decoders.
 * <p>
 * Stores {@link CBORTypedObjectDecoder} classes for automatic instantiation during decoding.
 * </p>
 * <p>
 * Also see <a href='doc-files/typed-objects.html'>Typed Objects</a> for an example.
 * </p>
 */
public class CBORTypedObjectDecoderCache {

    private final Hashtable<String, 
                            Class<? extends CBORTypedObjectDecoder>> classMap = new Hashtable<>();
    
    private CBORTypedObjectDecoder getInstance(
            Class<? extends CBORTypedObjectDecoder> decoderClass) {
        try {
            return decoderClass.getDeclaredConstructor().newInstance();
        } catch (InstantiationException | InvocationTargetException | 
                 NoSuchMethodException | IllegalAccessException e) {
            throw new CBORException(e);
        }        
    }
    
    /**
     * Creates empty typed object decoder cache.
     */
    public CBORTypedObjectDecoderCache() {
        
    }

    /**
     * Decode and instantiate typed object decoder.
     * 
     * @param typedObject Typed object to be decoded
     * @return Instantiated {@link CBORTypedObjectDecoder}
     */
    public CBORTypedObjectDecoder decode(CBORObject typedObject) {
        CBORTag tag = typedObject.getTag();
        if (tag.tagNumber != CBORTag.RESERVED_TAG_COTX) {
            throw new CBORException("COTX expcted, got: " + tag.tagNumber);
        }
        CBORArray cborArray = tag.object.getArray();
        String objectId = cborArray.get(0).getString();
        Class<? extends CBORTypedObjectDecoder> schemaClass = classMap.get(objectId);
        if (schemaClass == null) {
            throw new CBORException("Unknown ObjectId: " + objectId);
        }
        CBORTypedObjectDecoder decoder = getInstance(schemaClass);
        decoder.root = typedObject;
        decoder.decode(cborArray.get(1));
        if (decoder.enableCheckForUnread()) {
            typedObject.checkForUnread();
        }
        return decoder;

    }

    /**
     * Add typed object decoder class to cache.
     * 
     * @param decoderClass Typed decoder class
     * @return {@link CBORTypedObjectDecoderCache}
     */
    public CBORTypedObjectDecoderCache addToCache(
            Class<? extends CBORTypedObjectDecoder> decoderClass) {
        CBORTypedObjectDecoder schemaObject = getInstance(decoderClass);
        String objectId = schemaObject.getObjectId();
        if (classMap.put(objectId, schemaObject.getClass()) != null) {
            throw new RuntimeException("ObjectId already defined: " + objectId);
        }
        return this;
    }
}

