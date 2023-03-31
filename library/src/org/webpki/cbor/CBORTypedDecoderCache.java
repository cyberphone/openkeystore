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

import java.lang.reflect.InvocationTargetException;

import java.security.GeneralSecurityException;

import java.io.IOException;

import java.util.Hashtable;

/**
 * Cache for typed decoders.
 * <p>
 * Stores {@link CBORTypedDecoder} classes for automatic instantiation during decoding.
 * </p>
 * <p>
 * See <a href='doc-files/typed-decoders.html'>Typed Decoders</a> for an example.
 * </p>
 */
public class CBORTypedDecoderCache {

    private boolean checkForUnread = true;

    private Hashtable<String, Class<? extends CBORTypedDecoder>> classMap = new Hashtable<>();
    
    private CBORTypedDecoder getInstance(Class<? extends CBORTypedDecoder> decoderClass) {
        try {
            return decoderClass.getDeclaredConstructor().newInstance();
        } catch (InstantiationException | InvocationTargetException | 
                 NoSuchMethodException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }        
    }
    
    /**
     * Creates empty decoder cache.
     */
    public CBORTypedDecoderCache() {
        
    }

    /**
     * Decodes and instantiates typed decoder.
     * 
     * @param typedObject Typed object to be decoded
     * @return Instantiated {@link CBORTypedDecoder}
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORTypedDecoder decode(CBORObject typedObject) 
            throws IOException, GeneralSecurityException {
        CBORTag tag = typedObject.getTag();
        if (tag.tagNumber != CBORTag.RESERVED_TAG_COTX) {
            throw new IOException("COTX expcted, got: " + tag.tagNumber);
        }
        CBORArray cborArray = tag.getObject().getArray(2);
        String objectId = cborArray.getObject(0).getString();
        Class<? extends CBORTypedDecoder> schemaClass = classMap.get(objectId);
        if (schemaClass == null) {
            throw new IOException("Unknown ObjectId: " + objectId);
        }
        CBORTypedDecoder decoder = getInstance(schemaClass);
        decoder.root = typedObject;
        decoder.decode(cborArray.getObject(1));
        if (checkForUnread) {
            typedObject.checkForUnread();
        }
        return decoder;

    }

    /**
     * Adds typed decoder class to cache.
     * 
     * @param decoderClass Typed decoder class
     * @return {@link CBORTypedDecoderCache}
     */
    public CBORTypedDecoderCache addToCache(Class<? extends CBORTypedDecoder> decoderClass) {
        CBORTypedDecoder schemaObject = getInstance(decoderClass);
        String objectId = schemaObject.getObjectId();
        if (classMap.put(objectId, schemaObject.getClass()) != null) {
            throw new RuntimeException("ObjectId already defined: " + objectId);
        }
        return this;
    }

    /**
     * Sets the check for unread mode.
     * <p>
     * The default is <code>true</code>.
     * </p>
     * @param flag  <code>true</code> if checks should be performed
     */
    public void setCheckForUnread(boolean flag) {
        checkForUnread = flag;
    }
}
