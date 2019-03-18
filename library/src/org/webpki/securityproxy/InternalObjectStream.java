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
package org.webpki.securityproxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;

/**
 * Internal class for dealing with classloader serialization issues.
 */
class InternalObjectStream extends ObjectInputStream {

    Object owner;

    @Override
    public Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        try {
            return owner.getClass().getClassLoader().loadClass(desc.getName());
        } catch (Exception e) {
        }
        return super.resolveClass(desc);
    }

    InternalObjectStream(InputStream in, Object owner) throws IOException {
        super(in);
        this.owner = owner;
    }

    static Object readObject(byte[] data, Object owner) throws IOException, ClassNotFoundException {
        InternalObjectStream ios = new InternalObjectStream(new ByteArrayInputStream(data), owner);
        Object object = ios.readObject();
        ios.close();
        return object;
    }

    static byte[] writeObject(Object object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectOutputStream(baos).writeObject(object);
        return baos.toByteArray();
    }
}
