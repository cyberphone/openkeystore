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
package org.webpki.util;


/**
 * Wrapped exception handler.
 * Note: the use of RuntimeException is deliberate, declared exceptions only complicate
 * programming and was excluded in .NET.
 */
public final class WrappedException extends RuntimeException {
    static final long serialVersionUID = 10000000000L;

    /**
     * Takes an existing exception and creates a new one while keeping the stack intact.
     *
     * @param wrapped_exception The exception.
     */
    public WrappedException(Exception wrapped_exception) {
        super(wrapped_exception.getMessage());
        setStackTrace(wrapped_exception.getStackTrace());
    }
}
