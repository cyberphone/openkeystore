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
package org.webpki.securityproxy.common;

import org.webpki.securityproxy.JavaUploadInterface;

public class SampleUploadObject implements JavaUploadInterface {
    private static final long serialVersionUID = 1L;

    private long last_time_stamp;

    public long getTimeStamp() {
        return last_time_stamp;
    }

    public SampleUploadObject(long last_time_stamp) {
        this.last_time_stamp = last_time_stamp;
    }
}
