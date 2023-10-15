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
package org.webpki.kg2xml;

import java.io.Serializable;

public class ImagePreference implements Serializable
  {
    private static final long serialVersionUID = 1L;

    String type;
    String mimeType;
    int width;
    int height;

    public String getType ()
      {
        return type;
      }

    public String getMimeType ()
      {
        return mimeType;
      }

    public int getWidth ()
      {
        return width;
      }

    public int getHeight ()
      {
        return height;
      }
  }
