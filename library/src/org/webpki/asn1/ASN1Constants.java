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

public interface ASN1Constants {
    /* Identifier constants ****************************************************************/
    /* Tag classes */
    public static final int CLASS_MASK      = 0xC0; /* Bits 8 and 7 */
    public static final int UNIVERSAL       = 0x00; /* 0 = Universal (defined by ITU X.680) */
    public static final int APPLICATION     = 0x40; /* 1 = Application */
    public static final int CONTEXT         = 0x80; /* 2 = Context-specific */
    public static final int PRIVATE         = 0xC0; /* 3 = Private */
    /* Encoding type */
    public static final int FORM_MASK       = 0x20; /* Bit 6 */
    public static final int PRIMITIVE       = 0x00; /* 0 = primitive */
    public static final int CONSTRUCTED     = 0x20; /* 1 = constructed */
    /* Universal tags */
    public static final int TAG_MASK        = 0x1F; /* Bits 5 - 1 */
    public static final int EOC             = 0x00; /*  0: End-of-contents octets */
    public static final int BOOLEAN         = 0x01; /*  1: Boolean */
    public static final int INTEGER         = 0x02; /*  2: Integer */
    public static final int BITSTRING       = 0x03; /*  2: Bit string */
    public static final int OCTETSTRING     = 0x04; /*  4: Byte string */
    public static final int NULL            = 0x05; /*  5: NULL */
    public static final int OID             = 0x06; /*  6: Object Identifier */
    public static final int OBJDESCRIPTOR   = 0x07; /*  7: Object Descriptor */
    public static final int EXTERNAL        = 0x08; /*  8: External */
    public static final int REAL            = 0x09; /*  9: Real */
    public static final int ENUMERATED      = 0x0A; /* 10: Enumerated */
    public static final int EMBEDDED_PDV    = 0x0B; /* 11: Embedded Presentation Data Value */
    public static final int UTF8STRING      = 0x0C; /* 12: UTF-8 string */
    public static final int SEQUENCE        = 0x10; /* 16: Sequence/sequence of */
    public static final int SET             = 0x11; /* 17: Set/set of */
    public static final int NUMERICSTRING   = 0x12; /* 18: Numeric string */
    public static final int PRINTABLESTRING = 0x13; /* 19: Printable string (ASCII subset) */
    public static final int T61STRING       = 0x14; /* 20: T61/Teletex string */
    public static final int VIDEOTEXSTRING  = 0x15; /* 21: Videotex string */
    public static final int IA5STRING       = 0x16; /* 22: IA5/ASCII string */
    public static final int UTCTIME         = 0x17; /* 23: UTC time */
    public static final int GENERALIZEDTIME = 0x18; /* 24: Generalized time */
    public static final int GRAPHICSTRING   = 0x19; /* 25: Graphic string */
    public static final int VISIBLESTRING   = 0x1A; /* 26: Visible string (ASCII subset) */
    public static final int GENERALSTRING   = 0x1B; /* 27: General string */
    public static final int UNIVERSALSTRING = 0x1C; /* 28: Universal string */
    public static final int BMPSTRING       = 0x1E; /* 30: Basic Multilingual Plane/Unicode string */
    /* EO Identifier constants ******************************************************************/
}
