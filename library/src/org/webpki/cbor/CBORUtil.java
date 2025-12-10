package org.webpki.cbor;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import static org.webpki.cbor.CBORInternal.*;

public class CBORUtil {

    private CBORUtil() {} 

    /**
     * Create <code>DateTime</code> object.
     * 
<div style='margin-top:0.5em'>
This method creates a date/time string in the ISO format described in section 5.6&nbsp;of 
[<a href='https://www.rfc-editor.org/rfc/rfc3339.html#section-5.6' class='webpkilink'>RFC3339</a>].
The string is subsequently wrapped in a {@link CBORString} object.</div>
<div style='margin-top:0.5em'>
If the <code>instant</code> object is not within
the range <code style='white-space:nowrap'>"0000-01-01T00:00:00Z"</code> to
<code style='white-space:nowrap'>"9999-12-31T23:59:59Z"</code>,
a {@link CBORException} is thrown .</div>
<div style='margin-top:0.5em'>
If <code>millis</code> is <code>true</code> the date/time string will feature
milliseconds (<code>.nnn</code>) as well.</div>
<div style='margin-top:0.5em'>Sample code:</div>
<div style='margin:0.3em 0 0 1.2em'><code>CBORString iso = CBORUtil.createDateTime(Instant.now(), true, false);<br>
System.out.println(iso.toString());<br>
<span style='color:#007fdd'>"2025-12-05T13:55:42.418+01:00"</span></code></div>
@see CBORObject#getDateTime()
@param instant Time source object.
@param millis <div style='margin-left:2em'>
If <code>millis</code> is <code>true</code>,
the milliseconds of the <code>instant</code> object will be
featured in the created time object.  Note: if the millisecond
part of the <code>instant</code> object is zero,
<code>millis</code> is considered to be <code>false</code>.
<div style='margin-top:0.5em'>If <code>millis</code> is
<code>false</code>, the millisecond part of the <code>instant</code>
object will not be used, but may after <i>rounding</i>,
add a second to the created time object.</div><div>
@param utc <div style='margin-left:2em'>
If <code>utc</i></code> is <code>true</code>,
the <code>UTC</code> time zone (denoted by a terminating <code>Z</code>) will be used,
else the local time followed by the <code>UTC</code> offset
(<code>&plusmn;hh:mm</code>) will be used.</div>

@return {@link CBORString}
@throws CBORException
    */
    public static CBORString createDateTime(Instant instant, boolean millis, boolean utc) {
        long epochMillis = instantDateTimeToMillisCheck(instant);
        millis = millisCheck(epochMillis, millis);
        if (!millis) {
            long remainder = epochMillis % 1000;
            if (remainder >= 500) {
                epochMillis += 1000;
            }
            epochMillis -= remainder;
        }
        String dateTime = Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault())
            .format(utc ? DateTimeFormatter.ISO_INSTANT : DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        if (millis && utc) {
            int i = dateTime.length();
            while (dateTime.charAt(--i - 1) == '0') {
                ;
            }
            dateTime = dateTime.substring(0, i) + "Z";
        }
        return new CBORString(dateTime);
    }

    /**
     * Create <code>EpochTime</code> object.
     * 
<div style='margin-top:0.5em'>
This method creates an Epoch
[<a href='https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html#tag_04_19'
 class='webpkilink'>TIME</a>] time stamp.</div>
<div style='margin-top:0.5em'>
If the <code>instant</code> object is not within
the range <code style='white-space:nowrap'>"1970-01-01T00:00:00Z"</code> to
<code style='white-space:nowrap'>"9999-12-31T23:59:59Z"</code>,
a {@link CBORException} is thrown.</div>
<div style='margin-top:0.5em'>
If <code>millis</code> is <code>true</code> a {@link CBORFloat}
object holding seconds with a milliseconds fraction will be created,
else a {@link CBORInt} object holding seconds will be created.</div>
<div style='margin-top:0.5em'>Sample code:</div>
<div style='margin:0.3em 0 0 1.2em'><code>CBORObject epoch = CBORUtil.createEpochTime(Instant.now(), false);<br>
System.out.println(epoch.toString());<br>
<span style='color:#007fdd'>1764939916</span></code></div>
@see CBORObject#getEpochTime()
@param instant Time source object.
@param millis <div style='margin-left:2em'>
If <code>millis</code> is <code>true</code>,
the milliseconds of the <code>instant</code> object will be
featured in the created time object.  Note: if the millisecond
part of the <code>instant</code> object is zero,
<code>millis</code> is considered to be <code>false</code>.
<div style='margin-top:0.5em'>If <code>millis</code> is
<code>false</code>, the millisecond part of the <code>instant</code>
object will not be used, but may after <i>rounding</i>,
add a second to the created time object.</div><div>

@return {@link CBORObject}
@throws CBORException
    */
    public static CBORObject createEpochTime(Instant instant, boolean millis) {
        long epochMillis = epochCheck(instant.toEpochMilli());
        millis = millisCheck(epochMillis, millis);
        epochMillis = timeRound(epochMillis, millis);
        return millis ? new CBORFloat((double)epochMillis / 1000) 
                                    : 
                        new CBORInt(epochMillis / 1000);
    }

    public static byte[] concatByteArrays(byte[]...listOfArrays) {
        int totalLength = 0;
        for (byte[] array : listOfArrays) {
            totalLength += array.length;
        }
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : listOfArrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }

    public static byte[] unsignedLongToByteArray(long value) {
        long temp = value;
        int length = 0;
        do {
            length++;
        } while ((temp >>>= 8) != 0);
        byte[] result = new byte[length];
        while (--length >= 0) {
            result[length] = (byte)value;
            value >>>= 8;
        }
        return result;
    }

    public static long reverseBits(long bits, int fieldWidth) {
        long reversed = 0;
        int bitCount = 0;
        while (bits > 0) {
            bitCount++;
            reversed <<= 1;
            if ((bits & 1) == 1)
                reversed |= 1;
            bits >>= 1;
        }
        if (bitCount > fieldWidth) {
            throw new IllegalArgumentException("Field exceeds fieldWidth");
        }
        return reversed << (fieldWidth - bitCount);
    }

    static void epochOutOfRange() {
        cborError(STDERR_EPOCH_OUT_OF_RANGE);
    }

    static long epochCheck(long epochMillis) {
        if (epochMillis < 0 || epochMillis > MAX_INSTANT_IN_MILLIS) {
            epochOutOfRange();
        }
        return epochMillis;
    }

    static long instantDateTimeToMillisCheck(Instant instant) {
        long dateTimeMillis = instant.toEpochMilli();
        if (dateTimeMillis < MIN_INSTANT_IN_MILLIS || dateTimeMillis > MAX_INSTANT_IN_MILLIS) {
            cborError(STDERR_DATETIME_OUT_OF_RANGE);
        }
        return dateTimeMillis;
    }

    static boolean millisCheck(long epochMillis, boolean millis) {
        return epochMillis % 1000 == 0 ? false : millis;
    }

    static long timeRound(long epochMillis, boolean millis) {
        if (!millis) {
            if (epochMillis % 1000 > 500) {
                epochMillis += 1000;
            }
        }
        return epochMillis;
    }

    static final String STDERR_EPOCH_OUT_OF_RANGE =
            "Epoch outside the range 0 to 253402300799";

    static final String STDERR_DATETIME_OUT_OF_RANGE =
            "DateTime out of range";
}
