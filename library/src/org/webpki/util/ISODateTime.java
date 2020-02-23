/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.util;

import java.io.IOException;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import java.util.regex.Pattern;

/**
 * Useful functions for ISO time.
 */
public class ISODateTime {

    private ISODateTime() {}  // No instantiation please
    
    public static enum DatePatterns {UTC,
                                     LOCAL,
                                     MILLISECONDS,
                                     MICROSECONDS,
                                     NANOSECONDS,
                                     ANYFRACTION};
                                     
    public static final EnumSet<DatePatterns> UTC_NO_SUBSECONDS = EnumSet.of(DatePatterns.UTC);
    public static final EnumSet<DatePatterns> LOCAL_NO_SUBSECONDS = EnumSet.of(DatePatterns.LOCAL);
    public static final EnumSet<DatePatterns> COMPLETE = EnumSet.allOf(DatePatterns.class);

    static final Pattern DATE_PATTERN =
            Pattern.compile("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(\\.\\d{1,9})?([+-]\\d{2}:\\d{2}|Z)");

    
    /**
     * Parse an ISO formatted dateTime string.<p>
     * <i>Always:</i> <code>yyyy-mm-ddThh:mm:ss</code><br>
     * <i>Optionally:</i> a '.' followed by 1-9 digits holding fractions of a second<br>
     * <i>Finally:</i> 'Z' for UTC or an UTC time-zone difference expressed as <code>+hh:mm</code> or <code>-hh:mm</code></p>
     *
     * @param dateTime String to be parsed
     * @param format Permitted format
     * @return GregorianCalendar
     * @throws IOException If anything unexpected is found...
     */
    public static GregorianCalendar parseDateTime(String dateTime, EnumSet<DatePatterns> format) throws IOException {

        if (!DATE_PATTERN.matcher(dateTime).matches()) {
            throw new IOException("DateTime syntax error: " + dateTime);
        }
        
        GregorianCalendar gc = new GregorianCalendar();
        gc.clear();

        gc.set(GregorianCalendar.ERA, GregorianCalendar.AD);
        gc.set(GregorianCalendar.YEAR, Integer.parseInt(dateTime.substring(0, 4)));
        gc.set(GregorianCalendar.MONTH, Integer.parseInt(dateTime.substring(5, 7)) - 1);

        gc.set(GregorianCalendar.DAY_OF_MONTH, Integer.parseInt(dateTime.substring(8, 10)));

        gc.set(GregorianCalendar.HOUR_OF_DAY, Integer.parseInt(dateTime.substring(11, 13)));

        gc.set(GregorianCalendar.MINUTE, Integer.parseInt(dateTime.substring(14, 16)));

        gc.set(GregorianCalendar.SECOND, Integer.parseInt(dateTime.substring(17, 19)));

        String milliSeconds = null;

        // Find time zone info.
        if (dateTime.endsWith("Z")) {
            if (!format.contains(DatePatterns.UTC)) {
                bad(dateTime);
            }
            gc.setTimeZone(TimeZone.getTimeZone("UTC"));
            milliSeconds = dateTime.substring(19, dateTime.length() - 1);
        } else {
            if (!format.contains(DatePatterns.LOCAL)) {
                bad(dateTime);
            }
            int factor = 60 * 1000;
            int i = dateTime.indexOf('+');
            if (i < 0) {
                i = dateTime.lastIndexOf('-');
                factor = -factor;
            }
            milliSeconds = dateTime.substring(19, i);
            int tzHour = Integer.parseInt(dateTime.substring(++i, i + 2)),
                                          tzMinute = Integer.parseInt(dateTime.substring(i + 3, i + 5));
            gc.setTimeZone(new SimpleTimeZone(((60 * tzHour) + tzMinute) * factor, ""));
        }
        if (milliSeconds.length() > 0) {
            if (!format.contains(DatePatterns.ANYFRACTION)) {
                if (format.contains(DatePatterns.MILLISECONDS)) {
                    if (milliSeconds.length() != 4) {
                        bad(dateTime);
                    }
                } else if (format.contains(DatePatterns.MICROSECONDS)) {
                    if (milliSeconds.length() != 7) {
                        bad(dateTime);
                    }
                } else if (format.contains(DatePatterns.NANOSECONDS)) {
                    if (milliSeconds.length() != 10) {
                        bad(dateTime);
                    }
                } else {
                    bad(dateTime);
                }
            }
            // Milliseconds is the only thing we can eat though
            milliSeconds = milliSeconds.substring(1, milliSeconds.length() > 4 ? 4 : milliSeconds.length());
            int fraction = Integer.parseInt(milliSeconds) * 100;
            for (int q = 1; q < milliSeconds.length(); q++) {
                fraction /= 10;
            }
            gc.set(GregorianCalendar.MILLISECOND, fraction);
        } else if (format.contains(DatePatterns.MILLISECONDS) && 
                   !format.contains(DatePatterns.ANYFRACTION)) {
            bad(dateTime);
        }
        return gc;
    }

    private static void bad(String dateTime) throws IOException {
        throw new IOException("DateTime format doesn't match specification: " + dateTime);
    }

    /**
     * Create an ISO formatted dateTime string.<p>
     * <i>Always:</i> <code>yyyy-mm-ddThh:mm:ss</code><br>
     * <i>Optional:</i> a '.' followed by 3 digits holding milliseconds<br>
     * <i>UTC:</i> Append 'Z'<br>
     * <i>Local time:</i> Append time-zone difference expressed as <code>+hh:mm</code> or <code>-hh:mm</code></p>
     * @param dateTime The date/time object
     * @param format Format: Note <i>Representation:</i> <code>true</code> for UTC, <code>false</code> for local time
     * @return String
     */
    public static String formatDateTime(GregorianCalendar dateTime, EnumSet<DatePatterns> format) {
        SimpleDateFormat sdf = new SimpleDateFormat(
                format.contains(DatePatterns.MILLISECONDS) ?
                               "yyyy-MM-dd'T'HH:mm:ss.SSS" : "yyyy-MM-dd'T'HH:mm:ss");
        sdf.setTimeZone(format.contains(DatePatterns.UTC) ? 
                              TimeZone.getTimeZone("UTC") : dateTime.getTimeZone());
        StringBuilder s = new StringBuilder(sdf.format(dateTime.getTime()));
        if (format.contains(DatePatterns.UTC)) {
           s.append('Z');
        } else {
           int tzo = (dateTime.get(Calendar.ZONE_OFFSET) + dateTime.get(Calendar.DST_OFFSET)) / (60 * 1000);
           if (tzo < 0) {
                tzo = - tzo;
                s.append('-');
            } else {
                s.append('+');
            }
            int tzh = tzo / 60, tzm = tzo % 60;
            s.append(tzh < 10 ? "0" : "").append(tzh).append(tzm < 10 ? ":0" : ":").append(tzm);
        }
        return s.toString();
    }
}

