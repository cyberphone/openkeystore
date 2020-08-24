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
package org.webpki.json;

import java.util.Random;

public class ES6Numbers {
    
    public static String javaStr;
    public static String ryuStr;
    
    static long javaTot;
    static long ryuTot;
    
    static String HEADER="IEEE-754           JDK   Ryu  JDK Serialization         Ryu Serialization\n";
 
    static int PERVALUETURNS = 1000000;
    
    static void oneRound(long ieee754) {
        double d = Double.longBitsToDouble(ieee754);
        try {
            long start = System.currentTimeMillis();
            for (int q = 0; q < 1000000; q++) {
                javaStr = String.valueOf(d);
            }
            long javaTime = System.currentTimeMillis() - start;
            start = System.currentTimeMillis();
            for (int q = 0; q < 1000000; q++) {
                ryuStr = NumberToJSON.serializeNumber(d);
            }
            long ryuTime = System.currentTimeMillis() - start;
            System.out.println(String.format("%016x",ieee754) +
                               String.format(" %5d",javaTime) +
                               String.format(" %5d",ryuTime) + 
                               String.format("  %-25s",javaStr) + 
                               " " + ryuStr);
            javaTot += javaTime;
            ryuTot += ryuTime;
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage() + " d=" + d + " v=" + Long.toString(ieee754, 16));
        }
    }
    
    static void oneRound(String ieee754) {
        oneRound(Long.parseUnsignedLong(ieee754, 16));
    }
    
    public static void main(String[] argc) {
        if (argc.length != 1) {
            System.out.println("ES6Numbers number-of-turns");
            System.exit(0);
        }
        double d = 0;
        long v = 0;
        System.out.println(HEADER + "Selected values:");
        oneRound("0000000000000000");
        oneRound("8000000000000000");
        oneRound("0000000000000001");
        oneRound("8000000000000001");
        oneRound("7fefffffffffffff");
        oneRound("ffefffffffffffff");
        oneRound("4340000000000000");
        oneRound("c340000000000000");
        oneRound("4430000000000000");
        oneRound("44b52d02c7e14af5");
        oneRound("44b52d02c7e14af6");
        oneRound("44b52d02c7e14af7");
        oneRound("444b1ae4d6e2ef4e");
        oneRound("444b1ae4d6e2ef4f");
        oneRound("444b1ae4d6e2ef50");
        oneRound("3eb0c6f7a0b5ed8c");
        oneRound("3eb0c6f7a0b5ed8d");
        oneRound("41b3de4355555553");
        oneRound("41b3de4355555554");
        oneRound("41b3de4355555555");
        oneRound("41b3de4355555556");
        oneRound("41b3de4355555557");
        oneRound("becbf647612f3696");
        System.out.println(HEADER + "Random values:");
        Random random = new Random();
        long i = Long.parseLong(argc[0]);
        long c = 0;
        while (c++ < i) {
            v = random.nextLong();
            d = Double.longBitsToDouble(v);
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                continue;
            }
            oneRound(v);
        }
        System.out.println("JDK Total=" + javaTot + " Ryu Total=" + ryuTot);
    }
}
