package com.example.es6numbers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Vector;

import org.webpki.json.v8dtoa.V8NumberCanonicalizer;
import org.webpki.json.v8dtoa.DToA;

public class CreateTestFile {
    
    static FileOutputStream fos;
    
    static void write(byte[] utf8) throws Exception {
        fos.write(utf8);
    }

    static void write(String utf8) throws Exception {
        write(utf8.getBytes("UTF-8"));
    }
    
    static void test(double value) throws Exception {
        String es6number = V8NumberCanonicalizer.numberToString(value);

        if (!es6number.equals(V8NumberCanonicalizer.numberToString(Double.valueOf(es6number)))) {
            throw new RuntimeException("Roundtrip 1 failed for:" + es6number);
        }
        if (value != Double.valueOf(es6number)) {
            throw new RuntimeException("Roundtrip 2 failed for:" + es6number);
        }
        write(Long.toHexString(Double.doubleToRawLongBits(value)) 
              + ","
              + es6number
              + "\n");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("\nUsage: " + CreateTestFile.class.getCanonicalName()
                    + "testfile");
            System.exit(-3);
        }
        fos = new FileOutputStream(args[0]);

        for (int i = -1; i < 2; i += 2) {
            double factor = 3e-22;
            for (int q = 0; q < 50; q++) {
                test(i / factor);
                factor *= 10;
            }
        }
        test(10);
        test(0);
        for (int i = 0; i < 10; i++) {
            test(5.0 / Math.pow(10, i));
        }
        test(0.00000506);
        test(0.000005006);
        test(0.0000050006);
        test(0.00000500006);
        test(0.000005000006);
        test(0.0000050000006);
        test(0.00000500000006);
        test(0.000005000000006);
        test(0.0000050000000006);
        test(0.00000500000000006);
        test(0.000005000000000006);
        test(0.0000050000000000006);
        test(0.00000500000000000006);
        test(0.000005000000000000006);
        test(0.0000050000000000000006);
        test(0.999999999999999999999999999);
        test(-0.999999999999999999999999999);
        test(-0.9999999999999993);
        test(-0.9999999999999995);
        test(0.9999999999999993);
        test(0.9999999999999995);
        test(0.9999999999999996);
        test(0.9999999999999998);
        test(-0.9999999999999999);
        test(-0.9999999999999999);
        test(0.9999999999999999);
        test(0.9999999999999999);
        test(0.29999999999999993338661852249060757458209991455078125);
        test(0.299999999999999988897769753748434595763683319091796875);
        test(0.3000000000000000444089209850062616169452667236328125);
        test(Double.MIN_NORMAL);
        test(Double.MIN_VALUE);
        for (int i = 0; i < 1000; i++) {
            test(2.2250738585072E-308 + (i * 1e-323));
        }
        try {
            test(Double.POSITIVE_INFINITY);
            throw new RuntimeException("fallthrough");
        } catch (IllegalArgumentException e) {
            
        }
        try {
            test(Double.NaN);
            throw new RuntimeException("fallthrough");
        } catch (IllegalArgumentException e) {
            
        }
        SecureRandom random = new SecureRandom();
        byte[] rawDouble = new byte[8];
        for (int i = 0; i < 10000000; i++) {
            random.nextBytes(rawDouble);
            ByteArrayInputStream baos = new ByteArrayInputStream(rawDouble);
            Double randomDouble = new DataInputStream(baos).readDouble();
            if (randomDouble.isInfinite() || randomDouble.isNaN()) {
                continue;
            }
            test(randomDouble);
        }
        fos.close();
    }
}
