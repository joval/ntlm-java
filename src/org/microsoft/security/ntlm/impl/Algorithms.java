/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class Algorithms {

    public static final Charset UNICODE_ENCODING = Charset.forName("UnicodeLittleUnmarked");
    public static final Charset ASCII_ENCODING = Charset.forName("US-ASCII");
    public static final byte[] EMPTY_ARRAY = new byte[4];

    private static final String SHA1_NAME = "SHA-1";
    private static final String HMAC_MD5_NAME = "HmacMD5";
    private static final String MD5_NAME = "MD5";
    private static final String RC4_NAME = "RC4";

    public static String encodeBase64(byte[] in) {
        String out = new sun.misc.BASE64Encoder() {
            protected int bytesPerLine () {
                return 1024;
            }
        }.encode(in);
        return out;
    }

    public static byte[] decodeBase64(String in) {
        try {
            byte[] out = new sun.misc.BASE64Decoder().decodeBuffer(in);
            return out;
        } catch (IOException e) {
            throw new RuntimeException("Invalid data", e);
        }
    }

    public static boolean compareArray(byte[] src, int srcPos, byte[] dst, int dstpos, int len) {
        for (int i = 0; i < len; i++) {
            if (src[srcPos+i] != dst[dstpos+i]) return false;
        }
        return true;
    }
    
    public static long bytesTo8(byte[] in, int pos) {
        long result = byteToLong(in[pos]);
        result += byteToLong(in[pos+1]) << 8;
        result += byteToLong(in[pos+2]) << 16;
        result += byteToLong(in[pos+3]) << 24;
        result += byteToLong(in[pos+4]) << 32;
        result += byteToLong(in[pos+5]) << 40;
        result += byteToLong(in[pos+6]) << 48;
        result += byteToLong(in[pos+7]) << 56;
        return result;
    }

    public static int bytesTo4(byte[] in, int pos) {
        int result = byteToInt(in[pos]);
        result += byteToInt(in[pos+1]) << 8;
        result += byteToInt(in[pos+2]) << 16;
        result += byteToInt(in[pos+3]) << 24;
        return result;
    }

    public static int bytesTo2(byte[] in, int pos) {
        int result = byteToInt(in[pos]);
        result += byteToInt(in[pos+1]) << 8;
        return result;
    }

    public static long byteToLong(byte b) {
        return (long) byteToInt(b);
    }

    public static int byteToInt(byte b) {
        return b < 0 ? 256+b : b;
    }
    
    public static byte[] intToBytes(int v) {
        byte[] out = new byte[4];
        out[0] = (byte) v;
        out[1] = (byte) (v >>>  8);
        out[2] = (byte) (v >>> 16);
        out[3] = (byte) (v >>> 24);
        return out;
    }

    public static byte[] shortToBytes(int v) {
	byte[] out = new byte[2];
        out[0]   = (byte) v;
        out[1] = (byte) (v >>>  8);
	return out;
    }

    public static void intTo2Bytes(int v, byte[] data, int pos) {
        data[pos]   = (byte) v;
        data[pos+1] = (byte) (v >>>  8);
    }

    public static void intTo4Bytes(int v, byte[] data, int pos) {
        data[pos]   = (byte) v;
        data[pos+1] = (byte) (v >>>  8);
        data[pos+2] = (byte) (v >>>  16);
        data[pos+3] = (byte) (v >>>  24);
    }

    public static byte[] msTimestamp() {
        long time = System.currentTimeMillis();
        time += 11644473600000l; // milliseconds from January 1, 1601 -> epoch.
        time *= 10000; // tenths of a microsecond.
        // convert to little-endian byte array.
        byte[] timestamp = new byte[8];
        for (int i = 0; i < 8; i++) {
            timestamp[i] = (byte) time;
            time >>>= 8;
        }
        return timestamp;
    }


    public static void bytesToCharsReverse(byte[] data, int offset, int length, char[] out, int outOffset) {
        for (int i = offset+length-1; i >= offset; i--) {
            byte _b = data[i];
            int b = _b < 0 ? 256+_b : _b;
            Algorithms.byteToChars(b, out, outOffset);
            outOffset += 2;
        }
    }

    public static void bytesToChars(byte[] data, int offset, int length, char[] out, int outOffset) {
        for (int i = offset; i < offset+length; i++) {
            byte _b = data[i];
            int b = _b < 0 ? 256+_b : _b;
            byteToChars(b, out, outOffset);
            outOffset += 2;
        }
    }

    public static void byteToChars(int b, char[] out, int outOffset) {
        out[outOffset++] = digits[(b >> 4) % 16];
        out[outOffset] = digits[b % 16];
    }

    public static String bytesToString(byte[] data, int offset, int length) {
        char[] out = new char[length * 2];
        bytesToChars(data, offset, length, out, 0);
        return new String(out);
    }

    public static String bytesToString(byte[] data) {
        return bytesToString(data, 0, data.length);
    }

    public static String bytesToString(ByteArray data) {
        return bytesToString(data.getData(), data.getOffset(), data.getLength());
    }

    public static byte[] stringToBytes(String in) {
        byte[] out = new byte[in.length() / 2];
        int i = 0;
        for (int offset = 0; offset < in.length();) {
//            String byteStr = "" + in.charAt(i) + in.charAt(i+1);
            char c1 = in.charAt(offset);
            if (c1 == ' ' || c1 == '-') { // skip spaces
                offset++;
            } else {
                char c2 = in.charAt(offset + 1);
                out[i] = (byte) (Character.digit(c1,16)*16 + Character.digit(c2,16));
                offset +=2;
                i++;
            }

        }
        if (out.length > i) {
            byte[] newOut = new byte[i];
            System.arraycopy(out, 0, newOut, 0, i);
            out = newOut;
        }
        return out;
    }

    final static char[] digits = {
	'0' , '1' , '2' , '3' , '4' , '5' ,
	'6' , '7' , '8' , '9' , 'A' , 'B' ,
	'C' , 'D' , 'E' , 'F' , 'G' , 'H' ,
	'I' , 'J' , 'K' , 'L' , 'M' , 'N' ,
	'O' , 'P' , 'Q' , 'R' , 'S' , 'T' ,
	'U' , 'V' , 'W' , 'X' , 'Y' , 'Z'
    };

    public static byte[] concat(Object... args) {
        int length = 0;
        for (int i=0; i < args.length; i++) {
            Object arg = args[i];
            if (arg instanceof ByteArray) {
                ByteArray byteArray = (ByteArray)arg;
                length += byteArray.getLength();
            } else if (arg instanceof byte[]) {
                byte[] bytes = (byte[]) arg;
                length += bytes.length;
            } else if (arg != null) {
                throw new RuntimeException("Unknown type. Only ByteArray or byte[] are supported[" + i + "]: " + arg);
            }
        }
        byte[] data = new byte[length];
        int offset = 0;
        for (Object arg : args) {
            if (arg instanceof ByteArray) {
                ByteArray byteArray = (ByteArray)arg;
                offset += byteArray.copyTo(data, offset);
            } else if (arg instanceof byte[]) {
                byte[] bytes = (byte[]) arg;
                System.arraycopy(bytes, 0, data, offset, bytes.length);
                offset += bytes.length;
            }
        }
        return data;
    }

    public static MessageDigest createMD4() {
        MessageDigest md4 = sun.security.provider.MD4.getInstance();
        return md4;
    }

    public static MessageDigest createMD5() {
        try {
            MessageDigest md5 = MessageDigest.getInstance(MD5_NAME);
            return md5;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    public static Mac createHmacMD5(byte[] key) {
        try {
            // Create a MAC object using HMAC-MD5 and initialize with key
            Mac hmacMD5 = Mac.getInstance(HMAC_MD5_NAME);
            hmacMD5.init(new SecretKeySpec(key, HMAC_MD5_NAME));
            return hmacMD5;
        } catch (Exception e) {
            throw new RuntimeException("Invalid key", e);
        }
    }

    public static Cipher createRC4(byte[] key) {
	return createRC4(key, Cipher.ENCRYPT_MODE);
    }

    public static Cipher createRC4(byte[] key, int opmode) {
        try {
            Cipher rc4 = Cipher.getInstance(RC4_NAME);
            rc4.init(opmode, new SecretKeySpec(key, RC4_NAME));
            return rc4;
        } catch (Exception e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    public static MessageDigest createSHA1() {
        try {
            MessageDigest sha1 = MessageDigest.getInstance(SHA1_NAME);
            return sha1;
        } catch (Exception e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    public static Cipher createDES() {
        try {
            Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
            return des;
        } catch (Exception e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    public static byte[] calculateMD4(byte[] data) {
        MessageDigest md4 = createMD4();
        md4.update(data);
        return md4.digest();
    }

    public static byte[] calculateMD5(byte[] data) {
        MessageDigest md5 = createMD5();
        md5.update(data);
        return md5.digest();
    }

    public static byte[] calculateHmacMD5(byte[] key, ByteArray data) {
        Mac hmacMD5 = createHmacMD5(key);
        hmacMD5.update(data.getData(), data.getOffset(), data.getLength());
        return hmacMD5.doFinal();
    }

    public static byte[] calculateHmacMD5(byte[] key, byte[] data) {
        Mac hmacMD5 = createHmacMD5(key);
        hmacMD5.update(data);
        return hmacMD5.doFinal();
    }


    /**
     * 6 Appendix A: Cryptographic Operations Reference
     * RC4K(K,D)
     * Indicates the encryption of data item D with the key K
     * using the RC4 algorithm.
     * Note The key sizes for RC4 encryption in NTLM are
     * defined in sections KXKEY, SIGNKEY, and SEALKEY, where
     * they are created.
     * 
     * @param key
     * @param data
     * @return
     */
    public static byte[] calculateRC4K(byte[] key, byte[] data) {
        try {
            Cipher rc4 = createRC4(key);
            return rc4.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    public static byte[] calculateSHA1(byte[] data) {
        MessageDigest sha1 = createSHA1();
        sha1.update(data);
        return sha1.digest();
    }

    /**
     * 6 Appendix A: Cryptographic Operations Reference
     *
     * DES(K, D) Indicates the encryption of an 8-byte data item D with the
     *    7-byte key K using the Data Encryption Standard (DES)
     *    algorithm in Electronic Codebook (ECB) mode. The result is
     *    8 bytes in length ([FIPS46-2]).
     *
     *
     *
     * @param keyData A byte array containing the DES key material.
     * @param data data
     *
     * @return A DES encryption key created from the key material
     * starting at the specified offset in the given byte array.
     */
    public static byte[] calculateDES(ByteArray keyData, ByteArray data) {
        try {
            // Creates a DES encryption key from the given 7-byte key material.
            byte[] keyBytes = new byte[7];
            if (keyData.getLength() > 0) {
                System.arraycopy(keyData.getData(), keyData.getOffset(), keyBytes, 0, keyData.getLength());
            }
            byte[] material = new byte[8];
            material[0] = keyData.getNotNullByte(0);
            material[1] = (byte) (keyData.getNotNullByte(0) << 7 | (keyData.getNotNullByte(1) & 0xff) >>> 1);
            material[2] = (byte) (keyData.getNotNullByte(1) << 6 | (keyData.getNotNullByte(2) & 0xff) >>> 2);
            material[3] = (byte) (keyData.getNotNullByte(2) << 5 | (keyData.getNotNullByte(3) & 0xff) >>> 3);
            material[4] = (byte) (keyData.getNotNullByte(3) << 4 | (keyData.getNotNullByte(4) & 0xff) >>> 4);
            material[5] = (byte) (keyData.getNotNullByte(4) << 3 | (keyData.getNotNullByte(5) & 0xff) >>> 5);
            material[6] = (byte) (keyData.getNotNullByte(5) << 2 | (keyData.getNotNullByte(6) & 0xff) >>> 6);
            material[7] = (byte) (keyData.getNotNullByte(6) << 1);

            // Applies odd parity to the given byte array.
            for (int i = 0; i < material.length; i++) {
                byte b = material[i];
                boolean needsParity = (((b >>> 7) ^ (b >>> 6) ^ (b >>> 5) ^
                        (b >>> 4) ^ (b >>> 3) ^ (b >>> 2) ^
                        (b >>> 1)) & 0x01) == 0;
                if (needsParity) {
                    material[i] |= (byte) 0x01;
                } else {
                    material[i] &= (byte) 0xfe;
                }
            }
            SecretKey secretKey = new SecretKeySpec(material, "DES");

            Cipher des = createDES();
            des.init(Cipher.ENCRYPT_MODE, secretKey);
            return des.doFinal(data.getData(), data.getOffset(), data.getLength());
        } catch (Exception e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    /**
     * 6 Appendix A: Cryptographic Operations Reference
     *
     * DESL(K, D) Indicates the encryption of an 8-byte data item D with the 3.3.1
     *     16-byte key K using the Data Encryption Standard Long
     *     (DESL) algorithm. The result is 24 bytes in length. DESL(K,
     *     D) is computed as follows.
     * ConcatenationOf( DES(K[0..6], D), \
     * DES(K[7..13], D), DES( \
     * ConcatenationOf(K[14..15], Z(5)), D));
     * Note K[] implies a key represented as a character array.
     * 
     * @param keyData key
     * @param data data
     * @return DESL result
     */
    public static byte[] calculateDESL(byte[] keyData, ByteArray data) {
        byte[] out1 = calculateDES(new ByteArray(keyData, 0, 7), data);
        byte[] out2 = calculateDES(new ByteArray(keyData, 7, 7), data);
        byte[] out3 = calculateDES(new ByteArray(keyData, 14, 7), data);
        return concat(out1, out2, out3);
    }


    /**
     * CRC32(M) Indicates a 32-bit CRC calculated over M. 3.4.3, 3.4.4
     * todo [6] use sun.security.krb5.internal.crypto.crc32.byte2crc32sum_bytes()
     * @return cr
     */
    public static byte[] calculateCRC32(byte[] data) {
        Checksum checksum = new CRC32();
        /*
        * To compute the CRC32 checksum for byte array, use
        *
        * void update(bytes[] b, int start, int length)
        * method of CRC32 class.
        */

        checksum.update(data, 0, data.length);

        /*
        * Get the generated checksum using
        * getValue method of CRC32 class.
        */
        long lngChecksum = checksum.getValue();

        return intToBytes((int) lngChecksum);
    }

    /**
     * Generate random byte array
     *
     * @param length array length
     * @return random byte array 
     */
    public static byte[] nonce(int length) {
        byte[] nonce = new byte[length];
        nonce(nonce, 0, length);
        return nonce;
    }

    public static void nonce(byte[] array, int offset, int length) {
        for (int i = offset+length-1; i >= offset ; i--) {
            array[i] = (byte) (Math.random() * 256);
        }
    }

    public static final class ByteArray {
        private byte[] data;
        private int offset;
        private int length;

        public ByteArray(byte[] data) {
            this.data = data;
            offset = 0;
            length = data.length;
        }

        public ByteArray(byte[] data, int offset, int length) {
            this.data = data;
            this.offset = offset;
            this.length = Math.min(length, data.length - offset);
        }

        public byte[] getData() {
            return data;
        }

        public int getOffset() {
            return offset;
        }

        public int getLength() {
            return length;
        }

        public int copyTo(byte[] dstData, int dstOffset) {
            System.arraycopy(data, offset, dstData, dstOffset, length);
            return length;
        }

        /**
         * Return byte or zero
         *
         * @param pos
         * @return
         */
        public byte getNotNullByte(int pos) {
            return pos >= length ? 0 : data[offset + pos];
        }

        public String asString(Charset charset) {
            return new String(data, offset, length, charset);            
        }

	public String toHex() {	
	    int end = offset + length;
	    StringBuffer sb = new StringBuffer();
	    for (int i=offset; i < end; i++) {
		String h = Integer.toHexString(data[i]);
		if (h.length() == 1) {
		    sb.append("0");
		}
		sb.append(h);
	    }
	    return sb.toString();
	}
    }


}
