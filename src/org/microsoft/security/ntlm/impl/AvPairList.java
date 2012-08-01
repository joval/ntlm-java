/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import static org.microsoft.security.ntlm.impl.Algorithms.*;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.*;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class AvPairList {

    private ByteArray[] avPairs = new ByteArray[MS_AV_LENGTH];

    public void add(int id, ByteArray bytes) {
        avPairs[id] = bytes;
    }

    public void add(int id, byte[] bytes) {
        add(id, new ByteArray(bytes));
    }

    public byte[] getData() {
        int len = 4; // MsvAvEOL len
        for (ByteArray avPair : avPairs) {
            if (avPair != null) {
                len += avPair.getLength() + 4;
            }
        }
        byte[] data = new byte[len];
        int offset = 0;
        for (int i = 0; i < avPairs.length; i++) {
            ByteArray avPair = avPairs[i];
            if (avPair != null) {
                int length = avPair.getLength();
                intTo2Bytes(i, data, offset);
                intTo2Bytes(length, data, offset+2);
                avPair.copyTo(data, offset+4);
                offset += avPair.getLength() + 4;
            }
        }
        return data;
    }
}
