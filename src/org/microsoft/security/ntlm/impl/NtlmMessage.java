/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import java.util.ArrayList;
import java.util.List;

import static org.microsoft.security.ntlm.impl.Algorithms.ByteArray;
import static org.microsoft.security.ntlm.impl.Algorithms.UNICODE_ENCODING;
import static org.microsoft.security.ntlm.impl.Algorithms.intTo2Bytes;
import static org.microsoft.security.ntlm.impl.Algorithms.intTo4Bytes;
import static org.microsoft.security.ntlm.impl.Algorithms.intToBytes;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLM_MESSAGE_SIGNATURE;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class NtlmMessage {
    /**
     * Object can be byte[] or ByteArray
     * If byte[] then then content is copied as is
     * If Bytearray
     */
    private List<Object> dataList = new ArrayList<Object>();
    private int payloadLength;
    private int plainLength;

    public NtlmMessage(int type) {
        appendPlain(NTLM_MESSAGE_SIGNATURE);
        appendPlain(intToBytes(type));
    }

    public void appendPlain(byte[] data) {
        dataList.add(data);
        plainLength += data.length;

    }

    public void appendStructure(ByteArray data) {
        dataList.add(data);
        payloadLength += data == null ? 0 : data.getLength();
        plainLength += 8;
    }

    public void appendStructure(byte[] data) {
        if (data == null) {
            dataList.add(null);
            plainLength += 8;
        } else {
            appendStructure(new ByteArray(data));
        }
    }

    public void appendStructure(String data) {
	if (data == null) {
	    dataList.add(null);
	    plainLength += 8;
	} else {
            appendStructure(data.getBytes(UNICODE_ENCODING));
	}
    }

    public byte[] getData() {
        byte[] data = new byte[payloadLength + plainLength];
        int plainOffset = 0;
        int payloadOffset = plainLength;
        for (Object dataItem : dataList) {
            if (dataItem instanceof byte[]) {
                byte[] plainDataItem = (byte[]) dataItem;
                System.arraycopy(plainDataItem, 0, data, plainOffset, plainDataItem.length);
                plainOffset += plainDataItem.length;
            } else {
                ByteArray structureDataItem = (ByteArray) dataItem;
                if (structureDataItem != null) {
                    int dataLen = structureDataItem.getLength();
                    intTo2Bytes(dataLen, data, plainOffset);
                    intTo2Bytes(dataLen, data, plainOffset+2);
		    if (dataLen == 0) {
                	intTo4Bytes(0, data, plainOffset+4);
		    } else {
                	intTo4Bytes(payloadOffset, data, plainOffset+4);
                	payloadOffset += structureDataItem.copyTo(data, payloadOffset);
		    }
                }
                plainOffset += 8;
            }
        }
        return data;
    }
}
