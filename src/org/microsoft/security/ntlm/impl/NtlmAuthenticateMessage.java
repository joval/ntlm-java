/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import static org.microsoft.security.ntlm.impl.Algorithms.bytesTo4;
import static org.microsoft.security.ntlm.impl.Algorithms.compareArray;

/**
 * [MS-NLMP:2.2.1.3] AUTHENTICATE_MESSAGE
 *
 *
 * Signature (8 bytes): An 8-byte character array that MUST contain the ASCII string ('N', 'T', 'L',
'M', 'S', 'S', 'P', '\0').

 * MessageType (4 bytes): A 32-bit unsigned integer that indicates the message type. This field
MUST be set to 0x00000003.
 *
 * LmChallengeResponseFields (8 bytes)
 *
 *
 *


Authenticate message

        LmChallengeResponse == type[12..19]
        LmChallengeResponseLen == x18 == 24
        LmChallengeResponseBufferOffset = ?


        NtChallengeResponseFields == type[20..27]
        NtChallengeResponseLen == NtChallengeResponseMaxLen == x18


        DomainNameFields == type[28..35]
        DomainNameBufferOffset == type[32..35] == x40 == 64

        UserNameFields == type[36..43]
        WorkstationFields == type[44..51]
        EncryptedRandomSessionKeyFields == type[52..59]
        NegotiateFlags == type[60..63]
        Version == type[64..72]
        MIC == type[72..88] - The MIC field is omitted in Windows NT, Windows 2000, Windows XP, and Windows Server 2003.
        Payload == type[88..]: LmChallengeResponseBufferOffset, NtChallengeResponseBufferOffset,
                                DomainNameBufferOffset, UserNameBufferOffset, WorkstationBufferOffset, and
                                EncryptedRandomSessionKeyBufferOffset

 *
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class NtlmAuthenticateMessage {
    private byte[] messageData;

    public NtlmAuthenticateMessage(byte[] data) {
        messageData = data;
        if (!compareArray(data, 0, NtlmRoutines.NTLM_MESSAGE_SIGNATURE, 0, NtlmRoutines.NTLM_MESSAGE_SIGNATURE.length)) {
            throw new RuntimeException("Invalid signature");
        }
        int messageType = bytesTo4(data, 8);
        if (messageType != 3) {
            throw new RuntimeException("Invalid message type: " + messageType);
        }

/*
        // LmChallengeResponseFields (8 bytes)
        int lmChallengeResponseLen = bytesTo2(data, 12);
        int lmChallengeResponseMaxLen = bytesTo2(data, 14);
        int lmChallengeResponseBufferOffset = bytesTo2(data, 16);

        // NtChallengeResponseFields (8 bytes)
        int NtChallengeResponseLen = bytesTo2(data, 20);
        int NtChallengeResponseMaxLen = bytesTo2(data, 22);
        int NtChallengeResponseBufferOffset = bytesTo4(data, 24);

        // DomainNameFields (8 bytes)
        int DomainNameLen = bytesTo2(data, 28);
        int DomainNameMaxLen = bytesTo2(data, 30);
        int DomainNameBufferOffset = bytesTo4(data, 32);

        // UserNameFields (8 bytes)
        int UserNameLen = bytesTo2(data, 36);
        int UserNameMaxLen = bytesTo2(data, 38);
        int UserNameBufferOffset = bytesTo4(data, 40);

        // WorkstationFields (8 bytes)
        int WorkstationLen = bytesTo2(data, 44);
        int WorkstationMaxLen = bytesTo2(data, 46);
        int WorkstationBufferOffset = bytesTo4(data, 48);

        // EncryptedRandomSessionKeyFields (8 bytes) - If the NTLMSSP_NEGOTIATE_KEY_EXCH flag
        // is set in NegotiateFlags, indicating that EncryptedRandomSessionKey is supplied
        int EncryptedRandomSessionKeyLen = bytesTo2(data, 52);
        int EncryptedRandomSessionKeyMaxLen = bytesTo2(data, 54);
        int EncryptedRandomSessionKeyBufferOffset = bytesTo4(data, 56);

        // NegotiateFlags (4 bytes)
        int NegotiateFlags = bytesTo4(data, 60);
*/

        /*
Version (8 bytes): A VERSION structure (section 2.2.2.10) that is present only when the
NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field. This structure is used
for debugging purposes only. In normal protocol messages, it is ignored and does not affect
the NTLM message processing.<9>

The Version field is NOT sent or consumed by Windows NT or Windows 2000.
Windows NT and Windows 2000 assume that the Payload field started immediately after
NegotiateFlags. Since all references into the Payload field are by offset from the start of the
message (not from the start of the Payload field), Windows NT and Windows 2000 can correctly
interpret messages constructed with Version fields.

         */
    }

    public NtlmAuthenticateMessage(byte[] LmChallengeResponse, byte[] NtChallengeResponse, String DomainName) {
    }
}
