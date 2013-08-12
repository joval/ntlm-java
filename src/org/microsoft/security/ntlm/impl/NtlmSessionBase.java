/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import java.nio.charset.Charset;
import java.nio.CharBuffer;
import java.security.SignatureException;
import java.util.Arrays;
import javax.crypto.Cipher;

import org.microsoft.security.ntlm.NtlmAuthenticator;
import org.microsoft.security.ntlm.NtlmSession;

import static org.microsoft.security.ntlm.NtlmAuthenticator.ConnectionType;
import static org.microsoft.security.ntlm.NtlmAuthenticator.LOCALHOST;
import static org.microsoft.security.ntlm.NtlmAuthenticator.LOCALDOMAIN;
import static org.microsoft.security.ntlm.NtlmAuthenticator.WindowsVersion;
import static org.microsoft.security.ntlm.impl.Algorithms.ByteArray;
import static org.microsoft.security.ntlm.impl.Algorithms.EMPTY_ARRAY;
import static org.microsoft.security.ntlm.impl.Algorithms.ASCII_ENCODING;
import static org.microsoft.security.ntlm.impl.Algorithms.UNICODE_ENCODING;
import static org.microsoft.security.ntlm.impl.Algorithms.bytesTo4;
import static org.microsoft.security.ntlm.impl.Algorithms.calculateHmacMD5;
import static org.microsoft.security.ntlm.impl.Algorithms.calculateRC4K;
import static org.microsoft.security.ntlm.impl.Algorithms.concat;
import static org.microsoft.security.ntlm.impl.Algorithms.createRC4;
import static org.microsoft.security.ntlm.impl.Algorithms.intToBytes;
import static org.microsoft.security.ntlm.impl.Algorithms.msTimestamp;
import static org.microsoft.security.ntlm.impl.Algorithms.nonce;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_128;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_56;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_KEY_EXCH;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_LM_KEY;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_OEM;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_UNICODE;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_VERSION;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_TARGET_TYPE_DOMAIN;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_TARGET_TYPE_SERVER;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_TARGET_INFO;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.MsvAvNbDomainName;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.MsvAvNbComputerName;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.KeyMode;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.mac;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.reinitSealingKey;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.sealkey;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.signkey;

/**
 *
 * See useful information on keys calculation here:
 * http://blogs.msdn.com/b/openspecification/archive/2010/04/20/ntlm-keys-and-sundry-stuff.aspx
 *
 * Explanation on some key calculation issues:
 * http://social.msdn.microsoft.com/Forums/en-US/os_windowsprotocols/thread/c1db6e46-ed1a-4403-a836-04a4cee3c0c1
 *
 *
 *
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public abstract class NtlmSessionBase  implements NtlmSession {
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private static final String NULL = null;

    static byte[] toBytes(char[] chars, Charset encoding) {
        return encoding.encode(CharBuffer.wrap(chars)).array();
    }

    private ConnectionType connectionType;
    private WindowsVersion windowsVersion;

    protected String workstation;
    protected String domain;
    protected String username;
    protected char[] password;

    private byte[] exportedSessionKey;
    private byte[] encryptedRandomSessionKey;
    private byte[] clientSigningKey;
    private byte[] serverSigningKey;
    private byte[] clientSealingKey;
    private byte[] serverSealingKey;
    private Cipher clientSealingKeyCipher;
    private Cipher serverSealingKeyCipher;
    private int seqNum;

    private byte[] negotiateMessageData;
    private NtlmMessage authenticateMessage;

    int negotiateFlags;
    byte[] ntChallengeResponse;
    byte[] lmChallengeResponse;
    byte[] sessionBaseKey;
    ByteArray serverChallenge;

    public NtlmSessionBase(ConnectionType connectionType, int negotiateFlags, WindowsVersion windowsVersion,
		String workstation, String domain, String username, char[] password) {

        this.connectionType = connectionType;
        this.windowsVersion = windowsVersion;
        this.workstation = workstation;
        this.domain = "".equals(domain) ? LOCALHOST : domain;
        this.username = username;
	this.password = password;
	this.negotiateFlags = negotiateFlags;
    }

    /**
     * 3.1.5.1.2 Client Receives a CHALLENGE_MESSAGE from the Server
     * When the client receives a CHALLENGE_MESSAGE from the server, it MUST determine if the features
     * selected by the server are strong enough for the client authentication policy. If not, the client MUST
     * return an error to the calling application. Otherwise, the client responds with an
     * AUTHENTICATE_MESSAGE message.
     * 
     * If ClientRequire128bitEncryption == TRUE, then if 128-bit encryption is not negotiated, then the
     * client MUST return SEC_E_UNSUPPORTED_FUNCTION to the application.
     * 
     * The client processes the CHALLENGE_MESSAGE and constructs an AUTHENTICATE_MESSAGE per
     * the following pseudocode where all strings are encoded as RPC_UNICODE_STRING ([MS-DTYP]
     * section 2.3.8):
     * 
     * -- Input:
     * --  ClientConfigFlags, User, and UserDom - Defined in section 3.1.1.
     * --  NbMachineName - The NETBIOS machine name of the server.
     * --  An NTLM NEGOTIATE_MESSAGE whose fields are defined in section 2.2.1.2.
     * --  An NTLM CHALLENGE_MESSAGE whose message fields are defined in section 2.2.1.2.
     * --  An NTLM AUTHENTICATE_MESSAGE whose message fields are defined in section 2.2.1.3 with MIC field set to 0.
     * --  OPTIONAL ClientSuppliedTargetName - Defined in section 3.1.1.2
     * --  OPTIONAL ClientChannelBindingUnhashed - Defined in section 3.1.1.2
     * --
     * -- Output:
     * --  ClientHandle - The handle to a key state structure corresponding to the current state of the ClientSealingKey
     * --  ServerHandle - The handle to a key state structure corresponding to the current state of the ServerSealingKey
     * --  An NTLM AUTHENTICATE_MESSAGE whose message fields are defined in section 2.2.1.3.
     * --
     * --  The following NTLM keys generated by the client are defined in section 3.1.1:
     * --  ExportedSessionKey, ClientSigningKey, ClientSealingKey, ServerSigningKey, and ServerSealingKey.
     *
     * -- Temporary variables that do not pass over the wire are defined
     *    below:
     * --  KeyExchangeKey, ResponseKeyNT, ResponseKeyLM, SessionBaseKey - Temporary variables used to store 128-bit keys.
     * --  Time - Temporary variable used to hold the 64-bit time.
     * --  MIC - message integrity for the NTLM NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE
     * --
     * -- Functions used:
     * --  NTOWFv1, LMOWFv1, NTOWFv2, LMOWFv2, ComputeResponse - Defined in section 3.3
     * --  KXKEY, SIGNKEY, SEALKEY - Defined in sections 3.4.5, 3.4.6, and 3.4.7
     * --  Currenttime, NIL, NONCE - Defined in section 6.
     * 
     * If NTLM v2 authentication is used and the CHALLENGE_MESSAGE does not contain both
     * MsvAvNbComputerName and MsvAvNbDomainName AVPairs and either Integrity is TRUE or
     * Confidentiality is TRUE, then return STATUS_LOGON_FAILURE.
     * If NTLM v2 authentication is used and the CHALLENGE_MESSAGE contains a TargetInfo field, the
     * client SHOULD NOT send the LmChallengeResponse and SHOULD set the LmChallengeResponseLen
     * and LmChallengeResponseMaxLen fields in the AUTHENTICATE_MESSAGE to zero. <41>
     * <41> Section 3.1.5.1.2: This functionality is not supported in Windows NT, Windows 2000,
     * Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008.
     * 
     * Response keys are computed using the ComputeResponse() function, as specified in section 3.3.
     * 
     * Set AUTHENTICATE_MESSAGE.NtChallengeResponse, AUTHENTICATE_MESSAGE.LmChallengeResponse, SessionBaseKey to
     * ComputeResponse(CHALLENGE_MESSAGE.NegotiateFlags, ResponseKeyNT, ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge,
     *         AUTHENTICATE_MESSAGE.ClientChallenge, Time, CHALLENGE_MESSAGE.TargetInfo)
     * 
     */
    @Override
    public void processChallengeMessage(byte[] challengeMessageData) {
        NtlmChallengeMessage challengeMessage = new NtlmChallengeMessage(challengeMessageData);

	//
	// Update negotiateFlags according to known rules
	//
        negotiateFlags = challengeMessage.getNegotiateFlags();
	negotiateFlags = NTLMSSP_TARGET_TYPE_DOMAIN.excludeFlag(negotiateFlags);
	negotiateFlags = NTLMSSP_TARGET_TYPE_SERVER.excludeFlag(negotiateFlags);
        if (NTLMSSP_NEGOTIATE_OEM.isSet(negotiateFlags) && NTLMSSP_NEGOTIATE_UNICODE.isSet(negotiateFlags)) {
            negotiateFlags = NTLMSSP_NEGOTIATE_OEM.excludeFlag(negotiateFlags);
        }
        if (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.isSet(negotiateFlags)) {
            negotiateFlags = NTLMSSP_NEGOTIATE_LM_KEY.excludeFlag(negotiateFlags);
        }
	if (NTLMSSP_NEGOTIATE_TARGET_INFO.isSet(negotiateFlags)) {
	    if (LOCALHOST.equalsIgnoreCase(domain) || domain == null) {
		domain = challengeMessage.getTargetInfoPairs()[MsvAvNbComputerName].asString(UNICODE_ENCODING);
	    } else if (LOCALDOMAIN.equalsIgnoreCase(domain)) {
		domain = challengeMessage.getTargetInfoPairs()[MsvAvNbDomainName].asString(UNICODE_ENCODING);
	    }
	}

	//
	// 3.1.5.1.2
	// If NTLM v2 authentication is used, the client SHOULD send the timestamp in the
	// CHALLENGE_MESSAGE. <40>
	// <40> Section 3.1.5.1.2: Not supported by Windows NT, Windows 2000, Windows XP, and Windows
	// Server 2003.
	// 
	// If there exists a CHALLENGE_MESSAGE.NTLMv2_CLIENT_CHALLENGE.AvId == MsvAvTimestamp
	//     Set Time to CHALLENGE_MESSAGE.TargetInfo.Value of that AVPair
	// Else
	//     Set Time to Currenttime
	// Endif
	// 
        Algorithms.ByteArray time = challengeMessage.getTime();
        if (time == null) {
            time = new Algorithms.ByteArray(msTimestamp());
        }

        serverChallenge = challengeMessage.getServerChallenge();
        calculateNTLMResponse(time, challengeMessage.getTargetInfo());
        calculateKeys();

	//
	// 2.2.1.3 AUTHENTICATE_MESSAGE
	// 
        authenticateMessage = new NtlmMessage(3);
        authenticateMessage.appendStructure(lmChallengeResponse);
        authenticateMessage.appendStructure(ntChallengeResponse);
	authenticateMessage.appendStructure(domain);
        authenticateMessage.appendStructure(username);
	authenticateMessage.appendStructure(workstation);
        authenticateMessage.appendStructure(encryptedRandomSessionKey);
        authenticateMessage.appendPlain(intToBytes(negotiateFlags));

	//
	// A VERSION structure (section 2.2.2.10) that is present only when the
	// NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field. This structure is used
	// for debugging purposes only. In normal protocol messages, it is ignored and does not affect
	// the NTLM message processing.<9>
	// 
	//  <9> Section 2.2.1.3: The Version field is NOT sent or consumed by Windows NT or Windows 2000.
	// Windows NT and Windows 2000 assume that the Payload field started immediately after
	// NegotiateFlags. Since all references into the Payload field are by offset from the start of the
	// message (not from the start of the Payload field), Windows NT and Windows 2000 can correctly
	// interpret messages constructed with Version fields
	// 
        if (windowsVersion.ordinal() >= WindowsVersion.WindowsXp.ordinal() &&
	    NTLMSSP_NEGOTIATE_VERSION.isSet(negotiateFlags)) {

            authenticateMessage.appendPlain(windowsVersion.data);
        }

	//
	// The message integrity for the NTLM NEGOTIATE_MESSAGE,
	// CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE.<10>
	// 
	// <10> Section 2.2.1.3: The MIC field is omitted in Windows NT, Windows 2000, Windows XP, and
	// Windows Server 2003.
	//
	//
	// 3.1.5.1.2 Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE,
	//                                                                   CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
	// Set AUTHENTICATE_MESSAGE.MIC to MIC
	//
        if (windowsVersion.ordinal() >= WindowsVersion.WindowsVista.ordinal()) {
            byte[] mic = calculateHmacMD5(exportedSessionKey,
                    connectionType == ConnectionType.connectionOriented ?
                            concat(negotiateMessageData, challengeMessage.getMessageData(), authenticateMessage.getData()) :
                            concat(challengeMessage.getMessageData(), authenticateMessage.getData())
            );
            authenticateMessage.appendPlain(mic);
        }
    }

    protected abstract void calculateNTLMResponse(ByteArray time, ByteArray targetInfo);

    /**
     * 3.1.5.1.2
     * Set KeyExchangeKey to KXKEY(SessionBaseKey, LmChallengeResponse, CHALLENGE_MESSAGE.ServerChallenge)
     * If (NTLMSSP_NEGOTIATE_KEY_EXCH bit is set in CHALLENGE_MESSAGE.NegotiateFlags )
     *     Set ExportedSessionKey to NONCE(16)
     *     Set AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey to RC4K(KeyExchangeKey, ExportedSessionKey)
     * Else
     *     Set ExportedSessionKey to KeyExchangeKey
     *     Set AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey to NIL
     * Endif
     * 
     * Set ClientSigningKey to SIGNKEY(NegFlg, ExportedSessionKey, "Client")
     * Set ServerSigningKey to SIGNKEY(NegFlg, ExportedSessionKey, "Server")
     * Set ClientSealingKey to SEALKEY(NegFlg, ExportedSessionKey, "Client")
     * Set ServerSealingKey to SEALKEY(NegFlg, ExportedSessionKey, "Server")
     * 
     * RC4Init(ClientHandle, ClientSealingKey)
     * RC4Init(ServerHandle, ServerSealingKey)
     *  
     */
    private void calculateKeys() {
        byte[] keyExchangeKey = kxkey();
        if (NTLMSSP_NEGOTIATE_KEY_EXCH.isSet(negotiateFlags)) {
            exportedSessionKey = nonce(16);
            encryptedRandomSessionKey = calculateRC4K(keyExchangeKey, exportedSessionKey);
        } else {
            exportedSessionKey = keyExchangeKey;
            encryptedRandomSessionKey = null;
        }
        clientSigningKey = signkey(negotiateFlags, exportedSessionKey, KeyMode.client);
        serverSigningKey = signkey(negotiateFlags, exportedSessionKey, KeyMode.server);
        clientSealingKey = sealkey(negotiateFlags, exportedSessionKey, KeyMode.client);
        serverSealingKey = sealkey(negotiateFlags, exportedSessionKey, KeyMode.server);

        if (connectionType == NtlmAuthenticator.ConnectionType.connectionOriented) {
            clientSealingKeyCipher = createRC4(clientSealingKey, Cipher.ENCRYPT_MODE);
            serverSealingKeyCipher = createRC4(serverSealingKey, Cipher.DECRYPT_MODE);
        }
    }

    /**
     * 3.4.5.1 KXKEY
     * @return kxkey
     */
    protected abstract byte[] kxkey();

    @Override
    public byte[] generateNegotiateMessage() {
        if (connectionType == ConnectionType.connectionOriented) {
            NtlmMessage negotiateMessage = new NtlmMessage(1);
            negotiateMessage.appendPlain(intToBytes(negotiateFlags));
/*
            negotiateMessage.appendStructure(domain);
            negotiateMessage.appendStructure(workstation);
*/
	    negotiateMessage.appendStructure(NULL); // domain
	    negotiateMessage.appendStructure(NULL); // workstation
            negotiateMessage.appendPlain(windowsVersion.data);
            negotiateMessageData = negotiateMessage.getData();
        } else {
            negotiateMessageData = EMPTY_BYTE_ARRAY;
        }
        return negotiateMessageData;
    }

    @Override
    public void updateSequenceNumber(int seqNum) {
	// NTLMSSP_NEGOTIATE_DATAGRAM.isSet(negotiateFlags)
        if (connectionType != NtlmAuthenticator.ConnectionType.connectionless) {
            throw new IllegalArgumentException("Can't update equence number on connection-oriented session");
        }
        clientSealingKeyCipher = reinitSealingKey(clientSealingKey, seqNum);
        serverSealingKeyCipher = reinitSealingKey(serverSealingKey, seqNum);
        this.seqNum = seqNum;
    }

    /**
     * 2.2.2.9 NTLMSSP_MESSAGE_SIGNATURE
     * The NTLMSSP_MESSAGE_SIGNATURE structure (section 3.4.4), specifies the signature block used
     * for application message integrity and confidentiality. This structure is then passed back to the
     * application, which embeds it within the application protocol messages, along with the NTLM-
     * encrypted or integrity-protected application message data.
     * This structure MUST take one of the two following forms, depending on whether the
     * NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is negotiated:
     * NTLMSSP_MESSAGE_SIGNATURE
     * NTLMSSP_MESSAGE_SIGNATURE for Extended Session Security
     * 
     * 
     * 2.2.2.9.2 NTLMSSP_MESSAGE_SIGNATURE for Extended Session Security
     * This version of the NTLMSSP_MESSAGE_SIGNATURE structure MUST be used when the
     * NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is negotiated.
     * Version (4 bytes): A 32-bit unsigned integer MUST be 0x00000001
     * Checksum (8 bytes):
     * SeqNum (4 bytes):
     */
    private byte[] sign(byte[] message) {
        byte[] mac = mac(negotiateFlags, seqNum, clientSigningKey, clientSealingKeyCipher, message);
        if (connectionType == ConnectionType.connectionOriented) {
            seqNum++;
        }
        return mac;
    }

    /**
     * 3.4.3 Message Confidentiality
     * Message confidentiality, if it is negotiated, also implies message integrity. If message confidentiality
     * is negotiated, a sealed (and implicitly signed) message is sent instead of a signed or unsigned
     * message. The function that seals a message using the signing key, sealing key, and message
     * sequence number is as follows:
     * -- Input:
     * --  SigningKey - The key used to sign the message.
     * --  Message - The message to be sealed, as provided to the application.
     * --  NegFlg, SeqNum - Defined in section 3.1.1.
     * --  Handle - The handle to a key state structure corresponding to the
     * --          current state of the SealingKey
     * --
     * -- Output:
     * --  Sealed message – The encrypted message
     * --  Signature – The checksum of the Sealed message
     * --
     * -- Functions used:
     * --  RC4() - Defined in Section 6 and 3.1.
     * --  MAC() - Defined in Section 3.4.4.1 and 3.4.4.2.
     * 
     * Define SEAL(Handle, SigningKey, SeqNum, Message) as
     *     Set Sealed message to RC4(Handle, Message)
     *     Set Signature to MAC(Handle, SigningKey, SeqNum, Message)
     * EndDefine
     * 
     * Message confidentiality is available in connectionless mode only if the client configures extended
     * session security.
     * 
     */
    public byte[] seal(byte[] message) {
        try {
	    byte[] sealed = clientSealingKeyCipher.update(message);
	    byte[] signature = sign(message);
	    return concat(intToBytes(signature.length), signature, sealed);
        } catch (Exception e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    /**
     * Unseal a message that was sealed by the server.
     */
    public byte[] unseal(byte[] encrypted) throws SignatureException {
        try {
	    int sigLen = bytesTo4(encrypted, 0);
	    int offset = 4 + sigLen;
	    int messageLen = encrypted.length - offset;
            byte[] unsealed = serverSealingKeyCipher.update(encrypted, offset, messageLen);

            byte[] signature = new ByteArray(encrypted, 4, sigLen).asByteArray();
	    int seqNum = bytesTo4(signature, sigLen - 4); // last 4 bytes are sequence number
            byte[] mac = mac(negotiateFlags, seqNum, serverSigningKey, serverSealingKeyCipher, unsealed);
	    if (!Arrays.equals(signature, mac)) {
		throw new SignatureException("Signature " + new ByteArray(mac).toHex() +
			" does not match expected value " + new ByteArray(signature).toHex());
	    }
	    return unsealed;
        } catch (Exception e) {
            throw new RuntimeException("Internal error", e);
        }
    }

    /**
     * If the CHALLENGE_MESSAGE TargetInfo field (section 2.2.1.2) has an MsvAvTimestamp present,
     * the client SHOULD provide a MIC<48>:
     * If there is an AV_PAIR structure (section 2.2.2.1) with the AvId field set to MsvAvFlags,
     * then in the Value field, set bit 0x2 to 1.
     * else add an AV_PAIR structure (section 2.2.2.1) and set the AvId field to MsvAvFlags and the
     * Value field bit 0x2 to 1.
     * 
     * Populate the MIC field with the MIC, where
     * Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(
     * CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
     * 
     * 
     * The client SHOULD send the channel binding AV_PAIR <49>:
     * ...
     * 
     */
    public byte[] generateAuthenticateMessage() {
	if (authenticateMessage == null) {
	    throw new IllegalStateException("You must first process a challenge message");
	} else {
            return authenticateMessage.getData();
	}
    }
}
