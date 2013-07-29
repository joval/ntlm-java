/*
 * $Id: $
 */
package org.microsoft.security.ntlm.impl;

import org.microsoft.security.ntlm.NtlmAuthenticator;

import javax.crypto.Mac;
import java.security.MessageDigest;

import static org.microsoft.security.ntlm.NtlmAuthenticator.*;
import static org.microsoft.security.ntlm.impl.Algorithms.ByteArray;
import static org.microsoft.security.ntlm.impl.Algorithms.UNICODE_ENCODING;
import static org.microsoft.security.ntlm.impl.Algorithms.calculateHmacMD5;
import static org.microsoft.security.ntlm.impl.Algorithms.concat;
import static org.microsoft.security.ntlm.impl.Algorithms.createHmacMD5;
import static org.microsoft.security.ntlm.impl.Algorithms.createMD4;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.Z;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class NtlmV2Session extends NtlmSessionBase {
    public NtlmV2Session(ConnectionType connectionType, int negotiateFlags, WindowsVersion windowsVersion,
		String hostname, String domain, String username, char[] password) {

        super(connectionType, negotiateFlags, windowsVersion, hostname, domain, username, password);
    }

    /**
     * 3.3.2 NTLM v2 Authentication
     * The following pseudocode defines the details of the algorithms used to calculate the keys used in
     * NTLM v2 authentication.
     * 
     * Note The NTLM authentication version is not negotiated by the protocol. It MUST be configured on
     * both the client and the server prior to authentication. The NTOWF v2 and LMOWF v2 functions
     * defined in this section are NTLM version-dependent and are used only by NTLM v2.
     * 
     * The NT and LM response keys MUST be encoded using the following specific one-way functions
     * where all strings are encoded as RPC_UNICODE_STRING ([MS-DTYP] section 2.3.8).
     * 
     * -- Explanation of message fields and variables:
     * --  NegFlg, User, UserDom - Defined in section 3.1.1.
     * --  Passwd - Password of the user.
     * --  LmChallengeResponse - The LM response to the server challenge.
     *     Computed by the client.
     * --  NTChallengeResponse - The NT response to the server challenge.
     *     Computed by the client.
     * --  ClientChallenge - The 8-byte challenge message generated by the
     *     client.
     * --  CHALLENGE_MESSAGE.ServerChallenge - The 8-byte challenge message
     *     generated by the server.
     * --  ResponseKeyNT - Temporary variable to hold the results of
     *     calling NTOWF().
     * --  ResponseKeyLM - Temporary variable to hold the results of
     *     calling LMGETKEY.
     * --  ServerName - The TargetInfo field structure of the
     *     CHALLENGE_MESSAGE payload.
     * --  KeyExchangeKey - Temporary variable to hold the results of
     *     calling KXKEY.
     * --  HiResponserversion - The 1-byte highest response version
     *     understood by the client. Currently set to 1.
     * --  Responserversion - The 1-byte response version. Currently set
     *     to 1.
     * -- Time - The 8-byte little-endian time in GMT.
     * --
     * -- Functions Used:
     * --  Z(M) - Defined in section 6.
     * 
     * 
     * Define NTOWFv2(Passwd, User, UserDom) as
     *     HMAC_MD5(MD4(UNICODE(Passwd)), ConcatenationOf( Uppercase(User),UserDom ) )
     * EndDefine
     * 
     * Define LMOWFv2(Passwd, User, UserDom) as
     *     NTOWFv2(Passwd, User, UserDom)
     * EndDefine
     * 
     * Set ResponseKeyNT to NTOWFv2(Passwd, User, UserDom)
     * Set ResponseKeyLM to LMOWFv2(Passwd, User, UserDom)
     * 
     * Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM,
     *     CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge, Time, ServerName)
     * As
     * If (User is set to "" && Passwd is set to "")
     *     -- Special case for anonymous authentication
     *     Set NtChallengeResponseLen to 0
     *     Set NtChallengeResponseMaxLen to 0
     *     Set NtChallengeResponseBufferOffset to 0
     *     Set LmChallengeResponse to Z(1)
     * Else
     *     Set temp to ConcatenationOf(Responserversion, HiResponserversion,
     *         Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
     *     Set NTProofStr to HMAC_MD5(ResponseKeyNT,
     *         ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
     *     Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
     *     Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
     *             ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
     *         ClientChallenge )
     * EndIf
     * 
     * Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
     * EndDefine
     */
    private static final ByteArray ALL_RESPONSER_VERSION = new ByteArray(new byte[]{1, 1});

    @Override
    protected void calculateNTLMResponse(ByteArray time, byte[] clientChallengeArray, ByteArray targetInfo) {
        byte[] responseKeyNT = calculateNTOWFv2();
        byte[] responseKeyLM = responseKeyNT;
        ByteArray clientChallenge = new ByteArray(clientChallengeArray);

        byte[] temp = concat(ALL_RESPONSER_VERSION, Z(6), time, clientChallenge, Z(4), targetInfo, Z(4));
        byte[] ntProofStr = calculateHmacMD5(responseKeyNT, concat(serverChallenge, temp));
        ntChallengeResponse = concat(new ByteArray(ntProofStr), temp);

	if (targetInfo == null) {
	    //
	    // Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
	    //        ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
	    //        ClientChallenge )
	    //
            lmChallengeResponse = concat(calculateHmacMD5(responseKeyLM, concat(serverChallenge, clientChallenge)),
        				 clientChallenge);
	} else {
	    // 
	    // If NTLM v2 authentication is used and the CHALLENGE_MESSAGE contains a TargetInfo field,
	    // the client SHOULD NOT send the LmChallengeResponse and SHOULD set the LmChallengeResponseLen
	    // and LmChallengeResponseMaxLen fields in the AUTHENTICATE_MESSAGE to zero. <41>
	    // 
	    lmChallengeResponse = new byte[24]; // DAS - in NTLMv2, this SHOULD BE all NULLs
	}
        sessionBaseKey = calculateHmacMD5(responseKeyNT, ntProofStr);
    }

    /**
     * 3.4.5.1 KXKEY
     * 
     * If NTLM v2 is used, the key exchange key MUST be the 128-bit session base key.
     * 
     */
    @Override
    public byte[] kxkey() {
        return sessionBaseKey;
    }

    /**
     * Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(
     *     MD4(UNICODE(Passwd)), ConcatenationOf( Uppercase(User),
     *     UserDom ) )
     * EndDefine
     * 
     * Define LMOWFv2(Passwd, User, UserDom) as NTOWFv2(Passwd, User,
     *     UserDom)
     * EndDefine
     * 
     * Set ResponseKeyNT to NTOWFv2(Passwd, User, UserDom)
     * Set ResponseKeyLM to LMOWFv2(Passwd, User, UserDom)
     */
    private byte[] calculateNTOWFv2() {
        try {
            MessageDigest md4 = createMD4();
            md4.update(toBytes(password, UNICODE_ENCODING));

            Mac hmacMD5 = createHmacMD5(md4.digest());
            hmacMD5.update(username.toUpperCase().getBytes(UNICODE_ENCODING));
            hmacMD5.update(domain.getBytes(UNICODE_ENCODING));
            return hmacMD5.doFinal();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
