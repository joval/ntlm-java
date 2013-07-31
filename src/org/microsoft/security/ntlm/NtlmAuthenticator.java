/*
 * $Id: $
 */
package org.microsoft.security.ntlm;

import org.microsoft.security.ntlm.impl.Algorithms;
import org.microsoft.security.ntlm.impl.NtlmV1Session;
import org.microsoft.security.ntlm.impl.NtlmV2Session;

import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_128_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_56_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_ALWAYS_SIGN_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_DATAGRAM_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_IDENTIFY_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_NTLM_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_SIGN_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_SEAL_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_TARGET_INFO_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_UNICODE_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_NEGOTIATE_VERSION_FLAG;
import static org.microsoft.security.ntlm.impl.NtlmRoutines.NTLMSSP_REQUEST_TARGET_FLAG;

/**
 *
 *
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Revision: $
 */
public class NtlmAuthenticator {

    private static final WindowsVersion DEFAULT_WINDOWS_VERSION = WindowsVersion.Windows7;

    /**
     * 3.1.1.1 Variables Internal to the Protocol
     * 
     * 
     * ExportedSessionKey: A 128-bit (16-byte) session key used to derive ClientSigningKey,
     * ClientSealingKey, ServerSealingKey, and ServerSigningKey.
     * 
     * NegFlg: The set of configuration flags (section 2.2.2.5) that specifies the negotiated capabilities of
     * the client and server for the current NTLM session.
     * 
     * User: A string that indicates the name of the user.
     * 
     * UserDom: A string that indicates the name of the user's domain.
     * 
     * 
     * The following NTLM configuration variables are internal to the client and impact all authenticated
     * sessions:
     * 
     * NoLMResponseNTLMv1: A Boolean setting that controls using the NTLM response for the LM
     * response to the server challenge when NTLMv1 authentication is used.<30>
     * <30> Section 3.1.1.1: The default value of this state variable is TRUE. Windows NT Server 4.0 SP3
     * does not support providing NTLM instead of LM responses.
     * 
     * 
     * ClientBlocked: A Boolean setting that disables the client from sending NTLM_AUTHENTICATE
     * messages. <31>
     * <31> Section 3.1.1.1: The default value of this state variable is FALSE. ClientBlocked is not
     * supported in Windows NT, Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and
     * Windows Server 2008.
     * 
     * 
     * ClientBlockExceptions: A list of server names that can use NTLM authentication. <32>
     * <32> Section 3.1.1.1: The default value of this state variable is NULL. ClientBlockExceptions is not
     * supported in Windows NT, Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and
     * Windows Server 2008.
     * 
     * 
     * ClientRequire128bitEncryption: A Boolean setting that requires the client to use 128-bit
     * encryption. <33>
     *    <33> Section 3.1.1.1: In Windows NT, Windows 2000, Windows XP, Windows Server 2003,
     * Windows Vista, and Windows Server 2008 this variable is set to FALSE. In Windows 7 and Windows
     * Server 2008 R2, this variable is set to TRUE.
     * 
     * 
     * The following variables are internal to the client and are maintained for the entire length of the
     * authenticated session:
     * 
     * MaxLifetime: An integer that indicates the maximum lifetime for challenge/response pairs. <34>
     * <34> Section 3.1.1.1: In Windows NT 4.0 and Windows 2000, the maximum lifetime for the
     * challenge is 30 minutes. In Windows XP, Windows Server 2003, Windows Vista, Windows
     * Server 2008, Windows 7, and Windows Server 2008 R2, the maximum lifetime is 36 hours.
     * 
     * ClientSigningKey: The signing key used by the client to sign messages and used by the server to
     * verify signed client messages. It is generated after the client is authenticated by the server and is
     * not passed over the wire.
     * 
     * ClientSealingKey: The sealing key used by the client to seal messages and used by the server to
     * unseal client messages. It is generated after the client is authenticated by the server and is not
     * passed over the wire.
     * 
     * SeqNum: A 4-byte sequence number (section 3.4.4).
     * 
     * ServerSealingKey: The sealing key used by the server to seal messages and used by the client to
     * unseal server messages. It is generated after the client is authenticated by the server and is not
     * passed over the wire.
     * ServerSigningKey: The signing key used by the server to sign messages and used by the client to
     * verify signed server messages. It is generated after the client is authenticated by the server and is
     * not passed over the wire.
     */

    /**
     * Minimum set of common features we need to work.
     * we operate in NTLMv2 mode
     */
    private static final int NEGOTIATE_FLAGS_COMMON_MIN =
	( NTLMSSP_NEGOTIATE_UNICODE_FLAG |
	  NTLMSSP_NEGOTIATE_NTLM_FLAG |
	  NTLMSSP_NEGOTIATE_ALWAYS_SIGN_FLAG |
	  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG |
	  NTLMSSP_NEGOTIATE_TARGET_INFO_FLAG
	);

    /**
     * Negotiate flags for connection-based mode. Nice to have but optional.
     */
    public static final int NEGOTIATE_FLAGS_CONN =
	( NEGOTIATE_FLAGS_COMMON_MIN |
	  NTLMSSP_NEGOTIATE_VERSION_FLAG |
	  NTLMSSP_NEGOTIATE_128_FLAG |
	  NTLMSSP_NEGOTIATE_56_FLAG |
	  NTLMSSP_REQUEST_TARGET_FLAG
	);

    /**
     * Extra negotiate flags required in connectionless NTLM
     */
    private static final int NEGOTIATE_FLAGS_CONNLESS_EXTRA =
	( NTLMSSP_NEGOTIATE_SIGN_FLAG |
	  NTLMSSP_NEGOTIATE_DATAGRAM_FLAG |
	  NTLMSSP_NEGOTIATE_IDENTIFY_FLAG |
	  NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG
	);

    /**
     * Negotiate flags required in connectionless NTLM
     */
    public static final int NEGOTIATE_FLAGS_CONNLESS =
	( NEGOTIATE_FLAGS_CONN |
	  NEGOTIATE_FLAGS_CONNLESS_EXTRA
	);

    /**
     * 3.1.1.2 Variables Exposed to the Application
     * The following parameters are provided by the application to the NTLM client. These logical
     * parameters can influence various protocol-defined flags.<35>
     * 
     * Note The following variables are logical, abstract parameters that an implementation MUST
     * maintain and expose to provide the proper level of service. How these variables are maintained and
     * exposed is up to the implementation.
     * 
     * Integrity: A Boolean setting which indicates that the caller wants to sign messages so that they
     * cannot be tampered with while in transit. Setting this flag results in the NTLMSSP_NEGOTIATE_SIGN
     * flag being set in the NegotiateFlags field of the NTLM NEGOTIATE_MESSAGE.
     * 
     * Replay Detect: A Boolean setting which indicates that the caller wants to sign messages so that
     * they cannot be replayed. Setting this flag results in the NTLMSSP_NEGOTIATE_SIGN flag being set
     * in the NegotiateFlags field of the NTLM NEGOTIATE_MESSAGE.
     * 
     * Sequence Detect: A Boolean setting which indicates that the caller wants to sign messages so
     * that they cannot be sent out of order. Setting this flag results in the NTLMSSP_NEGOTIATE_SIGN
     * flag being set in the NegotiateFlags field of the NTLM NEGOTIATE_MESSAGE.
     * 
     * Confidentiality: A Boolean setting which indicates that the caller wants to encrypt messages so
     * that they cannot be read while in transit. If the Confidentiality option is selected by the client, NTLM
     * performs a bitwise OR operation with the following NTLM Negotiate Flags into the
     * ClientConfigFlags. (The ClientConfigFlags indicate which features the client host supports.)
     * NTLMSSP_NEGOTIATE_SEAL
     * NTLMSSP_NEGOTIATE_KEY_EXCH
     * NTLMSSP_NEGOTIATE_LM_KEY
     * NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
     * 
     * Datagram: A Boolean setting which indicates that the connectionless mode of NTLM is to be
     * selected. If the Datagram option is selected by the client, then connectionless mode is used and
     * NTLM performs a bitwise OR operation with the following NTLM Negotiate Flag into the
     * ClientConfigFlags.
     * 
     * Identify: A Boolean setting which indicates that the caller wants the server to know the identity of
     * the caller, but that the server not be allowed to impersonate the caller to resources on that system.
     * Setting this flag results in the NTLMSSP_NEGOTIATE_IDENTIFY flag being set. Indicates that the
     * GSS_C_IDENTIFY_FLAG flag was set in the GSS_Init_sec_context call, as discussed in [RFC4757]
     * section 7.1, and results in the GSS_C_IDENTIFY_FLAG flag set in the authenticator's checksum
     * field ([RFC4757] section 7.1).
     * 
     * 
     * 
     * The following variables are used by applications for channel binding token support:
     * 
     * ClientSuppliedTargetName: Service principal name (SPN) of the service that the client wishes to
     * authenticate to. This value is optional. <36>
     * <36> Section 3.1.1.2: ClientSuppliedTargetName is not supported in Windows NT,
     * Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008.
     * 
     * 
     * ClientChannelBindingsUnhashed: An octet string provided by the application used for channel
     * binding. This value is optional. <37>
     * <37> Section 3.1.1.2: ClientChannelBindingsUnhashed is not supported in Windows NT,
     * Windows 2000, Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008.
     * 
     */
    public static NtlmSession createSession(NtlmVersion version, ConnectionType type, boolean seal,
		String workstation, String domain, String username, char[] password) {

	/**
	 * ClientConfigFlags: The set of client configuration flags (section 2.2.2.5) that specify the full set of
	 * capabilities of the client.
	 */
	int flags;

	switch(type) {
	  case connectionless:
	    flags = NEGOTIATE_FLAGS_CONNLESS;
	    break;
	  default:
	    flags = NEGOTIATE_FLAGS_CONN;
	    break;
	}

	if (seal) {
	    flags |= NTLMSSP_NEGOTIATE_SEAL_FLAG;
	}

	switch (version) {
	  case ntlmv1:
	    return new NtlmV1Session(type, flags, DEFAULT_WINDOWS_VERSION, workstation, domain, username, password);

	  case ntlmv2:
	    return new NtlmV2Session(type, flags, DEFAULT_WINDOWS_VERSION, workstation, domain, username, password);

	  default:
	    throw new RuntimeException("Internal error. Unsupported NTLM version");
	}
    }

    public enum ConnectionType {
	connectionOriented, connectionless
    }

    /**
     * How NTLM version is detected: http://davenport.sourceforge.net/ntlm.html#ntlmVersion2
     * Also NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is used to negotiate
     */
    public enum NtlmVersion {
	ntlmv1, ntlmv2
    }

    public enum WindowsVersion {
	WindowsXp("0501280A0000000F"),
	WindowsVista("060072170000000F"),
	Windows7("0601B11D0000000F");

	public final byte[] data;

	WindowsVersion(String data) {
	    this.data = Algorithms.stringToBytes(data);
	}
    }
}
