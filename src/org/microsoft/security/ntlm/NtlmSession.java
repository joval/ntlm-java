package org.microsoft.security.ntlm;

import java.security.SignatureException;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Id:$
 */
public interface NtlmSession {
    byte[] generateNegotiateMessage();

    /**
     * 3.1.5.2.1 Client Receives a CHALLENGE_MESSAGE
     */
    void processChallengeMessage(byte[] challengeMessageData);

    byte[] generateAuthenticateMessage();
    
    void updateSequenceNumber(int seqNum);

    byte[] sign(byte[] message);

    byte[] seal(byte[] message);

    /**
     * Unseal the specified message received from the server.
     *
     * @param message the encrypted message bytes
     * @param signature if not null, the signature against which the decrypted message will be verified
     * @throws SignatureException if the signature does not match the decrypted data
     */
    byte[] unseal(byte[] message, byte[] signature) throws SignatureException;

    /**
     * Determine the signature for a message that will be sent to the server.
     */
    byte[] calculateMac(byte[] message);
}
