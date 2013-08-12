package org.microsoft.security.ntlm;

import java.security.SignatureException;

/**
 * @author <a href="http://profiles.google.com/109977706462274286343">Veritatem Quaeres</a>
 * @version $Id:$
 */
public interface NtlmSession {
    /**
     * Create a negotiate message to send to the server.
     */
    byte[] generateNegotiateMessage();

    /**
     * 3.1.5.2.1 Client Receives a CHALLENGE_MESSAGE
     */
    void processChallengeMessage(byte[] challengeMessageData);

    /**
     * Create a negotiate message to send to the server. Call after processing a challenge message.
     */
    byte[] generateAuthenticateMessage();
    
    /**
     * For connectionless sessions.
     */
    void updateSequenceNumber(int seqNum);

    /**
     * Encrypt a message that will be sent to the server. Result will be a MAC followed by the encrypted message.
     */
    byte[] seal(byte[] message);

    /**
     * Decrypt (and validate) an encrypted message received from the server.
     *
     * @throws SignatureException if the signature does not match the decrypted data
     */
    byte[] unseal(byte[] encrypted) throws SignatureException;
}
