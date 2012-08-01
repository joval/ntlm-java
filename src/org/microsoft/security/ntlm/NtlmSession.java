package org.microsoft.security.ntlm;

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
    byte[] calculateMac(byte[] message);
}
