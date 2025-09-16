package org.keycloak.example.util;

import java.security.KeyPair;

import org.jboss.logging.Logger;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.util.DPoPGenerator;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DPoPContext {

    private static final Logger log = Logger.getLogger(DPoPContext.class);

    private KeyPair keyPair;
    private String lastDpopProof;

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public String getLastDpopProof() {
        return lastDpopProof;
    }

    public void setLastDpopProof(String lastDpopProof) {
        this.lastDpopProof = lastDpopProof;
    }

    public String generateDPoP(String httpMethod, String endpointUrl, String accessToken) {
        if (keyPair == null) {
            keyPair = KeyUtils.generateRsaKeyPair(2048);
            log.info("New DPoP RSA keyPair generated.");
        }
        lastDpopProof = DPoPGenerator.generateRsaSignedDPoPProof(keyPair, httpMethod, endpointUrl, accessToken);
        return lastDpopProof;
    }

    public void rotateKeys() {
        // TODO:mposolda implement...
    }
}
