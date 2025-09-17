package org.keycloak.example.util;

import java.security.KeyPair;

import org.jboss.logging.Logger;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.util.DPoPGenerator;
import org.keycloak.util.JWKSUtils;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DPoPContext {

    private static final Logger log = Logger.getLogger(DPoPContext.class);

    private KeyPair keyPair;
    private String lastDpopProof;

    public String getLastDpopProof() {
        return lastDpopProof;
    }

    public String generateDPoP(String httpMethod, String endpointUrl, String accessToken) {
        if (keyPair == null) {
            generateKeys();
        }
        lastDpopProof = DPoPGenerator.generateRsaSignedDPoPProof(keyPair, httpMethod, endpointUrl, accessToken);
        return lastDpopProof;
    }

    public String generateThumbprintOfLastDpopProof() {
        if (lastDpopProof == null) {
            return null;
        }

        try {
            JWK key = new JWSInput(lastDpopProof).getHeader().getKey();
            return JWKSUtils.computeThumbprint(key);
        } catch (JWSInputException jws) {
            throw new MyException("Error when computing thumbprint of last DPoP proof", jws);
        }
    }

    public void rotateKeys() {
        generateKeys();
    }

    private void generateKeys() {
        keyPair = KeyUtils.generateRsaKeyPair(2048);
        log.info("New DPoP RSA keyPair generated.");
    }
}
