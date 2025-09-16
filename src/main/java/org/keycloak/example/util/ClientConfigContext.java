package org.keycloak.example.util;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientConfigContext {

    private final String initialAccessToken;

    public ClientConfigContext(String initialAccessToken) {
        this.initialAccessToken = initialAccessToken;
    }

    public String getInitialAccessToken() {
        return initialAccessToken;
    }
}
