package org.keycloak.example.util;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientConfigContext {

    private final String initialAccessToken;
    private final String clientAuthMethod;

    public ClientConfigContext(String initialAccessToken, String clientAuthMethod) {
        this.initialAccessToken = initialAccessToken;
        this.clientAuthMethod = clientAuthMethod;
    }

    public String getInitialAccessToken() {
        return initialAccessToken;
    }

    public String getClientAuthMethod() {
        return clientAuthMethod;
    }
}
