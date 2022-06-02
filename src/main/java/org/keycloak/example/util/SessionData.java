package org.keycloak.example.util;

import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SessionData {

    private OIDCConfigurationRepresentation authServerInfo;

    private String initToken;

    private OIDCClientRepresentation registeredClient;

    private KeysWrapper keys;

    private OAuthClient.AccessTokenResponse tokenResponse;

    public OIDCConfigurationRepresentation getAuthServerInfo() {
        return authServerInfo;
    }

    public void setAuthServerInfo(OIDCConfigurationRepresentation authServerInfo) {
        this.authServerInfo = authServerInfo;
    }

    public String getInitToken() {
        return initToken;
    }

    public void setInitToken(String initToken) {
        this.initToken = initToken;
    }

    public OIDCClientRepresentation getRegisteredClient() {
        return registeredClient;
    }

    public void setRegisteredClient(OIDCClientRepresentation registeredClient) {
        this.registeredClient = registeredClient;
    }

    public KeysWrapper getKeys() {
        return keys;
    }

    public void setKeys(KeysWrapper keys) {
        this.keys = keys;
    }

    public OAuthClient.AccessTokenResponse getTokenResponse() {
        return tokenResponse;
    }

    public void setTokenResponse(OAuthClient.AccessTokenResponse tokenResponse) {
        this.tokenResponse = tokenResponse;
    }
}
