package org.keycloak.example.util;

import org.keycloak.example.Services;
import org.keycloak.example.oauth.AccessTokenRequest;
import org.keycloak.example.oauth.AccessTokenResponse;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SessionData {

    private String initToken;

    private OIDCClientRepresentation registeredClient;

    private KeysWrapper keys;

    private String authenticationRequestUrl;

    private WebRequestContext<AccessTokenRequest, AccessTokenResponse> tokenRequestCtx;

    public OIDCConfigurationRepresentation getAuthServerInfo() {
        return Services.instance().getOauthClient().
                realm(MyConstants.REALM_NAME)
                .doWellKnownRequest();
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

    public String getAuthenticationRequestUrl() {
        return authenticationRequestUrl;
    }

    public void setAuthenticationRequestUrl(String authenticationRequestUrl) {
        this.authenticationRequestUrl = authenticationRequestUrl;
    }

    public WebRequestContext<AccessTokenRequest, AccessTokenResponse> getTokenRequestCtx() {
        return tokenRequestCtx;
    }

    public void setTokenRequestCtx(WebRequestContext<AccessTokenRequest, AccessTokenResponse> tokenRequestCtx) {
        this.tokenRequestCtx = tokenRequestCtx;
    }
}
