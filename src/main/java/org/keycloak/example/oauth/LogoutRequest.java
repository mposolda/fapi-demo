package org.keycloak.example.oauth;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.keycloak.OAuth2Constants;

import java.io.IOException;

public class LogoutRequest extends AbstractHttpPostRequest<LogoutRequest, LogoutResponse> {

    private final String refreshToken;

    LogoutRequest(String refreshToken, AbstractOAuthClient<?> client) {
        super(client);
        this.refreshToken = refreshToken;
    }

    @Override
    protected String getEndpoint() {
        return client.getEndpoints().getLogout();
    }

    protected void initRequest() {
        parameter(OAuth2Constants.REFRESH_TOKEN, refreshToken);
    }

    @Override
    protected LogoutResponse toResponse(CloseableHttpResponse response) throws IOException {
        return new LogoutResponse(response);
    }

}
