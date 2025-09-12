package org.keycloak.example.oauth;

import org.apache.http.client.methods.CloseableHttpResponse;

import java.io.IOException;

public class OpenIDProviderConfigurationRequest extends AbstractHttpGetRequest<OpenIDProviderConfigurationResponse> {

    public OpenIDProviderConfigurationRequest(AbstractOAuthClient<?> client) {
        super(client);
    }

    @Override
    protected String getEndpoint() {
        return client.getEndpoints().getOpenIDConfiguration();
    }

    @Override
    protected void initRequest() {
    }

    @Override
    protected OpenIDProviderConfigurationResponse toResponse(CloseableHttpResponse response) throws IOException {
        return new OpenIDProviderConfigurationResponse(response);
    }

}
