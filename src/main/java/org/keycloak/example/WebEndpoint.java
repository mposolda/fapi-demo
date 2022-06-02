package org.keycloak.example;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.apache.http.NameValuePair;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.example.bean.AuthorizationEndpointRequestObject;
import org.keycloak.example.bean.InfoBean;
import org.keycloak.example.bean.UrlBean;
import org.keycloak.example.util.ClientRegistrationWrapper;
import org.keycloak.example.util.KeysWrapper;
import org.keycloak.example.util.MutualTLSUtils;
import org.keycloak.example.util.MyConstants;
import org.keycloak.example.util.MyException;
import org.keycloak.example.util.OAuthClient;
import org.keycloak.example.util.ReqParams;
import org.keycloak.example.util.SessionData;
import org.keycloak.example.util.UUIDUtil;
import org.keycloak.example.util.WebResponse;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Path("/")
public class WebEndpoint {

    private static final Logger log = Logger.getLogger(WebEndpoint.class);

    @Context
    private HttpHeaders headers;

    @Context
    private HttpRequest request;

    Map<String, Object> fmAttributes = new HashMap<>();

    @GET
    @Produces("text/html")
    @NoCache
    public Response getWebPage() {
        fmAttributes.put("info", new InfoBean(null, null, null, null));
        fmAttributes.put("reqParams", new ReqParams(null));
        return renderHtml();
    }

    private Response renderHtml() {
        fmAttributes.put("url", new UrlBean());
        return Services.instance().getFreeMarker().processTemplate(fmAttributes, "index.ftl");
    }


    @POST
    @Produces("text/html")
    @NoCache
    @Path("/action")
    public Response processAction() {
        MultivaluedMap<String, String> params = request.getDecodedFormParameters();
        String action = params.getFirst("my-action");
        fmAttributes.put("reqParams", new ReqParams(params));
        SessionData session = Services.instance().getSession();
        try {
            switch (action) {
                case "wellknown-endpoint":
                    OAuthClient oauthClient = Services.instance().getOauthClient();
                    WebResponse<String, OIDCConfigurationRepresentation> response = oauthClient.doWellKnownRequest(MyConstants.REALM_NAME);
                    session.setAuthServerInfo(response.getResponse());

                    try {
                        fmAttributes.put("info", new InfoBean("Sent OIDC well-known request", response.getRequest(), "OIDC well-known response", JsonSerialization.writeValueAsPrettyString(response.getResponse())));
                    } catch (IOException ioe) {
                        throw new MyException("Error when trying to deserialize OIDC well-known response to string", ioe);
                    }
                    break;

                case "register-client":
                    String initToken = params.getFirst("init-token");
                    if (initToken == null || initToken.trim().isEmpty()) {
                        throw new MyException("Init token is missing. It is required when registering client. Please obtain init token from Keycloak admin console and try again");
                    }

                    ClientRegistrationWrapper clientReg = ClientRegistrationWrapper.create();
                    clientReg.setInitToken(initToken);
                    boolean confidentialClient = params.getFirst("confidential-client") != null;
                    boolean generateJwks = params.getFirst("jwks") != null;
                    OIDCClientRepresentation oidcClient = createClientToRegister(confidentialClient, generateJwks);
                    try {
                        WebResponse<OIDCClientRepresentation, OIDCClientRepresentation> res = clientReg.registerClient(oidcClient);
                        session.setRegisteredClient(res.getResponse());

                        fmAttributes.put("info", new InfoBean("Client Registration Request", JsonSerialization.writeValueAsPrettyString(res.getRequest()),
                                "Client Registration Response", JsonSerialization.writeValueAsPrettyString(res.getResponse())));
                    } catch (IOException ioe) {
                        throw new MyException("Error when trying to deserialize OIDC client registration", ioe);
                    } finally {
                        clientReg.close();
                    }
                    break;

                case "show-registered-client":
                    OIDCClientRepresentation client = session.getRegisteredClient();
                    if (client == null) {
                        fmAttributes.put("info", new InfoBean(null,null, "No Registered client", "No client registered"));
                    } else {
                        try {
                            fmAttributes.put("info", new InfoBean(null, null, "Last Registered client", JsonSerialization.writeValueAsPrettyString(client)));
                        } catch (IOException ioe) {
                            throw new MyException("Error when trying to deserialize OIDC registered client", ioe);
                        }
                    }

                    break;
                case "create-login-url":
                    boolean pkce = params.getFirst("pkce") != null;
                    boolean nonce = params.getFirst("nonce") != null;
                    boolean requestObject = params.getFirst("request-object") != null;
                    String authRequestUrl = getAuthorizationRequestUrl(pkce, nonce, requestObject);
                    fmAttributes.put("info", new InfoBean("OIDC Authentication Request URL", authRequestUrl, null, null));
                    fmAttributes.put("authRequestUrl", authRequestUrl);
                    break;
                case "show-last-token-response":
                    OAuthClient.AccessTokenResponse tokenResp = session.getTokenResponse();
                    if (tokenResp == null) {
                        fmAttributes.put("info", new InfoBean(null,null, "No Token Response", "No token response yet. Please login first."));
                    } else {
                        try {
                            fmAttributes.put("info", new InfoBean(null, null, "Last Token Response", JsonSerialization.writeValueAsPrettyString(tokenResp)));
                        } catch (IOException ioe) {
                            throw new MyException("Error when trying to deserialize OIDC registered client", ioe);
                        }
                    }
                    break;
                case "show-last-tokens":
                    OAuthClient.AccessTokenResponse tokenRespp = session.getTokenResponse();
                    if (tokenRespp == null) {
                        fmAttributes.put("info", new InfoBean(null,null, "No Token Response", "No token response yet. Please login first."));
                    } else {
                        try {
                            IDToken idToken = new JWSInput(tokenRespp.getIdToken()).readJsonContent(IDToken.class);
                            AccessToken accessToken = new JWSInput(tokenRespp.getAccessToken()).readJsonContent(AccessToken.class);
                            fmAttributes.put("info", new InfoBean("Last ID Token", JsonSerialization.writeValueAsPrettyString(idToken),
                                    "Last Access Token", JsonSerialization.writeValueAsPrettyString(accessToken)));
                        } catch (IOException | JWSInputException ioe) {
                            throw new MyException("Error when trying to deserialize tokens from token response", ioe);
                        }
                    }
                    break;
                default:
                    throw new MyException("Illegal action");
            }
        } catch (MyException me) {
            fmAttributes.put("info", new InfoBean("Error!", "Error when performing action. See server log for details", null, null));
            log.error(me.getMessage(), me);
        }

        return renderHtml();
    }

    @GET
    @Produces("text/html")
    @NoCache
    @Path("/login-callback")
    public Response loginCallback(@QueryParam(OAuth2Constants.CODE) String code,
                                  @QueryParam(OAuth2Constants.STATE) String state,
                                  @QueryParam(OAuth2Constants.SESSION_STATE) String sessionState,
                                  @QueryParam(OAuth2Constants.ERROR) String error,
                                  @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {
        if (code == null && error == null) {
            // Fragment response mode
            fmAttributes.put("url", new UrlBean());
            return Services.instance().getFreeMarker().processTemplate(fmAttributes, "code-parser.ftl");
        }
        if (error != null) {
            fmAttributes.put("info", new InfoBean("Error!", "Error returned from Authentication response: " + error + ", Error description: " + errorDescription, null, null));
        } else {
            try {
                WebResponse<List<NameValuePair>, OAuthClient.AccessTokenResponse> tokenResponse = Services.instance().getOauthClient().doAccessTokenRequest(code, null, MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore());
                fmAttributes.put("info", new InfoBean("Token request parameters", tokenResponse.getRequest().toString(),
                        "Token response", JsonSerialization.writeValueAsPrettyString(tokenResponse.getResponse())));
                Services.instance().getSession().setTokenResponse(tokenResponse.getResponse());
            } catch (Exception me) {
                fmAttributes.put("info", new InfoBean("Error!", "Error when performing action. See server log for details", null, null));
                log.error(me.getMessage(), me);
            }
        }
        fmAttributes.put("reqParams", new ReqParams(null));
        return renderHtml();
    }


    private String getAuthorizationRequestUrl(boolean pkce, boolean nonce, boolean useRequestObject) {
        OAuthClient oauthClient = Services.instance().getOauthClient();
        SessionData session = Services.instance().getSession();
        OIDCClientRepresentation oidcClient = session.getRegisteredClient();
        if (oidcClient == null) {
            throw new MyException("Not client registered. Please register client first");
        }

        if (useRequestObject) {
            AuthorizationEndpointRequestObject requestObject = createValidRequestObjectForSecureRequestObjectExecutor(oidcClient.getClientId(), nonce);
            KeysWrapper keys = Services.instance().getSession().getKeys();
            if (keys == null) {
                throw new MyException("JWKS keys not set when generating request object. Keys need to be created during client registration");
            }
            String request = keys.getOidcRequest(requestObject, Services.instance().getSession().getRegisteredClient().getRequestObjectSigningAlg());
            oauthClient.clientId(oidcClient.getClientId());
            oauthClient.request(request);
            oauthClient.nonce(null);
            oauthClient.stateParamHardcoded(null);
            oauthClient.redirectUri(null);
            oauthClient.responseType(null);
            // oauthClient.responseMode("query");
            return oauthClient.getLoginFormUrl();
        } else {
            oauthClient.clientId(oidcClient.getClientId());
            oauthClient.responseType(OAuth2Constants.CODE);
            oauthClient.redirectUri(oidcClient.getRedirectUris().get(0));
            oauthClient.stateParamRandom();
            oauthClient.request(null);

            if (pkce) {
                String codeVerifier = UUIDUtil.generateId() + UUIDUtil.generateId();
                String codeChallenge = generateS256CodeChallenge(codeVerifier);
                oauthClient.codeChallenge(codeChallenge);
                oauthClient.codeChallengeMethod(OAuth2Constants.PKCE_METHOD_S256);
                oauthClient.codeVerifier(codeVerifier);
            } else {
                oauthClient.codeVerifier(null);
                oauthClient.codeChallenge(null);
                oauthClient.codeChallengeMethod(null);
            }

            if (nonce) {
                oauthClient.nonce(UUIDUtil.generateId());
            } else {
                oauthClient.nonce(null);
            }
            return oauthClient.getLoginFormUrl();
        }
    }

    private String generateS256CodeChallenge(String codeVerifier) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(codeVerifier.getBytes("ISO_8859_1"));
            byte[] digestBytes = md.digest();
            String codeChallenge = Base64Url.encode(digestBytes);
            return codeChallenge;
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new MyException("Error when generating code challenge for pkce", e);
        }
    }


    private OIDCClientRepresentation createClientToRegister(boolean confidentialClient, boolean generateJwks) {
        OIDCClientRepresentation client = new OIDCClientRepresentation();
        client.setClientName("my fapi client");
        UrlBean urls = new UrlBean();
        client.setClientUri(urls.getBaseUrl());
        client.setRedirectUris(Collections.singletonList(urls.getClientRedirectUri()));
        if (confidentialClient) {
            client.setTokenEndpointAuthMethod(OIDCLoginProtocol.TLS_CLIENT_AUTH);
            client.setTlsClientAuthSubjectDn(MyConstants.EXACT_CERTIFICATE_SUBJECT_DN);
            client.setResponseTypes(Arrays.asList("code", "code id_token")); // Indicates that we want fapi advanced. This should be done in a better way...
        } else {
            client.setTokenEndpointAuthMethod("none");
        }

        if (generateJwks) {
            KeysWrapper keys = new KeysWrapper();
            keys.generateKeys("PS256", true); // Hardcoded alg to be default for fapi-advanced. Should be improved...
            JSONWebKeySet jwks = keys.getJwks();
            client.setJwks(jwks);
            Services.instance().getSession().setKeys(keys);
        }
        return client;
    }

    protected AuthorizationEndpointRequestObject createValidRequestObjectForSecureRequestObjectExecutor(String clientId, boolean nonce) {
        AuthorizationEndpointRequestObject requestObject = new AuthorizationEndpointRequestObject();
        requestObject.id(UUIDUtil.generateId());
        requestObject.iat(Long.valueOf(Time.currentTime()));
        requestObject.exp(requestObject.getIat() + Long.valueOf(300));
        requestObject.nbf(requestObject.getIat());
        requestObject.setClientId(clientId);
        requestObject.setResponseType("code id_token");
        requestObject.setRedirectUriParam(new UrlBean().getClientRedirectUri());
        requestObject.setScope("openid");
        String state = UUIDUtil.generateId();
        requestObject.setState(state);
        requestObject.setMax_age(Integer.valueOf(600));
        requestObject.setOtherClaims("custom_claim_ein", "rot");
        if (Services.instance().getSession().getAuthServerInfo() == null) {
            throw new MyException("Please make sure that well-known info is executed before generating request object");
        }
        requestObject.audience(Services.instance().getSession().getAuthServerInfo().getIssuer(), "https://example.com");
        if (nonce) {
            requestObject.setNonce(UUIDUtil.generateId());
        }
        return requestObject;
    }

}
