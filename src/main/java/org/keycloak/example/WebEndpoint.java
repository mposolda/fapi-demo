package org.keycloak.example;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.example.bean.AuthorizationEndpointRequestObject;
import org.keycloak.example.bean.InfoBean;
import org.keycloak.example.bean.ServerInfoBean;
import org.keycloak.example.bean.UrlBean;
import org.keycloak.example.oauth.AccessTokenRequest;
import org.keycloak.example.oauth.AccessTokenResponse;
import org.keycloak.example.oauth.LoginUrlBuilder;
import org.keycloak.example.oauth.PkceGenerator;
import org.keycloak.example.util.ClientConfigContext;
import org.keycloak.example.util.ClientRegistrationWrapper;
import org.keycloak.example.util.KeysWrapper;
import org.keycloak.example.util.MyConstants;
import org.keycloak.example.util.MyException;
import org.keycloak.example.util.OAuthClient;
import org.keycloak.example.util.OIDCFlowConfigContext;
import org.keycloak.example.util.OIDCLoginProtocol;
import org.keycloak.example.util.SessionData;
import org.keycloak.example.util.UUIDUtil;
import org.keycloak.example.util.WebRequestContext;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
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
        fmAttributes.put("info", new InfoBean());
        return renderHtml();
    }

    private Response renderHtml() {
        fmAttributes.put("serverInfo", new ServerInfoBean());
        fmAttributes.put("url", new UrlBean());
        fmAttributes.put("clientConfigCtx", Services.instance().getSession().getClientConfigContext());
        fmAttributes.put("oidcConfigCtx", Services.instance().getSession().getOidcConfigContext());
        return Services.instance().getFreeMarker().processTemplate(fmAttributes, "index.ftl");
    }


    @POST
    @Produces("text/html")
    @NoCache
    @Path("/action")
    public Response processAction() {
        MultivaluedMap<String, String> params = request.getDecodedFormParameters();
        String action = params.getFirst("my-action");
        SessionData session = Services.instance().getSession();
        try {
            switch (action) {
                case "wellknown-endpoint":
                    OIDCConfigurationRepresentation cfg = Services.instance().getSession().getAuthServerInfo();
                    try {
                        fmAttributes.put("info", new InfoBean("OIDC well-known response", JsonSerialization.writeValueAsPrettyString(cfg)));
                    } catch (IOException ioe) {
                        throw new MyException("Error when trying to deserialize OIDC well-known response to string", ioe);
                    }
                    break;

                case "register-client":
                    ClientConfigContext clientCtx = collectClientConfigParams(params, session);
                    String initToken = clientCtx.getInitialAccessToken();
                    if (initToken == null || initToken.trim().isEmpty()) {
                        throw new MyException("Init token is missing. It is required when registering client. Please obtain init token from Keycloak admin console and try again");
                    }

                    ClientRegistrationWrapper clientReg = ClientRegistrationWrapper.create();
                    clientReg.setInitToken(initToken);
                    boolean confidentialClient = params.getFirst("confidential-client") != null;
                    boolean generateJwks = params.getFirst("jwks") != null;
                    OIDCClientRepresentation oidcClient = createClientToRegister(confidentialClient, generateJwks);
                    try {
                        WebRequestContext<OIDCClientRepresentation, OIDCClientRepresentation> res = clientReg.registerClient(oidcClient);
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
                        fmAttributes.put("info", new InfoBean("No Registered client", "No client registered"));
                    } else {
                        try {
                            fmAttributes.put("info", new InfoBean("Last Registered client", JsonSerialization.writeValueAsPrettyString(client)));
                        } catch (IOException ioe) {
                            throw new MyException("Error when trying to deserialize OIDC registered client", ioe);
                        }
                    }

                    break;
                case "create-login-url":
                    OIDCFlowConfigContext oidcFlowCtx = collectOIDCFlowConfigParams(params, session);

                    String authRequestUrl = getAuthorizationRequestUrl(oidcFlowCtx);
                    fmAttributes.put("info", new InfoBean("OIDC Authentication Request URL", authRequestUrl));
                    fmAttributes.put("authRequestUrl", authRequestUrl);
                    session.setAuthenticationRequestUrl(authRequestUrl);
                    break;
                case "process-fragment":
                    String authzResponseUrl = params.getFirst("authz-response-url");
                    int fragmentIndex = authzResponseUrl.indexOf('#');
                    if (fragmentIndex == -1) {
                        throw new MyException("Fragment did not found in the URL " + authzResponseUrl);
                    }
                    String fragment = authzResponseUrl.substring(fragmentIndex + 1);
                    Map<String, String> parsedParams = Stream.of(fragment.split("&")).collect(Collectors.toMap(
                            param -> param.substring(0, param.indexOf('=')),
                            param -> param.substring(param.indexOf('=') + 1)));
                    return handleLoginCallback(parsedParams.get(OAuth2Constants.CODE), parsedParams.get(OAuth2Constants.ERROR), parsedParams.get(OAuth2Constants.ERROR_DESCRIPTION), authzResponseUrl);
                case "show-last-token-response":
                    WebRequestContext<AccessTokenRequest, AccessTokenResponse> tokenResp = session.getTokenRequestCtx();
                    if (tokenResp == null) {
                        fmAttributes.put("info", new InfoBean("No Token Response", "No token response yet. Please login first."));
                    } else {
                        try {
                            InfoBean info = new InfoBean();
                            fmAttributes.put("info", info);

                            infoTokenRequestAndResponse(info, tokenResp.getRequest(), tokenResp.getResponse());
                        } catch (IOException ioe) {
                            throw new MyException("Error when trying to deserialize OIDC registered client", ioe);
                        }
                    }
                    break;
                case "show-last-tokens":
                    WebRequestContext<AccessTokenRequest, AccessTokenResponse> tokenRespp = session.getTokenRequestCtx();
                    if (tokenRespp == null) {
                        fmAttributes.put("info", new InfoBean("No Token Response", "No token response yet. Please login first."));
                    } else {
                        try {
                            AccessTokenResponse atr = tokenRespp.getResponse();
                            IDToken idToken = new JWSInput(atr.getIdToken()).readJsonContent(IDToken.class);
                            AccessToken accessToken = new JWSInput(atr.getAccessToken()).readJsonContent(AccessToken.class);
                            RefreshToken refreshToken = new JWSInput(atr.getRefreshToken()).readJsonContent(RefreshToken.class);
                            fmAttributes.put("info", new InfoBean(
                                    "Last ID Token", JsonSerialization.writeValueAsPrettyString(idToken),
                                    "Last Access Token", JsonSerialization.writeValueAsPrettyString(accessToken),
                                    "Last Refresh Token", JsonSerialization.writeValueAsPrettyString(refreshToken)));
                        } catch (IOException | JWSInputException ioe) {
                            throw new MyException("Error when trying to deserialize tokens from token response", ioe);
                        }
                    }
                    break;
                default:
                    throw new MyException("Illegal action");
            }
        } catch (MyException me) {
            fmAttributes.put("info", new InfoBean("Error!", "Error when performing action. See server log for details"));
            log.error(me.getMessage(), me);
        }

        return renderHtml();
    }

    private ClientConfigContext collectClientConfigParams(MultivaluedMap<String, String> params, SessionData session) {
        String initToken = params.getFirst("init-token");
        ClientConfigContext clientCtx = new ClientConfigContext(initToken);
        session.setClientConfigContext(clientCtx);
        return clientCtx;
    }

    private OIDCFlowConfigContext collectOIDCFlowConfigParams(MultivaluedMap<String, String> params, SessionData session) {
        boolean pkce = params.getFirst("pkce") != null;
        boolean nonce = params.getFirst("nonce") != null;
        boolean requestObject = params.getFirst("request-object") != null;
        boolean useDPoP = params.getFirst("dpop") != null;
        OIDCFlowConfigContext ctx = new OIDCFlowConfigContext(pkce, nonce, requestObject, useDPoP);
        session.setOidcFlowContext(ctx);
        return ctx;
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
            fmAttributes.put("serverInfo", new ServerInfoBean());
            fmAttributes.put("url", new UrlBean());
            return Services.instance().getFreeMarker().processTemplate(fmAttributes, "code-parser.ftl");
        }
        return handleLoginCallback(code, error, errorDescription, request.getUri().getRequestUri().toString());
    }

    private Response handleLoginCallback(String code, String error, String errorDescription, String origAuthzResponseUrl) {
        SessionData session = Services.instance().getSession();
        if (error != null) {
            fmAttributes.put("info", new InfoBean("OIDC Authentication request URL sent", session.getAuthenticationRequestUrl(), "Error!", "Error returned from Authentication response: " + error + ", Error description: " + errorDescription));
        } else {
            try {
                // WebResponse<List<NameValuePair>, OAuthClient.AccessTokenResponse> tokenResponse = Services.instance().getOauthClient().doAccessTokenRequest(code, null, MutualTLSUtils.newCloseableHttpClientWithDefaultKeyStoreAndTrustStore());
                AccessTokenRequest tokenRequest = Services.instance().getOauthClient().accessTokenRequest(code);

                if (session.getOidcConfigContext().isUseDPoP()) {
                    String dpopProof = session.getOrCreateDpopContext().generateDPoP(HttpMethod.POST, session.getAuthServerInfo().getTokenEndpoint(), null);
                    tokenRequest.dpopProof(dpopProof);
                }
                AccessTokenResponse tokenResponse = tokenRequest.send();

                InfoBean info = new InfoBean("Authentication request URL", session.getAuthenticationRequestUrl())
                        .addOutput("Authentication response URL", origAuthzResponseUrl);

                infoTokenRequestAndResponse(info, tokenRequest, tokenResponse);

                fmAttributes.put("info", info);
                session.setTokenRequestCtx(new WebRequestContext<>(tokenRequest, tokenResponse));
            } catch (Exception me) {
                fmAttributes.put("info", new InfoBean("Error!", "Error when performing action. See server log for details"));
                log.error(me.getMessage(), me);
            }
        }
        return renderHtml();
    }

    private void infoTokenRequestAndResponse(InfoBean info, AccessTokenRequest tokenRequest, AccessTokenResponse tokenResponse) throws IOException {
        info.addOutput("Token request", JsonSerialization.writeValueAsPrettyString(tokenRequest.getRequestInfo()))
                .addOutput("Token response", JsonSerialization.writeValueAsPrettyString(tokenResponse));
    }


    private String getAuthorizationRequestUrl(OIDCFlowConfigContext oidcFlowCtx) {
        OAuthClient oauthClient = Services.instance().getOauthClient();
        SessionData session = Services.instance().getSession();
        OIDCClientRepresentation oidcClient = session.getRegisteredClient();
        if (oidcClient == null) {
            throw new MyException("Not client registered. Please register client first");
        }

        if (oidcFlowCtx.isUseRequestObject()) {
            AuthorizationEndpointRequestObject requestObject = createValidRequestObjectForSecureRequestObjectExecutor(oidcClient.getClientId(), oidcFlowCtx.isUseNonce());
            KeysWrapper keys = Services.instance().getSession().getKeys();
            if (keys == null) {
                throw new MyException("JWKS keys not set when generating request object. Keys need to be created during client registration");
            }
            String request = keys.getOidcRequest(requestObject, Services.instance().getSession().getRegisteredClient().getRequestObjectSigningAlg());
            oauthClient.client(oidcClient.getClientId());
            return oauthClient.redirectUri(null)
                    .responseType(null)
                    .loginForm()
                        .request(request)
                        .nonce(null)
                        .state(null)
                    //.responseType(null);
            // oauthClient.responseMode("query");
                        .build();
        } else {
            LoginUrlBuilder loginUrl = oauthClient.client(oidcClient.getClientId())
                .responseType(OAuth2Constants.CODE)
                .redirectUri(oidcClient.getRedirectUris().get(0))
                    .loginForm()
                        .state(SecretGenerator.getInstance().generateSecureID())
                        .request(null);
            if (oidcFlowCtx.isUsePkce()) {
                loginUrl.codeChallenge(PkceGenerator.s256());
            } else {
                loginUrl.codeChallenge(null, null);
            }

            if (oidcFlowCtx.isUseNonce()) {
                loginUrl.nonce(SecretGenerator.getInstance().generateSecureID());
            } else {
                loginUrl.nonce(null);
            }
            return loginUrl.build();
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
        } else {
            Services.instance().getSession().setKeys(null);
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
