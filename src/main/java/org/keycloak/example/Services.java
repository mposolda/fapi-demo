package org.keycloak.example;

import org.keycloak.example.util.FreeMarkerUtil;
import org.keycloak.example.util.MyConstants;
import org.keycloak.example.util.OAuthClient;
import org.keycloak.example.util.SessionData;
import org.keycloak.example.util.WebResponse;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

/**
 * Application-scoped stuff
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class Services {

    private static final Services instance = new Services();
    private Services() {
    }



    public static Services instance() {
        return instance;
    }

    private final FreeMarkerUtil freeMarker = new FreeMarkerUtil();
    private volatile OAuthClient oauthClient;

    private final SessionData session = new SessionData(); // TODO:mposolda make sure that this is really session data and not app-scoped stuff


    public FreeMarkerUtil getFreeMarker() {
        return freeMarker;
    }

    public OAuthClient getOauthClient() {
        if (oauthClient == null) {
            synchronized (this) {
                oauthClient = new OAuthClient();
                oauthClient.init();
                WebResponse<String, OIDCConfigurationRepresentation> response = oauthClient.doWellKnownRequest(MyConstants.REALM_NAME);
                session.setAuthServerInfo(response.getResponse());
            }
        }
        return oauthClient;
    }

    public SessionData getSession() {
        return session;
    }

//    public void setSession(SessionData session) {
//        this.session = session;
//    }
}
