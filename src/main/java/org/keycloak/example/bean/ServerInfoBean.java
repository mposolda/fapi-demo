package org.keycloak.example.bean;

import org.keycloak.example.Services;
import org.keycloak.example.util.MyConstants;

/**
 * TODO: Configurable in the app...
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ServerInfoBean {

    public String getAuthServerInfo() {
        return Services.instance().getOauthClient().AUTH_SERVER_ROOT;
    }

    public String getRealmName() {
        return MyConstants.REALM_NAME;
    }
}
