package org.keycloak.example.util;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.example.Services;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ReqParams {

    private final MultivaluedMap<String, String> origParams;

    public ReqParams(MultivaluedMap<String, String> origParams) {
        this.origParams = origParams;
    }

    public String getInitToken() {
        return Services.instance().getSession().getInitToken();
    }


}
