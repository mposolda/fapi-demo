package org.keycloak.example.util;

import javax.ws.rs.core.MultivaluedMap;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ReqParams {

    private final MultivaluedMap<String, String> origParams;

    public ReqParams(MultivaluedMap<String, String> origParams) {
        this.origParams = origParams;
    }

    public String getInitToken() {
        return origParams == null ? "" : origParams.getFirst("init-token");
    }


}
