package org.keycloak.example;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.jboss.resteasy.annotations.cache.NoCache;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Path("jwks")
public class JWKSEndpoint {

    @GET
    @Produces("application/json")
    @NoCache
    public List<String> getProducts() {
        ArrayList<String> rtn = new ArrayList<String>();
        rtn.add("iphone");
        rtn.add("ipad");
        rtn.add("ipod");
        return rtn;
    }
}
