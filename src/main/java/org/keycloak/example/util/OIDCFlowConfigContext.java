package org.keycloak.example.util;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OIDCFlowConfigContext {

    private final boolean usePkce;
    private final boolean useNonce;
    private final boolean useRequestObject;
    private final boolean useDPoP;

    public OIDCFlowConfigContext(boolean usePkce, boolean useNonce, boolean useRequestObject, boolean useDPoP) {
        this.usePkce = usePkce;
        this.useNonce = useNonce;
        this.useRequestObject = useRequestObject;
        this.useDPoP = useDPoP;
    }


    public boolean usePkce() {
        return usePkce;
    }

    public boolean useNonce() {
        return useNonce;
    }

    public boolean useRequestObject() {
        return useRequestObject;
    }

    public boolean useDPoP() {
        return useDPoP;
    }
}
