package org.keycloak.example.bean;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class InfoBean {

    private final String out1Title;
    private final String out2Title;
    private final String out1;
    private final String out2;

    public InfoBean(String out1Title, String out1, String out2Title, String out2) {
        this.out1Title = out1Title;
        this.out1 = out1;
        this.out2Title = out2Title;
        this.out2 = out2;
    }

    public String getOut1Title() {
        return out1Title;
    }

    public String getOut2Title() {
        return out2Title;
    }

    public String getOut1() {
        return out1;
    }

    public String getOut2() {
        return out2;
    }
}
