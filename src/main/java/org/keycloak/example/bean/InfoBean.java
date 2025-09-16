package org.keycloak.example.bean;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class InfoBean {

    // Key is title, value is text-area
    private final List<Out> outs = new ArrayList<>();

    public InfoBean(String... infos) {
        for (int i = 0 ; i < infos.length ; i = i+2) {
            String key = infos[i];
            String value = infos[i + 1];
            outs.add(new Out(key, value));
        }
    }

    public List<Out> getOuts() {
        return outs;
    }

    public static class Out {

        private final String title;
        private final String content;

        public Out(String title, String textArea) {
            this.title = title;
            this.content = textArea;
        }

        public String getTitle() {
            return title;
        }

        public String getContent() {
            return content;
        }
    }
}
