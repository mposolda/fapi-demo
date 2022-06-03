# devconf2022-fapi

## FAPI Demo

This is the example application to demonstrate Keycloak FAPI 1 support. It requires to:
- Run and setup Keycloak server on your laptop
- Run Wildfly server on your laptop with this application deployed

## Warning

This application is for demonstration purposes with Keycloak integration. It is not proper implementation of FAPI relying party and
does not do all the verifications prescribed for the client application in the FAPI specifications:
- https://openid.net/specs/openid-financial-api-part-1-1_0.html#public-client
- https://openid.net/specs/openid-financial-api-part-2-1_0.html#confidential-client


## Pre-requisites

This demo assumes Keycloak running on `https://as.keycloak-fapi.org:8443` and application running on `https://app.keycloak-fapi.org:8543`.
In order to have both running on your laptop, you may need to ensure that these servers are bound to your host.

On linux, the easiest is to edit `/etc/hosts` file and add the host similar to this
```
127.0.0.1 as.keycloak-fapi.org app.keycloak-fapi.org
``` 

## Build this project

From the root of this project, run:
```
mvn clean install
```
This is tested with OpenJDK 8 and Maven 3.6.3

## Start and prepare keycloak

This was tested with OpenJDK 8 and Keycloak 18.0.0 legacy distribution based on Wildfly.
( NOTE: Contribution welcome to replace this with Keycloak + Quarkus based dist. )

1) Download Keycloak legacy (Wildfly based distribution), unzip on your laptop. Will be referred as KEYCLOAK_HOME in next steps:

2) Copy keystore + truststore to the distribution:
```
cp keystores/keycloak.* $KEYCLOAK_HOME/standalone/configuration
```

3) Configure `$KEYCLOAK_HOME/standalone/configuration/standalone.xml` for use keystore and truststore from above and logging
( NOTE: Contribution welcome to replace this with JBoss CLI)

3.a) In the logging subsystem section add this to see advanced logging from client policies:
```
<logger category="org.keycloak.services.clientpolicy">
    <level name="TRACE"/>
</logger>
```

3.b) In the elytron subsystem in `tls` -> `keystores` part add this:
```
<key-store name="httpsKS">
    <credential-reference clear-text="secret"/>
    <implementation type="JKS"/>
    <file path="keycloak.jks" relative-to="jboss.server.config.dir"/>
</key-store>
<key-store name="twoWayTS">
    <credential-reference clear-text="secret"/>
    <implementation type="JKS"/>
    <file path="keycloak.truststore" relative-to="jboss.server.config.dir"/>
</key-store>
```

3.c) In the `tls` -> `key-managers` part add this:
```
<key-manager name="httpsKM" key-store="httpsKS">
    <credential-reference clear-text="secret"/>
</key-manager>
```

3.d) Add new `trust-managers` part under `tls` element:
```
<trust-managers>
    <trust-manager name="twoWayTM" key-store="twoWayTS"/>
</trust-managers>
```

3.e) Finally under `tls` -> `server-ssl-contexts` add this:
```
<server-ssl-context name="httpsSSC" protocols="TLSv1.2" want-client-auth="true" key-manager="httpsKM" trust-manager="twoWayTM"
    cipher-suite-filter="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"/>
```

3.f In the `undertow` subsystem in the `server` element, comment the default `https-listener` and replace with this one:
```
<https-listener name="https" socket-binding="https" ssl-context="httpsSSC"/>
```

4) Run the server:
```
cd $KEYCLOAK_HOME/bin
./standalone.sh -b as.keycloak-fapi.org
```

5) Create and configure new realm

5.a) Go to `https://as.keycloak-fapi.org:8443/auth/`, create admin account, login to admin console

5.b) Create realm `test` and some user in it 

5.c) Under `Client Registration` -> `Initial Access Tokens` create new initial access token and copy it somewhere for the
later use in the demo 


## Start example app and deploy the example

1) Unzip Wildlfy 23.0.2 to some directory. Will be referred as `$APP_HOME`

2) Copy keystore and truststore:
```
cp keystores/keycloak.truststore $APP_HOME/standalone/configuration/
cp keystores/client.jks $APP_HOME/standalone/configuration/
```

3) Deploy the application:
```
cp target/fapi-demo.war $APP_HOME/standalone/deployments/
```

3) Start the wildfly server:
```
cd $APP_HOME/bin
./standalone.sh -b app.keycloak-fapi.org -Djboss.socket.binding.port-offset=100
```

## Demo

1) Go to `https://app.keycloak-fapi.org:8543/fapi-demo` 

2) No FAPI yet

2.a) In the `Client Registration` part, you can provide Initial access token from Keycloak (See above) and register some client

2.b) You can click `Create Login URL` and click `Login` . After user authentication, you can be redirected back to the application.
No FAPI is involved yet. You can see that tokens don't have `nonce` claim in it.

3) Fapi Baseline test

3.a) In the Keycloak admin console, in `Client Policies`, you can create create client policy with `any-client` condition and
link with the built-in `fapi-1-baseline` profile.

3.b) Now in the application, you can register new client. You can doublecheck in the Keycloak admin console, that it has `Consent Required` switched to ON

3.c) You can create login URL and login with new client. Note that to pass `fapi-1-baseline`, it is needed to check `Use Nonce param`
and `Use PKCE`. Otherwise, Keycloak won't allow login.

3.d) Authentication requires user to consent. After authentication, check that tokens have `nonce` claim (Ideally you should check that it matches with the
`nonce` sent in the initial request)

4) Fapi advanced test

4.a) Change client policy from above to use `fapi-1-advanced` instead of baseline.

4.b) Register new client. It must be checked both checkboxes `Confidential client` and `Generate client keys`

4.c) Create login URL. It must be checked with both `Use nonce` and `Use Request Object` to send stuff in signed request object.

4.d) After authentication, you can check by `Show Last Tokens` that access token has hash of it's certificate, due Keycloak used `Sender Constrained access token`
required by the specs.

## Contributions

Anyone is welcome to use this demo according with the licence and feel free to use it in your own presentations for FAPI.
Contributions are welcome (See above for potential contributions tips :-) )
