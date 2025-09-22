# FAPI Demo

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
This is tested with OpenJDK 21 and Maven 3.9.9

## Start and prepare keycloak

This was tested with OpenJDK 21 and Keycloak nightly distribution (before 26.4.0 release) 

1) Copy keystore + truststore to the Keycloak distribution:
```
cp keystores/keycloak.* $KEYCLOAK_HOME/bin
```

2) Start the server 
```
cd $KEYCLOAK_HOME/bin
./kc.sh start --hostname=as.keycloak-fapi.org --https-key-store-file=keycloak.jks --https-key-store-password=secret \
--https-trust-store-file=keycloak.truststore --https-trust-store-password=secret \
--https-client-auth=request --features=dpop
```


3) Create and configure new realm

3.a) Go to `https://as.keycloak-fapi.org:8443/`, create admin account, login to admin console

3.b) Create realm `test`

3.c) Create some user with password in this realm 

3.d) Under `Clients` -> `Initial Access Tokens` create new initial access token and copy it somewhere for the
later use in the demo. For demo purposes, use bigger number of clients (EG. 99).


## Start example app and deploy the example

1) Unzip Wildlfy 33.0.1 to some directory. Will be referred as `$APP_HOME`

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

### FAPI 1 DEMO

1) Go to `https://app.keycloak-fapi.org:8543/fapi-demo` 

2) No FAPI yet

2.a) In the `Client Registration` part, you can provide Initial access token from Keycloak (See above) and register some client. Can be for example
public client (Switch `Client authentication method` can be switched to `none`)

2.b) You can click `Create Login URL` and click `Login` . After user authentication, you can be redirected back to the application.
You should see 200 from token response. No FAPI is involved yet. You can see that tokens don't have `nonce` claim in it (Tokens can be seen by click on the button `Show Last tokens`) 

3) Fapi Baseline test

3.a) In the Keycloak admin console, in the tab `Realm Settings` -> `Client Policies`, you can create create client policy with `any-client` condition and
link with the built-in `fapi-1-baseline` profile.

3.b) Now in the application, you can register new client. You can doublecheck in the Keycloak admin console, that it has `Consent Required` switched to ON
Note that you can doublecheck the client by looking at `Client_id` claim from the returned client registration response and then lookup this client by this client ID
in the Keycloak admin console `Clients` tab.

3.c) You can create login URL and login with new client. Note that to pass `fapi-1-baseline`, it is needed to check `Use Nonce param`
and `Use PKCE`. Otherwise, Keycloak won't allow login.

3.d) Authentication requires user to consent. After authentication, check that ID token has `nonce` claim (Ideally you should check that it matches with the
`nonce` sent in the initial request)

4) Fapi advanced test

4.a) Change client policy from above to use `fapi-1-advanced` instead of baseline.

4.b) Register new client. It must be checked both checkboxes `Confidential client` and `Generate client keys`

4.c) Create login URL. It must be checked with both `Use nonce` and `Use Request Object` to send stuff in signed request object.

4.d) After authentication, you can check by `Show Last Tokens` that access token has hash of it's certificate, due Keycloak used `Sender Constrained access token`
required by the specs.

### DPOP Demo

1) Create new realm `test`, create user `john` in the realm. Update timeouts (SSO Session idle to 2 hours, Access Token lifespan to 1 hour)

2) Normal client registration and login. User-info request
```
export KC_REALM=test
export KC_TOKEN=<copy token here>
curl -k -v -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Accept: application/json" -H "Authorization: Bearer $KC_TOKEN" \
  https://as.keycloak-fapi.org:8443/realms/$KC_REALM/protocol/openid-connect/userinfo
```

3) DPoP demo basic. Login. Checking DPoP proof and access-token

4) Sending user-info. Checking DPoP proof being used

4) Switch the client to have DPoP being required

5) Refresh token (including public client registration)

6) dpop_jkt showing and testing

7) Executor



## Contributions

Anyone is welcome to use this demo according with the licence and feel free to use it in your own presentations for FAPI.
Contributions are welcome (See above for potential contributions tips and also search for `TODO:` in the code :-) )

## Slides

See slides from devconf 2022 presentation in file [Keycloak FAPI slides](keycloak-fapi-devconf-2022-slides.pdf).
