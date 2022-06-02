# devconf2022-fapi

## Under construction

If you see this, it means that this README is "under construction" and it is not yet polished.
The example will be polished in next few days and the README will be properly updated.

## Start Keycloak from FAPI

- Everything should work on Java 8 (TODO: Doublecheck)
- Checkout kc-sig-fapi

- Run this:
```
cd kc-sig-fapi
export AUTOMATE_TESTS=false
docker-compose -p keycloak-fapi -f docker-compose.yml -f docker-compose-keycloak-legacy.yml up --build
```

Go to https://as.keycloak-fapi.org/auth/admin and login as admin/admin .

## Start example app and deploy the example

- Unzip Wildlfy 23

- Add `app.keycloak-fapi.org` to `/etc/hosts`

- Start with `./standalone.sh -b app.keycloak-fapi.org -Djboss.socket.binding.port-offset=100`

- Deploy the app:
```
mvn clean install
cp target/devconf2022-fapi.war /home/mposolda/tmp/devconf2022-fapi/wildfly-23.0.2.Final/standalone/deployments/
```

- Go to 
