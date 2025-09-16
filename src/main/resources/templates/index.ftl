<html>
    <head><title>FAPI demo</title></head>
    <body>

    <h3>Server info</h3>
    Keycloak server URL: <b>${serverInfo.authServerInfo} </b><br />
    Realm name: <b>${serverInfo.realmName} </b><br />
    <br />
    <hr />


<form id="my-form" method="post" action="${url.action}">
    <h3>Client Registration</h3>

    <div>
        <table>
            <tr><td>Init token: </td><td><input id="init-token" name="init-token" value="${clientConfigCtx.initialAccessToken!}"></td></td></tr>
            <tr><td>Confidential client: </td><td><input id="confidential-client" name="confidential-client" type="checkbox"></td></td></tr>
            <tr><td>Generate client keys: </td><td><input id="jwks" name="jwks" type="checkbox"></td></td></tr>
        </table>
    </div>
    <br />
    <div>
        <button onclick="submitWithAction('wellknown-endpoint')">Show response from OIDC well-known endpoint</button>
        <button onclick="submitWithAction('register-client')">Register client</button>
        <button onclick="submitWithAction('show-registered-client')">Show last registered client</button>
    </div>

    <br />
    <hr />

    <h3>OIDC flow</h3>

    <div>
        <table>
            <tr>
                <td>Use PKCE: </td><td>
                <#if oidcConfigCtx.usePkce>
                    <input id="pkce" name="pkce" type="checkbox" checked>
                <#else>
                    <input id="pkce" name="pkce" type="checkbox">
                </#if>
                </td></td>
            </tr>
            <tr>
                <td>Use Nonce parameter: </td><td>
                <#if oidcConfigCtx.useNonce>
                    <input id="nonce" name="nonce" type="checkbox" checked>
                <#else>
                    <input id="nonce" name="nonce" type="checkbox">
                </#if>
            </td></td></tr>
            <tr>
                <td>Use Request object: </td><td>
                <#if oidcConfigCtx.useRequestObject>
                    <input id="request-object" name="request-object" type="checkbox" checked>
                <#else>
                    <input id="request-object" name="request-object" type="checkbox">
                </#if>
                </td></td>
            </tr>
            <tr>
                <td>Use DPoP: </td><td>
                <#if oidcConfigCtx.useDPoP>
                    <input id="dpop" name="dpop" type="checkbox" checked>
                <#else>
                    <input id="dpop" name="dpop" type="checkbox">
                </#if>
                </td></td>
            </tr>
        </table>
    </div>
    <br />
    <div>
    <button onclick="submitWithAction('create-login-url')">Create Login URL</button>
    <button onclick="submitWithAction('show-last-token-response')">Show Last Token Response</button>
    <button onclick="submitWithAction('show-last-tokens')">Show Last Tokens</button>
    </div>


    <input type="hidden" id="my-action" name="my-action">

</form>

<br />
<br />

<hr />

<#if info??>
    <#list info.outputs as out>
        <h3>${out.title!}</h3>
        <pre style="background-color: #ddd; border: 1px solid #ccc; padding: 10px; word-wrap: break-word; white-space: pre-wrap;" id="output">${out.content!}</pre>
        <hr />
    </#list>
</#if>

<#if authRequestUrl??>
    <a href="${authRequestUrl}">Login</a>
</#if>

<script>

    function submitWithAction(myAction) {
        document.getElementById('my-action').value = myAction;
        document.getElementById('my-form').submit();
    }

    function redirectToAccountManagement() {
        window.location.href = "${url.accountConsoleUrl}";
    }

</script>
</body>
</html>