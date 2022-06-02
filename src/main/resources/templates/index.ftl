<html>
    <head><title>FAPI demo</title></head>
    <body>

    <h2>Server Info</h2>

<form id="my-form" method="post" action="${url.action}">
    <div>
        <table>
            <tr><td>Init token: </td><td><input id="init-token" name="init-token" value="${reqParams.initToken!}"></td></td></tr>
            <tr><td>Confidential client: </td><td><input id="confidential-client" name="confidential-client" type="checkbox"></td></td></tr>
            <tr><td>Generate client keys: </td><td><input id="jwks" name="jwks" type="checkbox"></td></td></tr>
            <tr><td>Use PKCE: </td><td><input id="pkce" name="pkce" type="checkbox"></td></td></tr>
            <tr><td>Use Nonce parameter: </td><td><input id="nonce" name="nonce" type="checkbox"></td></td></tr>
            <tr><td>Use Request object: </td><td><input id="request-object" name="request-object" type="checkbox"></td></td></tr>
        </table>
    </div>

    <input type="hidden" id="my-action" name="my-action">

</form

<br />

<br />

<div>
    <button onclick="submitWithAction('wellknown-endpoint')">Send request to OIDC well-known endpoint</button>
    <button onclick="submitWithAction('register-client')">Register client</button>
    <button onclick="submitWithAction('show-registered-client')">Show last registered client</button>
    <button onclick="submitWithAction('create-login-url')">Create Login URL</button>
    <button onclick="submitWithAction('show-last-token-response')">Show Last Token Response</button>
    <button onclick="submitWithAction('show-last-tokens')">Show Last Tokens</button>
</div>

<hr />

<h3>${info.out1Title!}</h3>
<pre style="background-color: #ddd; border: 1px solid #ccc; padding: 10px; word-wrap: break-word; white-space: pre-wrap;" id="output">${info.out1!}</pre>

<#if authRequestUrl??>
    <a href="${authRequestUrl}">Login</a>
</#if>
<hr />

<h3>${info.out2Title!}</h3>
<pre style="background-color: #ddd; border: 1px solid #ccc; padding: 10px; word-wrap: break-word; white-space: pre-wrap;" id="events">${info.out2!}</pre>

<script>

    function submitWithAction(myAction) {
        document.getElementById('my-action').value = myAction;
        document.getElementById('my-form').submit();
    }

</script>
</body>
</html>