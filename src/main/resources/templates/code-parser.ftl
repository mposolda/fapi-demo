<html>
    <head><title>FAPI demo</title>
    </head>
    <body onload="parseFragment()">

    <h2>Code Parser</h2>
    Code: <input id="code" name="code"></input>
    <button onclick="parseFragment()">Parse fragment</button>

    <script>

    function parseFragment() {
        var myurl = window.location.href;
//        console.log("url: " + myurl);
        var fragmentIndex = myurl.indexOf('#');
        var supportedParams = ['access_token', 'token_type', 'id_token', 'code', 'state', 'session_state', 'expires_in', 'kc_action_status'];
        parsed = parseCallbackParams(myurl.substring(fragmentIndex + 1), supportedParams);

        var code = parsed.oauthParams.code;
        console.log("code: " + code);
        document.getElementById('code').value = code;

        // Very dummy. Should be improved
        var newUrl = myurl.substring(0, fragmentIndex) + "?code=" + code;
        window.location.href = newUrl;
    }

        function parseCallbackParams(paramsString, supportedParams) {
            var p = paramsString.split('&');
            var result = {
                paramsString: '',
                oauthParams: {}
            }
            for (var i = 0; i < p.length; i++) {
                var split = p[i].indexOf("=");
                var key = p[i].slice(0, split);
                if (supportedParams.indexOf(key) !== -1) {
                    result.oauthParams[key] = p[i].slice(split + 1);
                } else {
                    if (result.paramsString !== '') {
                        result.paramsString += '&';
                    }
                    result.paramsString += p[i];
                }
            }
            return result;
        }

    </script>
</body>
</html>