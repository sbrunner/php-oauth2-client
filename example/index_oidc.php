<?php

/*
 * Copyright (c) 2017, 2018 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

require_once \dirname(__DIR__).'/vendor/autoload.php';
$baseDir = \dirname(__DIR__);

use fkooman\OAuth\Client\ErrorLogger;
use fkooman\OAuth\Client\Exception\TokenException;
use fkooman\OAuth\Client\Http\CurlHttpClient;
use fkooman\OAuth\Client\OAuthClient;
use fkooman\OAuth\Client\Provider;
use fkooman\OAuth\Client\SessionTokenStorage;

$requestScope = 'openid';

// absolute link to callback.php in this directory
$callbackUri = 'http://localhost:8081/callback.php';

try {
    // we assume your application has proper (SECURE!) session handling
    if (PHP_SESSION_ACTIVE !== \session_status()) {
        \session_start();
    }

    $client = new OAuthClient(
        // for DEMO purposes we store the AccessToken in the user session
        // data...
        new SessionTokenStorage(),
        // for DEMO purposes we also allow connecting to HTTP URLs, do **NOT**
        // do this in production
        new CurlHttpClient(['allowHttp' => true], new ErrorLogger())
    );

    $provider = new Provider(
        'demo_client',                          // client_id
        'demo_secret',                          // client_secret
        'http://localhost:8080/authorize.php',  // authorization_uri
        'http://localhost:8080/token.php'       // token_uri
    );
    // OpenID parameters
    $provider->setIssuer('http://localhost:8080');

    if (false === $idToken = $client->getIdToken($provider)) {
        // we don't know the user, so we MUST request authorization/authentication
        \http_response_code(302);
        \header(
            \sprintf(
                'Location: %s',
                $client->getAuthorizeUri($provider, null, $requestScope, $callbackUri)
            )
        );
        exit(0);
    }

    echo \sprintf('<pre>%s</pre>', \var_export($idToken, true));
} catch (TokenException $e) {
    // there was a problem using a refresh_token to obtain a new access_token
    // outside the accepted responses according to the OAuth specification,
    // show response to ease debugging... (this does NOT happen in normal
    // circumstances)
    echo \sprintf('%s: %s', \get_class($e), $e->getMessage());
    echo \var_export($e->getResponse(), true);
} catch (Exception $e) {
    echo \sprintf('%s: %s', \get_class($e), $e->getMessage());
}
