<?php

/**
 * Copyright (c) 2016, 2017 François Kooman <fkooman@tuxed.net>.
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
require_once sprintf('%s/vendor/autoload.php', dirname(__DIR__));

use fkooman\OAuth\Client\Http\CurlHttpClient;
use fkooman\OAuth\Client\OAuthClient;
use fkooman\OAuth\Client\Provider;
use fkooman\OAuth\Client\SessionTokenStorage;

$indexUri = 'http://localhost:8081/index.php';
$resourceUri = 'http://localhost:8080/resource.php';
$callbackUri = 'http://localhost:8081/callback.php';
$requestScope = 'demo_scope';
$userId = 'foo';

// XXX we should problably use Cookie for this, and not a session as to avoid
// interfering with existing session handlers
session_start();

try {
    $client = new OAuthClient(
        new Provider(
            'demo_client',
            'demo_secret',
            'http://localhost:8080/authorize.php',
            'http://localhost:8080/token.php'
        ),
        new SessionTokenStorage(),
        new CurlHttpClient(['httpsOnly' => false])
    );

    // bind the tokens to a particular userId, this comes from your application
    // where the user is already authenticated
    $client->setUserId($userId);

    if (false === $response = $client->get($requestScope, $resourceUri)) {
        // no authorization yet for this scope, or obtaining the resource
        // failed, access_token was not accepted by the resource server and
        // refresh didn't work or was not possible. Nothing we can do but to
        // re-request authorization
        $authorizeUri = $client->getAuthorizeUri($requestScope, $callbackUri);
        $_SESSION['session'] = $authorizeUri;
        // redirect the browser to the authorization endpoint (with a 302)
        http_response_code(302);
        header(sprintf('Location: %s', $authorizeUri));
        exit(0);
    }

    // we got the resource, print the response
    echo sprintf('<pre>%s</pre>', $response);
} catch (Exception $e) {
    error_log($e->getMessage());
    echo $e->getMessage();
    exit(1);
}
