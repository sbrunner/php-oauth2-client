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
$userId = 'foo';

if ('' === session_id()) {
    session_start();
}

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

    $client->handleCallback(
        $_SESSION['session'], // URI from session
        $_GET['code'],        // the code value (e.g. 12345)
        $_GET['state']        // the state value (e.g. abcde)
    );

    // unset session field as to not allow additional redirects to the same
    // URI to attempt to get another access token with this code
    unset($_SESSION['session']);

    // redirect the browser back to the index (with a 302)
    http_response_code(302);
    header(sprintf('Location: %s', $indexUri));
    exit(0);
} catch (Exception $e) {
    echo $e->getMessage();
    exit(1);
}
