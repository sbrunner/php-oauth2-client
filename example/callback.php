<?php
/**
 *  Copyright (C) 2017 François Kooman <fkooman@tuxed.net>.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
require_once sprintf('%s/vendor/autoload.php', dirname(__DIR__));

$provider = new \fkooman\OAuth\Client\Provider(
    'demo_client',
    'demo_secret',
    'http://localhost:8080/authorize.php',
    'http://localhost:8080/token.php'
);

$curlHttpClient = new \fkooman\OAuth\Client\CurlHttpClient();
$curlHttpClient->setHttpsOnly(false);
$client = new \fkooman\OAuth\Client\OAuth2Client(
    $provider,
    $curlHttpClient
);

session_start();

try {
    $accessToken = $client->getAccessToken(
        $_SESSION['oauth2_session'], // URI from session
        $_GET['code'],               // the code value (e.g. 12345)
        $_GET['state']               // the state value (e.g. abcde)
    );

    // get the access token value
    echo $accessToken->getToken().'<br>';
    // get the token type, usually "bearer"
    echo $accessToken->getTokenType().'<br>';
    // get the time in which the token will expire, null if not provided
    echo $accessToken->getExpiresAt()->format('Y-m-d H:i:s').'<br>';
    // get the obtained scope, null if not provided
    echo $accessToken->getScope().'<br>';
} catch (\fkooman\OAuth\Client\Exception\OAuthException $e) {
    echo $e->getMessage();
}

// unset session field as to not allow additional redirects to the same
// URI to attempt to get another access token with this code
//unset($_SESSION['oauth2_session']);
