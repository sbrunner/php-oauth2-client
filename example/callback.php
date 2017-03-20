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

use fkooman\OAuth\Client\CurlHttpClient;
use fkooman\OAuth\Client\Exception\OAuthException;
use fkooman\OAuth\Client\OAuth2Client;
use fkooman\OAuth\Client\Provider;

$indexUri = 'http://localhost:8081/index.php';

session_start();

try {
    $provider = new Provider(
        'demo_client',
        'demo_secret',
        'http://localhost:8080/authorize.php',
        'http://localhost:8080/token.php'
    );

    // we need to provide a client, because we need to disable https, if we only
    // talk to HTTPS servers there would be no need for that
    $httpClient = new CurlHttpClient();
    $httpClient->setHttpsOnly(false);

    $client = new OAuth2Client(
        $provider,
        $httpClient
    );

    $accessToken = $client->getAccessToken(
        $_SESSION['session'], // URI from session
        $_GET['code'],        // the code value (e.g. 12345)
        $_GET['state']        // the state value (e.g. abcde)
    );

    $_SESSION['access_token'] = $accessToken;

    // unset session field as to not allow additional redirects to the same
    // URI to attempt to get another access token with this code
    unset($_SESSION['session']);

    // redirect the browser back to the index (with a 302)
    http_response_code(302);
    header(sprintf('Location: %s', $indexUri));
    exit(0);
} catch (OAuthException $e) {
    echo $e->getMessage();
    exit(1);
}
