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

use fkooman\OAuth\Client\AccessToken;
use fkooman\OAuth\Client\Http\BearerClient;
use fkooman\OAuth\Client\Http\CurlHttpClient;
use fkooman\OAuth\Client\OAuth2Client;
use fkooman\OAuth\Client\Provider;

$indexUri = 'http://localhost:8081/index.php';
$resourceUri = 'http://localhost:8080/resource.php';
$callbackUri = 'http://localhost:8081/callback.php';
$requestScope = 'demo_scope';

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

    // do we have an access_token?
    if (!array_key_exists('access_token', $_SESSION)) {
        // no: request one
        $authorizationRequestUri = $client->getAuthorizationRequestUri(
            $requestScope,
            $callbackUri
        );
        // store the request state
        $_SESSION['session'] = $authorizationRequestUri;

        // redirect the browser to the authorization endpoint (with a 302)
        http_response_code(302);
        header(sprintf('Location: %s', $authorizationRequestUri));
        exit(0);
    }

    // we have a token
    $accessToken = $_SESSION['access_token'];

    $bearerClient = new BearerClient(
        $client,
        function (AccessToken $accessToken) {
            $_SESSION['access_token'] = $accessToken;
        },
        function (AccessToken $accessToken) {
            unset($_SESSION['access_token']);
        }
    );

    if (false === $response = $bearerClient->get($accessToken, $resourceUri)) {
        http_response_code(302);
        header(sprintf('Location: %s', $indexUri));
        exit(0);
    }
    echo 'Expires (UTC): '.$accessToken->getExpiresAt()->format('Y-m-d H:i:s');
    echo sprintf('<pre>%s</pre>', $response);
} catch (Exception $e) {
    error_log($e->getMessage());
    echo $e->getMessage();
    exit(1);
}