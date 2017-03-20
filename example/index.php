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
use fkooman\OAuth\Client\Exception\OAuthServerException;
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

    // did it expire?
    if ($accessToken->isExpired()) {
        // expired, try to refresh it
        if (is_null($_SESSION['refresh_token'])) {
            // we do not have a refresh_token, delete access_token and try again
            unset($_SESSION['access_token']);
            http_response_code(302);
            header(sprintf('Location: %s', $indexUri));
            exit(0);
        }

        // we have a refresh token, use it!
        $accessToken = $client->refreshAccessToken($_SESSION['refresh_token'], $requestScope);

        // update the token in the session as well
        $_SESSION['access_token'] = $accessToken;

        echo '** refreshed **';
    }

    $curlChannel = curl_init();
    $curlOptions = [
        CURLOPT_URL => $resourceUri,
        CURLOPT_HEADER => 0,
        CURLOPT_HTTPHEADER => [
            sprintf('Authorization: Bearer %s', $accessToken->getToken()),
        ],
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_FOLLOWLOCATION => 0,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
    ];
    curl_setopt_array($curlChannel, $curlOptions);
    if (false === $responseData = curl_exec($curlChannel)) {
        $curlError = curl_error($curlChannel);
        throw new RuntimeException(sprintf('failure performing the HTTP request: "%s"', $curlError));
    }
    // XXX deal with invalid tokens, e.g. when the user revokes it.
    echo $responseData;
} catch (OAuthServerException $e) {
    // probably something went wrong with talking to the OAuth server, just
    // delete all tokens
    error_log($e->getMessage());
    unset($_SESSION['access_token']);
    unset($_SESSION['refresh_token']);
    http_response_code(302);
    header(sprintf('Location: %s', $indexUri));
    exit(0);
} catch (OAuthException $e) {
    // most likely client error
    error_log($e->getMessage());
    echo $e->getMessage();
    exit(1);
}
