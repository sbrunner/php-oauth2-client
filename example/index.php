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

use fkooman\OAuth\Client\Http\CurlHttpClient;
use fkooman\OAuth\Client\OAuth2Client;
use fkooman\OAuth\Client\Provider;
use fkooman\OAuth\Client\Random;
use fkooman\OAuth\Client\SessionTokenStorage;
use Psr\Log\NullLogger;

$indexUri = 'http://localhost:8081/index.php';
$resourceUri = 'http://localhost:8080/resource.php';
$callbackUri = 'http://localhost:8081/callback.php';
$requestScope = 'demo_scope';
$userId = 'foo';

// XXX we should problably use Cookie for this, and not a session as to avoid
// interfering with existing session handlers
session_start();

try {
    $client = new OAuth2Client(
        new Provider(
            'demo_client',
            'demo_secret',
            'http://localhost:8080/authorize.php',
            'http://localhost:8080/token.php'
        ),
        new SessionTokenStorage(),
        new CurlHttpClient(['httpsOnly' => false]),
        new Random(),
        new NullLogger(),
        new DateTime()
    );

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
