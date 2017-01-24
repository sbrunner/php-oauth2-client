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

$authorizationRequestUri = $client->getAuthorizationRequestUri(
    'demo_scope',
    'http://localhost:8081/callback.php'
);

session_start();
// store the state
$_SESSION['oauth2_session'] = $authorizationRequestUri;

// redirect the browser to the authorization endpoint (with a 302)
http_response_code(302);
header(sprintf('Location: %s', $authorizationRequestUri));
