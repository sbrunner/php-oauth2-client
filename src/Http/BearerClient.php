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

namespace fkooman\OAuth\Client\Http;

use fkooman\OAuth\Client\AccessToken;
use fkooman\OAuth\Client\Exception\OAuthServerException;
use fkooman\OAuth\Client\OAuth2Client;

class BearerClient
{
    /** @var \fkooman\OAuth\Client\OAuth2Client */
    private $oauthClient;

    /** @var callable */
    private $setToken;

    /** @var callable */
    private $deleteToken;

    public function __construct(OAuth2Client $oauthClient, callable $setToken, callable $deleteToken)
    {
        $this->oauthClient = $oauthClient;
        $this->setToken = $setToken;
        $this->deleteToken = $deleteToken;
    }

    /**
     * @return Response|false
     */
    public function get(AccessToken $accessToken, $requestUri, array $requestHeaders = [])
    {
        $refreshedToken = false;
        if ($accessToken->isExpired()) {
            error_log('access_token expired');
            // access_token is expired, try to refresh it
            if (is_null($accessToken->getRefreshToken())) {
                error_log('no refresh_token available, delete access_token');
                // we do not have a refresh_token, delete this access token, it
                // is useless now...
                call_user_func($this->deleteToken, $accessToken);

                return false;
            }

            error_log('attempting to refresh access_token');
            // deal with possibly revoked authorization! XXX
            try {
                $accessToken = $this->oauthClient->refreshAccessToken($accessToken);
            } catch (OAuthServerException $e) {
                error_log(sprintf('unable to use refresh_token %s', $e->getMessage()));

                // delete the access_token, the refresh_token could not be used

                call_user_func($this->deleteToken, $accessToken);

                return false;
            }

            // maybe delete old accesstoken here? XXX
            error_log('access_token refreshed');
            $refreshedToken = true;
        }

        // add Authorization header to the request headers
        $requestHeaders['Authorization'] = sprintf('Bearer %s', $accessToken->getToken());

        $response = $this->oauthClient->getHttpClient()->get($requestUri, $requestHeaders);
        if (401 === $response->getStatusCode()) {
            error_log('access_token appears to be invalid, delete access_token');
            // this indicates an invalid access_token
            call_user_func($this->deleteToken, $accessToken);

            return false;
        }

        error_log('access_token was valid, call succeeded');

        if ($refreshedToken) {
            error_log('access_token was refreshed, so store it now for future use');
            // if we refreshed the token, and it was successful, i.e. not a 401,
            // update the stored AccessToken
            call_user_func($this->setToken, $accessToken);
        }

        return $response;
    }

    public function post(AccessToken $accessToken, $requestUri, array $postData = [], array $requestHeaders = [])
    {
    }
}
