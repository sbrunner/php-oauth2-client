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

namespace fkooman\OAuth\Client;

use DateTime;
use fkooman\OAuth\Client\Exception\OAuthServerException;
use fkooman\OAuth\Client\Http\Response;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

class BearerClient
{
    /** @var \fkooman\OAuth\Client\OAuth2Client */
    private $oauthClient;

    /** @var \fkooman\OAuth\Client\TokenStorageInterface */
    private $tokenStorage;

    /** @var string|null */
    private $userId;

    /** @var \Psr\Log\LoggerInterface */
    private $logger;

    /** @var DateTime */
    private $dateTime;

    public function __construct(OAuth2Client $oauthClient, TokenStorageInterface $tokenStorage, $userId = null, LoggerInterface $logger = null, DateTime $dateTime = null)
    {
        $this->oauthClient = $oauthClient;
        $this->tokenStorage = $tokenStorage;
        $this->userId = $userId;
        if (is_null($logger)) {
            $logger = new NullLogger();
        }
        $this->logger = $logger;
        if (is_null($dateTime)) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
    }

    /**
     * @var string|null
     */
    public function setUserId($userId)
    {
        $this->userId = $userId;
    }

    /**
     * @return Response|false
     */
    public function get($requestUri, array $requestHeaders = [])
    {
        // make sure we have an access token
        $accessToken = $this->tokenStorage->getAccessToken($this->userId);
        if (is_null($accessToken)) {
            $this->logger->info('no access_token available');

            return false;
        }

        $refreshedToken = false;
        if ($accessToken->isExpired($this->dateTime)) {
            $this->logger->info('access_token expired');
            // access_token is expired, try to refresh it
            if (is_null($accessToken->getRefreshToken())) {
                $this->logger->info('no refresh_token available, delete access_token');
                // we do not have a refresh_token, delete this access token, it
                // is useless now...
                $this->tokenStorage->deleteAccessToken($this->userId, $accessToken);

                return false;
            }

            $this->logger->info('attempting to refresh access_token');
            // deal with possibly revoked authorization! XXX
            try {
                $accessToken = $this->oauthClient->refreshAccessToken($accessToken);
            } catch (OAuthServerException $e) {
                $this->logger->info(sprintf('unable to use refresh_token %s', $e->getMessage()));

                // delete the access_token, the refresh_token could not be used
                $this->tokenStorage->deleteAccessToken($this->userId, $accessToken);

                return false;
            }

            // maybe delete old accesstoken here? XXX
            $this->logger->info('access_token refreshed');
            $refreshedToken = true;
        }

        // add Authorization header to the request headers
        $requestHeaders['Authorization'] = sprintf('Bearer %s', $accessToken->getToken());

        $response = $this->oauthClient->getHttpClient()->get($requestUri, $requestHeaders);
        if (401 === $response->getStatusCode()) {
            $this->logger->info('access_token appears to be invalid, delete access_token');
            // this indicates an invalid access_token
            $this->tokenStorage->deleteAccessToken($this->userId, $accessToken);

            return false;
        }

        $this->logger->info('access_token was valid, call succeeded');

        if ($refreshedToken) {
            $this->logger->info('access_token was refreshed, so store it now for future use');
            // if we refreshed the token, and it was successful, i.e. not a 401,
            // update the stored AccessToken
            $this->tokenStorage->setAccessToken($this->userId, $accessToken);
        }

        return $response;
    }

    public function post($requestUri, array $postData = [], array $requestHeaders = [])
    {
    }
}
