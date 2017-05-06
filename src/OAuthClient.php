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

namespace fkooman\OAuth\Client;

use DateInterval;
use DateTime;
use fkooman\OAuth\Client\Exception\OAuthException;
use fkooman\OAuth\Client\Exception\OAuthServerException;
use fkooman\OAuth\Client\Http\HttpClientInterface;
use fkooman\OAuth\Client\Http\Request;
use fkooman\OAuth\Client\Http\Response;
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

class OAuthClient
{
    /** @var TokenStorageInterface */
    private $tokenStorage;

    /** @var \fkooman\OAuth\Client\Http\HttpClientInterface */
    private $httpClient;

    /** @var SessionInterface */
    private $session;

    /** @var RandomInterface */
    private $random;

    /** @var \Psr\Log\LoggerInterface */
    private $logger;

    /** @var \DateTime */
    private $dateTime;

    /** @var array */
    private $providerList = [];

    /** @var string */
    private $providerId = null;

    /** @var string|null */
    private $userId = null;

    /**
     * @param TokenStorageInterface    $tokenStorage
     * @param Http\HttpClientInterface $httpClient
     */
    public function __construct(TokenStorageInterface $tokenStorage, HttpClientInterface $httpClient)
    {
        $this->tokenStorage = $tokenStorage;
        $this->httpClient = $httpClient;

        $this->session = new Session();
        $this->random = new Random();
        $this->logger = new NullLogger();
        $this->dateTime = new DateTime();
    }

    /**
     * @param string   $providerId
     * @param Provider $provider
     */
    public function addProvider($providerId, Provider $provider)
    {
        $this->providerList[$providerId] = $provider;
        // the first provider we add becomes the active provider, can be
        // overridden by the "setProviderId" method
        if (1 === count($this->providerList)) {
            $this->providerId = $providerId;
        }
    }

    /**
     * @param string $providerId
     */
    public function setProviderId($providerId)
    {
        if (!array_key_exists($providerId, $this->providerList)) {
            throw new OAuthException(sprintf('provider with providerId "%s" does not exist', $this->providerId));
        }
    }

    /**
     * @param SessionInterface $session
     */
    public function setSession(SessionInterface $session)
    {
        $this->session = $session;
    }

    /**
     * @param RandomInterface $random
     */
    public function setRandom(RandomInterface $random)
    {
        $this->random = $random;
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param DateTime $dateTime
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $userId
     */
    public function setUserId($userId)
    {
        $this->userId = $userId;
    }

    /**
     * Perform a GET request.
     *
     * @param string|null $requestScope   the required scope to perform the
     *                                    request, use `null` if you want to
     *                                    request a resource without token
     * @param string      $requestUri
     * @param array       $requestHeaders
     *
     * @return Http\Response|false
     */
    public function get($requestScope, $requestUri, array $requestHeaders = [])
    {
        return $this->send($requestScope, Request::get($requestUri, $requestHeaders));
    }

    /**
     * Perform a POST request.
     *
     * @param string|null $requestScope
     * @param string      $requestUri
     * @param array       $postBody
     * @param array       $requestHeaders
     *
     * @return Http\Response|false
     */
    public function post($requestScope, $requestUri, array $postBody, array $requestHeaders = [])
    {
        return $this->send($requestScope, Request::post($requestUri, $postBody, $requestHeaders));
    }

    /**
     * Perform a HTTP request.
     *
     * @param string|null  $requestScope
     * @param Http\Request $request
     *
     * @return Response|false
     */
    public function send($requestScope, Request $request)
    {
        // if the requestScope is null, the request is sent without an OAuth
        // token, useful to use the same API to request resources that are not
        // protected
        if (is_null($requestScope)) {
            return $this->httpClient->send($request);
        }

        if (is_null($this->userId)) {
            throw new OAuthException('userId not set');
        }

        // make sure we have an access token
        if (false === $accessToken = $this->tokenStorage->getAccessToken($this->userId, $this->providerId, $requestScope)) {
            $this->logger->info(sprintf('no access_token available for user "%s" with scope "%s"', $this->userId, $requestScope));

            return false;
        }

        if ($requestScope !== $accessToken->getScope()) {
            throw new OAuthException('access_token does not have the required scope');
        }

        $refreshedToken = false;
        if ($accessToken->isExpired($this->dateTime)) {
            $this->logger->info(sprintf('access_token for user "%s" with scope "%s" expired', $this->userId, $requestScope));
            // access_token is expired, try to refresh it
            if (is_null($accessToken->getRefreshToken())) {
                $this->logger->info(sprintf('no refresh_token available in this access_token for user "%s" with scope "%s", deleting it', $this->userId, $requestScope));
                // we do not have a refresh_token, delete this access token, it
                // is useless now...
                $this->tokenStorage->deleteAccessToken($this->userId, $this->providerId, $accessToken);

                return false;
            }

            $this->logger->info(sprintf('using refresh_token to obtain new access_token for user "%s" with scope "%s"', $this->userId, $requestScope));

            try {
                // delete the old one, and use it to try to get a new one
                $this->tokenStorage->deleteAccessToken($this->userId, $this->providerId, $accessToken);
                $accessToken = $this->refreshAccessToken($accessToken);
            } catch (OAuthServerException $e) {
                $this->logger->info(sprintf('deleting access_token as refresh_token for user "%s" with scope "%s" was not accepted by the authorization server: "%s"', $this->userId, $requestScope, $e->getMessage()));

                return false;
            }
            $this->logger->info(sprintf('got a new access_token using the refresh_token for user "%s" with scope "%s"', $this->userId, $requestScope));
            $refreshedToken = true;
        }

        // add Authorization header to the request headers
        $request->setHeader('Authorization', sprintf('Bearer %s', $accessToken->getToken()));

        $response = $this->httpClient->send($request);
        if (401 === $response->getStatusCode()) {
            $this->logger->info(sprintf('deleting access_token for user "%s" with scope "%s" that was supposed to work, but did not, possibly revoked by user', $this->userId, $requestScope));
            // this indicates an invalid access_token
            $this->tokenStorage->deleteAccessToken($this->userId, $this->providerId, $accessToken);

            return false;
        }

        $this->logger->info(sprintf('access_token for use "%s" with scope "%s" successfully used', $this->userId, $requestScope));

        if ($refreshedToken) {
            $this->logger->info(sprintf('storing refreshed access_token for user "%s" with scope "%s" as it was successfully used', $this->userId, $requestScope));
            // if we refreshed the token, and it was successful, i.e. not a 401,
            // update the stored AccessToken
            $this->tokenStorage->setAccessToken($this->userId, $this->providerId, $accessToken);
        }

        return $response;
    }

    /**
     * Obtain an authorization request URL to start the authorization process
     * at the OAuth provider.
     *
     * @param string $scope       the space separated scope tokens
     * @param string $redirectUri the URL to redirect back to after coming back
     *                            from the OAuth provider (callback URL)
     *
     * @return string the authorization request URL
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.2
     */
    public function getAuthorizeUri($scope, $redirectUri)
    {
        $queryParams = http_build_query(
            [
                'client_id' => $this->getActiveProvider()->getId(),
                'redirect_uri' => $redirectUri,
                'scope' => $scope,
                'state' => $this->random->get(16),
                'response_type' => 'code',
            ],
            '&'
        );

        $authorizeUri = sprintf(
            '%s%s%s',
            $this->getActiveProvider()->getAuthorizationEndpoint(),
            false === strpos($this->getActiveProvider()->getAuthorizationEndpoint(), '?') ? '?' : '&',
            $queryParams
        );
        $this->session->set('_oauth2_session_provider_id', $this->providerId);
        $this->session->set('_oauth2_session_authorize_uri', $authorizeUri);

        return $authorizeUri;
    }

    /**
     * @param string $responseCode  the code passed to the "code"
     *                              query parameter on the callback URL
     * @param string $responseState the state passed to the "state"
     *                              query parameter on the callback URL
     */
    public function handleCallback($responseCode, $responseState)
    {
        if (is_null($this->userId)) {
            throw new OAuthException('userId not set');
        }

        // set the providerId from session, Provider *MUST* already be
        // registered at this time...
        $this->setProviderId($this->session->get('_oauth2_session_provider_id'));

        $requestParameters = self::parseRequestUri(
            $this->session->get('_oauth2_session_authorize_uri')
        );

        // delete the session, we don't want it to be used multiple times...
        $this->session->del('_oauth2_session_authorize_uri');
        $this->session->del('_oauth2_session_provider_id');

        if ($responseState !== $requestParameters['state']) {
            // the OAuth state from the initial request MUST be the same as the
            // state used by the response
            throw new OAuthException('invalid OAuth state');
        }

        if ($requestParameters['client_id'] !== $this->getActiveProvider()->getId()) {
            // the client_id used for the initial request differs from the
            // currently configured Provider, the client_id MUST be identical
            throw new OAuthException('unexpected client identifier');
        }

        // prepare access_token request
        $tokenRequestData = [
            'client_id' => $this->getActiveProvider()->getId(),
            'grant_type' => 'authorization_code',
            'code' => $responseCode,
            'redirect_uri' => $requestParameters['redirect_uri'],
        ];

        $responseData = $this->validateTokenResponse(
            $this->httpClient->send(
                Request::post(
                    $this->getActiveProvider()->getTokenEndpoint(),
                    $tokenRequestData,
                    [
                        'Authorization' => sprintf(
                            'Basic %s',
                            Base64::encode(
                                sprintf('%s:%s', $this->getActiveProvider()->getId(), $this->getActiveProvider()->getSecret())
                            )
                        ),
                    ]
                )
            ),
            $requestParameters['scope']
        );

        $this->tokenStorage->setAccessToken(
            $this->userId,
            $this->providerId,
            new AccessToken(
                $responseData['access_token'],
                $responseData['token_type'],
                $responseData['scope'],
                array_key_exists('refresh_token', $responseData) ? $responseData['refresh_token'] : null,
                $responseData['expires_at']
            )
        );
    }

    /**
     * @param AccessToken $accessToken
     *
     * @return AccessToken
     */
    private function refreshAccessToken(AccessToken $accessToken)
    {
        // prepare access_token request
        $tokenRequestData = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $accessToken->getRefreshToken(),
            'scope' => $accessToken->getScope(),
        ];

        $responseData = $this->validateTokenResponse(
            $this->httpClient->send(
                Request::post(
                    $this->getActiveProvider()->getTokenEndpoint(),
                    $tokenRequestData,
                    [
                        'Authorization' => sprintf(
                            'Basic %s',
                            Base64::encode(
                                sprintf('%s:%s', $this->getActiveProvider()->getId(), $this->getActiveProvider()->getSecret())
                            )
                        ),
                    ]
                )
            ),
            $accessToken->getScope()
        );

        return new AccessToken(
            $responseData['access_token'],
            $responseData['token_type'],
            $responseData['scope'],
            // if a new refresh_token was provided use that, if not reuse the old one
            array_key_exists('refresh_token', $responseData) ? $responseData['refresh_token'] : $accessToken->getRefreshToken(),
            $responseData['expires_at']
        );
    }

    /**
     * @param string $requestUri
     *
     * @return array
     */
    private static function parseRequestUri($requestUri)
    {
        if (!is_string($requestUri)) {
            throw new InvalidArgumentException('"requestUri" MUST be string');
        }

        if (false === $qPos = strpos($requestUri, '?')) {
            throw new OAuthException('"requestUri" not valid, no query string');
        }
        parse_str(substr($requestUri, $qPos + 1), $requestParameters);

        $requiredParameters = [
            'client_id',
            'redirect_uri',
            'scope',
            'state',
            'response_type',
        ];

        // all of the above parameters were part of the requestUri, make sure
        // they are still there...
        foreach ($requiredParameters as $requiredParameter) {
            if (!array_key_exists($requiredParameter, $requestParameters)) {
                throw new OAuthException(
                    sprintf(
                        'request URI not valid, missing required query parameter "%s"',
                        $requiredParameter
                    )
                );
            }
        }

        return $requestParameters;
    }

    /**
     * @param Http\Response $response
     * @param string        $requestScope
     *
     * @return array
     */
    private function validateTokenResponse(Response $response, $requestScope)
    {
        $tokenResponse = $response->json();
        // XXX what if not array?

        // check if an error occurred
        if (array_key_exists('error', $tokenResponse)) {
            if (array_key_exists('error_description', $tokenResponse)) {
                throw new OAuthServerException(sprintf('%s: %s', $tokenResponse['error'], $tokenResponse['error_description']));
            }

            throw new OAuthServerException($tokenResponse['error']);
        }

        $requiredParameters = [
            'access_token',
            'token_type',
        ];

        foreach ($requiredParameters as $requiredParameter) {
            if (!array_key_exists($requiredParameter, $tokenResponse)) {
                throw new OAuthException(
                    sprintf(
                        'token response not valid, missing required parameter "%s"',
                        $requiredParameter
                    )
                );
            }
        }

        if (!array_key_exists('scope', $tokenResponse)) {
            // if the token endpoint does not return a 'scope' value, the
            // specification says the requested scope was granted
            $tokenResponse['scope'] = $requestScope;
        }

        $tokenResponse['expires_at'] = $this->calculateExpiresAt($tokenResponse);

        return $tokenResponse;
    }

    /**
     * @param array $tokenResponse
     *
     * @return \DateTime
     */
    private function calculateExpiresAt(array $tokenResponse)
    {
        $dateTime = clone $this->dateTime;
        if (array_key_exists('expires_in', $tokenResponse)) {
            return date_add($dateTime, new DateInterval(sprintf('PT%dS', $tokenResponse['expires_in'])));
        }

        // if the 'expires_in' field is not available, we default to 1 year
        return date_add($dateTime, new DateInterval('P1Y'));
    }

    /**
     * Get the active OAuth provider.
     *
     * @return Provider
     */
    private function getActiveProvider()
    {
        return $this->providerList[$this->providerId];
    }
}
