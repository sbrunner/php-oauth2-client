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

use DateInterval;
use DateTime;
use fkooman\OAuth\Client\Exception\OAuthException;
use fkooman\OAuth\Client\Exception\OAuthServerException;
use InvalidArgumentException;

/**
 * OAuth 2.0 Client. Helper class to make it easy to obtain an access token
 * from an OAuth 2.0 provider.
 */
class OAuth2Client
{
    /** @var Provider */
    private $provider;

    /** @var HttpClientInterface */
    private $httpClient;

    /** @var RandomInterface */
    private $random;

    /** @var \DateTime */
    private $dateTime;

    /**
     * Instantiate an OAuth 2.0 Client.
     *
     * @param Provider                 $provider   the OAuth 2.0 provider configuration
     * @param HttpClientInterface|null $httpClient the HTTP client implementation
     * @param RandomInterface|null     $random     the random implementation
     * @param DateTime|null            $dateTime   the DateTime object for the current time
     */
    public function __construct(Provider $provider, HttpClientInterface $httpClient = null, RandomInterface $random = null, DateTime $dateTime = null)
    {
        $this->provider = $provider;
        if (is_null($httpClient)) {
            $httpClient = new CurlHttpClient();
        }
        $this->httpClient = $httpClient;
        if (is_null($random)) {
            $random = new Random();
        }
        $this->random = $random;
        if (is_null($dateTime)) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
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
    public function getAuthorizationRequestUri($scope, $redirectUri)
    {
        $queryParams = http_build_query(
            [
                'client_id' => $this->provider->getId(),
                'redirect_uri' => $redirectUri,
                'scope' => $scope,
                'state' => $this->random->get(16),
                'response_type' => 'code',
            ],
            '&'
        );

        return sprintf(
            '%s%s%s',
            $this->provider->getAuthorizationEndpoint(),
            false === strpos($this->provider->getAuthorizationEndpoint(), '?') ? '?' : '&',
            $queryParams
        );
    }

    /**
     * Obtain the access token from the OAuth provider after returning from the
     * OAuth provider on the redirectUri (callback URL).
     *
     * @param string $requestUri    the original authorization
     *                              request URL as obtained by getAuthorzationRequestUri
     * @param string $responseCode  the code passed to the 'code'
     *                              query parameter on the callback URL
     * @param string $responseState the state passed to the 'state'
     *                              query parameter on the callback URL
     *
     * @return AccessToken
     */
    public function getAccessToken($requestUri, $responseCode, $responseState)
    {
        // the requestUri parameter is provided by the caller of this call, and
        // does NOT contain external input so does not need to be validated
        $requestParameters = self::parseRequestUri($requestUri);
        if ($responseState !== $requestParameters['state']) {
            // the OAuth state from the initial request MUST be the same as the
            // state used by the response
            throw new OAuthException('invalid OAuth state');
        }

        if ($requestParameters['client_id'] !== $this->provider->getId()) {
            // the client_id used for the initial request differs from the
            // currently configured Provider, the client_id MUST be identical
            throw new OAuthException('unexpected client identifier');
        }

        // prepare access_token request
        $tokenRequestData = [
            'client_id' => $this->provider->getId(),
            'grant_type' => 'authorization_code',
            'code' => $responseCode,
            'redirect_uri' => $requestParameters['redirect_uri'],
        ];

        $responseData = $this->validateTokenResponse(
            $this->httpClient->post(
                $this->provider,
                $tokenRequestData
            ),
            $requestParameters['scope']
        );

        return new AccessToken(
            $responseData['access_token'],
            $responseData['token_type'],
            $responseData['scope'],
            array_key_exists('refresh_token', $responseData) ? $responseData['refresh_token'] : null,
            $responseData['expires_at']
        );
    }

    /**
     * Refresh the access token from the OAuth.
     *
     * @param string $refreshToken the refresh token
     * @param string $requestScope the scope associated with the previously
     *                             obtained access token
     *
     * @return AccessToken
     */
    public function refreshAccessToken($refreshToken, $requestScope)
    {
        // prepare access_token request
        $tokenRequestData = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'scope' => $requestScope,
        ];

        $responseData = $this->validateTokenResponse(
            $this->httpClient->post(
                $this->provider,
                $tokenRequestData
            ),
            $requestScope
        );

        return new AccessToken(
            $responseData['access_token'],
            $responseData['token_type'],
            $responseData['scope'],
            // if a new refresh_token was provided use that, if not reuse the old one
            array_key_exists('refresh_token', $responseData) ? $responseData['refresh_token'] : $refreshToken,
            $responseData['expires_at']
        );
    }

    /**
     * Validate the provided URI to see if it has the right format, it is
     * provided by the API consumer.
     */
    private static function parseRequestUri($requestUri)
    {
        if (!is_string($requestUri)) {
            throw new InvalidArgumentException('"requestUri" MUST be string');
        }

        if (false === strpos($requestUri, '?')) {
            throw new OAuthException('"requestUri" not valid, no query string');
        }

        parse_str(explode('?', $requestUri)[1], $requestParameters);

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

    private function validateTokenResponse(array $tokenResponse, $requestScope)
    {
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

    private function calculateExpiresAt(array $tokenResponse)
    {
        $dateTime = clone $this->dateTime;
        if (array_key_exists('expires_in', $tokenResponse)) {
            return date_add($dateTime, new DateInterval(sprintf('PT%dS', $tokenResponse['expires_in'])));
        }

        // if the 'expires_in' field is not available, we default to 1 year
        return date_add($dateTime, new DateInterval('P1Y'));
    }
}
