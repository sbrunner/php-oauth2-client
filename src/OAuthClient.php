<?php

/*
 * Copyright (c) 2017, 2018 François Kooman <fkooman@tuxed.net>
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

use DateTime;
use fkooman\Jwt\RS256;
use fkooman\OAuth\Client\Exception\AuthorizeException;
use fkooman\OAuth\Client\Exception\IdTokenException;
use fkooman\OAuth\Client\Exception\OAuthException;
use fkooman\OAuth\Client\Exception\TokenException;
use fkooman\OAuth\Client\Http\HttpClientInterface;
use fkooman\OAuth\Client\Http\Request;
use fkooman\OAuth\Client\Http\Response;
use ParagonIE\ConstantTime\Base64;

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

    /** @var \DateTime */
    private $dateTime;

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
        $this->dateTime = new DateTime();
    }

    /**
     * @param SessionInterface $session
     *
     * @return void
     */
    public function setSession(SessionInterface $session)
    {
        $this->session = $session;
    }

    /**
     * @param RandomInterface $random
     *
     * @return void
     */
    public function setRandom(RandomInterface $random)
    {
        $this->random = $random;
    }

    /**
     * @param \DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * Perform a GET request, convenience wrapper for ::send().
     *
     * @param Provider $provider
     * @param string   $userId
     * @param string   $requestScope
     * @param string   $requestUri
     * @param array    $requestHeaders
     *
     * @return false|Http\Response
     */
    public function get(Provider $provider, $userId, $requestScope, $requestUri, array $requestHeaders = [])
    {
        return $this->send($provider, $userId, $requestScope, Request::get($requestUri, $requestHeaders));
    }

    /**
     * Perform a POST request, convenience wrapper for ::send().
     *
     * @param Provider $provider
     * @param string   $userId
     * @param string   $requestScope
     * @param string   $requestUri
     * @param array    $postBody
     * @param array    $requestHeaders
     *
     * @return false|Http\Response
     */
    public function post(Provider $provider, $userId, $requestScope, $requestUri, array $postBody, array $requestHeaders = [])
    {
        return $this->send($provider, $userId, $requestScope, Request::post($requestUri, $postBody, $requestHeaders));
    }

    /**
     * Perform a HTTP request.
     *
     * @param Provider     $provider
     * @param string       $userId
     * @param string       $requestScope
     * @param Http\Request $request
     *
     * @return false|Http\Response
     */
    public function send(Provider $provider, $userId, $requestScope, Request $request)
    {
        $accessToken = $this->getAccessToken($provider, $userId, $requestScope);
        if (false === $accessToken) {
            return false;
        }

        if ($accessToken->isExpired($this->dateTime)) {
            // access_token is expired, try to refresh it
            if (null === $accessToken->getRefreshToken()) {
                // we do not have a refresh_token, delete this access token, it
                // is useless now...
                $this->tokenStorage->deleteAccessToken($userId, $accessToken);

                return false;
            }

            // try to refresh the AccessToken
            $accessToken = $this->refreshAccessToken($provider, $userId, $accessToken);
            if (false === $accessToken) {
                // didn't work
                return false;
            }
        }

        // add Authorization header to the request headers
        $request->setHeader('Authorization', \sprintf('Bearer %s', $accessToken->getToken()));

        $response = $this->httpClient->send($request);
        if (401 === $response->getStatusCode()) {
            // the access_token was not accepted, but isn't expired, we assume
            // the user revoked it, also no need to try with refresh_token
            $this->tokenStorage->deleteAccessToken($userId, $accessToken);

            return false;
        }

        return $response;
    }

    /**
     * Obtain an authorization request URL to start the authorization process
     * at the OAuth provider.
     *
     * @param Provider    $provider
     * @param null|string $userId
     * @param string      $scope       the space separated scope tokens
     * @param string      $redirectUri the URL registered at the OAuth provider, to
     *                                 be redirected back to
     *
     * @return string the authorization request URL
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.2
     */
    public function getAuthorizeUri(Provider $provider, $userId, $scope, $redirectUri)
    {
        $queryParameters = [
            'client_id' => $provider->getClientId(),
            'redirect_uri' => $redirectUri,
            'scope' => $scope,
            'state' => $this->random->getHex(16),
            'response_type' => 'code',
        ];

        $authorizeUri = \sprintf(
            '%s%s%s',
            $provider->getAuthorizationEndpoint(),
            false === \strpos($provider->getAuthorizationEndpoint(), '?') ? '?' : '&',
            \http_build_query($queryParameters, '&')
        );
        $this->session->set(
            '_oauth2_session',
            \array_merge(
                $queryParameters,
                [
                    'user_id' => $userId,
                    'provider_id' => $provider->getProviderId(),
                ]
            )
        );

        return $authorizeUri;
    }

    /**
     * @param Provider    $provider
     * @param null|string $userId
     * @param array       $getData
     *
     * @return void
     */
    public function handleCallback(Provider $provider, $userId, array $getData)
    {
        if (\array_key_exists('error', $getData)) {
            // remove the session
            $this->session->take('_oauth2_session');

            throw new AuthorizeException(
                $getData['error'],
                \array_key_exists('error_description', $getData) ? $getData['error_description'] : null
            );
        }

        if (false === \array_key_exists('code', $getData)) {
            throw new OAuthException(
                'missing "code" query parameter from server response'
            );
        }

        if (false === \array_key_exists('state', $getData)) {
            throw new OAuthException(
                'missing "state" query parameter from server response'
            );
        }

        $this->doHandleCallback($provider, $userId, $getData['code'], $getData['state']);
    }

    /**
     * @param Provider $provider
     *
     * @return false|IdToken
     */
    public function getIdToken(Provider $provider)
    {
        if (!$this->session->has('_oauth2_id_token')) {
            return false;
        }

        /** @var IdToken */
        $idToken = $this->session->get('_oauth2_id_token');
        if ($idToken->getIss() !== $provider->getIssuer()) {
            // id_token did not come from the expected provider
            return false;
        }

        // XXX should we invalidate/remove the idToken after giving it back once?
        return $idToken;
    }

    /**
     * @param Provider    $provider
     * @param null|string $userId
     * @param string      $responseCode  the code passed to the "code" query parameter on the callback URL
     * @param string      $responseState the state passed to the "state" query parameter on the callback URL
     *
     * @return void
     */
    private function doHandleCallback(Provider $provider, $userId, $responseCode, $responseState)
    {
        // get and delete the OAuth session information
        $sessionData = $this->session->take('_oauth2_session');

        if (false === \hash_equals($sessionData['state'], $responseState)) {
            // the OAuth state from the initial request MUST be the same as the
            // state used by the response
            throw new OAuthException('invalid session (state)');
        }

        // session providerId MUST match current set Provider
        if ($sessionData['provider_id'] !== $provider->getProviderId()) {
            throw new OAuthException('invalid session (provider_id)');
        }

        // session userId MUST match current set userId
        if ($sessionData['user_id'] !== $userId) {
            throw new OAuthException('invalid session (user_id)');
        }

        // prepare access_token request
        $tokenRequestData = [
            'client_id' => $provider->getClientId(),
            'grant_type' => 'authorization_code',
            'code' => $responseCode,
            'redirect_uri' => $sessionData['redirect_uri'],
        ];

        $response = $this->httpClient->send(
            Request::post(
                $provider->getTokenEndpoint(),
                $tokenRequestData,
                self::getAuthorizationHeader(
                    $provider->getClientId(),
                    $provider->getSecret()
                )
            )
        );

        if (false === $response->isOkay()) {
            throw new TokenException('unable to obtain access_token', $response);
        }

        $accessToken = AccessToken::fromCodeResponse(
            $provider,
            $this->dateTime,
            $response->json(),
            // in case server does not return a scope, we know it granted
            // our requested scope (according to OAuth specification)
            $sessionData['scope']
        );

        // check if we requested (and got) the "openid" scope
        if (\in_array('openid', \explode(' ', $accessToken->getScope()), true)) {
            // make sure the public key for verification is set
            if (null === $publicKey = $provider->getPublicKey()) {
                throw new OAuthException('no public key set for "id_token" verification');
            }
            // make sure we got an id_token in the response
            if (null === $idToken = $accessToken->getIdToken()) {
                throw new TokenException('no "id_token" present', $response);
            }
            // decode the id_token using RSA with SHA256
            $jwtDecoder = new RS256($publicKey);
            $idToken = IdToken::decode($jwtDecoder->decode($idToken));
            if ($idToken->getAud() !== $provider->getClientId()) {
                throw new IdTokenException('"aud" has unexpected value');
            }
            if ($idToken->getIss() !== $provider->getIssuer()) {
                throw new IdTokenException('"iss" has unexpected value');
            }
            $this->session->set('_oauth2_id_token', $idToken);
            $userId = $idToken->getSub();
        }

        $this->tokenStorage->storeAccessToken(
            $userId,
            $accessToken
        );
    }

    /**
     * @param Provider    $provider
     * @param string      $userId
     * @param AccessToken $accessToken
     *
     * @return false|AccessToken
     */
    private function refreshAccessToken(Provider $provider, $userId, AccessToken $accessToken)
    {
        // prepare access_token request
        $tokenRequestData = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $accessToken->getRefreshToken(),
            'scope' => $accessToken->getScope(),
        ];

        $response = $this->httpClient->send(
            Request::post(
                $provider->getTokenEndpoint(),
                $tokenRequestData,
                self::getAuthorizationHeader(
                    $provider->getClientId(),
                    $provider->getSecret()
                )
            )
        );

        if (false === $response->isOkay()) {
            $responseData = $response->json();
            if (\array_key_exists('error', $responseData) && 'invalid_grant' === $responseData['error']) {
                // delete the access_token, we assume the user revoked it, that
                // is why we get "invalid_grant"
                $this->tokenStorage->deleteAccessToken($userId, $accessToken);

                return false;
            }

            throw new TokenException('unable to refresh access_token', $response);
        }

        // delete old AccessToken as we'll write a new one anyway...
        $this->tokenStorage->deleteAccessToken($userId, $accessToken);

        $accessToken = AccessToken::fromRefreshResponse(
            $provider,
            $this->dateTime,
            $response->json(),
            // provide the old AccessToken to borrow some fields if the server
            // does not provide them on "refresh"
            $accessToken
        );

        // store the refreshed AccessToken
        $this->tokenStorage->storeAccessToken($userId, $accessToken);

        return $accessToken;
    }

    /**
     * Find an AccessToken in the list that matches this scope, bound to
     * providerId and userId.
     *
     * @param Provider $provider
     * @param string   $userId
     * @param string   $scope
     *
     * @return false|AccessToken
     */
    private function getAccessToken(Provider $provider, $userId, $scope)
    {
        $accessTokenList = $this->tokenStorage->getAccessTokenList($userId);
        foreach ($accessTokenList as $accessToken) {
            if ($provider->getProviderId() !== $accessToken->getProviderId()) {
                continue;
            }
            if ($scope !== $accessToken->getScope()) {
                continue;
            }

            return $accessToken;
        }

        return false;
    }

    /**
     * @param string $authUser
     * @param string $authPass
     *
     * @return array
     */
    private static function getAuthorizationHeader($authUser, $authPass)
    {
        return [
            'Accept' => 'application/json',
            'Authorization' => \sprintf(
                'Basic %s',
                Base64::encode(
                    \sprintf('%s:%s', $authUser, $authPass)
                )
            ),
        ];
    }
}
