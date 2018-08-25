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

use fkooman\Jwt\RS256;
use fkooman\OAuth\Client\Exception\IdTokenException;
use fkooman\OAuth\Client\Exception\TokenException;
use fkooman\OAuth\Client\Http\HttpClientInterface;
use fkooman\OAuth\Client\Http\Request;
use fkooman\OAuth\Client\Http\Response;

class OpenIdClient extends OAuthClient
{
    /** @var \fkooman\Jwt\RS256 */
    private $jwtDecoder;

    /**
     * @param TokenStorageInterface    $tokenStorage
     * @param Http\HttpClientInterface $httpClient
     */
    public function __construct(TokenStorageInterface $tokenStorage, HttpClientInterface $httpClient, RS256 $jwtDecoder)
    {
        parent::__construct($tokenStorage, $httpClient);
        $this->jwtDecoder = $jwtDecoder;
    }

    /**
     * @param Provider $provider
     * @param string   $requestScope
     *
     * @return false|IdToken
     */
    public function getIdToken(Provider $provider, $requestScope)
    {
        if (false === $this->session->has('_oidc_id_token')) {
            return false;
        }

        return $this->session->get('_oidc_id_token');
    }

    /**
     * Obtain an authorization request URL to start the authorization process
     * at the OAuth provider.
     *
     * @param Provider $provider
     * @param string   $scope       the space separated scope tokens
     * @param string   $redirectUri the URL registered at the OAuth provider, to
     *                              be redirected back to
     *
     * @return string the authorization request URL
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.2
     */
    public function getAuthenticateUri(Provider $provider, $scope, $redirectUri)
    {
        return parent::getAuthorizeUri($provider, null, $scope, $redirectUri);
    }

    /**
     * @param Provider $provider
     * @param array    $getData
     *
     * @return void
     */
    public function handleAuthenticateCallback(Provider $provider, array $getData)
    {
        parent::handleCallback($provider, null, $getData);
    }

    /**
     * @param Provider      $provider
     * @param AccessToken   $accessToken
     * @param Http\Response $response
     *
     * @return string
     */
    public function handleTokenId(Provider $provider, AccessToken $accessToken, Response $response)
    {
        if (null === $idTokenStr = $accessToken->getIdToken()) {
            throw new TokenException('no "token_id"', $response);
        }

        try {
            $idToken = IdToken::decode($this->jwtDecoder->decode($idTokenStr));

            if (self::getIssFromUrl($provider->getAuthorizationEndpoint()) !== $idToken->getIss()) {
                throw new TokenException('unexpected iss', $response);
            }
            if ($provider->getClientId() !== $idToken->getAud()) {
                throw new TokenException('unexpected audience', $response);
            }

            $this->session->set('_oidc_id_token', $idToken);

            return $idToken->getSub();
        } catch (IdTokenException $e) {
            throw new TokenException($e->getMessage(), $response);
        }
    }

    /**
     * @param string $url
     *
     * @return string
     */
    public static function getIssFromUrl($url)
    {
        $urlParts = \parse_url($url);

        return $urlParts['scheme'].'://'.$urlParts['host'].':'.$urlParts['port'];
    }
}
