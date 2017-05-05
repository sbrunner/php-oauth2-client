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

class SessionTokenStorage implements TokenStorageInterface
{
    /**
     * @param string $userId
     * @param string $requestScope
     *
     * @return AccessToken|false
     */
    public function getAccessToken($userId, $requestScope)
    {
        $this->startSession($userId);
        foreach ($_SESSION['_oauth2_client'][$userId] as $accessToken) {
            if ($requestScope === $accessToken->getScope()) {
                return $accessToken;
            }
        }

        return false;
    }

    /**
     * @param string      $userId
     * @param AccessToken $accessToken
     */
    public function setAccessToken($userId, AccessToken $accessToken)
    {
        $this->startSession($userId);
        $_SESSION['_oauth2_client'][$userId][] = $accessToken;
    }

    /**
     * @param string      $userId
     * @param AccessToken $accessToken
     */
    public function deleteAccessToken($userId, AccessToken $accessToken)
    {
        $this->startSession($userId);
        foreach ($_SESSION['_oauth2_client'][$userId] as $i => $sessionAccessToken) {
            if ($accessToken->getScope() === $sessionAccessToken->getScope()) {
                unset($_SESSION['_oauth2_client'][$userId][$i]);
            }
        }
    }

    private function startSession($userId)
    {
        if ('' === session_id()) {
            session_start();
        }

        if (!isset($_SESSION['_oauth2_client'][$userId])) {
            $_SESSION['_oauth2_client'][$userId] = [];
        }
    }
}
