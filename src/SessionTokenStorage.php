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

class SessionTokenStorage implements TokenStorageInterface
{
    /**
     * @param string $userId
     *
     * @return AccessToken|null
     */
    public function getAccessToken($userId)
    {
        // there is only one token ever in the session, it is bound to the
        // browser
        if (array_key_exists($userId, $_SESSION)) {
            if (array_key_exists('access_token', $_SESSION[$userId])) {
                return $_SESSION[$userId]['access_token'];
            }
        }
    }

    public function setAccessToken($userId, AccessToken $accessToken)
    {
        $_SESSION[$userId]['access_token'] = $accessToken;
    }

    public function deleteAccessToken($userId, AccessToken $accessToken)
    {
        unset($_SESSION[$userId]['access_token']);
    }
}
