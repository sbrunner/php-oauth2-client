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

namespace fkooman\OAuth\Client\Tests;

use DateTime;
use fkooman\OAuth\Client\AccessToken;
use fkooman\OAuth\Client\TokenStorageInterface;

class TestTokenStorage implements TokenStorageInterface
{
    /** @var array */
    private $data = [];

    public function __construct()
    {
        $this->data['bar']['access_token'] = new AccessToken('AT:xyz', 'bearer', 'my_scope', null, new DateTime('2016-01-01 01:00:00'));
        $this->data['baz']['access_token'] = new AccessToken('AT:expired', 'bearer', 'my_scope', 'RT:abc', new DateTime('2016-01-01 01:00:00'));
    }

    /**
     * @return AccessToken|false
     */
    public function getAccessToken($userId)
    {
        if (!array_key_exists($userId, $this->data)) {
            return false;
        }

        if (array_key_exists('access_token', $this->data[$userId])) {
            return $this->data[$userId]['access_token'];
        }

        return false;
    }

    public function setAccessToken($userId, AccessToken $accessToken)
    {
        $this->data[$userId]['access_token'] = $accessToken;
    }

    public function deleteAccessToken($userId, AccessToken $accessToken)
    {
        unset($this->data[$userId]['access_token']);
    }
}
