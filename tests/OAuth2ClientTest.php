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
use fkooman\OAuth\Client\OAuth2Client;
use fkooman\OAuth\Client\Provider;
use PHPUnit_Framework_TestCase;
use Psr\Log\NullLogger;

class OAuth2ClientTest extends PHPUnit_Framework_TestCase
{
    /** @var \fkooman\OAuth\Client\RandomInterface */
    private $random;

    public function setUp()
    {
        $this->random = $this->getMockBuilder('\fkooman\OAuth\Client\RandomInterface')->getMock();
        $this->random->method('get')->willReturn('state12345abcde');
    }

    public function testHasNoAccessToken()
    {
        $o = new OAuth2Client(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            $this->random,
            new NullLogger(),
            new DateTime('2016-01-01')
        );
        $o->setUserId('foo');
        $this->assertFalse($o->get('my_scope', 'https://example.org/resource'));
        $this->assertSame('http://localhost/authorize?client_id=foo&redirect_uri=https%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=state12345abcde&response_type=code', $o->getAuthorizeUri('my_scope', 'https://example.org/callback'));
    }

    public function testHasValidAccessToken()
    {
        $o = new OAuth2Client(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            $this->random,
            new NullLogger(),
            new DateTime('2016-01-01')
        );
        $o->setUserId('bar');
        $response = $o->get('my_scope', 'https://example.org/resource');
        $this->assertSame(200, $response->getStatusCode());
        $this->assertTrue($response->json()['ok']);
    }

    public function testHasExpiredAccessTokenNoRefreshToken()
    {
        $o = new OAuth2Client(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            $this->random,
            new NullLogger(),
            new DateTime('2016-01-01 02:00:00')
        );
        $o->setUserId('bar');
        $this->assertFalse($o->get('my_scope', 'https://example.org/resource'));
    }

    public function testHasExpiredAccessTokenRefreshToken()
    {
        $o = new OAuth2Client(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            $this->random,
            new NullLogger(),
            new DateTime('2016-01-01 02:00:00')
        );
        $o->setUserId('baz');
        $response = $o->get('my_scope', 'https://example.org/resource');
        $this->assertSame(200, $response->getStatusCode());
        $this->assertTrue($response->json()['refreshed']);
    }

    public function testCallback()
    {
        $tokenStorage = new TestTokenStorage();

        $o = new OAuth2Client(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            $tokenStorage,
            new TestHttpClient(),
            $this->random,
            new NullLogger(),
            new DateTime('2016-01-01')
        );
        $o->setUserId('foo');
        $o->handleCallback('http://localhost/authorize?client_id=foo&redirect_uri=https%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=state12345abcde&response_type=code', 'AC:abc', 'state12345abcde');
        $accessToken = $tokenStorage->getAccessToken('foo');
        $this->assertSame('AT:code12345', $accessToken->getToken());
    }
}
