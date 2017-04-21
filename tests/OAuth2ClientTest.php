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

//    public function testGetAuthorizeUri()
//    {
//        $o = new OAuth2Client(
//            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
//            new TestTokenStorage(),
//            new TestHttpClient(),
//            $this->random
//        );
//        $this->assertSame(
//            'http://localhost/authorize?client_id=foo&redirect_uri=http%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=state12345abcde&response_type=code',
//            $o->getAuthorizeUri('my_scope', 'http://example.org/callback')
//        );
//    }

//    public function testGetAccessToken()
//    {
//        $o = new OAuth2Client(
//            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
//            new TestTokenStorage(),
//            new TestHttpClient(),
//            $this->random,
//            new DateTime('2016-01-01')
//        );

//        $authorizationRequestUri = 'http://localhost/authorize?client_id=foo&redirect_uri=http%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=state12345abcde&response_type=code';

//        $accessToken = $o->getAccessToken($authorizationRequestUri, 'code12345', 'state12345abcde');
//        $this->assertSame('AT:code12345', $accessToken->getToken());
//        $this->assertSame('bearer', $accessToken->getTokenType());
//        $this->assertSame('2017-01-01 00:00:00', $accessToken->getExpiresAt()->format('Y-m-d H:i:s'));
//        $this->assertSame('my_scope', $accessToken->getScope());
//    }

//    public function testGetAccessTokenWithExpires()
//    {
//        $o = new OAuth2Client(
//            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
//            new TestTokenStorage(),
//            new TestHttpClient(),
//            $this->random,
//            new DateTime('2016-01-01')
//        );

//        $authorizationRequestUri = 'http://localhost/authorize?client_id=foo&redirect_uri=http%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=state12345abcde&response_type=code';

//        $accessToken = $o->getAccessToken($authorizationRequestUri, 'code12345expires', 'state12345abcde');
//        $this->assertSame('AT:code12345expires', $accessToken->getToken());
//        $this->assertSame('bearer', $accessToken->getTokenType());
//        $this->assertSame('2016-01-01 01:00:00', $accessToken->getExpiresAt()->format('Y-m-d H:i:s'));
//        $this->assertSame('my_scope', $accessToken->getScope());
//        $this->assertSame('RT:code12345expires', $accessToken->getRefreshToken());
//    }

//    /**
//     * @expectedException \fkooman\OAuth\Client\Exception\OAuthException
//     * @expectedExceptionMessage invalid OAuth state
//     */
//    public function testGetAccessTokenNonMatchingState()
//    {
//        $o = new OAuth2Client(
//            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
//            new TestTokenStorage(),
//            new TestHttpClient(),
//            $this->random
//        );

//        $authorizationRequestUri = 'http://localhost/authorize?client_id=foo&redirect_uri=http%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=brokenstate&response_type=code';
//        $o->getAccessToken($authorizationRequestUri, 'code12345', 'state12345abcde');
//    }

//    /**
//     * @expectedException \fkooman\OAuth\Client\Exception\OAuthServerException
//     * @expectedExceptionMessage [SERVER] invalid_grant: invalid authorization code
//     */
//    public function testErrorResponseFromTokenEndpoint()
//    {
//        $o = new OAuth2Client(
//            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
//            new TestTokenStorage(),
//            new TestHttpClient(),
//            $this->random
//        );
//        $authorizationRequestUri = 'http://localhost/authorize?client_id=foo&redirect_uri=http%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=state12345abcde&response_type=code';
//        $o->getAccessToken($authorizationRequestUri, 'invalid_code', 'state12345abcde');
//    }

//    public function testRefreshToken()
//    {
//        $o = new OAuth2Client(
//            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
//            new TestTokenStorage(),
//            new TestHttpClient(),
//            $this->random,
//            new DateTime('2016-01-01')
//        );

//        $accessToken = $o->refreshAccessToken(new AccessToken('AT:xyz', 'bearer', 'my_scope', 'refresh:x:y:z', new DateTime('2016-01-01')));
//        $this->assertSame('AT:refreshed', $accessToken->getToken());
//        $this->assertSame('bearer', $accessToken->getTokenType());
//        $this->assertSame('2016-01-01 01:00:00', $accessToken->getExpiresAt()->format('Y-m-d H:i:s'));
//        $this->assertSame('my_scope', $accessToken->getScope());
//    }
}
