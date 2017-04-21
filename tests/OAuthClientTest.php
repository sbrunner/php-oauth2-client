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

namespace fkooman\OAuth\Client\Tests;

use DateTime;
use fkooman\OAuth\Client\OAuthClient;
use fkooman\OAuth\Client\Provider;
use PHPUnit_Framework_TestCase;
use Psr\Log\NullLogger;

class OAuthClientTest extends PHPUnit_Framework_TestCase
{
    public function testHasNoAccessToken()
    {
        $o = new OAuthClient(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            new TestRandom(),
            new NullLogger(),
            new DateTime('2016-01-01')
        );
        $o->setUserId('foo');
        $this->assertFalse($o->get('my_scope', 'https://example.org/resource'));
        $this->assertSame('http://localhost/authorize?client_id=foo&redirect_uri=https%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=random_0&response_type=code', $o->getAuthorizeUri('my_scope', 'https://example.org/callback'));
    }

    public function testHasValidAccessToken()
    {
        $o = new OAuthClient(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            new TestRandom(),
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
        $o = new OAuthClient(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            new TestRandom(),
            new NullLogger(),
            new DateTime('2016-01-01 02:00:00')
        );
        $o->setUserId('bar');
        $this->assertFalse($o->get('my_scope', 'https://example.org/resource'));
    }

    public function testHasExpiredAccessTokenRefreshToken()
    {
        $o = new OAuthClient(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            new TestTokenStorage(),
            new TestHttpClient(),
            new TestRandom(),
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

        $o = new OAuthClient(
            new Provider('foo', 'bar', 'http://localhost/authorize', 'http://localhost/token'),
            $tokenStorage,
            new TestHttpClient(),
            new TestRandom(),
            new NullLogger(),
            new DateTime('2016-01-01')
        );
        $o->setUserId('foo');
        $o->handleCallback('http://localhost/authorize?client_id=foo&redirect_uri=https%3A%2F%2Fexample.org%2Fcallback&scope=my_scope&state=state12345abcde&response_type=code', 'AC:abc', 'state12345abcde');
        $accessToken = $tokenStorage->getAccessToken('foo');
        $this->assertSame('AT:code12345', $accessToken->getToken());
    }
}
