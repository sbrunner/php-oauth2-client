[![Build Status](https://travis-ci.org/fkooman/php-oauth2-client.svg?branch=master)](https://travis-ci.org/fkooman/php-oauth2-client)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fkooman/php-oauth2-client/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/fkooman/php-oauth2-client/?branch=master)

# Introduction
This is a very simple to use OAuth 2.0 client for integration in your own 
application. It has minimal dependencies, and tries to be as secure as 
possible. The main reason for starting this library was to be compatible with 
PHP >= 5.4.

**NOTE**: if you are not bound to PHP 5.4, you are probably better of using the 
OAuth 2.0 client of the League of Extraordinary Packages! It can be found 
[here](http://oauth2-client.thephpleague.com/).

# Features

- Simplicity
- Easy integration with your own application and/or framework;
- Does not enforce a framework on you;
- Only "authorization code" profile support, will not implement anything else;
- Only conforming OAuth 2.0 servers will work, this library will not get out of 
  its way to deal with services that violate the OAuth 2.0 RFC;
- There will be no toggles to shoot yourself in the foot;
- Uses `paragonie/constant_time_encoding` for constant time encoding;
- Uses `paragonie/random_compat` polyfill for CSPRNG;
- Supports OAuth refresh tokens.

# API

The API is very simple to use. Below, the API is explained in more detail, see
the `example/` folder for working examples.

## Provider 

To create a `Provider` object, you need some information about your OAuth 2.0 
provider.

    $provider = new \fkooman\OAuth\Client\Provider(
        'my_client_id',                  # the client id
        'my_client_secret',              # the client secret
        'https://example.org/authorize', # the authorization endpoint
        'https://example.org/token'      # the token endpoint
    );

## TokenStorage

Typically an application wants to bind tokens obtained from the OAuth server to
a local user account for reuse at a later time. How to do this is application 
specific. A simple session based token storage is provided in the library. You
can implement your own token storage by implementing the 
`\fkooman\OAuth\Client\TokenStorageInterface`.

    $tokenStorage = \fkooman\OAuth\Client\SessionTokenStorage();

## HttpClient

You need to instantiate a HTTP client for interacting with the OAuth server and
the resource(s). A simple cURL HTTP client is available as part of this 
library.

    $httpClient = \fkooman\OAuth\Client\Http\CurlHttpClient();

An array parameter `httpsOnly` is accepted that can be used to allow connecting
to HTTP resources. This configuration option defaults to `true`.

## OAuthClient

with the provider, token storage and HTTP client it is possible to instantiate
the OAuth client:

    $oauthClient = new \fkooman\OAuth\Client\OAuthClient(
        $provider,
        $tokenStorage,
        $httpClient
    );

Now, we also want to set the user ID to bind the tokens to. This is the user ID
the user has in *your* application.

    $oauthClient->setUserId('foo');

## Obtaining a Resource

Obtaining a resource is very simple. You can immediately start trying to get
the resource. If it fails because in an expected way, e.g. there is no token 
yet, it was revoked, it expired, `false` is returned. And an authorization 
request can be started.

    $response = $oauthClient->get('my_scope', 'https://example.org/resource');
    if(false === $response) {
        // we need to ask for authorization again
        $requestUri = $client->getAuthorizeUri(
            'my_scope',                    # the requested OAuth scope
            'https://example.com/callback' # the redirect URI the OAuth service
                                           # redirects you back to, must usually
                                           # be registered at the OAuth provider
        );

        // store the state
        $_SESSION['oauth2_session'] = $requestUri;
        
        // redirect the browser to the authorization endpoint
        http_response_code(302);
        header(sprintf('Location: %s', $requestUri));
        exit(0);
    }

    // we have the response!

    echo $response->getStatusCode();
    echo $response->getHeader('Content-Type');
    var_dump($response->json());

## Callback

Your application MUST also listen on the redirect URI specified above, i.e. 
`https://example.com/callback` and listen for two query parameters in 
particular, `code` and `state`. These need to be provided to the 
`handleCallback` method. Typically the OAuth provider will send you back to 
your redirect URI by adding some additional parameters:

    https://example.com/callback?code=12345&state=abcde

Now those two values need to be provided to the `handleCallback` method:

    $oauthClient->handleCallback(
        $_SESSION['oauth2_session'], // URI from session
        $_GET['code'],               // the code value (e.g. 12345)
        $_GET['state']               // the state value (e.g. abcde)
    );

    // unset session field as to not allow additional redirects to the same 
    // URI to attempt to get another access token with this code
    unset($_SESSION['oauth2_session']);

Now you can either redirect to the page that has the "Obtaining a Resource" 
code on it, or immediately obtain resources on the callback URL.

# Security

As always, make sure you understand what you are doing. If you are using HTTP 
sessions for storing the "state", make sure you follow 
[these](https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions) 
best practices!

OAuth 2.0 is complicated to get right, even if you don't make the obvious 
mistakes, so please make sure you read the RFC and related security documents,
i.e. [RFC 6749](https://tools.ietf.org/html/rfc6749), 
[RFC 6750](https://tools.ietf.org/html/rfc6750) and 
[RFC 6819](https://tools.ietf.org/html/rfc6819).

Make sure you send all relevant "security headers" to the browser as well, see 
e.g. [securityheaders.io](https://securityheaders.io/).

# License

[MIT](LICENSE).
