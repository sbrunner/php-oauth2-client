Simple OAuth 2.0 client library with support for "Authorization Code Grant" and
OpenID Connect.

# Features

* OpenID Connect support (only "Authorization Code Flow");
  * Currently no support for "User Info" endpoint, only "ID Token";
* "Refresh Token" support;
* Very few dependencies;
* Easy integration with your own application and/or framework;
* Does not enforce a framework on you;
* Only "Authorization Code Grant" support;
* Supports only OAuth 2.0 servers that follow the specification;
* There will be no toggles to shoot yourself in the foot;
* Uses `paragonie/constant_time_encoding` for constant time encoding;
* Uses `paragonie/random_compat` polyfill for CSPRNG;
* Uses `symfony/polyfill-php56` polyfill for `hash_equals`;
* Uses `psr/log` to provide an interface to log HTTP requests between OAuth
  client and server; usually very hard to debug "in the field";

You **MUST** configure PHP in such a way that it enforces secure cookies! 
See 
[this](https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions) 
resource for more information.

# Requirements

* PHP >= 5.4, see `composer.json` for the exact requirements;

# API

The API is very simple to use. See the `example/` folder for working examples!

# Security

As always, make sure you understand what you are doing! Some resources:

* [The Fast Track to Safe and Secure PHP Sessions](https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions)
* [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
* [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
* [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
* [securityheaders.io](https://securityheaders.io/)
* [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

# Contact

You can contact me with any questions or issues regarding this project. Drop
me a line at [fkooman@tuxed.net](mailto:fkooman@tuxed.net).

If you want to (responsibly) disclose a security issue you can also use the
PGP key with key ID `9C5EDD645A571EB2` and fingerprint
`6237 BAF1 418A 907D AA98  EAA7 9C5E DD64 5A57 1EB2`.

# License

[MIT](LICENSE).
