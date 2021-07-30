# TOTP ![PHP 7.4+][php-image] [![Build Status][build-image]][build-url] [![PHPStan][phpstan-image]][phpstan-url] [![Coverage Status][coveralls-image]][coveralls-url] [![Packagist][packagist-image]][packagist-url]

A PHP library for generating one-time passwords according to [RFC-6238](http://tools.ietf.org/html/rfc6238) for time-based OTP generation.

This library is compatible with Google Authenticator apps available for Android and iPhone.

## Quick Start

Use [Composer](https://getcomposer.org/) to add `ericmann/totp` to your project.

```php
require __DIR__ . '/vendor/autoload.php';

// Create a new, random token
$token = new EAMann\TOTP\Key();

// Import a known token
$raw = '...';
$token = EAMann\TOTP\Key::import($raw);

// Validate an OTP against a token
if (EAMann\TOTP\is_valid_auth_code($token, $otp)) {
  // ...
}
```


[php-image]: https://img.shields.io/badge/php-7.4%2B-green.svg
[packagist-image]: https://img.shields.io/packagist/dt/ericmann/totp.svg
[packagist-url]: https://packagist.org/packages/ericmann/totp
[phpstan-image]: https://github.com/ericmann/totp/actions/workflows/analysis.yml/badge.svg
[phpstan-url]: https://github.com/ericmann/totp/actions/workflows/analysis.yml
[build-image]: https://github.com/ericmann/totp/actions/workflows/build.yml/badge.svg
[build-url]: https://github.com/ericmann/totp/actions/workflows/build.yml
[coveralls-image]: https://coveralls.io/repos/github/ericmann/totp/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/ericmann/totp?branch=master
