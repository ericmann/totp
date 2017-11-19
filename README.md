# TOTP [![Build Status][travis-image]][travis-url] [![Coverage Status][coveralls-image]][coveralls-url]

A PHP library for TOTP support in PHP 5.6+.

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


[travis-image]: https://travis-ci.org/ericmann/totp.svg?branch=master
[travis-url]: https://travis-ci.org/ericmann/totp
[coveralls-image]: https://coveralls.io/repos/github/ericmann/totp/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/ericmann/totp?branch=master