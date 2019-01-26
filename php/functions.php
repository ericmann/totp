<?php

namespace EAMann\TOTP;

use \ParagonIE\ConstantTime\Encoding;

/**
 * Generates random TOTP key
 *
 * @param int $bytes Number of bytes to use for key.
 *
 * @throws \Exception if it was not possible to gather sufficient entropy.
 *
 * @return Key Long, random string composed of base32 characters.
 */
function generate_key(int $bytes = 16) : Key
{
    return new Key($bytes);
}

/**
 * Checks if a given code is valid for a given key, allowing for a certain amount of time drift
 *
 * @param string|Key $key       The share secret key to use.
 * @param string     $authcode  The code to test.
 * @param string     $hash      The hash used to calculate the code.
 * @param int        $time_step The size of the time step.
 *
 * @throws \Exception if it was not possible to gather sufficient entropy.
 *
 * @return bool Whether the code is valid within the time frame
 */
function is_valid_authcode($key, string $authcode, string $hash = 'sha1', int $time_step = 30) : bool
{
    if (!($key instanceof Key)) {
        $key = Key::import($key);
    }

    $max_ticks = 4;

    // Array of all ticks to allow, sorted using absolute value to test closest match first.
    $ticks = range(-$max_ticks, $max_ticks);
    usort($ticks, function ($a, $b) {
        $a = abs($a);
        $b = abs($b);
        if ($a === $b) {
            return 0;
        }
        return ($a < $b) ? -1 : 1;
    });
    $time = time() / 30;

    $digits = strlen($authcode);

    foreach ($ticks as $offset) {
        $log_time = $time + $offset;
        if (calc_totp($key, $log_time, $digits, $hash, $time_step) === $authcode) {
            return true;
        }
    }
    return false;
}

/**
 * Pad a short secret with bytes from the same until it's the correct length
 * for hashing.
 *
 * @param string $secret Secret key to pad
 * @param int    $length Byte length of the desired padded secret
 *
 * @throws \InvalidArgumentException If the secret or length are invalid
 *
 * @return string
 */
function pad_secret(string $secret, int $length) : string
{
    if (empty($secret)) {
        throw new \InvalidArgumentException('Secret must be non-empty!');
    }

    $length = intval($length);
    if ($length <= 0) {
        throw new \InvalidArgumentException('Padding length must be non-zero');
    }

    return str_pad($secret, $length, $secret, STR_PAD_RIGHT);
}

/**
 * Calculate a valid code given the shared secret key
 *
 * @param string|Key     $key        The shared secret key to use for calculating code.
 * @param mixed          $step_count The time step used to calculate the code.
 * @param int            $digits     The number of digits in the returned code.
 * @param string         $hash       The hash used to calculate the code.
 * @param int            $time_step  The size of the time step.
 *
 * @throws \Exception if it was not possible to gather sufficient entropy.
 *
 * @return string The totp code
 */
function calc_totp($key, $step_count = false, int $digits = 6, string $hash = 'sha1', int $time_step = 30) : string
{
    if (!$key instanceof Key) {
        $key = Key::import($key);
    }

    $secret = Encoding::base32DecodeUpper((string)$key);

    switch ($hash) {
        case 'sha1':
            $secret = pad_secret($secret, 20);
            break;
        case 'sha256':
            $secret = pad_secret($secret, 32);
            break;
        case 'sha512':
            $secret = pad_secret($secret, 64);
            break;
        default:
            throw new \InvalidArgumentException('Invalid hash type specified!');
    }

    $time_step = intval($time_step);
    if ($time_step <= 0) {
        throw new \InvalidArgumentException('Time step must be greater than zero');
    }

    if (false === $step_count) {
        $step_count = floor(time() / $time_step);
    }

    $timestamp = pack('J', $step_count);
    $hash = hash_hmac($hash, $timestamp, $secret, true);
    $offset = ord($hash[ strlen($hash) - 1 ]) & 0xf;
    $code = (
                ((ord($hash[ $offset + 0 ]) & 0x7f) << 24) |
                ((ord($hash[ $offset + 1 ]) & 0xff) << 16) |
                ((ord($hash[ $offset + 2 ]) & 0xff) << 8) |
                (ord($hash[ $offset + 3 ]) & 0xff)
            ) % pow(10, $digits);

    return str_pad($code, $digits, '0', STR_PAD_LEFT);
}
