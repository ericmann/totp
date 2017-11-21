<?php

namespace EAMann\TOTP;

use \ParagonIE\ConstantTime\Encoding;

/**
 * Generates random TOTP key
 *
 * @param int $bytes Number of bytes to use for key.
 *
 * @return Key Long, random string composed of base32 characters.
 */
function generate_key($bytes = 16)
{
    return new Key($bytes);
}

/**
 * Checks if a given code is valid for a given key, allowing for a certain amount of time drift
 *
 * @param string|Key $key      The share secret key to use.
 * @param string         $authcode The code to test.
 *
 * @return bool Whether the code is valid within the time frame
 */
function is_valid_authcode($key, $authcode)
{
    if (!$key instanceof Key) {
        $key = Key::import($key);
    }

    $max_ticks = 4;

    // Array of all ticks to allow, sorted using absolute value to test closest match first.
    $ticks = range(-$max_ticks, $max_ticks);
    usort($ticks, function($a, $b) {
        $a = abs($a);
        $b = abs($b);
        if ($a === $b) {
            return 0;
        }
        return ($a < $b) ? -1 : 1;
    });
    $time = time() / 30;

    foreach ($ticks as $offset) {
        $log_time = $time + $offset;
        if (calc_totp($key, $log_time) === $authcode) {
            return true;
        }
    }
    return false;
}

/**
 * Calculate a valid code given the shared secret key
 *
 * @param string|Key $key        The shared secret key to use for calculating code.
 * @param mixed          $step_count The time step used to calculate the code, which is the floor of time() divided by step size.
 * @param int            $digits     The number of digits in the returned code.
 * @param string         $hash       The hash used to calculate the code.
 * @param int            $time_step  The size of the time step.
 *
 * @return string The totp code
 */
function calc_totp($key, $step_count = false, $digits = 6, $hash = 'sha1', $time_step = 30)
{
    if (!$key instanceof Key) {
        $key = Key::import($key);
    }

    $secret = Encoding::base32DecodeUpper((string)$key);

    if ($hash === 'sha256') {
        $secret .= substr($secret, 0, 12);
    } else if ($hash === 'sha512') {
        $secret .= $secret . $secret . substr($secret, 0, 4);
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