<?php

namespace EAMann\TOTP;

use PHPUnit\Framework\TestCase;

class CoreTest extends TestCase
{
    public function test_key_generation_uniqueness()
    {
        $first = generate_key();
        $second = generate_key();

        $this->assertNotEquals((string)$first, (string)$second);
    }

    public function test_key_validation()
    {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $key = new Key();
        $otp = calc_totp($key);

        $this->assertTrue(is_valid_authcode($key, $otp));
    }

    public function test_string_key_validation()
    {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $key = new Key();
        $key_str = (string) $key;

        $otp = calc_totp($key);

        $this->assertTrue(is_valid_authcode($key_str, $otp));
    }

    public function test_invalid_otp()
    {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $key = new Key();

        $this->assertFalse(is_valid_authcode($key, '000000'));
    }

    public function pad_short_secrets()
    {
        $secret = 'abc';

        $this->assertEquals('abc', pad_secret($secret, 3));
        $this->assertEquals('abcabc', pad_secret($secret, 6));
        $this->assertEquals('abcabcabcabc', pad_secret($secret, 12));
        $this->assertEquals('abcab', pad_secret($secret, 5));
    }

    public function test_padding_empty_string()
    {
        $this->expectException(\InvalidArgumentException::class);

        pad_secret('', 20);
    }

    public function test_padding_negative_length()
    {
        $this->expectException(\InvalidArgumentException::class);

        pad_secret('secret', -5);
    }

    public function test_invalid_hash()
    {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $this->expectException(\InvalidArgumentException::class);

        $key = new Key();
        calc_totp($key, false, 6, 'md5');
    }

    public function test_time_step_nonzero()
    {
        $this->expectException(\InvalidArgumentException::class);

        $key = new Key();
        calc_totp($key, false, 6, 'sha1', 0);
    }

    public function test_time_step_positive()
    {
        $this->expectException(\InvalidArgumentException::class);

        $key = new Key();
        calc_totp($key, false, 6, 'sha1', -30);
    }
}