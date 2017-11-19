<?php
namespace EAMann\TOTP;

use PHPUnit\Framework\TestCase;

class CoreTest extends TestCase {
    public function test_key_generation_uniqueness() {
        $first = generate_key();
        $second = generate_key();

        $this->assertNotEquals((string) $first, (string) $second);
    }

    public function test_key_validation() {
        if ( PHP_INT_SIZE === 4 ) {
            $this->markTestSkipped( 'calc_totp requires 64-bit PHP' );
        }

        $key = new Key();
        $otp = calc_totp($key);

        $this->assertTrue(is_valid_authcode($key, $otp));
    }

    public function test_invalid_otp() {
        if ( PHP_INT_SIZE === 4 ) {
            $this->markTestSkipped( 'calc_totp requires 64-bit PHP' );
        }

        $key = new Key();

        $this->assertFalse(is_valid_authcode($key, '000000'));
    }
}