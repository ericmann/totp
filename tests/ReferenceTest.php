<?php
namespace EAMann\TOTP;

use PHPUnit\Framework\TestCase;
use \ParagonIE\ConstantTime\Encoding;

/**
 * Override time() in the current namespace for testing.
 *
 * @return int
 */
function time()
{
    return ReferenceTest::$now ?: \time();
}

/**
 * Verify the TOTPs calculated for various timestamps match the
 * text vectors identified in the reference spec implementation.
 *
 * @see https://tools.ietf.org/html/rfc6238#appendix-B
 */
class ReferenceTest extends TestCase {
    private static $token = '12345678901234567890';
    private static $step = 30;

    /**
     * @var int $now Timestamp returned by time()
     */
    public static $now;

    private static $vectors = [
        59          => ['94287082', '46119246', '90693936'],
        1111111109  => ['07081804', '68084774', '25091201'],
        1111111111  => ['14050471', '67062674', '99943326'],
        1234567890  => ['89005924', '91819424', '93441116'],
        2000000000  => ['69279037', '90698825', '38618901'],
        20000000000 => ['65353130', '77737706', '47863826']
    ];


    public function test_sha1_generate() {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $hash = 'sha1';
        $token = Encoding::base32EncodeUpper(self::$token);

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertEquals($vector[0], calc_totp($token, false, 8, $hash, self::$step));
        }

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertEquals(substr($vector[0], 2), calc_totp($token, false, 6, $hash, self::$step));
        }
    }

    public function test_sha1_authenticate() {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $hash = 'sha1';
        $token = Encoding::base32EncodeUpper(self::$token);

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertTrue(is_valid_authcode($token, $vector[0], $hash));
        }

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertTrue(is_valid_authcode($token, substr($vector[0], 2), $hash));
        }
    }

    public function test_sha256_generate() {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $hash = 'sha256';
        $token = Encoding::base32EncodeUpper(self::$token);

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertEquals($vector[1], calc_totp($token, false, 8, $hash, self::$step));
        }

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertEquals(substr($vector[1], 2), calc_totp($token, false, 6, $hash, self::$step));
        }
    }

    public function test_sha256_authenticate() {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $hash = 'sha256';
        $token = Encoding::base32EncodeUpper(self::$token);

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertTrue(is_valid_authcode($token, $vector[1], $hash));
        }

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertTrue(is_valid_authcode($token, substr($vector[1], 2), $hash));
        }
    }

    public function test_sha512_generate() {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $hash = 'sha512';
        $token = Encoding::base32EncodeUpper(self::$token);

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertEquals($vector[2], calc_totp($token, false, 8, $hash, self::$step));
        }

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertEquals(substr($vector[2], 2), calc_totp($token, false, 6, $hash, self::$step));
        }
    }

    public function test_sha512_authenticate() {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('calc_totp requires 64-bit PHP');
        }

        $hash = 'sha512';
        $token = Encoding::base32EncodeUpper(self::$token);

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertTrue(is_valid_authcode($token, $vector[2], $hash));
        }

        foreach (self::$vectors as $time => $vector) {
            self::$now = (int) $time;

            $this->assertTrue(is_valid_authcode($token, substr($vector[2], 2), $hash));
        }
    }
}