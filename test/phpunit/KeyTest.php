<?php
namespace EAMann\TOTP;

use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase {
    function test_uniqueness() {
        $first = new Key();
        $second = new Key();

        $this->assertNotEquals((string) $first, (string) $second);
    }

    function test_import() {
        $first = new Key();
        $asString = (string) $first;

        $second = Key::import($asString);

        $this->assertEquals($asString, (string) $second);
    }

    function test_invalid_length() {
        $key = new Key();
        $encoded = (string) $key;

        $this->expectException(\InvalidArgumentException::class);

        Key::import(substr($encoded, 0, strlen($encoded) - 1));
    }

    function test_qr_generation() {
        $key = 'W4E2HCCNWDW5BOLSOJ7T7FMDDM======';
        $token = Key::import($key);
        $expected = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2Fhttp%3A%2F%2Ftest.com%3Aadmin%3Fsecret%3DW4E2HCCNWDW5BOLSOJ7T7FMDDM%3D%3D%3D%3D%3D%3D%26issuer%3Dhttp%253A%252F%252Ftest.com';

        $qr = $token->qr_code('http://test.com', 'admin');

        $this->assertEquals($expected, $qr);
    }
}