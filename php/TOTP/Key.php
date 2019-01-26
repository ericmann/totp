<?php

namespace EAMann\TOTP;

use \ParagonIE\ConstantTime\Encoding;

class Key
{
    private $bytes;

    /**
     * Create a new, random TOTP key
     *
     * @param int $byte_length
     */
    public function __construct(int $byte_length = 16)
    {
        if ($byte_length > 0) {
            $this->bytes = random_bytes($byte_length);
        }
    }

    /**
     * Get a Base32-encoded representation of this TOTP key
     *
     * @return string
     */
    public function __toString() : string
    {
        return Encoding::base32EncodeUpper($this->bytes);
    }

    /**
     * Uses the Google Charts API to build a QR Code for use with an otpauth url
     *
     * @param string $site Site name to display in the Authentication app.
     * @param string $user Username to share with the Authentication app.
     *
     * @return string A URL to use as an img src to display the QR code
     */
    public function qrCode(string $site, string $user) : string
    {
        $name = $site . ':' . $user;
        $google_url = urlencode('otpauth://totp/' . $name . '?secret=' . (string)$this);
        $google_url .= urlencode('&issuer=' . urlencode($site));

        return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . $google_url;
    }

    /**
     * Attempt to import a Base32-encoded TOTP key.
     *
     * @param string $key The key we wish to import
     *
     * @throws \RangeException If the key is invalid
     *
     * @return Key
     */
    public static function import(string $key) : Key
    {
        $token = new Key(0);

        $raw = Encoding::base32DecodeUpper(strtoupper($key));

        $token->bytes = $raw;

        return $token;
    }
}
