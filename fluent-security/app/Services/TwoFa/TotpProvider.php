<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * The TOTP algorithm itself - RFC 6238 over RFC 4226, as every authenticator app
 * implements it.
 *
 * Nothing here touches the database, the user or WordPress settings, so the maths can
 * be tested against the RFC test vectors on its own. Storage and enrollment live in
 * TotpTwoFaMethod.
 */
class TotpProvider
{
    /**
     * SHA1 is what RFC 6238 specifies and what authenticator apps assume. Several
     * popular ones silently ignore the algorithm parameter of a provisioning URI and
     * use SHA1 regardless, so offering anything else would produce codes that only
     * some apps could generate.
     */
    const ALGORITHM = 'sha1';

    const DIGITS = 6;

    /**
     * Seconds a code is generated for.
     */
    const PERIOD = 30;

    /**
     * 160 bits, the SHA1 block size, as recommended by RFC 4226.
     */
    const SECRET_BYTES = 20;

    /**
     * How many periods either side of now are accepted, to absorb clock drift between
     * the server and the user's phone. One step means a code stays usable for at most
     * 90 seconds; widening this trades directly against how long a shoulder surfed or
     * phished code stays replayable.
     */
    const WINDOW = 1;

    const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * A fresh shared secret, base32 encoded for the user to type or scan.
     *
     * @return string empty if the platform has no usable source of randomness, in which
     *                case enrollment must not proceed
     */
    public static function generateSecret()
    {
        try {
            $bytes = random_bytes(self::SECRET_BYTES);
        } catch (\Exception $e) {
            return '';
        }

        return self::base32Encode($bytes);
    }

    /**
     * @param $secret string
     * @return bool
     */
    public static function isValidSecret($secret)
    {
        if (!is_string($secret) || $secret === '') {
            return false;
        }

        return (bool)preg_match('/^[A-Z2-7]{16,128}$/', $secret);
    }

    /**
     * The otpauth:// URI an authenticator app consumes, by QR or by hand.
     *
     * The issuer appears both in the label and as a parameter: the parameter is the
     * modern form, the label prefix is what older apps read, and apps that understand
     * both expect them to agree.
     *
     * @param $secret string
     * @param $accountName string what the user will see in their app, so their login
     * @param $issuer string
     * @return string
     */
    public static function getProvisioningUri($secret, $accountName, $issuer)
    {
        $issuer = trim(html_entity_decode((string)$issuer, ENT_QUOTES | ENT_HTML5, 'UTF-8'));

        // A colon separates issuer from account in the label, so it cannot appear inside either.
        $issuer = str_replace(':', ' ', $issuer);
        $accountName = str_replace(':', ' ', (string)$accountName);

        if ($issuer === '') {
            $issuer = 'WordPress';
        }

        $label = rawurlencode($issuer) . ':' . rawurlencode($accountName);

        return 'otpauth://totp/' . $label . '?' . http_build_query([
                'secret'    => $secret,
                'issuer'    => $issuer,
                'algorithm' => strtoupper(self::ALGORITHM),
                'digits'    => self::DIGITS,
                'period'    => self::PERIOD
            ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * The code for one particular time step.
     *
     * @param $secret string base32
     * @param $counter int
     * @return string empty if the secret cannot be decoded
     */
    public static function getCodeForCounter($secret, $counter)
    {
        $key = self::base32Decode($secret);

        if ($key === '') {
            return '';
        }

        // The counter is a 64 bit big endian integer; pack('J') is not available everywhere.
        $binCounter = pack('N', ($counter >> 32) & 0xFFFFFFFF) . pack('N', $counter & 0xFFFFFFFF);

        $hash = hash_hmac(self::ALGORITHM, $binCounter, $key, true);

        // Dynamic truncation, RFC 4226 section 5.3.
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

        $value = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        $code = $value % (10 ** self::DIGITS);

        return str_pad((string)$code, self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Checks a submitted code and reports which time step it belonged to.
     *
     * The caller must persist that step and pass it back as $afterCounter next time.
     * Without it a code stays valid for its whole window, so anyone who observes one -
     * over a shoulder, in a phishing proxy, in a log - can replay it. Returning the
     * step rather than a bare true is what makes single use enforceable.
     *
     * @param $secret string base32
     * @param $code string as typed by the user
     * @param $afterCounter int the last step already spent, or 0 for none
     * @param $timestamp int|null unix time, for tests
     * @return int|false the matched step, or false
     */
    public static function verify($secret, $code, $afterCounter = 0, $timestamp = null)
    {
        $code = preg_replace('/\D/', '', (string)$code);

        if (strlen($code) !== self::DIGITS || !self::isValidSecret($secret)) {
            return false;
        }

        if ($timestamp === null) {
            $timestamp = time();
        }

        $current = (int)floor($timestamp / self::PERIOD);

        $match = false;

        for ($i = -self::WINDOW; $i <= self::WINDOW; $i++) {
            $counter = $current + $i;

            if ($counter <= $afterCounter) {
                continue; // already spent, and every step before it with it
            }

            /*
             * No early return: comparing every candidate regardless of an earlier match
             * keeps the work constant, so the time taken does not reveal which step -
             * and therefore how far off the user's clock - produced the code.
             */
            if (hash_equals(self::getCodeForCounter($secret, $counter), $code) && $match === false) {
                $match = $counter;
            }
        }

        return $match;
    }

    /**
     * @param $bytes string raw
     * @return string
     */
    private static function base32Encode($bytes)
    {
        if ($bytes === '') {
            return '';
        }

        $binary = '';

        foreach (str_split($bytes) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $encoded = '';

        foreach (str_split($binary, 5) as $chunk) {
            $encoded .= self::BASE32_ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $encoded;
    }

    /**
     * Tolerates how people actually retype a secret - lower case, spaces, the padding
     * some apps show.
     *
     * @param $secret string
     * @return string raw bytes, empty if the input is not base32
     */
    private static function base32Decode($secret)
    {
        $secret = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', (string)$secret));

        if ($secret === '') {
            return '';
        }

        $binary = '';

        for ($i = 0, $len = strlen($secret); $i < $len; $i++) {
            $position = strpos(self::BASE32_ALPHABET, $secret[$i]);

            if ($position === false) {
                return '';
            }

            $binary .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';

        foreach (str_split($binary, 8) as $chunk) {
            if (strlen($chunk) < 8) {
                break; // a partial trailing byte is base32 padding, not data
            }

            $bytes .= chr(bindec($chunk));
        }

        return $bytes;
    }
}
