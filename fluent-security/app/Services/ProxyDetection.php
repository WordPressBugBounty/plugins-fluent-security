<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Helper;

/**
 * Works out whether this site is sitting behind a reverse proxy.
 *
 * This only ever advises. Nothing here is allowed to widen who is trusted, because the
 * whole reason the IP resolver refuses to infer a proxy is that inferring one is what
 * lets a visitor announce their own address. What it produces is a suggestion for an
 * administrator to confirm, and - more usefully - a warning when the evidence says the
 * site is behind a proxy that has not been declared, which is a failure that otherwise
 * says nothing at all while every visitor quietly resolves to the same address.
 *
 * The two mistakes are not equally bad. Saying "proxy" when there is none costs a
 * settings panel nobody needed. Saying "no proxy" when there is one hides the only
 * screen that can fix a site where the login attempt limit is counting every visitor
 * as the same person. So the confident answer is the positive one, and the absence of
 * evidence is reported as absence of evidence.
 */
class ProxyDetection
{
    /**
     * Cloudflare, which the resolver already handles on its own.
     */
    const STATUS_CLOUDFLARE = 'cloudflare';

    /**
     * The request reached PHP from inside the network, so something is in front.
     */
    const STATUS_DETECTED = 'detected';

    /**
     * Forwarding headers are present, but they arrived over a public connection and any
     * visitor can send them, so this is a hint rather than a finding.
     */
    const STATUS_POSSIBLE = 'possible';

    const STATUS_NONE = 'none';

    /**
     * Headers a proxy might announce the visitor in, most specific first. The vendor
     * ones are worth naming separately because they identify what is in front.
     */
    private static $knownHeaders = [
        'HTTP_CF_CONNECTING_IP'   => ['label' => 'CF-Connecting-IP', 'vendor' => 'Cloudflare'],
        'HTTP_TRUE_CLIENT_IP'     => ['label' => 'True-Client-IP', 'vendor' => 'Akamai or Cloudflare Enterprise'],
        'HTTP_X_SUCURI_CLIENTIP'  => ['label' => 'X-Sucuri-ClientIP', 'vendor' => 'Sucuri'],
        'HTTP_INCAP_CLIENT_IP'    => ['label' => 'Incap-Client-IP', 'vendor' => 'Imperva'],
        'HTTP_X_REAL_IP'          => ['label' => 'X-Real-IP', 'vendor' => ''],
        'HTTP_X_FORWARDED_FOR'    => ['label' => 'X-Forwarded-For', 'vendor' => ''],
        'HTTP_FORWARDED'          => ['label' => 'Forwarded', 'vendor' => ''],
        'HTTP_X_CLUSTER_CLIENT_IP' => ['label' => 'X-Cluster-Client-IP', 'vendor' => '']
    ];

    /**
     * What this request can be made to say about the site's topology.
     *
     * @return array
     */
    public static function detect()
    {
        $remoteAddr = '';

        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $remoteAddr = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        $isPrivate = self::isPrivateOrLocal($remoteAddr);
        $headers = self::presentHeaders();
        $configured = (bool)Helper::getTrustedProxies();

        $status = self::resolveStatus($remoteAddr, $isPrivate, $headers);

        return [
            'status'            => $status,
            'remote_addr'       => $remoteAddr,
            'remote_is_private' => $isPrivate,
            // What the plugin would record for whoever is reading this screen.
            'resolved_ip'       => Helper::getIp(),
            'headers'           => $headers,
            'vendor'            => self::guessVendor($headers),
            'configured'        => $configured,
            'config_locked'     => defined('FLUENT_AUTH_TRUSTED_PROXIES') && FLUENT_AUTH_TRUSTED_PROXIES,
            /*
             * The case worth interrupting someone for: the evidence says there is a
             * proxy, nothing has been declared, so every visitor is arriving as the
             * same address and the attempt limit is counting them as one person.
             */
            'needs_attention'   => self::isAmbiguous(),
            // Offered for the administrator to accept, never applied on their behalf.
            'suggested_proxy'   => ($isPrivate && $remoteAddr) ? $remoteAddr : '',
            'suggested_header'  => self::suggestHeader($headers)
        ];
    }

    /**
     * Whether this site's visitor addresses cannot currently be told apart.
     *
     * True when the request reached PHP from inside the network - so something in front
     * relayed it - and no proxy has been declared for the resolver to trust. In that state
     * every visitor resolves to the same address, which makes the attempt limit count them
     * as one person, and makes an IP allow list catastrophic: exempting that one shared
     * address exempts everyone who can reach the site. The allow list checks this before it
     * will apply, which is why the condition lives here as its own answer rather than being
     * buried in the array detect() returns.
     *
     * @return bool
     */
    public static function isAmbiguous()
    {
        // Declared, so the resolver already knows which hop to believe.
        if (Helper::getTrustedProxies()) {
            return false;
        }

        $remoteAddr = '';

        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $remoteAddr = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }

        if (!$remoteAddr) {
            // No connection behind this request at all - WP-CLI or cron, nothing to exempt.
            return false;
        }

        // Cloudflare proves itself against their published ranges, so it is not ambiguous.
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && Helper::isCfIp($remoteAddr)) {
            return false;
        }

        return self::isPrivateOrLocal($remoteAddr);
    }

    /**
     * @param $remoteAddr string
     * @param $isPrivate bool
     * @param $headers array
     * @return string
     */
    private static function resolveStatus($remoteAddr, $isPrivate, $headers)
    {
        /*
         * Cloudflare proves itself: the header only counts once the connection is known
         * to have come from one of their edges, and that is checked against their
         * published ranges rather than taken on trust.
         */
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && Helper::isCfIp($remoteAddr)) {
            return self::STATUS_CLOUDFLARE;
        }

        /*
         * A private or loopback REMOTE_ADDR is the one signal a remote visitor cannot
         * fake, because it is the source address of the TCP connection rather than
         * anything they were able to write. Something local relayed this request.
         */
        if ($isPrivate) {
            return self::STATUS_DETECTED;
        }

        if ($headers) {
            return self::STATUS_POSSIBLE;
        }

        return self::STATUS_NONE;
    }

    /**
     * The recognised forwarding headers on this request.
     *
     * Values are attacker supplied - anyone can send X-Forwarded-For - so they are
     * sanitised and cut short before being handed to a screen that will display them.
     *
     * @return array
     */
    private static function presentHeaders()
    {
        $found = [];

        foreach (self::$knownHeaders as $key => $meta) {
            if (empty($_SERVER[$key])) {
                continue;
            }

            $value = sanitize_text_field(wp_unslash($_SERVER[$key]));

            if (strlen($value) > 120) {
                $value = substr($value, 0, 120) . '...';
            }

            $found[] = [
                'header' => $meta['label'],
                'value'  => $value,
                'vendor' => $meta['vendor']
            ];
        }

        return $found;
    }

    /**
     * @param $headers array
     * @return string
     */
    private static function guessVendor($headers)
    {
        foreach ($headers as $header) {
            if ($header['vendor']) {
                return $header['vendor'];
            }
        }

        return '';
    }

    /**
     * @param $headers array
     * @return string
     */
    private static function suggestHeader($headers)
    {
        foreach ($headers as $header) {
            // Cloudflare needs no setting, so it is never the suggestion.
            if ($header['header'] !== 'CF-Connecting-IP') {
                return $header['header'];
            }
        }

        return '';
    }

    /**
     * Whether an address belongs to a range that cannot be routed from the internet.
     *
     * PHP's own flags cover the private and reserved blocks for both IPv4 and IPv6.
     * Carrier grade NAT is not among them and is worth adding, because container
     * networks hand those addresses out and a request relayed from one looks public
     * without it.
     *
     * @param $ip string
     * @return bool
     */
    public static function isPrivateOrLocal($ip)
    {
        $ip = trim((string)$ip);

        if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        if (self::isCarrierGradeNat($ip)) {
            return true;
        }

        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /**
     * 100.64.0.0/10.
     *
     * @param $ip string
     * @return bool
     */
    private static function isCarrierGradeNat($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $long = ip2long($ip);

        if ($long === false) {
            return false;
        }

        return ($long & 0xFFC00000) === (ip2long('100.64.0.0') & 0xFFC00000);
    }
}
