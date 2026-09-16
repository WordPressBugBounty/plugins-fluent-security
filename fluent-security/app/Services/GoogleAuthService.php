<?php

namespace FluentAuth\App\Services;

use FluentAuth\App\Helpers\Arr;
use FluentAuth\App\Helpers\Helper;

class GoogleAuthService
{
    public static function getAuthRedirect($state = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        $params = [
            'response_type' => 'code',
            'client_id'     => $config['google_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'scope'         => 'openid%20email%20profile',
            'state'         => $state,
            'nonce'         => wp_generate_uuid4()
        ];

        return add_query_arg($params, 'https://accounts.google.com/o/oauth2/v2/auth');
    }

    public static function getTokenByCode($code)
    {
        $postUrl = 'https://oauth2.googleapis.com/token';
        $params = self::getAuthConfirmParams($code);

        $response = wp_remote_post($postUrl, [
            'body'    => $params,
            'headers' => [
                'Accept' => 'application/json'
            ]
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!$data || empty($data['id_token'])) {
            return new \WP_Error('token_error', __('Sorry! There has an error when fetching token for google authentication. Please try again', 'fluent-security'));
        }

        return Arr::get($data, 'id_token');
    }


    public static function verifyClientToken($idToken)
    {
        $postUrl = 'https://oauth2.googleapis.com/tokeninfo';

        $response = wp_remote_post($postUrl, [
            'body'    => [
                'id_token' => $idToken
            ],
            'headers' => [
                'Accept' => 'application/json'
            ]
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        $config = Helper::getSocialAuthSettings('edit');

        $clientId = (string)Arr::get($config, 'google_client_id');
        $audience = (string)Arr::get($data, 'aud');

        /*
         * Both have to be present before comparing. A misconfigured site leaves the
         * client id empty, and an error response from tokeninfo carries no audience -
         * comparing those two would match and wave the token through.
         */
        if (!is_array($data) || !$clientId || !$audience || !hash_equals($clientId, $audience)) {
            return new \WP_Error('token_error', __('Sorry! Invalid token audience for google authentication. Please try again', 'fluent-security'));
        }

        /*
         * The email is what we match an existing WordPress account on, so an unverified
         * one would mean anybody able to put an address on a Google account could sign
         * in as whoever holds that address here. Google documents this claim as the
         * thing to check before treating the email as an identity.
         */
        if (!self::isVerifiedEmail($data)) {
            return new \WP_Error('email_unverified', __('Your Google account email address is not verified. Please verify it with Google and try again', 'fluent-security'));
        }

        return $data;
    }

    /**
     * tokeninfo reports the claim as the string "true", an id_token payload as a bool.
     *
     * @param $data array
     * @return bool
     */
    private static function isVerifiedEmail($data)
    {
        $verified = Arr::get($data, 'email_verified', Arr::get($data, 'verified_email'));

        if (is_string($verified)) {
            return strtolower($verified) === 'true';
        }

        return $verified === true;
    }


    public static function getAuthConfirmParams($code = '')
    {
        $config = Helper::getSocialAuthSettings('edit');

        return [
            'client_id'     => $config['google_client_id'],
            'redirect_uri'  => self::getAppRedirect(),
            'code'          => $code,
            'grant_type'    => 'authorization_code',
            'client_secret' => $config['google_client_secret']
        ];
    }

    public static function getDataByIdToken($token)
    {
        $verifiedData = self::verifyClientToken($token);

        if (is_wp_error($verifiedData)) {
            return $verifiedData;
        }

        if (empty($verifiedData['email'])) {
            return new \WP_Error('payload_error', __('Sorry! There has an error when fetching data for google authentication. Please try again', 'fluent-security'));
        }

        $username = Arr::get($verifiedData, 'email');
        $emailArray = explode('@', $username);
        if (count($emailArray)) {
            $username = $emailArray[0];
        }

        return [
            'full_name' => Arr::get($verifiedData, 'name'),
            'email'     => Arr::get($verifiedData, 'email'),
            'username'  => $username
        ];
    }

    public static function getAppRedirect()
    {

        if (defined('FLUENT_AUTH_SOCIAL_REDIRECT_URL') && FLUENT_AUTH_SOCIAL_REDIRECT_URL) {
            return FLUENT_AUTH_SOCIAL_REDIRECT_URL;
        }

        return wp_login_url();
    }
}
