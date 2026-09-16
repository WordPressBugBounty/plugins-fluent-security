<?php

namespace FluentAuth\App\Services\TwoFa;

/**
 * The kinds of proof a login step can provide.
 *
 * Two factor authentication only means something when the second step proves
 * something the first one did not. A magic link and an emailed code are both proof of
 * the same mailbox, so asking for both is one factor collected twice - all friction,
 * no security. Every login route therefore declares what it proved, and the dispatcher
 * only asks for a method that proves something else.
 *
 * The reverse matters more: an authenticator app or a passkey proves a device, which
 * no email or social login ever does, so those stay required however the user got here.
 * Skipping them for magic login would quietly turn the mailbox into the only thing
 * standing between an attacker and an account that asked for a stronger factor.
 */
class AuthFactor
{
    /**
     * A password - something the user knows.
     */
    const KNOWLEDGE = 'knowledge';

    /**
     * Control of the account's mailbox - magic links and emailed codes.
     */
    const EMAIL = 'email';

    /**
     * A registered device - authenticator apps and passkeys.
     */
    const DEVICE = 'device';

    /**
     * An external identity provider - Google, GitHub, Facebook.
     */
    const IDP = 'idp';
}
