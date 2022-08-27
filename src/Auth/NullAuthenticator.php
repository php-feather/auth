<?php

namespace Feather\Auth;

/**
 * Description of NullAuthenticator
 *
 * @author fcarbah
 */
class NullAuthenticator extends Authenticator
{

    public function getErrorCode(): int
    {
        return 0;
    }

    public function getErrorMessage(): string
    {
        return '';
    }

    public function login(array $attributes): bool
    {
        return false;
    }

    public function loginUser(IAuthUser $user): bool
    {
        return false;
    }

    public function loginWithId($id): bool
    {
        return false;
    }

    public function logout(): bool
    {
        return false;
    }

    public function user()
    {
        return null;
    }

}
