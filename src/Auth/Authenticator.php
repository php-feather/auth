<?php

namespace Feather\Auth;

/**
 * Description of Authenticator
 *
 * @author fcarbah
 */
abstract class Authenticator implements IAuthenticator
{

    protected int $errorCode = 0;

    /**
     * Get error message
     * @return string
     */
    public abstract function getErrorMessage(): string;
}
