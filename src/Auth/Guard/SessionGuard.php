<?php

namespace Feather\Auth\Guard;

use Feather\Session\Session;

/**
 * Description of SessionGuard
 *
 * @author fcarbah
 */
class SessionGuard implements IAuthGuard
{

    protected $identifier = 'id';

    const KEY_PREFIX = 'AUTH_';

    public function forget(): void
    {
        Session::remove(static::KEY_PREFIX . $this->identifier);
    }

    public function getIdentifier(): \mixed
    {
        return Session::get(static::KEY_PREFIX . $this->identifier);
    }

    /**
     *
     * @param string|int $identifier
     */
    public function setIdentifier($identifier): void
    {
        Session::set(static::KEY_PREFIX . $this->identifier, $identifier);
    }

}
