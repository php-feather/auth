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

    protected $identity = 'id';

    const SESS_NAME = 'AUTH_USER';

    public function forget(): void
    {
        Session::remove(static::SESS_NAME . $this->identifier);
    }

    /**
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        return Session::get(static::SESS_NAME);
    }

    /**
     *
     * @param string|int $identifier
     */
    public function setIdentifier($identifier): void
    {
        Session::set(static::SESS_NAME, $identifier);
    }

    /**
     *
     * @param string $identity
     * @return $this
     */
    public function setIdentity(string $identity)
    {
        $this->identity = $identity;
        return $this;
    }

}
