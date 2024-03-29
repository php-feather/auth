<?php

namespace Feather\Auth;

use Feather\Auth\Authenticator;

/**
 * Description of Auth
 *
 * @author fcarbah
 */
class Authentication
{

    /** @var \Feather\Auth\Authenticator * */
    protected $authenticator;

    /**
     *
     * @param \Feather\Auth\Authenticator $authenticator
     */
    public function __construct(Authenticator $authenticator)
    {
        $this->authenticator = $authenticator;
    }

    /**
     *
     * @param array $attributes
     * @return bool
     */
    public function attempt(array $attributes)
    {
        return $this->authenticator->login($attributes);
    }

    /**
     *
     * @param string|int $id
     * @return bool
     */
    public function loginWithId($id)
    {
        return $this->authenticator->loginWithId($id);
    }

    /**
     *
     * @param \Feather\Auth\IAuthUser $user
     * @return bool
     */
    public function loginWithUser(IAuthUser $user)
    {
        return $this->authenticator->loginUser($user);
    }

    /**
     *
     * @param Authenticator $authenticator
     * @return $this
     */
    public function setAuthenticator(\Feather\Auth\Authenticator $authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }

    /**
     *
     * @return \Feather\Auth\IAuthUser|null
     */
    public static function user()
    {
        return $this->authenticator->user();
    }

}
