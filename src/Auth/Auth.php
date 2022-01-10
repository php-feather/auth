<?php

namespace Feather\Auth;

use Feather\Support\Contracts\IProvider;
use Feather\Auth\IAuthenticator;

/**
 * Description of Auth
 *
 * @author fcarbah
 */
class Auth
{

    /** @var \Feather\Support\Contracts\IProvider * */
    protected static $provider;

    /** @var Feather\Auth\IAuthenticator * */
    protected static $authenticator;

    public static function __callStatic($name, $arguments)
    {
        if (method_exists(static::$authenticator, $name)) {
            return call_user_func_array([static::$authenticator, $name], $arguments);
        }
    }

    public static function boot(Authenticator $authenticator)
    {
        if (!static::$authenticator instanceof Authenticator) {
            static::$authenticator = $authenticator;
        }
    }

    /**
     *
     * @param array $attributes
     * @return boolean
     * @throws AuthException
     */
    public static function attempt(array $attributes)
    {
        if (empty($attributes)) {
            throw new AuthException('No attributes provided to authenticate with', 100);
        }

        return static::$authenticator->login($attributes);
    }

    /**
     *
     * @return int
     */
    public static function getErrorCode()
    {
        return static::$authenticator->getErrorCode();
    }

    /**
     *
     * @param string|int $id
     * @return bool
     */
    public static function loginWithId($id)
    {
        return static::$authenticator->loginWithId($id);
    }

    /**
     *
     * @param \Feather\Auth\IAuthUser $user
     * @return bool
     */
    public static function loginWithUser(IAuthUser $user)
    {
        return static::$authenticator->loginUser($user);
    }

    /**
     *
     * @return bool
     */
    public static function logOut()
    {
        return static::$authenticator->logout();
    }

    /**
     *
     * @return \Feather\Auth\IAuthUser|null
     */
    public static function user()
    {
        return static::$authenticator->user();
    }

}
