<?php

namespace Feather\Auth\Guard;

use Feather\Support\Contracts\IApp;
use Feather\Support\Contracts\IEncrypter;
use Feather\Support\Contracts\IRequestParamBag as RequestBag;

/**
 * Description of CookieGuard
 *
 * @author fcarbah
 */
class CookieGuard implements IAuthGuard
{

    const COOKIE_NAME = 'auth_user';

    /** @var bool * */
    protected $secure = false;

    /** @var bool * */
    protected $httpOnly = true;

    /** @var int * */
    protected $expire;

    /** @var string * */
    protected $domain = null;

    /** @var string * */
    protected $sameSite = null;

    /** @var \Feather\Support\Contracts\IEncrypter * */
    protected $encrypter;

    /** @var Feather\Support\Contracts\IRequestParamBag * */
    protected $cookieBag;

    public function forget(): void
    {
        setcookie(static::COOKIE_NAME, '', -1000, '/', $this->domain, $this->secure, $this->httpOnly);
        $this->cookieBag->cookie(null, null)->remove(static::COOKIE_NAME);
    }

    /**
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        $identifier = $this->cookieBag->cookie(static::COOKIE_NAME, null);

        if ($this->encrypter && $identifier) {
            $decrypted  = $this->encrypter->decrypt($identifier);
            $identifier = $decrypted ? $decrypted : $identifier;
        }

        return $identifier;
    }

    /**
     *
     * @param RequestBag $requestBag
     * @return $this
     */
    public function setCookieBag(RequestBag $requestBag)
    {
        $this->cookieBag = $requestBag;
        return $this;
    }

    /**
     *
     * @param string $name
     * @return $this
     */
    public function setCookieName(string $name)
    {
        $this->cookieName = $name;
        return $this;
    }

    /**
     *
     * @param string|null $domain
     * @return $this
     */
    public function setDomain(?string $domain)
    {
        $this->domain = $domain;
        return $this;
    }

    /**
     *
     * @param \Feather\Support\Contracts\IEncrypter $encrypter
     * @return $this
     */
    public function setEncrypter(IEncrypter $encrypter)
    {
        $this->encrypter = $encrypter;
        return $this;
    }

    /**
     *
     * @param int $expire
     * @return $this
     */
    public function setExpireTime(int $expire)
    {
        $this->expire = $expire;
        return $this;
    }

    /**
     *
     * @param bool $httpOnly
     * @return $this
     */
    public function setHttpOnly(bool $httpOnly)
    {
        $this->httpOnly = $httpOnly;
        return $this;
    }

    /**
     *
     * @param string|int $identity
     * @return void
     */
    public function setIdentifier($identity): void
    {
        if ($this->encrypter) {
            $identity = $this->encrypter->encrypt($identity);
        }

        $options = [
            'expires'  => $this->expire,
            'path'     => '/',
            'domain'   => $this->domain,
            'secure'   => $this->secure,
            'httponly' => $this->httpOnly,
            'samesite' => $this->sameSite
        ];

        setcookie(static::COOKIE_NAME, $identity, $options);
    }

    /**
     *
     * @param string|null $sameSite
     * @return $this
     */
    public function setSameSite(?string $sameSite)
    {
        $allowedValues = ['lax', 'strict', 'none', null];

        if (in_array(strtolower($sameSite), $allowedValues)) {
            $this->sameSite = $sameSite;
        }

        return $this;
    }

    /**
     *
     * @param bool $secure
     * @return $this
     */
    public function setSecure(bool $secure)
    {
        $this->secure = $secure;
        return $this;
    }

}
