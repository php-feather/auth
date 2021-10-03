<?php

namespace Feather\Auth\Guard;

use Feather\Support\Util\Token;
use Feather\Support\Contracts\IRequestParamBag as RequestBag;

/**
 * Description of TokenGuard
 *
 * @author fcarbah
 */
class TokenGuard implements IAuthGuard
{

    const TOKEN_NAME = 'x-auth-token';
    const TOKEN_REQUEST_PARAM = 'auth-token';

    /**
     * Number of minutes to expire after
     * @var int
     */
    protected $expire;

    /** @var Feather\Support\Contracts\IRequestParamBag * */
    protected $requestBag;

    public function forget(): void
    {
        header_remove(static::TOKEN_NAME);
        $this->requestBag->get(null)->remove(static::TOKEN_REQUEST_PARAM);
        $this->requestBag->post(null)->remove(static::TOKEN_REQUEST_PARAM);
    }

    /**
     *
     * @return string|null
     */
    public function getIdentifier()
    {
        $token = $this->getToken();
        return $token ? $token->getValue() : null;
    }

    /**
     *
     * @param string|int $identity
     * @return void
     */
    public function setIdentifier($identity): void
    {
        $token = new Token(static::TOKEN_NAME, $identity, $this->expire);

        $tokenStr = base64_encode(serialize($token));

        header(static::TOKEN_NAME . ': ' . $tokenStr);

        $this->requestBag->addItems([static::TOKEN_REQUEST_PARAM => $tokenStr], true);
    }

    /**
     *
     * @param RequestBag $bag
     * @return $this
     */
    public static function setRequestBag(RequestBag $bag)
    {
        $this->requestBag = $bag;
        return $this;
    }

    /**
     *
     * @return Token|null
     */
    protected function getToken()
    {
        $token = $this->requestBag->all(static::TOKEN_REQUEST_PARAM, null);

        if (!$token) {
            $token = $this->requestBag->header(static::TOKEN_NAME, null);
        }

        if (!$token) {
            return null;
        }

        $token = unserialize(base64_decode($token));

        if ($token instanceof Token) {
            if ($token->isExpired()) {
                $this->setIdentifier($token->getValue());
            }

            return $token;
        }

        return null;
    }

}
