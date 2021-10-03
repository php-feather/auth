<?php

namespace Feather\Auth;

use Feather\Support\Util\Bag;

/**
 * Description of AuthUser
 *
 * @author fcarbah
 */
class AuthUser implements IAuthUser
{

    /** @var \Feather\Support\Util\Bag * */
    protected $attributes;

    /**
     *
     * @param array|object $source
     */
    public function __construct($source = [])
    {
        $this->attributes = new Bag();
        $this->setAttributes($source);
    }

    /**
     *
     * @return \Feather\Support\Util\Bag
     */
    public function getAttributes()
    {
        return $this->attributes;
    }

    /**
     *
     * @param array|object $source
     * @return $this
     */
    public function setAttributes($source)
    {
        if (is_object($source)) {
            $source = get_object_vars($source);
        }
        $this->attributes->addItems($source);

        return $this;
    }

    /**
     *
     * @param string $name
     * @return mixed
     */
    public function __get(string $name)
    {
        return $this->{$name} ?? $this->attributes->get($name);
    }

}
