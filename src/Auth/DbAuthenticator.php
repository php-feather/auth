<?php

namespace Feather\Auth;

use Feather\Support\Database\IConnection;
use PDO;
use Feather\Security\Hash;

/**
 * Description of DbAuthenticator
 *
 * @author fcarbah
 */
class DbAuthenticator extends Authenticator
{

    /** @var string * */
    protected $identityField = 'id';

    /** @var string * */
    protected $passwordField = 'password';

    /** @var string * */
    protected $dbTable = 'users';

    /** @var \Feather\Auth\IAuthUser * */
    protected $user;

    /** @var \Feather\Support\Database\IConnection * */
    protected $connection;

    /** @var \Feather\Auth\Guard\IAuthGuard * */
    protected $guard;

    /**
     * @var array|string
     * Callable (function/Object,method) names that accepts 2 arguments and returns a bool:
     * 1. hashed password as the first argument
     * 2. plain text password as the second argument
     * */
    protected $hashFunc;

    /**
     * Get error code
     * @return int
     */
    public function getErrorCode(): int
    {
        return $this->errorCode;
    }

    /**
     * Get error message
     * @return string
     */
    public function getErrorMessage(): string
    {
        switch ($this->errorCode) {
            case 1:
                return 'User not found';
            case 2:
                return 'Incorrect password';
            default:
                return '';
        }
    }

    /**
     *
     * @param array $attributes
     * @return bool
     */
    public function login(array $attributes): bool
    {
        if (empty($attributes)) {
            return false;
        }

        $checkPassword = false;

        if (isset($attributes[$this->passwordField])) {
            $password      = $attributes[$this->passwordField];
            unset($attributes[$this->passwordField]);
            $checkPassword = true;
        }

        $user = $this->getUser($attributes);

        if (!$user) {
            $this->errorCode = 1;
            return false;
        }

        $this->user = new AuthUser($user);

        if ($checkPassword && !$this->verifyPassword($this->user, $password)) {
            $this->errorCode = 2;
            return false;
        }

        $this->guard->setIdentifier($this->user->{$this->identityField});

        return true;
    }

    /**
     *
     * @param \Feather\Auth\IAuthUser $user
     * @return bool
     */
    public function loginUser(IAuthUser $user): bool
    {
        $identifier = $user->{$this->identityField};
        return $this->login([$this->identityField => $identifier]);
    }

    /**
     *
     * @param string|int $id
     * @return bool
     */
    public function loginWithId($id): bool
    {
        return $this->login([$this->identityField => $id]);
    }

    /**
     *
     * @return bool
     */
    public function logout(): bool
    {
        $this->user = null;
        $this->guard->forget();
        return true;
    }

    /**
     *
     * @param string $fieldname
     * @return $this
     */
    public function setIdentityField(string $fieldname)
    {
        $this->identityField = $fieldname;
        return $this;
    }

    /**
     *
     * @param IConnection $connection
     * @return $this
     */
    public function setConnection(\Feather\Support\Database\IConnection $connection)
    {
        $this->connection = $connection;
        return $this;
    }

    /**
     *
     * @param \Feather\Auth\Guard\IAuthGuard $guard
     * @return $this
     */
    public function setGuard(Guard\IAuthGuard $guard)
    {
        $this->guard = $guard;
        return $this;
    }

    /**
     *
     * @param string|array $hashMethod
     * Callable (function/Object,method) name that accepts 2 arguments and returns a bool:
     * 1. hashed password as the first argument
     * 2. plain text password as the second argument
     * @return $this
     */
    public function setHashMethod($hashMethod)
    {
        $this->hashFunc = $hashMethod;
        return $this;
    }

    /**
     *
     * @param string $passwordField
     * @return $this
     */
    public function setPasswordField(string $passwordField)
    {
        $this->passwordField = $passwordField;
        return $this;
    }

    /**
     *
     * @param string $table
     * @return $this
     */
    public function setTable(string $table)
    {
        $this->dbTable = $table;
        return $this;
    }

    /**
     * Get Authenticated user
     * @return \Feather\Auth\IAuthUser|null
     */
    public function user()
    {
        $identifier = $this->guard->getIdentifier();

        if ($identifier && $user = $this->getUser([$this->identityField => $identifier])) {
            $this->user = new AuthUser($user);
        }

        return $this->user;
    }

    /**
     *
     * @param array $attributes
     * @return array|null
     */
    protected function getUser(array $attributes)
    {
        $sql   = "select * from {$this->dbTable} where ";
        $where = [];

        foreach ($attributes as $key => $val) {
            $where[] = "$key = :$key";
        }

        $sql .= implode(' and ', $where) . ' limit 1';

        $stmt = $this->connection->getPdo()->prepare($sql);

        foreach ($attributes as $key => $val) {
            $stmt->bindValue(":$key", $val);
        }

        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    /**
     *
     * @param \Feather\Auth\IAuthUser $user
     * @param string $password
     * @return bool
     */
    protected function verifyPassword(IAuthUser $user, string $password)
    {
        if (!$this->hashFunc) {
            return Hash::compare($user->{$this->passwordField}, $password);
        }

        return call_user_func_array($this->hashFunc, [$user->{$this->passwordField}, $password]);
    }

}
