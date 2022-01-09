<?php

namespace Feather\Auth;

use Feather\Support\Database\IConnection;
use PDO;

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
    protected $dbTable = 'users';

    /** @var \Feather\Auth\IAuthUser * */
    protected $user;

    /** @var \Feather\Support\Database\IConnection * */
    protected $connection;

    /** @var \Feather\Auth\Guard\IAuthGuard * */
    protected $guard;

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
            default:
                return '';
        }
    }

    /**
     *
     * @param array $attributes
     * @return boolean
     */
    public function login(array $attributes): boolean
    {
        if (empty($attributes)) {
            return false;
        }

        $user = $this->getUser($attributes);

        if (!$user) {
            return false;
        }

        $this->user = new AuthUser($user);

        $this->guard->setIdentifier($this->user->{$this->identityField});

        return true;
    }

    /**
     *
     * @param \Feather\Auth\IAuthUser $user
     * @return boolean
     */
    public function loginUser(IAuthUser $user): boolean
    {
        $identifier = $user->{$this->identityField};
        return $this->login([$this->identityField => $identifier]);
    }

    /**
     *
     * @param string|int $id
     * @return boolean
     */
    public function loginWithId($id): boolean
    {
        return $this->login([$this->identityField => $id]);
    }

    /**
     *
     * @return boolean
     */
    public function logout(): boolean
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
     * @return \Feather\Auth\IAuthUser
     */
    public function user(): \Feather\Auth\IAuthUser
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
        $sql = "select * from {$this->dbTable} where ";
        $where = [];

        foreach ($attributes as $key => $val) {
            $where[] = ["$key = :$key"];
        }

        $sql .= implode(' and ', $where) . ' limit 1';

        $stmt = $this->connection->getPdo()->prepare($sql);

        foreach ($attributes as $key => $val) {
            $stmt->bindValue(":$key", $val);
        }

        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

}
