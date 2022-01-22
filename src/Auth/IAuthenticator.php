<?php

namespace Feather\Auth;

/**
 *
 * @author fcarbah
 */
interface IAuthenticator
{

    /**
     * Get error code if login failed
     * @return int
     */
    public function getErrorCode(): int;

    /**
     * Authenticate user using attributes
     * @param array $attributes
     * @return bool
     */
    public function login(array $attributes): bool;

    /**
     * Authenticate user using AuthUser object
     * @param \Feather\Auth\IAuthUser $user
     * @return bool
     */
    public function loginUser(IAuthUser $user): bool;

    /**
     * Authenticate user using identifier
     * @param string|int $id
     * @return bool
     */
    public function loginWithId($id): bool;

    /**
     * Logout authenticated user
     * @return bool
     */
    public function logout(): bool;

    /**
     * Get Authenticated User
     * @return \Feather\Auth\IAuthUser|null
     */
    public function user();
}
