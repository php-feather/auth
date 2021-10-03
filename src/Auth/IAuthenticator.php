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
     * @return boolean
     */
    public function login(array $attributes): boolean;

    /**
     * Authenticate user using AuthUser object
     * @param \Feather\Auth\IAuthUser $user
     * @return boolean
     */
    public function loginUser(IAuthUser $user): boolean;

    /**
     * Authenticate user using identifier
     * @param string|int $id
     * @return boolean
     */
    public function loginWithId($id): boolean;

    /**
     * Logout authenticated user
     * @return boolean
     */
    public function logout(): boolean;

    /**
     * Get Authenticated User
     * @return \Feather\Auth\IAuthUser
     */
    public function user(): IAuthUser;
}
