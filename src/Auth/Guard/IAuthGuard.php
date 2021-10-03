<?php

namespace Feather\Auth\Guard;

/**
 *
 * @author fcarbah
 */
interface IAuthGuard
{

    /**
     * Get identifier value
     * @return mixed
     */
    public function getIdentifier(): mixed;

    /**
     * Set identifier value
     * @param int|string $identity
     * @return void
     */
    public function setIdentifier($identity): void;

    /**
     * Clear Identifier
     * @return void
     */
    public function forget(): void;
}
