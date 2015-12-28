<?php

/*
 * This file is part of the ACME PHP Client Library
 * (C) 2015 Benjamin Sonntag <benjamin@octopuce.fr>
 * distributed under LPGL 2.1+ see LICENSE file
 */

namespace Octopuce\Acme\Storage;

use Octopuce\Acme\StorableInterface;

/**
 * Acme DB storage interface
 * @author benjamin
 */
interface StorageInterface
{
    /**
     * Save entity
     *
     * @param StorableInterface $obj
     * @param string            $tableKey
     *
     * @return int The object ID
     */
    public function save(StorableInterface $obj, $tableKey);

    /**
     * Load status
     *
     * @return array|false
     */
    public function loadStatus();

    /**
     * Update status
     *
     * @param string $nonce
     * @param string $apiUrls
     *
     * @return int
     */
    public function updateStatus($nonce, $apiUrls);

    /**
     * Find any object by Id
     *
     * @param int $id
     *
     * @return array|false
     */
    public function findById($id, $type);
}
