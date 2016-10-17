<?php

/*
 * This file is part of the ACME PHP Client Library
 * (C) 2015 Benjamin Sonntag <benjamin@octopuce.fr>
 * distributed under LPGL 2.1+ see LICENSE file
 */

namespace Octopuce\Acme\Ssl;

use Octopuce\Acme\CertificateInterface;

/**
 * Acme SSL interface
 * @author benjamin
 */
interface SslInterface
{
    /**
     * Generate a $length bits RSA private key
     *
     * @param  int    $lentgh  Length of the key
     *
     * @return array           An array containing key pair in PEM format
     *                         array ('publickey' => '..', 'privateKey' => '..').
     */
    public function generateRsaKey($length = 4096);

    /**
     * Generate a CSR for given fqdn & altnames
     *
     * @param string $fqdn
     * @param array  $altNames
     *
     * @return string The CSR in DER format
     */
    public function generateCsr($fqdn, array $altNames = array());

    /**
     * Return a new RSA object instance
     *
     * @return \phpseclib\Crypt\RSA
     */
    public function getRsa();

    /**
     * Get the thumbprint of a RSA public key
     *
     * @param string $publicKey
     *
     * @return string
     */
    public function getPublicKeyThumbprint($publicKey);

    /**
     * Load a certificate
     *
     * @param CertificateInterface $certificate
     *
     * @return self
     */
    public function loadCertificate(CertificateInterface $certificate);

    /**
     * Get the certificate expiration timestamp
     *
     * @param CertificateInterface $certificate
     *
     * @return int
     */
    public function getCertificateExpirationDate();
}
