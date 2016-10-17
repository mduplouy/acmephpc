<?php

namespace Octopuce\Acme;

interface CertificateInterface
{
    /**
     * Sign a certificate using api
     *
     * @param string $fqdn      The fully qualified domain name
     * @param array  $altNames  Alternative names
     *
     * @return self
     */
    public function sign($fqdn, array $altNames = array());

    /**
     * Revoke all certificates for given fqdn
     *
     * @param string $fqdn The fully qualified domain name
     *
     * @return self
     */
    public function revoke($fqdn);

    /**
     * Renew certificate for given fqdn
     *
     * @param string $fqdn The fully qualified domain name
     *
     * @return self
     */
    public function renew($fqdn);

    /**
     * Find a certificate by domain name
     *
     * @param string $fqdn
     *
     * @return self
     */
    public function findByDomainName($fqdn);

    /**
     * Return the raw content of current certificate
     *
     * @return string
     */
    public function __toString();
}
