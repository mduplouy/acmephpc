<?php

namespace Octopuce\Acme;

use Octopuce\Acme\Exception\CertificateNotFoundException;
use Octopuce\Acme\Exception\ApiBadResponseException;

class Certificate extends AbstractEntity implements CertificateInterface, StorableInterface
{
    /**
     * FQDN
     * @var string
     */
    private $fqdn;

    /**
     * Alt names
     * @var array
     */
    private $altNames = array();

    /**
     * Expiration timestamp
     * @var int
     */
    private $expireAt;

    /**
     * Certificate string
     * @var string
     */
    private $certificate;

    /**
     * @inheritDoc
     */
    public function sign($fqdn, array $altNames = array())
    {
        // Check all provided names
        $this->checkFqdn($fqdn);
        foreach ($altNames as $name) {
            $this->checkFqdn($name);
        }

        $this->fqdn     = $fqdn;
        $this->altNames = $altNames;

        // Generate a proper CSR
        $csr = $this->ssl->generateCsr(
            $fqdn,
            $altNames
        );

        // Call API and save
        try {

            $this->certificate = $this->httpClient->signCertificate(
                \JOSE_URLSafeBase64::encode($csr),
                $this->getPrivateKey(),
                $this->getPublicKey()
            );

            $this->expireAt = $this->ssl->loadCertificate($this)->getCertificateExpirationDate();

            $this->save('certificate');

        } catch (CertificateNotYetAvailableException $e) {
            // @todo: handle retry here
            $retryUrl = $e->getMessage();

        }

        return $this;
    }

    /**
     * @inheritDoc
     *
     * @throws CertificateNotFoundException
     */
    public function findByDomainName($fqdn)
    {
        $this->checkFqdn($fqdn);

        $data = $this->storage->findCertificateByDomain($fqdn);

        if (empty($data)) {
            throw new CertificateNotFoundException(
                sprintf('Unable to find certificate matching %s domain name', $fqdn),
                12
            );
        }

        return $this->setDataFromArray($data);
    }

    /**
     * @inheritDoc
     */
    public function revoke($fqdn)
    {
        $this->findByDomainName($fqdn);

        $response = $this->httpClient->revokeCertificate(
            \JOSE_URLSafeBase64::encode($this->certificate),
            $this->getPrivateKey(),
            $this->getPublicKey()
        );

        $this->storage->delete($this, 'certificate');

        return $this;
    }

    /**
     * @inheritDoc
     */
    public function renew($fqdn)
    {
        $this->findByDomainName($fqdn);

        $this->httpClient->revokeCertificate(
            \JOSE_URLSafeBase64::encode($this->certificate),
            $this->getPrivateKey(),
            $this->getPublicKey()
        );

        $this->sign($fqdn, $this->altNames);

        return $this;
    }

    /**
     * Set data from array
     *
     * @param array $data
     *
     * @return $this
     */
    private function setDataFromArray(array $data)
    {
        $this->id          = $data['id'];
        $this->fqdn        = $data['fqdn'];
        $this->altNames    = $data['altNames'];
        $this->certificate = base64_decode($data['certificate']);

        return $this;
    }

    /**
     * Get storable data
     *
     * @return array
     */
    public function getStorableData()
    {
        return array(
            'id'          => $this->id,
            'fqdn'        => $this->fqdn,
            'altNames'    => $this->altNames,
            'expireAt'    => $this->expireAt,
            'certificate' => base64_encode($this->certificate),
        );
    }

    /**
     * @inheritDoc
     */
    public function __toString()
    {
        return $this->certificate;
    }

}
