<?php

namespace Octopuce\Acme\ChallengeSolver;

/**
 * Dns Challenge solver for DVSNI
 */
class Dns implements SolverInterface
{
    /**
     * Solve the challenge by placing a file in a web root folder
     *
     * @param string $token
     * @param string $key
     *
     * @return bool
     *
     * @throws \RuntimeException
     */
    public function solve($token, $key)
    {
        // @todo plug some dns api (gandi ?) management here

        return true;
    }

    /**
     * Solve the challenge by placing a file in a web root folder
     *
     * @param string $fqdn
     * @param string $token
     * @param string $key
     *
     * @return array
     */
    public function getChallengeInfo($fqdn, $token, $key)
    {
        $dnsInfo = sprintf('_acme-challenge.%s. 300 IN TXT "%s"',
            $fqdn,
            $key
        );

        return array(
            'info' => $dnsInfo,
            'keyAuthorization' => $key,
        );
    }

    /**
     * @inheritDoc
     */
    public function getType($forApiCall = false)
    {
        if ($forApiCall) {
            return 'dns';
        }

        return 'dns-01';
    }
}
