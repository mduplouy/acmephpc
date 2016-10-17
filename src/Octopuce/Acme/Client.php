<?php

namespace Octopuce\Acme;

use Pimple\Container;
use Octopuce\Acme\Exception\ApiCallErrorException;
use Octopuce\Acme\Exception\ApiBadResponseException;
use Octopuce\Acme\Exception\AccountNotFoundException;
use Symfony\Component\Finder\Finder;

class Client extends Container implements ClientInterface
{
    /**
     * User agent string
     */
    const USER_AGENT = 'ACME PHP Client 1.0';

    /**
     * Maximum time we try to use a nonce before generating a new one.
     */
    const NONCE_MAX_AGE = 86400;

    /**
     * Default config values
     * @var array
     */
    private $defaultValues = array(
        'params' => array(
            'api' => 'https://acme.api.letsencrypt.org',
            'storage' => array(
                'type' => 'filesystem',
                'database' => array(
                    'dsn' => '',
                    'table_prefix' => 'acme',
                ),
            ),
            'challenge' => array(
                'type' => 'http',
                'config' => array(
                    'doc-root' => '',
                    'target-path' => '/tmp/',
                ),
            ),
            'account' => null,
        ),
    );

    /**
     * Initialized
     * @var bool
     */
    private $initialized = false;

    /**
     * @inheritDoc
     */
    public function __construct(array $values = array())
    {
        // Must construct parent class now to have factories & protected available
        parent::__construct();

        $this->defaultValues['params']['storage']['filesystem'] = __DIR__.'/../../../var';

        $this->defaultValues['storage'] = function ($c) {

            $storageConfig = $c['params']['storage'];

            $factory = new Storage\Factory(array(
                'filesystem' => function () use ($storageConfig) {
                    return new Storage\FileSystem($storageConfig['filesystem'], new Finder);
                },
                'database' => function () use ($storageConfig) {
                    return new Storage\DoctrineDbal(
                        $storageConfig['database']['dsn'],
                        $storageConfig['database']['table_prefix']
                    );
                },
            ));

            return $factory->create($storageConfig['type']);
        };

        $this->defaultValues['rsa'] = $this->factory(function () {
            return new \phpseclib\Crypt\RSA;
        });

        $this->defaultValues['ssl'] = function ($c) {
            return new Ssl\PhpSecLib($c->raw('rsa'));
        };

        $this->defaultValues['http-client'] = function ($c) {
            return new Http\GuzzleClient(
                new \Guzzle\Http\Client,
                $c->raw('rsa'),
                $c['storage']
            );
        };

        $this->defaultValues['certificate'] = function ($c) {
            return new Certificate($c['storage'], $c['http-client'], $c['ssl']);
        };

        $this->defaultValues['account'] = function ($c) {
            return new Account($c['storage'], $c['http-client'], $c['ssl']);
        };

        $this->defaultValues['ownership'] = $this->factory(function ($c) {
            return new Ownership($c['storage'], $c['http-client'], $c['ssl']);
        });

        $this->defaultValues['challenge-solver-http'] = function ($c) {
            return new \Octopuce\Acme\ChallengeSolver\Http($c['params']['challenge']['config']);
        };
        $this->defaultValues['challenge-solver-dns'] = function ($c) {
            return new \Octopuce\Acme\ChallengeSolver\Dns($c['params']['challenge']['config']);
        };

        /*
        $values['challenge-solver-dvsni'] = function () {
            return new Octopuce\Acme\ChallengeSolver\DvSni;
        };
        */

        // Override default values with provided config
        $values = array_replace_recursive($this->defaultValues, $values);

        foreach ($values as $key => $value) {
            $this->offsetSet($key, $value);
        }
    }

    /**
     * Init data by calling enumerate
     *
     * @return $this
     */
    private function init()
    {
        if (!$this->initialized) {

            // Load nonce from storage and check for validity
            $status = $this['storage']->loadStatus();

            if (empty($status['nonce']) || $status['noncets'] < (time() - self::NONCE_MAX_AGE)) {
                // If nonce is expired, reload it from enumerate
                $response = $this->enumerate();

                $status['nonce'] = (string) $response->getHeader('replay-nonce');
                $status['apiurls'] = (string) $response->getBody();

                // Store the new nonce and endpoints
                $this['storage']->updateStatus($status['nonce'], $status['apiurls']);
            }

            $this['http-client']
                ->setEndPoints(
                    json_decode($status['apiurls'], true)
                )
                ->setNonce($status['nonce']);

            $this->initialized = true;

            if (!empty($this['params']['account'])) {
                try {
                    $this['account']->load($this['params']['account']);
                } catch (AccountNotFoundException $e) {
                    $this->newAccount($this['params']['account']);
                }
            }

        }

        return $this;
    }

    /**
     * Enumerate api endpoints and get a nonce
     *
     * @return string The replay-nonce header value
     */
    public function enumerate()
    {
        // Call directory endpoint
        return $this['http-client']->enumerate($this['params']['api']);
    }

    /**
     * Load account
     *
     * @param string $mailto Email of the account to be loaded
     *
     * @return $this
     */
    public function loadAccount($mailto)
    {
        $this['account']->load($mailto);

        return $this;
    }

    /**
     * Create and register a new account then store it
     *
     * @param string $mailto     Owner email address
     * @param string $tel        Optional phone number
     * @param string $privateKey Optional private key to use otherwise a new one will be created
     * @param string $publicKey  Optional public key to use otherwise a new one will be created
     *
     * @return $this
     */
    public function newAccount($mailto, $tel = null, $privateKey = null, $publicKey = null)
    {
        $this->init();

        // Generate new key pair from ssl service if not provided
        if (null === $privateKey || null === $publicKey) {
            $keys = $this['ssl']->generateRsaKey();
            $privateKey = $keys['privatekey'];
            $publicKey = $keys['publickey'];
        }

        $this['account']
            ->setKeys($privateKey, $publicKey)
            ->register($mailto, $tel);

        return $this;
    }

    /**
     * Ask for new ownership
     *
     * @param string $value Value of ownership (usually a fqdn)
     *
     * @return $this
     */
    public function newOwnership($value)
    {
        $this->init();

        $account = $this['account'];

        $this['ownership']
            ->setKeys($account->getPrivateKey(), $account->getPublicKey())
            ->register($value);

        return $this;
    }

    /**
     * Get challenge data to solve it manually
     *
     * @param string $fqdn                   FQDN
     * @param string $overrideChallengeType  Force this challenge type (use config if empty)
     *
     * @return array The data needed to solve the challenge
     */
    public function getChallengeData($fqdn, $overrideChallengeType = null)
    {
        $challengeSolver = $this->getChallengeSolver($overrideChallengeType);

        $this->init();

        $account = $this['account'];

        return $this['ownership']
            ->setKeys($account->getPrivateKey(), $account->getPublicKey())
            ->getChallengeData(
                $challengeSolver,
                $fqdn
            );
    }

    /**
     * Challenge an existing ownership
     *
     * @param string $fqdn                   FQDN to challenge
     * @param string $overrideChallengeType  Force this challenge type (use config if empty)
     * @param bool   $doSolverAction         Run the solver action if exists ? (ie generate file for http challenge)
     *
     * @return $this
     *
     * @throws \InvalidArgumentException
     */
    public function challengeOwnership($fqdn, $overrideChallengeType = null, $doSolverAction = true)
    {
        $challengeSolver = $this->getChallengeSolver($overrideChallengeType);

        $this->init();

        $account = $this['account'];

        $this['ownership']
            ->setKeys($account->getPrivateKey(), $account->getPublicKey())
            ->challenge(
                $challengeSolver,
                $fqdn,
                $doSolverAction
            );

        return $this;
    }

    /**
     * Get the challenge solver instance
     *
     * @param string $forceType
     *
     * @return \Octopuce\Acme\ChallengeSolver\SolverInterface
     */
    private function getChallengeSolver($forceType)
    {
        try {
            $challengeType = $this['params']['challenge']['type'];
            if (null !== $forceType) {
                $challengeType = $forceType;
            }

            $challengeSolver = $this->offsetGet('challenge-solver-'.$challengeType);

        } catch (\Exception $e) {
            throw new \InvalidArgumentException(sprintf('Challenge solver type %s is not supported', $challengeType));
        }

        return $challengeSolver;
    }

    /**
     * Sign a certificate for specified FQDN
     *
     * @param string $fqdn       FQDN to challenge
     * @param array  $altNames   Alternative names
     *
     * @return string The certificate content
     */
    public function signCertificate($fqdn, array $altNames = array())
    {
        $this->init();

        $account = $this['account'];

        return (string) $this['certificate']
            ->setKeys($account->getPrivateKey(), $account->getPublicKey())
            ->sign($fqdn);
    }

    /**
     * Get the certificate for a given FQDN
     *
     * @return string The certificate content
     */
    public function getCertificate($fqdn)
    {
        return (string) $this['certificate']->findByDomainName($fqdn);
    }

    /**
     * Revoke certificate for specified FQDN
     *
     * @param string $fqdn
     *
     * @return $this
     */
    public function revokeCertificate($fqdn)
    {
        $this->init();

        $account = $this['account'];

        $this['certificate']
            ->setKeys($account->getPrivateKey(), $account->getPublicKey())
            ->revoke($fqdn);

        return $this;
    }

    /**
     * Renew certificate for specified FQDN
     *
     * @param string $fqdn
     *
     * @return string The new certificate content
     */
    public function renewCertificate($fqdn)
    {
        $this->init();

        $account = $this['account'];

        $this['certificate']
            ->setKeys($account->getPrivateKey(), $account->getPublicKey())
            ->renew($fqdn);

        return (string) $this['certificate'];
    }

}
