<?php

namespace Gos\Bundle\WebSocketBundle\Client\Auth;

use Doctrine\ORM\EntityManager;
use Gos\Bundle\WebSocketBundle\Client\ClientStorageInterface;
use Gos\Bundle\WebSocketBundle\Client\Exception\StorageException;
use Psr\Log\LoggerInterface;
use Ratchet\ConnectionInterface;
use Symfony\Component\HttpKernel\Log\NullLogger;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class WebsocketAuthenticationProvider implements WebsocketAuthenticationProviderInterface
{
    /**
     * @var SecurityContextInterface|TokenStorageInterface
     */
    protected $tokenStorage;

    /**
     * @var array
     */
    protected $firewalls;

    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var ClientStorageInterface
     */
    protected $clientStorage;

    /**
     * @var string
     */
    private $encryptionMethod;

    /**
     * @var string
     */
    private $secretHash;

    /**
     * @var EntityManager
     */
    private $em;

    /**
     * @param SecurityContextInterface|TokenStorageInterface $tokenStorage
     * @param array                                          $firewalls
     * @param ClientStorageInterface                         $clientStorage
     * @param LoggerInterface                                $logger
     */
    public function __construct(
        $tokenStorage,
        $firewalls = array(),
        ClientStorageInterface $clientStorage,
        LoggerInterface $logger = null,
        $encryptionMethod,
        $secretHash,
        EntityManager $em
    ) {
        if (!$tokenStorage instanceof TokenStorageInterface && !$tokenStorage instanceof SecurityContextInterface) {
            throw new \InvalidArgumentException('Argument 1 should be an instance of Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface or Symfony\Component\Security\Core\SecurityContextInterface');
        }

        $this->tokenStorage     = $tokenStorage;
        $this->firewalls        = $firewalls;
        $this->clientStorage    = $clientStorage;
        $this->logger           = null === $logger ? new NullLogger() : $logger;
        $this->encryptionMethod = $encryptionMethod;
        $this->secretHash       = $secretHash;
        $this->em               = $em;
    }

    /**
     * @param $connection
     * @param $decoded_cookie
     */
    private function decryptCookie($connection, $decoded_cookie)
    {
        $decoded_cookie = base64_decode($decoded_cookie);
        $iv_size        = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $iv             = substr($decoded_cookie, 0, $iv_size);

        if (false !== ($decryptedString = openssl_decrypt(substr($decoded_cookie, $iv_size), $this->encryptionMethod, $this->secretHash, 0, $iv))) {
            $data   = unserialize($decryptedString);
            $userId = $data['data']['UserID'];
            if (null !== ($user = $this->em->getRepository('CoreBundle:Users')->find($userId))) {
                //
                foreach ($this->firewalls as $firewall) {
                    $token = new UsernamePasswordToken($user, null, $firewall, array('ROLE_ADMIN'));
                    $connection->Session->set('_security_'.$firewall, serialize($token));
                }
                $connection->Session->save();
            }
        }
    }

    /**
     * @param ConnectionInterface $connection
     *
     * @return TokenInterface
     */
    protected function getToken(ConnectionInterface $connection)
    {
        $token = null;
        $query = $connection->getConnection()->getConnection()->getHttpRequest()->getUri()->getQuery();
        parse_str($query, $query_values);
        if (isset($query_values['c']) && null !== ($cookie = $query_values['c'])) {
            $this->decryptCookie($connection, $cookie);
        }

        if (isset($connection->Session) && $connection->Session) {
            foreach ($this->firewalls as $firewall) {
                if (false !== $serializedToken = $connection->Session->get('_security_'.$firewall, false)) {
                    /** @var TokenInterface $token */
                    $token = unserialize($serializedToken);
                    break;
                }
            }
        }

        if (null === $token) {
            $token = new AnonymousToken($this->firewalls[0], 'anon-'.$connection->WAMP->sessionId);
        }

        if ($this->tokenStorage->getToken() !== $token) {
            $this->tokenStorage->setToken($token);
        }

        return $token;
    }

    /**
     * @param ConnectionInterface $conn
     *
     * @return TokenInterface
     *
     * @throws StorageException
     * @throws \Exception
     */
    public function authenticate(ConnectionInterface $conn)
    {
        if (1 === count($this->firewalls) && 'ws_firewall' === $this->firewalls[0]) {
            $this->logger->warning(
                sprintf(
                    'User firewall is not configured, we have set %s by default',
                    $this->firewalls[0]
                )
            );
        }

        $loggerContext = array(
            'connection_id' => $conn->resourceId,
            'session_id'    => $conn->WAMP->sessionId,
        );

        $token    = $this->getToken($conn);
        $user     = $token->getUser();
        $username = $user instanceof UserInterface ? $user->getUsername() : $user;

        try {
            $identifier = $this->clientStorage->getStorageId($conn, $username);
        } catch (StorageException $e) {
            $this->logger->error(
                $e->getMessage(),
                $loggerContext
            );

            throw $e;
        }

        $loggerContext['storage_id'] = $identifier;
        $this->clientStorage->addClient($identifier, $token->getUser());
        $conn->WAMP->clientStorageId = $identifier;

        $this->logger->info(
            sprintf(
                '%s connected',
                $username
            ), $loggerContext
        );

        return $token;
    }
}
