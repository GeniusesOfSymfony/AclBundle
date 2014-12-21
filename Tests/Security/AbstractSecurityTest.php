<?php

namespace Problematic\AclManagerBundle\Tests\Security;

use Doctrine\DBAL\Driver\Connection;
use Problematic\AclManagerBundle\Model\AclManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\Security\Acl\Dbal\Schema;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\User;

class AbstractSecurityTest extends WebTestCase
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @var TokenInterface
     */
    protected $token;

    /**
     * @var Connection
     */
    protected $connection;

    /**
     * @var AclManagerInterface
     */
    protected $aclManager;

    protected $tableNames;

    public function setUp()
    {
        $this->client = static::createClient();
        $this->container = $this->client->getContainer();
        $this->authenticateUser('user1');

        $this->connection = $this->container->get('database_connection');

        if (!class_exists('PDO') || !in_array('sqlite', \PDO::getAvailableDrivers())) {
            $this->markTestSkipped('This test requires SQLite support in your environment.');
        }

        $this->tableNames = array(
            'oid_table_name' => 'acl_object_identities',
            'oid_ancestors_table_name' => 'acl_object_identity_ancestors',
            'class_table_name' => 'acl_classes',
            'sid_table_name' => 'acl_security_identities',
            'entry_table_name' => 'acl_entries',
        );

        $schema = new Schema($this->tableNames);

        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->exec($sql);
        }

        $this->aclManager = $this->container->get('problematic.acl_manager');
    }

    protected function generateSidForUser($username)
    {
        return new UserSecurityIdentity($username, 'Symfony\Component\Security\Core\User\User');
    }

    protected function resetDB()
    {
        foreach($this->tableNames as $table){
            $this->connection->exec(sprintf('TRUNCATE TABLE `%s`', $table));
        }
    }

    protected function authenticateUser($username, array $roles = array())
    {
        $this->token = $this->createToken($username, $roles);
        $this->container->get('security.context')->setToken($this->token);
        $this->assertTrue($this->token->isAuthenticated());
    }

    protected function createToken($username, array $roles = array())
    {
        $roles = array_merge(array('ROLE_USER'), $roles);
        $user = new User($username, '', $roles);
        $token = new UsernamePasswordToken($user, '', 'main', $roles);
        return $token;
    }

    public function testIfContainerExists()
    {
        $this->assertNotNull($this->client);
        $this->assertNotNull($this->container);
    }

    public function testIfSecurityContextLoads()
    {
        $securityContext = $this->container->get('security.context');
        $this->assertNotNull($securityContext->getToken());
    }
}