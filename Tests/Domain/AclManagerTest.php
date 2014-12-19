<?php

namespace Problematic\AclManagerBundle\Tests\Domain;

use Problematic\AclManagerBundle\Tests\Model\BarObject;
use Problematic\AclManagerBundle\Tests\Model\FooObject;
use Problematic\AclManagerBundle\Tests\Security\AbstractSecurityTest;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;

class AclManager extends AbstractSecurityTest
{
    protected $fooObj;
    protected $barObj;

    public function setUp()
    {
        parent::setUp();

        $this->fooObj = new FooObject(uniqid());
        $this->barObj = new BarObject(uniqid());

        $this->authenticateUser('user1');
        $this->aclManager->setObjectPermission($this->fooObj, MaskBuilder::MASK_VIEW);
        $this->aclManager->setObjectPermission($this->barObj, MaskBuilder::MASK_OWNER);

        $this->authenticateUser('user2');
        $this->aclManager->setObjectPermission($this->fooObj, MaskBuilder::MASK_OWNER);
        $this->aclManager->setObjectPermission($this->barObj, MaskBuilder::MASK_VIEW);

        $this->aclManager->setClassPermission(
            'Problematic\AclManagerBundle\Tests\Model\FooObject',
            MaskBuilder::MASK_MASTER,
            'ROLE_ADMIN'
        );
    }

    public function testGetProvider()
    {
        $this->assertInstanceOf(
            'Symfony\Component\Security\Core\User\UserInterface',
            $this->aclManager->getUser(),
            'Must retrieve UserInterface'
        );
    }

    public function testIsGrantedObjects()
    {
        $this->authenticateUser('user1');
        $this->assertTrue($this->aclManager->isGranted('OWNER', $this->barObj));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $this->fooObj));
        $this->assertFalse($this->aclManager->isGranted('OWNER', $this->fooObj));

        $this->authenticateUser('user2');
        $this->assertTrue($this->aclManager->isGranted('OWNER', $this->fooObj));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $this->barObj));
        $this->assertFalse($this->aclManager->isGranted('OWNER', $this->barObj));

        $this->authenticateUser('hacker');
        $this->assertFalse($this->aclManager->isGranted('DELETE', $this->fooObj));
        $this->assertFalse($this->aclManager->isGranted('DELETE', $this->barObj));
    }

    public function testIsGrantedClass()
    {
        $this->authenticateUser('admin', ['ROLE_ADMIN']);

        $this->assertTrue($this->aclManager->isGranted(
            ['VIEW', 'EDIT', 'DELETE', 'UNDELETE'],
            $this->fooObj
        ));

        $this->assertTrue($this->aclManager->isGranted(
            'MASTER',
            $this->fooObj
        ));

        $this->authenticateUser('hacker');

        $this->assertFalse($this->aclManager->isGranted(
            'MASTER',
            $this->fooObj
        ));
    }

    public function testIsGrantedRoles()
    {
        $this->authenticateUser('user1');

        $this->assertTrue(
            $this->aclManager->isGranted('ROLE_USER'),
            'User 1 must be granted ROLE_USER'
        );

        $this->assertFalse(
            $this->aclManager->isGranted('ROLE_ADMIN'),
            'User 1 must not be granted ROLE_ADMIN'
        );

        $this->authenticateUser('user2');

        $this->assertTrue(
            $this->aclManager->isGranted('ROLE_USER'),
            'User 1 must be granted ROLE_USER'
        );

        $this->assertFalse(
            $this->aclManager->isGranted('ROLE_ADMIN'),
            'User 1 must not be granted ROLE_ADMIN'
        );

        $this->authenticateUser('admin', ['ROLE_ADMIN']);

        $this->assertTrue(
            $this->aclManager->isGranted('ROLE_USER'),
            'Admin must be granted ROLE_USER'
        );

        $this->assertTrue(
            $this->aclManager->isGranted('ROLE_ADMIN'),
            'Admin must be granted ROLE_ADMIN'
        );

        $this->assertTrue(
            $this->aclManager->isGranted(['ROLE_ADMIN', 'ROLE_USER']),
            'Admin must be granted ROLE_ADMIN and also ROLE_USER'
        );
    }
}