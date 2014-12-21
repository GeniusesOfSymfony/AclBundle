<?php

namespace Problematic\AclManagerBundle\Tests\Domain;

use Problematic\AclManagerBundle\Tests\Model\BarObject;
use Problematic\AclManagerBundle\Tests\Model\FooObject;
use Problematic\AclManagerBundle\Tests\Security\AbstractSecurityTest;

class AclManager extends AbstractSecurityTest
{
    protected $fooClass;

    protected $barClass;

    public function setUp()
    {
        parent::setUp();
        $this->fooClass = get_class((new FooObject(uniqid())));
        $this->barClass = get_class(new BarObject(uniqid()));
    }

    public function testGetProvider()
    {
        $this->assertInstanceOf(
            'Symfony\Component\Security\Core\User\UserInterface',
            $this->aclManager->getUser(),
            'Must retrieve UserInterface'
        );
    }

    public function testIsGrantedObject()
    {
        $a = new FooObject('granted_object_a'.uniqid());
        $b = new BarObject('granted_object_b'.uniqid());

        $user1Sid = $this->generateSidForUser('user1');
        $this->aclManager->setObjectPermission($b, 'OWNER', $user1Sid);
        $this->aclManager->setObjectPermission($a, 'VIEW', $user1Sid);

        $user2Sid = $this->generateSidForUser('user2');
        $this->aclManager->setObjectPermission($b, 'VIEW', $user2Sid);
        $this->aclManager->setObjectPermission($a, 'OWNER', $user2Sid);

        $this->authenticateUser('user1');
        $this->assertTrue($this->aclManager->isGranted('OWNER', $b));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $a));
        $this->assertFalse($this->aclManager->isGranted('OWNER', $a));

        $this->authenticateUser('user2');
        $this->assertTrue($this->aclManager->isGranted('OWNER', $a));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $b));
        $this->assertFalse($this->aclManager->isGranted('OWNER', $b));

        $this->authenticateUser('sneakyuser');
        $this->assertFalse($this->aclManager->isGranted('DELETE', $a));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $a));
        $this->assertFalse($this->aclManager->isGranted('DELETE', $b));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $b));
    }

    public function testIsFieldGrantedClass()
    {
        $a = new FooObject('field_granted_class_object_a'.uniqid());
        $b = new FooObject('field_granted_class_object_b'.uniqid());
        $c = new FooObject('field_granted_class_object_c'.uniqid());
        $d = new BarObject('field_granted_class_object_d'.uniqid());

        $this->aclManager->setClassFieldPermission($a, 'securedField', 'MASTER', 'ROLE_ADMIN');
        $this->aclManager->setClassFieldPermission($c, 'securedField', 'VIEW', $this->generateSidForUser('user1'));
        $this->aclManager->setClassFieldPermission($this->fooClass, ['securedField', 'bar'], 'VIEW', $this->generateSidForUser('user2'));

        $this->authenticateUser('admin', ['ROLE_ADMIN']);
        $this->assertTrue($this->aclManager->isFieldGranted('MASTER', $a, 'securedField', 'class' ));
        $this->assertTrue($this->aclManager->isFieldGranted('MASTER', $b, 'securedField', 'class'));
        $this->assertTrue($this->aclManager->isFieldGranted('MASTER', $c, 'securedField', 'class'));
        $this->assertFalse($this->aclManager->isFieldGranted('MASTER', $c, 'foo', 'class'));
        $this->assertFalse($this->aclManager->isFieldGranted('MASTER', $c, 'bar', 'class'));

        $this->authenticateUser('user1');
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $a, 'securedField', 'class'));

        $this->authenticateUser('user2');
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $a, 'securedField', 'class'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $a, 'bar', 'class'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $d, 'securedField', 'class'));

        $this->authenticateUser('sneakyuser');
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $a, 'securedField', 'class'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $b, 'securedField', 'class'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $c, 'securedField', 'class'));
    }

    public function testIsGrantedClass()
    {
        $a = new FooObject('granted_class_object_a'.uniqid());
        $b = new BarObject('granted_class_object_b'.uniqid());

        $user3Sid = $this->generateSidForUser('user3');

        $this->aclManager->setClassPermission($a, 'OWNER', $user3Sid);
        $this->aclManager->setClassPermission($this->barClass, 'VIEW', $user3Sid);

        $this->authenticateUser('user3');
        $this->assertTrue($this->aclManager->isGranted('OWNER', $a, 'class'));
        $this->assertTrue($this->aclManager->isGranted('OWNER', get_class($a), 'class'));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $b, 'class'));

        $this->authenticateUser('sneakyuser');
        $this->assertFalse($this->aclManager->isGranted('OWNER', $a, 'class'));
        $this->assertFalse($this->aclManager->isGranted('OWNER', get_class($a), 'class'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $b, 'class'));
    }

    public function testIsGrantedRoles()
    {
        $this->authenticateUser('user1');
        $this->assertTrue($this->aclManager->isGranted('ROLE_USER'));
        $this->assertFalse($this->aclManager->isGranted('ROLE_ADMIN'));

        $this->authenticateUser('user2');
        $this->assertTrue($this->aclManager->isGranted('ROLE_USER'));
        $this->assertFalse($this->aclManager->isGranted('ROLE_ADMIN'));

        $this->authenticateUser('admin', ['ROLE_ADMIN']);
        $this->assertTrue($this->aclManager->isGranted('ROLE_USER'));
        $this->assertTrue($this->aclManager->isGranted('ROLE_ADMIN'));
        $this->assertTrue($this->aclManager->isGranted(array('ROLE_ADMIN', 'ROLE_USER')));
    }

    public function testRevokePermission()
    {
        $a = new FooObject('revoke_permission_object_a'.uniqid());
        $b = new FooObject('revoke_permission_object_b'.uniqid());

        $user3Sid = $this->generateSidForUser('user3');
        $user4Sid = $this->generateSidForUser('user4');

        $this->aclManager->setObjectPermission($a, 'OWNER', $user3Sid);
        $this->aclManager->setObjectPermission($b, 'VIEW', $user3Sid);
        $this->aclManager->setObjectPermission($a, 'VIEW', $user4Sid);
        $this->aclManager->setObjectPermission($b, 'OWNER', $user4Sid);

        //Revoke permission for user4
        $this->aclManager->revokePermission($a, 'EDIT', $user4Sid);

        $this->authenticateUser('user4');
        $this->assertFalse($this->aclManager->isGranted('EDIT', $a));
        $this->assertFalse($this->aclManager->isGranted('OWNER', $a));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $a));
        $this->assertTrue($this->aclManager->isGranted('OWNER', $b));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $b));

        $this->authenticateUser('user3');
        $this->assertTrue($this->aclManager->isGranted('OWNER', $a));

        //Revoke permission for all users
        $this->aclManager->revokePermission($a, 'VIEW');

    }

    public function testRevokeFieldPermission()
    {
        $a = new FooObject('revoke_permission_field_object_a'.uniqid());
        $b = new FooObject('revoke_permission_field_object_b'.uniqid());

        $user5Sid = $this->generateSidForUser('user5');
        $user6Sid = $this->generateSidForUser('user6');

        $this->aclManager->setObjectFieldPermission($a, 'securedField', 'OWNER', $user5Sid);
        $this->aclManager->setObjectFieldPermission($a, 'foo', 'VIEW', $user5Sid);
        $this->aclManager->setObjectFieldPermission($b, 'securedField', 'VIEW', $user5Sid);

        $this->aclManager->setObjectFieldPermission($a, 'securedField', 'VIEW', $user6Sid);
        $this->aclManager->setObjectFieldPermission($b, 'securedField', 'OWNER', $user6Sid);
        $this->aclManager->setObjectFieldPermission($b, 'foo', 'VIEW', $user6Sid);

        $this->authenticateUser('user5');
        $this->assertTrue($this->aclManager->isFieldGranted('OWNER', $a, 'securedField'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $a, 'foo'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, 'securedField'));
        $this->assertFalse($this->aclManager->isFieldGranted('IDDQ', $a, 'securedField'));

        $this->authenticateUser('user6');
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, 'foo'));
        $this->assertTrue($this->aclManager->isFieldGranted('OWNER', $b, 'securedField'));
        $this->assertFalse($this->aclManager->isFieldGranted('IDDQ', $a, 'securedField'));

        $this->aclManager->revokeFieldPermission($a, 'securedField', 'OWNER', $user5Sid);

        $this->authenticateUser('user5');
        $this->assertFalse($this->aclManager->isFieldGranted('OWNER', $a, 'securedField'));
        $this->assertFalse($this->aclManager->isFieldGranted('EDIT', $a, 'securedField'));

        $this->authenticateUser('user6');
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclManager->isFieldGranted('IDDQ', $a, 'securedField'));

        $this->aclManager->revokeFieldPermission($b, ['foo', 'securedField'], 'VIEW', $user6Sid);

        $this->authenticateUser('user6');
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $b, 'foo'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $b, 'securedField'));

        $this->authenticateUser('user5');
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, 'securedField'));
    }

    public function testRevokeAllObjectPermissions()
    {
        $a = new FooObject('revoke_all_permission_object_a'.uniqid());
        $b = new FooObject('revoke_all_permission_object_b'.uniqid());

        $user7Sid = $this->generateSidForUser('user7');
        $user8Sid = $this->generateSidForUser('user8');

        $this->aclManager->setObjectPermission($a, 'OWNER', $user7Sid);
        $this->aclManager->setObjectPermission($a, 'VIEW', $user8Sid);
        $this->aclManager->setObjectPermission($b, 'OWNER', $user7Sid);
        $this->aclManager->setObjectPermission($b, 'VIEW', $user8Sid);

        //Delete permission for all SID
        $this->aclManager->revokeAllObjectPermissions($a);

        $this->authenticateUser('user7');
        $this->assertFalse($this->aclManager->isGranted('OWNER', $a));
        $this->assertTrue($this->aclManager->isGranted('OWNER', $b));

        $this->authenticateUser('user8');
        $this->assertFalse($this->aclManager->isGranted('VIEW', $a));
        $this->assertTrue($this->aclManager->isGranted('VIEW', $b));

        //Delete permission only for user8
        $this->aclManager->revokeAllObjectPermissions($b, $user8Sid);

        $this->authenticateUser('user7');
        $this->assertTrue($this->aclManager->isGranted('OWNER', $b));

        $this->authenticateUser('user8');
        $this->assertFalse($this->aclManager->isGranted('VIEW', $b));
    }

    public function testRevokeAllObjectFieldPermissions()
    {
        $a = new FooObject('revoke_all_permission_field_object_a'.uniqid());
        $b = new FooObject('revoke_all_permission_field_object_b'.uniqid());

        $user9Sid = $this->generateSidForUser('user9');
        $user10Sid = $this->generateSidForUser('user10');

        $this->aclManager->setObjectFieldPermission($a, 'securedField', 'OWNER', $user9Sid);
        $this->aclManager->setObjectFieldPermission($a, 'foo', 'OWNER', $user9Sid);
        $this->aclManager->setObjectFieldPermission($a, 'bar', 'OWNER', $user9Sid);
        $this->aclManager->setObjectFieldPermission($a, 'securedField', 'VIEW', $user10Sid);
        $this->aclManager->setObjectFieldPermission($a, 'bar', 'VIEW', $user10Sid);
        $this->aclManager->setObjectFieldPermission($a, 'foo', 'VIEW', $user10Sid);
        $this->aclManager->setObjectFieldPermission($b, 'securedField', 'OWNER', $user9Sid);
        $this->aclManager->setObjectFieldPermission($b, 'foo', 'OWNER', $user9Sid);
        $this->aclManager->setObjectFieldPermission($b, 'securedField', 'VIEW', $user10Sid);
        $this->aclManager->setObjectFieldPermission($b, 'foo', 'VIEW', $user10Sid);
        $this->aclManager->setObjectFieldPermission($b, 'bar', 'VIEW', $user10Sid);
        $this->aclManager->setObjectFieldPermission($b, 'bar', 'VIEW', $user9Sid);

        //Revoke all field permission for all sid
        $this->aclManager->revokeAllObjectFieldPermissions($a, 'securedField');

        $this->authenticateUser('user9');
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclManager->isFieldGranted('OWNER', $a, 'foo'));

        $this->authenticateUser('user10');
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $a, 'foo'));

        //Revoke all field permission for all sid
        $this->aclManager->revokeAllObjectFieldPermissions($a, array('foo', 'bar'));

        $this->authenticateUser('user9');
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $a, 'foo'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $a, 'bar'));
        $this->assertTrue($this->aclManager->isFieldGranted('OWNER', $b, 'securedField'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, array('foo', 'bar')));

        $this->authenticateUser('user10');
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $a, 'foo'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $a, 'bar'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, 'securedField'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, array('foo', 'bar')));

        //Revoke all field permission only for user10
        $this->aclManager->revokeAllObjectFieldPermissions($b, array('foo', 'bar'), $user10Sid);

        $this->authenticateUser('user9');
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, 'foo'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, 'bar'));
        $this->assertTrue($this->aclManager->isFieldGranted('VIEW', $b, array('bar', 'foo')));

        $this->authenticateUser('user10');
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $b, 'foo'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $b, 'bar'));
        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $b, array('bar', 'foo')));

    }
}