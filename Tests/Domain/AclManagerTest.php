<?php

namespace Problematic\AclManagerBundle\Tests\Domain;

use Problematic\AclManagerBundle\Tests\Model\BarObject;
use Problematic\AclManagerBundle\Tests\Model\FooObject;
use Problematic\AclManagerBundle\Tests\Security\AbstractSecurityTest;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;

class AclManager extends AbstractSecurityTest
{
    protected $fooClass;

    protected $barClass;

    public function setUp()
    {
        parent::setUp();
        $this->fooClass = 'Problematic\\AclManagerBundle\\Tests\\Model\\FooObject';
        $this->barClass = 'Problematic\\AclManagerBundle\\Tests\\Model\\BarObject';
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
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $user1Sid = $this->generateSidForUser('user1');
        $user2Sid = $this->generateSidForUser('user2');

        $this->aclManager
            ->addObjectPermission($b, 'OWNER', $user1Sid)
            ->addObjectPermission($a, 'VIEW', $user1Sid)
        ;

        $this->aclManager
            ->addObjectPermission($b, 'VIEW', $user2Sid)
            ->addObjectPermission($a, 'OWNER', $user2Sid)
        ;

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
        $a = new FooObject(uniqid());
        $b = new FooObject(uniqid());
        $c = new FooObject(uniqid());
        $d = new BarObject(uniqid());

        $this->aclManager
            ->addClassFieldPermission($a, 'securedField', 'MASTER', 'ROLE_ADMIN')
            ->addClassFieldPermission($c, 'securedField', 'VIEW', $this->generateSidForUser('user1'))
            ->addClassFieldPermission($this->fooClass, ['securedField', 'bar'], 'VIEW', $this->generateSidForUser('user2'))
        ;

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
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $user3Sid = $this->generateSidForUser('user3');

        $this->aclManager
            ->addClassPermission($a, 'EDIT', $user3Sid)
            ->addClassPermission($this->barClass, 'VIEW', $user3Sid)
        ;

        $this->authenticateUser('user3');
        $this->assertTrue($this->aclManager->isGranted('EDIT', $a, 'class'));
        $this->assertTrue($this->aclManager->isGranted('EDIT', new ObjectIdentity($this->fooClass, 'class')));
        $this->assertTrue($this->aclManager->isGranted('EDIT', $a, 'class'));
        $this->assertTrue($this->aclManager->isGranted('EDIT', get_class($a), 'class'));
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

        $this->aclManager
            ->addObjectPermission($a, 'OWNER', $user3Sid)
            ->addObjectPermission($b, 'VIEW', $user3Sid)
            ->addObjectPermission($a, 'VIEW', $user4Sid)
            ->addObjectPermission($b, 'OWNER', $user4Sid)
        ;

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
        $a = new FooObject(uniqid());
        $b = new FooObject(uniqid());

        $user5Sid = $this->generateSidForUser('user5');
        $user6Sid = $this->generateSidForUser('user6');

        $this->aclManager
            ->addObjectFieldPermission($a, 'securedField', 'OWNER', $user5Sid)
            ->addObjectFieldPermission($a, 'foo', 'VIEW', $user5Sid)
            ->addObjectFieldPermission($b, 'securedField', 'VIEW', $user5Sid)
            ->addObjectFieldPermission($a, 'securedField', 'VIEW', $user6Sid)
            ->addObjectFieldPermission($b, 'securedField', 'OWNER', $user6Sid)
            ->addObjectFieldPermission($b, 'foo', 'VIEW', $user6Sid)
        ;

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
        $a = new FooObject(uniqid());
        $b = new FooObject(uniqid());

        $user7Sid = $this->generateSidForUser('user7');
        $user8Sid = $this->generateSidForUser('user8');

        $this->aclManager
            ->addObjectPermission($a, 'OWNER', $user7Sid)
            ->addObjectPermission($a, 'VIEW', $user8Sid)
            ->addObjectPermission($b, 'OWNER', $user7Sid)
            ->addObjectPermission($b, 'VIEW', $user8Sid)
        ;

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
        $a = new FooObject(uniqid());
        $b = new FooObject(uniqid());

        $user9Sid = $this->generateSidForUser('user9');
        $user10Sid = $this->generateSidForUser('user10');

        $this->aclManager
            ->addObjectFieldPermission($a, 'securedField', 'OWNER', $user9Sid)
            ->addObjectFieldPermission($a, 'foo', 'OWNER', $user9Sid)
            ->addObjectFieldPermission($a, 'bar', 'OWNER', $user9Sid)
            ->addObjectFieldPermission($a, 'securedField', 'VIEW', $user10Sid)
            ->addObjectFieldPermission($a, 'bar', 'VIEW', $user10Sid)
            ->addObjectFieldPermission($a, 'foo', 'VIEW', $user10Sid)
            ->addObjectFieldPermission($b, 'securedField', 'OWNER', $user9Sid)
            ->addObjectFieldPermission($b, 'foo', 'OWNER', $user9Sid)
            ->addObjectFieldPermission($b, 'securedField', 'VIEW', $user10Sid)
            ->addObjectFieldPermission($b, 'foo', 'VIEW', $user10Sid)
            ->addObjectFieldPermission($b, 'bar', 'VIEW', $user10Sid)
            ->addObjectFieldPermission($b, 'bar', 'VIEW', $user9Sid)
        ;

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

    /**
     * @see https://github.com/GeniusesOfSymfony/AclBundle/issues/6
     */
    public function testFixIssue1()
    {
        $a = new FooObject(uniqid('a'));
        $b = new BarObject(uniqid('b'));

        $user13Sid = $this->generateSidForUser('user13');
        $user14Sid = $this->generateSidForUser('user14');

        $this->aclManager
            ->addClassPermission($a, 'EDIT', $user13Sid)
            ->addClassPermission($b, 'EDIT', $user13Sid)
            ->addClassPermission($b, 'EDIT', $user14Sid)
        ;

        $this->authenticateUser('user13');
        $this->assertTrue($this->aclManager->isGranted('EDIT', $a, 'class'));
        $this->assertTrue($this->aclManager->isGranted('EDIT', $b, 'class'));

        $this->authenticateUser('user14');
        $this->assertTrue($this->aclManager->isGranted('EDIT', $b, 'class'));

        $this->aclManager->revokeAllClassPermissions($a);

        //From now class FooObject loose all class based acl for all sid
        //So user13 can't view, edit FooObject, but still do it on BarObject
        $this->assertFalse($this->aclManager->isGranted('EDIT', $a, 'class'));
        $this->assertTrue($this->aclManager->isGranted('EDIT', $b, 'class')); //Currently that bug

        $this->authenticateUser('user14');
        $this->assertTrue($this->aclManager->isGranted('EDIT', $b, 'class')); //Currently that bug
    }

    public function testRevokeClassPermissions()
    {
        $a = new FooObject(uniqid('a'));
        $b = new BarObject(uniqid('b'));
        $c = new FooObject(uniqid('c'));

        $user11Sid = $this->generateSidForUser('user11');
        $user12Sid = $this->generateSidForUser('user12');

        $this->aclManager
            ->addClassPermission($a, 'EDIT', $user11Sid)
            ->addClassPermission($b, 'EDIT', $user11Sid)
            ->addClassPermission($c, 'VIEW', $user12Sid)
            ->addClassPermission($this->barClass, 'VIEW', $user12Sid)
            ->addClassPermission($this->fooClass, 'MASTER', 'ROLE_ADMIN')
        ;

        //Revoke all class permission for all sid
        $this->aclManager->revokeAllClassPermissions($a);

        $this->authenticateUser('admin', array('ROLE_ADMIN'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $a, 'class'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', new ObjectIdentity($this->fooClass, 'class')));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $this->fooClass, 'class'));

        $this->authenticateUser('user11');
        $this->assertFalse($this->aclManager->isGranted('VIEW', $a, 'class'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $c, 'class'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $this->fooClass, 'class'));
        $this->assertTrue($this->aclManager->isGranted('EDIT', $b, 'class')); //#6

        $this->authenticateUser('user12');
        $this->assertFalse($this->aclManager->isGranted('VIEW', $a, 'class'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $c, 'class'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $this->fooClass, 'class'));

        //Revoke all class permission for user12
        $this->aclManager->revokeAllClassPermissions($b, $user12Sid);

        $this->authenticateUser('user11');
        $this->assertTrue($this->aclManager->isGranted('EDIT', $b, 'class'));

        $this->authenticateUser('user12');
        $this->assertFalse($this->aclManager->isGranted('VIEW', new ObjectIdentity($this->barClass, 'class')));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $this->barClass, 'class'));
        $this->assertFalse($this->aclManager->isGranted('VIEW', $b, 'class'));
    }

//    public function testRevokeAllClassFieldPermissions()
//    {
//        $class = 'Problematic\AclManagerBundle\Tests\Model\BarObject';
//
//        $this->aclManager->setClassFieldPermission(
//            $class,
//            ['securedField', 'bar'],
//            array('EDIT'),
//            'ROLE_ADMIN'
//        );
//
//        $this->authenticateUser('admin', array('ROLE_ADMIN'));
//        $this->aclManager->revokeAllClassFieldPermissions($class, 'securedField');
//
//        $this->assertFalse($this->aclManager->isFieldGranted('OWNER', $class, 'securedField', 'class'));
//        $this->assertFalse($this->aclManager->isFieldGranted('OWNER', $class, 'bar', 'class'));

//        //also might work with oid directly
//        $oid = new ObjectIdentity($class, 'class');
//        $this->assertFalse($this->aclManager->isFieldGranted('VIEW', $oid, 'securedField'));
//        $this->assertFalse($this->aclManager->isFieldGranted('EDIT', $oid, 'securedField'));
//        $this->assertFalse($this->aclManager->isFieldGranted(array('EDIT', 'VIEW'), $oid, 'securedField'));
//    }
//
//    public function testDeleteAclFor()
//    {
//        $this->authenticateUser('user3');
//        $foobar = new FooObject(uniqid());
//        $this->aclManager->addObjectPermission($foobar, 'OWNER');
//        $this->aclManager->addObjectFieldPermission($foobar, 'bar', 'OWNER');
//        $this->assertTrue($this->aclManager->isGranted('OWNER', $foobar));
//        $this->aclManager->deleteAclFor($foobar);
//        $this->assertFalse($this->aclManager->isGranted('OWNER', $foobar));
//        $this->assertFalse($this->aclManager->isFieldGranted('OWNER', 'bar', $foobar));
//    }
}