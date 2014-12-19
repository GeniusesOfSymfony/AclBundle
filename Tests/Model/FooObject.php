<?php

namespace Problematic\AclManagerBundle\Tests\Model;

class FooObject
{
    protected $id;

    protected $foo;

    protected $bar;

    protected $securedField;

    public function __construct($id, $foo = null, $bar = null)
    {
        $this->id = $id;
        $this->foo = $foo;
        $this->bar = $bar;
    }

    /**
     * @return mixed
     */
    public function getFoo()
    {
        return $this->foo;
    }

    /**
     * @param mixed $foo
     */
    public function setFoo($foo)
    {
        $this->foo = $foo;
    }

    /**
     * @return mixed
     */
    public function getBar()
    {
        return $this->bar;
    }

    /**
     * @param mixed $bar
     */
    public function setBar($bar)
    {
        $this->bar = $bar;
    }

    /**
     * @return mixed
     */
    public function getSecuredField()
    {
        return $this->securedField;
    }

    /**
     * @param mixed $securedField
     */
    public function setSecuredField($securedField)
    {
        $this->securedField = $securedField;
    }

    public function getId()
    {
        return $this->id;
    }

}