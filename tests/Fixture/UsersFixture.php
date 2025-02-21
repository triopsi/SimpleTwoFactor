<?php
declare(strict_types=1);

namespace SimpleTwoFactor\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class UsersFixture extends TestFixture
{
    public $fields = [
        'id' => ['type' => 'integer', 'autoIncrement' => true],
        'username' => ['type' => 'string', 'length' => 255, 'null' => false],
        'password' => ['type' => 'string', 'length' => 255, 'null' => false],
        'email' => ['type' => 'string', 'length' => 255, 'null' => false],
        'secret_2tfa' => ['type' => 'string', 'length' => 255, 'null' => true],
        'created' => ['type' => 'datetime', 'null' => false],
        'modified' => ['type' => 'datetime', 'null' => false],
        '_constraints' => [
            'primary' => ['type' => 'primary', 'columns' => ['id']],
        ],
    ];

    public $records = [
        [
            'id' => 1,
            'username' => 'user1',
            'password' => 'password1',
            'email' => 'user1@example.com',
            'secret_2tfa' => 'secret1',
            'created' => '2025-02-16 10:00:00',
            'modified' => '2025-02-16 10:00:00',
        ],
        [
            'id' => 2,
            'username' => 'user2',
            'password' => 'password2',
            'email' => 'user2@example.com',
            'secret_2tfa' => null,
            'created' => '2025-02-16 10:00:00',
            'modified' => '2025-02-16 10:00:00',
        ],
    ];
}