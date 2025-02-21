<?php
declare(strict_types=1);

namespace SimpleTwoFactor\Test\TestCase\Controller\Component;

use Cake\Controller\ComponentRegistry;
use Cake\Controller\Controller;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use RobThree\Auth\TwoFactorAuth;
use SimpleTwoFactor\Controller\Component\SimpleTwoFactorComponent;
use SimpleTwoFactor\Result\Result;
use SimpleTwoFactor\Result\Result as ResultResult;

class SimpleTwoFactorComponentTest extends TestCase
{
    /**
     * Test the verifyCode method.
     *
     * Testziel:
     * - Überprüfen, dass die Methode verifyCode den Code korrekt überprüft.
     *
     * Erwartetes Ergebnis:
     * - Die Methode sollte true zurückgeben, wenn der Code korrekt ist.
     */
    public function testVerifyCode()
    {
        $secret = 'JBSWY3DPEHPK3PXP';
        $code = '123456';

        $tfa = $this->createMock(TwoFactorAuth::class);
        $tfa->expects($this->once())
            ->method('verifyCode')
            ->with($secret, $code)
            ->willReturn(true);

        $request = new ServerRequest();
        $request = $request->withAttribute('simpleAuthenticationObject', $tfa);
        $controller = new Controller($request);
        $registry = new ComponentRegistry($controller);
        $simpleTwoFactor = new SimpleTwoFactorComponent($registry);

        $result = $simpleTwoFactor->verifyCode($secret, $code);
        $this->assertTrue($result);
    }

    /**
     * Test the createSecret method.
     *
     * Testziel:
     * - Überprüfen, dass die Methode createSecret ein Geheimnis korrekt erstellt.
     *
     * Erwartetes Ergebnis:
     * - Die Methode sollte das erstellte Geheimnis zurückgeben.
     */
    public function testCreateSecret()
    {
        $secret = 'JBSWY3DPEHPK3PXP';

        $tfa = $this->createMock(TwoFactorAuth::class);
        $tfa->expects($this->once())
            ->method('createSecret')
            ->with(80, true)
            ->willReturn($secret);

        $request = new ServerRequest();
        $request = $request->withAttribute('simpleAuthenticationObject', $tfa);
        $controller = new Controller($request);
        $registry = new ComponentRegistry($controller);
        $simpleTwoFactor = new SimpleTwoFactorComponent($registry);

        $result = $simpleTwoFactor->createSecret();
        $this->assertEquals($secret, $result);
    }

    /**
     * Test the getQRCodeImageAsDataUri method.
     *
     * Testziel:
     * - Überprüfen, dass die Methode getQRCodeImageAsDataUri den QR-Code korrekt generiert.
     *
     * Erwartetes Ergebnis:
     * - Die Methode sollte die Data-URI des QR-Codes zurückgeben.
     */
    public function testGetQRCodeImageAsDataUri()
    {
        $label = 'MyApp:user@example.com';
        $secret = 'JBSWY3DPEHPK3PXP';
        $size = 200;
        $dataUri = 'data:image/png;base64,...';

        $tfa = $this->createMock(TwoFactorAuth::class);
        $tfa->expects($this->once())
            ->method('getQRCodeImageAsDataUri')
            ->with($label, $secret, $size)
            ->willReturn($dataUri);

        $request = new ServerRequest();
        $request = $request->withAttribute('simpleAuthenticationObject', $tfa);
        $controller = new Controller($request);
        $registry = new ComponentRegistry($controller);
        $simpleTwoFactor = new SimpleTwoFactorComponent($registry);

        $result = $simpleTwoFactor->getQRCodeImageAsDataUri($label, $secret, $size);
        $this->assertEquals($dataUri, $result);
    }

    /**
     * Test the getResult method.
     *
     * Testziel:
     * - Überprüfen, dass die Methode getResult das richtige Ergebnis zurückgibt.
     *
     * Erwartetes Ergebnis:
     * - Die Methode sollte das Ergebnis zurückgeben, das im Request-Objekt gespeichert ist.
     */
    public function testGetResult()
    {
        $request = new ServerRequest();
        $result = new ResultResult( ResultResult::SIMPLE_TWO_FA_AUTH_MISSING_CREDENTIALS );
        $request = $request->withAttribute('simpleAuthenticationResult', $result);
        $controller = new Controller($request);
        $registry = new ComponentRegistry($controller);
        $simpleTwoFactor = new SimpleTwoFactorComponent($registry);

        $actualResult = $simpleTwoFactor->getResult();
        $this->assertSame($result, $actualResult);
        $this->assertInstanceOf(Result::class, $actualResult);
    }

    /**
     * Test the getResult method throws exception.
     *
     * Testziel:
     * - Überprüfen, dass die Methode getResult eine Ausnahme auslöst, wenn das Attribut simpleAuthenticationResult nicht vorhanden ist.
     *
     * Erwartetes Ergebnis:
     * - Die Methode sollte eine Exception mit der entsprechenden Fehlermeldung auslösen.
     */
    public function testGetResultThrowsException()
    {
        $request = new ServerRequest();
        $controller = new Controller($request);
        $registry = new ComponentRegistry($controller);
        $simpleTwoFactor = new SimpleTwoFactorComponent($registry);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('The request object does not contain the required `simpleAuthenticationResult` attribute. Verify the TwoFactorMiddleware has been added.');

        $simpleTwoFactor->getResult();
    }

    /**
     * Test the getTfa method.
     *
     * Testziel:
     * - Überprüfen, dass die Methode getTfa das richtige TwoFactorAuth-Objekt zurückgibt.
     *
     * Erwartetes Ergebnis:
     * - Die Methode sollte das TwoFactorAuth-Objekt zurückgeben, das im Request-Objekt gespeichert ist.
     */
    public function testGetTfa()
    {
        $tfa = $this->createMock(TwoFactorAuth::class);
        $request = new ServerRequest();
        $request = $request->withAttribute('simpleAuthenticationObject', $tfa);
        $controller = new Controller($request);
        $registry = new ComponentRegistry($controller);
        $simpleTwoFactor = new SimpleTwoFactorComponent($registry);

        $actualTfa = $simpleTwoFactor->getTfa();
        $this->assertInstanceOf(TwoFactorAuth::class, $actualTfa);
    }

    /**
     * Test the getTfa method throws exception.
     *
     * Testziel:
     * - Überprüfen, dass die Methode getTfa eine Ausnahme auslöst, wenn das Attribut simpleAuthenticationObject nicht vorhanden ist.
     *
     * Erwartetes Ergebnis:
     * - Die Methode sollte eine Exception mit der entsprechenden Fehlermeldung auslösen.
     */
    public function testGetTfaThrowsException()
    {
        $request = new ServerRequest();
        $controller = new Controller($request);
        $registry = new ComponentRegistry($controller);
        $simpleTwoFactor = new SimpleTwoFactorComponent($registry);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('The request object does not contain the required `simpleAuthenticationObject` attribute. Verify the TwoFactorMiddleware has been added.');

        $simpleTwoFactor->getTfa();
    }
}