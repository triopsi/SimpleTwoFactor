<?php
declare(strict_types=1);

namespace SimpleTwoFactor\Test\TestCase\Middleware;

use Cake\Http\ServerRequest;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Http\Response;
use SimpleTwoFactor\Middleware\TwoFactorMiddleware;
use SimpleTwoFactor\Result\Result as ResultResult;
use TestApp\Http\TestRequestHandler;

class TwoFactorMiddlewareTest extends TestCase {

	use IntegrationTestTrait;

	protected $middleware;

	public function setUp(): void {
		parent::setUp();
		$this->middleware = new TwoFactorMiddleware();
	}

	/**
	 * Test the process method when no user is authenticated.
	 *
	 * Testziel:
	 * - Überprüfen, dass die Middleware den Request korrekt verarbeitet, wenn kein Benutzer authentifiziert ist.
	 *
	 * Erwartetes Ergebnis:
	 * - Die Middleware sollte den Request an den nächsten Handler weiterleiten und eine Response zurückgeben.
	 */
	public function testProcessWithoutUser() {
		$request = new ServerRequest( array( 'url' => '/test' ) );
		$handler = new TestRequestHandler();

		$response = $this->middleware->process( $request, $handler );
		$this->assertInstanceOf( Response::class, $response );

		$instance = $handler->request->getAttribute( 'simpleAuthenticationResult' );
		$this->assertEquals( ResultResult::SIMPLE_TWO_FA_AUTH_MISSING_CREDENTIALS, $instance->getStatus() );
	}

	/**
	 * Test the process method when a user is authenticated but 2FA is not enabled.
	 *
	 * Testziel:
	 * - Überprüfen, dass die Middleware den Request korrekt verarbeitet, wenn ein Benutzer authentifiziert ist, aber 2FA nicht aktiviert ist.
	 *
	 * Erwartetes Ergebnis:
	 * - Die Middleware sollte den Request an den nächsten Handler weiterleiten und eine Response zurückgeben.
	 */
	public function testProcessWithUserWithout2FA() {
		$request = new ServerRequest();
		$request = $request->withAttribute(
			'identity',
			array(
				'id'          => 2,
				'username'    => 'user2',
				'secret_2tfa' => null,
			)
		);
		$handler = new TestRequestHandler();

		$response = $this->middleware->process( $request, $handler );
		$this->assertInstanceOf( Response::class, $response );

		$instance = $handler->request->getAttribute( 'simpleAuthenticationResult' );
		$this->assertEquals( ResultResult::SIMPLE_TWO_FA_NO_AUTH_REQUIRED, $instance->getStatus() );
	}

	/**
	 * Test the process method when a user is authenticated and 2FA is enabled.
	 *
	 * Testziel:
	 * - Überprüfen, dass die Middleware den Request korrekt verarbeitet, wenn ein Benutzer authentifiziert ist und 2FA aktiviert ist.
	 *
	 * Erwartetes Ergebnis:
	 * - Die Middleware sollte den Request nicht an den nächsten Handler weiterleiten und stattdessen eine RedirectResponse zurückgeben.
	 */
	public function testProcessWithUserWith2FA() {
		$request = new ServerRequest();
		$request = $request->withAttribute(
			'identity',
			array(
				'id'          => 1,
				'username'    => 'user1',
				'secret_2tfa' => 'secret1',
			)
		);
		$handler = new TestRequestHandler();

		$response = $this->middleware->process( $request, $handler );
		$this->assertInstanceOf( Response::class, $response );

		$headers = $response->getHeaders();
        $this->assertEquals('/users/verifytfa', $headers['Location'][0]);

		$instance = $handler->request->getAttribute( 'simpleAuthenticationResult' );
		$this->assertEquals( ResultResult::SIMPLE_TWO_FA_AUTH_REQUIRED, $instance->getStatus() );
	}

	/**
	 * Test the process method when a valid 2FA code is provided.
	 *
	 * Testziel:
	 * - Überprüfen, dass die Middleware den Request korrekt verarbeitet, wenn ein gültiger 2FA-Code bereitgestellt wird.
	 *
	 * Erwartetes Ergebnis:
	 * - Die Middleware sollte den Request an den nächsten Handler weiterleiten und eine Response zurückgeben.
	 */
	public function testProcessWithValid2FACode() {

		$authUser = new \ArrayObject([
			'id' => 1,
			'username' => 'user1',
			'secret_2tfa' => 'secret1',
		], \ArrayObject::ARRAY_AS_PROPS);
		$session = new \Cake\Http\Session();
		$session->write('Auth', $authUser);

		$request = new ServerRequest(
			array(
				'post' => array(
					'code' => '123456',
				),
				'session' => $session,
			)
		);
		$request = $request->withAttribute(
			'identity',
			array(
				'id'          => 1,
				'username'    => 'user1',
				'secret_2tfa' => 'secret1',
			)
		);

		$handler = new TestRequestHandler();

		$middleware = $this->getMockBuilder( TwoFactorMiddleware::class )
			->onlyMethods( array( '_verifyCode' ) )
			->getMock();
		$middleware->expects( $this->once() )
			->method( '_verifyCode' )
			->with( 'secret1', '123456' )
			->willReturn( true );

		/** @disregard **/
		$response = $middleware->process( $request, $handler );
		$this->assertInstanceOf( Response::class, $response );

		$instance = $handler->request->getAttribute( 'simpleAuthenticationResult' );
		$this->assertEquals( ResultResult::SIMPLE_TWO_FA_AUTH_SUCCESS, $instance->getStatus() );
	}

	/**
	 * Test the process method when an invalid 2FA code is provided.
	 *
	 * Testziel:
	 * - Überprüfen, dass die Middleware den Request korrekt verarbeitet, wenn ein ungültiger 2FA-Code bereitgestellt wird.
	 *
	 * Erwartetes Ergebnis:
	 * - Die Middleware sollte den Request an den nächsten Handler weiterleiten und eine Response zurückgeben.
	 * - Die Response sollte den Status SIMPLE_TWO_FA_AUTH_FAILED enthalten.
	 */
	public function testProcessWithInvalid2FACode() {
		$authUser = new \ArrayObject([
			'id' => 1,
			'username' => 'user1',
			'secret_2tfa' => 'secret1',
		], \ArrayObject::ARRAY_AS_PROPS);
		$session = new \Cake\Http\Session();
		$session->write('Auth', $authUser);

		$request = new ServerRequest(
			array(
				'post' => array(
					'code' => '123456',
				),
				'session' => $session,
			)
		);
		$request = $request->withAttribute(
			'identity',
			array(
				'id'          => 1,
				'username'    => 'user1',
				'secret_2tfa' => 'secret1',
			)
		);
		$handler = new TestRequestHandler();

		$middleware = $this->getMockBuilder( TwoFactorMiddleware::class )
			->onlyMethods( array( '_verifyCode' ) )
			->getMock();
		$middleware->expects( $this->once() )
			->method( '_verifyCode' )
			->with( 'secret1', '123456' )
			->willReturn( false );

		/** @disregard **/
		$response = $middleware->process( $request, $handler );
		$this->assertInstanceOf( Response::class, $response );

		$instance = $handler->request->getAttribute( 'simpleAuthenticationResult' );
		$this->assertEquals( ResultResult::SIMPLE_TWO_FA_AUTH_FAILED, $instance->getStatus() );
	}

	/**
	 * Test the process method with different QR code providers.
	 */
	public function testProcessWithDifferentQrCodeProviders() {
		$providers = ['BaconQrCodeProvider', 'EndroidQrCodeProvider', 'defaultTrigger'];

		foreach ($providers as $provider) {
			$middleware = new TwoFactorMiddleware(['qrcodeprovider' => $provider]);

			$request = new ServerRequest();
			$request = $request->withAttribute(
				'identity',
				array(
					'id'          => 1,
					'username'    => 'user1',
					'secret_2tfa' => 'secret1',
				)
			);
			$handler = new TestRequestHandler();

			$response = $middleware->process($request, $handler);
			$this->assertInstanceOf(Response::class, $response);

			$headers = $response->getHeaders();
			$this->assertEquals('/users/verifytfa', $headers['Location'][0]);

			$instance = $handler->request->getAttribute('simpleAuthenticationResult');
			$this->assertEquals(ResultResult::SIMPLE_TWO_FA_AUTH_REQUIRED, $instance->getStatus());
		}
	}

	/**
	 * Test the process method with different algorithms.
	 */
	public function testProcessWithDifferentAlgorithms() {
		$algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'defaultTrigger'];

		foreach ($algorithms as $algorithm) {
			$middleware = new TwoFactorMiddleware(['algorithm' => $algorithm]);

			$request = new ServerRequest();
			$request = $request->withAttribute(
				'identity',
				array(
					'id'          => 1,
					'username'    => 'user1',
					'secret_2tfa' => 'secret1',
				)
			);
			$handler = new TestRequestHandler();

			$response = $middleware->process($request, $handler);
			$this->assertInstanceOf(Response::class, $response);

			$headers = $response->getHeaders();
			$this->assertEquals('/users/verifytfa', $headers['Location'][0]);

			$instance = $handler->request->getAttribute('simpleAuthenticationResult');
			$this->assertEquals(ResultResult::SIMPLE_TWO_FA_AUTH_REQUIRED, $instance->getStatus());
		}
	}

	/**
	 * Test the _verifyCode method with an invalid code.
	 */
	public function testVerifyCodeWithInvalidCode() {
		$secret = 'secret1';
		$invalidCode = '654321';

		$result = $this->invokeMethod($this->middleware, '_verifyCode', [$secret, $invalidCode]);
		$this->assertFalse($result);
	}

	/**
	 * Helper method to invoke protected/private methods.
	 */
	protected function invokeMethod(&$object, $methodName, array $parameters = []) {
		$reflection = new \ReflectionClass(get_class($object));
		$method = $reflection->getMethod($methodName);
		$method->setAccessible(true);

		return $method->invokeArgs($object, $parameters);
	}
}
