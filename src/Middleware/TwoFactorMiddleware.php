<?php
/**
 * Created on Sun Feb 16 2025
 * TH Control Panel
 * Copyright (c) 2025 IT-Dienstleistungen Drevermann - All Rights Reserved
 *
 * @author Daniel Drevermann <info@triopsi.com>
 * @copyright Copyright (c) 2025, IT-Dienstleistungen Drevermann
 * @package TH Control Panel
 */

namespace SimpleTwoFactor\Middleware;

use Authentication\UrlChecker\UrlCheckerTrait;
use Cake\Core\InstanceConfigTrait;
use Cake\Utility\Hash;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Server\MiddlewareInterface;
use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;
use RobThree\Auth\Providers\Qr\EndroidQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;
use SimpleTwoFactor\Result\Result as ResultResult;

class TwoFactorMiddleware implements MiddlewareInterface {

	use InstanceConfigTrait;
	use UrlCheckerTrait;

	/**
	 * Object TwoFactorAuth.
	 *
	 * @var \RobThree\Auth\TwoFactorAuth
	 */
	protected $_tfaObject;

	/**
	 * Configuration options
	 *
	 * The following keys are deprecated and should instead be set on the AuthenticationService
	 *
	 * - `sessionKey` - The session key to store the user in. Default: Auth
	 * - `redirect_url` - The URL to redirect unauthenticated users to. Default: /users/verifytfa
	 * - `session_key_verified` - The session key to store the 2FA verified status. Default: 2fa_verified
	 * - `user_key_secret` - The user key to store the 2FA secret. Default: secret_2tfa
	 * - `urlChecker` - The URL checker config. Default: Authentication.Default
	 * - `issuer` Will be displayed in the app as issuer name. Default: null
	 * - `digits` The number of digits the resulting codes will be. Default: 6
	 * - `period` The number of seconds a code will be valid. Default: 30
	 * - `algorithm` The algorithm used. Options: Sha1, Sha256, Sha512, Md5 Default: Sha1
	 * - `qrcodeprovider` QR-code provider. Options: BaconQrCodeProvider, EndroidQrCodeProvider Default: BaconQrCodeProvider
	 * - `rngprovider` Random Number Generator provider. Default: null
	 * - `timeprovider` Time provider. Default: null
	 *
	 * @var array
	 */
	protected $_defaultConfig = array(
		'userSessionKey'       => 'Auth',
		'codeField'            => 'code',
		'redirectUrl'          => '/users/verifytfa',
		'sessionKeyVerified'   => '2fa_verified',
		'userKeySecret'        => 'secret_2tfa',
		'isEnabled2faProperty' => 'secret_2tfa',
		'urlChecker'           => 'Authentication.Default',
		'issuer'               => null,
		'digits'               => 6,
		'period'               => 30,
		'algorithm'            => 'sha1',
		'qrcodeprovider'       => 'BaconQrCodeProvider',
		'rngprovider'          => null,
		'timeprovider'         => null,
	);

	/**
	 * Constructor
	 *
	 * @param array $config Configuration options.
	 */
	public function __construct( array $config = array() ) {
		$this->setConfig( $config );
	}

	/**
	 * Process the middleware.
	 *
	 * @param \Psr\Http\Message\ServerRequestInterface $request The request.
	 * @param \Psr\Http\Server\RequestHandlerInterface $handler The request handler.
	 * @return \Psr\Http\Message\ResponseInterface A response.
	 */
	public function process( ServerRequestInterface $request, RequestHandlerInterface $handler ): ResponseInterface {

		// Get the user from the session.
		$userSession  = $this->_getUserSession( $request );
		$userIdentity = $request->getAttribute( 'identity' );

		// If no user is logged in, we don't need to check for 2FA
		$result  = new ResultResult( ResultResult::SIMPLE_TWO_FA_AUTH_MISSING_CREDENTIALS );
		$request = $request->withAttribute( 'simpleAuthenticationResult', $result );
		$request = $request->withAttribute( 'simpleAuthenticationObject', $this->getTfa() );
		if ( empty( $userIdentity ) ) {
			return $handler->handle( $request );
		}

		// 1. Get the 2FA secret from the user
		$twoFactorSecret = false;
		if($this->_getUserTwoFaEnabledStatus( $userIdentity )){
			$twoFactorSecret = $this->_getUserSecretField( $userIdentity );
		}

		// 2. Get the 2FA verified status from the session
		$verifyViaSession = $this->_getUserTwoFaEnabledStatusFromSession( $userSession );

		// 3. Check if the request is a valid redirect target
		$validRequestRedirecTarget = $this->_getUrlChecker()->check(
			$request,
			$this->getConfig( 'redirectUrl' ),
			(array) $this->getConfig( 'urlChecker' )
		);

		// 4. Get the code field value from the request.
		$codeFieldValue = Hash::get( $request->getParsedBody(), $this->getConfig( 'codeField' ) );

		// If the code field is not empty, we need to verify the code
		if ( ! is_null( $codeFieldValue ) ) {
			// Check if the code is valid
			$validCode = $this->_verifyCode( $twoFactorSecret, $codeFieldValue );

			// If the code is valid, set the 2FA verified status in the session
			if ( $validCode ) {
				$userSession->{$this->getConfig( 'userSessionKey' )} = true;
				$this->_writeUserSession( $request, $userSession );
				$result  = new ResultResult( ResultResult::SIMPLE_TWO_FA_AUTH_SUCCESS );
				$request = $request->withAttribute( 'simpleAuthenticationResult', $result );
			} else {
				$result  = new ResultResult( ResultResult::SIMPLE_TWO_FA_AUTH_FAILED );
				$request = $request->withAttribute( 'simpleAuthenticationResult', $result );
			}
			return $handler->handle( $request );
		}

		if ( $twoFactorSecret && ! $verifyViaSession ) {
			$result  = new ResultResult( ResultResult::SIMPLE_TWO_FA_AUTH_REQUIRED );
			$request = $request->withAttribute( 'simpleAuthenticationResult', $result );
		}

		// If the user has a 2FA secret or it's not 2tfa verified or the target is the redirectUrl, than redirect to the 2FA verification page.
		if ( ! $twoFactorSecret || $verifyViaSession || $validRequestRedirecTarget ) {
			$result  = new ResultResult( ResultResult::SIMPLE_TWO_FA_NO_AUTH_REQUIRED );
			$request = $request->withAttribute( 'simpleAuthenticationResult', $result );
			return $handler->handle( $request );
		}

		$response = $handler->handle( $request );
		return $response->withHeader( 'Location', $this->getConfig( 'redirectUrl' ) )->withStatus( 302 );
	}

	/**
	 * Get user's 2FA secret.
	 *
	 * @param array $user User.
	 * @return string|null
	 */
	protected function _getUserSecretField( $user ) {
		return Hash::get( $user, $this->getConfig( 'userKeySecret' ) );
	}

	/**
	 * Check if 2FA is enabled for the given user.
	 *
	 * @param array $user User.
	 * @return bool
	 */
	protected function _getUserTwoFaEnabledStatus( $user ) {
		return (bool) Hash::get( $user, $this->getConfig( 'isEnabled2faProperty', $this->getConfig( 'userKeySecret' ) ) );
	}

	/**
	 * Check if 2FA is enabled for the given user.
	 *
	 * @param array $user User.
	 * @return bool
	 */
	protected function _getUserTwoFaEnabledStatusFromSession( $user ) {
		if ( empty( $user ) ) {
			return false;
		}
		return $user;
	}

	/**
	 * Get the User Session.
	 *
	 * @param ServerRequestInterface $request
	 * @return object|null
	 */
	protected function _getUserSession( ServerRequestInterface $request ) {
		$session = $request->getAttribute( 'session' );
		return $session->read( $this->getConfig( 'userSessionKey' ) );
	}

	/**
	 * Write the User Session.
	 *
	 * @param ServerRequestInterface $request
	 * @param $value
	 */
	protected function _writeUserSession( ServerRequestInterface $request, $value ) {
		$session = $request->getAttribute( 'session' );
		$session->write( $this->getConfig( 'userSessionKey' ), $value );
	}

	/**
	 * Verify 2FA code.
	 *
	 * @param string $secret Secret.
	 * @param string $codeFieldValue One-time code.
	 * @return bool
	 */
	protected function _verifyCode( $secret, $codeFieldValue ): bool {
		try {
			return $this->getTfa()->verifyCode( $secret, $codeFieldValue );
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Get RobThree\Auth\TwoFactorAuth object.
	 *
	 * @return \RobThree\Auth\TwoFactorAuth
	 * @throws \RobThree\Auth\TwoFactorAuthException Throw.
	 */
	public function getTfa() {
		if ( ! $this->_tfaObject ) {

			// Switch case for the QRCodeProvider
			switch ( $this->getConfig( 'qrcodeprovider' ) ) {
				case 'BaconQrCodeProvider':
					$qrcodeprovider = new BaconQrCodeProvider();
					break;
				case 'EndroidQrCodeProvider':
					$qrcodeprovider = new EndroidQrCodeProvider();
					break;
				default:
					$qrcodeprovider = new BaconQrCodeProvider();
					break;
			}

			// Swict Case for the Algorithm
			switch ( $this->getConfig( 'algorithm' ) ) {
				case 'md5':
					$algorithm = \RobThree\Auth\Algorithm::Md5;
					break;
				case 'sha1':
					$algorithm = \RobThree\Auth\Algorithm::Sha1;
					break;
				case 'sha256':
					$algorithm = \RobThree\Auth\Algorithm::Sha256;
					break;
				case 'sha512':
					$algorithm = \RobThree\Auth\Algorithm::Sha512;
					break;
				default:
					$algorithm = \RobThree\Auth\Algorithm::Sha1;
					break;
			}

			$this->_tfaObject = new TwoFactorAuth(
				$qrcodeprovider,
				$this->getConfig( 'issuer' ),
				$this->getConfig( 'digits' ),
				$this->getConfig( 'period' ),
				$algorithm,
				$this->getConfig( 'rngprovider' ),
				$this->getConfig( 'timeprovider' )
			);
		}

		return $this->_tfaObject;
	}
}
