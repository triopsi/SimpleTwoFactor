<?php
/**
 * Webinterface for Triopsi Hosting.
 * Copyright (C) 2021 Triopsi Hosting - All Rights Reserved
 *
 * @author Daniel Drevermann <info@triopsi.com>
 * @copyright Copyright (c) 2021, Triopsi Hosting
 * @package th-control-panel
 */

namespace SimpleTwoFactor\Controller\Component;

use Cake\Controller\Component;
use Exception;

/**
 * Authentication component
 */
class SimpleTwoFactorComponent extends Component {

	/**
	 * Default configuration.
	 *
	 * @var array
	 */
	protected $_defaultConfig = array();

	/**
	 * Verify one-time code.
	 *
	 * @param string $secret users's secret.
	 * @param string $code one-time code.
	 * @return bool
	 * @throws \RobThree\Auth\TwoFactorAuthException Throws.
	 */
	public function verifyCode( $secret, $code) {
		return $this->getTfa()->verifyCode( $secret, str_replace( ' ', '', $code ) );
	}

	/**
	 * Create 2FA secret.
	 *
	 * @param int  $bits Number of bits.
	 * @param bool $requireCryptoSecure Require crypto secure.
	 * @return string
	 * @throws \RobThree\Auth\TwoFactorAuthException Throws.
	 */
	public function createSecret( $bits = 80, $requireCryptoSecure = true) {
		return $this->getTfa()->createSecret( $bits, $requireCryptoSecure );
	}

	/**
	 * Get data-uri of QRCode.
	 *
	 * @param string $label Label.
	 * @param string $secret Secret.
	 * @param int    $size Size.
	 * @return string
	 * @throws \RobThree\Auth\TwoFactorAuthException Throws.
	 */
	public function getQRCodeImageAsDataUri( $label, $secret, $size = 200) {
		return $this->getTfa()->getQRCodeImageAsDataUri( $label, $secret, $size );
	}

	/**
	 * Get the result of the two-factor authentication.
	 * 
	 * @return \Authentication\Authenticator\ResultInterface
	 * @throws \Exception Throws.
	 */
    public function getResult() {
        $controller = $this->getController();
        $simpleAuthenticationResult = $controller->getRequest()->getAttribute('simpleAuthenticationResult');
        if ($simpleAuthenticationResult === null) {
            throw new Exception(
                'The request object does not contain the required `simpleAuthenticationResult` attribute. Verify the ' .
                'TwoFactorMiddleware has been added.'
            );
        }
        return $simpleAuthenticationResult;
    }

	/**
	 * Get RobThree\Auth\TwoFactorAuth object.
	 *
	 * @return \RobThree\Auth\TwoFactorAuth
	 * @throws \RobThree\Auth\TwoFactorAuthException Throws.
	 */
	public function getTfa() {
        $controller = $this->getController();
        $simpleAuthenticationObject = $controller->getRequest()->getAttribute('simpleAuthenticationObject');
        if ($simpleAuthenticationObject === null) {
            throw new Exception(
                'The request object does not contain the required `simpleAuthenticationObject` attribute. Verify the ' .
                'TwoFactorMiddleware has been added.'
            );
        }

		return $simpleAuthenticationObject;
	}
}
