<?php
/**
 * Created on Mon Feb 17 2025
 * TH Control Panel
 * Copyright (c) 2025 IT-Dienstleistungen Drevermann - All Rights Reserved
 *
 * @author Daniel Drevermann <info@triopsi.com>
 * @copyright Copyright (c) 2025, IT-Dienstleistungen Drevermann
 * @package TH Control Panel
 */

namespace SimpleTwoFactor\Result;

use Authentication\Authenticator\ResultInterface;

class Result implements ResultInterface {

	/**
	 * Authentication result status
	 *
	 * @var string
	 */
	protected $_status;

	/**
	 * General failure due to any other circumstances.
	 */
	public const SIMPLE_TWO_FA_AUTH_REQUIRED = 'SIMPLE_TWO_FA_AUTH_REQUIRED';

	/**
	 * General failure due to any other circumstances.
	 */
	public const SIMPLE_TWO_FA_NO_AUTH_REQUIRED = 'SIMPLE_TWO_FA_NO_AUTH_REQUIRED';

	/**
	 * General failure due to any other circumstances.
	 */
	public const SIMPLE_TWO_FA_AUTH_FAILED = 'SIMPLE_TWO_FA_AUTH_FAILED';

	/**
	 * General failure due to any other circumstances.
	 */
	public const SIMPLE_TWO_FA_AUTH_SUCCESS = 'SIMPLE_TWO_FA_AUTH_SUCCESS';

	/**
	 * General failure due to any other circumstances.
	 */
	public const SIMPLE_TWO_FA_AUTH_MISSING_CREDENTIALS = 'SIMPLE_TWO_FA_AUTH_MISSING_CREDENTIALS';

	/**
	 * Sets the result status, identity, and failure messages
	 *
	 * @param string $status Status constant equivalent.
	 */
	public function __construct( $status ) {
		$this->_status = $status;
	}

	/**
	 * Returns whether the result represents a successful authentication attempt.
	 * @codeCoverageIgnore
	 * 
	 * @return bool
	 */
	public function isValid(): bool {
		return $this->_status === ResultInterface::SUCCESS;
	}

    /**
     * Returns the status of the authentication attempt.
     *
     * @return string
     */
	public function getStatus(): string {
		return $this->_status;
	}

	/**
	 * Returns the data related to the authentication attempt.
	 *
	 * @codeCoverageIgnore
	 * @return array
	 */
	public function getData(): array {
		return array();
	}

	/**
	 * Returns the errors related to the authentication attempt.
	 *
	 * @codeCoverageIgnore
	 * @return array
	 */
	public function getErrors(): array {
		return array();
	}


}
