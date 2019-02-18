<?php
namespace {
if (!class_exists('Crypt_DES')) {
	include_once 'DES.php';
}

define('CRYPT_MODE_3CBC', -2);

define('CRYPT_DES_MODE_3CBC', -2);

define('CRYPT_MODE_CBC3', CRYPT_MODE_CBC);

define('CRYPT_DES_MODE_CBC3', CRYPT_MODE_CBC3);

class Crypt_TripleDES extends Crypt_DES
{

	var $key_length = 24;

	var $password_default_salt = 'phpseclib';

	var $const_namespace = 'DES';

	var $cipher_name_mcrypt = 'tripledes';

	var $cfb_init_len = 750;

	var $key_length_max = 24;

	var $mode_3cbc;

	var $des;

	function __construct($mode = CRYPT_MODE_CBC)
	{
		switch ($mode) {
									case CRYPT_DES_MODE_3CBC:
				parent::Crypt_Base(CRYPT_MODE_CBC);
				$this->mode_3cbc = true;

								$this->des = array(
					new Crypt_DES(CRYPT_MODE_CBC),
					new Crypt_DES(CRYPT_MODE_CBC),
					new Crypt_DES(CRYPT_MODE_CBC),
				);

								$this->des[0]->disablePadding();
				$this->des[1]->disablePadding();
				$this->des[2]->disablePadding();
				break;
						default:
				parent::__construct($mode);
		}
	}

	function Crypt_TripleDES($mode = CRYPT_MODE_CBC)
	{
		$this->__construct($mode);
	}

	function isValidEngine($engine)
	{
		if ($engine == CRYPT_ENGINE_OPENSSL) {
			$this->cipher_name_openssl_ecb = 'des-ede3';
			$mode = $this->_openssl_translate_mode();
			$this->cipher_name_openssl = $mode == 'ecb' ? 'des-ede3' : 'des-ede3-' . $mode;
		}

		return parent::isValidEngine($engine);
	}

	function setIV($iv)
	{
		parent::setIV($iv);
		if ($this->mode_3cbc) {
			$this->des[0]->setIV($iv);
			$this->des[1]->setIV($iv);
			$this->des[2]->setIV($iv);
		}
	}

	function setKeyLength($length)
	{
		$length >>= 3;
		switch (true) {
			case $length <= 8:
				$this->key_length = 8;
				break;
			case $length <= 16:
				$this->key_length = 16;
				break;
			default:
				$this->key_length = 24;
		}

		parent::setKeyLength($length);
	}

	function setKey($key)
	{
		$length = $this->explicit_key_length ? $this->key_length : strlen($key);
		if ($length > 8) {
			$key = str_pad(substr($key, 0, 24), 24, chr(0));
									$key = $length <= 16 ? substr_replace($key, substr($key, 0, 8), 16) : substr($key, 0, 24);
		} else {
			$key = str_pad($key, 8, chr(0));
		}
		parent::setKey($key);

										if ($this->mode_3cbc && $length > 8) {
			$this->des[0]->setKey(substr($key,	0, 8));
			$this->des[1]->setKey(substr($key,	8, 8));
			$this->des[2]->setKey(substr($key, 16, 8));
		}
	}

	function encrypt($plaintext)
	{

				if ($this->mode_3cbc && strlen($this->key) > 8) {
			return $this->des[2]->encrypt(
				$this->des[1]->decrypt(
					$this->des[0]->encrypt(
						$this->_pad($plaintext)
					)
				)
			);
		}

		return parent::encrypt($plaintext);
	}

	function decrypt($ciphertext)
	{
		if ($this->mode_3cbc && strlen($this->key) > 8) {
			return $this->_unpad(
				$this->des[0]->decrypt(
					$this->des[1]->encrypt(
						$this->des[2]->decrypt(
							str_pad($ciphertext, (strlen($ciphertext) + 7) & 0xFFFFFFF8, "\0")
						)
					)
				)
			);
		}

		return parent::decrypt($ciphertext);
	}

	function enableContinuousBuffer()
	{
		parent::enableContinuousBuffer();
		if ($this->mode_3cbc) {
			$this->des[0]->enableContinuousBuffer();
			$this->des[1]->enableContinuousBuffer();
			$this->des[2]->enableContinuousBuffer();
		}
	}

	function disableContinuousBuffer()
	{
		parent::disableContinuousBuffer();
		if ($this->mode_3cbc) {
			$this->des[0]->disableContinuousBuffer();
			$this->des[1]->disableContinuousBuffer();
			$this->des[2]->disableContinuousBuffer();
		}
	}

	function _setupKey()
	{
		switch (true) {
									case strlen($this->key) <= 8:
				$this->des_rounds = 1;
				break;

						default:
				$this->des_rounds = 3;

								if ($this->mode_3cbc) {
					$this->des[0]->_setupKey();
					$this->des[1]->_setupKey();
					$this->des[2]->_setupKey();

															return;
				}
		}
				parent::_setupKey();
	}

	function setPreferredEngine($engine)
	{
		if ($this->mode_3cbc) {
			$this->des[0]->setPreferredEngine($engine);
			$this->des[1]->setPreferredEngine($engine);
			$this->des[2]->setPreferredEngine($engine);
		}

		return parent::setPreferredEngine($engine);
	}
}}