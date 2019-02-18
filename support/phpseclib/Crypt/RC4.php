<?php
namespace {
if (!class_exists('Crypt_Base')) {
	include_once 'Base.php';
}

define('CRYPT_RC4_ENCRYPT', 0);
define('CRYPT_RC4_DECRYPT', 1);

class Crypt_RC4 extends Crypt_Base
{

	var $block_size = 0;

	var $key_length = 128;

	var $const_namespace = 'RC4';

	var $cipher_name_mcrypt = 'arcfour';

	var $use_inline_crypt = false;

	var $key;

	var $stream;

	function __construct()
	{
		parent::__construct(CRYPT_MODE_STREAM);
	}

	function Crypt_RC4()
	{
		$this->__construct();
	}

	function isValidEngine($engine)
	{
		if ($engine == CRYPT_ENGINE_OPENSSL) {
			if (version_compare(PHP_VERSION, '5.3.7') >= 0) {
				$this->cipher_name_openssl = 'rc4-40';
			} else {
				switch (strlen($this->key)) {
					case 5:
						$this->cipher_name_openssl = 'rc4-40';
						break;
					case 8:
						$this->cipher_name_openssl = 'rc4-64';
						break;
					case 16:
						$this->cipher_name_openssl = 'rc4';
						break;
					default:
						return false;
				}
			}
		}

		return parent::isValidEngine($engine);
	}

	function setIV($iv)
	{
	}

	function setKeyLength($length)
	{
		if ($length < 8) {
			$this->key_length = 1;
		} elseif ($length > 2048) {
			$this->key_length = 256;
		} else {
			$this->key_length = $length >> 3;
		}

		parent::setKeyLength($length);
	}

	function encrypt($plaintext)
	{
		if ($this->engine != CRYPT_ENGINE_INTERNAL) {
			return parent::encrypt($plaintext);
		}
		return $this->_crypt($plaintext, CRYPT_RC4_ENCRYPT);
	}

	function decrypt($ciphertext)
	{
		if ($this->engine != CRYPT_ENGINE_INTERNAL) {
			return parent::decrypt($ciphertext);
		}
		return $this->_crypt($ciphertext, CRYPT_RC4_DECRYPT);
	}

	function _setupKey()
	{
		$key = $this->key;
		$keyLength = strlen($key);
		$keyStream = range(0, 255);
		$j = 0;
		for ($i = 0; $i < 256; $i++) {
			$j = ($j + $keyStream[$i] + ord($key[$i % $keyLength])) & 255;
			$temp = $keyStream[$i];
			$keyStream[$i] = $keyStream[$j];
			$keyStream[$j] = $temp;
		}

		$this->stream = array();
		$this->stream[CRYPT_RC4_DECRYPT] = $this->stream[CRYPT_RC4_ENCRYPT] = array(
			0, 			0, 			$keyStream
		);
	}

	function _crypt($text, $mode)
	{
		if ($this->changed) {
			$this->_setup();
			$this->changed = false;
		}

		$stream = &$this->stream[$mode];
		if ($this->continuousBuffer) {
			$i = &$stream[0];
			$j = &$stream[1];
			$keyStream = &$stream[2];
		} else {
			$i = $stream[0];
			$j = $stream[1];
			$keyStream = $stream[2];
		}

		$len = strlen($text);
		for ($k = 0; $k < $len; ++$k) {
			$i = ($i + 1) & 255;
			$ksi = $keyStream[$i];
			$j = ($j + $ksi) & 255;
			$ksj = $keyStream[$j];

			$keyStream[$i] = $ksj;
			$keyStream[$j] = $ksi;
			$text[$k] = $text[$k] ^ chr($keyStream[($ksj + $ksi) & 255]);
		}

		return $text;
	}
}}