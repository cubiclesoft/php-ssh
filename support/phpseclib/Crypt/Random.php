<?php
namespace {
if (!function_exists('crypt_random_string')) {

	define('CRYPT_RANDOM_IS_WINDOWS', strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

	function crypt_random_string($length)
	{
		if (!$length) {
			return '';
		}

		if (CRYPT_RANDOM_IS_WINDOWS) {
						if (extension_loaded('mcrypt') && version_compare(PHP_VERSION, '5.3.0', '>=')) {
				return @mcrypt_create_iv($length);
			}
																																										if (extension_loaded('openssl') && version_compare(PHP_VERSION, '5.3.4', '>=')) {
				return openssl_random_pseudo_bytes($length);
			}
		} else {
						if (extension_loaded('openssl') && version_compare(PHP_VERSION, '5.3.0', '>=')) {
				return openssl_random_pseudo_bytes($length);
			}
						static $fp = true;
			if ($fp === true) {
												$fp = @fopen('/dev/urandom', 'rb');
			}
			if ($fp !== true && $fp !== false) { 				return fread($fp, $length);
			}
																		if (extension_loaded('mcrypt')) {
				return @mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
			}
		}

																																				static $crypto = false, $v;
		if ($crypto === false) {
						$old_session_id = session_id();
			$old_use_cookies = ini_get('session.use_cookies');
			$old_session_cache_limiter = session_cache_limiter();
			$_OLD_SESSION = isset($_SESSION) ? $_SESSION : false;
			if ($old_session_id != '') {
				session_write_close();
			}

			session_id(1);
			ini_set('session.use_cookies', 0);
			session_cache_limiter('');
			session_start();

			$v = $seed = $_SESSION['seed'] = pack('H*', sha1(
				(isset($_SERVER) ? phpseclib_safe_serialize($_SERVER) : '') .
				(isset($_POST) ? phpseclib_safe_serialize($_POST) : '') .
				(isset($_GET) ? phpseclib_safe_serialize($_GET) : '') .
				(isset($_COOKIE) ? phpseclib_safe_serialize($_COOKIE) : '') .
				phpseclib_safe_serialize($GLOBALS) .
				phpseclib_safe_serialize($_SESSION) .
				phpseclib_safe_serialize($_OLD_SESSION)
			));
			if (!isset($_SESSION['count'])) {
				$_SESSION['count'] = 0;
			}
			$_SESSION['count']++;

			session_write_close();

						if ($old_session_id != '') {
				session_id($old_session_id);
				session_start();
				ini_set('session.use_cookies', $old_use_cookies);
				session_cache_limiter($old_session_cache_limiter);
			} else {
				if ($_OLD_SESSION !== false) {
					$_SESSION = $_OLD_SESSION;
					unset($_OLD_SESSION);
				} else {
					unset($_SESSION);
				}
			}

																											$key = pack('H*', sha1($seed . 'A'));
			$iv = pack('H*', sha1($seed . 'C'));

												switch (true) {
				case phpseclib_resolve_include_path('Crypt/AES.php'):
					if (!class_exists('Crypt_AES')) {
						include_once 'AES.php';
					}
					$crypto = new Crypt_AES(CRYPT_AES_MODE_CTR);
					break;
				case phpseclib_resolve_include_path('Crypt/Twofish.php'):
					if (!class_exists('Crypt_Twofish')) {
						include_once 'Twofish.php';
					}
					$crypto = new Crypt_Twofish(CRYPT_TWOFISH_MODE_CTR);
					break;
				case phpseclib_resolve_include_path('Crypt/Blowfish.php'):
					if (!class_exists('Crypt_Blowfish')) {
						include_once 'Blowfish.php';
					}
					$crypto = new Crypt_Blowfish(CRYPT_BLOWFISH_MODE_CTR);
					break;
				case phpseclib_resolve_include_path('Crypt/TripleDES.php'):
					if (!class_exists('Crypt_TripleDES')) {
						include_once 'TripleDES.php';
					}
					$crypto = new Crypt_TripleDES(CRYPT_DES_MODE_CTR);
					break;
				case phpseclib_resolve_include_path('Crypt/DES.php'):
					if (!class_exists('Crypt_DES')) {
						include_once 'DES.php';
					}
					$crypto = new Crypt_DES(CRYPT_DES_MODE_CTR);
					break;
				case phpseclib_resolve_include_path('Crypt/RC4.php'):
					if (!class_exists('Crypt_RC4')) {
						include_once 'RC4.php';
					}
					$crypto = new Crypt_RC4();
					break;
				default:
					user_error('crypt_random_string requires at least one symmetric cipher be loaded');
					return false;
			}

			$crypto->setKey($key);
			$crypto->setIV($iv);
			$crypto->enableContinuousBuffer();
		}

																		$result = '';
		while (strlen($result) < $length) {
			$i = $crypto->encrypt(microtime()); 			$r = $crypto->encrypt($i ^ $v); 			$v = $crypto->encrypt($r ^ $i); 			$result.= $r;
		}
		return substr($result, 0, $length);
	}
}

if (!function_exists('phpseclib_safe_serialize')) {

	function phpseclib_safe_serialize(&$arr)
	{
		if (is_object($arr)) {
			return '';
		}
		if (!is_array($arr)) {
			return serialize($arr);
		}
				if (isset($arr['__phpseclib_marker'])) {
			return '';
		}
		$safearr = array();
		$arr['__phpseclib_marker'] = true;
		foreach (array_keys($arr) as $key) {
						if ($key !== '__phpseclib_marker') {
				$safearr[$key] = phpseclib_safe_serialize($arr[$key]);
			}
		}
		unset($arr['__phpseclib_marker']);
		return serialize($safearr);
	}
}

if (!function_exists('phpseclib_resolve_include_path')) {

	function phpseclib_resolve_include_path($filename)
	{
		if (function_exists('stream_resolve_include_path')) {
			return stream_resolve_include_path($filename);
		}

				if (file_exists($filename)) {
			return realpath($filename);
		}

		$paths = PATH_SEPARATOR == ':' ?
			preg_split('#(?<!phar):#', get_include_path()) :
			explode(PATH_SEPARATOR, get_include_path());
		foreach ($paths as $prefix) {
						$ds = substr($prefix, -1) == DIRECTORY_SEPARATOR ? '' : DIRECTORY_SEPARATOR;
			$file = $prefix . $ds . $filename;
			if (file_exists($file)) {
				return realpath($file);
			}
		}

		return false;
	}
}}