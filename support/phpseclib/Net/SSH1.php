<?php
namespace {
define('NET_SSH1_CIPHER_NONE',		0);

define('NET_SSH1_CIPHER_IDEA',		1);

define('NET_SSH1_CIPHER_DES',		2);

define('NET_SSH1_CIPHER_3DES',		3);

define('NET_SSH1_CIPHER_BROKEN_TSS', 4);

define('NET_SSH1_CIPHER_RC4',		5);

define('NET_SSH1_CIPHER_BLOWFISH',	6);

define('NET_SSH1_AUTH_RHOSTS',	 1);

define('NET_SSH1_AUTH_RSA',		2);

define('NET_SSH1_AUTH_PASSWORD',	3);

define('NET_SSH1_AUTH_RHOSTS_RSA', 4);

define('NET_SSH1_TTY_OP_END',	0);

define('NET_SSH1_RESPONSE_TYPE', 1);

define('NET_SSH1_RESPONSE_DATA', 2);

define('NET_SSH1_MASK_CONSTRUCTOR', 0x00000001);
define('NET_SSH1_MASK_CONNECTED',	0x00000002);
define('NET_SSH1_MASK_LOGIN',		0x00000004);
define('NET_SSH1_MASK_SHELL',		0x00000008);

define('NET_SSH1_LOG_SIMPLE',	1);

define('NET_SSH1_LOG_COMPLEX', 2);

define('NET_SSH1_LOG_REALTIME', 3);

define('NET_SSH1_LOG_REALTIME_FILE', 4);

define('NET_SSH1_READ_SIMPLE',	1);

define('NET_SSH1_READ_REGEX', 2);

class Net_SSH1
{

	var $identifier = 'SSH-1.5-phpseclib';

	var $fsock;

	var $crypto = false;

	var $bitmap = 0;

	var $server_key_public_exponent;

	var $server_key_public_modulus;

	var $host_key_public_exponent;

	var $host_key_public_modulus;

	var $supported_ciphers = array(
		NET_SSH1_CIPHER_NONE		=> 'No encryption',
		NET_SSH1_CIPHER_IDEA		=> 'IDEA in CFB mode',
		NET_SSH1_CIPHER_DES		=> 'DES in CBC mode',
		NET_SSH1_CIPHER_3DES		=> 'Triple-DES in CBC mode',
		NET_SSH1_CIPHER_BROKEN_TSS => 'TRI\'s Simple Stream encryption CBC',
		NET_SSH1_CIPHER_RC4		=> 'RC4',
		NET_SSH1_CIPHER_BLOWFISH	=> 'Blowfish'
	);

	var $supported_authentications = array(
		NET_SSH1_AUTH_RHOSTS	 => '.rhosts or /etc/hosts.equiv',
		NET_SSH1_AUTH_RSA		=> 'pure RSA authentication',
		NET_SSH1_AUTH_PASSWORD	=> 'password authentication',
		NET_SSH1_AUTH_RHOSTS_RSA => '.rhosts with RSA host authentication'
	);

	var $server_identification = '';

	var $protocol_flags = array();

	var $protocol_flag_log = array();

	var $message_log = array();

	var $realtime_log_file;

	var $realtime_log_size;

	var $realtime_log_wrap;

	var $interactiveBuffer = '';

	var $timeout;

	var $curTimeout;

	var $log_boundary = ':';

	var $log_long_width = 65;

	var $log_short_width = 16;

	var $host;

	var $port;

	var $connectionTimeout;

	var $cipher;

	function __construct($host, $port = 22, $timeout = 10, $cipher = NET_SSH1_CIPHER_3DES)
	{
		if (!class_exists('Math_BigInteger')) {
			include_once 'Math/BigInteger.php';
		}

												if (!function_exists('crypt_random_string') && !class_exists('Crypt_Random') && !function_exists('crypt_random_string')) {
			include_once 'Crypt/Random.php';
		}

		$this->protocol_flags = array(
			1	=> 'NET_SSH1_MSG_DISCONNECT',
			2	=> 'NET_SSH1_SMSG_PUBLIC_KEY',
			3	=> 'NET_SSH1_CMSG_SESSION_KEY',
			4	=> 'NET_SSH1_CMSG_USER',
			9	=> 'NET_SSH1_CMSG_AUTH_PASSWORD',
			10 => 'NET_SSH1_CMSG_REQUEST_PTY',
			12 => 'NET_SSH1_CMSG_EXEC_SHELL',
			13 => 'NET_SSH1_CMSG_EXEC_CMD',
			14 => 'NET_SSH1_SMSG_SUCCESS',
			15 => 'NET_SSH1_SMSG_FAILURE',
			16 => 'NET_SSH1_CMSG_STDIN_DATA',
			17 => 'NET_SSH1_SMSG_STDOUT_DATA',
			18 => 'NET_SSH1_SMSG_STDERR_DATA',
			19 => 'NET_SSH1_CMSG_EOF',
			20 => 'NET_SSH1_SMSG_EXITSTATUS',
			33 => 'NET_SSH1_CMSG_EXIT_CONFIRMATION'
		);

		$this->_define_array($this->protocol_flags);

		$this->host = $host;
		$this->port = $port;
		$this->connectionTimeout = $timeout;
		$this->cipher = $cipher;
	}

	function Net_SSH1($host, $port = 22, $timeout = 10, $cipher = NET_SSH1_CIPHER_3DES)
	{
		$this->__construct($host, $port, $timeout, $cipher);
	}

	function _connect()
	{
		$this->fsock = @fsockopen($this->host, $this->port, $errno, $errstr, $this->connectionTimeout);
		if (!$this->fsock) {
			user_error(rtrim("Cannot connect to {$this->host}:{$this->port}. Error $errno. $errstr"));
			return false;
		}

		$this->server_identification = $init_line = fgets($this->fsock, 255);

		if (defined('NET_SSH1_LOGGING')) {
			$this->_append_log('<-', $this->server_identification);
			$this->_append_log('->', $this->identifier . "\r\n");
		}

		if (!preg_match('#SSH-([0-9\.]+)-(.+)#', $init_line, $parts)) {
			user_error('Can only connect to SSH servers');
			return false;
		}
		if ($parts[1][0] != 1) {
			user_error("Cannot connect to SSH $parts[1] servers");
			return false;
		}

		fputs($this->fsock, $this->identifier."\r\n");

		$response = $this->_get_binary_packet();
		if ($response[NET_SSH1_RESPONSE_TYPE] != NET_SSH1_SMSG_PUBLIC_KEY) {
			user_error('Expected SSH_SMSG_PUBLIC_KEY');
			return false;
		}

		$anti_spoofing_cookie = $this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 8);

		$this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 4);

		if (strlen($response[NET_SSH1_RESPONSE_DATA]) < 2) {
			return false;
		}
		$temp = unpack('nlen', $this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 2));
		$server_key_public_exponent = new Math_BigInteger($this->_string_shift($response[NET_SSH1_RESPONSE_DATA], ceil($temp['len'] / 8)), 256);
		$this->server_key_public_exponent = $server_key_public_exponent;

		if (strlen($response[NET_SSH1_RESPONSE_DATA]) < 2) {
			return false;
		}
		$temp = unpack('nlen', $this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 2));
		$server_key_public_modulus = new Math_BigInteger($this->_string_shift($response[NET_SSH1_RESPONSE_DATA], ceil($temp['len'] / 8)), 256);
		$this->server_key_public_modulus = $server_key_public_modulus;

		$this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 4);

		if (strlen($response[NET_SSH1_RESPONSE_DATA]) < 2) {
			return false;
		}
		$temp = unpack('nlen', $this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 2));
		$host_key_public_exponent = new Math_BigInteger($this->_string_shift($response[NET_SSH1_RESPONSE_DATA], ceil($temp['len'] / 8)), 256);
		$this->host_key_public_exponent = $host_key_public_exponent;

		if (strlen($response[NET_SSH1_RESPONSE_DATA]) < 2) {
			return false;
		}
		$temp = unpack('nlen', $this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 2));
		$host_key_public_modulus = new Math_BigInteger($this->_string_shift($response[NET_SSH1_RESPONSE_DATA], ceil($temp['len'] / 8)), 256);
		$this->host_key_public_modulus = $host_key_public_modulus;

		$this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 4);

				if (strlen($response[NET_SSH1_RESPONSE_DATA]) < 4) {
			return false;
		}
		extract(unpack('Nsupported_ciphers_mask', $this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 4)));
		foreach ($this->supported_ciphers as $mask => $name) {
			if (($supported_ciphers_mask & (1 << $mask)) == 0) {
				unset($this->supported_ciphers[$mask]);
			}
		}

				if (strlen($response[NET_SSH1_RESPONSE_DATA]) < 4) {
			return false;
		}
		extract(unpack('Nsupported_authentications_mask', $this->_string_shift($response[NET_SSH1_RESPONSE_DATA], 4)));
		foreach ($this->supported_authentications as $mask => $name) {
			if (($supported_authentications_mask & (1 << $mask)) == 0) {
				unset($this->supported_authentications[$mask]);
			}
		}

		$session_id = pack('H*', md5($host_key_public_modulus->toBytes() . $server_key_public_modulus->toBytes() . $anti_spoofing_cookie));

		$session_key = crypt_random_string(32);
		$double_encrypted_session_key = $session_key ^ str_pad($session_id, 32, chr(0));

		if ($server_key_public_modulus->compare($host_key_public_modulus) < 0) {
			$double_encrypted_session_key = $this->_rsa_crypt(
				$double_encrypted_session_key,
				array(
					$server_key_public_exponent,
					$server_key_public_modulus
				)
			);
			$double_encrypted_session_key = $this->_rsa_crypt(
				$double_encrypted_session_key,
				array(
					$host_key_public_exponent,
					$host_key_public_modulus
				)
			);
		} else {
			$double_encrypted_session_key = $this->_rsa_crypt(
				$double_encrypted_session_key,
				array(
					$host_key_public_exponent,
					$host_key_public_modulus
				)
			);
			$double_encrypted_session_key = $this->_rsa_crypt(
				$double_encrypted_session_key,
				array(
					$server_key_public_exponent,
					$server_key_public_modulus
				)
			);
		}

		$cipher = isset($this->supported_ciphers[$this->cipher]) ? $this->cipher : NET_SSH1_CIPHER_3DES;
		$data = pack('C2a*na*N', NET_SSH1_CMSG_SESSION_KEY, $cipher, $anti_spoofing_cookie, 8 * strlen($double_encrypted_session_key), $double_encrypted_session_key, 0);

		if (!$this->_send_binary_packet($data)) {
			user_error('Error sending SSH_CMSG_SESSION_KEY');
			return false;
		}

		switch ($cipher) {
												case NET_SSH1_CIPHER_DES:
				if (!class_exists('Crypt_DES')) {
					include_once 'Crypt/DES.php';
				}
				$this->crypto = new Crypt_DES();
				$this->crypto->disablePadding();
				$this->crypto->enableContinuousBuffer();
				$this->crypto->setKey(substr($session_key, 0, 8));
				break;
			case NET_SSH1_CIPHER_3DES:
				if (!class_exists('Crypt_TripleDES')) {
					include_once 'Crypt/TripleDES.php';
				}
				$this->crypto = new Crypt_TripleDES(CRYPT_DES_MODE_3CBC);
				$this->crypto->disablePadding();
				$this->crypto->enableContinuousBuffer();
				$this->crypto->setKey(substr($session_key, 0, 24));
				break;
																										}

		$response = $this->_get_binary_packet();

		if ($response[NET_SSH1_RESPONSE_TYPE] != NET_SSH1_SMSG_SUCCESS) {
			user_error('Expected SSH_SMSG_SUCCESS');
			return false;
		}

		$this->bitmap = NET_SSH1_MASK_CONNECTED;

		return true;
	}

	function login($username, $password = '')
	{
		if (!($this->bitmap & NET_SSH1_MASK_CONSTRUCTOR)) {
			$this->bitmap |= NET_SSH1_MASK_CONSTRUCTOR;
			if (!$this->_connect()) {
				return false;
			}
		}

		if (!($this->bitmap & NET_SSH1_MASK_CONNECTED)) {
			return false;
		}

		$data = pack('CNa*', NET_SSH1_CMSG_USER, strlen($username), $username);

		if (!$this->_send_binary_packet($data)) {
			user_error('Error sending SSH_CMSG_USER');
			return false;
		}

		$response = $this->_get_binary_packet();

		if ($response === true) {
			return false;
		}
		if ($response[NET_SSH1_RESPONSE_TYPE] == NET_SSH1_SMSG_SUCCESS) {
			$this->bitmap |= NET_SSH1_MASK_LOGIN;
			return true;
		} elseif ($response[NET_SSH1_RESPONSE_TYPE] != NET_SSH1_SMSG_FAILURE) {
			user_error('Expected SSH_SMSG_SUCCESS or SSH_SMSG_FAILURE');
			return false;
		}

		$data = pack('CNa*', NET_SSH1_CMSG_AUTH_PASSWORD, strlen($password), $password);

		if (!$this->_send_binary_packet($data)) {
			user_error('Error sending SSH_CMSG_AUTH_PASSWORD');
			return false;
		}

				if (defined('NET_SSH1_LOGGING') && NET_SSH1_LOGGING == NET_SSH1_LOG_COMPLEX) {
			$data = pack('CNa*', NET_SSH1_CMSG_AUTH_PASSWORD, strlen('password'), 'password');
			$this->message_log[count($this->message_log) - 1] = $data;
		}

		$response = $this->_get_binary_packet();

		if ($response === true) {
			return false;
		}
		if ($response[NET_SSH1_RESPONSE_TYPE] == NET_SSH1_SMSG_SUCCESS) {
			$this->bitmap |= NET_SSH1_MASK_LOGIN;
			return true;
		} elseif ($response[NET_SSH1_RESPONSE_TYPE] == NET_SSH1_SMSG_FAILURE) {
			return false;
		} else {
			user_error('Expected SSH_SMSG_SUCCESS or SSH_SMSG_FAILURE');
			return false;
		}
	}

	function setTimeout($timeout)
	{
		$this->timeout = $this->curTimeout = $timeout;
	}

	function exec($cmd, $block = true)
	{
		if (!($this->bitmap & NET_SSH1_MASK_LOGIN)) {
			user_error('Operation disallowed prior to login()');
			return false;
		}

		$data = pack('CNa*', NET_SSH1_CMSG_EXEC_CMD, strlen($cmd), $cmd);

		if (!$this->_send_binary_packet($data)) {
			user_error('Error sending SSH_CMSG_EXEC_CMD');
			return false;
		}

		if (!$block) {
			return true;
		}

		$output = '';
		$response = $this->_get_binary_packet();

		if ($response !== false) {
			do {
				$output.= substr($response[NET_SSH1_RESPONSE_DATA], 4);
				$response = $this->_get_binary_packet();
			} while (is_array($response) && $response[NET_SSH1_RESPONSE_TYPE] != NET_SSH1_SMSG_EXITSTATUS);
		}

		$data = pack('C', NET_SSH1_CMSG_EXIT_CONFIRMATION);

				$this->_send_binary_packet($data);

		fclose($this->fsock);

				$this->bitmap = 0;

		return $output;
	}

	function _initShell()
	{
								$data = pack('CNa*N4C', NET_SSH1_CMSG_REQUEST_PTY, strlen('vt100'), 'vt100', 24, 80, 0, 0, NET_SSH1_TTY_OP_END);

		if (!$this->_send_binary_packet($data)) {
			user_error('Error sending SSH_CMSG_REQUEST_PTY');
			return false;
		}

		$response = $this->_get_binary_packet();

		if ($response === true) {
			return false;
		}
		if ($response[NET_SSH1_RESPONSE_TYPE] != NET_SSH1_SMSG_SUCCESS) {
			user_error('Expected SSH_SMSG_SUCCESS');
			return false;
		}

		$data = pack('C', NET_SSH1_CMSG_EXEC_SHELL);

		if (!$this->_send_binary_packet($data)) {
			user_error('Error sending SSH_CMSG_EXEC_SHELL');
			return false;
		}

		$this->bitmap |= NET_SSH1_MASK_SHELL;

		return true;
	}

	function write($cmd)
	{
		return $this->interactiveWrite($cmd);
	}

	function read($expect, $mode = NET_SSH1_READ_SIMPLE)
	{
		if (!($this->bitmap & NET_SSH1_MASK_LOGIN)) {
			user_error('Operation disallowed prior to login()');
			return false;
		}

		if (!($this->bitmap & NET_SSH1_MASK_SHELL) && !$this->_initShell()) {
			user_error('Unable to initiate an interactive shell session');
			return false;
		}

		$match = $expect;
		while (true) {
			if ($mode == NET_SSH1_READ_REGEX) {
				preg_match($expect, $this->interactiveBuffer, $matches);
				$match = isset($matches[0]) ? $matches[0] : '';
			}
			$pos = strlen($match) ? strpos($this->interactiveBuffer, $match) : false;
			if ($pos !== false) {
				return $this->_string_shift($this->interactiveBuffer, $pos + strlen($match));
			}
			$response = $this->_get_binary_packet();

			if ($response === true) {
				return $this->_string_shift($this->interactiveBuffer, strlen($this->interactiveBuffer));
			}
			$this->interactiveBuffer.= substr($response[NET_SSH1_RESPONSE_DATA], 4);
		}
	}

	function interactiveWrite($cmd)
	{
		if (!($this->bitmap & NET_SSH1_MASK_LOGIN)) {
			user_error('Operation disallowed prior to login()');
			return false;
		}

		if (!($this->bitmap & NET_SSH1_MASK_SHELL) && !$this->_initShell()) {
			user_error('Unable to initiate an interactive shell session');
			return false;
		}

		$data = pack('CNa*', NET_SSH1_CMSG_STDIN_DATA, strlen($cmd), $cmd);

		if (!$this->_send_binary_packet($data)) {
			user_error('Error sending SSH_CMSG_STDIN');
			return false;
		}

		return true;
	}

	function interactiveRead()
	{
		if (!($this->bitmap & NET_SSH1_MASK_LOGIN)) {
			user_error('Operation disallowed prior to login()');
			return false;
		}

		if (!($this->bitmap & NET_SSH1_MASK_SHELL) && !$this->_initShell()) {
			user_error('Unable to initiate an interactive shell session');
			return false;
		}

		$read = array($this->fsock);
		$write = $except = null;
		if (stream_select($read, $write, $except, 0)) {
			$response = $this->_get_binary_packet();
			return substr($response[NET_SSH1_RESPONSE_DATA], 4);
		} else {
			return '';
		}
	}

	function disconnect()
	{
		$this->_disconnect();
	}

	function __destruct()
	{
		$this->_disconnect();
	}

	function _disconnect($msg = 'Client Quit')
	{
		if ($this->bitmap) {
			$data = pack('C', NET_SSH1_CMSG_EOF);
			$this->_send_binary_packet($data);

			$data = pack('CNa*', NET_SSH1_MSG_DISCONNECT, strlen($msg), $msg);

			$this->_send_binary_packet($data);
			fclose($this->fsock);
			$this->bitmap = 0;
		}
	}

	function _get_binary_packet()
	{
		if (feof($this->fsock)) {
						return false;
		}

		if ($this->curTimeout) {
			$read = array($this->fsock);
			$write = $except = null;

			$start = strtok(microtime(), ' ') + strtok(''); 			$sec = floor($this->curTimeout);
			$usec = 1000000 * ($this->curTimeout - $sec);
						if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
								return true;
			}
			$elapsed = strtok(microtime(), ' ') + strtok('') - $start;
			$this->curTimeout-= $elapsed;
		}

		$start = strtok(microtime(), ' ') + strtok(''); 		$data = fread($this->fsock, 4);
		if (strlen($data) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $data);

		$padding_length = 8 - ($temp['length'] & 7);
		$length = $temp['length'] + $padding_length;
		$raw = '';

		while ($length > 0) {
			$temp = fread($this->fsock, $length);
			$raw.= $temp;
			$length-= strlen($temp);
		}
		$stop = strtok(microtime(), ' ') + strtok('');

		if (strlen($raw) && $this->crypto !== false) {
			$raw = $this->crypto->decrypt($raw);
		}

		$padding = substr($raw, 0, $padding_length);
		$type = $raw[$padding_length];
		$data = substr($raw, $padding_length + 1, -4);

		if (strlen($raw) < 4) {
			return false;
		}
		$temp = unpack('Ncrc', substr($raw, -4));

		$type = ord($type);

		if (defined('NET_SSH1_LOGGING')) {
			$temp = isset($this->protocol_flags[$type]) ? $this->protocol_flags[$type] : 'UNKNOWN';
			$temp = '<- ' . $temp .
					' (' . round($stop - $start, 4) . 's)';
			$this->_append_log($temp, $data);
		}

		return array(
			NET_SSH1_RESPONSE_TYPE => $type,
			NET_SSH1_RESPONSE_DATA => $data
		);
	}

	function _send_binary_packet($data)
	{
		if (feof($this->fsock)) {
						return false;
		}

		$length = strlen($data) + 4;

		$padding = crypt_random_string(8 - ($length & 7));

		$orig = $data;
		$data = $padding . $data;
		$data.= pack('N', $this->_crc($data));

		if ($this->crypto !== false) {
			$data = $this->crypto->encrypt($data);
		}

		$packet = pack('Na*', $length, $data);

		$start = strtok(microtime(), ' ') + strtok(''); 		$result = strlen($packet) == fputs($this->fsock, $packet);
		$stop = strtok(microtime(), ' ') + strtok('');

		if (defined('NET_SSH1_LOGGING')) {
			$temp = isset($this->protocol_flags[ord($orig[0])]) ? $this->protocol_flags[ord($orig[0])] : 'UNKNOWN';
			$temp = '-> ' . $temp .
					' (' . round($stop - $start, 4) . 's)';
			$this->_append_log($temp, $orig);
		}

		return $result;
	}

	function _crc($data)
	{
		static $crc_lookup_table = array(
			0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
			0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
			0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
			0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
			0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
			0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
			0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
			0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
			0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
			0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
			0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
			0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
			0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
			0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
			0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
			0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
			0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
			0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
			0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
			0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
			0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
			0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
			0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
			0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
			0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
			0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
			0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
			0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
			0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
			0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
			0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
			0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
			0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
			0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
			0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
			0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
			0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
			0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
			0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
			0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
			0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
			0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
			0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
			0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
			0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
			0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
			0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
			0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
			0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
			0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
			0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
			0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
			0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
			0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
			0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
			0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
			0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
			0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
			0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
			0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
			0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
			0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
			0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
			0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
		);

						$crc = 0x00000000;
		$length = strlen($data);

		for ($i=0; $i<$length; $i++) {
															$crc = (($crc >> 8) & 0x00FFFFFF) ^ $crc_lookup_table[($crc & 0xFF) ^ ord($data[$i])];
		}

						return $crc;
	}

	function _string_shift(&$string, $index = 1)
	{
		$substr = substr($string, 0, $index);
		$string = substr($string, $index);
		return $substr;
	}

	function _rsa_crypt($m, $key)
	{

								$modulus = $key[1]->toBytes();
		$length = strlen($modulus) - strlen($m) - 3;
		$random = '';
		while (strlen($random) != $length) {
			$block = crypt_random_string($length - strlen($random));
			$block = str_replace("\x00", '', $block);
			$random.= $block;
		}
		$temp = chr(0) . chr(2) . $random . chr(0) . $m;

		$m = new Math_BigInteger($temp, 256);
		$m = $m->modPow($key[0], $key[1]);

		return $m->toBytes();
	}

	function _define_array()
	{
		$args = func_get_args();
		foreach ($args as $arg) {
			foreach ($arg as $key => $value) {
				if (!defined($value)) {
					define($value, $key);
				} else {
					break 2;
				}
			}
		}
	}

	function getLog()
	{
		if (!defined('NET_SSH1_LOGGING')) {
			return false;
		}

		switch (NET_SSH1_LOGGING) {
			case NET_SSH1_LOG_SIMPLE:
				return $this->message_number_log;
				break;
			case NET_SSH1_LOG_COMPLEX:
				return $this->_format_log($this->message_log, $this->protocol_flags_log);
				break;
			default:
				return false;
		}
	}

	function _format_log($message_log, $message_number_log)
	{
		$output = '';
		for ($i = 0; $i < count($message_log); $i++) {
			$output.= $message_number_log[$i] . "\r\n";
			$current_log = $message_log[$i];
			$j = 0;
			do {
				if (strlen($current_log)) {
					$output.= str_pad(dechex($j), 7, '0', STR_PAD_LEFT) . '0  ';
				}
				$fragment = $this->_string_shift($current_log, $this->log_short_width);
				$hex = substr(preg_replace_callback('#.#s', array($this, '_format_log_helper'), $fragment), strlen($this->log_boundary));
																$raw = preg_replace('#[^\x20-\x7E]|<#', '.', $fragment);
				$output.= str_pad($hex, $this->log_long_width - $this->log_short_width, ' ') . $raw . "\r\n";
				$j++;
			} while (strlen($current_log));
			$output.= "\r\n";
		}

		return $output;
	}

	function _format_log_helper($matches)
	{
		return $this->log_boundary . str_pad(dechex(ord($matches[0])), 2, '0', STR_PAD_LEFT);
	}

	function getServerKeyPublicExponent($raw_output = false)
	{
		return $raw_output ? $this->server_key_public_exponent->toBytes() : $this->server_key_public_exponent->toString();
	}

	function getServerKeyPublicModulus($raw_output = false)
	{
		return $raw_output ? $this->server_key_public_modulus->toBytes() : $this->server_key_public_modulus->toString();
	}

	function getHostKeyPublicExponent($raw_output = false)
	{
		return $raw_output ? $this->host_key_public_exponent->toBytes() : $this->host_key_public_exponent->toString();
	}

	function getHostKeyPublicModulus($raw_output = false)
	{
		return $raw_output ? $this->host_key_public_modulus->toBytes() : $this->host_key_public_modulus->toString();
	}

	function getSupportedCiphers($raw_output = false)
	{
		return $raw_output ? array_keys($this->supported_ciphers) : array_values($this->supported_ciphers);
	}

	function getSupportedAuthentications($raw_output = false)
	{
		return $raw_output ? array_keys($this->supported_authentications) : array_values($this->supported_authentications);
	}

	function getServerIdentification()
	{
		return rtrim($this->server_identification);
	}

	function _append_log($protocol_flags, $message)
	{
		switch (NET_SSH1_LOGGING) {
						case NET_SSH1_LOG_SIMPLE:
				$this->protocol_flags_log[] = $protocol_flags;
				break;
						case NET_SSH1_LOG_COMPLEX:
				$this->protocol_flags_log[] = $protocol_flags;
				$this->_string_shift($message);
				$this->log_size+= strlen($message);
				$this->message_log[] = $message;
				while ($this->log_size > NET_SSH1_LOG_MAX_SIZE) {
					$this->log_size-= strlen(array_shift($this->message_log));
					array_shift($this->protocol_flags_log);
				}
				break;
												case NET_SSH1_LOG_REALTIME:
				echo "<pre>\r\n" . $this->_format_log(array($message), array($protocol_flags)) . "\r\n</pre>\r\n";
				@flush();
				@ob_flush();
				break;
															case NET_SSH1_LOG_REALTIME_FILE:
				if (!isset($this->realtime_log_file)) {
										$filename = NET_SSH1_LOG_REALTIME_FILE;
					$fp = fopen($filename, 'w');
					$this->realtime_log_file = $fp;
				}
				if (!is_resource($this->realtime_log_file)) {
					break;
				}
				$entry = $this->_format_log(array($message), array($protocol_flags));
				if ($this->realtime_log_wrap) {
					$temp = "<<< START >>>\r\n";
					$entry.= $temp;
					fseek($this->realtime_log_file, ftell($this->realtime_log_file) - strlen($temp));
				}
				$this->realtime_log_size+= strlen($entry);
				if ($this->realtime_log_size > NET_SSH1_LOG_MAX_SIZE) {
					fseek($this->realtime_log_file, 0);
					$this->realtime_log_size = strlen($entry);
					$this->realtime_log_wrap = true;
				}
				fputs($this->realtime_log_file, $entry);
		}
	}
}}