<?php
namespace {
define('NET_SSH2_MASK_CONSTRUCTOR',	0x00000001);
define('NET_SSH2_MASK_CONNECTED',	 0x00000002);
define('NET_SSH2_MASK_LOGIN_REQ',	 0x00000004);
define('NET_SSH2_MASK_LOGIN',		 0x00000008);
define('NET_SSH2_MASK_SHELL',		 0x00000010);
define('NET_SSH2_MASK_WINDOW_ADJUST', 0x00000020);

define('NET_SSH2_CHANNEL_EXEC',			1); define('NET_SSH2_CHANNEL_SHELL',		 2);
define('NET_SSH2_CHANNEL_SUBSYSTEM',	 3);
define('NET_SSH2_CHANNEL_AGENT_FORWARD', 4);
define('NET_SSH2_CHANNEL_KEEP_ALIVE',	5);

define('NET_SSH2_LOG_SIMPLE',	1);

define('NET_SSH2_LOG_COMPLEX', 2);

define('NET_SSH2_LOG_REALTIME', 3);

define('NET_SSH2_LOG_REALTIME_FILE', 4);

define('NET_SSH2_LOG_MAX_SIZE', 1024 * 1024);

define('NET_SSH2_READ_SIMPLE',	1);

define('NET_SSH2_READ_REGEX', 2);

define('NET_SSH2_READ_NEXT', 3);

class Net_SSH2
{

	var $identifier;

	var $fsock;

	var $bitmap = 0;

	var $errors = array();

	var $server_identifier = false;

	var $kex_algorithms = false;

	var $kex_dh_group_size_min = 1536;

	var $kex_dh_group_size_preferred = 2048;

	var $kex_dh_group_size_max = 4096;

	var $server_host_key_algorithms = false;

	var $encryption_algorithms_client_to_server = false;

	var $encryption_algorithms_server_to_client = false;

	var $mac_algorithms_client_to_server = false;

	var $mac_algorithms_server_to_client = false;

	var $compression_algorithms_client_to_server = false;

	var $compression_algorithms_server_to_client = false;

	var $languages_server_to_client = false;

	var $languages_client_to_server = false;

	var $encrypt_block_size = 8;

	var $decrypt_block_size = 8;

	var $decrypt = false;

	var $encrypt = false;

	var $hmac_create = false;

	var $hmac_check = false;

	var $hmac_size = false;

	var $server_public_host_key;

	var $session_id = false;

	var $exchange_hash = false;

	var $message_numbers = array();

	var $disconnect_reasons = array();

	var $channel_open_failure_reasons = array();

	var $terminal_modes = array();

	var $channel_extended_data_type_codes = array();

	var $send_seq_no = 0;

	var $get_seq_no = 0;

	var $server_channels = array();

	var $channel_buffers = array();

	var $channel_status = array();

	var $packet_size_client_to_server = array();

	var $message_number_log = array();

	var $message_log = array();

	var $window_size = 0x7FFFFFFF;

	var $window_size_server_to_client = array();

	var $window_size_client_to_server = array();

	var $signature = '';

	var $signature_format = '';

	var $interactiveBuffer = '';

	var $log_size;

	var $timeout;

	var $curTimeout;

	var $realtime_log_file;

	var $realtime_log_size;

	var $signature_validated = false;

	var $realtime_log_wrap;

	var $quiet_mode = false;

	var $last_packet;

	var $exit_status;

	var $request_pty = false;

	var $in_request_pty_exec = false;

	var $in_subsystem;

	var $stdErrorLog;

	var $last_interactive_response = '';

	var $keyboard_requests_responses = array();

	var $banner_message = '';

	var $is_timeout = false;

	var $log_boundary = ':';

	var $log_long_width = 65;

	var $log_short_width = 16;

	var $host;

	var $port;

	var $windowColumns = 80;

	var $windowRows = 24;

	var $crypto_engine = false;

	var $agent;

	var $send_id_string_first = true;

	var $send_kex_first = true;

	var $bad_key_size_fix = false;

	var $decrypt_algorithm = '';

	var $retry_connect = false;

	var $binary_packet_buffer = false;

	var $preferred_signature_format = false;

	var $auth = array();

	function __construct($host, $port = 22, $timeout = 10)
	{
						if (!class_exists('Math_BigInteger')) {
			include_once 'Math/BigInteger.php';
		}

		if (!function_exists('crypt_random_string')) {
			include_once 'Crypt/Random.php';
		}

		if (!class_exists('Crypt_Hash')) {
			include_once 'Crypt/Hash.php';
		}

				if (!class_exists('Crypt_Base')) {
			include_once 'Crypt/Base.php';
		}

		$this->message_numbers = array(
			1 => 'NET_SSH2_MSG_DISCONNECT',
			2 => 'NET_SSH2_MSG_IGNORE',
			3 => 'NET_SSH2_MSG_UNIMPLEMENTED',
			4 => 'NET_SSH2_MSG_DEBUG',
			5 => 'NET_SSH2_MSG_SERVICE_REQUEST',
			6 => 'NET_SSH2_MSG_SERVICE_ACCEPT',
			20 => 'NET_SSH2_MSG_KEXINIT',
			21 => 'NET_SSH2_MSG_NEWKEYS',
			30 => 'NET_SSH2_MSG_KEXDH_INIT',
			31 => 'NET_SSH2_MSG_KEXDH_REPLY',
			50 => 'NET_SSH2_MSG_USERAUTH_REQUEST',
			51 => 'NET_SSH2_MSG_USERAUTH_FAILURE',
			52 => 'NET_SSH2_MSG_USERAUTH_SUCCESS',
			53 => 'NET_SSH2_MSG_USERAUTH_BANNER',

			80 => 'NET_SSH2_MSG_GLOBAL_REQUEST',
			81 => 'NET_SSH2_MSG_REQUEST_SUCCESS',
			82 => 'NET_SSH2_MSG_REQUEST_FAILURE',
			90 => 'NET_SSH2_MSG_CHANNEL_OPEN',
			91 => 'NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION',
			92 => 'NET_SSH2_MSG_CHANNEL_OPEN_FAILURE',
			93 => 'NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST',
			94 => 'NET_SSH2_MSG_CHANNEL_DATA',
			95 => 'NET_SSH2_MSG_CHANNEL_EXTENDED_DATA',
			96 => 'NET_SSH2_MSG_CHANNEL_EOF',
			97 => 'NET_SSH2_MSG_CHANNEL_CLOSE',
			98 => 'NET_SSH2_MSG_CHANNEL_REQUEST',
			99 => 'NET_SSH2_MSG_CHANNEL_SUCCESS',
			100 => 'NET_SSH2_MSG_CHANNEL_FAILURE'
		);
		$this->disconnect_reasons = array(
			1 => 'NET_SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT',
			2 => 'NET_SSH2_DISCONNECT_PROTOCOL_ERROR',
			3 => 'NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED',
			4 => 'NET_SSH2_DISCONNECT_RESERVED',
			5 => 'NET_SSH2_DISCONNECT_MAC_ERROR',
			6 => 'NET_SSH2_DISCONNECT_COMPRESSION_ERROR',
			7 => 'NET_SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE',
			8 => 'NET_SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED',
			9 => 'NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE',
			10 => 'NET_SSH2_DISCONNECT_CONNECTION_LOST',
			11 => 'NET_SSH2_DISCONNECT_BY_APPLICATION',
			12 => 'NET_SSH2_DISCONNECT_TOO_MANY_CONNECTIONS',
			13 => 'NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER',
			14 => 'NET_SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE',
			15 => 'NET_SSH2_DISCONNECT_ILLEGAL_USER_NAME'
		);
		$this->channel_open_failure_reasons = array(
			1 => 'NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED'
		);
		$this->terminal_modes = array(
			0 => 'NET_SSH2_TTY_OP_END'
		);
		$this->channel_extended_data_type_codes = array(
			1 => 'NET_SSH2_EXTENDED_DATA_STDERR'
		);

		$this->_define_array(
			$this->message_numbers,
			$this->disconnect_reasons,
			$this->channel_open_failure_reasons,
			$this->terminal_modes,
			$this->channel_extended_data_type_codes,
			array(60 => 'NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ'),
			array(60 => 'NET_SSH2_MSG_USERAUTH_PK_OK'),
			array(60 => 'NET_SSH2_MSG_USERAUTH_INFO_REQUEST',
					61 => 'NET_SSH2_MSG_USERAUTH_INFO_RESPONSE'),
						array(30 => 'NET_SSH2_MSG_KEXDH_GEX_REQUEST_OLD',
					31 => 'NET_SSH2_MSG_KEXDH_GEX_GROUP',
					32 => 'NET_SSH2_MSG_KEXDH_GEX_INIT',
					33 => 'NET_SSH2_MSG_KEXDH_GEX_REPLY',
					34 => 'NET_SSH2_MSG_KEXDH_GEX_REQUEST')
		);

		if (is_resource($host)) {
			$this->fsock = $host;
			return;
		}

		if (is_string($host)) {
			$this->host = $host;
			$this->port = $port;
			$this->timeout = $timeout;
		}
	}

	function Net_SSH2($host, $port = 22, $timeout = 10)
	{
		$this->__construct($host, $port, $timeout);
	}

	function setCryptoEngine($engine)
	{
		$this->crypto_engine = $engine;
	}

	function sendIdentificationStringFirst()
	{
		$this->send_id_string_first = true;
	}

	function sendIdentificationStringLast()
	{
		$this->send_id_string_first = false;
	}

	function sendKEXINITFirst()
	{
		$this->send_kex_first = true;
	}

	function sendKEXINITLast()
	{
		$this->send_kex_first = false;
	}

	function _connect()
	{
		if ($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR) {
			return false;
		}

		$this->bitmap |= NET_SSH2_MASK_CONSTRUCTOR;

		$this->curTimeout = $this->timeout;

		$this->last_packet = strtok(microtime(), ' ') + strtok('');
		if (!is_resource($this->fsock)) {
			$start = strtok(microtime(), ' ') + strtok(''); 												$this->fsock = @fsockopen($this->host, $this->port, $errno, $errstr, $this->curTimeout == 0 ? 100000 : $this->curTimeout);
			if (!$this->fsock) {
				$host = $this->host . ':' . $this->port;
				user_error(rtrim("Cannot connect to $host. Error $errno. $errstr"));
				return false;
			}
			$elapsed = strtok(microtime(), ' ') + strtok('') - $start;

			if ($this->curTimeout) {
				$this->curTimeout-= $elapsed;
				if ($this->curTimeout < 0) {
					$this->is_timeout = true;
					return false;
				}
			}
		}

		$this->identifier = $this->_generate_identifier();

		if ($this->send_id_string_first) {
			fputs($this->fsock, $this->identifier . "\r\n");
		}

		$temp = '';
		$extra = '';
		while (!feof($this->fsock) && !preg_match('#^SSH-(\d\.\d+)#', $temp, $matches)) {
			if (substr($temp, -2) == "\r\n") {
				$extra.= $temp;
				$temp = '';
			}

			if ($this->curTimeout) {
				if ($this->curTimeout < 0) {
					$this->is_timeout = true;
					return false;
				}
				$read = array($this->fsock);
				$write = $except = null;
				$start = strtok(microtime(), ' ') + strtok('');
				$sec = floor($this->curTimeout);
				$usec = 1000000 * ($this->curTimeout - $sec);
												if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
					$this->is_timeout = true;
					return false;
				}
				$elapsed = strtok(microtime(), ' ') + strtok('') - $start;
				$this->curTimeout-= $elapsed;
			}

			$temp.= fgets($this->fsock, 255);
		}

		if (feof($this->fsock)) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}

		if (defined('NET_SSH2_LOGGING')) {
			$this->_append_log('<-', $extra . $temp);
			$this->_append_log('->', $this->identifier . "\r\n");
		}

		$this->server_identifier = trim($temp, "\r\n");
		if (strlen($extra)) {
			$this->errors[] = $extra;
		}

		if (version_compare($matches[1], '1.99', '<')) {
			user_error("Cannot connect to SSH $matches[1] servers");
			return false;
		}

		if (!$this->send_id_string_first) {
			fputs($this->fsock, $this->identifier . "\r\n");
		}

		if (!$this->send_kex_first) {
			$response = $this->_get_binary_packet();
			if ($response === false) {
				$this->bitmap = 0;
				user_error('Connection closed by server');
				return false;
			}

			if (!strlen($response) || ord($response[0]) != NET_SSH2_MSG_KEXINIT) {
				user_error('Expected SSH_MSG_KEXINIT');
				return false;
			}

			if (!$this->_key_exchange($response)) {
				return false;
			}
		}

		if ($this->send_kex_first && !$this->_key_exchange()) {
			return false;
		}

		$this->bitmap|= NET_SSH2_MASK_CONNECTED;

		return true;
	}

	function _generate_identifier()
	{
		$identifier = 'SSH-2.0-phpseclib_1.0';

		$ext = array();
		if (extension_loaded('openssl')) {
			$ext[] = 'openssl';
		} elseif (extension_loaded('mcrypt')) {
			$ext[] = 'mcrypt';
		}

		if (extension_loaded('gmp')) {
			$ext[] = 'gmp';
		} elseif (extension_loaded('bcmath')) {
			$ext[] = 'bcmath';
		}

		if (!empty($ext)) {
			$identifier .= ' (' . implode(', ', $ext) . ')';
		}

		return $identifier;
	}

	function _key_exchange($kexinit_payload_server = false)
	{
		static $kex_algorithms = array(
			'diffie-hellman-group1-sha1', 			'diffie-hellman-group14-sha1', 			'diffie-hellman-group-exchange-sha1', 			'diffie-hellman-group-exchange-sha256', 		);

		static $server_host_key_algorithms = array(
			'rsa-sha2-256', 			'rsa-sha2-512', 			'ssh-rsa', 			'ssh-dss'			);

		static $encryption_algorithms = false;
		if ($encryption_algorithms === false) {
			$encryption_algorithms = array(
								'arcfour256',
				'arcfour128',

								'aes128-ctr',	 				'aes192-ctr',	 				'aes256-ctr',
				'twofish128-ctr', 				'twofish192-ctr', 				'twofish256-ctr',
				'aes128-cbc',	 				'aes192-cbc',	 				'aes256-cbc',
				'twofish128-cbc', 				'twofish192-cbc', 				'twofish256-cbc',
				'twofish-cbc',
				'blowfish-ctr',
				'blowfish-cbc',
				'3des-ctr',
				'3des-cbc',						 			);

			if (extension_loaded('openssl') && !extension_loaded('mcrypt')) {
												$encryption_algorithms = array_diff(
					$encryption_algorithms,
					array('arcfour256', 'arcfour128', 'arcfour')
				);
			}

			if (phpseclib_resolve_include_path('Crypt/RC4.php') === false) {
				$encryption_algorithms = array_diff(
					$encryption_algorithms,
					array('arcfour256', 'arcfour128', 'arcfour')
				);
			}
			if (phpseclib_resolve_include_path('Crypt/Rijndael.php') === false) {
				$encryption_algorithms = array_diff(
					$encryption_algorithms,
					array('aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc')
				);
			}
			if (phpseclib_resolve_include_path('Crypt/Twofish.php') === false) {
				$encryption_algorithms = array_diff(
					$encryption_algorithms,
					array('twofish128-ctr', 'twofish192-ctr', 'twofish256-ctr', 'twofish128-cbc', 'twofish192-cbc', 'twofish256-cbc', 'twofish-cbc')
				);
			}
			if (phpseclib_resolve_include_path('Crypt/Blowfish.php') === false) {
				$encryption_algorithms = array_diff(
					$encryption_algorithms,
					array('blowfish-ctr', 'blowfish-cbc')
				);
			}
			if (phpseclib_resolve_include_path('Crypt/TripleDES.php') === false) {
				$encryption_algorithms = array_diff(
					$encryption_algorithms,
					array('3des-ctr', '3des-cbc')
				);
			}
			$encryption_algorithms = array_values($encryption_algorithms);
		}

		$mac_algorithms = array(
						'hmac-sha2-256',
			'hmac-sha1-96', 			'hmac-sha1',				'hmac-md5-96',				'hmac-md5',	 					);

		static $compression_algorithms = array(
			'none'						);

				switch (true) {
			case $this->server_identifier == 'SSH-2.0-SSHD':
			case substr($this->server_identifier, 0, 13) == 'SSH-2.0-DLINK':
				$mac_algorithms = array_values(array_diff(
					$mac_algorithms,
					array('hmac-sha1-96', 'hmac-md5-96')
				));
		}

		static $str_kex_algorithms, $str_server_host_key_algorithms,
				$encryption_algorithms_server_to_client, $mac_algorithms_server_to_client, $compression_algorithms_server_to_client,
				$encryption_algorithms_client_to_server, $mac_algorithms_client_to_server, $compression_algorithms_client_to_server;

		if (empty($str_kex_algorithms)) {
			$str_kex_algorithms = implode(',', $kex_algorithms);
			$str_server_host_key_algorithms = implode(',', $server_host_key_algorithms);
			$encryption_algorithms_server_to_client = $encryption_algorithms_client_to_server = implode(',', $encryption_algorithms);
			$mac_algorithms_server_to_client = $mac_algorithms_client_to_server = implode(',', $mac_algorithms);
			$compression_algorithms_server_to_client = $compression_algorithms_client_to_server = implode(',', $compression_algorithms);
		}

		$client_cookie = crypt_random_string(16);

		$kexinit_payload_client = pack(
			'Ca*Na*Na*Na*Na*Na*Na*Na*Na*Na*Na*CN',
			NET_SSH2_MSG_KEXINIT,
			$client_cookie,
			strlen($str_kex_algorithms),
			$str_kex_algorithms,
			strlen($str_server_host_key_algorithms),
			$str_server_host_key_algorithms,
			strlen($encryption_algorithms_client_to_server),
			$encryption_algorithms_client_to_server,
			strlen($encryption_algorithms_server_to_client),
			$encryption_algorithms_server_to_client,
			strlen($mac_algorithms_client_to_server),
			$mac_algorithms_client_to_server,
			strlen($mac_algorithms_server_to_client),
			$mac_algorithms_server_to_client,
			strlen($compression_algorithms_client_to_server),
			$compression_algorithms_client_to_server,
			strlen($compression_algorithms_server_to_client),
			$compression_algorithms_server_to_client,
			0,
			'',
			0,
			'',
			0,
			0
		);

		if ($this->send_kex_first) {
			if (!$this->_send_binary_packet($kexinit_payload_client)) {
				return false;
			}

			$kexinit_payload_server = $this->_get_binary_packet();
			if ($kexinit_payload_server === false) {
				$this->bitmap = 0;
				user_error('Connection closed by server');
				return false;
			}

			if (!strlen($kexinit_payload_server) || ord($kexinit_payload_server[0]) != NET_SSH2_MSG_KEXINIT) {
				user_error('Expected SSH_MSG_KEXINIT');
				return false;
			}
		}

		$response = $kexinit_payload_server;
		$this->_string_shift($response, 1); 		$server_cookie = $this->_string_shift($response, 16);

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->kex_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->server_host_key_algorithms = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->encryption_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->encryption_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->mac_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->mac_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->compression_algorithms_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->compression_algorithms_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->languages_client_to_server = explode(',', $this->_string_shift($response, $temp['length']));

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->languages_server_to_client = explode(',', $this->_string_shift($response, $temp['length']));

		if (!strlen($response)) {
			return false;
		}
		extract(unpack('Cfirst_kex_packet_follows', $this->_string_shift($response, 1)));
		$first_kex_packet_follows = $first_kex_packet_follows != 0;

		if (!$this->send_kex_first && !$this->_send_binary_packet($kexinit_payload_client)) {
			return false;
		}

								$decrypt = $this->_array_intersect_first($encryption_algorithms, $this->encryption_algorithms_server_to_client);
		$decryptKeyLength = $this->_encryption_algorithm_to_key_size($decrypt);
		if ($decryptKeyLength === null) {
			user_error('No compatible server to client encryption algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}

		$encrypt = $this->_array_intersect_first($encryption_algorithms, $this->encryption_algorithms_client_to_server);
		$encryptKeyLength = $this->_encryption_algorithm_to_key_size($encrypt);
		if ($encryptKeyLength === null) {
			user_error('No compatible client to server encryption algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}

		$keyLength = $decryptKeyLength > $encryptKeyLength ? $decryptKeyLength : $encryptKeyLength;

				$kex_algorithm = $this->_array_intersect_first($kex_algorithms, $this->kex_algorithms);
		if ($kex_algorithm === false) {
			user_error('No compatible key exchange algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}
		if (strpos($kex_algorithm, 'diffie-hellman-group-exchange') === 0) {
			$dh_group_sizes_packed = pack(
				'NNN',
				$this->kex_dh_group_size_min,
				$this->kex_dh_group_size_preferred,
				$this->kex_dh_group_size_max
			);
			$packet = pack(
				'Ca*',
				NET_SSH2_MSG_KEXDH_GEX_REQUEST,
				$dh_group_sizes_packed
			);
			if (!$this->_send_binary_packet($packet)) {
				return false;
			}

			$response = $this->_get_binary_packet();
			if ($response === false) {
				$this->bitmap = 0;
				user_error('Connection closed by server');
				return false;
			}
			if (!strlen($response)) {
				return false;
			}
			extract(unpack('Ctype', $this->_string_shift($response, 1)));
			if ($type != NET_SSH2_MSG_KEXDH_GEX_GROUP) {
				user_error('Expected SSH_MSG_KEX_DH_GEX_GROUP');
				return false;
			}

			if (strlen($response) < 4) {
				return false;
			}
			extract(unpack('NprimeLength', $this->_string_shift($response, 4)));
			$primeBytes = $this->_string_shift($response, $primeLength);
			$prime = new Math_BigInteger($primeBytes, -256);

			if (strlen($response) < 4) {
				return false;
			}
			extract(unpack('NgLength', $this->_string_shift($response, 4)));
			$gBytes = $this->_string_shift($response, $gLength);
			$g = new Math_BigInteger($gBytes, -256);

			$exchange_hash_rfc4419 = pack(
				'a*Na*Na*',
				$dh_group_sizes_packed,
				$primeLength,
				$primeBytes,
				$gLength,
				$gBytes
			);

			$clientKexInitMessage = NET_SSH2_MSG_KEXDH_GEX_INIT;
			$serverKexReplyMessage = NET_SSH2_MSG_KEXDH_GEX_REPLY;
		} else {
			switch ($kex_algorithm) {
												case 'diffie-hellman-group1-sha1':
					$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
							'020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
							'4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
							'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF';
					break;
								case 'diffie-hellman-group14-sha1':
					$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
							'020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
							'4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
							'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
							'98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
							'9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
							'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
							'3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';
					break;
			}
									$g = new Math_BigInteger(2);
			$prime = new Math_BigInteger($prime, 16);
			$exchange_hash_rfc4419 = '';
			$clientKexInitMessage = NET_SSH2_MSG_KEXDH_INIT;
			$serverKexReplyMessage = NET_SSH2_MSG_KEXDH_REPLY;
		}

		switch ($kex_algorithm) {
			case 'diffie-hellman-group-exchange-sha256':
				$kexHash = new Crypt_Hash('sha256');
				break;
			default:
				$kexHash = new Crypt_Hash('sha1');
		}

		$one = new Math_BigInteger(1);
		$keyLength = min($keyLength, $kexHash->getLength());
		$max = $one->bitwise_leftShift(16 * $keyLength); 		$max = $max->subtract($one);

		$x = $one->random($one, $max);
		$e = $g->modPow($x, $prime);

		$eBytes = $e->toBytes(true);
		$data = pack('CNa*', $clientKexInitMessage, strlen($eBytes), $eBytes);

		if (!$this->_send_binary_packet($data)) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}

		$response = $this->_get_binary_packet();
		if ($response === false) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}
		if (!strlen($response)) {
			return false;
		}
		extract(unpack('Ctype', $this->_string_shift($response, 1)));

		if ($type != $serverKexReplyMessage) {
			user_error('Expected SSH_MSG_KEXDH_REPLY');
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->server_public_host_key = $server_public_host_key = $this->_string_shift($response, $temp['length']);

		if (strlen($server_public_host_key) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
		$public_key_format = $this->_string_shift($server_public_host_key, $temp['length']);

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$fBytes = $this->_string_shift($response, $temp['length']);
		$f = new Math_BigInteger($fBytes, -256);

		if (strlen($response) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($response, 4));
		$this->signature = $this->_string_shift($response, $temp['length']);

		if (strlen($this->signature) < 4) {
			return false;
		}
		$temp = unpack('Nlength', $this->_string_shift($this->signature, 4));
		$this->signature_format = $this->_string_shift($this->signature, $temp['length']);

		$key = $f->modPow($x, $prime);
		$keyBytes = $key->toBytes(true);

		$this->exchange_hash = pack(
			'Na*Na*Na*Na*Na*a*Na*Na*Na*',
			strlen($this->identifier),
			$this->identifier,
			strlen($this->server_identifier),
			$this->server_identifier,
			strlen($kexinit_payload_client),
			$kexinit_payload_client,
			strlen($kexinit_payload_server),
			$kexinit_payload_server,
			strlen($this->server_public_host_key),
			$this->server_public_host_key,
			$exchange_hash_rfc4419,
			strlen($eBytes),
			$eBytes,
			strlen($fBytes),
			$fBytes,
			strlen($keyBytes),
			$keyBytes
		);

		$this->exchange_hash = $kexHash->hash($this->exchange_hash);

		if ($this->session_id === false) {
			$this->session_id = $this->exchange_hash;
		}

		$server_host_key_algorithm = $this->_array_intersect_first($server_host_key_algorithms, $this->server_host_key_algorithms);
		if ($server_host_key_algorithm === false) {
			user_error('No compatible server host key algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}

		switch ($server_host_key_algorithm) {
			case 'ssh-dss':
				$expected_key_format = 'ssh-dss';
				break;
												default:
				$expected_key_format = 'ssh-rsa';
		}

		if ($public_key_format != $expected_key_format || $this->signature_format != $server_host_key_algorithm) {
			switch (true) {
				case $this->signature_format == $server_host_key_algorithm:
				case $server_host_key_algorithm != 'rsa-sha2-256' && $server_host_key_algorithm != 'rsa-sha2-512':
				case $this->signature_format != 'ssh-rsa':
					user_error('Server Host Key Algorithm Mismatch');
					return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
			}
		}

		$packet = pack(
			'C',
			NET_SSH2_MSG_NEWKEYS
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$response = $this->_get_binary_packet();

		if ($response === false) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}

		if (!strlen($response)) {
			return false;
		}
		extract(unpack('Ctype', $this->_string_shift($response, 1)));

		if ($type != NET_SSH2_MSG_NEWKEYS) {
			user_error('Expected SSH_MSG_NEWKEYS');
			return false;
		}

		switch ($encrypt) {
			case '3des-cbc':
				if (!class_exists('Crypt_TripleDES')) {
					include_once 'Crypt/TripleDES.php';
				}
				$this->encrypt = new Crypt_TripleDES();
								break;
			case '3des-ctr':
				if (!class_exists('Crypt_TripleDES')) {
					include_once 'Crypt/TripleDES.php';
				}
				$this->encrypt = new Crypt_TripleDES(CRYPT_DES_MODE_CTR);
								break;
			case 'aes256-cbc':
			case 'aes192-cbc':
			case 'aes128-cbc':
				if (!class_exists('Crypt_Rijndael')) {
					include_once 'Crypt/Rijndael.php';
				}
				$this->encrypt = new Crypt_Rijndael();
				$this->encrypt_block_size = 16; 				break;
			case 'aes256-ctr':
			case 'aes192-ctr':
			case 'aes128-ctr':
				if (!class_exists('Crypt_Rijndael')) {
					include_once 'Crypt/Rijndael.php';
				}
				$this->encrypt = new Crypt_Rijndael(CRYPT_RIJNDAEL_MODE_CTR);
				$this->encrypt_block_size = 16; 				break;
			case 'blowfish-cbc':
				if (!class_exists('Crypt_Blowfish')) {
					include_once 'Crypt/Blowfish.php';
				}
				$this->encrypt = new Crypt_Blowfish();
				$this->encrypt_block_size = 8;
				break;
			case 'blowfish-ctr':
				if (!class_exists('Crypt_Blowfish')) {
					include_once 'Crypt/Blowfish.php';
				}
				$this->encrypt = new Crypt_Blowfish(CRYPT_BLOWFISH_MODE_CTR);
				$this->encrypt_block_size = 8;
				break;
			case 'twofish128-cbc':
			case 'twofish192-cbc':
			case 'twofish256-cbc':
			case 'twofish-cbc':
				if (!class_exists('Crypt_Twofish')) {
					include_once 'Crypt/Twofish.php';
				}
				$this->encrypt = new Crypt_Twofish();
				$this->encrypt_block_size = 16;
				break;
			case 'twofish128-ctr':
			case 'twofish192-ctr':
			case 'twofish256-ctr':
				if (!class_exists('Crypt_Twofish')) {
					include_once 'Crypt/Twofish.php';
				}
				$this->encrypt = new Crypt_Twofish(CRYPT_TWOFISH_MODE_CTR);
				$this->encrypt_block_size = 16;
				break;
			case 'arcfour':
			case 'arcfour128':
			case 'arcfour256':
				if (!class_exists('Crypt_RC4')) {
					include_once 'Crypt/RC4.php';
				}
				$this->encrypt = new Crypt_RC4();
				break;
			case 'none':
						}

		switch ($decrypt) {
			case '3des-cbc':
				if (!class_exists('Crypt_TripleDES')) {
					include_once 'Crypt/TripleDES.php';
				}
				$this->decrypt = new Crypt_TripleDES();
				break;
			case '3des-ctr':
				if (!class_exists('Crypt_TripleDES')) {
					include_once 'Crypt/TripleDES.php';
				}
				$this->decrypt = new Crypt_TripleDES(CRYPT_DES_MODE_CTR);
				break;
			case 'aes256-cbc':
			case 'aes192-cbc':
			case 'aes128-cbc':
				if (!class_exists('Crypt_Rijndael')) {
					include_once 'Crypt/Rijndael.php';
				}
				$this->decrypt = new Crypt_Rijndael();
				$this->decrypt_block_size = 16;
				break;
			case 'aes256-ctr':
			case 'aes192-ctr':
			case 'aes128-ctr':
				if (!class_exists('Crypt_Rijndael')) {
					include_once 'Crypt/Rijndael.php';
				}
				$this->decrypt = new Crypt_Rijndael(CRYPT_RIJNDAEL_MODE_CTR);
				$this->decrypt_block_size = 16;
				break;
			case 'blowfish-cbc':
				if (!class_exists('Crypt_Blowfish')) {
					include_once 'Crypt/Blowfish.php';
				}
				$this->decrypt = new Crypt_Blowfish();
				$this->decrypt_block_size = 8;
				break;
			case 'blowfish-ctr':
				if (!class_exists('Crypt_Blowfish')) {
					include_once 'Crypt/Blowfish.php';
				}
				$this->decrypt = new Crypt_Blowfish(CRYPT_BLOWFISH_MODE_CTR);
				$this->decrypt_block_size = 8;
				break;
			case 'twofish128-cbc':
			case 'twofish192-cbc':
			case 'twofish256-cbc':
			case 'twofish-cbc':
				if (!class_exists('Crypt_Twofish')) {
					include_once 'Crypt/Twofish.php';
				}
				$this->decrypt = new Crypt_Twofish();
				$this->decrypt_block_size = 16;
				break;
			case 'twofish128-ctr':
			case 'twofish192-ctr':
			case 'twofish256-ctr':
				if (!class_exists('Crypt_Twofish')) {
					include_once 'Crypt/Twofish.php';
				}
				$this->decrypt = new Crypt_Twofish(CRYPT_TWOFISH_MODE_CTR);
				$this->decrypt_block_size = 16;
				break;
			case 'arcfour':
			case 'arcfour128':
			case 'arcfour256':
				if (!class_exists('Crypt_RC4')) {
					include_once 'Crypt/RC4.php';
				}
				$this->decrypt = new Crypt_RC4();
				break;
			case 'none':
						}

		$this->decrypt_algorithm = $decrypt;

		$keyBytes = pack('Na*', strlen($keyBytes), $keyBytes);

		if ($this->encrypt) {
			if ($this->crypto_engine) {
				$this->encrypt->setPreferredEngine($this->crypto_engine);
			}
			$this->encrypt->enableContinuousBuffer();
			$this->encrypt->disablePadding();

			$iv = $kexHash->hash($keyBytes . $this->exchange_hash . 'A' . $this->session_id);
			while ($this->encrypt_block_size > strlen($iv)) {
				$iv.= $kexHash->hash($keyBytes . $this->exchange_hash . $iv);
			}
			$this->encrypt->setIV(substr($iv, 0, $this->encrypt_block_size));

			$key = $kexHash->hash($keyBytes . $this->exchange_hash . 'C' . $this->session_id);
			while ($encryptKeyLength > strlen($key)) {
				$key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
			}
			$this->encrypt->setKey(substr($key, 0, $encryptKeyLength));
		}

		if ($this->decrypt) {
			if ($this->crypto_engine) {
				$this->decrypt->setPreferredEngine($this->crypto_engine);
			}
			$this->decrypt->enableContinuousBuffer();
			$this->decrypt->disablePadding();

			$iv = $kexHash->hash($keyBytes . $this->exchange_hash . 'B' . $this->session_id);
			while ($this->decrypt_block_size > strlen($iv)) {
				$iv.= $kexHash->hash($keyBytes . $this->exchange_hash . $iv);
			}
			$this->decrypt->setIV(substr($iv, 0, $this->decrypt_block_size));

			$key = $kexHash->hash($keyBytes . $this->exchange_hash . 'D' . $this->session_id);
			while ($decryptKeyLength > strlen($key)) {
				$key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
			}
			$this->decrypt->setKey(substr($key, 0, $decryptKeyLength));
		}

		if ($encrypt == 'arcfour128' || $encrypt == 'arcfour256') {
			$this->encrypt->encrypt(str_repeat("\0", 1536));
		}
		if ($decrypt == 'arcfour128' || $decrypt == 'arcfour256') {
			$this->decrypt->decrypt(str_repeat("\0", 1536));
		}

		$mac_algorithm = $this->_array_intersect_first($mac_algorithms, $this->mac_algorithms_client_to_server);
		if ($mac_algorithm === false) {
			user_error('No compatible client to server message authentication algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}

		$createKeyLength = 0; 		switch ($mac_algorithm) {
			case 'hmac-sha2-256':
				$this->hmac_create = new Crypt_Hash('sha256');
				$createKeyLength = 32;
				break;
			case 'hmac-sha1':
				$this->hmac_create = new Crypt_Hash('sha1');
				$createKeyLength = 20;
				break;
			case 'hmac-sha1-96':
				$this->hmac_create = new Crypt_Hash('sha1-96');
				$createKeyLength = 20;
				break;
			case 'hmac-md5':
				$this->hmac_create = new Crypt_Hash('md5');
				$createKeyLength = 16;
				break;
			case 'hmac-md5-96':
				$this->hmac_create = new Crypt_Hash('md5-96');
				$createKeyLength = 16;
		}

		$mac_algorithm = $this->_array_intersect_first($mac_algorithms, $this->mac_algorithms_server_to_client);
		if ($mac_algorithm === false) {
			user_error('No compatible server to client message authentication algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}

		$checkKeyLength = 0;
		$this->hmac_size = 0;
		switch ($mac_algorithm) {
			case 'hmac-sha2-256':
				$this->hmac_check = new Crypt_Hash('sha256');
				$checkKeyLength = 32;
				$this->hmac_size = 32;
				break;
			case 'hmac-sha1':
				$this->hmac_check = new Crypt_Hash('sha1');
				$checkKeyLength = 20;
				$this->hmac_size = 20;
				break;
			case 'hmac-sha1-96':
				$this->hmac_check = new Crypt_Hash('sha1-96');
				$checkKeyLength = 20;
				$this->hmac_size = 12;
				break;
			case 'hmac-md5':
				$this->hmac_check = new Crypt_Hash('md5');
				$checkKeyLength = 16;
				$this->hmac_size = 16;
				break;
			case 'hmac-md5-96':
				$this->hmac_check = new Crypt_Hash('md5-96');
				$checkKeyLength = 16;
				$this->hmac_size = 12;
		}

		$key = $kexHash->hash($keyBytes . $this->exchange_hash . 'E' . $this->session_id);
		while ($createKeyLength > strlen($key)) {
			$key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
		}
		$this->hmac_create->setKey(substr($key, 0, $createKeyLength));

		$key = $kexHash->hash($keyBytes . $this->exchange_hash . 'F' . $this->session_id);
		while ($checkKeyLength > strlen($key)) {
			$key.= $kexHash->hash($keyBytes . $this->exchange_hash . $key);
		}
		$this->hmac_check->setKey(substr($key, 0, $checkKeyLength));

		$compression_algorithm = $this->_array_intersect_first($compression_algorithms, $this->compression_algorithms_server_to_client);
		if ($compression_algorithm === false) {
			user_error('No compatible server to client compression algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}
		$this->decompress = $compression_algorithm == 'zlib';

		$compression_algorithm = $this->_array_intersect_first($compression_algorithms, $this->compression_algorithms_client_to_server);
		if ($compression_algorithm === false) {
			user_error('No compatible client to server compression algorithms found');
			return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
		}
		$this->compress = $compression_algorithm == 'zlib';

		return true;
	}

	function _encryption_algorithm_to_key_size($algorithm)
	{
		if ($this->bad_key_size_fix && $this->_bad_algorithm_candidate($algorithm)) {
			return 16;
		}

		switch ($algorithm) {
			case 'none':
				return 0;
			case 'aes128-cbc':
			case 'aes128-ctr':
			case 'arcfour':
			case 'arcfour128':
			case 'blowfish-cbc':
			case 'blowfish-ctr':
			case 'twofish128-cbc':
			case 'twofish128-ctr':
				return 16;
			case '3des-cbc':
			case '3des-ctr':
			case 'aes192-cbc':
			case 'aes192-ctr':
			case 'twofish192-cbc':
			case 'twofish192-ctr':
				return 24;
			case 'aes256-cbc':
			case 'aes256-ctr':
			case 'arcfour256':
			case 'twofish-cbc':
			case 'twofish256-cbc':
			case 'twofish256-ctr':
				return 32;
		}
		return null;
	}

	function _bad_algorithm_candidate($algorithm)
	{
		switch ($algorithm) {
			case 'arcfour256':
			case 'aes192-ctr':
			case 'aes256-ctr':
				return true;
		}

		return false;
	}

	function login($username)
	{
		$args = func_get_args();
		$this->auth[] = $args;
		return call_user_func_array(array(&$this, '_login'), $args);
	}

	function _login($username)
	{
		if (!($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR)) {
			if (!$this->_connect()) {
				return false;
			}
		}

		$args = array_slice(func_get_args(), 1);
		if (empty($args)) {
			return $this->_login_helper($username);
		}

		foreach ($args as $arg) {
			if ($this->_login_helper($username, $arg)) {
				return true;
			}
		}
		return false;
	}

	function _login_helper($username, $password = null)
	{
		if (!($this->bitmap & NET_SSH2_MASK_CONNECTED)) {
			return false;
		}

		if (!($this->bitmap & NET_SSH2_MASK_LOGIN_REQ)) {
			$packet = pack(
				'CNa*',
				NET_SSH2_MSG_SERVICE_REQUEST,
				strlen('ssh-userauth'),
				'ssh-userauth'
			);

			if (!$this->_send_binary_packet($packet)) {
				return false;
			}

			$response = $this->_get_binary_packet();
			if ($response === false) {
				if ($this->retry_connect) {
					$this->retry_connect = false;
					if (!$this->_connect()) {
						return false;
					}
					return $this->_login_helper($username, $password);
				}
				$this->bitmap = 0;
				user_error('Connection closed by server');
				return false;
			}

			if (strlen($response) < 4) {
				return false;
			}
			extract(unpack('Ctype', $this->_string_shift($response, 1)));

			if ($type != NET_SSH2_MSG_SERVICE_ACCEPT) {
				user_error('Expected SSH_MSG_SERVICE_ACCEPT');
				return false;
			}
			$this->bitmap |= NET_SSH2_MASK_LOGIN_REQ;
		}

		if (strlen($this->last_interactive_response)) {
			return !is_string($password) && !is_array($password) ? false : $this->_keyboard_interactive_process($password);
		}

				if (is_object($password)) {
			switch (strtolower(get_class($password))) {
				case 'crypt_rsa':
					return $this->_privatekey_login($username, $password);
				case 'system_ssh_agent':
					return $this->_ssh_agent_login($username, $password);
			}
		}

		if (is_array($password)) {
			if ($this->_keyboard_interactive_login($username, $password)) {
				$this->bitmap |= NET_SSH2_MASK_LOGIN;
				return true;
			}
			return false;
		}

		if (!isset($password)) {
			$packet = pack(
				'CNa*Na*Na*',
				NET_SSH2_MSG_USERAUTH_REQUEST,
				strlen($username),
				$username,
				strlen('ssh-connection'),
				'ssh-connection',
				strlen('none'),
				'none'
			);

			if (!$this->_send_binary_packet($packet)) {
				return false;
			}

			$response = $this->_get_binary_packet();
			if ($response === false) {
				$this->bitmap = 0;
				user_error('Connection closed by server');
				return false;
			}

			if (!strlen($response)) {
				return false;
			}
			extract(unpack('Ctype', $this->_string_shift($response, 1)));

			switch ($type) {
				case NET_SSH2_MSG_USERAUTH_SUCCESS:
					$this->bitmap |= NET_SSH2_MASK_LOGIN;
					return true;
								default:
					return false;
			}
		}

		$packet = pack(
			'CNa*Na*Na*CNa*',
			NET_SSH2_MSG_USERAUTH_REQUEST,
			strlen($username),
			$username,
			strlen('ssh-connection'),
			'ssh-connection',
			strlen('password'),
			'password',
			0,
			strlen($password),
			$password
		);

				if (!defined('NET_SSH2_LOGGING')) {
			$logged = null;
		} else {
			$logged = pack(
				'CNa*Na*Na*CNa*',
				NET_SSH2_MSG_USERAUTH_REQUEST,
				strlen('username'),
				'username',
				strlen('ssh-connection'),
				'ssh-connection',
				strlen('password'),
				'password',
				0,
				strlen('password'),
				'password'
			);
		}

		if (!$this->_send_binary_packet($packet, $logged)) {
			return false;
		}

		$response = $this->_get_binary_packet();
		if ($response === false) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}

		if (!strlen($response)) {
			return false;
		}
		extract(unpack('Ctype', $this->_string_shift($response, 1)));

		switch ($type) {
			case NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ: 				if (defined('NET_SSH2_LOGGING')) {
					$this->message_number_log[count($this->message_number_log) - 1] = 'NET_SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ';
				}
				if (strlen($response) < 4) {
					return false;
				}
				extract(unpack('Nlength', $this->_string_shift($response, 4)));
				$this->errors[] = 'SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: ' . $this->_string_shift($response, $length);
				return $this->_disconnect(NET_SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER);
			case NET_SSH2_MSG_USERAUTH_FAILURE:
												if (strlen($response) < 4) {
					return false;
				}
				extract(unpack('Nlength', $this->_string_shift($response, 4)));
				$auth_methods = explode(',', $this->_string_shift($response, $length));
				if (!strlen($response)) {
					return false;
				}
				extract(unpack('Cpartial_success', $this->_string_shift($response, 1)));
				$partial_success = $partial_success != 0;

				if (!$partial_success && in_array('keyboard-interactive', $auth_methods)) {
					if ($this->_keyboard_interactive_login($username, $password)) {
						$this->bitmap |= NET_SSH2_MASK_LOGIN;
						return true;
					}
					return false;
				}
				return false;
			case NET_SSH2_MSG_USERAUTH_SUCCESS:
				$this->bitmap |= NET_SSH2_MASK_LOGIN;
				return true;
		}

		return false;
	}

	function _keyboard_interactive_login($username, $password)
	{
		$packet = pack(
			'CNa*Na*Na*Na*Na*',
			NET_SSH2_MSG_USERAUTH_REQUEST,
			strlen($username),
			$username,
			strlen('ssh-connection'),
			'ssh-connection',
			strlen('keyboard-interactive'),
			'keyboard-interactive',
			0,
			'',
			0,
			''
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		return $this->_keyboard_interactive_process($password);
	}

	function _keyboard_interactive_process()
	{
		$responses = func_get_args();

		if (strlen($this->last_interactive_response)) {
			$response = $this->last_interactive_response;
		} else {
			$orig = $response = $this->_get_binary_packet();
			if ($response === false) {
				$this->bitmap = 0;
				user_error('Connection closed by server');
				return false;
			}
		}

		if (!strlen($response)) {
			return false;
		}
		extract(unpack('Ctype', $this->_string_shift($response, 1)));

		switch ($type) {
			case NET_SSH2_MSG_USERAUTH_INFO_REQUEST:
				if (strlen($response) < 4) {
					return false;
				}
				extract(unpack('Nlength', $this->_string_shift($response, 4)));
				$this->_string_shift($response, $length); 				if (strlen($response) < 4) {
					return false;
				}
				extract(unpack('Nlength', $this->_string_shift($response, 4)));
				$this->_string_shift($response, $length); 				if (strlen($response) < 4) {
					return false;
				}
				extract(unpack('Nlength', $this->_string_shift($response, 4)));
				$this->_string_shift($response, $length); 				if (strlen($response) < 4) {
					return false;
				}
				extract(unpack('Nnum_prompts', $this->_string_shift($response, 4)));

				for ($i = 0; $i < count($responses); $i++) {
					if (is_array($responses[$i])) {
						foreach ($responses[$i] as $key => $value) {
							$this->keyboard_requests_responses[$key] = $value;
						}
						unset($responses[$i]);
					}
				}
				$responses = array_values($responses);

				if (isset($this->keyboard_requests_responses)) {
					for ($i = 0; $i < $num_prompts; $i++) {
						if (strlen($response) < 4) {
							return false;
						}
						extract(unpack('Nlength', $this->_string_shift($response, 4)));
												$prompt = $this->_string_shift($response, $length);
												foreach ($this->keyboard_requests_responses as $key => $value) {
							if (substr($prompt, 0, strlen($key)) == $key) {
								$responses[] = $value;
								break;
							}
						}
					}
				}

								if (strlen($this->last_interactive_response)) {
					$this->last_interactive_response = '';
				} elseif (defined('NET_SSH2_LOGGING')) {
					$this->message_number_log[count($this->message_number_log) - 1] = str_replace(
						'UNKNOWN',
						'NET_SSH2_MSG_USERAUTH_INFO_REQUEST',
						$this->message_number_log[count($this->message_number_log) - 1]
					);
				}

				if (!count($responses) && $num_prompts) {
					$this->last_interactive_response = $orig;
					return false;
				}

								$packet = $logged = pack('CN', NET_SSH2_MSG_USERAUTH_INFO_RESPONSE, count($responses));
				for ($i = 0; $i < count($responses); $i++) {
					$packet.= pack('Na*', strlen($responses[$i]), $responses[$i]);
					$logged.= pack('Na*', strlen('dummy-answer'), 'dummy-answer');
				}

				if (!$this->_send_binary_packet($packet, $logged)) {
					return false;
				}

				if (defined('NET_SSH2_LOGGING') && NET_SSH2_LOGGING == NET_SSH2_LOG_COMPLEX) {
					$this->message_number_log[count($this->message_number_log) - 1] = str_replace(
						'UNKNOWN',
						'NET_SSH2_MSG_USERAUTH_INFO_RESPONSE',
						$this->message_number_log[count($this->message_number_log) - 1]
					);
				}

												return $this->_keyboard_interactive_process();
			case NET_SSH2_MSG_USERAUTH_SUCCESS:
				return true;
			case NET_SSH2_MSG_USERAUTH_FAILURE:
				return false;
		}

		return false;
	}

	function _ssh_agent_login($username, $agent)
	{
		$this->agent = $agent;
		$keys = $agent->requestIdentities();
		foreach ($keys as $key) {
			if ($this->_privatekey_login($username, $key)) {
				return true;
			}
		}

		return false;
	}

	function _privatekey_login($username, $privatekey)
	{
				$publickey = $privatekey->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_RAW);
		if ($publickey === false) {
			return false;
		}

		$publickey = array(
			'e' => $publickey['e']->toBytes(true),
			'n' => $publickey['n']->toBytes(true)
		);
		$publickey = pack(
			'Na*Na*Na*',
			strlen('ssh-rsa'),
			'ssh-rsa',
			strlen($publickey['e']),
			$publickey['e'],
			strlen($publickey['n']),
			$publickey['n']
		);

		switch ($this->signature_format) {
			case 'rsa-sha2-512':
				$hash = 'sha512';
				$signatureType = 'rsa-sha2-512';
				break;
			case 'rsa-sha2-256':
				$hash = 'sha256';
				$signatureType = 'rsa-sha2-256';
				break;
						default:
				$hash = 'sha1';
				$signatureType = 'ssh-rsa';
		}

		$part1 = pack(
			'CNa*Na*Na*',
			NET_SSH2_MSG_USERAUTH_REQUEST,
			strlen($username),
			$username,
			strlen('ssh-connection'),
			'ssh-connection',
			strlen('publickey'),
			'publickey'
		);
		$part2 = pack('Na*Na*', strlen($signatureType), $signatureType, strlen($publickey), $publickey);

		$packet = $part1 . chr(0) . $part2;
		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$response = $this->_get_binary_packet();
		if ($response === false) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}

		if (!strlen($response)) {
			return false;
		}
		extract(unpack('Ctype', $this->_string_shift($response, 1)));

		switch ($type) {
			case NET_SSH2_MSG_USERAUTH_FAILURE:
				if (strlen($response) < 4) {
					return false;
				}
				extract(unpack('Nlength', $this->_string_shift($response, 4)));
				$this->errors[] = 'SSH_MSG_USERAUTH_FAILURE: ' . $this->_string_shift($response, $length);
				return false;
			case NET_SSH2_MSG_USERAUTH_PK_OK:
												if (defined('NET_SSH2_LOGGING') && NET_SSH2_LOGGING == NET_SSH2_LOG_COMPLEX) {
					$this->message_number_log[count($this->message_number_log) - 1] = str_replace(
						'UNKNOWN',
						'NET_SSH2_MSG_USERAUTH_PK_OK',
						$this->message_number_log[count($this->message_number_log) - 1]
					);
				}
		}

		$packet = $part1 . chr(1) . $part2;
		$privatekey->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
		$privatekey->setHash($hash);
		$signature = $privatekey->sign(pack('Na*a*', strlen($this->session_id), $this->session_id, $packet));
		$signature = pack('Na*Na*', strlen($signatureType), $signatureType, strlen($signature), $signature);
		$packet.= pack('Na*', strlen($signature), $signature);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$response = $this->_get_binary_packet();
		if ($response === false) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}

		if (!strlen($response)) {
			return false;
		}
		extract(unpack('Ctype', $this->_string_shift($response, 1)));

		switch ($type) {
			case NET_SSH2_MSG_USERAUTH_FAILURE:
								return false;
			case NET_SSH2_MSG_USERAUTH_SUCCESS:
				$this->bitmap |= NET_SSH2_MASK_LOGIN;
				return true;
		}

		return false;
	}

	function setTimeout($timeout)
	{
		$this->timeout = $this->curTimeout = $timeout;
	}

	function getStdError()
	{
		return $this->stdErrorLog;
	}

	function exec($command, $callback = null)
	{
		$this->curTimeout = $this->timeout;
		$this->is_timeout = false;
		$this->stdErrorLog = '';

		if (!$this->isAuthenticated()) {
			return false;
		}

		if ($this->in_request_pty_exec) {
			user_error('If you want to run multiple exec()\'s you will need to disable (and re-enable if appropriate) a PTY for each one.');
			return false;
		}

										$this->window_size_server_to_client[NET_SSH2_CHANNEL_EXEC] = $this->window_size;
						$packet_size = 0x4000;

		$packet = pack(
			'CNa*N3',
			NET_SSH2_MSG_CHANNEL_OPEN,
			strlen('session'),
			'session',
			NET_SSH2_CHANNEL_EXEC,
			$this->window_size_server_to_client[NET_SSH2_CHANNEL_EXEC],
			$packet_size
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_OPEN;

		$response = $this->_get_channel_packet(NET_SSH2_CHANNEL_EXEC);
		if ($response === false) {
			return false;
		}

		if ($this->request_pty === true) {
			$terminal_modes = pack('C', NET_SSH2_TTY_OP_END);
			$packet = pack(
				'CNNa*CNa*N5a*',
				NET_SSH2_MSG_CHANNEL_REQUEST,
				$this->server_channels[NET_SSH2_CHANNEL_EXEC],
				strlen('pty-req'),
				'pty-req',
				1,
				strlen('vt100'),
				'vt100',
				$this->windowColumns,
				$this->windowRows,
				0,
				0,
				strlen($terminal_modes),
				$terminal_modes
			);

			if (!$this->_send_binary_packet($packet)) {
				return false;
			}

			$response = $this->_get_binary_packet();
			if ($response === false) {
				$this->bitmap = 0;
				user_error('Connection closed by server');
				return false;
			}

			if (!strlen($response)) {
				return false;
			}
			list(, $type) = unpack('C', $this->_string_shift($response, 1));

			switch ($type) {
				case NET_SSH2_MSG_CHANNEL_SUCCESS:
					break;
				case NET_SSH2_MSG_CHANNEL_FAILURE:
				default:
					user_error('Unable to request pseudo-terminal');
					return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
			}
			$this->in_request_pty_exec = true;
		}

								$packet = pack(
			'CNNa*CNa*',
			NET_SSH2_MSG_CHANNEL_REQUEST,
			$this->server_channels[NET_SSH2_CHANNEL_EXEC],
			strlen('exec'),
			'exec',
			1,
			strlen($command),
			$command
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_REQUEST;

		$response = $this->_get_channel_packet(NET_SSH2_CHANNEL_EXEC);
		if ($response === false) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_EXEC] = NET_SSH2_MSG_CHANNEL_DATA;

		if ($callback === false || $this->in_request_pty_exec) {
			return true;
		}

		$output = '';
		while (true) {
			$temp = $this->_get_channel_packet(NET_SSH2_CHANNEL_EXEC);
			switch (true) {
				case $temp === true:
					return is_callable($callback) ? true : $output;
				case $temp === false:
					return false;
				default:
					if (is_callable($callback)) {
						if (call_user_func($callback, $temp) === true) {
							$this->_close_channel(NET_SSH2_CHANNEL_EXEC);
							return true;
						}
					} else {
						$output.= $temp;
					}
			}
		}
	}

	function _initShell()
	{
		if ($this->in_request_pty_exec === true) {
			return true;
		}

		$this->window_size_server_to_client[NET_SSH2_CHANNEL_SHELL] = $this->window_size;
		$packet_size = 0x4000;

		$packet = pack(
			'CNa*N3',
			NET_SSH2_MSG_CHANNEL_OPEN,
			strlen('session'),
			'session',
			NET_SSH2_CHANNEL_SHELL,
			$this->window_size_server_to_client[NET_SSH2_CHANNEL_SHELL],
			$packet_size
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_SHELL] = NET_SSH2_MSG_CHANNEL_OPEN;

		$response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SHELL);
		if ($response === false) {
			return false;
		}

		$terminal_modes = pack('C', NET_SSH2_TTY_OP_END);
		$packet = pack(
			'CNNa*CNa*N5a*',
			NET_SSH2_MSG_CHANNEL_REQUEST,
			$this->server_channels[NET_SSH2_CHANNEL_SHELL],
			strlen('pty-req'),
			'pty-req',
			1,
			strlen('vt100'),
			'vt100',
			$this->windowColumns,
			$this->windowRows,
			0,
			0,
			strlen($terminal_modes),
			$terminal_modes
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$response = $this->_get_binary_packet();
		if ($response === false) {
			$this->bitmap = 0;
			user_error('Connection closed by server');
			return false;
		}

		if (!strlen($response)) {
			return false;
		}
		list(, $type) = unpack('C', $this->_string_shift($response, 1));

		switch ($type) {
			case NET_SSH2_MSG_CHANNEL_SUCCESS:
						case NET_SSH2_MSG_CHANNEL_FAILURE:
				break;
			default:
				user_error('Unable to request pseudo-terminal');
				return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
		}

		$packet = pack(
			'CNNa*C',
			NET_SSH2_MSG_CHANNEL_REQUEST,
			$this->server_channels[NET_SSH2_CHANNEL_SHELL],
			strlen('shell'),
			'shell',
			1
		);
		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_SHELL] = NET_SSH2_MSG_CHANNEL_REQUEST;

		$response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SHELL);
		if ($response === false) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_SHELL] = NET_SSH2_MSG_CHANNEL_DATA;

		$this->bitmap |= NET_SSH2_MASK_SHELL;

		return true;
	}

	function _get_interactive_channel()
	{
		switch (true) {
			case $this->in_subsystem:
				return NET_SSH2_CHANNEL_SUBSYSTEM;
			case $this->in_request_pty_exec:
				return NET_SSH2_CHANNEL_EXEC;
			default:
				return NET_SSH2_CHANNEL_SHELL;
		}
	}

	function _get_open_channel()
	{
		$channel = NET_SSH2_CHANNEL_EXEC;
		do {
			if (isset($this->channel_status[$channel]) && $this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_OPEN) {
				return $channel;
			}
		} while ($channel++ < NET_SSH2_CHANNEL_SUBSYSTEM);

		return false;
	}

	function read($expect = '', $mode = NET_SSH2_READ_SIMPLE)
	{
		$this->curTimeout = $this->timeout;
		$this->is_timeout = false;

		if (!$this->isAuthenticated()) {
			user_error('Operation disallowed prior to login()');
			return false;
		}

		if (!($this->bitmap & NET_SSH2_MASK_SHELL) && !$this->_initShell()) {
			user_error('Unable to initiate an interactive shell session');
			return false;
		}

		$channel = $this->_get_interactive_channel();

		if ($mode == NET_SSH2_READ_NEXT) {
			return $this->_get_channel_packet($channel);
		}

		$match = $expect;
		while (true) {
			if ($mode == NET_SSH2_READ_REGEX) {
				preg_match($expect, substr($this->interactiveBuffer, -1024), $matches);
				$match = isset($matches[0]) ? $matches[0] : '';
			}
			$pos = strlen($match) ? strpos($this->interactiveBuffer, $match) : false;
			if ($pos !== false) {
				return $this->_string_shift($this->interactiveBuffer, $pos + strlen($match));
			}
			$response = $this->_get_channel_packet($channel);
			if (is_bool($response)) {
				$this->in_request_pty_exec = false;
				return $response ? $this->_string_shift($this->interactiveBuffer, strlen($this->interactiveBuffer)) : false;
			}

			$this->interactiveBuffer.= $response;
		}
	}

	function write($cmd)
	{
		if (!$this->isAuthenticated()) {
			user_error('Operation disallowed prior to login()');
			return false;
		}

		if (!($this->bitmap & NET_SSH2_MASK_SHELL) && !$this->_initShell()) {
			user_error('Unable to initiate an interactive shell session');
			return false;
		}

		return $this->_send_channel_packet($this->_get_interactive_channel(), $cmd);
	}

	function startSubsystem($subsystem)
	{
		$this->window_size_server_to_client[NET_SSH2_CHANNEL_SUBSYSTEM] = $this->window_size;

		$packet = pack(
			'CNa*N3',
			NET_SSH2_MSG_CHANNEL_OPEN,
			strlen('session'),
			'session',
			NET_SSH2_CHANNEL_SUBSYSTEM,
			$this->window_size,
			0x4000
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_OPEN;

		$response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SUBSYSTEM);
		if ($response === false) {
			return false;
		}

		$packet = pack(
			'CNNa*CNa*',
			NET_SSH2_MSG_CHANNEL_REQUEST,
			$this->server_channels[NET_SSH2_CHANNEL_SUBSYSTEM],
			strlen('subsystem'),
			'subsystem',
			1,
			strlen($subsystem),
			$subsystem
		);
		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_REQUEST;

		$response = $this->_get_channel_packet(NET_SSH2_CHANNEL_SUBSYSTEM);

		if ($response === false) {
			return false;
		}

		$this->channel_status[NET_SSH2_CHANNEL_SUBSYSTEM] = NET_SSH2_MSG_CHANNEL_DATA;

		$this->bitmap |= NET_SSH2_MASK_SHELL;
		$this->in_subsystem = true;

		return true;
	}

	function stopSubsystem()
	{
		$this->in_subsystem = false;
		$this->_close_channel(NET_SSH2_CHANNEL_SUBSYSTEM);
		return true;
	}

	function reset()
	{
		$this->_close_channel($this->_get_interactive_channel());
	}

	function isTimeout()
	{
		return $this->is_timeout;
	}

	function disconnect()
	{
		$this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
		if (isset($this->realtime_log_file) && is_resource($this->realtime_log_file)) {
			fclose($this->realtime_log_file);
		}
	}

	function __destruct()
	{
		$this->disconnect();
	}

	function isConnected()
	{
		return (bool) ($this->bitmap & NET_SSH2_MASK_CONNECTED);
	}

	function isAuthenticated()
	{
		return (bool) ($this->bitmap & NET_SSH2_MASK_LOGIN);
	}

	function ping()
	{
		if (!$this->isAuthenticated()) {
			return false;
		}

		$this->window_size_server_to_client[NET_SSH2_CHANNEL_KEEP_ALIVE] = $this->window_size;
		$packet_size = 0x4000;
		$packet = pack(
			'CNa*N3',
			NET_SSH2_MSG_CHANNEL_OPEN,
			strlen('session'),
			'session',
			NET_SSH2_CHANNEL_KEEP_ALIVE,
			$this->window_size_server_to_client[NET_SSH2_CHANNEL_KEEP_ALIVE],
			$packet_size
		);

		if (!@$this->_send_binary_packet($packet)) {
			return $this->_reconnect();
		}

		$this->channel_status[NET_SSH2_CHANNEL_KEEP_ALIVE] = NET_SSH2_MSG_CHANNEL_OPEN;

		$response = @$this->_get_channel_packet(NET_SSH2_CHANNEL_KEEP_ALIVE);
		if ($response !== false) {
			$this->_close_channel(NET_SSH2_CHANNEL_KEEP_ALIVE);
			return true;
		}

		return $this->_reconnect();
	}

	function _reconnect()
	{
		$this->_reset_connection(NET_SSH2_DISCONNECT_CONNECTION_LOST);
		$this->retry_connect = true;
		if (!$this->_connect()) {
			return false;
		}
		foreach ($this->auth as $auth) {
			$result = call_user_func_array(array(&$this, 'parent::login'), $auth);
		}
		return $result;
	}

	function _reset_connection($reason)
	{
		$this->_disconnect($reason);
		$this->decrypt = $this->encrypt = false;
		$this->decrypt_block_size = $this->encrypt_block_size = 8;
		$this->hmac_check = $this->hmac_create = false;
		$this->hmac_size = false;
		$this->session_id = false;
		$this->retry_connect = true;
		$this->get_seq_no = $this->send_seq_no = 0;
	}

	function _get_binary_packet($skip_channel_filter = false)
	{
		if (!is_resource($this->fsock) || feof($this->fsock)) {
			$this->bitmap = 0;
			user_error('Connection closed prematurely');
			return false;
		}

		$start = strtok(microtime(), ' ') + strtok(''); 		$raw = fread($this->fsock, $this->decrypt_block_size);

		if (!strlen($raw)) {
			return '';
		}

		if ($this->decrypt !== false) {
			$raw = $this->decrypt->decrypt($raw);
		}
		if ($raw === false) {
			user_error('Unable to decrypt content');
			return false;
		}

		if (strlen($raw) < 5) {
			return false;
		}
		extract(unpack('Npacket_length/Cpadding_length', $this->_string_shift($raw, 5)));

		$remaining_length = $packet_length + 4 - $this->decrypt_block_size;

								if ($remaining_length < -$this->decrypt_block_size || $remaining_length > 0x9000 || $remaining_length % $this->decrypt_block_size != 0) {
			if (!$this->bad_key_size_fix && $this->_bad_algorithm_candidate($this->decrypt_algorithm) && !($this->bitmap & NET_SSH2_MASK_LOGIN)) {
				$this->bad_key_size_fix = true;
				$this->_reset_connection(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
				return false;
			}
			user_error('Invalid size');
			return false;
		}

		$buffer = '';
		while ($remaining_length > 0) {
			$temp = fread($this->fsock, $remaining_length);
			if ($temp === false || feof($this->fsock)) {
				$this->bitmap = 0;
				user_error('Error reading from socket');
				return false;
			}
			$buffer.= $temp;
			$remaining_length-= strlen($temp);
		}

		$stop = strtok(microtime(), ' ') + strtok('');
		if (strlen($buffer)) {
			$raw.= $this->decrypt !== false ? $this->decrypt->decrypt($buffer) : $buffer;
		}

		$payload = $this->_string_shift($raw, $packet_length - $padding_length - 1);
		$padding = $this->_string_shift($raw, $padding_length);
		if ($this->hmac_check !== false) {
			$hmac = fread($this->fsock, $this->hmac_size);
			if ($hmac === false || strlen($hmac) != $this->hmac_size) {
				$this->bitmap = 0;
				user_error('Error reading socket');
				return false;
			} elseif ($hmac != $this->hmac_check->hash(pack('NNCa*', $this->get_seq_no, $packet_length, $padding_length, $payload . $padding))) {
				user_error('Invalid HMAC');
				return false;
			}
		}

		$this->get_seq_no++;

		if (defined('NET_SSH2_LOGGING')) {
			$current = strtok(microtime(), ' ') + strtok('');
			$message_number = isset($this->message_numbers[ord($payload[0])]) ? $this->message_numbers[ord($payload[0])] : 'UNKNOWN (' . ord($payload[0]) . ')';
			$message_number = '<- ' . $message_number .
								' (since last: ' . round($current - $this->last_packet, 4) . ', network: ' . round($stop - $start, 4) . 's)';
			$this->_append_log($message_number, $payload);
			$this->last_packet = $current;
		}

		return $this->_filter($payload, $skip_channel_filter);
	}

	function _filter($payload, $skip_channel_filter)
	{
		switch (ord($payload[0])) {
			case NET_SSH2_MSG_DISCONNECT:
				$this->_string_shift($payload, 1);
				if (strlen($payload) < 8) {
					return false;
				}
				extract(unpack('Nreason_code/Nlength', $this->_string_shift($payload, 8)));
				$this->errors[] = 'SSH_MSG_DISCONNECT: ' . $this->disconnect_reasons[$reason_code] . "\r\n" . $this->_string_shift($payload, $length);
				$this->bitmap = 0;
				return false;
			case NET_SSH2_MSG_IGNORE:
				$payload = $this->_get_binary_packet($skip_channel_filter);
				break;
			case NET_SSH2_MSG_DEBUG:
				$this->_string_shift($payload, 2);
				if (strlen($payload) < 4) {
					return false;
				}
				extract(unpack('Nlength', $this->_string_shift($payload, 4)));
				$this->errors[] = 'SSH_MSG_DEBUG: ' . $this->_string_shift($payload, $length);
				$payload = $this->_get_binary_packet($skip_channel_filter);
				break;
			case NET_SSH2_MSG_UNIMPLEMENTED:
				return false;
			case NET_SSH2_MSG_KEXINIT:
				if ($this->session_id !== false) {
					$this->send_kex_first = false;
					if (!$this->_key_exchange($payload)) {
						$this->bitmap = 0;
						return false;
					}
					$payload = $this->_get_binary_packet($skip_channel_filter);
				}
		}

				if (($this->bitmap & NET_SSH2_MASK_CONNECTED) && !$this->isAuthenticated() && ord($payload[0]) == NET_SSH2_MSG_USERAUTH_BANNER) {
			$this->_string_shift($payload, 1);
			if (strlen($payload) < 4) {
				return false;
			}
			extract(unpack('Nlength', $this->_string_shift($payload, 4)));
			$this->banner_message = $this->_string_shift($payload, $length);
			$payload = $this->_get_binary_packet();
		}

				if (($this->bitmap & NET_SSH2_MASK_CONNECTED) && $this->isAuthenticated()) {
			switch (ord($payload[0])) {
				case NET_SSH2_MSG_CHANNEL_DATA:
				case NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:
				case NET_SSH2_MSG_CHANNEL_REQUEST:
				case NET_SSH2_MSG_CHANNEL_CLOSE:
				case NET_SSH2_MSG_CHANNEL_EOF:
					if (!$skip_channel_filter && !empty($this->server_channels)) {
						$this->binary_packet_buffer = $payload;
						$this->_get_channel_packet(true);
						$payload = $this->_get_binary_packet();
					}
					break;
				case NET_SSH2_MSG_GLOBAL_REQUEST: 					if (strlen($payload) < 4) {
						return false;
					}
					extract(unpack('Nlength', $this->_string_shift($payload, 4)));
					$this->errors[] = 'SSH_MSG_GLOBAL_REQUEST: ' . $this->_string_shift($payload, $length);

					if (!$this->_send_binary_packet(pack('C', NET_SSH2_MSG_REQUEST_FAILURE))) {
						return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
					}

					$payload = $this->_get_binary_packet($skip_channel_filter);
					break;
				case NET_SSH2_MSG_CHANNEL_OPEN: 					$this->_string_shift($payload, 1);
					if (strlen($payload) < 4) {
						return false;
					}
					extract(unpack('Nlength', $this->_string_shift($payload, 4)));
					$data = $this->_string_shift($payload, $length);
					if (strlen($payload) < 4) {
						return false;
					}
					extract(unpack('Nserver_channel', $this->_string_shift($payload, 4)));
					switch ($data) {
						case 'auth-agent':
						case 'auth-agent@openssh.com':
							if (isset($this->agent)) {
								$new_channel = NET_SSH2_CHANNEL_AGENT_FORWARD;

								if (strlen($payload) < 8) {
									return false;
								}
								extract(unpack('Nremote_window_size', $this->_string_shift($payload, 4)));
								extract(unpack('Nremote_maximum_packet_size', $this->_string_shift($payload, 4)));

								$this->packet_size_client_to_server[$new_channel] = $remote_window_size;
								$this->window_size_server_to_client[$new_channel] = $remote_maximum_packet_size;
								$this->window_size_client_to_server[$new_channel] = $this->window_size;

								$packet_size = 0x4000;

								$packet = pack(
									'CN4',
									NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,
									$server_channel,
									$new_channel,
									$packet_size,
									$packet_size
								);

								$this->server_channels[$new_channel] = $server_channel;
								$this->channel_status[$new_channel] = NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION;
								if (!$this->_send_binary_packet($packet)) {
									return false;
								}
							}
							break;
						default:
							$packet = pack(
								'CN3a*Na*',
								NET_SSH2_MSG_REQUEST_FAILURE,
								$server_channel,
								NET_SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED,
								0,
								'',
								0,
								''
							);

							if (!$this->_send_binary_packet($packet)) {
								return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
							}
					}
					$payload = $this->_get_binary_packet($skip_channel_filter);
					break;
				case NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST:
					$this->_string_shift($payload, 1);
					if (strlen($payload) < 8) {
						return false;
					}
					extract(unpack('Nchannel', $this->_string_shift($payload, 4)));
					extract(unpack('Nwindow_size', $this->_string_shift($payload, 4)));
					$this->window_size_client_to_server[$channel]+= $window_size;

					$payload = ($this->bitmap & NET_SSH2_MASK_WINDOW_ADJUST) ? true : $this->_get_binary_packet($skip_channel_filter);
			}
		}

		return $payload;
	}

	function enableQuietMode()
	{
		$this->quiet_mode = true;
	}

	function disableQuietMode()
	{
		$this->quiet_mode = false;
	}

	function isQuietModeEnabled()
	{
		return $this->quiet_mode;
	}

	function enablePTY()
	{
		$this->request_pty = true;
	}

	function disablePTY()
	{
		if ($this->in_request_pty_exec) {
			$this->_close_channel(NET_SSH2_CHANNEL_EXEC);
			$this->in_request_pty_exec = false;
		}
		$this->request_pty = false;
	}

	function isPTYEnabled()
	{
		return $this->request_pty;
	}

	function _get_channel_packet($client_channel, $skip_extended = false)
	{
		if (!empty($this->channel_buffers[$client_channel])) {
			return array_shift($this->channel_buffers[$client_channel]);
		}

		while (true) {
			if ($this->binary_packet_buffer !== false) {
				$response = $this->binary_packet_buffer;
				$this->binary_packet_buffer = false;
			} else {
				$read = array($this->fsock);
				$write = $except = null;

				if (!$this->curTimeout) {
					@stream_select($read, $write, $except, null);
				} else {
					if ($this->curTimeout < 0) {
						$this->is_timeout = true;
						return true;
					}

					$read = array($this->fsock);
					$write = $except = null;

					$start = strtok(microtime(), ' ') + strtok(''); 					$sec = floor($this->curTimeout);
					$usec = 1000000 * ($this->curTimeout - $sec);
										if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
						$this->is_timeout = true;
						return true;
					}
					$elapsed = strtok(microtime(), ' ') + strtok('') - $start;
					$this->curTimeout-= $elapsed;
				}

				$response = $this->_get_binary_packet(true);
				if ($response === false) {
					$this->bitmap = 0;
					user_error('Connection closed by server');
					return false;
				}
			}

			if ($client_channel == -1 && $response === true) {
				return true;
			}
			if (!strlen($response)) {
				return false;
			}
			extract(unpack('Ctype', $this->_string_shift($response, 1)));

			if (strlen($response) < 4) {
				return false;
			}
			if ($type == NET_SSH2_MSG_CHANNEL_OPEN) {
				extract(unpack('Nlength', $this->_string_shift($response, 4)));
			} else {
				extract(unpack('Nchannel', $this->_string_shift($response, 4)));
			}

						if (isset($channel) && isset($this->channel_status[$channel]) && isset($this->window_size_server_to_client[$channel])) {
				$this->window_size_server_to_client[$channel]-= strlen($response);

								if ($this->window_size_server_to_client[$channel] < 0) {
					$packet = pack('CNN', NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST, $this->server_channels[$channel], $this->window_size);
					if (!$this->_send_binary_packet($packet)) {
						return false;
					}
					$this->window_size_server_to_client[$channel]+= $this->window_size;
				}

				switch ($type) {
					case NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:

												if (strlen($response) < 8) {
							return false;
						}
						extract(unpack('Ndata_type_code/Nlength', $this->_string_shift($response, 8)));
						$data = $this->_string_shift($response, $length);
						$this->stdErrorLog.= $data;
						if ($skip_extended || $this->quiet_mode) {
							continue 2;
						}
						if ($client_channel == $channel && $this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_DATA) {
							return $data;
						}
						if (!isset($this->channel_buffers[$channel])) {
							$this->channel_buffers[$channel] = array();
						}
						$this->channel_buffers[$channel][] = $data;

						continue 2;
					case NET_SSH2_MSG_CHANNEL_REQUEST:
						if ($this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_CLOSE) {
							continue 2;
						}
						if (strlen($response) < 4) {
							return false;
						}
						extract(unpack('Nlength', $this->_string_shift($response, 4)));
						$value = $this->_string_shift($response, $length);
						switch ($value) {
							case 'exit-signal':
								$this->_string_shift($response, 1);
								if (strlen($response) < 4) {
									return false;
								}
								extract(unpack('Nlength', $this->_string_shift($response, 4)));
								$this->errors[] = 'SSH_MSG_CHANNEL_REQUEST (exit-signal): ' . $this->_string_shift($response, $length);
								$this->_string_shift($response, 1);
								if (strlen($response) < 4) {
									return false;
								}
								extract(unpack('Nlength', $this->_string_shift($response, 4)));
								if ($length) {
									$this->errors[count($this->errors)].= "\r\n" . $this->_string_shift($response, $length);
								}

								$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));
								$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));

								$this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_EOF;

								continue 3;
							case 'exit-status':
								if (strlen($response) < 5) {
									return false;
								}
								extract(unpack('Cfalse/Nexit_status', $this->_string_shift($response, 5)));
								$this->exit_status = $exit_status;

								continue 3;
							default:
																								continue 3;
						}
				}

				switch ($this->channel_status[$channel]) {
					case NET_SSH2_MSG_CHANNEL_OPEN:
						switch ($type) {
							case NET_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION:
								if (strlen($response) < 4) {
									return false;
								}
								extract(unpack('Nserver_channel', $this->_string_shift($response, 4)));
								$this->server_channels[$channel] = $server_channel;
								if (strlen($response) < 4) {
									return false;
								}
								extract(unpack('Nwindow_size', $this->_string_shift($response, 4)));
								if ($window_size < 0) {
									$window_size&= 0x7FFFFFFF;
									$window_size+= 0x80000000;
								}
								$this->window_size_client_to_server[$channel] = $window_size;
								if (strlen($response) < 4) {
									 return false;
								}
								$temp = unpack('Npacket_size_client_to_server', $this->_string_shift($response, 4));
								$this->packet_size_client_to_server[$channel] = $temp['packet_size_client_to_server'];
								$result = $client_channel == $channel ? true : $this->_get_channel_packet($client_channel, $skip_extended);
								$this->_on_channel_open();
								return $result;
														default:
								user_error('Unable to open channel');
								return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
						}
						break;
					case NET_SSH2_MSG_CHANNEL_REQUEST:
						switch ($type) {
							case NET_SSH2_MSG_CHANNEL_SUCCESS:
								return true;
							case NET_SSH2_MSG_CHANNEL_FAILURE:
								return false;
							default:
								user_error('Unable to fulfill channel request');
								return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
						}
					case NET_SSH2_MSG_CHANNEL_CLOSE:
						return $type == NET_SSH2_MSG_CHANNEL_CLOSE ? true : $this->_get_channel_packet($client_channel, $skip_extended);
				}
			}

			switch ($type) {
				case NET_SSH2_MSG_CHANNEL_DATA:

					if (strlen($response) < 4) {
						return false;
					}
					extract(unpack('Nlength', $this->_string_shift($response, 4)));
					$data = $this->_string_shift($response, $length);

					if ($channel == NET_SSH2_CHANNEL_AGENT_FORWARD) {
						$agent_response = $this->agent->_forward_data($data);
						if (!is_bool($agent_response)) {
							$this->_send_channel_packet($channel, $agent_response);
						}
						break;
					}

					if ($client_channel == $channel) {
						return $data;
					}
					if (!isset($this->channel_buffers[$channel])) {
						$this->channel_buffers[$channel] = array();
					}
					$this->channel_buffers[$channel][] = $data;
					break;
				case NET_SSH2_MSG_CHANNEL_CLOSE:
					$this->curTimeout = 0;

					if ($this->bitmap & NET_SSH2_MASK_SHELL) {
						$this->bitmap&= ~NET_SSH2_MASK_SHELL;
					}
					if ($this->channel_status[$channel] != NET_SSH2_MSG_CHANNEL_EOF) {
						$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));
					}

					$this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_CLOSE;
					if ($client_channel == $channel) {
						return true;
					}
				case NET_SSH2_MSG_CHANNEL_EOF:
					break;
				default:
					user_error('Error reading channel data');
					return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
			}
		}
	}

	function _send_binary_packet($data, $logged = null)
	{
		if (!is_resource($this->fsock) || feof($this->fsock)) {
			$this->bitmap = 0;
			user_error('Connection closed prematurely');
			return false;
		}

				$packet_length = strlen($data) + 9;
				$packet_length+= (($this->encrypt_block_size - 1) * $packet_length) % $this->encrypt_block_size;
				$padding_length = $packet_length - strlen($data) - 5;
		$padding = crypt_random_string($padding_length);

				$packet = pack('NCa*', $packet_length - 4, $padding_length, $data . $padding);

		$hmac = $this->hmac_create !== false ? $this->hmac_create->hash(pack('Na*', $this->send_seq_no, $packet)) : '';
		$this->send_seq_no++;

		if ($this->encrypt !== false) {
			$packet = $this->encrypt->encrypt($packet);
		}

		$packet.= $hmac;

		$start = strtok(microtime(), ' ') + strtok(''); 		$result = strlen($packet) == fputs($this->fsock, $packet);
		$stop = strtok(microtime(), ' ') + strtok('');

		if (defined('NET_SSH2_LOGGING')) {
			$current = strtok(microtime(), ' ') + strtok('');
			$message_number = isset($this->message_numbers[ord($data[0])]) ? $this->message_numbers[ord($data[0])] : 'UNKNOWN (' . ord($data[0]) . ')';
			$message_number = '-> ' . $message_number .
								' (since last: ' . round($current - $this->last_packet, 4) . ', network: ' . round($stop - $start, 4) . 's)';
			$this->_append_log($message_number, isset($logged) ? $logged : $data);
			$this->last_packet = $current;
		}

		return $result;
	}

	function _append_log($message_number, $message)
	{
				if (strlen($message_number) > 2) {
			$this->_string_shift($message);
		}

		switch (NET_SSH2_LOGGING) {
						case NET_SSH2_LOG_SIMPLE:
				$this->message_number_log[] = $message_number;
				break;
						case NET_SSH2_LOG_COMPLEX:
				$this->message_number_log[] = $message_number;
				$this->log_size+= strlen($message);
				$this->message_log[] = $message;
				while ($this->log_size > NET_SSH2_LOG_MAX_SIZE) {
					$this->log_size-= strlen(array_shift($this->message_log));
					array_shift($this->message_number_log);
				}
				break;
												case NET_SSH2_LOG_REALTIME:
				switch (PHP_SAPI) {
					case 'cli':
						$start = $stop = "\r\n";
						break;
					default:
						$start = '<pre>';
						$stop = '</pre>';
				}
				echo $start . $this->_format_log(array($message), array($message_number)) . $stop;
				@flush();
				@ob_flush();
				break;
															case NET_SSH2_LOG_REALTIME_FILE:
				if (!isset($this->realtime_log_file)) {
										$filename = NET_SSH2_LOG_REALTIME_FILENAME;
					$fp = fopen($filename, 'w');
					$this->realtime_log_file = $fp;
				}
				if (!is_resource($this->realtime_log_file)) {
					break;
				}
				$entry = $this->_format_log(array($message), array($message_number));
				if ($this->realtime_log_wrap) {
					$temp = "<<< START >>>\r\n";
					$entry.= $temp;
					fseek($this->realtime_log_file, ftell($this->realtime_log_file) - strlen($temp));
				}
				$this->realtime_log_size+= strlen($entry);
				if ($this->realtime_log_size > NET_SSH2_LOG_MAX_SIZE) {
					fseek($this->realtime_log_file, 0);
					$this->realtime_log_size = strlen($entry);
					$this->realtime_log_wrap = true;
				}
				fputs($this->realtime_log_file, $entry);
		}
	}

	function _send_channel_packet($client_channel, $data)
	{
		while (strlen($data)) {
			if (!$this->window_size_client_to_server[$client_channel]) {
				$this->bitmap^= NET_SSH2_MASK_WINDOW_ADJUST;
								$this->_get_channel_packet(-1);
				$this->bitmap^= NET_SSH2_MASK_WINDOW_ADJUST;
			}

			$max_size = min(
				$this->packet_size_client_to_server[$client_channel],
				$this->window_size_client_to_server[$client_channel]
			);

			$temp = $this->_string_shift($data, $max_size);
			$packet = pack(
				'CN2a*',
				NET_SSH2_MSG_CHANNEL_DATA,
				$this->server_channels[$client_channel],
				strlen($temp),
				$temp
			);
			$this->window_size_client_to_server[$client_channel]-= strlen($temp);
			if (!$this->_send_binary_packet($packet)) {
				return false;
			}
		}

		return true;
	}

	function _close_channel($client_channel, $want_reply = false)
	{

		$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));

		if (!$want_reply) {
			$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$client_channel]));
		}

		$this->channel_status[$client_channel] = NET_SSH2_MSG_CHANNEL_CLOSE;

		$this->curTimeout = 0;

		while (!is_bool($this->_get_channel_packet($client_channel))) {
		}

		if ($want_reply) {
			$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$client_channel]));
		}

		if ($this->bitmap & NET_SSH2_MASK_SHELL) {
			$this->bitmap&= ~NET_SSH2_MASK_SHELL;
		}
	}

	function _disconnect($reason)
	{
		if ($this->bitmap & NET_SSH2_MASK_CONNECTED) {
			$data = pack('CNNa*Na*', NET_SSH2_MSG_DISCONNECT, $reason, 0, '', 0, '');
			$this->_send_binary_packet($data);
			$this->bitmap = 0;
			fclose($this->fsock);
			return false;
		}
	}

	function _string_shift(&$string, $index = 1)
	{
		$substr = substr($string, 0, $index);
		$string = substr($string, $index);
		return $substr;
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
		if (!defined('NET_SSH2_LOGGING')) {
			return false;
		}

		switch (NET_SSH2_LOGGING) {
			case NET_SSH2_LOG_SIMPLE:
				return $this->message_number_log;
			case NET_SSH2_LOG_COMPLEX:
				$log = $this->_format_log($this->message_log, $this->message_number_log);
				return PHP_SAPI == 'cli' ? $log : '<pre>' . $log . '</pre>';
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

	function _on_channel_open()
	{
		if (isset($this->agent)) {
			$this->agent->_on_channel_open($this);
		}
	}

	function _array_intersect_first($array1, $array2)
	{
		foreach ($array1 as $value) {
			if (in_array($value, $array2)) {
				return $value;
			}
		}
		return false;
	}

	function getErrors()
	{
		return $this->errors;
	}

	function getLastError()
	{
		$count = count($this->errors);

		if ($count > 0) {
			return $this->errors[$count - 1];
		}
	}

	function getServerIdentification()
	{
		$this->_connect();

		return $this->server_identifier;
	}

	function getKexAlgorithms()
	{
		$this->_connect();

		return $this->kex_algorithms;
	}

	function getServerHostKeyAlgorithms()
	{
		$this->_connect();

		return $this->server_host_key_algorithms;
	}

	function getEncryptionAlgorithmsClient2Server()
	{
		$this->_connect();

		return $this->encryption_algorithms_client_to_server;
	}

	function getEncryptionAlgorithmsServer2Client()
	{
		$this->_connect();

		return $this->encryption_algorithms_server_to_client;
	}

	function getMACAlgorithmsClient2Server()
	{
		$this->_connect();

		return $this->mac_algorithms_client_to_server;
	}

	function getMACAlgorithmsServer2Client()
	{
		$this->_connect();

		return $this->mac_algorithms_server_to_client;
	}

	function getCompressionAlgorithmsClient2Server()
	{
		$this->_connect();

		return $this->compression_algorithms_client_to_server;
	}

	function getCompressionAlgorithmsServer2Client()
	{
		$this->_connect();

		return $this->compression_algorithms_server_to_client;
	}

	function getLanguagesServer2Client()
	{
		$this->_connect();

		return $this->languages_server_to_client;
	}

	function getLanguagesClient2Server()
	{
		$this->_connect();

		return $this->languages_client_to_server;
	}

	function getBannerMessage()
	{
		return $this->banner_message;
	}

	function getServerPublicHostKey()
	{
		if (!($this->bitmap & NET_SSH2_MASK_CONSTRUCTOR)) {
			if (!$this->_connect()) {
				return false;
			}
		}

		$signature = $this->signature;
		$server_public_host_key = $this->server_public_host_key;

		if (strlen($server_public_host_key) < 4) {
			return false;
		}
		extract(unpack('Nlength', $this->_string_shift($server_public_host_key, 4)));
		$this->_string_shift($server_public_host_key, $length);

		if ($this->signature_validated) {
			return $this->bitmap ?
				$this->signature_format . ' ' . base64_encode($this->server_public_host_key) :
				false;
		}

		$this->signature_validated = true;

		switch ($this->signature_format) {
			case 'ssh-dss':
				$zero = new Math_BigInteger();

				if (strlen($server_public_host_key) < 4) {
					return false;
				}
				$temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
				$p = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

				if (strlen($server_public_host_key) < 4) {
					return false;
				}
				$temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
				$q = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

				if (strlen($server_public_host_key) < 4) {
					return false;
				}
				$temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
				$g = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

				if (strlen($server_public_host_key) < 4) {
					return false;
				}
				$temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
				$y = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

				$temp = unpack('Nlength', $this->_string_shift($signature, 4));
				if ($temp['length'] != 40) {
					user_error('Invalid signature');
					return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
				}

				$r = new Math_BigInteger($this->_string_shift($signature, 20), 256);
				$s = new Math_BigInteger($this->_string_shift($signature, 20), 256);

				switch (true) {
					case $r->equals($zero):
					case $r->compare($q) >= 0:
					case $s->equals($zero):
					case $s->compare($q) >= 0:
						user_error('Invalid signature');
						return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
				}

				$w = $s->modInverse($q);

				$u1 = $w->multiply(new Math_BigInteger(sha1($this->exchange_hash), 16));
				list(, $u1) = $u1->divide($q);

				$u2 = $w->multiply($r);
				list(, $u2) = $u2->divide($q);

				$g = $g->modPow($u1, $p);
				$y = $y->modPow($u2, $p);

				$v = $g->multiply($y);
				list(, $v) = $v->divide($p);
				list(, $v) = $v->divide($q);

				if (!$v->equals($r)) {
					user_error('Bad server signature');
					return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
				}

				break;
			case 'ssh-rsa':
			case 'rsa-sha2-256':
			case 'rsa-sha2-512':
				if (strlen($server_public_host_key) < 4) {
					return false;
				}
				$temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
				$e = new Math_BigInteger($this->_string_shift($server_public_host_key, $temp['length']), -256);

				if (strlen($server_public_host_key) < 4) {
					return false;
				}
				$temp = unpack('Nlength', $this->_string_shift($server_public_host_key, 4));
				$rawN = $this->_string_shift($server_public_host_key, $temp['length']);
				$n = new Math_BigInteger($rawN, -256);
				$nLength = strlen(ltrim($rawN, "\0"));

				if (strlen($signature) < 4) {
					return false;
				}
				$temp = unpack('Nlength', $this->_string_shift($signature, 4));
				$s = new Math_BigInteger($this->_string_shift($signature, $temp['length']), 256);

				if ($s->compare(new Math_BigInteger()) < 0 || $s->compare($n->subtract(new Math_BigInteger(1))) > 0) {
					user_error('Invalid signature');
					return $this->_disconnect(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
				}

				$s = $s->modPow($e, $n);
				$s = $s->toBytes();

				switch ($this->signature_format) {
					case 'rsa-sha2-512':
						$hash = 'sha512';
						break;
					case 'rsa-sha2-256':
						$hash = 'sha256';
						break;
										default:
						$hash = 'sha1';
				}
				$hashObj = new Crypt_Hash($hash);
				switch ($this->signature_format) {
					case 'rsa-sha2-512':
						$h = pack('N5a*', 0x00305130, 0x0D060960, 0x86480165, 0x03040203, 0x05000440, $hashObj->hash($this->exchange_hash));
						break;
					case 'rsa-sha2-256':
						$h = pack('N5a*', 0x00303130, 0x0D060960, 0x86480165, 0x03040201, 0x05000420, $hashObj->hash($this->exchange_hash));
						break;
										default:
						$hash = 'sha1';
						$h = pack('N4a*', 0x00302130, 0x0906052B, 0x0E03021A, 0x05000414, $hashObj->hash($this->exchange_hash));
				}
				$h = chr(0x01) . str_repeat(chr(0xFF), $nLength - 2 - strlen($h)) . $h;

				if ($s != $h) {
					user_error('Bad server signature');
					return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
				}
				break;
			default:
				user_error('Unsupported signature format');
				return $this->_disconnect(NET_SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
		}

		return $this->signature_format . ' ' . base64_encode($this->server_public_host_key);
	}

	function getExitStatus()
	{
		if (is_null($this->exit_status)) {
			return false;
		}
		return $this->exit_status;
	}

	function getWindowColumns()
	{
		return $this->windowColumns;
	}

	function getWindowRows()
	{
		return $this->windowRows;
	}

	function setWindowColumns($value)
	{
		$this->windowColumns = $value;
	}

	function setWindowRows($value)
	{
		$this->windowRows = $value;
	}

	function setWindowSize($columns = 80, $rows = 24)
	{
		$this->windowColumns = $columns;
		$this->windowRows = $rows;
	}
}}