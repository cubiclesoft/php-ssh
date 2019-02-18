<?php
namespace {
define('SYSTEM_SSH_AGENTC_REQUEST_IDENTITIES', 11);
define('SYSTEM_SSH_AGENT_IDENTITIES_ANSWER', 12);
define('SYSTEM_SSH_AGENT_FAILURE', 5);
define('SYSTEM_SSH_AGENTC_SIGN_REQUEST', 13);
define('SYSTEM_SSH_AGENT_SIGN_RESPONSE', 14);

define('SYSTEM_SSH_AGENT_FORWARD_NONE', 0);
define('SYSTEM_SSH_AGENT_FORWARD_REQUEST', 1);
define('SYSTEM_SSH_AGENT_FORWARD_ACTIVE', 2);

define('SYSTEM_SSH_AGENT_RSA2_256', 2);
define('SYSTEM_SSH_AGENT_RSA2_512', 4);

class System_SSH_Agent_Identity
{

	var $key;

	var $key_blob;

	var $fsock;

	var $flags = 0;

	function __construct($fsock)
	{
		$this->fsock = $fsock;
	}

	function System_SSH_Agent_Identity($fsock)
	{
		$this->__construct($fsock);
	}

	function setPublicKey($key)
	{
		$this->key = $key;
		$this->key->setPublicKey();
	}

	function setPublicKeyBlob($key_blob)
	{
		$this->key_blob = $key_blob;
	}

	function getPublicKey($format = null)
	{
		return !isset($format) ? $this->key->getPublicKey() : $this->key->getPublicKey($format);
	}

	function setSignatureMode($mode)
	{
	}

	function setHash($hash)
	{
		$this->flags = 0;
		switch ($hash) {
			case 'sha1':
				break;
			case 'sha256':
				$this->flags = SYSTEM_SSH_AGENT_RSA2_256;
				break;
			case 'sha512':
				$this->flags = SYSTEM_SSH_AGENT_RSA2_512;
				break;
			default:
				user_error('The only supported hashes for RSA are sha1, sha256 and sha512');
		}
	}

	function sign($message)
	{
				$packet = pack('CNa*Na*N', SYSTEM_SSH_AGENTC_SIGN_REQUEST, strlen($this->key_blob), $this->key_blob, strlen($message), $message, $this->flags);
		$packet = pack('Na*', strlen($packet), $packet);
		if (strlen($packet) != fputs($this->fsock, $packet)) {
			user_error('Connection closed during signing');
		}

		$length = current(unpack('N', fread($this->fsock, 4)));
		$type = ord(fread($this->fsock, 1));
		if ($type != SYSTEM_SSH_AGENT_SIGN_RESPONSE) {
			user_error('Unable to retreive signature');
		}

		$signature_blob = fread($this->fsock, $length - 1);
		$length = current(unpack('N', $this->_string_shift($signature_blob, 4)));
		if ($length != strlen($signature_blob)) {
			user_error('Malformed signature blob');
		}
		$length = current(unpack('N', $this->_string_shift($signature_blob, 4)));
		if ($length > strlen($signature_blob) + 4) {
			user_error('Malformed signature blob');
		}
		$type = $this->_string_shift($signature_blob, $length);
		$this->_string_shift($signature_blob, 4);

		return $signature_blob;
	}

	function _string_shift(&$string, $index = 1)
	{
		$substr = substr($string, 0, $index);
		$string = substr($string, $index);
		return $substr;
	}
}

class System_SSH_Agent
{

	var $fsock;

	var $forward_status = SYSTEM_SSH_AGENT_FORWARD_NONE;

	var $socket_buffer = '';

	var $expected_bytes = 0;

	function __construct($address = null)
	{
		if (!$address) {
			switch (true) {
				case isset($_SERVER['SSH_AUTH_SOCK']):
					$address = $_SERVER['SSH_AUTH_SOCK'];
					break;
				case isset($_ENV['SSH_AUTH_SOCK']):
					$address = $_ENV['SSH_AUTH_SOCK'];
					break;
				default:
					user_error('SSH_AUTH_SOCK not found');
					return false;
			}
		}

		$this->fsock = fsockopen('unix://' . $address, 0, $errno, $errstr);
		if (!$this->fsock) {
			user_error("Unable to connect to ssh-agent (Error $errno: $errstr)");
		}
	}

	function System_SSH_Agent($address = null)
	{
		$this->__construct($address);
	}

	function requestIdentities()
	{
		if (!$this->fsock) {
			return array();
		}

		$packet = pack('NC', 1, SYSTEM_SSH_AGENTC_REQUEST_IDENTITIES);
		if (strlen($packet) != fputs($this->fsock, $packet)) {
			user_error('Connection closed while requesting identities');
			return array();
		}

		$length = current(unpack('N', fread($this->fsock, 4)));
		$type = ord(fread($this->fsock, 1));
		if ($type != SYSTEM_SSH_AGENT_IDENTITIES_ANSWER) {
			user_error('Unable to request identities');
			return array();
		}

		$identities = array();
		$keyCount = current(unpack('N', fread($this->fsock, 4)));
		for ($i = 0; $i < $keyCount; $i++) {
			$length = current(unpack('N', fread($this->fsock, 4)));
			$key_blob = fread($this->fsock, $length);
			$key_str = 'ssh-rsa ' . base64_encode($key_blob);
			$length = current(unpack('N', fread($this->fsock, 4)));
			if ($length) {
				$key_str.= ' ' . fread($this->fsock, $length);
			}
			$length = current(unpack('N', substr($key_blob, 0, 4)));
			$key_type = substr($key_blob, 4, $length);
			switch ($key_type) {
				case 'ssh-rsa':
					if (!class_exists('Crypt_RSA')) {
						include_once 'Crypt/RSA.php';
					}
					$key = new Crypt_RSA();
					$key->loadKey($key_str);
					break;
				case 'ssh-dss':
										break;
			}
						if (isset($key)) {
				$identity = new System_SSH_Agent_Identity($this->fsock);
				$identity->setPublicKey($key);
				$identity->setPublicKeyBlob($key_blob);
				$identities[] = $identity;
				unset($key);
			}
		}

		return $identities;
	}

	function startSSHForwarding($ssh)
	{
		if ($this->forward_status == SYSTEM_SSH_AGENT_FORWARD_NONE) {
			$this->forward_status = SYSTEM_SSH_AGENT_FORWARD_REQUEST;
		}
	}

	function _request_forwarding($ssh)
	{
		$request_channel = $ssh->_get_open_channel();
		if ($request_channel === false) {
			return false;
		}

		$packet = pack(
			'CNNa*C',
			NET_SSH2_MSG_CHANNEL_REQUEST,
			$ssh->server_channels[$request_channel],
			strlen('auth-agent-req@openssh.com'),
			'auth-agent-req@openssh.com',
			1
		);

		$ssh->channel_status[$request_channel] = NET_SSH2_MSG_CHANNEL_REQUEST;

		if (!$ssh->_send_binary_packet($packet)) {
			return false;
		}

		$response = $ssh->_get_channel_packet($request_channel);
		if ($response === false) {
			return false;
		}

		$ssh->channel_status[$request_channel] = NET_SSH2_MSG_CHANNEL_OPEN;
		$this->forward_status = SYSTEM_SSH_AGENT_FORWARD_ACTIVE;

		return true;
	}

	function _on_channel_open($ssh)
	{
		if ($this->forward_status == SYSTEM_SSH_AGENT_FORWARD_REQUEST) {
			$this->_request_forwarding($ssh);
		}
	}

	function _forward_data($data)
	{
		if ($this->expected_bytes > 0) {
			$this->socket_buffer.= $data;
			$this->expected_bytes -= strlen($data);
		} else {
			$agent_data_bytes = current(unpack('N', $data));
			$current_data_bytes = strlen($data);
			$this->socket_buffer = $data;
			if ($current_data_bytes != $agent_data_bytes + 4) {
				$this->expected_bytes = ($agent_data_bytes + 4) - $current_data_bytes;
				return false;
			}
		}

		if (strlen($this->socket_buffer) != fwrite($this->fsock, $this->socket_buffer)) {
			user_error('Connection closed attempting to forward data to SSH agent');
		}

		$this->socket_buffer = '';
		$this->expected_bytes = 0;

		$agent_reply_bytes = current(unpack('N', fread($this->fsock, 4)));

		$agent_reply_data = fread($this->fsock, $agent_reply_bytes);
		$agent_reply_data = current(unpack('a*', $agent_reply_data));

		return pack('Na*', $agent_reply_bytes, $agent_reply_data);
	}
}}