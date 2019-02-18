<?php
namespace {
define('NET_SCP_LOCAL_FILE', 1);

define('NET_SCP_STRING',	2);

define('NET_SCP_SSH1', 1);

define('NET_SCP_SSH2',	2);

class Net_SCP
{

	var $ssh;

	var $packet_size;

	var $mode;

	function __construct($ssh)
	{
		if (!is_object($ssh)) {
			return;
		}

		switch (strtolower(get_class($ssh))) {
			case 'net_ssh2':
				$this->mode = NET_SCP_SSH2;
				break;
			case 'net_ssh1':
				$this->packet_size = 50000;
				$this->mode = NET_SCP_SSH1;
				break;
			default:
				return;
		}

		$this->ssh = $ssh;
	}

	function Net_SCP($ssh)
	{
		$this->__construct($ssh);
	}

	function put($remote_file, $data, $mode = NET_SCP_STRING, $callback = null)
	{
		if (!isset($this->ssh)) {
			return false;
		}

		if (empty($remote_file)) {
			user_error('remote_file cannot be blank', E_USER_NOTICE);
			return false;
		}

		if (!$this->ssh->exec('scp -t ' . escapeshellarg($remote_file), false)) { 			return false;
		}

		$temp = $this->_receive();
		if ($temp !== chr(0)) {
			return false;
		}

		if ($this->mode == NET_SCP_SSH2) {
			$this->packet_size = $this->ssh->packet_size_client_to_server[NET_SSH2_CHANNEL_EXEC] - 4;
		}

		$remote_file = basename($remote_file);

		if ($mode == NET_SCP_STRING) {
			$size = strlen($data);
		} else {
			if (!is_file($data)) {
				user_error("$data is not a valid file", E_USER_NOTICE);
				return false;
			}

			$fp = @fopen($data, 'rb');
			if (!$fp) {
				return false;
			}
			$size = filesize($data);
		}

		$this->_send('C0644 ' . $size . ' ' . $remote_file . "\n");

		$temp = $this->_receive();
		if ($temp !== chr(0)) {
			return false;
		}

		$sent = 0;
		while ($sent < $size) {
			$temp = $mode & NET_SCP_STRING ? substr($data, $sent, $this->packet_size) : fread($fp, $this->packet_size);
			$this->_send($temp);
			$sent+= strlen($temp);

			if (is_callable($callback)) {
				call_user_func($callback, $sent);
			}
		}
		$this->_close();

		if ($mode != NET_SCP_STRING) {
			fclose($fp);
		}

		return true;
	}

	function get($remote_file, $local_file = false)
	{
		if (!isset($this->ssh)) {
			return false;
		}

		if (!$this->ssh->exec('scp -f ' . escapeshellarg($remote_file), false)) { 			return false;
		}

		$this->_send("\0");

		if (!preg_match('#(?<perms>[^ ]+) (?<size>\d+) (?<name>.+)#', rtrim($this->_receive()), $info)) {
			return false;
		}

		$this->_send("\0");

		$size = 0;

		if ($local_file !== false) {
			$fp = @fopen($local_file, 'wb');
			if (!$fp) {
				return false;
			}
		}

		$content = '';
		while ($size < $info['size']) {
			$data = $this->_receive();
						$size+= strlen($data);

			if ($local_file === false) {
				$content.= $data;
			} else {
				fputs($fp, $data);
			}
		}

		$this->_close();

		if ($local_file !== false) {
			fclose($fp);
			return true;
		}

		return $content;
	}

	function _send($data)
	{
		switch ($this->mode) {
			case NET_SCP_SSH2:
				$this->ssh->_send_channel_packet(NET_SSH2_CHANNEL_EXEC, $data);
				break;
			case NET_SCP_SSH1:
				$data = pack('CNa*', NET_SSH1_CMSG_STDIN_DATA, strlen($data), $data);
				$this->ssh->_send_binary_packet($data);
		}
	}

	function _receive()
	{
		switch ($this->mode) {
			case NET_SCP_SSH2:
				return $this->ssh->_get_channel_packet(NET_SSH2_CHANNEL_EXEC, true);
			case NET_SCP_SSH1:
				if (!$this->ssh->bitmap) {
					return false;
				}
				while (true) {
					$response = $this->ssh->_get_binary_packet();
					switch ($response[NET_SSH1_RESPONSE_TYPE]) {
						case NET_SSH1_SMSG_STDOUT_DATA:
							if (strlen($response[NET_SSH1_RESPONSE_DATA]) < 4) {
								return false;
							}
							extract(unpack('Nlength', $response[NET_SSH1_RESPONSE_DATA]));
							return $this->ssh->_string_shift($response[NET_SSH1_RESPONSE_DATA], $length);
						case NET_SSH1_SMSG_STDERR_DATA:
							break;
						case NET_SSH1_SMSG_EXITSTATUS:
							$this->ssh->_send_binary_packet(chr(NET_SSH1_CMSG_EXIT_CONFIRMATION));
							fclose($this->ssh->fsock);
							$this->ssh->bitmap = 0;
							return false;
						default:
							user_error('Unknown packet received', E_USER_NOTICE);
							return false;
					}
				}
		}
	}

	function _close()
	{
		switch ($this->mode) {
			case NET_SCP_SSH2:
				$this->ssh->_close_channel(NET_SSH2_CHANNEL_EXEC, true);
				break;
			case NET_SCP_SSH1:
				$this->ssh->disconnect();
		}
	}
}}