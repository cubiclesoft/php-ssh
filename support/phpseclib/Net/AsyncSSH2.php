<?php
	// Overrides parts of the SSH2 class and adds useful non-blocking related functionality for interactive shell mode only.

	class Async_Net_SSH2 extends Patched_Net_SSH2
	{
		var $fsock_blocking = true;
		var $async_write_buffer = "";
		var $async_read_buffer = "", $async_read_buffer_2 = "", $async_read_peek_only = false;

		function startShell()
		{
			if (!$this->isAuthenticated()) {
				user_error('Operation disallowed prior to login()');
				return false;
			}

			if (!($this->bitmap & NET_SSH2_MASK_SHELL) && !$this->_initShell()) {
				user_error('Unable to initiate an interactive shell session');
				return false;
			}

			return true;
		}

		function getStream()
		{
			return $this->fsock;
		}

		function setBlocking($block)
		{
			@stream_set_blocking($this->fsock, (int)$block);

			$this->fsock_blocking = $block;
		}

		function hasShell()
		{
			return ($this->isConnected() && (($this->bitmap & NET_SSH2_MASK_SHELL) || $this->in_request_pty_exec === true));
		}

		// For use with a stream_select() call.
		function wantWrite()
		{
			return ($this->async_write_buffer !== "");
		}

		function sendWrite()
		{
			if (!$this->isAuthenticated()) {
				user_error('Operation disallowed prior to login()');
				return false;
			}

			if (!$this->hasShell()) {
				user_error('Initiate an interactive shell session prior to calling sendWrite()');
				return false;
			}

			if ($this->async_write_buffer !== "")
			{
				$result = fwrite($this->fsock, $this->async_write_buffer);

				// Serious bug in PHP core for all socket types:  https://bugs.php.net/bug.php?id=73535
				if ($result === 0)
				{
					// Temporarily switch to non-blocking sockets and test a one byte read (doesn't matter if data is available or not).
					if ($this->fsock_blocking)  @stream_set_blocking($this->fsock, 0);

					$data2 = @fread($this->fsock, 1);

					if ($data2 === false)  return false;
					if ($data2 === "" && feof($this->fsock))  return false;

					if ($data2 !== "")  $this->async_read_buffer .= $data2;

					if ($this->fsock_blocking)  @stream_set_blocking($this->fsock, 1);
				}
				else
				{
					$this->async_write_buffer = (string)substr($this->async_write_buffer, $result);
				}
			}

			return true;
		}

		function readAsync()
		{
			if (!$this->isAuthenticated()) {
				user_error('Operation disallowed prior to login()');
				return false;
			}

			if (!$this->hasShell()) {
				user_error('Initiate an interactive shell session prior to calling readAsync()');
				return false;
			}

			if (!$this->fsock_blocking)  $this->setBlocking(false);

			$channel = $this->_get_interactive_channel();

			// Attempt to decrypt a channel packet on the interactive channel.
			if (!empty($this->channel_buffers[$channel]))  $result = true;
			else
			{
				$lastseqno = $this->get_seq_no;
				$this->async_read_peek_only = true;
				$result = $this->_get_channel_packet($channel);
				$this->async_read_buffer = $this->async_read_buffer_2 . $this->async_read_buffer;
				$this->async_read_buffer_2 = "";
				$this->async_read_peek_only = false;
				$this->get_seq_no = $lastseqno;
			}

			if ($result === false)
			{
				if (feof($this->fsock))
				{
					$result = $this->_get_channel_packet($channel);

					$this->disconnect();
				}

				return $result;
			}

			return $this->_get_channel_packet($channel);
		}

	// Modified function to support pushing data into async_write_buffer.
	function _send_binary_packet($data, $logged = null)
	{
		// When just checking for a valid packet for the channel, writes can occur.  Skip those requests as they will be queued in the future.
		if ($this->async_read_peek_only)  return true;

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

		$start = strtok(microtime(), ' ') + strtok('');
		if ($this->fsock_blocking)  $result = strlen($packet) == fputs($this->fsock, $packet);
		else
		{
			$this->async_write_buffer .= $packet;
			$result = strlen($packet);
		}
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

	// Modified functions to support attempting to read the desired channel packet.
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
				if ($this->fsock_blocking) {
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

						$start = strtok(microtime(), ' ') + strtok('');
						$sec = floor($this->curTimeout);
						$usec = 1000000 * ($this->curTimeout - $sec);
						if (!@stream_select($read, $write, $except, $sec, $usec) && !count($read)) {
							$this->is_timeout = true;
							return true;
						}
						$elapsed = strtok(microtime(), ' ') + strtok('') - $start;
						$this->curTimeout-= $elapsed;
					}
				}

				$response = $this->_get_binary_packet(true);
				if ($response === false) {
					if (!$this->async_read_peek_only) {
						$this->bitmap = 0;
						user_error('Connection closed by server');
					}
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
				if (!$this->async_read_peek_only) {
					$this->window_size_server_to_client[$channel]-= strlen($response);

					if ($this->window_size_server_to_client[$channel] < 0) {
						$packet = pack('CNN', NET_SSH2_MSG_CHANNEL_WINDOW_ADJUST, $this->server_channels[$channel], $this->window_size);
						if (!$this->_send_binary_packet($packet)) {
							return false;
						}
						$this->window_size_server_to_client[$channel]+= $this->window_size;
					}
				}

				switch ($type) {
					case NET_SSH2_MSG_CHANNEL_EXTENDED_DATA:

						if (strlen($response) < 8) {
							return false;
						}
						extract(unpack('Ndata_type_code/Nlength', $this->_string_shift($response, 8)));
						$data = $this->_string_shift($response, $length);
						if (!$this->async_read_peek_only)  $this->stdErrorLog.= $data;
						if ($skip_extended || $this->quiet_mode) {
							continue 2;
						}
						if ($client_channel == $channel && $this->channel_status[$channel] == NET_SSH2_MSG_CHANNEL_DATA) {
							return $data;
						}
						if (!$this->async_read_peek_only) {
							if (!isset($this->channel_buffers[$channel])) {
								$this->channel_buffers[$channel] = array();
							}
							$this->channel_buffers[$channel][] = $data;
						}

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
								if (!$this->async_read_peek_only)  $this->errors[] = 'SSH_MSG_CHANNEL_REQUEST (exit-signal): ' . $this->_string_shift($response, $length);
								$this->_string_shift($response, 1);
								if (strlen($response) < 4) {
									return false;
								}
								extract(unpack('Nlength', $this->_string_shift($response, 4)));
								if ($this->async_read_peek_only) {
									return true;
								} else {
									if ($length) {
										$this->errors[count($this->errors)].= "\r\n" . $this->_string_shift($response, $length);
									}

									$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_EOF, $this->server_channels[$client_channel]));
									$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));

									$this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_EOF;
								}

								continue 3;
							case 'exit-status':
								if (strlen($response) < 5) {
									return false;
								}
								extract(unpack('Cfalse/Nexit_status', $this->_string_shift($response, 5)));
								if (!$this->async_read_peek_only)  $this->exit_status = $exit_status;

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
								if (!$this->async_read_peek_only)  $this->server_channels[$channel] = $server_channel;
								if (strlen($response) < 4) {
									return false;
								}
								extract(unpack('Nwindow_size', $this->_string_shift($response, 4)));
								if ($window_size < 0) {
									$window_size&= 0x7FFFFFFF;
									$window_size+= 0x80000000;
								}
								if (!$this->async_read_peek_only)  $this->window_size_client_to_server[$channel] = $window_size;
								if (strlen($response) < 4) {
									 return false;
								}
								if (!$this->async_read_peek_only) {
									$temp = unpack('Npacket_size_client_to_server', $this->_string_shift($response, 4));
									$this->packet_size_client_to_server[$channel] = $temp['packet_size_client_to_server'];
								}
								$result = $client_channel == $channel ? true : $this->_get_channel_packet($client_channel, $skip_extended);
								if (!$this->async_read_peek_only)  $this->_on_channel_open();
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
						if (!$this->async_read_peek_only && !is_bool($agent_response)) {
							$this->_send_channel_packet($channel, $agent_response);
						}
						break;
					}

					if ($client_channel == $channel) {
						return $data;
					}
					if (!$this->async_read_peek_only) {
						if (!isset($this->channel_buffers[$channel])) {
							$this->channel_buffers[$channel] = array();
						}
						$this->channel_buffers[$channel][] = $data;
					}
					break;
				case NET_SSH2_MSG_CHANNEL_CLOSE:
					if (!$this->async_read_peek_only) {
						$this->curTimeout = 0;

						if ($this->bitmap & NET_SSH2_MASK_SHELL) {
							$this->bitmap&= ~NET_SSH2_MASK_SHELL;
						}
						if ($this->channel_status[$channel] != NET_SSH2_MSG_CHANNEL_EOF) {
							$this->_send_binary_packet(pack('CN', NET_SSH2_MSG_CHANNEL_CLOSE, $this->server_channels[$channel]));
						}

						$this->channel_status[$channel] = NET_SSH2_MSG_CHANNEL_CLOSE;
					}
					if ($client_channel == $channel) {
						return true;
					}
				case NET_SSH2_MSG_CHANNEL_EOF:
					if ($this->async_read_peek_only)  return true;
					break;
				default:
					user_error('Error reading channel data');
					return $this->_disconnect(NET_SSH2_DISCONNECT_BY_APPLICATION);
			}
		}
	}

	function _fread($size)
	{
		if (!$size)  return "";

		$y = strlen($this->async_read_buffer);
//echo $y . " bytes available.  Want " . $size . " bytes.\n";

		do
		{
			if ($size <= $y)
			{
				$pos = $size;

				$data = substr($this->async_read_buffer, 0, $pos);
				$this->async_read_buffer = (string)substr($this->async_read_buffer, $pos);
				if ($this->async_read_peek_only)  $this->async_read_buffer_2 .= $data;

				return $data;
			}

			$data2 = fread($this->fsock, $size);

			if ($data2 === false || $data2 === "")
			{
				if ($this->async_read_buffer === "")  return $data2;

				$data = $this->async_read_buffer;
				$this->async_read_buffer = "";
				if ($this->async_read_peek_only)  $this->async_read_buffer_2 .= $data;

				return $data;
			}

			$this->async_read_buffer .= $data2;

			$y = strlen($this->async_read_buffer);
		} while ($this->fsock_blocking || ($size <= $y));

		$data = $this->async_read_buffer;
		$this->async_read_buffer = "";
		if ($this->async_read_peek_only)  $this->async_read_buffer_2 .= $data;

		return $data;
	}

	function _get_binary_packet($skip_channel_filter = false)
	{
		if (!is_resource($this->fsock)) {
			$this->bitmap = 0;
			user_error('Connection closed prematurely');
			return false;
		}

		$start = strtok(microtime(), ' ') + strtok('');
		$raw = $this->_fread($this->decrypt_block_size);
		if ($this->async_read_peek_only && strlen($raw) !== $this->decrypt_block_size) {
			return false;
		}

		if (!strlen($raw)) {
			return '';
		}

		if ($this->decrypt !== false) {
			$currdecrypt = ($this->async_read_peek_only ? clone $this->decrypt : $this->decrypt);
			$raw = $currdecrypt->decrypt($raw);
		}
		if ($raw === false) {
			if (!$this->async_read_peek_only)  user_error('Unable to decrypt content');
			return false;
		}

		if (strlen($raw) < 5) {
			return false;
		}
		extract(unpack('Npacket_length/Cpadding_length', $this->_string_shift($raw, 5)));

		$remaining_length = $packet_length + 4 - $this->decrypt_block_size;
//echo $remaining_length . " = " . $packet_length . " + 4 - " . $this->decrypt_block_size . "\n";

		if ($remaining_length < -$this->decrypt_block_size || $remaining_length > 0x9000 || $remaining_length % $this->decrypt_block_size != 0) {
			if (!$this->bad_key_size_fix && $this->_bad_algorithm_candidate($this->decrypt_algorithm) && !($this->bitmap & NET_SSH2_MASK_LOGIN)) {
				$this->bad_key_size_fix = true;
				$this->_reset_connection(NET_SSH2_DISCONNECT_KEY_EXCHANGE_FAILED);
				return false;
			}
			if (!$this->async_read_peek_only)  user_error('Invalid size');
			return false;
		}

		$buffer = $this->_fread($remaining_length);
		if ($buffer === false || ($buffer === "" && feof($this->fsock))) {
			$this->bitmap = 0;
			user_error('Error reading from socket');
			return false;
		}
		$remaining_length -= strlen($buffer);
		if ($remaining_length)
		{
			if (!$this->async_read_peek_only) {
				$this->bitmap = 0;
				user_error('Error reading from socket');
			}
			return false;
		}

		$stop = strtok(microtime(), ' ') + strtok('');
		if (strlen($buffer)) {
			$raw.= $this->decrypt !== false ? $currdecrypt->decrypt($buffer) : $buffer;
		}

		$payload = $this->_string_shift($raw, $packet_length - $padding_length - 1);
		$padding = $this->_string_shift($raw, $padding_length);
		if ($this->hmac_check !== false) {
			$hmac = $this->_fread($this->hmac_size);
			if ($hmac === false || ($hmac === "" && feof($this->fsock))) {
				if (!$this->async_read_peek_only) {
					$this->bitmap = 0;
					user_error('Error reading socket');
				}
				return false;
			} elseif (strlen($hmac) != $this->hmac_size) {
				if (!$this->async_read_peek_only) {
					$this->bitmap = 0;
					user_error('Error reading socket');
				}
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

	}
?>