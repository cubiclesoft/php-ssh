<?php
	// Applies useful patches to the SSH2 class.

	class Patched_Net_SSH2 extends Net_SSH2
	{
		var $terminal = "vt100";

		// See exec() and _initShell() below.
		function setTerminal($value)
		{
			$this->terminal = $value;
		}

		function getTerminal()
		{
			return $this->terminal;
		}

		// See setWindowColumns(), setWindowRows(), and setWindowSize() below.
		function _send_window_change()
		{
			if (!($this->bitmap & NET_SSH2_MASK_SHELL) && $this->in_request_pty_exec !== true)  return;

			$channel = $this->_get_interactive_channel();

			$packet = pack(
				'CNNa*CN4',
				NET_SSH2_MSG_CHANNEL_REQUEST,
				$this->server_channels[$channel],
				strlen('window-change'),
				'window-change',
				0,
				$this->windowColumns,
				$this->windowRows,
				0,
				0
			);

			$this->_send_binary_packet($packet);
		}

	// Overridden functions with improved functionality based on the above additions/changes.
	function setWindowColumns($value)
	{
		$this->windowColumns = $value;

		$this->_send_window_change();
	}

	function setWindowRows($value)
	{
		$this->windowRows = $value;

		$this->_send_window_change();
	}

	function setWindowSize($columns = 80, $rows = 24)
	{
		$this->windowColumns = $columns;
		$this->windowRows = $rows;

		$this->_send_window_change();
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
				strlen($this->terminal),
				$this->terminal,
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
			strlen($this->terminal),
			$this->terminal,
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



	}
?>