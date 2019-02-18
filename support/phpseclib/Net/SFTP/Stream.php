<?php
namespace {
class Net_SFTP_Stream
{

	static $instances;

	var $sftp;

	var $path;

	var $mode;

	var $pos;

	var $size;

	var $entries;

	var $eof;

	var $context;

	var $notification;

	static function register($protocol = 'sftp')
	{
		if (in_array($protocol, stream_get_wrappers(), true)) {
			return false;
		}
		$class = function_exists('get_called_class') ? get_called_class() : __CLASS__;
		return stream_wrapper_register($protocol, $class);
	}

	function __construct()
	{
		if (defined('NET_SFTP_STREAM_LOGGING')) {
			echo "__construct()\r\n";
		}

		if (!class_exists('Net_SFTP')) {
			include_once 'Net/SFTP.php';
		}
	}

	function _parse_path($path)
	{
		$orig = $path;
		extract(parse_url($path) + array('port' => 22));
		if (isset($query)) {
			$path.= '?' . $query;
		} elseif (preg_match('/(\?|\?#)$/', $orig)) {
			$path.= '?';
		}
		if (isset($fragment)) {
			$path.= '#' . $fragment;
		} elseif ($orig[strlen($orig) - 1] == '#') {
			$path.= '#';
		}

		if (!isset($host)) {
			return false;
		}

		if (isset($this->context)) {
			$context = stream_context_get_params($this->context);
			if (isset($context['notification'])) {
				$this->notification = $context['notification'];
			}
		}

		if ($host[0] == '$') {
			$host = substr($host, 1);
			global ${$host};
			if (!is_object($$host) || get_class($$host) != 'Net_SFTP') {
				return false;
			}
			$this->sftp = $$host;
		} else {
			if (isset($this->context)) {
				$context = stream_context_get_options($this->context);
			}
			if (isset($context[$scheme]['session'])) {
				$sftp = $context[$scheme]['session'];
			}
			if (isset($context[$scheme]['sftp'])) {
				$sftp = $context[$scheme]['sftp'];
			}
			if (isset($sftp) && is_object($sftp) && get_class($sftp) == 'Net_SFTP') {
				$this->sftp = $sftp;
				return $path;
			}
			if (isset($context[$scheme]['username'])) {
				$user = $context[$scheme]['username'];
			}
			if (isset($context[$scheme]['password'])) {
				$pass = $context[$scheme]['password'];
			}
			if (isset($context[$scheme]['privkey']) && is_object($context[$scheme]['privkey']) && get_Class($context[$scheme]['privkey']) == 'Crypt_RSA') {
				$pass = $context[$scheme]['privkey'];
			}

			if (!isset($user) || !isset($pass)) {
				return false;
			}

						if (isset(self::$instances[$host][$port][$user][(string) $pass])) {
				$this->sftp = self::$instances[$host][$port][$user][(string) $pass];
			} else {
				$this->sftp = new Net_SFTP($host, $port);
				$this->sftp->disableStatCache();
				if (isset($this->notification) && is_callable($this->notification)) {

					call_user_func($this->notification, STREAM_NOTIFY_CONNECT, STREAM_NOTIFY_SEVERITY_INFO, '', 0, 0, 0);
					call_user_func($this->notification, STREAM_NOTIFY_AUTH_REQUIRED, STREAM_NOTIFY_SEVERITY_INFO, '', 0, 0, 0);
					if (!$this->sftp->login($user, $pass)) {
						call_user_func($this->notification, STREAM_NOTIFY_AUTH_RESULT, STREAM_NOTIFY_SEVERITY_ERR, 'Login Failure', NET_SSH2_MSG_USERAUTH_FAILURE, 0, 0);
						return false;
					}
					call_user_func($this->notification, STREAM_NOTIFY_AUTH_RESULT, STREAM_NOTIFY_SEVERITY_INFO, 'Login Success', NET_SSH2_MSG_USERAUTH_SUCCESS, 0, 0);
				} else {
					if (!$this->sftp->login($user, $pass)) {
						return false;
					}
				}
				self::$instances[$host][$port][$user][(string) $pass] = $this->sftp;
			}
		}

		return $path;
	}

	function _stream_open($path, $mode, $options, &$opened_path)
	{
		$path = $this->_parse_path($path);

		if ($path === false) {
			return false;
		}
		$this->path = $path;

		$this->size = $this->sftp->size($path);
		$this->mode = preg_replace('#[bt]$#', '', $mode);
		$this->eof = false;

		if ($this->size === false) {
			if ($this->mode[0] == 'r') {
				return false;
			} else {
				$this->sftp->touch($path);
				$this->size = 0;
			}
		} else {
			switch ($this->mode[0]) {
				case 'x':
					return false;
				case 'w':
					$this->sftp->truncate($path, 0);
					$this->size = 0;
			}
		}

		$this->pos = $this->mode[0] != 'a' ? 0 : $this->size;

		return true;
	}

	function _stream_read($count)
	{
		switch ($this->mode) {
			case 'w':
			case 'a':
			case 'x':
			case 'c':
				return false;
		}

		$result = $this->sftp->get($this->path, false, $this->pos, $count);
		if (isset($this->notification) && is_callable($this->notification)) {
			if ($result === false) {
				call_user_func($this->notification, STREAM_NOTIFY_FAILURE, STREAM_NOTIFY_SEVERITY_ERR, $this->sftp->getLastSFTPError(), NET_SFTP_OPEN, 0, 0);
				return 0;
			}
						call_user_func($this->notification, STREAM_NOTIFY_PROGRESS, STREAM_NOTIFY_SEVERITY_INFO, '', 0, strlen($result), $this->size);
		}

		if (empty($result)) { 			$this->eof = true;
			return false;
		}
		$this->pos+= strlen($result);

		return $result;
	}

	function _stream_write($data)
	{
		switch ($this->mode) {
			case 'r':
				return false;
		}

		$result = $this->sftp->put($this->path, $data, NET_SFTP_STRING, $this->pos);
		if (isset($this->notification) && is_callable($this->notification)) {
			if (!$result) {
				call_user_func($this->notification, STREAM_NOTIFY_FAILURE, STREAM_NOTIFY_SEVERITY_ERR, $this->sftp->getLastSFTPError(), NET_SFTP_OPEN, 0, 0);
				return 0;
			}
						call_user_func($this->notification, STREAM_NOTIFY_PROGRESS, STREAM_NOTIFY_SEVERITY_INFO, '', 0, strlen($data), strlen($data));
		}

		if ($result === false) {
			return false;
		}
		$this->pos+= strlen($data);
		if ($this->pos > $this->size) {
			$this->size = $this->pos;
		}
		$this->eof = false;
		return strlen($data);
	}

	function _stream_tell()
	{
		return $this->pos;
	}

	function _stream_eof()
	{
		return $this->eof;
	}

	function _stream_seek($offset, $whence)
	{
		switch ($whence) {
			case SEEK_SET:
				if ($offset >= $this->size || $offset < 0) {
					return false;
				}
				break;
			case SEEK_CUR:
				$offset+= $this->pos;
				break;
			case SEEK_END:
				$offset+= $this->size;
		}

		$this->pos = $offset;
		$this->eof = false;
		return true;
	}

	function _stream_metadata($path, $option, $var)
	{
		$path = $this->_parse_path($path);
		if ($path === false) {
			return false;
		}

								switch ($option) {
			case 1: 				return $this->sftp->touch($path, $var[0], $var[1]);
			case 2: 			case 3: 				return false;
			case 4: 				return $this->sftp->chown($path, $var);
			case 5: 				return $this->sftp->chgrp($path, $var);
			case 6: 				return $this->sftp->chmod($path, $var) !== false;
		}
	}

	function _stream_cast($cast_as)
	{
		return $this->sftp->fsock;
	}

	function _stream_lock($operation)
	{
		return false;
	}

	function _rename($path_from, $path_to)
	{
		$path1 = parse_url($path_from);
		$path2 = parse_url($path_to);
		unset($path1['path'], $path2['path']);
		if ($path1 != $path2) {
			return false;
		}

		$path_from = $this->_parse_path($path_from);
		$path_to = parse_url($path_to);
		if ($path_from === false) {
			return false;
		}

		$path_to = $path_to['path']; 						if (!$this->sftp->rename($path_from, $path_to)) {
			if ($this->sftp->stat($path_to)) {
				return $this->sftp->delete($path_to, true) && $this->sftp->rename($path_from, $path_to);
			}
			return false;
		}

		return true;
	}

	function _dir_opendir($path, $options)
	{
		$path = $this->_parse_path($path);
		if ($path === false) {
			return false;
		}
		$this->pos = 0;
		$this->entries = $this->sftp->nlist($path);
		return $this->entries !== false;
	}

	function _dir_readdir()
	{
		if (isset($this->entries[$this->pos])) {
			return $this->entries[$this->pos++];
		}
		return false;
	}

	function _dir_rewinddir()
	{
		$this->pos = 0;
		return true;
	}

	function _dir_closedir()
	{
		return true;
	}

	function _mkdir($path, $mode, $options)
	{
		$path = $this->_parse_path($path);
		if ($path === false) {
			return false;
		}

		return $this->sftp->mkdir($path, $mode, $options & STREAM_MKDIR_RECURSIVE);
	}

	function _rmdir($path, $options)
	{
		$path = $this->_parse_path($path);
		if ($path === false) {
			return false;
		}

		return $this->sftp->rmdir($path);
	}

	function _stream_flush()
	{
		return true;
	}

	function _stream_stat()
	{
		$results = $this->sftp->stat($this->path);
		if ($results === false) {
			return false;
		}
		return $results;
	}

	function _unlink($path)
	{
		$path = $this->_parse_path($path);
		if ($path === false) {
			return false;
		}

		return $this->sftp->delete($path, false);
	}

	function _url_stat($path, $flags)
	{
		$path = $this->_parse_path($path);
		if ($path === false) {
			return false;
		}

		$results = $flags & STREAM_URL_STAT_LINK ? $this->sftp->lstat($path) : $this->sftp->stat($path);
		if ($results === false) {
			return false;
		}

		return $results;
	}

	function _stream_truncate($new_size)
	{
		if (!$this->sftp->truncate($this->path, $new_size)) {
			return false;
		}

		$this->eof = false;
		$this->size = $new_size;

		return true;
	}

	function _stream_set_option($option, $arg1, $arg2)
	{
		return false;
	}

	function _stream_close()
	{
	}

	function __call($name, $arguments)
	{
		if (defined('NET_SFTP_STREAM_LOGGING')) {
			echo $name . '(';
			$last = count($arguments) - 1;
			foreach ($arguments as $i => $argument) {
				var_export($argument);
				if ($i != $last) {
					echo ',';
				}
			}
			echo ")\r\n";
		}
		$name = '_' . $name;
		if (!method_exists($this, $name)) {
			return false;
		}
		return call_user_func_array(array($this, $name), $arguments);
	}
}

Net_SFTP_Stream::register();}