<?php
namespace {
if (!class_exists('Net_SSH2')) {
	include_once 'SSH2.php';
}

define('NET_SFTP_LOG_SIMPLE',	NET_SSH2_LOG_SIMPLE);

define('NET_SFTP_LOG_COMPLEX', NET_SSH2_LOG_COMPLEX);

define('NET_SFTP_LOG_REALTIME', 3);

define('NET_SFTP_CHANNEL', 0x100);

define('NET_SFTP_LOCAL_FILE',	1);

define('NET_SFTP_STRING',		2);

define('NET_SFTP_CALLBACK',	 16);

define('NET_SFTP_RESUME',		4);

define('NET_SFTP_RESUME_START',	8);

class Net_SFTP extends Net_SSH2
{

	var $packet_types = array();

	var $status_codes = array();

	var $request_id = false;

	var $packet_type = -1;

	var $packet_buffer = '';

	var $extensions = array();

	var $version;

	var $pwd = false;

	var $packet_type_log = array();

	var $packet_log = array();

	var $sftp_errors = array();

	var $stat_cache = array();

	var $max_sftp_packet;

	var $use_stat_cache = true;

	var $sortOptions = array();

	var $canonicalize_paths = true;

	function __construct($host, $port = 22, $timeout = 10)
	{
		parent::__construct($host, $port, $timeout);

		$this->max_sftp_packet = 1 << 15;

		$this->packet_types = array(
			1	=> 'NET_SFTP_INIT',
			2	=> 'NET_SFTP_VERSION',

			3	=> 'NET_SFTP_OPEN',
			4	=> 'NET_SFTP_CLOSE',
			5	=> 'NET_SFTP_READ',
			6	=> 'NET_SFTP_WRITE',
			7	=> 'NET_SFTP_LSTAT',
			9	=> 'NET_SFTP_SETSTAT',
			11 => 'NET_SFTP_OPENDIR',
			12 => 'NET_SFTP_READDIR',
			13 => 'NET_SFTP_REMOVE',
			14 => 'NET_SFTP_MKDIR',
			15 => 'NET_SFTP_RMDIR',
			16 => 'NET_SFTP_REALPATH',
			17 => 'NET_SFTP_STAT',

			18 => 'NET_SFTP_RENAME',
			19 => 'NET_SFTP_READLINK',
			20 => 'NET_SFTP_SYMLINK',

			101=> 'NET_SFTP_STATUS',
			102=> 'NET_SFTP_HANDLE',

			103=> 'NET_SFTP_DATA',
			104=> 'NET_SFTP_NAME',
			105=> 'NET_SFTP_ATTRS',

			200=> 'NET_SFTP_EXTENDED'
		);
		$this->status_codes = array(
			0 => 'NET_SFTP_STATUS_OK',
			1 => 'NET_SFTP_STATUS_EOF',
			2 => 'NET_SFTP_STATUS_NO_SUCH_FILE',
			3 => 'NET_SFTP_STATUS_PERMISSION_DENIED',
			4 => 'NET_SFTP_STATUS_FAILURE',
			5 => 'NET_SFTP_STATUS_BAD_MESSAGE',
			6 => 'NET_SFTP_STATUS_NO_CONNECTION',
			7 => 'NET_SFTP_STATUS_CONNECTION_LOST',
			8 => 'NET_SFTP_STATUS_OP_UNSUPPORTED',
			9 => 'NET_SFTP_STATUS_INVALID_HANDLE',
			10 => 'NET_SFTP_STATUS_NO_SUCH_PATH',
			11 => 'NET_SFTP_STATUS_FILE_ALREADY_EXISTS',
			12 => 'NET_SFTP_STATUS_WRITE_PROTECT',
			13 => 'NET_SFTP_STATUS_NO_MEDIA',
			14 => 'NET_SFTP_STATUS_NO_SPACE_ON_FILESYSTEM',
			15 => 'NET_SFTP_STATUS_QUOTA_EXCEEDED',
			16 => 'NET_SFTP_STATUS_UNKNOWN_PRINCIPAL',
			17 => 'NET_SFTP_STATUS_LOCK_CONFLICT',
			18 => 'NET_SFTP_STATUS_DIR_NOT_EMPTY',
			19 => 'NET_SFTP_STATUS_NOT_A_DIRECTORY',
			20 => 'NET_SFTP_STATUS_INVALID_FILENAME',
			21 => 'NET_SFTP_STATUS_LINK_LOOP',
			22 => 'NET_SFTP_STATUS_CANNOT_DELETE',
			23 => 'NET_SFTP_STATUS_INVALID_PARAMETER',
			24 => 'NET_SFTP_STATUS_FILE_IS_A_DIRECTORY',
			25 => 'NET_SFTP_STATUS_BYTE_RANGE_LOCK_CONFLICT',
			26 => 'NET_SFTP_STATUS_BYTE_RANGE_LOCK_REFUSED',
			27 => 'NET_SFTP_STATUS_DELETE_PENDING',
			28 => 'NET_SFTP_STATUS_FILE_CORRUPT',
			29 => 'NET_SFTP_STATUS_OWNER_INVALID',
			30 => 'NET_SFTP_STATUS_GROUP_INVALID',
			31 => 'NET_SFTP_STATUS_NO_MATCHING_BYTE_RANGE_LOCK'
		);
						$this->attributes = array(
			0x00000001 => 'NET_SFTP_ATTR_SIZE',
			0x00000002 => 'NET_SFTP_ATTR_UIDGID', 			0x00000004 => 'NET_SFTP_ATTR_PERMISSIONS',
			0x00000008 => 'NET_SFTP_ATTR_ACCESSTIME',
															(-1 << 31) & 0xFFFFFFFF => 'NET_SFTP_ATTR_EXTENDED'
		);
								$this->open_flags = array(
			0x00000001 => 'NET_SFTP_OPEN_READ',
			0x00000002 => 'NET_SFTP_OPEN_WRITE',
			0x00000004 => 'NET_SFTP_OPEN_APPEND',
			0x00000008 => 'NET_SFTP_OPEN_CREATE',
			0x00000010 => 'NET_SFTP_OPEN_TRUNCATE',
			0x00000020 => 'NET_SFTP_OPEN_EXCL'
		);
						$this->file_types = array(
			1 => 'NET_SFTP_TYPE_REGULAR',
			2 => 'NET_SFTP_TYPE_DIRECTORY',
			3 => 'NET_SFTP_TYPE_SYMLINK',
			4 => 'NET_SFTP_TYPE_SPECIAL',
			5 => 'NET_SFTP_TYPE_UNKNOWN',
									6 => 'NET_SFTP_TYPE_SOCKET',
			7 => 'NET_SFTP_TYPE_CHAR_DEVICE',
			8 => 'NET_SFTP_TYPE_BLOCK_DEVICE',
			9 => 'NET_SFTP_TYPE_FIFO'
		);
		$this->_define_array(
			$this->packet_types,
			$this->status_codes,
			$this->attributes,
			$this->open_flags,
			$this->file_types
		);

		if (!defined('NET_SFTP_QUEUE_SIZE')) {
			define('NET_SFTP_QUEUE_SIZE', 32);
		}
	}

	function Net_SFTP($host, $port = 22, $timeout = 10)
	{
		$this->__construct($host, $port, $timeout);
	}

	function login($username)
	{
		$args = func_get_args();
		if (!call_user_func_array(array(&$this, '_login'), $args)) {
			return false;
		}

		$this->window_size_server_to_client[NET_SFTP_CHANNEL] = $this->window_size;

		$packet = pack(
			'CNa*N3',
			NET_SSH2_MSG_CHANNEL_OPEN,
			strlen('session'),
			'session',
			NET_SFTP_CHANNEL,
			$this->window_size,
			0x4000
		);

		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SFTP_CHANNEL] = NET_SSH2_MSG_CHANNEL_OPEN;

		$response = $this->_get_channel_packet(NET_SFTP_CHANNEL, true);
		if ($response === false) {
			return false;
		}

		$packet = pack(
			'CNNa*CNa*',
			NET_SSH2_MSG_CHANNEL_REQUEST,
			$this->server_channels[NET_SFTP_CHANNEL],
			strlen('subsystem'),
			'subsystem',
			1,
			strlen('sftp'),
			'sftp'
		);
		if (!$this->_send_binary_packet($packet)) {
			return false;
		}

		$this->channel_status[NET_SFTP_CHANNEL] = NET_SSH2_MSG_CHANNEL_REQUEST;

		$response = $this->_get_channel_packet(NET_SFTP_CHANNEL, true);
		if ($response === false) {
						$command = "test -x /usr/lib/sftp-server && exec /usr/lib/sftp-server\n" .
						"test -x /usr/local/lib/sftp-server && exec /usr/local/lib/sftp-server\n" .
						"exec sftp-server";
									$packet = pack(
				'CNNa*CNa*',
				NET_SSH2_MSG_CHANNEL_REQUEST,
				$this->server_channels[NET_SFTP_CHANNEL],
				strlen('exec'),
				'exec',
				1,
				strlen($command),
				$command
			);
			if (!$this->_send_binary_packet($packet)) {
				return false;
			}

			$this->channel_status[NET_SFTP_CHANNEL] = NET_SSH2_MSG_CHANNEL_REQUEST;

			$response = $this->_get_channel_packet(NET_SFTP_CHANNEL, true);
			if ($response === false) {
				return false;
			}
		}

		$this->channel_status[NET_SFTP_CHANNEL] = NET_SSH2_MSG_CHANNEL_DATA;

		if (!$this->_send_sftp_packet(NET_SFTP_INIT, "\0\0\0\3")) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_VERSION) {
			user_error('Expected SSH_FXP_VERSION');
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nversion', $this->_string_shift($response, 4)));
		$this->version = $version;
		while (!empty($response)) {
			if (strlen($response) < 4) {
				return false;
			}
			extract(unpack('Nlength', $this->_string_shift($response, 4)));
			$key = $this->_string_shift($response, $length);
			if (strlen($response) < 4) {
				return false;
			}
			extract(unpack('Nlength', $this->_string_shift($response, 4)));
			$value = $this->_string_shift($response, $length);
			$this->extensions[$key] = $value;
		}

		$this->request_id = 1;

		switch ($this->version) {
			case 2:
			case 3:
				break;
			default:
				return false;
		}

		$this->pwd = $this->_realpath('.');

		$this->_update_stat_cache($this->pwd, array());

		return true;
	}

	function disableStatCache()
	{
		$this->use_stat_cache = false;
	}

	function enableStatCache()
	{
		$this->use_stat_cache = true;
	}

	function clearStatCache()
	{
		$this->stat_cache = array();
	}

	function enablePathCanonicalization()
	{
		$this->canonicalize_paths = true;
	}

	function disablePathCanonicalization()
	{
		$this->canonicalize_paths = false;
	}

	function pwd()
	{
		return $this->pwd;
	}

	function _logError($response, $status = -1)
	{
		if ($status == -1) {
			if (strlen($response) < 4) {
				return;
			}
			extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		}

		$error = $this->status_codes[$status];

		if ($this->version > 2 || strlen($response) < 4) {
			extract(unpack('Nlength', $this->_string_shift($response, 4)));
			$this->sftp_errors[] = $error . ': ' . $this->_string_shift($response, $length);
		} else {
			$this->sftp_errors[] = $error;
		}
	}

	function realpath($path)
	{
		return $this->_realpath($path);
	}

	function _realpath($path)
	{
		if (!$this->canonicalize_paths) {
			return $path;
		}

		if ($this->pwd === false) {
						if (!$this->_send_sftp_packet(NET_SFTP_REALPATH, pack('Na*', strlen($path), $path))) {
				return false;
			}

			$response = $this->_get_sftp_packet();
			switch ($this->packet_type) {
				case NET_SFTP_NAME:
																				$this->_string_shift($response, 4); 					if (strlen($response) < 4) {
						return false;
					}
					extract(unpack('Nlength', $this->_string_shift($response, 4)));
					return $this->_string_shift($response, $length);
				case NET_SFTP_STATUS:
					$this->_logError($response);
					return false;
				default:
					user_error('Expected SSH_FXP_NAME or SSH_FXP_STATUS');
					return false;
			}
		}

		if ($path[0] != '/') {
			$path = $this->pwd . '/' . $path;
		}

		$path = explode('/', $path);
		$new = array();
		foreach ($path as $dir) {
			if (!strlen($dir)) {
				continue;
			}
			switch ($dir) {
				case '..':
					array_pop($new);
				case '.':
					break;
				default:
					$new[] = $dir;
			}
		}

		return '/' . implode('/', $new);
	}

	function chdir($dir)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

				if ($dir === '') {
			$dir = './';
				} elseif ($dir[strlen($dir) - 1] != '/') {
			$dir.= '/';
		}

		$dir = $this->_realpath($dir);

				if ($this->use_stat_cache && is_array($this->_query_stat_cache($dir))) {
			$this->pwd = $dir;
			return true;
		}

		if (!$this->_send_sftp_packet(NET_SFTP_OPENDIR, pack('Na*', strlen($dir), $dir))) {
			return false;
		}

				$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_HANDLE:
				$handle = substr($response, 4);
				break;
			case NET_SFTP_STATUS:
				$this->_logError($response);
				return false;
			default:
				user_error('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS');
				return false;
		}

		if (!$this->_close_handle($handle)) {
			return false;
		}

		$this->_update_stat_cache($dir, array());

		$this->pwd = $dir;
		return true;
	}

	function nlist($dir = '.', $recursive = false)
	{
		return $this->_nlist_helper($dir, $recursive, '');
	}

	function _nlist_helper($dir, $recursive, $relativeDir)
	{
		$files = $this->_list($dir, false);

		if (!$recursive || $files === false) {
			return $files;
		}

		$result = array();
		foreach ($files as $value) {
			if ($value == '.' || $value == '..') {
				if ($relativeDir == '') {
					$result[] = $value;
				}
				continue;
			}
			if (is_array($this->_query_stat_cache($this->_realpath($dir . '/' . $value)))) {
				$temp = $this->_nlist_helper($dir . '/' . $value, true, $relativeDir . $value . '/');
				$result = array_merge($result, $temp);
			} else {
				$result[] = $relativeDir . $value;
			}
		}

		return $result;
	}

	function rawlist($dir = '.', $recursive = false)
	{
		$files = $this->_list($dir, true);
		if (!$recursive || $files === false) {
			return $files;
		}

		static $depth = 0;

		foreach ($files as $key => $value) {
			if ($depth != 0 && $key == '..') {
				unset($files[$key]);
				continue;
			}
			$is_directory = false;
			if ($key != '.' && $key != '..') {
				if ($this->use_stat_cache) {
					$is_directory = is_array($this->_query_stat_cache($this->_realpath($dir . '/' . $key)));
				} else {
					$stat = $this->lstat($dir . '/' . $key);
					$is_directory = $stat && $stat['type'] === NET_SFTP_TYPE_DIRECTORY;
				}
			}

			if ($is_directory) {
				$depth++;
				$files[$key] = $this->rawlist($dir . '/' . $key, true);
				$depth--;
			} else {
				$files[$key] = (object) $value;
			}
		}

		return $files;
	}

	function _list($dir, $raw = true)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$dir = $this->_realpath($dir . '/');
		if ($dir === false) {
			return false;
		}

				if (!$this->_send_sftp_packet(NET_SFTP_OPENDIR, pack('Na*', strlen($dir), $dir))) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_HANDLE:
																$handle = substr($response, 4);
				break;
			case NET_SFTP_STATUS:
								$this->_logError($response);
				return false;
			default:
				user_error('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS');
				return false;
		}

		$this->_update_stat_cache($dir, array());

		$contents = array();
		while (true) {
												if (!$this->_send_sftp_packet(NET_SFTP_READDIR, pack('Na*', strlen($handle), $handle))) {
				return false;
			}

			$response = $this->_get_sftp_packet();
			switch ($this->packet_type) {
				case NET_SFTP_NAME:
					if (strlen($response) < 4) {
						return false;
					}
					extract(unpack('Ncount', $this->_string_shift($response, 4)));
					for ($i = 0; $i < $count; $i++) {
						if (strlen($response) < 4) {
							return false;
						}
						extract(unpack('Nlength', $this->_string_shift($response, 4)));
						$shortname = $this->_string_shift($response, $length);
						if (strlen($response) < 4) {
							return false;
						}
						extract(unpack('Nlength', $this->_string_shift($response, 4)));
						$longname = $this->_string_shift($response, $length);
						$attributes = $this->_parseAttributes($response);
						if (!isset($attributes['type'])) {
							$fileType = $this->_parseLongname($longname);
							if ($fileType) {
								$attributes['type'] = $fileType;
							}
						}
						$contents[$shortname] = $attributes + array('filename' => $shortname);

						if (isset($attributes['type']) && $attributes['type'] == NET_SFTP_TYPE_DIRECTORY && ($shortname != '.' && $shortname != '..')) {
							$this->_update_stat_cache($dir . '/' . $shortname, array());
						} else {
							if ($shortname == '..') {
								$temp = $this->_realpath($dir . '/..') . '/.';
							} else {
								$temp = $dir . '/' . $shortname;
							}
							$this->_update_stat_cache($temp, (object) array('lstat' => $attributes));
						}
																	}
					break;
				case NET_SFTP_STATUS:
					if (strlen($response) < 4) {
						return false;
					}
					extract(unpack('Nstatus', $this->_string_shift($response, 4)));
					if ($status != NET_SFTP_STATUS_EOF) {
						$this->_logError($response, $status);
						return false;
					}
					break 2;
				default:
					user_error('Expected SSH_FXP_NAME or SSH_FXP_STATUS');
					return false;
			}
		}

		if (!$this->_close_handle($handle)) {
			return false;
		}

		if (count($this->sortOptions)) {
			uasort($contents, array(&$this, '_comparator'));
		}

		return $raw ? $contents : array_keys($contents);
	}

	function _comparator($a, $b)
	{
		switch (true) {
			case $a['filename'] === '.' || $b['filename'] === '.':
				if ($a['filename'] === $b['filename']) {
					return 0;
				}
				return $a['filename'] === '.' ? -1 : 1;
			case $a['filename'] === '..' || $b['filename'] === '..':
				if ($a['filename'] === $b['filename']) {
					return 0;
				}
				return $a['filename'] === '..' ? -1 : 1;
			case isset($a['type']) && $a['type'] === NET_SFTP_TYPE_DIRECTORY:
				if (!isset($b['type'])) {
					return 1;
				}
				if ($b['type'] !== $a['type']) {
					return -1;
				}
				break;
			case isset($b['type']) && $b['type'] === NET_SFTP_TYPE_DIRECTORY:
				return 1;
		}
		foreach ($this->sortOptions as $sort => $order) {
			if (!isset($a[$sort]) || !isset($b[$sort])) {
				if (isset($a[$sort])) {
					return -1;
				}
				if (isset($b[$sort])) {
					return 1;
				}
				return 0;
			}
			switch ($sort) {
				case 'filename':
					$result = strcasecmp($a['filename'], $b['filename']);
					if ($result) {
						return $order === SORT_DESC ? -$result : $result;
					}
					break;
				case 'permissions':
				case 'mode':
					$a[$sort]&= 07777;
					$b[$sort]&= 07777;
				default:
					if ($a[$sort] === $b[$sort]) {
						break;
					}
					return $order === SORT_ASC ? $a[$sort] - $b[$sort] : $b[$sort] - $a[$sort];
			}
		}
	}

	function setListOrder()
	{
		$this->sortOptions = array();
		$args = func_get_args();
		if (empty($args)) {
			return;
		}
		$len = count($args) & 0x7FFFFFFE;
		for ($i = 0; $i < $len; $i+=2) {
			$this->sortOptions[$args[$i]] = $args[$i + 1];
		}
		if (!count($this->sortOptions)) {
			$this->sortOptions = array('bogus' => true);
		}
	}

	function size($filename)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$result = $this->stat($filename);
		if ($result === false) {
			return false;
		}
		return isset($result['size']) ? $result['size'] : -1;
	}

	function _update_stat_cache($path, $value)
	{
		if ($this->use_stat_cache === false) {
			return;
		}

				$dirs = explode('/', preg_replace('#^/|/(?=/)|/$#', '', $path));

		$temp = &$this->stat_cache;
		$max = count($dirs) - 1;
		foreach ($dirs as $i => $dir) {
												if (is_object($temp)) {
				$temp = array();
			}
			if (!isset($temp[$dir])) {
				$temp[$dir] = array();
			}
			if ($i === $max) {
				if (is_object($temp[$dir]) && is_object($value)) {
					if (!isset($value->stat) && isset($temp[$dir]->stat)) {
						$value->stat = $temp[$dir]->stat;
					}
					if (!isset($value->lstat) && isset($temp[$dir]->lstat)) {
						$value->lstat = $temp[$dir]->lstat;
					}
				}
				$temp[$dir] = $value;
				break;
			}
			$temp = &$temp[$dir];
		}
	}

	function _remove_from_stat_cache($path)
	{
		$dirs = explode('/', preg_replace('#^/|/(?=/)|/$#', '', $path));

		$temp = &$this->stat_cache;
		$max = count($dirs) - 1;
		foreach ($dirs as $i => $dir) {
			if ($i === $max) {
				unset($temp[$dir]);
				return true;
			}
			if (!isset($temp[$dir])) {
				return false;
			}
			$temp = &$temp[$dir];
		}
	}

	function _query_stat_cache($path)
	{
		$dirs = explode('/', preg_replace('#^/|/(?=/)|/$#', '', $path));

		$temp = &$this->stat_cache;
		foreach ($dirs as $dir) {
			if (!isset($temp[$dir])) {
				return null;
			}
			$temp = &$temp[$dir];
		}
		return $temp;
	}

	function stat($filename)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$filename = $this->_realpath($filename);
		if ($filename === false) {
			return false;
		}

		if ($this->use_stat_cache) {
			$result = $this->_query_stat_cache($filename);
			if (is_array($result) && isset($result['.']) && isset($result['.']->stat)) {
				return $result['.']->stat;
			}
			if (is_object($result) && isset($result->stat)) {
				return $result->stat;
			}
		}

		$stat = $this->_stat($filename, NET_SFTP_STAT);
		if ($stat === false) {
			$this->_remove_from_stat_cache($filename);
			return false;
		}
		if (isset($stat['type'])) {
			if ($stat['type'] == NET_SFTP_TYPE_DIRECTORY) {
				$filename.= '/.';
			}
			$this->_update_stat_cache($filename, (object) array('stat' => $stat));
			return $stat;
		}

		$pwd = $this->pwd;
		$stat['type'] = $this->chdir($filename) ?
			NET_SFTP_TYPE_DIRECTORY :
			NET_SFTP_TYPE_REGULAR;
		$this->pwd = $pwd;

		if ($stat['type'] == NET_SFTP_TYPE_DIRECTORY) {
			$filename.= '/.';
		}
		$this->_update_stat_cache($filename, (object) array('stat' => $stat));

		return $stat;
	}

	function lstat($filename)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$filename = $this->_realpath($filename);
		if ($filename === false) {
			return false;
		}

		if ($this->use_stat_cache) {
			$result = $this->_query_stat_cache($filename);
			if (is_array($result) && isset($result['.']) && isset($result['.']->lstat)) {
				return $result['.']->lstat;
			}
			if (is_object($result) && isset($result->lstat)) {
				return $result->lstat;
			}
		}

		$lstat = $this->_stat($filename, NET_SFTP_LSTAT);
		if ($lstat === false) {
			$this->_remove_from_stat_cache($filename);
			return false;
		}
		if (isset($lstat['type'])) {
			if ($lstat['type'] == NET_SFTP_TYPE_DIRECTORY) {
				$filename.= '/.';
			}
			$this->_update_stat_cache($filename, (object) array('lstat' => $lstat));
			return $lstat;
		}

		$stat = $this->_stat($filename, NET_SFTP_STAT);

		if ($lstat != $stat) {
			$lstat = array_merge($lstat, array('type' => NET_SFTP_TYPE_SYMLINK));
			$this->_update_stat_cache($filename, (object) array('lstat' => $lstat));
			return $stat;
		}

		$pwd = $this->pwd;
		$lstat['type'] = $this->chdir($filename) ?
			NET_SFTP_TYPE_DIRECTORY :
			NET_SFTP_TYPE_REGULAR;
		$this->pwd = $pwd;

		if ($lstat['type'] == NET_SFTP_TYPE_DIRECTORY) {
			$filename.= '/.';
		}
		$this->_update_stat_cache($filename, (object) array('lstat' => $lstat));

		return $lstat;
	}

	function _stat($filename, $type)
	{
				$packet = pack('Na*', strlen($filename), $filename);
		if (!$this->_send_sftp_packet($type, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_ATTRS:
				return $this->_parseAttributes($response);
			case NET_SFTP_STATUS:
				$this->_logError($response);
				return false;
		}

		user_error('Expected SSH_FXP_ATTRS or SSH_FXP_STATUS');
		return false;
	}

	function truncate($filename, $new_size)
	{
		$attr = pack('N3', NET_SFTP_ATTR_SIZE, $new_size / 4294967296, $new_size);
		return $this->_setstat($filename, $attr, false);
	}

	function touch($filename, $time = null, $atime = null)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$filename = $this->_realpath($filename);
		if ($filename === false) {
			return false;
		}

		if (!isset($time)) {
			$time = time();
		}
		if (!isset($atime)) {
			$atime = $time;
		}

		$flags = NET_SFTP_OPEN_WRITE | NET_SFTP_OPEN_CREATE | NET_SFTP_OPEN_EXCL;
		$attr = pack('N3', NET_SFTP_ATTR_ACCESSTIME, $time, $atime);
		$packet = pack('Na*Na*', strlen($filename), $filename, $flags, $attr);
		if (!$this->_send_sftp_packet(NET_SFTP_OPEN, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_HANDLE:
				return $this->_close_handle(substr($response, 4));
			case NET_SFTP_STATUS:
				$this->_logError($response);
				break;
			default:
				user_error('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS');
				return false;
		}

		return $this->_setstat($filename, $attr, false);
	}

	function chown($filename, $uid, $recursive = false)
	{
						$attr = pack('N3', NET_SFTP_ATTR_UIDGID, $uid, -1);

		return $this->_setstat($filename, $attr, $recursive);
	}

	function chgrp($filename, $gid, $recursive = false)
	{
		$attr = pack('N3', NET_SFTP_ATTR_UIDGID, -1, $gid);

		return $this->_setstat($filename, $attr, $recursive);
	}

	function chmod($mode, $filename, $recursive = false)
	{
		if (is_string($mode) && is_int($filename)) {
			$temp = $mode;
			$mode = $filename;
			$filename = $temp;
		}

		$attr = pack('N2', NET_SFTP_ATTR_PERMISSIONS, $mode & 07777);
		if (!$this->_setstat($filename, $attr, $recursive)) {
			return false;
		}
		if ($recursive) {
			return true;
		}

		$filename = $this->realpath($filename);
								$packet = pack('Na*', strlen($filename), $filename);
		if (!$this->_send_sftp_packet(NET_SFTP_STAT, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_ATTRS:
				$attrs = $this->_parseAttributes($response);
				return $attrs['permissions'];
			case NET_SFTP_STATUS:
				$this->_logError($response);
				return false;
		}

		user_error('Expected SSH_FXP_ATTRS or SSH_FXP_STATUS');
		return false;
	}

	function _setstat($filename, $attr, $recursive)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$filename = $this->_realpath($filename);
		if ($filename === false) {
			return false;
		}

		$this->_remove_from_stat_cache($filename);

		if ($recursive) {
			$i = 0;
			$result = $this->_setstat_recursive($filename, $attr, $i);
			$this->_read_put_responses($i);
			return $result;
		}

						if (!$this->_send_sftp_packet(NET_SFTP_SETSTAT, pack('Na*a*', strlen($filename), $filename, $attr))) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_STATUS) {
			user_error('Expected SSH_FXP_STATUS');
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		if ($status != NET_SFTP_STATUS_OK) {
			$this->_logError($response, $status);
			return false;
		}

		return true;
	}

	function _setstat_recursive($path, $attr, &$i)
	{
		if (!$this->_read_put_responses($i)) {
			return false;
		}
		$i = 0;
		$entries = $this->_list($path, true);

		if ($entries === false) {
			return $this->_setstat($path, $attr, false);
		}

						if (empty($entries)) {
			return false;
		}

		unset($entries['.'], $entries['..']);
		foreach ($entries as $filename => $props) {
			if (!isset($props['type'])) {
				return false;
			}

			$temp = $path . '/' . $filename;
			if ($props['type'] == NET_SFTP_TYPE_DIRECTORY) {
				if (!$this->_setstat_recursive($temp, $attr, $i)) {
					return false;
				}
			} else {
				if (!$this->_send_sftp_packet(NET_SFTP_SETSTAT, pack('Na*a*', strlen($temp), $temp, $attr))) {
					return false;
				}

				$i++;

				if ($i >= NET_SFTP_QUEUE_SIZE) {
					if (!$this->_read_put_responses($i)) {
						return false;
					}
					$i = 0;
				}
			}
		}

		if (!$this->_send_sftp_packet(NET_SFTP_SETSTAT, pack('Na*a*', strlen($path), $path, $attr))) {
			return false;
		}

		$i++;

		if ($i >= NET_SFTP_QUEUE_SIZE) {
			if (!$this->_read_put_responses($i)) {
				return false;
			}
			$i = 0;
		}

		return true;
	}

	function readlink($link)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$link = $this->_realpath($link);

		if (!$this->_send_sftp_packet(NET_SFTP_READLINK, pack('Na*', strlen($link), $link))) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_NAME:
				break;
			case NET_SFTP_STATUS:
				$this->_logError($response);
				return false;
			default:
				user_error('Expected SSH_FXP_NAME or SSH_FXP_STATUS');
				return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Ncount', $this->_string_shift($response, 4)));
				if (!$count) {
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nlength', $this->_string_shift($response, 4)));
		return $this->_string_shift($response, $length);
	}

	function symlink($target, $link)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

				$link = $this->_realpath($link);

		$packet = pack('Na*Na*', strlen($target), $target, strlen($link), $link);
		if (!$this->_send_sftp_packet(NET_SFTP_SYMLINK, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_STATUS) {
			user_error('Expected SSH_FXP_STATUS');
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		if ($status != NET_SFTP_STATUS_OK) {
			$this->_logError($response, $status);
			return false;
		}

		return true;
	}

	function mkdir($dir, $mode = -1, $recursive = false)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$dir = $this->_realpath($dir);
						$attr = $mode == -1 ? "\0\0\0\0" : pack('N2', NET_SFTP_ATTR_PERMISSIONS, $mode & 07777);

		if ($recursive) {
			$dirs = explode('/', preg_replace('#/(?=/)|/$#', '', $dir));
			if (empty($dirs[0])) {
				array_shift($dirs);
				$dirs[0] = '/' . $dirs[0];
			}
			for ($i = 0; $i < count($dirs); $i++) {
				$temp = array_slice($dirs, 0, $i + 1);
				$temp = implode('/', $temp);
				$result = $this->_mkdir_helper($temp, $attr);
			}
			return $result;
		}

		return $this->_mkdir_helper($dir, $attr);
	}

	function _mkdir_helper($dir, $attr)
	{
		if (!$this->_send_sftp_packet(NET_SFTP_MKDIR, pack('Na*a*', strlen($dir), $dir, $attr))) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_STATUS) {
			user_error('Expected SSH_FXP_STATUS');
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		if ($status != NET_SFTP_STATUS_OK) {
			$this->_logError($response, $status);
			return false;
		}

		return true;
	}

	function rmdir($dir)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$dir = $this->_realpath($dir);
		if ($dir === false) {
			return false;
		}

		if (!$this->_send_sftp_packet(NET_SFTP_RMDIR, pack('Na*', strlen($dir), $dir))) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_STATUS) {
			user_error('Expected SSH_FXP_STATUS');
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		if ($status != NET_SFTP_STATUS_OK) {
						$this->_logError($response, $status);
			return false;
		}

		$this->_remove_from_stat_cache($dir);

		return true;
	}

	function put($remote_file, $data, $mode = NET_SFTP_STRING, $start = -1, $local_start = -1, $progressCallback = null)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$remote_file = $this->_realpath($remote_file);
		if ($remote_file === false) {
			return false;
		}

		$this->_remove_from_stat_cache($remote_file);

		$flags = NET_SFTP_OPEN_WRITE | NET_SFTP_OPEN_CREATE;

		if ($start >= 0) {
			$offset = $start;
		} elseif ($mode & NET_SFTP_RESUME) {
						$size = $this->size($remote_file);
			$offset = $size !== false ? $size : 0;
		} else {
			$offset = 0;
			$flags|= NET_SFTP_OPEN_TRUNCATE;
		}

		$packet = pack('Na*N2', strlen($remote_file), $remote_file, $flags, 0);
		if (!$this->_send_sftp_packet(NET_SFTP_OPEN, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_HANDLE:
				$handle = substr($response, 4);
				break;
			case NET_SFTP_STATUS:
				$this->_logError($response);
				return false;
			default:
				user_error('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS');
				return false;
		}

				$dataCallback = false;
		switch (true) {
			case $mode & NET_SFTP_CALLBACK:
				if (!is_callable($data)) {
					user_error("\$data should be is_callable if you set NET_SFTP_CALLBACK flag");
				}
				$dataCallback = $data;
								break;
			case is_resource($data):
				$mode = $mode & ~NET_SFTP_LOCAL_FILE;
				$info = stream_get_meta_data($data);
				if ($info['wrapper_type'] == 'PHP' && $info['stream_type'] == 'Input') {
					$fp = fopen('php://memory', 'w+');
					stream_copy_to_stream($data, $fp);
					rewind($fp);
				} else {
					$fp = $data;
				}
				break;
			case $mode & NET_SFTP_LOCAL_FILE:
				if (!is_file($data)) {
					user_error("$data is not a valid file");
					return false;
				}
				$fp = @fopen($data, 'rb');
				if (!$fp) {
					return false;
				}
		}

		if (isset($fp)) {
			$stat = fstat($fp);
			$size = !empty($stat) ? $stat['size'] : 0;

			if ($local_start >= 0) {
				fseek($fp, $local_start);
				$size-= $local_start;
			}
		} elseif ($dataCallback) {
			$size = 0;
		} else {
			$size = strlen($data);
		}

		$sent = 0;
		$size = $size < 0 ? ($size & 0x7FFFFFFF) + 0x80000000 : $size;

		$sftp_packet_size = 4096; 				$sftp_packet_size-= strlen($handle) + 25;
		$i = 0;
		while ($dataCallback || ($size === 0 || $sent < $size)) {
			if ($dataCallback) {
				$temp = call_user_func($dataCallback, $sftp_packet_size);
				if (is_null($temp)) {
					break;
				}
			} else {
				$temp = isset($fp) ? fread($fp, $sftp_packet_size) : substr($data, $sent, $sftp_packet_size);
				if ($temp === false || $temp === '') {
					break;
				}
			}

			$subtemp = $offset + $sent;
			$packet = pack('Na*N3a*', strlen($handle), $handle, $subtemp / 4294967296, $subtemp, strlen($temp), $temp);
			if (!$this->_send_sftp_packet(NET_SFTP_WRITE, $packet)) {
				if ($mode & NET_SFTP_LOCAL_FILE) {
					fclose($fp);
				}
				return false;
			}
			$sent+= strlen($temp);
			if (is_callable($progressCallback)) {
				call_user_func($progressCallback, $sent);
			}

			$i++;

			if ($i == NET_SFTP_QUEUE_SIZE) {
				if (!$this->_read_put_responses($i)) {
					$i = 0;
					break;
				}
				$i = 0;
			}
		}

		if (!$this->_read_put_responses($i)) {
			if ($mode & NET_SFTP_LOCAL_FILE) {
				fclose($fp);
			}
			$this->_close_handle($handle);
			return false;
		}

		if ($mode & NET_SFTP_LOCAL_FILE) {
			fclose($fp);
		}

		return $this->_close_handle($handle);
	}

	function _read_put_responses($i)
	{
		while ($i--) {
			$response = $this->_get_sftp_packet();
			if ($this->packet_type != NET_SFTP_STATUS) {
				user_error('Expected SSH_FXP_STATUS');
				return false;
			}

			if (strlen($response) < 4) {
				return false;
			}
			extract(unpack('Nstatus', $this->_string_shift($response, 4)));
			if ($status != NET_SFTP_STATUS_OK) {
				$this->_logError($response, $status);
				break;
			}
		}

		return $i < 0;
	}

	function _close_handle($handle)
	{
		if (!$this->_send_sftp_packet(NET_SFTP_CLOSE, pack('Na*', strlen($handle), $handle))) {
			return false;
		}

						$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_STATUS) {
			user_error('Expected SSH_FXP_STATUS');
			return false;
		}

		if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		if ($status != NET_SFTP_STATUS_OK) {
			$this->_logError($response, $status);
			return false;
		}

		return true;
	}

	function get($remote_file, $local_file = false, $offset = 0, $length = -1)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$remote_file = $this->_realpath($remote_file);
		if ($remote_file === false) {
			return false;
		}

		$packet = pack('Na*N2', strlen($remote_file), $remote_file, NET_SFTP_OPEN_READ, 0);
		if (!$this->_send_sftp_packet(NET_SFTP_OPEN, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_HANDLE:
				$handle = substr($response, 4);
				break;
			case NET_SFTP_STATUS: 				$this->_logError($response);
				return false;
			default:
				user_error('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS');
				return false;
		}

		if (is_resource($local_file)) {
			$fp = $local_file;
			$stat = fstat($fp);
			$res_offset = $stat['size'];
		} else {
			$res_offset = 0;
			if ($local_file !== false) {
				$fp = fopen($local_file, 'wb');
				if (!$fp) {
					return false;
				}
			} else {
				$content = '';
			}
		}

		$fclose_check = $local_file !== false && !is_resource($local_file);

		$start = $offset;
		$read = 0;
		while (true) {
			$i = 0;

			while ($i < NET_SFTP_QUEUE_SIZE && ($length < 0 || $read < $length)) {
				$tempoffset = $start + $read;

				$packet_size = $length > 0 ? min($this->max_sftp_packet, $length - $read) : $this->max_sftp_packet;

				$packet = pack('Na*N3', strlen($handle), $handle, $tempoffset / 4294967296, $tempoffset, $packet_size);
				if (!$this->_send_sftp_packet(NET_SFTP_READ, $packet)) {
					if ($fclose_check) {
						fclose($fp);
					}
					return false;
				}
				$packet = null;
				$read+= $packet_size;
				$i++;
			}

			if (!$i) {
				break;
			}

			$clear_responses = false;
			while ($i > 0) {
				$i--;

				if ($clear_responses) {
					$this->_get_sftp_packet();
					continue;
				} else {
					$response = $this->_get_sftp_packet();
				}

				switch ($this->packet_type) {
					case NET_SFTP_DATA:
						$temp = substr($response, 4);
						$offset+= strlen($temp);
						if ($local_file === false) {
							$content.= $temp;
						} else {
							fputs($fp, $temp);
						}
						$temp = null;
						break;
					case NET_SFTP_STATUS:
												$this->_logError($response);
						$clear_responses = true; 						break;
					default:
						if ($fclose_check) {
							fclose($fp);
						}
						user_error('Expected SSH_FX_DATA or SSH_FXP_STATUS');
				}
				$response = null;
			}

			if ($clear_responses) {
				break;
			}
		}

		if ($length > 0 && $length <= $offset - $start) {
			if ($local_file === false) {
				$content = substr($content, 0, $length);
			} else {
				ftruncate($fp, $length + $res_offset);
			}
		}

		if ($fclose_check) {
			fclose($fp);
		}

		if (!$this->_close_handle($handle)) {
			return false;
		}

				return isset($content) ? $content : true;
	}

	function delete($path, $recursive = true)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		if (is_object($path)) {
						$path = (string) $path;
		}

		if (!is_string($path) || $path == '') {
			return false;
		}

		$path = $this->_realpath($path);
		if ($path === false) {
			return false;
		}

				if (!$this->_send_sftp_packet(NET_SFTP_REMOVE, pack('Na*', strlen($path), $path))) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_STATUS) {
			user_error('Expected SSH_FXP_STATUS');
			return false;
		}

				if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		if ($status != NET_SFTP_STATUS_OK) {
			$this->_logError($response, $status);
			if (!$recursive) {
				return false;
			}
			$i = 0;
			$result = $this->_delete_recursive($path, $i);
			$this->_read_put_responses($i);
			return $result;
		}

		$this->_remove_from_stat_cache($path);

		return true;
	}

	function _delete_recursive($path, &$i)
	{
		if (!$this->_read_put_responses($i)) {
			return false;
		}
		$i = 0;
		$entries = $this->_list($path, true);

						if (empty($entries)) {
			return false;
		}

		unset($entries['.'], $entries['..']);
		foreach ($entries as $filename => $props) {
			if (!isset($props['type'])) {
				return false;
			}

			$temp = $path . '/' . $filename;
			if ($props['type'] == NET_SFTP_TYPE_DIRECTORY) {
				if (!$this->_delete_recursive($temp, $i)) {
					return false;
				}
			} else {
				if (!$this->_send_sftp_packet(NET_SFTP_REMOVE, pack('Na*', strlen($temp), $temp))) {
					return false;
				}
				$this->_remove_from_stat_cache($temp);

				$i++;

				if ($i >= NET_SFTP_QUEUE_SIZE) {
					if (!$this->_read_put_responses($i)) {
						return false;
					}
					$i = 0;
				}
			}
		}

		if (!$this->_send_sftp_packet(NET_SFTP_RMDIR, pack('Na*', strlen($path), $path))) {
			return false;
		}
		$this->_remove_from_stat_cache($path);

		$i++;

		if ($i >= NET_SFTP_QUEUE_SIZE) {
			if (!$this->_read_put_responses($i)) {
				return false;
			}
			$i = 0;
		}

		return true;
	}

	function file_exists($path)
	{
		if ($this->use_stat_cache) {
			$path = $this->_realpath($path);

			$result = $this->_query_stat_cache($path);

			if (isset($result)) {
								return $result !== false;
			}
		}

		return $this->stat($path) !== false;
	}

	function is_dir($path)
	{
		$result = $this->_get_stat_cache_prop($path, 'type');
		if ($result === false) {
			return false;
		}
		return $result === NET_SFTP_TYPE_DIRECTORY;
	}

	function is_file($path)
	{
		$result = $this->_get_stat_cache_prop($path, 'type');
		if ($result === false) {
			return false;
		}
		return $result === NET_SFTP_TYPE_REGULAR;
	}

	function is_link($path)
	{
		$result = $this->_get_lstat_cache_prop($path, 'type');
		if ($result === false) {
			return false;
		}
		return $result === NET_SFTP_TYPE_SYMLINK;
	}

	function is_readable($path)
	{
		$path = $this->_realpath($path);

		$packet = pack('Na*N2', strlen($path), $path, NET_SFTP_OPEN_READ, 0);
		if (!$this->_send_sftp_packet(NET_SFTP_OPEN, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_HANDLE:
				return true;
			case NET_SFTP_STATUS: 				return false;
			default:
				user_error('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS');
				return false;
		}
	}

	function is_writable($path)
	{
		$path = $this->_realpath($path);

		$packet = pack('Na*N2', strlen($path), $path, NET_SFTP_OPEN_WRITE, 0);
		if (!$this->_send_sftp_packet(NET_SFTP_OPEN, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		switch ($this->packet_type) {
			case NET_SFTP_HANDLE:
				return true;
			case NET_SFTP_STATUS: 				return false;
			default:
				user_error('Expected SSH_FXP_HANDLE or SSH_FXP_STATUS');
				return false;
		}
	}

	function is_writeable($path)
	{
		return $this->is_writable($path);
	}

	function fileatime($path)
	{
		return $this->_get_stat_cache_prop($path, 'atime');
	}

	function filemtime($path)
	{
		return $this->_get_stat_cache_prop($path, 'mtime');
	}

	function fileperms($path)
	{
		return $this->_get_stat_cache_prop($path, 'permissions');
	}

	function fileowner($path)
	{
		return $this->_get_stat_cache_prop($path, 'uid');
	}

	function filegroup($path)
	{
		return $this->_get_stat_cache_prop($path, 'gid');
	}

	function filesize($path)
	{
		return $this->_get_stat_cache_prop($path, 'size');
	}

	function filetype($path)
	{
		$type = $this->_get_stat_cache_prop($path, 'type');
		if ($type === false) {
			return false;
		}

		switch ($type) {
			case NET_SFTP_TYPE_BLOCK_DEVICE:
				return 'block';
			case NET_SFTP_TYPE_CHAR_DEVICE:
				return 'char';
			case NET_SFTP_TYPE_DIRECTORY:
				return 'dir';
			case NET_SFTP_TYPE_FIFO:
				return 'fifo';
			case NET_SFTP_TYPE_REGULAR:
				return 'file';
			case NET_SFTP_TYPE_SYMLINK:
				return 'link';
			default:
				return false;
		}
	}

	function _get_stat_cache_prop($path, $prop)
	{
		return $this->_get_xstat_cache_prop($path, $prop, 'stat');
	}

	function _get_lstat_cache_prop($path, $prop)
	{
		return $this->_get_xstat_cache_prop($path, $prop, 'lstat');
	}

	function _get_xstat_cache_prop($path, $prop, $type)
	{
		if ($this->use_stat_cache) {
			$path = $this->_realpath($path);

			$result = $this->_query_stat_cache($path);

			if (is_object($result) && isset($result->$type)) {
				return $result->{$type}[$prop];
			}
		}

		$result = $this->$type($path);

		if ($result === false || !isset($result[$prop])) {
			return false;
		}

		return $result[$prop];
	}

	function rename($oldname, $newname)
	{
		if (!($this->bitmap & NET_SSH2_MASK_LOGIN)) {
			return false;
		}

		$oldname = $this->_realpath($oldname);
		$newname = $this->_realpath($newname);
		if ($oldname === false || $newname === false) {
			return false;
		}

				$packet = pack('Na*Na*', strlen($oldname), $oldname, strlen($newname), $newname);
		if (!$this->_send_sftp_packet(NET_SFTP_RENAME, $packet)) {
			return false;
		}

		$response = $this->_get_sftp_packet();
		if ($this->packet_type != NET_SFTP_STATUS) {
			user_error('Expected SSH_FXP_STATUS');
			return false;
		}

				if (strlen($response) < 4) {
			return false;
		}
		extract(unpack('Nstatus', $this->_string_shift($response, 4)));
		if ($status != NET_SFTP_STATUS_OK) {
			$this->_logError($response, $status);
			return false;
		}

								$this->_remove_from_stat_cache($oldname);
		$this->_remove_from_stat_cache($newname);

		return true;
	}

	function _parseAttributes(&$response)
	{
		$attr = array();
		if (strlen($response) < 4) {
			user_error('Malformed file attributes');
			return array();
		}
		extract(unpack('Nflags', $this->_string_shift($response, 4)));
				foreach ($this->attributes as $key => $value) {
			switch ($flags & $key) {
				case NET_SFTP_ATTR_SIZE: 																																			$attr['size'] = hexdec(bin2hex($this->_string_shift($response, 8)));
					break;
				case NET_SFTP_ATTR_UIDGID: 					if (strlen($response) < 8) {
						user_error('Malformed file attributes');
						return $attr;
					}
					$attr+= unpack('Nuid/Ngid', $this->_string_shift($response, 8));
					break;
				case NET_SFTP_ATTR_PERMISSIONS: 					if (strlen($response) < 4) {
						user_error('Malformed file attributes');
						return $attr;
					}
					$attr+= unpack('Npermissions', $this->_string_shift($response, 4));
															$attr+= array('mode' => $attr['permissions']);
					$fileType = $this->_parseMode($attr['permissions']);
					if ($fileType !== false) {
						$attr+= array('type' => $fileType);
					}
					break;
				case NET_SFTP_ATTR_ACCESSTIME: 					if (strlen($response) < 8) {
						user_error('Malformed file attributes');
						return $attr;
					}
					$attr+= unpack('Natime/Nmtime', $this->_string_shift($response, 8));
					break;
				case NET_SFTP_ATTR_EXTENDED: 					if (strlen($response) < 4) {
						user_error('Malformed file attributes');
						return $attr;
					}
					extract(unpack('Ncount', $this->_string_shift($response, 4)));
					for ($i = 0; $i < $count; $i++) {
						if (strlen($response) < 4) {
							user_error('Malformed file attributes');
							return $attr;
						}
						extract(unpack('Nlength', $this->_string_shift($response, 4)));
						$key = $this->_string_shift($response, $length);
						if (strlen($response) < 4) {
							user_error('Malformed file attributes');
							return $attr;
						}
						extract(unpack('Nlength', $this->_string_shift($response, 4)));
						$attr[$key] = $this->_string_shift($response, $length);
					}
			}
		}
		return $attr;
	}

	function _parseMode($mode)
	{
						switch ($mode & 0170000) {			case 0000000: 				return false;
			case 0040000:
				return NET_SFTP_TYPE_DIRECTORY;
			case 0100000:
				return NET_SFTP_TYPE_REGULAR;
			case 0120000:
				return NET_SFTP_TYPE_SYMLINK;
									case 0010000: 				return NET_SFTP_TYPE_FIFO;
			case 0020000: 				return NET_SFTP_TYPE_CHAR_DEVICE;
			case 0060000: 				return NET_SFTP_TYPE_BLOCK_DEVICE;
			case 0140000: 				return NET_SFTP_TYPE_SOCKET;
			case 0160000: 												return NET_SFTP_TYPE_SPECIAL;
			default:
				return NET_SFTP_TYPE_UNKNOWN;
		}
	}

	function _parseLongname($longname)
	{
						if (preg_match('#^[^/]([r-][w-][xstST-]){3}#', $longname)) {
			switch ($longname[0]) {
				case '-':
					return NET_SFTP_TYPE_REGULAR;
				case 'd':
					return NET_SFTP_TYPE_DIRECTORY;
				case 'l':
					return NET_SFTP_TYPE_SYMLINK;
				default:
					return NET_SFTP_TYPE_SPECIAL;
			}
		}

		return false;
	}

	function _send_sftp_packet($type, $data)
	{
		$packet = $this->request_id !== false ?
			pack('NCNa*', strlen($data) + 5, $type, $this->request_id, $data) :
			pack('NCa*', strlen($data) + 1, $type, $data);

		$start = strtok(microtime(), ' ') + strtok(''); 		$result = $this->_send_channel_packet(NET_SFTP_CHANNEL, $packet);
		$stop = strtok(microtime(), ' ') + strtok('');

		if (defined('NET_SFTP_LOGGING')) {
			$packet_type = '-> ' . $this->packet_types[$type] .
							' (' . round($stop - $start, 4) . 's)';
			if (NET_SFTP_LOGGING == NET_SFTP_LOG_REALTIME) {
				echo "<pre>\r\n" . $this->_format_log(array($data), array($packet_type)) . "\r\n</pre>\r\n";
				flush();
				ob_flush();
			} else {
				$this->packet_type_log[] = $packet_type;
				if (NET_SFTP_LOGGING == NET_SFTP_LOG_COMPLEX) {
					$this->packet_log[] = $data;
				}
			}
		}

		return $result;
	}

	function _get_sftp_packet()
	{
		$this->curTimeout = false;

		$start = strtok(microtime(), ' ') + strtok('');
				while (strlen($this->packet_buffer) < 4) {
			$temp = $this->_get_channel_packet(NET_SFTP_CHANNEL, true);
			if (is_bool($temp)) {
				$this->packet_type = false;
				$this->packet_buffer = '';
				return false;
			}
			$this->packet_buffer.= $temp;
		}
		if (strlen($this->packet_buffer) < 4) {
			return false;
		}
		extract(unpack('Nlength', $this->_string_shift($this->packet_buffer, 4)));
		$tempLength = $length;
		$tempLength-= strlen($this->packet_buffer);

				while ($tempLength > 0) {
			$temp = $this->_get_channel_packet(NET_SFTP_CHANNEL, true);
			if (is_bool($temp)) {
				$this->packet_type = false;
				$this->packet_buffer = '';
				return false;
			}
			$this->packet_buffer.= $temp;
			$tempLength-= strlen($temp);
		}

		$stop = strtok(microtime(), ' ') + strtok('');

		$this->packet_type = ord($this->_string_shift($this->packet_buffer));

		if ($this->request_id !== false) {
			$this->_string_shift($this->packet_buffer, 4); 			$length-= 5; 		} else {
			$length-= 1; 		}

		$packet = $this->_string_shift($this->packet_buffer, $length);

		if (defined('NET_SFTP_LOGGING')) {
			$packet_type = '<- ' . $this->packet_types[$this->packet_type] .
							' (' . round($stop - $start, 4) . 's)';
			if (NET_SFTP_LOGGING == NET_SFTP_LOG_REALTIME) {
				echo "<pre>\r\n" . $this->_format_log(array($packet), array($packet_type)) . "\r\n</pre>\r\n";
				flush();
				ob_flush();
			} else {
				$this->packet_type_log[] = $packet_type;
				if (NET_SFTP_LOGGING == NET_SFTP_LOG_COMPLEX) {
					$this->packet_log[] = $packet;
				}
			}
		}

		return $packet;
	}

	function getSFTPLog()
	{
		if (!defined('NET_SFTP_LOGGING')) {
			return false;
		}

		switch (NET_SFTP_LOGGING) {
			case NET_SFTP_LOG_COMPLEX:
				return $this->_format_log($this->packet_log, $this->packet_type_log);
				break;
						default:
				return $this->packet_type_log;
		}
	}

	function getSFTPErrors()
	{
		return $this->sftp_errors;
	}

	function getLastSFTPError()
	{
		return count($this->sftp_errors) ? $this->sftp_errors[count($this->sftp_errors) - 1] : '';
	}

	function getSupportedVersions()
	{
		$temp = array('version' => $this->version);
		if (isset($this->extensions['versions'])) {
			$temp['extensions'] = $this->extensions['versions'];
		}
		return $temp;
	}

	function _disconnect($reason)
	{
		$this->pwd = false;
		parent::_disconnect($reason);
	}
}}