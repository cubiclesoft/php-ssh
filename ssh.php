<?php
	// SSH tools in pure PHP.
	// (C) 2019 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/cli.php";
	require_once $rootpath . "/support/str_basics.php";

	// Process the command-line options.
	$options = array(
		"shortmap" => array(
			"s" => "suppressoutput",
			"?" => "help"
		),
		"rules" => array(
			"suppressoutput" => array("arg" => false),
			"help" => array("arg" => false)
		),
		"allow_opts_after_param" => false
	);
	$args = CLI::ParseCommandLine($options);

	if (isset($args["opts"]["help"]))
	{
		echo "SSH command-line tool\n";
		echo "Purpose:  Manage SSH keys and SSH/SFTP enabled servers.\n";
		echo "\n";
		echo "This tool is question/answer enabled.  Just running it will provide a guided interface.  It can also be run entirely from the command-line if you know all the answers.\n";
		echo "\n";
		echo "Syntax:  " . $args["file"] . " [options] [cmdgroup cmd [cmdoptions]]\n";
		echo "Options:\n";
		echo "\t-s   Suppress most output.  Useful for capturing JSON output.\n";
		echo "\n";
		echo "Examples:\n";
		echo "\tphp " . $args["file"] . "\n";
		echo "\tphp " . $args["file"] . " keys create -name test -bits 4096\n";
		echo "\tphp " . $args["file"] . " -s connect run myserver-root reboot\n";

		exit();
	}

	// Check enabled extensions.
	if (!extension_loaded("openssl"))  CLI::DisplayError("The 'openssl' PHP module is not enabled.  Please update the file '" . (php_ini_loaded_file() !== false ? php_ini_loaded_file() : "php.ini") . "' to enable the module.");

	$origargs = $args;
	$suppressoutput = (isset($args["opts"]["suppressoutput"]) && $args["opts"]["suppressoutput"]);

	// Get the command group.
	$cmdgroups = array(
		"keys" => "Manage SSH keys",
		"profiles" => "Manage SSH/SFTP connection profiles",
		"connect" => "Initiate a SSH/SFTP connection"
	);

	$cmdgroup = CLI::GetLimitedUserInputWithArgs($args, false, "Command group", false, "Available command groups:", $cmdgroups, true, $suppressoutput);

	// Get the command.
	switch ($cmdgroup)
	{
		case "keys":  $cmds = array("list" => "List SSH keys", "create" => "Create a new SSH key", "import" => "Import a SSH key", "get-info" => "Get detailed information about a SSH key", "export" => "Export a SSH key to multiple formats", "delete" => "Deletes a SSH key");  break;
		case "profiles":  $cmds = array("list" => "List SSH/SFTP profiles", "create" => "Create a new SSH/SFTP profile", "get-info" => "Get information about a SSH/SFTP profile", "remove-server-keys" => "Removes saved server public keys from a SSH/SFTP profile", "delete" => "Deletes a SSH/SFTP profile");  break;
		case "connect":  $cmds = array("test" => "Test connectivity", "run" => "Run one or more commands", "sequence" => "Run a set of commands stored in a file", "download" => "Download a file or directory", "upload" => "Upload a file or directory", "shell-php" => "Minimal interactive SSH shell in PHP", "shell-system" => "System SSH shell");  break;
	}

	$cmd = CLI::GetLimitedUserInputWithArgs($args, false, "Command", false, "Available commands:", $cmds, true, $suppressoutput);

	// Make sure directories exist.
	@mkdir($rootpath . "/ssh-keys", 0700);
	@mkdir($rootpath . "/ssh-profiles", 0700);
	@mkdir($rootpath . "/cache", 0700);

	function DisplayResult($result)
	{
		echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

		exit();
	}

	require_once $rootpath . "/support/phpseclib/Crypt/RSA.php";
	require_once $rootpath . "/support/phpseclib/Math/BigInteger.php";
	require_once $rootpath . "/support/phpseclib/Net/SFTP.php";

	$path = get_include_path();
	if (strpos($path, PATH_SEPARATOR . $rootpath . "/support/phpseclib/") === false)  set_include_path($path . PATH_SEPARATOR . $rootpath . "/support/phpseclib/");

	function SSHKeysList()
	{
		global $rootpath;

		$result = array("success" => true, "data" => array());
		$path = $rootpath . "/ssh-keys";
		$dir = opendir($path);
		if ($dir)
		{
			while (($file = readdir($dir)) !== false)
			{
				if ($file !== "." && $file !== ".." && is_file($path . "/" . $file) && substr($file, -5) == ".json")
				{
					$data = @json_decode(file_get_contents($path . "/" . $file), true);

					if (is_array($data))
					{
						$id = substr($file, 0, -5);

						$result["data"][$id] = array(
							"id" => $id,
							"fingerprint" => $data["fingerprint"],
							"bits" => $data["bits"],
							"created" => $data["created"]
						);
					}
				}
			}

			closedir($dir);
		}

		ksort($result["data"], SORT_NATURAL | SORT_FLAG_CASE);

		return $result;
	}

	function GetSSHKeyName()
	{
		global $suppressoutput, $args;

		if ($suppressoutput || CLI::CanGetUserInputWithArgs($args, "key"))  $sshkey = CLI::GetUserInputWithArgs($args, "key", "SSH key", false, "", $suppressoutput);
		else
		{
			$result = SSHKeysList();
			if (!$result["success"])  DisplayResult($result);

			$sshkeys = array();
			foreach ($result["data"] as $id => $sshkey)  $sshkeys[$id] = $sshkey["fingerprint"] . ", " . $sshkey["bits"] . " bits, " . date("M j, Y", $sshkey["created"]);
			if (!count($sshkeys))  CLI::DisplayError("No SSH keys have been created.  Try creating your first SSH key with the command:  keys create");
			$sshkey = CLI::GetLimitedUserInputWithArgs($args, "key", "SSH key", false, "Available SSH keys:", $sshkeys, true, $suppressoutput);
		}

		return $sshkey;
	}

	function SSHProfilesList()
	{
		global $rootpath;

		$result = array("success" => true, "data" => array());
		$path = $rootpath . "/ssh-profiles";
		$dir = opendir($path);
		if ($dir)
		{
			while (($file = readdir($dir)) !== false)
			{
				if ($file !== "." && $file !== ".." && is_file($path . "/" . $file) && substr($file, -5) == ".json")
				{
					$data = @json_decode(file_get_contents($path . "/" . $file), true);

					if (is_array($data))
					{
						$id = substr($file, 0, -5);

						$result["data"][$id] = array(
							"id" => $id,
							"chain" => $data["chain"],
							"created" => $data["created"]
						);
					}
				}
			}

			closedir($dir);
		}

		ksort($result["data"], SORT_NATURAL | SORT_FLAG_CASE);

		return $result;
	}

	function GetSSHProfileName()
	{
		global $suppressoutput, $args;

		if ($suppressoutput || CLI::CanGetUserInputWithArgs($args, "profile"))  $sshprofile = CLI::GetUserInputWithArgs($args, "profile", "SSH profile", false, "", $suppressoutput);
		else
		{
			$result = SSHProfilesList();
			if (!$result["success"])  DisplayResult($result);

			$sshprofiles = array();
			foreach ($result["data"] as $id => $sshprofile)
			{
				$info = array();
				foreach ($sshprofile["chain"] as $item)  $info[] = $item["username"] . "@" . $item["host"] . " (" . $item["method"] . ")";

				$sshprofiles[$id] = implode(" -> ", $info) . ", " . date("M j, Y", $sshprofile["created"]);
			}
			if (!count($sshprofiles))  CLI::DisplayError("No SSH profiles have been created.  Try creating your first SSH profile with the command:  profiles create");
			$sshprofile = CLI::GetLimitedUserInputWithArgs($args, "profile", "SSH profile", false, "Available SSH profiles:", $sshprofiles, true, $suppressoutput);
		}

		return $sshprofile;
	}

	function DownloadFile($ssh, $src, $dest, $info)
	{
		global $suppressoutput;

		@unlink($dest);
		if (file_exists($dest))
		{
			if (!$suppressoutput)  echo "Unable to remove '" . $dest . "'.\n";

			return array("success" => false, "error" => "Unable to remove '" . $dest . "'.", "errorcode" => "dest_file_remove");
		}

		if (!$suppressoutput)  echo "Downloading '" . $src . "'...\n";
		$result = $ssh->get($src, $dest);
		if (!$result)  return array("success" => false, "error" => "Unable to download '" . $src . "'.", "errorcode" => "download_failed", "info" => $ssh->getErrors());

		@touch($dest, $info["mtime"], $info["atime"]);

		return array("success" => true, "type" => "file", "src" => $src, "dest" => $dest);
	}

	function DownloadDirectory($ssh, $src, $dest)
	{
		global $suppressoutput;

		if (!$suppressoutput)  echo "Retrieving remote directory list '" . $src . "'...\n";
		$items = $ssh->rawlist($src);
		if ($items === false)  return array("success" => false, "error" => "An error occurred while reading directory '" . $src . "'.", "errorcode" => "sftp_read_error", "info" => $ssh->getErrors());

		$results = array();
		$results[] = array("success" => true, "type" => "dir", "src" => $src, "dest" => $dest);
		foreach ($items as $item)
		{
			if ($item["filename"] !== "." && $item["filename"] !== "..")
			{
				if ($item["type"] === NET_SFTP_TYPE_DIRECTORY)
				{
					$destdir = $dest . "/" . Str::FilenameSafe($item["filename"]);
					@mkdir($destdir);
					if (!is_dir($destdir))
					{
						$results[] = array("success" => false, "error" => "Unable to create '" . $destdir . "'.", "errorcode" => "dest_dir_create");
						if (!$suppressoutput)  echo "Unable to create '" . $destdir . "'.\n";
					}
					else
					{
						$srcdir = $src . "/" . $item["filename"];
						$result = DownloadDirectory($ssh, $srcdir, $destdir);
						if (!$result["success"])  $results[] = $result;
						else
						{
							foreach ($result["results"] as $result)  $results[] = $result;
						}

						@touch($destdir, $item["mtime"], $item["atime"]);
					}
				}
				else
				{
					$srcfile = $src . "/" . $item["filename"];
					$destfile = $dest . "/" . Str::FilenameSafe($item["filename"]);

					$results[] = DownloadFile($ssh, $srcfile, $destfile, $item);
				}
			}
		}

		return array("success" => true, "results" => $results);
	}

	function UploadFile($ssh, $src, $dest, $info)
	{
		global $suppressoutput;

		if (!$suppressoutput)  echo "Uploading '" . $src . "'...\n";
		$result = $ssh->put($dest, $src, NET_SFTP_LOCAL_FILE);
		if (!$result)  return array("success" => false, "error" => "Unable to upload '" . $src . "'.", "errorcode" => "upload_failed", "info" => $ssh->getErrors());

		@$ssh->touch($dest, $info["mtime"], $info["atime"]);

		return array("success" => true, "type" => "file", "src" => $src, "dest" => $dest);
	}

	function UploadDirectory($ssh, $src, $dest)
	{
		global $suppressoutput;

		if (!$suppressoutput)  echo "Processing '" . $src . "'...\n";
		$dir = @opendir($src);
		if ($dir === false)  return array("success" => false, "error" => "An error occurred while reading directory '" . $src . "'.", "errorcode" => "dir_read_error");

		$results = array();
		$results[] = array("success" => true, "type" => "dir", "src" => $src, "dest" => $dest);
		$files = array();
		while (($file = readdir($dir)) !== false)
		{
			if ($file !== "." && $file !== "..")
			{
				$files[] = $file;
			}
		}

		closedir($dir);

		sort($files, SORT_NATURAL | SORT_FLAG_CASE);

		foreach ($files as $file)
		{
			$info = @stat($src . "/" . $file);

			if (is_dir($src . "/" . $file))
			{
				$destdir = $dest . "/" . $file;
				@$ssh->mkdir($destdir);
				if (!$ssh->is_dir($destdir))
				{
					$results[] = array("success" => false, "error" => "Unable to create '" . $destdir . "'.", "errorcode" => "dest_dir_create");
					if (!$suppressoutput)  echo "Unable to create '" . $destdir . "'.\n";
				}
				else
				{
					$srcdir = $src . "/" . $file;
					$result = UploadDirectory($ssh, $srcdir, $destdir);
					if (!$result["success"])  $results[] = $result;
					else
					{
						foreach ($result["results"] as $result)  $results[] = $result;
					}

					@$ssh->touch($destdir, $info["mtime"], $info["atime"]);
				}
			}
			else
			{
				$srcfile = $src . "/" . $file;
				$destfile = $dest . "/" . $file;

				$results[] = UploadFile($ssh, $srcfile, $destfile, $info);
			}
		}

		return array("success" => true, "results" => $results);
	}

	function ReinitArgs($newargs)
	{
		global $args;

		// Process the parameters.
		$options = array(
			"shortmap" => array(
				"?" => "help"
			),
			"rules" => array(
			)
		);

		foreach ($newargs as $arg)  $options["rules"][$arg] = array("arg" => true, "multiple" => true);
		$options["rules"]["help"] = array("arg" => false);

		$args = CLI::ParseCommandLine($options, array_merge(array(""), $args["params"]));

		if (isset($args["opts"]["help"]))  DisplayResult(array("success" => true, "options" => array_keys($options["rules"])));
	}

	if ($cmdgroup === "keys")
	{
		// SSH keys.
		if ($cmd === "list")  DisplayResult(SSHKeysList());
		else if ($cmd === "create")
		{
			ReinitArgs(array("name", "bits"));

			do
			{
				$name = CLI::GetUserInputWithArgs($args, "name", "SSH key name", false, "", $suppressoutput);
				$name = Str::FilenameSafe($name);
				$filename = $rootpath . "/ssh-keys/" . $name . ".json";
				$found = file_exists($filename);
				if ($found)  CLI::DisplayError("A SSH key with that name already exists.  The file '" . $filename . "' already exists.", false, false);
			} while ($found);

			do
			{
				$numbits = (int)CLI::GetUserInputWithArgs($args, "bits", "Number of bits", "4096", "The more bits in a generated SSH key, the more secure the connection.  However, the more bits there are, the longer it takes to connect to a server.  Must be at least 1024 bits but the default of 4096 is reasonably strong.", $suppressoutput);
				if ($numbits < 1024)  CLI::DisplayError("Invalid number of bits specified.  Must be at least 1024.", false, false);
			} while ($numbits < 1024);

			// Use phpseclib to generate the new SSH key.
			if (!$suppressoutput)  echo "Generating SSH key... (this can take a while!)\n";

			$rsa = new Crypt_RSA();
			$data = $rsa->createKey($numbits);

			if (!$suppressoutput)  echo "Done.\n";

			// Load the keys to get the fingerprint.
			if (!$rsa->loadKey($data["publickey"]))  CLI::DisplayError("An error occurred while loading the public key.");
			if (!$rsa->loadKey($data["privatekey"]))  CLI::DisplayError("An error occurred while loading the private key.");

			$data = array(
				"fingerprint" => $rsa->getPublicKeyFingerprint(),
				"bits" => $numbits,
				"created" => time(),
				"publickey" => $data["publickey"],
				"privatekey" => $data["privatekey"],
			);

			file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
			chmod($filename, 0600);

			$result = array(
				"success" => true,
				"ssh_key" => array(
					"id" => $name,
					"fingerprint" => $data["fingerprint"],
					"bits" => $data["bits"],
					"created" => $data["created"]
				)
			);

			DisplayResult($result);
		}
		else if ($cmd === "import")
		{
			ReinitArgs(array("publickey", "privatekey", "name"));

			do
			{
				$valid = false;
				$filename = CLI::GetUserInputWithArgs($args, "publickey", "Public key filename", false, "", $suppressoutput);
				if (!file_exists($filename))  CLI::DisplayError("The file '" . $filename . "' does not exist.", false, false);
				else
				{
					$publickey = file_get_contents($filename);

					$rsa = new Crypt_RSA();
					if (!$rsa->loadKey($publickey))  CLI::DisplayError("The file '" . $filename . "' does not contain a valid public key.", false, false);
					else
					{
						$publickey = $rsa->getPublicKey();
						$valid = true;
					}
				}
			} while (!$valid);

			do
			{
				$valid = false;
				$filename = CLI::GetUserInputWithArgs($args, "privatekey", "Private key filename", false, "To specify a password for the private key, enter filename|password where a vertical pipe separates the filename from the password.  Note that the private key will have password protection removed as this tool exists primarily for automation purposes.  You are expected to protect the host itself via other means (i.e. policies, procedures, people).", $suppressoutput);
				$filename = explode("|", $filename, 2);
				if (!file_exists($filename[0]))  CLI::DisplayError("The file '" . $filename . "' does not exist.", false, false);
				else
				{
					$privatekey = file_get_contents($filename[0]);

					$rsa = new Crypt_RSA();
					$rsa->loadKey($publickey);
					if (count($filename) > 1)  $rsa->setPassword($filename[1]);
					if (!$rsa->loadKey($privatekey))  CLI::DisplayError("The file '" . $filename . "' does not contain a valid private key.", false, false);
					else
					{
						$rsa->setPassword(false);
						$privatekey = $rsa->getPrivateKey();
						$valid = true;
					}
				}
			} while (!$valid);

			do
			{
				$name = CLI::GetUserInputWithArgs($args, "name", "SSH key name", false, "", $suppressoutput);
				$name = Str::FilenameSafe($name);
				$filename = $rootpath . "/ssh-keys/" . $name . ".json";
				$found = file_exists($filename);
				if ($found)  CLI::DisplayError("A SSH key with that name already exists.  The file '" . $filename . "' already exists.", false, false);
			} while ($found);

			$data = array(
				"fingerprint" => $rsa->getPublicKeyFingerprint(),
				"bits" => $rsa->getSize(),
				"created" => time(),
				"publickey" => $publickey,
				"privatekey" => $privatekey
			);

			file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
			chmod($filename, 0600);

			$result = array(
				"success" => true,
				"ssh_key" => array(
					"id" => $name,
					"fingerprint" => $data["fingerprint"],
					"bits" => $data["bits"],
					"created" => $data["created"]
				)
			);

			DisplayResult($result);
		}
		else
		{
			if ($cmd === "export")  ReinitArgs(array("key", "path"));
			else  ReinitArgs(array("key"));

			$name = GetSSHKeyName();
			$filename = $rootpath . "/ssh-keys/" . $name . ".json";

			if ($cmd === "get-info" || $cmd === "export")
			{
				$data = json_decode(file_get_contents($filename), true);

				$rsa = new Crypt_RSA();
				if (!$rsa->loadKey($data["publickey"]))  CLI::DisplayError("An error occurred while loading the public key.");
				if (!$rsa->loadKey($data["privatekey"]))  CLI::DisplayError("An error occurred while loading the private key.");

				$result = array(
					"success" => true,
					"ssh_key" => array(
						"id" => $name,
						"fingerprint" => $data["fingerprint"],
						"bits" => $data["bits"],
						"created" => $data["created"],

						"putty" => $rsa->getPrivateKey(CRYPT_RSA_PRIVATE_FORMAT_PUTTY),

						"private_pkcs1" => $rsa->getPrivateKey(CRYPT_RSA_PRIVATE_FORMAT_PKCS1),
						"private_xml" => $rsa->getPrivateKey(CRYPT_RSA_PRIVATE_FORMAT_XML),
						"private_pkcs8" => $rsa->getPrivateKey(CRYPT_RSA_PRIVATE_FORMAT_PKCS8),

						"public_raw" => $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_RAW),
						"public_pkcs1" => $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_PKCS1),
						"public_xml" => $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_XML),
						"public_ssh_authorized_keys" => $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_OPENSSH),
						"public_pkcs8" => $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_PKCS8),
					)
				);

				if ($cmd === "export")
				{
					do
					{
						$exportpath = CLI::GetUserInputWithArgs($args, "path", "Export path", false, "", $suppressoutput);
						$exportpath = str_replace("\\", "/", $exportpath);
						while (substr($exportpath, -1) === "/")  $exportpath = substr($exportpath, 0, -1);
						@mkdir($exportpath, 0700, true);
						$found = is_dir($exportpath);
						if (!$found)  CLI::DisplayError("The directory name '" . $exportpath . "' is invalid.", false, false);
					} while (!$found);

					$exportpath = realpath($exportpath);
					$exportpath = str_replace("\\", "/", $exportpath);
					while (substr($exportpath, -1) === "/")  $exportpath = substr($exportpath, 0, -1);

					// Write out all formats to reasonable filenames.
					file_put_contents($exportpath . "/" . $name . ".ppk", $result["ssh_key"]["putty"]);

					file_put_contents($exportpath . "/" . $name . "_private_pkcs1.pem", $result["ssh_key"]["private_pkcs1"]);
					file_put_contents($exportpath . "/" . $name . "_private.xml", $result["ssh_key"]["private_xml"]);
					file_put_contents($exportpath . "/" . $name . "_private_pkcs8.pem", $result["ssh_key"]["private_pkcs8"]);

					file_put_contents($exportpath . "/" . $name . "_public.raw", $result["ssh_key"]["public_raw"]);
					file_put_contents($exportpath . "/" . $name . "_public_pkcs1.pem", $result["ssh_key"]["public_pkcs1"]);
					file_put_contents($exportpath . "/" . $name . "_public.xml", $result["ssh_key"]["public_xml"]);
					file_put_contents($exportpath . "/" . $name . "_public_ssh_authorized_keys", $result["ssh_key"]["public_ssh_authorized_keys"]);
					file_put_contents($exportpath . "/" . $name . "_public_pkcs8.pem", $result["ssh_key"]["public_pkcs8"]);

					// Alter the result to point at the exported files.
					$result["ssh_key"]["putty"] = $exportpath . "/" . $name . ".ppk";

					$result["ssh_key"]["private_pkcs1"] = $exportpath . "/" . $name . "_private_pkcs1.pem";
					$result["ssh_key"]["private_xml"] = $exportpath . "/" . $name . "_private.xml";
					$result["ssh_key"]["private_pkcs8"] = $exportpath . "/" . $name . "_private_pkcs8.pem";

					$result["ssh_key"]["public_raw"] = $exportpath . "/" . $name . "_public.raw";
					$result["ssh_key"]["public_pkcs1"] = $exportpath . "/" . $name . "_public_pkcs1.pem";
					$result["ssh_key"]["public_xml"] = $exportpath . "/" . $name . "_public.xml";
					$result["ssh_key"]["public_ssh_authorized_keys"] = $exportpath . "/" . $name . "_public_ssh_authorized_keys";
					$result["ssh_key"]["public_pkcs8"] = $exportpath . "/" . $name . "_public_pkcs8.pem";
				}
				else
				{
					// For security reasons, these should never be displayed on a screen.  To prevent that, removing them is a good idea.
					unset($result["ssh_key"]["putty"]);
					unset($result["ssh_key"]["private_pkcs1"]);
					unset($result["ssh_key"]["private_xml"]);
					unset($result["ssh_key"]["private_pkcs8"]);
				}

				DisplayResult($result);
			}
			else if ($cmd === "delete")
			{
				@unlink($filename);

				$result = array(
					"success" => true
				);

				DisplayResult($result);
			}
		}
	}
	else if ($cmdgroup === "profiles")
	{
		// SSH profiles.
		if ($cmd === "list")  DisplayResult(SSHProfilesList());
		else if ($cmd === "create")
		{
			ReinitArgs(array("name", "host", "port", "username", "method", "key", "password"));

			do
			{
				$name = CLI::GetUserInputWithArgs($args, "name", "SSH profile name", false, "", $suppressoutput);
				$name = Str::FilenameSafe($name);
				$filename = $rootpath . "/ssh-profiles/" . $name . ".json";
				$found = file_exists($filename);
				if ($found)  CLI::DisplayError("A SSH profile with that name already exists.  The file '" . $filename . "' already exists.", false, false);
			} while ($found);

			$chain = array();
			do
			{
				$entry = array();
				$entry["host"] = CLI::GetUserInputWithArgs($args, "host", "SSH host", false, "Using an IP address is a more secure way to connect to a SSH host as it avoids a DNS request, which could return a spoofed response.  However, using a host name via DNS is more convenient if you trust your DNS server responses.", $suppressoutput);
				$entry["port"] = CLI::GetUserInputWithArgs($args, "port", "SSH port", "22", "", $suppressoutput);
				$entry["username"] = CLI::GetUserInputWithArgs($args, "username", "Username", false, "", $suppressoutput);

				$methods = array(
					"ssh-key" => "SSH key (very secure)",
					"password" => "A stored password (less secure)"
				);
				$entry["method"] = CLI::GetLimitedUserInputWithArgs($args, "method", "Login method", "ssh-key", "Available login methods:", $methods, true, $suppressoutput);

				if ($entry["method"] === "ssh-key")  $entry["ssh-key"] = GetSSHKeyName();
				else if ($entry["method"] === "password")  $entry["password"] = CLI::GetUserInputWithArgs($args, "password", "Password", "", "", $suppressoutput);

				$chain[] = $entry;

				// Unfortunately, at this time, phpseclib doesn't support tunneling connections nor non-blocking sockets.
				// Most SSH connections don't really require tunneling anyway.
//				$more = CLI::GetYesNoUserInputWithArgs($args, "more", "SSH to another host", "N", "", $suppressoutput);
				$more = false;

			} while ($more);

			$data = array(
				"chain" => $chain,
				"created" => time()
			);

			file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
			chmod($filename, 0600);

			$result = array(
				"success" => true,
				"ssh_profile" => array(
					"id" => $name,
					"chain" => $data["chain"],
					"created" => $data["created"]
				)
			);

			DisplayResult($result);
		}
		else
		{
			ReinitArgs(array("profile"));

			$name = GetSSHProfileName();
			$filename = $rootpath . "/ssh-profiles/" . $name . ".json";

			if ($cmd === "get-info")
			{
				$data = json_decode(file_get_contents($filename), true);

				$result = array(
					"success" => true,
					"ssh_profile" => array(
						"id" => $name,
						"chain" => $data["chain"],
						"created" => $data["created"]
					)
				);

				DisplayResult($result);
			}
			else if ($cmd === "remove-server-keys")
			{
				$data = json_decode(file_get_contents($filename), true);

				foreach ($data["chain"] as $num => $entry)
				{
					unset($entry["server"]);

					$data["chain"][$num] = $entry;
				}

				file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
				chmod($filename, 0600);

				$result = array(
					"success" => true,
					"ssh_profile" => array(
						"id" => $name,
						"chain" => $data["chain"],
						"created" => $data["created"]
					)
				);

				DisplayResult($result);
			}
			else if ($cmd === "delete")
			{
				@unlink($filename);

				$result = array(
					"success" => true
				);

				DisplayResult($result);
			}
		}
	}
	else if ($cmdgroup === "connect")
	{
		if ($cmd === "run")  ReinitArgs(array("profile", "run", "error"));
		else if ($cmd === "sequence")  ReinitArgs(array("profile", "file"));
		else if ($cmd === "shell-php")  ReinitArgs(array("profile", "run"));
		else if ($cmd === "download" || $cmd === "upload")  ReinitArgs(array("profile", "src", "dest"));
		else  ReinitArgs(array("profile"));

		$name = GetSSHProfileName();
		$filename = $rootpath . "/ssh-profiles/" . $name . ".json";
		$data = json_decode(file_get_contents($filename), true);

		if (count($data["chain"]) > 1)  CLI::DisplayError("This software does not currently support starting more than one ssh process at a time.  Sorry.  Submit a working cross-platform patch?");

		if ($cmd === "shell-system")
		{
			if (is_file($rootpath . "/ssh-win64/ssh.exe"))  $ssh = $rootpath . "/ssh-win64/ssh.exe";
			else if (is_file($rootpath . "/ssh-win32/ssh.exe"))  $ssh = $rootpath . "/ssh-win32/ssh.exe";
			else  $ssh = "ssh";

			file_put_contents($rootpath . "/cache/ssh_config", "");
			$ssh .= " -F " . escapeshellarg($rootpath . "/cache/ssh_config") . " -o " . escapeshellarg("UserKnownHostsFile=" . $rootpath . "/cache/known_hosts");

			$ts = microtime(true);
			foreach ($data["chain"] as $num => $entry)
			{
				// Export the private key to a file.
				if ($entry["method"] === "ssh-key")
				{
					$filename = $rootpath . "/ssh-keys/" . $entry["ssh-key"] . ".json";
					if (!file_exists($filename))  CLI::DisplayError("SSH key '" . $entry["ssh-key"] . "' does not exist.  Filename '" . $filename . "' does not exist.");
					$data2 = json_decode(file_get_contents($filename), true);

					$rsa = new Crypt_RSA();
					if (!$rsa->loadKey($data2["publickey"]))  CLI::DisplayError("An error occurred while loading the public key '" . $entry["ssh-key"] . "'.");
					if (!$rsa->loadKey($data2["privatekey"]))  CLI::DisplayError("An error occurred while loading the private key '" . $entry["ssh-key"] . "'.");

					$tempkeyfilename = $rootpath ."/cache/id_" . $entry["ssh-key"] . ".pem";
					file_put_contents($tempkeyfilename, $rsa->getPrivateKey(CRYPT_RSA_PRIVATE_FORMAT_PKCS1));

					$ssh .= " -i " . escapeshellarg($tempkeyfilename);
				}

				$ssh .= " -p " . (int)$entry["port"] . " " . escapeshellarg($entry["username"] . "@" . $entry["host"]);

				system($ssh);
				@unlink($rootpath . "/cache/ssh_config");

				if ($entry["method"] === "ssh-key")  @unlink($tempkeyfilename);
			}

			$result = array(
				"success" => true,
				"total" => microtime(true) - $ts
			);

			DisplayResult($result);
		}
		else
		{
			$ts = microtime(true);
			$connections = array();
			foreach ($data["chain"] as $num => $entry)
			{
				$ssh = new Net_SFTP($entry["host"], $entry["port"]);

				if ($suppressoutput)  $publickey = @$ssh->getServerPublicHostKey();
				else  $publickey = $ssh->getServerPublicHostKey();

				if (!$ssh->isConnected())  DisplayResult(array("success" => false, "error" => "An error occurred while connecting to the SSH host '" . $entry["host"] . ":" . $entry["port"] . "'.", "errorcode" => "connect_failed"));

				if (!isset($entry["server"]))
				{
					$rsa = new Crypt_RSA();
					$rsa->loadKey($publickey);

					$entry["server"] = array(
						"fingerprint" => $rsa->getPublicKeyFingerprint(),
						"bits" => $rsa->getSize(),
						"seen" => time(),
						"publickey" => $publickey
					);

					$data["chain"][$num] = $entry;

					file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
					chmod($filename, 0600);
				}

				if ($entry["server"]["publickey"] !== $publickey)
				{
					$rsa = new Crypt_RSA();
					$rsa->loadKey($publickey);

					CLI::DisplayError("The public key of '" . $entry["host"] . ":" . $entry["port"] . "' has been changed.  The currently saved server fingerprint is " . $entry["server"]["fingerprint"] . " while the returned server fingerprint is " . $rsa->getPublicKeyFingerprint() . ".  Connection terminated.  If you wish to connect to the server with the '" . $name . "' SSH/SFTP profile, you can clear the saved server public key with the command:  profile remove-server-keys " . $name);
				}

				if ($entry["method"] === "ssh-key")
				{
					$filename = $rootpath . "/ssh-keys/" . $entry["ssh-key"] . ".json";
					if (!file_exists($filename))  CLI::DisplayError("SSH key '" . $entry["ssh-key"] . "' does not exist.  Filename '" . $filename . "' does not exist.");
					$data2 = json_decode(file_get_contents($filename), true);

					$rsa = new Crypt_RSA();
					if (!$rsa->loadKey($data2["publickey"]))  CLI::DisplayError("An error occurred while loading the public key '" . $entry["ssh-key"] . "'.");
					if (!$rsa->loadKey($data2["privatekey"]))  CLI::DisplayError("An error occurred while loading the private key '" . $entry["ssh-key"] . "'.");

					if (!$ssh->login($entry["username"], $rsa))  DisplayResult(array("success" => false, "error" => "SSH login to '" . $entry["host"] . ":" . $entry["port"] . "' with RSA private key failed.", "errorcode" => "login_failed", "info" => $ssh->getErrors()));
				}
				else if ($entry["method"] === "password")
				{
					if (!$ssh->login($entry["username"], $entry["password"]))  DisplayResult(array("success" => false, "error" => "SSH login to '" . $entry["host"] . ":" . $entry["port"] . "' with password failed.", "errorcode" => "login_failed", "info" => $ssh->getErrors()));
				}

				$connections[] = $ssh;
			}
			$connectdiff = microtime(true) - $ts;

			if ($cmd === "test")  DisplayResult(array("success" => true, "connect" => $connectdiff));
			else if ($cmd === "run" || $cmd === "sequence")
			{
				$items = array();
				if ($cmd === "run")
				{
					do
					{
						$run = CLI::GetUserInputWithArgs($args, "run", (count($items) ? "Another command to run" : "Command to run"), (count($items) ? "" : false), "", $suppressoutput);
						if ($run !== "")
						{
							$error = CLI::GetUserInputWithArgs($args, "error", "Error string (optional)", "", "", $suppressoutput);

							$items[] = array("run" => $run, "error" => $error);
						}
					} while ($run !== "");
				}
				else
				{
					do
					{
						$filename = CLI::GetUserInputWithArgs($args, "file", "Filename containing commands to run", false, "", $suppressoutput);
						if (!file_exists($filename))  CLI::DisplayError("The file '" . $filename . "' does not exist.", false, false);
					} while (!file_exists($filename));

					$lines = explode("\n", file_get_contents($filename));
					for ($x = 0; $x < count($lines) - 1; $x += 2)
					{
						$items[] = array("run" => rtrim($lines[$x]), "error" => rtrim($lines[$x + 1]));
					}
				}

				$results = array();
				foreach ($items as $item)
				{
					$ts = microtime(true);

					$result = @$ssh->exec($item["run"]);
					if ($result === false)  DisplayResult(array("success" => false, "error" => "Sending the SSH command failed.", "errorcode" => "command_failed", "info" => array("command" => $item["run"], "ssh_errors" => $ssh->getErrors()), "results" => $results));
					if ($item["error"] !== "" && stripos($result, $item["error"]) !== false)  DisplayResult(array("success" => false, "error" => "SSH command returned a detected error condition.", "errorcode" => "requested_error_string_detected", "info" => $result, "results" => $results));

					$results[] = array("command" => $item["run"], "output" => $result, "time" => microtime(true) - $ts);
				}

				$result = array(
					"success" => true,
					"connect" => $connectdiff,
					"results" => $results
				);

				DisplayResult($result);
			}
			else if ($cmd === "shell-php")
			{
				$ts = microtime(true);
				do
				{
					$run = CLI::GetUserInputWithArgs($args, "run", "", false, "", $suppressoutput);

					$result = @$ssh->exec($run);
					if ($result === false)  CLI::DisplayError("Sending the SSH command failed:  " . $run . "\n\n" . implode("\n", $ssh->getErrors()), false, false);
					else  echo $result;
				} while ($run !== "exit" && $run !== "logout");

				$result = array(
					"success" => true,
					"connect" => $connectdiff,
					"main" => microtime(true) - $ts
				);

				DisplayResult($result);
			}
			else if ($cmd === "download")
			{
				$ssh->setListOrder("filename", SORT_ASC);

				do
				{
					$src = CLI::GetUserInputWithArgs($args, "src", "Directory or file to download", false, "", $suppressoutput);
					$src = str_replace("\\", "/", $src);
					while (substr($src, -1) === "/")  $src = substr($src, 0, -1);
					$info = @$ssh->stat($src);
					if ($info === false)  CLI::DisplayError("The path '" . $src . "' does not exist on the remote host.", false, false);
				} while ($info === false);

				if ($info["type"] === NET_SFTP_TYPE_DIRECTORY)
				{
					$path = $rootpath . "/cache/" . Str::FilenameSafe($name . "-" . Str::ExtractFilename($src) . "-" . date("Ymd"));

					do
					{
						$dest = CLI::GetUserInputWithArgs($args, "dest", "Destination directory", $path, "", $suppressoutput);
						$dest = str_replace("\\", "/", $dest);
						while (substr($dest, -1) === "/")  $dest = substr($dest, 0, -1);
						@mkdir($dest, 0777, true);
						$valid = is_dir($dest);
						if (!$valid)  CLI::DisplayError("Unable to create '" . $dest . "'.", false, false);
					} while (!$valid);

					$ts = microtime(true);
					$result = DownloadDirectory($ssh, $src, $dest);
					$result["connect"] = $connectdiff;
					$result["main"] = microtime(true) - $ts;

					DisplayResult($result);
				}
				else
				{
					$filename = @getcwd();
					if ($filename !== false)
					{
						$filename = str_replace("\\", "/", $filename);
						while (substr($filename, -1) === "/")  $filename = substr($filename, 0, -1);
					}
					if ($filename === false || $filename === $rootpath)  $filename = $rootpath . "/cache";
					$rootpath .= "/" . Str::FilenameSafe(Str::ExtractFilename($src));

					do
					{
						$dest = CLI::GetUserInputWithArgs($args, "dest", "Destination filename", $filename, "", $suppressoutput);
						$dest = str_replace("\\", "/", $dest);
						while (substr($dest, -1) === "/")  $dest = substr($dest, 0, -1);
						$valid = (!file_exists($dest) || is_file($dest));
						if (!$valid)  CLI::DisplayError("The destination '" . $dest . "' exists but is not a file.", false, false);
					} while (!$valid);

					$ts = microtime(true);
					$result = DownloadFile($ssh, $src, $dest, $info);
					$result["connect"] = $connectdiff;
					$result["main"] = microtime(true) - $ts;

					DisplayResult($result);
				}
			}
			else if ($cmd === "upload")
			{
				do
				{
					$src = CLI::GetUserInputWithArgs($args, "src", "Directory or file to upload", false, "", $suppressoutput);
					$src = str_replace("\\", "/", $src);
					while (substr($src, -1) === "/")  $src = substr($src, 0, -1);
					$info = @stat($src);
					if ($info === false)  CLI::DisplayError("The path '" . $src . "' does not exist.", false, false);
				} while ($info === false);

				if (is_dir($src))
				{
					do
					{
						$dest = CLI::GetUserInputWithArgs($args, "dest", "Destination remote directory", false, "", $suppressoutput);
						$dest = str_replace("\\", "/", $dest);
						while (substr($dest, -1) === "/")  $dest = substr($dest, 0, -1);
						@$ssh->mkdir($dest, -1, true);
						$valid = $ssh->is_dir($dest);
						if (!$valid)  CLI::DisplayError("Unable to create '" . $dest . "'.", false, false);
					} while (!$valid);

					$ts = microtime(true);
					$result = UploadDirectory($ssh, $src, $dest);
					$result["connect"] = $connectdiff;
					$result["main"] = microtime(true) - $ts;

					DisplayResult($result);
				}
				else
				{
					$filename = $ssh->pwd();
					$filename = str_replace("\\", "/", $filename);
					while (substr($filename, -1) === "/")  $filename = substr($filename, 0, -1);
					$filename .= "/" . Str::ExtractFilename($src);

					do
					{
						$dest = CLI::GetUserInputWithArgs($args, "dest", "Destination filename", $filename, "", $suppressoutput);
						$dest = str_replace("\\", "/", $dest);
						while (substr($dest, -1) === "/")  $dest = substr($dest, 0, -1);
						$valid = (!file_exists($dest) || is_file($dest));
						if (!$valid)  CLI::DisplayError("The destination '" . $dest . "' exists but is not a file.", false, false);
					} while (!$valid);

					$ts = microtime(true);
					$result = UploadFile($ssh, $src, $dest, $info);
					$result["connect"] = $connectdiff;
					$result["main"] = microtime(true) - $ts;

					DisplayResult($result);
				}
			}
		}
	}
?>