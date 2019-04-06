<?php
	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/cli.php";

	// Check enabled extensions.
	if (!extension_loaded("openssl"))  CLI::DisplayError("The 'openssl' PHP module is not enabled.  Please update the file '" . (php_ini_loaded_file() !== false ? php_ini_loaded_file() : "php.ini") . "' to enable the module.");

	require_once $rootpath . "/support/phpseclib/Crypt/RSA.php";
	require_once $rootpath . "/support/phpseclib/Math/BigInteger.php";
	require_once $rootpath . "/support/phpseclib/Net/SSH2.php";
	require_once $rootpath . "/support/phpseclib/Net/PatchedSSH2.php";
	require_once $rootpath . "/support/phpseclib/Net/AsyncSSH2.php";

	$path = get_include_path();
	if (strpos($path, PATH_SEPARATOR . $rootpath . "/support/phpseclib/") === false)  set_include_path($path . PATH_SEPARATOR . $rootpath . "/support/phpseclib/");

	$ssh = new Async_Net_SSH2($argv[1], 22);

	$publickey = $ssh->getServerPublicHostKey();

	$rsa = new Crypt_RSA();
	$rsa->loadKey($publickey);

	echo $rsa->getPublicKeyFingerprint() . "\n";

	$filename = $rootpath . "/ssh-keys/" . $argv[2] . ".json";
	$data2 = json_decode(file_get_contents($filename), true);

	$rsa = new Crypt_RSA();
	if (!$rsa->loadKey($data2["publickey"]))  CLI::DisplayError("An error occurred while loading the public key '" . $argv[2] . "'.");
	if (!$rsa->loadKey($data2["privatekey"]))  CLI::DisplayError("An error occurred while loading the private key '" . $argv[2] . "'.");

	if (!$ssh->login($argv[3], $rsa))  CLI::DisplayError("SSH login to '" . $argv[1] . ":22' with RSA private key failed.", array("success" =>false, "error" => "See error above.", "errorcode" => "login_failed", "info" => $ssh->getErrors()));

	$ssh->setTerminal("xterm");

	// Run a process that takes a while to complete (e.g. sleep).
	$ssh->startShell();
	$ssh->setBlocking(false);

	var_dump($ssh->write("sleep 30\n"));

	$startts = time();
	$lastwints = time();
	do
	{
		$timeout = 3;
		$readfps = array($ssh->getStream());
		$writefps = array();
		if ($ssh->wantWrite())  $writefps[] = $ssh->getStream();
		$exceptfps = NULL;
		stream_select($readfps, $writefps, $exceptfps, $timeout);
		echo "[SSH]\n";

		$ssh->sendWrite();

		// Clear the read buffer.
		do
		{
			$result = $ssh->readAsync();
			if (is_string($result))  echo $result;
			else if (feof($ssh->getStream()))  $ssh->disconnect();
		} while (is_string($result));

		// Update the window size every few seconds.
		if ($lastwints < time() - 5)
		{
			echo "[WIN]\n";
			$ssh->setWindowSize(mt_rand(80, 100), mt_rand(25, 50));

			$lastwints = time();
		}

		if ($startts < time() - 60)
		{
			$ssh->write("exit\n");
			$startts = time();
		}
	} while ($ssh->hasShell());
?>