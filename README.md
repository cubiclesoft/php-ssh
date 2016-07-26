PHP SSH Tools
=============

Manage SSH keys and connection profiles, and connect to SSH and SFTP servers with a 100% pure PHP-based command-line all-in-one solution.  MIT or LGPL.

Features
--------

* Create/generate, import, and export SSH keys.
* Manage SSH connection profiles.
* Use SSH connection profiles to connect to SSH/SFTP servers to run commands as well as upload and download files and directories.
* Can use the built-in PHP-based shell (not very good) or a system SSH shell.
* No external tools required!  Just PHP with the OpenSSL extension.
* A complete, question/answer enabled command-line interface.
* Has a liberal open source license.  MIT or LGPL, your choice.
* Designed for relatively painless integration into your project.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

Getting Started
---------------

The command-line interface is question/answer enabled, which means all you have to do is run:

````
php ssh.php
````

Which will enter interactive mode and guide you through the entire process.

Once you grow tired of manually entering information, you can pass in some or all the answers to the questions on the command-line:

````
php ssh.php keys list

php ssh.php keys create

php ssh.php -s keys create name=www.domain.com bits=4096
````

The -s option suppresses normal output (except for fatal error conditions), which allows for the processed JSON result to be the only thing that is output.

System SSH Support
------------------

Even though there is built-in SSH support, some people might prefer using their system's included SSH client.  To do that:

````
php ssh.php connect shell-system
````

'ssh' must be on the path.  If you run Windows, you can run either of these commands from the same directory as 'ssh.php':

````
git clone https://github.com/cubiclesoft/ssh-win64.git

git clone https://github.com/cubiclesoft/ssh-win32.git
````

To get a self-contained 'ssh.exe' binary so that 'shell-system' works.

Known Issues
------------

Under the hood of this tool is the mostly excellent [phpseclib](https://github.com/phpseclib/phpseclib) library.  The library is the swiss army knife of crypto libraries for PHP and includes a not quite complete SSH 2 implementation.  SSH/SFTP are complex protocols (RFC4251, RFC4252, RFC4253, RFC4254, draft-ietf-secsh-filexfer-13).  The following is a list of known issues regarding SSH/SFTP connections:

* With the exception of 'shell-system', every command is effectively run as a new session.  This means that full paths and filenames must be used at all times for most commands.  'cd /var/www' followed by 'ls -la' will result in displaying the user's home directory, not '/var/www' - the session basically resets between the 'cd' and 'ls' commands.
* With the exception of 'shell-system', there is no TTY, which means that commands requiring user input will not work at all.  This tool is intended to be used for automation purposes anyway.
* The Windows SSH binaries mentioned in the previous section don't display prompts like you might expect under a normal Command Prompt.  They also won't transform terminal commands (e.g. ANSI color sequences), which might make it difficult to read the output.
* SSH port forwarding (aka SSH tunneling) is currently not possible.  phpseclib does not implement section 7 of RFC4254 ("TCP/IP Port Forwarding").  phpseclib also does not implement non-blocking socket support.  This tool has the plumbing built for forming SSH chains, but since phpseclib doesn't implement the necessary bits, the code ignores and assumes a single host.
* When the tool detects that a host SSH public key is different from the previous connection attempt, it will immediately terminate the requested operation for security reasons.  Using DNS names instead of an IP address to connect to a host is strongly discouraged.
* Downloaded files over SFTP have their filenames processed through a very strict filter (Str::FilenameSafe()) that only allows directories and filenames to consist of a very limited character set for both security and laziness reasons.  This means that files with spaces, oddball characters, and Unicode characters will get renamed.  Some OSes, such as Windows, also can't handle filenames that only differentiate by case.  There's not a particularly good way to deal with the various nuances across OSes without a lot of extra code.  If you name your files and directories using a limited character set (0-9, a-z, -, _, and .) for maximum portability across platforms, there won't be any issues here.
