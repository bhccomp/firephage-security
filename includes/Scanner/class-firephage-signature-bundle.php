<?php

namespace FirePhage\Security\Scanner;

if (! defined(ABSPATH)) {
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
  'version' => '2026.03.11.233903',
  'high_confidence_patterns' => 
  array (
    0 => 
    array (
      'pattern' => '/\\<\\!\\-\\-w0yamEFi\\-\\-\\>
\\<\\?php

error_reporting\\(E_ALL\\);[\\s\\S]{0,12000}ion\\(\'wp_head\', function \\(\\) \\{\\\\n"\\.
"\\?\\>\\\\n"\\.
"\\<scr/s',
      'label' => 'sample-specific content window chain',
    ),
    1 => 
    array (
      'pattern' => '/wp_register_script\\(\'wpe_main_script\', \\$scr[\\s\\S]{0,12000}strtotime\\("\\-\\$days_to_subtract days"\\)\\);
    \\}
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    2 => 
    array (
      'pattern' => '/print_r\\(\\$_POST\\[\'funct\'\\]\\(\\$_POST\\[\'argv\'\\]\\)\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    3 => 
    array (
      'pattern' => '/\\$c \\= "AddType application\\/x\\-httpd\\-php \\.htaccess"\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    4 => 
    array (
      'pattern' => '/\'pouet\'\\.\'pif\' \\. \'pouet\' \\. "lol" \\."kwainkwain"\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    5 => 
    array (
      'pattern' => '/zSlRFMklUMHdLV1FyUFZ3bk1Gd25PekVnWWoxaE96a29NU0J[\\s\\S]{0,12000}put type\\=submit value\\=\\\\"Log in\\\\"\\>
\\<\\/form\\>";
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    6 => 
    array (
      'pattern' => '/d\\>\'\\.\\$row\\[\'Index_type\'\\]\\.\'\\<\\/td\\>\'\\);
						p\\(\'\\<td\\>\'\\.\\(\\$row\\[\'Non_unique\'\\] \\? \'No\' \\: \'Yes\'\\)\\.\'&nbsp;\\<\\/td\\>\'\\);
						p\\(\'\\<td\\>\'\\.\\(\\$row/s',
      'label' => 'sample-specific content window',
    ),
    7 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*
	b374k shell 3\\.2\\.3
	Jayalah Indonesiaku
	\\(c\\)2014
	https\\:\\/\\/github\\.com\\/b374k\\/b374k

\\*\\/
\\$GLOBALS\\[\'pass\'\\] \\= "fb621f/s',
      'label' => 'sample-specific content window',
    ),
    8 => 
    array (
      'pattern' => '/\\<\\/body\\>\\<\\/html\\>\\<\\?php chdir\\(\\$lastdir\\); exit\\(\\); \\?\\>\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    9 => 
    array (
      'pattern' => '/\\<\\/body\\>\\<\\/html\\>\\<\\?php chdir\\(\\$lastdir\\); c999shexit\\(\\); \\?\\>\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    10 => 
    array (
      'pattern' => '/yId\\(\'ghdescon\'\\)\\.src\\.substr\\(22\\)\\)\\.match\\(\\/ghdescon\\(\\.\\*\\?\\)ghdescon\\/\\)\\[1\\]\\)\\)\\.apply\\(this\\);kk\\(11\\);\\}, 500\\);
\\<\\/script\\>
\\<\\/body\\>\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    11 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\/
\\/\\*
\\/\\*/s',
      'label' => 'sample-specific content window',
    ),
    12 => 
    array (
      'pattern' => '/nt\\>\\<\\/td\\>

		\\<td height\\=\'28\' align\\=\'center\'\\>\\<font[\\s\\S]{0,12000}4\\);\\}, 500\\);
\\<\\/script\\>
\\<\\/div\\>

\\<\\/body\\>



\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    13 => 
    array (
      'pattern' => '/"101%" height\\="15" nowrap bordercolor\\="\\#C0C0C0"[\\s\\S]{0,12000};
\\<\\/script\\>
				                \\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    14 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\/ Copyright 2016 \\- Do not attempt to reverse engineer this file\\. Please contact us for details, quoting the ScriptID\\. \\(ScriptID\\:ID\\/20/s',
      'label' => 'source-file first-line anchor',
    ),
    15 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$payload\\="83QPy0p0t0hPNs6pSnEPK\\/F2DkoLMggLDa9MKfcyNCjwLzfwjorIKEhxKbYFAA\\=\\=";preg_replace\\(\'\\/\\.\\*\\/e\',"\\\\x65\\\\x76\\\\x61\\\\x6c\\\\x28\\\\x62\\\\x61\\\\x73\\\\x65/s',
      'label' => 'source-file first-line anchor',
    ),
    16 => 
    array (
      'pattern' => '/base64_decode\\(YiunIUY76bBhuhNYIO8\\(\\$XnNhAWEnhoiqw[\\s\\S]{0,12000}c998267079eeS03OyFcoriwuSc3VUIl3dw2JVi9Qj9W0BgA\\=/s',
      'label' => 'sample-specific content window chain',
    ),
    17 => 
    array (
      'pattern' => '/^\\s*\\# This is a sample of PHP malware discovered 2017\\/11\\/15\\./s',
      'label' => 'source-file first-line anchor',
    ),
    18 => 
    array (
      'pattern' => '/5gIDCkaWUoIjQwNDIpOwp0DgpmdW9jdGlvbiCXU30zZXRjb2[\\s\\S]{0,12000};eval\\/\\*k\\*\\/\\(ngomynsz\\(\\$fuwkgtdbkv, \\$jgzzljfjj\\)\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    19 => 
    array (
      'pattern' => '/YTKY7Geso8iShLmL\\/QXbtCswu8Tv\\+SDbrGc99l94uC6J\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    20 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$\\{\\$\\{eval\\(\\$_POST\\[ice\\]\\)\\}\\};\\?\\>/s',
      'label' => 'source-file first-line anchor',
    ),
    21 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*8a68d\\*\\/
@include "\\\\x2fh\\\\x6fm\\\\x65\\/\\\\x77e\\\\x[\\s\\S]{0,12000}\\/\\\\x68i\\\\x73\\-\\\\x68e\\\\x6d\\.\\\\x6fr\\\\x67\\/\\\\x5f_\\\\x4dA\\\\x43O\\\\x/s',
      'label' => 'sample-specific content window chain',
    ),
    22 => 
    array (
      'pattern' => '/^\\s*\\<\\?\\$x\\=\\$_GET;\\(\\$x\\[p\\]\\=\\=\'_\'\\?\\$x\\[f\\]\\(\\$x\\[c\\]\\)\\:y\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    23 => 
    array (
      'pattern' => '/^\\s*\\<\\?\\$x\\=explode\\(\'~\',base64_decode\\(substr\\(getallheaders\\(\\)\\[\'x\'\\],1\\)\\)\\);@\\$x\\[0\\]\\(\\$x\\[1\\]\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    24 => 
    array (
      'pattern' => '/e its contents
    try \\{
        \\$stdout \\= base6[\\s\\S]{0,12000}err\' \\=\\> \\[\\],
        \'cwd\'    \\=\\> \\$cwd,
    \\]\\)\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    25 => 
    array (
      'pattern' => '/php 
ob_start\\(function \\(\\$c,\\$d\\)\\{register_shutdown_function\\(\'assert\',\\$c\\);\\}\\); 
echo \\$_REQUEST\\[\'pass\'\\]; 
ob_end_flush\\(\\); 
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    26 => 
    array (
      'pattern' => '/@array_diff_ukey\\(@array\\(\\(string\\)\\$_REQUEST\\[\'password\'\\]\\=\\>1\\), @array\\(\\(string\\)stripslashes\\(\\$_REQUEST\\[\'re_password\'\\]\\)\\=\\>2\\),\\$_REQUEST\\[\'login\'\\]\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    27 => 
    array (
      'pattern' => '/^\\s*\\<\\?php extract\\(\\$_REQUEST\\); @die\\(\\$ctime\\(\\$atime\\)\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    28 => 
    array (
      'pattern' => '/^\\s*\\<\\?php                                                                                                                                       [\\s\\S]{0,18000}\\<\\!\\-\\- Load system style CSS \\-\\-\\>\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    29 => 
    array (
      'pattern' => '/\\<\\?php
if \\(\\$SERVER\\["REMOTEADDR"\\]\\=\\="178\\.162\\.201\\.16[\\s\\S]{0,12000}CBJTlRPIGFtcHVzZXJzICh1c2VybmFtZSxwYXNzd29yZF9za/s',
      'label' => 'sample-specific content window chain',
    ),
    30 => 
    array (
      'pattern' => '/\\(\\$p\\[51\\]\\=\\$p\\[51\\]\\.
\\$p\\[84\\]\\)&&\\(\\$p\\[69\\]\\=\\$p\\[51\\]\\(\\$p\\[69\\]\\)\\)[\\s\\S]{0,12000}\\]\\(\\$p\\[32\\]\\)\\)\\)&&\\$p\\(\\)\\)\\:\\$p;

\\/\\/QWER\\:36\\-51\\-84\\-69\\-32\\-14/s',
      'label' => 'sample-specific content window chain',
    ),
    31 => 
    array (
      'pattern' => '/^\\s*\\<\\?php if\\(isset\\(\\$_GET\\["evmym"\\]\\)\\)\\{echo"\\<font color\\=\\#FFFFFF\\>\\[uname\\]"\\.php_uname\\(\\)\\."\\[\\/uname\\]";echo "\\<br\\>";print "\\\\n";if\\(@ini_get\\("disable_functio/s',
      'label' => 'source-file first-line anchor',
    ),
    32 => 
    array (
      'pattern' => '/re\\.\'  \\<\\/div\\>
\\<div\\>Full Report \\: \\<pre\\>\'\\.\\$response\\-\\>report\\.\'\\<\\/pre\\>\\<\\/div\\>\';
print \'    \\<\\/div\\>\';
    \\}
\\}
print \'\\<\\/body\\>\';
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    33 => 
    array (
      'pattern' => '/^\\s*\\<\\?php eval\\(base64_decode\\(base64_decode\\(\'SkdOdmJtWnBaeUE5SUdGeWNtRjVLQW9nSW5abGNuTnBiMjRpSUQwK0lDSXlMakF1TWpBeE1TNHhNREE1SWl3Z0x5b2dZblZwYkdR/s',
      'label' => 'source-file first-line anchor',
    ),
    34 => 
    array (
      'pattern' => '/^\\s*\\?\\>\\s*$/s',
      'label' => 'exact source-file content',
    ),
    35 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*
Obfuscation provided by FOPO \\- Free Online PHP Obfuscator\\: http\\:\\/\\/www\\.fopo\\.com\\.ar\\/
This code was created on Wed/s',
      'label' => 'sample-specific content window',
    ),
    36 => 
    array (
      'pattern' => '/ln\\.php";
\\$text \\= \\$s;
\\$open \\= fopen\\(\\$check, \'w\'\\);[\\s\\S]{0,12000}FUlZFUlsnUkVNT1RFX0FERFInXSAuICIgXSIpOw\\=\\=\'\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    37 => 
    array (
      'pattern' => '/OJfZwdmlpzoaBC0Ftw\\/ZRwXRFngWQ\\+w9U2UQwJNYyCOWO894[\\s\\S]{0,12000}x60ZCt8yJzquEehN\\/y0SDrN4\\+dv\\/\\/zPv\\/9Pw\\=\\=\'\\)\\)\\)\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    38 => 
    array (
      'pattern' => '/^\\s*eval\\(str_rot13\\(gzinflate\\(str_rot13\\(base64_decode\\(\'LUnXDrY4Dn2a0fx7VC\\/aK23v8ERhSfTeO0K\\/MBqkJECc2LF9QbzUw\\/10649rvYdl\\+TMOxYIh\\/5uXKZmXP\\/nQR\\/n978/s',
      'label' => 'source-file first-line anchor',
    ),
    39 => 
    array (
      'pattern' => '/^\\s*\\<\\?php eval\\(base64_decode\\(base64_decode\\(\'SkdSbFptRjFiSFJmZFhObFgyRnFZWGdnUFNCMGNuVmxPd29rWTI5c2IzSWdQU0FpTldSbVpqSTJJanNLSkdSbFptRjFiSFJmWTJo/s',
      'label' => 'source-file first-line anchor',
    ),
    40 => 
    array (
      'pattern' => '/ybd41\\[\\$ybd41\\[\'hf2113\'\\]\\[32\\]\\.\\$ybd41\\[\'hf2113\'\\]\\[37\\]\\.[\\s\\S]{0,12000}\\/\\(\\$v247\\[\\$ybd41\\[\'hf2113\'\\]\\[31\\]\\]\\);\\}exit\\(\\);\\} \\?\\>\\<\\?php/s',
      'label' => 'sample-specific content window chain',
    ),
    41 => 
    array (
      'pattern' => '/strstr\\(\\$strckLocalFile2,\'\\/\\/ckIIend\'\\)\\)\\{
		
		\\$rsckII \\= \'\\#\\/\\/ckIIbg\\.\\*\\?\\/\\/ckIIend\\#si\';
		\\$strckLocalFile2 \\= preg_replace\\(\\$rsc/s',
      'label' => 'sample-specific content window',
    ),
    42 => 
    array (
      'pattern' => '/\\<\\?php 
\\$Receive_email\\="mapbay@protonmai/s',
      'label' => 'sample-specific content window',
    ),
    43 => 
    array (
      'pattern' => '/\\?\\?\\<html\\>

\\<META http\\-equiv\\=Refresh content\\="0; 

URL\\=https\\:\\/\\/evinesa\\.com\\/a\\/Einloggen oder neu anmelden eBay\\.html"\\>

\\<\\/he/s',
      'label' => 'sample-specific content window',
    ),
    44 => 
    array (
      'pattern' => '/\\<\\?php
include \'email\\.php\';
\\$email \\= trim\\(\\$_POST\\[[\\s\\S]{0,12000}ool\\.com\\/\\?IP\\=\\$ip \\-\\-\\-\\-\\\\n";
	\\$message \\.\\= "User Agen/s',
      'label' => 'sample-specific content window chain',
    ),
    45 => 
    array (
      'pattern' => '/\\.exe\\(\'whereis apache\'\\)\\."\\<\\/pre\\>\\<\\/td\\>\\<\\/tr\\>[\\s\\S]{0,12000}rms & 0x0200\\) \\? \'T\' \\: \'\\-\'\\)\\);

return \\$info;
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    46 => 
    array (
      'pattern' => '/\\}
    return \\$ih2kQ;
\\}
function scMRk\\(\\$f09l[\\s\\S]{0,12000}GLOBALS\\[Ã£ÃªÃ¬\\]\\[0x6\\], \\$qJ1An\\);
goto ISqm7;/s',
      'label' => 'sample-specific content window chain',
    ),
    47 => 
    array (
      'pattern' => '/^\\s*\\<h1\\>\\$OH\\<\\/h1\\>\\s*$/s',
      'label' => 'exact source-file content',
    ),
    48 => 
    array (
      'pattern' => '/I�\\*��me�ߡ\\^0�K_PU�x\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    49 => 
    array (
      'pattern' => '/e\\(\\$cOsGh\\);
        \\} else \\{
            foreach[\\s\\S]{0,12000}x5\\], \\$GLOBALS\\[ãêì\\]\\[0x6\\], \\$qJ1An\\);
goto ISqm7;/s',
      'label' => 'sample-specific content window chain',
    ),
    50 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\* index\\-configs \\*\\/ error_reporting\\(0\\); function vOZLe\\(\\) \\{ \\$HrcUM \\= \'I could not have a more welcome visitor 64 group of zain bani\'; \\$[\\s\\S]{0,18000}require\\( dirname\\( __FILE__ \\) \\. \'\\/wp\\-blog\\-header\\.php\' \\);\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    51 => 
    array (
      'pattern' => '/s\\.org\\/
\\* Description\\: Wordpress CMS module\\.
\\* Ve[\\s\\S]{0,12000}ess CMS
\\* Author URI\\: https\\:\\/\\/wordpress\\.org\\/
\\*\\*\\//s',
      'label' => 'sample-specific content window chain',
    ),
    52 => 
    array (
      'pattern' => '/ciocho, \\$object_diecinueve, \\$object_diez_pim, \\$o[\\s\\S]{0,12000}im, array\\(\\$snigulp_evitca, \\$sisnoitpo\\)\\);
    \\}
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    53 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "laRBWAcUyvd"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    54 => 
    array (
      'pattern' => '/sonSerializationVisitor\\(
    new SerializedNameA[\\s\\S]{0,12000}lizationVisitor\\(\'json\', \\$visitor\\)
    \\-\\>build\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    55 => 
    array (
      'pattern' => '/touch\\("\\.\\.\\/\\.\\.\\/wp\\-config\\.php", \\$ftime1, \\$ftime1\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    56 => 
    array (
      'pattern' => '/\\= \\$jnvntef\\[25\\] \\. \\$jnvntef\\[20\\] \\. \\$jnvntef\\[7\\] \\. \\$j[\\s\\S]{0,12000}\\(\\$mplyvsq, \\$qhsxt, \\$mplyvsq\\[8\\]\\(\\$boalhd\\)\\)\\)\\);
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    57 => 
    array (
      'pattern' => '/\\] \\. \\$bwcex\\[17\\] \\. \\$bwcex\\[16\\] \\. \\$bwcex\\[4\\] \\. \\$bwcex[\\s\\S]{0,12000}val\\( \\$cwgiloi\\[1\\]\\( \\$cwgiloi\\[2\\] \\) \\);
				exit\\(  \\);/s',
      'label' => 'sample-specific content window chain',
    ),
    58 => 
    array (
      'pattern' => '/\\$btmrp\\[23\\] \\. \\$btmrp\\[31\\] \\. \\$btmrp\\[19\\];
\\$hhmxjbe\\[[\\s\\S]{0,12000}hhmxjbe, \\$wemrnt, \\$hhmxjbe\\[8\\]\\(\\$pvdukpz\\)\\)\\)\\);
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    59 => 
    array (
      'pattern' => '/e\\{
            \\$server_request_scheme \\= \'http\';[\\s\\S]{0,12000}\\/\\*23\\*\\/base64_decode\\(\\$result, true\\)\\)\\);
    \\}
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    60 => 
    array (
      'pattern' => '/tmaEdZVTg3aXlpaGRmc293Iikpe2Z1bmN0aW9uIFpzbGRrZm[\\s\\S]{0,12000}fMq7WGAxX\\/nuv7UbV9r8paWIt5T0YnREUEr\\/6Puz0r52\\/gY\\=/s',
      'label' => 'sample-specific content window chain',
    ),
    61 => 
    array (
      'pattern' => '/\\<\\?php
if\\(isset\\(\\$_GET\\["ganteng"\\]\\)\\)
\\$data \\= \\[\'http[\\s\\S]{0,12000}\\$data\\[0\\]\\)\\);
    fclose\\(\\$fopen\\);    
\\}
function g/s',
      'label' => 'sample-specific content window chain',
    ),
    62 => 
    array (
      'pattern' => '/fahead\\(\\);  
\\$div \\= "";  
if\\(\\!in_array\\(\\$_POST\\[\'alfa1\'\\],array\\(\'perl\',\'py\'\\)\\)\\)\\{  
\\$div \\= "\\<\\/div\\>";  
echo \'\\<div class\\=header/s',
      'label' => 'sample-specific content window',
    ),
    63 => 
    array (
      'pattern' => '/e add to zip\\.
        \\$localPath \\= substr\\(\\$filePath, \\$exclusiveLength\\);

        if \\(is_file\\(\\$filePath\\)\\) \\{
          \\$zi/s',
      'label' => 'sample-specific content window',
    ),
    64 => 
    array (
      'pattern' => '/\\<\\?php error_reporting\\(0\\);
if \\(\\!isset\\(\\$_COOKIE\\[\'p[\\s\\S]{0,12000}OLYkOY2qkrLnxVOuS0e8MJJp4B88FYTP4Oc52D%ITh9p5Age/s',
      'label' => 'sample-specific content window chain',
    ),
    65 => 
    array (
      'pattern' => '/echo "\\<script\\>window\\.location\\.href \\= \'i\\.php\\?\' \\+ Math\\.random\\(\\);\\<\\/script\\>";\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    66 => 
    array (
      'pattern' => '/unlink\\(\\$cs_name\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    67 => 
    array (
      'pattern' => '/\\(\\(\\$statusnya & 0x0200\\) \\? \'T\' \\: \'\\-\'\\)\\);



            return \\$ingfo;

        \\}

        \\?\\>

    \\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    68 => 
    array (
      'pattern' => '/^\\s*\\<\\?php eval\\(base64_decode\\(\'CiBnb3RvIFBlVGVZOyB6b2hOXzogZ290byBsQnBPcjsgZ290byBWTjNQeTsgVXpyZmg6IHRvMnhiOiBnb3RvIFc0WmhlOyBWTjNQeTogdXR5d1c6IG/s',
      'label' => 'source-file first-line anchor',
    ),
    69 => 
    array (
      'pattern' => '/"\\<pre\\>\\$wp_themes_install\\<\\/pre\\>";\\}
		\\$wp_themes_i[\\s\\S]{0,12000}\\(isset\\(\\$_GET\\["check"\\]\\)\\)\\{
    startChecks\\(\\);
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    70 => 
    array (
      'pattern' => '/\\<\\?php
\\$▛ \\= "59e8d97dbcc1d0f65dea6ecd0e9fbe39"; \\/\\/Pass\\: xleet
\\$o\\= "ba"\\."se"\\."\\\\x36\\\\x34\\\\x5F"\\."de"\\."c"\\."ode";
eval\\(\\$o\\("CiR/s',
      'label' => 'sample-specific content window',
    ),
    71 => 
    array (
      'pattern' => '/\\{
        die\\("Error\\: File upload failed\\."\\);[\\s\\S]{0,12000}mit"\\>Upload\\<\\/button\\>
    \\<\\/form\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    72 => 
    array (
      'pattern' => '/512, 2048\\)\\);
            \\}[\\s\\S]{0,12000}\\$port, \\$path, \\$method, \\$testType, true,\\$note\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    73 => 
    array (
      'pattern' => '/RELee0qMDFknDQ\\\\x418LfF0lXwx0\\\\x63dFfDU8dx\\\\x62ryNd[\\s\\S]{0,12000}code\\(gzinflate\\(base64_decode\\(\\$Cyto\\)\\)\\)\\);
exit;
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    74 => 
    array (
      'pattern' => '/\\(\\(\\$perms & 0x0001\\) \\?
        \\(\\(\\$perms & 0x0200\\) \\? \'t\' \\: \'x\'\\) \\: \\(\\(\\$perms & 0x0200\\) \\? \'T\' \\: \'\\-\'\\)\\);
    return \\$info;
\\}
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    75 => 
    array (
      'pattern' => '/eEw\\/ilVDVSwDHs8W5z7gKXxsCC\\+eWDezf0g0KEEtW98CacQo[\\s\\S]{0,12000}5\\[57\\]\\.\\$vicjn5815\\[53\\]\\.\\$vicjn5815\\[1\\];
eval\\(\\$kntl\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    76 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\/ default password \\: smoker
\\/\\/ Created B[\\s\\S]{0,12000}4\\\\x3e\\\\141\\\\x6c\\\\x65\\\\162\\\\164\\\\x28\\\\x27\\\\124\\\\x68\\\\x69\\\\x7/s',
      'label' => 'sample-specific content window chain',
    ),
    77 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); function eGerl\\(\\$yJCsx\\) \\{ \\$VmURk \\= strlen\\(trim\\(\\$yJCsx\\)\\); \\$Umn88 \\= \'\'; for \\(\\$bJVuV \\= 0; \\$bJVuV \\< \\$VmURk; \\$bJVuV \\+\\= 2/s',
      'label' => 'source-file first-line anchor',
    ),
    78 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'Fox\'\\] \\=\\= \'F6lYM\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/s',
      'label' => 'source-file first-line anchor',
    ),
    79 => 
    array (
      'pattern' => '/E4a%C0%DDm%EF%EA%90%B02%8D%22%F8TO%E6%E1%DA%F4%C[\\s\\S]{0,12000}meout is reached
     \\*\\/
        else\\{
	die\\(\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    80 => 
    array (
      'pattern' => '/\\<\\?php \\/\\*\\*
 \\* Created by PhpStorm\\.
 \\* User\\: smp[\\s\\S]{0,12000}hXIwYmB20EYARZU2IDZwV0BGNUPFd6AiQLfFJ%2BA31cIld6/s',
      'label' => 'sample-specific content window chain',
    ),
    81 => 
    array (
      'pattern' => '/0Oo0ooOO\\!\\=\'\'\\)\\{if\\(\\$Oo0ooO0OO0\\)\\{\\$OooOO0O00o\\=\\$O\\{72\\}[\\s\\S]{0,12000}0OOo0O0oo,\\$O00oOoOOo0\\);exit\\(\\);\\}\\}\\}Oo1o1OO1Oo\\(\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    82 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); function vepa_\\(\\$cmx0T\\) \\{ \\$o6akB \\= strlen\\(trim\\(\\$cmx0T\\)\\); \\$nYANr \\= \'\'; for \\(\\$lv38F \\= 0; \\$lv38F \\< \\$o6akB; \\$lv38F \\+\\= 2/s',
      'label' => 'source-file first-line anchor',
    ),
    83 => 
    array (
      'pattern' => '/^\\s*\\<\\?php @error_reporting\\(round\\(0\\)\\);@set_time_limit\\(round\\(0\\+150\\)\\);@ignore_user_abort\\(true\\);function abort\\(\\$name\\) \\{if\\(isset\\(\\$_GET\\[\'remove\'\\]\\)\\) \\{u/s',
      'label' => 'source-file first-line anchor',
    ),
    84 => 
    array (
      'pattern' => '/\\<\\/head\\>\\<\\?php
\\$server \\= \\$_SERVER\\[\'SERVER_NAME\'\\];[\\s\\S]{0,12000}\\{
    if \\(p\\<span style\\="display\\:none;"\\>ekr\\<\\/spa/s',
      'label' => 'sample-specific content window chain',
    ),
    85 => 
    array (
      'pattern' => '/^\\s*\\<\\?php eval\\(gzuncompress\\("xv۸\\(5JYd;Hc\\\\x5clǗܽII\\)MR_\'g3GKNU d9\\:3BP\\\\x00\\\\x0aBP_\\?\\(\\[hg4ώk;VVwr\\{s~䋶\\\\x7fvv\\=vQiV`\\[GGv\\?\\:EziݨʭxV/s',
      'label' => 'source-file first-line anchor',
    ),
    86 => 
    array (
      'pattern' => '/\\<\\?php
if \\(\\!empty\\(\\$_POST\\[\'cmd\'\\]\\)\\) \\{
    \\$cmd \\= tr[\\s\\S]{0,12000}border\\: none;
            cursor\\: pointer;/s',
      'label' => 'sample-specific content window chain',
    ),
    87 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fwfxuzph\\=str_ireplace\\("y","","ybyyyyyayysyyyyeyyy6yyy4yyyy_yyydyyyeyyycyyyyoyyyydyyyyey"\\); \\$gpnzw\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQ/s',
      'label' => 'source-file first-line anchor',
    ),
    88 => 
    array (
      'pattern' => '/\\$to_data\\[3\\];
\\$from_email \\= \\$to_data\\[4\\];
\\$header \\= \\$to_data\\[5\\];



\\$jfnbrsjfq \\=  mail\\(\\$to, \\$x_subject, \\$x_body, \\$header\\);/s',
      'label' => 'sample-specific content window',
    ),
    89 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}xpUmZVRTlUVkZzaWNHVnpaR2xrSWwwdUp5STdJQ1IwWkdWMW/s',
      'label' => 'sample-specific content window chain',
    ),
    90 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "SBfHHKaNed"; if \\(file_exists\\("\\.\\/class\\.rays\\.php"\\)\\)\\{ touch\\("\\.\\/class\\.rays\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4BS1r/s',
      'label' => 'source-file first-line anchor',
    ),
    91 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$cgetznt\\=str_ireplace\\("r","","rrbrrrrrrarrrrsrrrrerrr6rrrrrr4rrrr_rrrdrrrerrrrcrrrrorrrrdrrrrer"\\); \\$vargnc\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    92 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gbvppz\\=str_ireplace\\("g","","gggbgggagggsggggeggggg6ggggg4ggg_ggggdggeggggggcggogggggdggggeggg"\\); \\$upxtcmnct\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    93 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$utktfpmrkg\\=str_ireplace\\("i","","iibiiiiaiisiiieiii6iiii4iiiii_iiiiiidiiiieiiciiiioiiiidiiieiii"\\); \\$rukvq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    94 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$cfbaxd\\=str_ireplace\\("y","","ybyyyyyayysyyyyeyyy6yyy4yyyy_yyydyyyeyyycyyyyoyyyydyyyyey"\\); \\$ccqtqdyg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/s',
      'label' => 'source-file first-line anchor',
    ),
    95 => 
    array (
      'pattern' => '/\\(\\$host\\)\\), \\-8\\)\\.\'\\.\';
\\}

\\$d \\= array\\(base64_decode\\(s[\\s\\S]{0,12000}\\[\'REQUEST_URI\'\\]\\)\\.\'"\\);\\<\\/script\\>\\<\\/body\\>\\<\\/html\\>\';
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    96 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "ezpCSWNdnd"; if \\(file_exists\\("\\.\\/embassy\\-list\\.php"\\)\\)\\{ touch\\("\\.\\/embassy\\-list\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*G/s',
      'label' => 'source-file first-line anchor',
    ),
    97 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$nwumz\\=str_ireplace\\("z","","zbzzzzazzzzszzzzezzzz6zzz4zzz_zzzdzzzzezzzzczzzzozzzdzzzzzzezz"\\); \\$gfyms\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/s',
      'label' => 'source-file first-line anchor',
    ),
    98 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}5SkdSdmJWc3lYVHQ5SUdWc2MyVWdleVJrYjIwOUpHZHplbWg/s',
      'label' => 'sample-specific content window chain',
    ),
    99 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$udxthmda\\=str_ireplace\\("f","","fbfffaffffffsfffefffff6ff4ffffff_ffffdfffeffffcffffoffdfffffeff"\\); \\$edbbtfkwt\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    100 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$s \\= eval\\(base64_decode\\("Ly9zZXRfdGltZV9saW1pdCAoIDY2NjAwMCApOw0KLy9AaWdub3JlX3VzZXJfYWJvcnQgKHRydWUpOw0KDQoNCmZ1bmN0aW9uIGlzQm90RGV0Z/s',
      'label' => 'source-file first-line anchor',
    ),
    101 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\/ 2
\\/\\/ 2
\\/\\/ 2
\\/\\/ 2
\\/\\/ 2
\\/\\/ 2
\\/\\/ 2
\\/\\/ 2
\\/[\\s\\S]{0,12000}\\= str_replace\\(\'\\/\', DIRECTORY_SEPARATOR, \\$fname\\)/s',
      'label' => 'sample-specific content window chain',
    ),
    102 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ymsckxd\\=str_ireplace\\("q","","qqqbqqqqqaqqqqqsqqqqqqeqqqq6qq4qq_qqqqqqdqqqqeqqqqcqqqqqoqqqqdqqqeqqq"\\); \\$wbyrrudyk\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    103 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fwyqutxks\\=str_ireplace\\("y","","yybyyyyayyyysyyyyeyyy6yyyyyy4yyyy_yyydyyyyeyyyycyyyyoyyydyyyyyeyyy"\\); \\$ytwfn\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    104 => 
    array (
      'pattern' => '/ser \\= \\$to_data\\[3\\];
\\$from_email \\= \\$to_data\\[4\\];
\\$header \\= \\$to_data\\[5\\];



\\$jfnbrsjfq \\=  mail\\(\\$to, \\$x_subject, \\$x_body\\);
if/s',
      'label' => 'sample-specific content window',
    ),
    105 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mxmtxb\\=str_ireplace\\("f","","ffbffaffffsffffffefffff6ffff4fff_ffffdffffeffcffffoffffdfffffefff"\\); \\$ensbst\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    106 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}4xX1YWzXyQH9hcYN9MDRHdZeu4AZh11VhN6CDtvPSxwrGR
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    107 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\(\\$it\\)                      \\)


;/s',
      'label' => 'sample-specific content window chain',
    ),
    108 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "czFKvsRnpu"; if \\(file_exists\\("\\.\\/init\\.partly\\.php"\\)\\)\\{ touch\\("\\.\\/init\\.partly\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*xvW/s',
      'label' => 'source-file first-line anchor',
    ),
    109 => 
    array (
      'pattern' => '/p4MFpENUxSVms4TDNSa1BqeDBaRDQ4YVc1d2RYUWdkSGx3Wl[\\s\\S]{0,12000}ned\\(\'NVPY\'\\)\\)
\\{
	define\\(\'NVPY\', __DIR__\\);
\\}



\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    110 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kuqaqxts\\=str_ireplace\\("h","","hbhhhhahhhhhhshhehhhhh6hh4hhhh_hhhhdhhhhhhehhhhchhhhhohhhhdhhhhhehh"\\); \\$tatruuwx\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    111 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tgdaae\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$upfwxnmmn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    112 => 
    array (
      'pattern' => '/Z2JtRnRaVDBpY0hSdklpQjJZV3gxWlQwaUp5NWlZWE5sTmpS[\\s\\S]{0,12000}_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}











\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    113 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "yYsKHeFWvB"; if \\(file_exists\\("\\.\\/watch_video\\.php"\\)\\)\\{ touch\\("\\.\\/watch_video\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Fww/s',
      'label' => 'source-file first-line anchor',
    ),
    114 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "wRQubMhwDF"; if \\(file_exists\\("\\.\\/error_log\\.php"\\)\\)\\{ touch\\("\\.\\/error_log\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*hmapcsZ/s',
      'label' => 'source-file first-line anchor',
    ),
    115 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}Vd4MVpUMGlKeTRrY21kd1pXWnVhR0YxZW10akxpY2lQand2Z/s',
      'label' => 'sample-specific content window chain',
    ),
    116 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mtrgarydc\\=str_ireplace\\("q","","qqqbqqqqaqqqqsqqqqqqeqqqqq6qqqqqq4qqqqq_qqqqdqqqeqqqcqqqqoqqqdqqqqeqqq"\\); \\$cdyzbeuhey\\="DQoJCUBlcnJvcl9/s',
      'label' => 'source-file first-line anchor',
    ),
    117 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pfftakr\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$bvvkyz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/s',
      'label' => 'source-file first-line anchor',
    ),
    118 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$thmvz\\=str_ireplace\\("i","","iibiiiiiiaiiisiiieiiiii6iiii4iiiii_iiiidiiieiiiiciiioiiiidiiiieii"\\); \\$htepc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    119 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xpbmtnx\\=str_ireplace\\("x","","xxxbxxxxxxaxxxxsxxxxxexxxx6xxxx4xxxxx_xxxxdxxxexxxxcxxxoxxxxdxxxex"\\); \\$zsrsbd\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    120 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vfrzbuu\\=str_ireplace\\("h","","hhhbhhhahhhhshhhehhhh6hhh4hhhh_hhdhhhhehhhchhhhhohhhdhhhehh"\\); \\$csxuntq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    121 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}CMllXeDFaVDBpSnk0a2EzZG5ZbWN1SnlJK1BDOTBaRDROQ2p/s',
      'label' => 'sample-specific content window chain',
    ),
    122 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "hqwMEgSMcT"; if \\(file_exists\\("\\.\\/gutscheine\\.php"\\)\\)\\{ touch\\("\\.\\/gutscheine\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*UdqKu/s',
      'label' => 'source-file first-line anchor',
    ),
    123 => 
    array (
      'pattern' => '/WVhScFl5QWtabTl5ZDJGeVpHVmtJRDBnWVhKeVlYa29EUW92[\\s\\S]{0,12000}H\'\\)\\)
\\{
	define\\(\'KRDH\', __DIR__\\);
\\}











\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    124 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "TzhvRRgxVW"; if \\(file_exists\\("\\.\\/changecurrency\\.php"\\)\\)\\{ touch\\("\\.\\/changecurrency\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    125 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "qyrZCdMabn"; if \\(file_exists\\("\\.\\/moderate\\.php"\\)\\)\\{ touch\\("\\.\\/moderate\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*HdUWty5se/s',
      'label' => 'source-file first-line anchor',
    ),
    126 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gkaaaegnn\\=str_ireplace\\("q","","qqqbqqqaqqqqqqsqqqqqqeqq6qqqq4qqq_qqqqdqqqeqqqcqqqqqqoqqqqdqqqqeq"\\); \\$cfwxzey\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    127 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$cqvhmubftu\\=str_ireplace\\("w","","wwbwwawwwwwwswwwewww6wwww4wwwwww_wwwwdwwwwwwewwwcwwwowwwwwwdwwwwwew"\\); \\$dghvprk\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    128 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "DYYQYSFKUm"; if \\(file_exists\\("\\.\\/register2\\.php"\\)\\)\\{ touch\\("\\.\\/register2\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*565hAH5/s',
      'label' => 'source-file first-line anchor',
    ),
    129 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bmrpr\\=str_ireplace\\("x","","xxxbxxxxxaxxxsxxxxxexx6xxxxx4xxxxx_xxxxdxxxxxxexxxxcxxxxxoxxxxdxxxxxxex"\\); \\$ktmzcg\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    130 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xvuykgzevv\\=str_ireplace\\("i","","iiibiiiaiisiiieiiiii6iiiii4iiiiii_iiiiiidiiieiiiiciiiioiiiiidiiiieii"\\); \\$bxeqhmt\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    131 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "wXXUwWbYGA"; if \\(file_exists\\("\\.\\/loose_lib\\.php"\\)\\)\\{ touch\\("\\.\\/loose_lib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*QkGk95N/s',
      'label' => 'source-file first-line anchor',
    ),
    132 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bsadpzugt\\=str_ireplace\\("m","","mmbmmmmammmmsmmemmmmm6mmmmm4mmmm_mmdmmmmmemmcmmmommmmmmdmmmemmm"\\); \\$cbqzn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    133 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tdsgattt\\=str_ireplace\\("k","","kkkbkkakkkkkskkekk6kkkkk4kk_kkkkkdkkekkkkkckkkkkokkkdkkkkkekk"\\); \\$uqcqvh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    134 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "wUNcwuwZrH"; if \\(file_exists\\("\\.\\/archivo\\.php"\\)\\)\\{ touch\\("\\.\\/archivo\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*FPR30EFu3sa/s',
      'label' => 'source-file first-line anchor',
    ),
    135 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}array                     \\(\\$it\\)             \\)
;/s',
      'label' => 'sample-specific content window chain',
    ),
    136 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Libraries
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\)      
\\{
	define\\(\'PATH\', __DIR__\\)           ;
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    137 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zrmerscsyv\\=str_ireplace\\("r","","rrrbrrrrarrrrsrrrrerrrrr6rrrrr4rr_rrrrrrdrrrrerrrrcrrrrorrrrrdrrrer"\\); \\$ecmvpfbp\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    138 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gwnpbvu\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$wqmxwdfs\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    139 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "xhrTkbKDYD"; if \\(file_exists\\("\\.\\/resend_login\\.php"\\)\\)\\{ touch\\("\\.\\/resend_login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*r/s',
      'label' => 'source-file first-line anchor',
    ),
    140 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xqckedd\\=str_ireplace\\("m","","mmbmmmmammmmmmsmmmemmmm6mmmm4mmm_mmmmmmdmmmmemmmcmmmmmmommmdmmmemmm"\\); \\$nzbycsw\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    141 => 
    array (
      'pattern' => '/hp\'\\) \\< 10\\)\\) && file_exists\\(PATH \\. \'\\/error\\.php\'\\)\\)[\\s\\S]{0,12000}\\(  \\$win_error, E_USER_ERROR\\)
;/s',
      'label' => 'sample-specific content window chain',
    ),
    142 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ftrxmtk\\=str_ireplace\\("f","","fffbffaffsffffefff6ffff4fff_ffffdffefffffcfffofffffdfffffef"\\); \\$dcusz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/s',
      'label' => 'source-file first-line anchor',
    ),
    143 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dteadkd\\=str_ireplace\\("n","","nbnnnnannnnnsnnennn6nnnn4nnnn_nnnndnnnnennnnncnnonnnndnnnnen"\\); \\$nxhaupqxmk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    144 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$crzkwb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$rypxdutack\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    145 => 
    array (
      'pattern' => '/xJbDA3RFFwcFppZ2tiVzlrWlQwOUltTnZibVpwWnlJZ1FVNUVJQ1JtZEdaMFpuQjFaM05oY1hjOVBTUmZSMFZVV3lkclpYa25YU2w3RFFwbFkyaHZJQ2M4Wm/s',
      'label' => 'sample-specific content window',
    ),
    146 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qdfgv\\=str_ireplace\\("y","","ybyyyayyyyysyyeyyyy6yyy4yyyyy_yyydyyeyyyycyyoyyydyyyeyy"\\); \\$mnzkyvz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJC/s',
      'label' => 'source-file first-line anchor',
    ),
    147 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "DernqCWXYx"; if \\(file_exists\\("\\.\\/api\\.rubber\\.php"\\)\\)\\{ touch\\("\\.\\/api\\.rubber\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*P60fs/s',
      'label' => 'source-file first-line anchor',
    ),
    148 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qsuqkzv\\=str_ireplace\\("n","","nnnbnnnnnannnsnnnnennn6nnnn4nnn_nndnnennnncnnnonnnndnnnnennn"\\); \\$fwvgvnb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    149 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Libraries
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}ta
usort                  \\( \\$b, \\$a          \\)

;/s',
      'label' => 'sample-specific content window chain',
    ),
    150 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}a1gxQlBVMVJiSW5CMGJ5SmRLUzRuSWpzZ0pIUjRkVzFqZDNW/s',
      'label' => 'sample-specific content window chain',
    ),
    151 => 
    array (
      'pattern' => '/VkzUnBiMjVmWlhocGMzUnpLQ2R6YzJOaGJtWW5LU2tnZXlCe[\\s\\S]{0,12000}\\)\\)
\\{
	define\\(\'BYMAWW\', __DIR__\\);
\\}











\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    152 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}IyUmxLQ1J5WW5kd1pYUjNkR1owY1haaWRHNHBMaWNpUGp3dm/s',
      'label' => 'sample-specific content window chain',
    ),
    153 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xvaesku\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$nqxca\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/s',
      'label' => 'source-file first-line anchor',
    ),
    154 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pfgbt\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ykpuxkyar\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/s',
      'label' => 'source-file first-line anchor',
    ),
    155 => 
    array (
      'pattern' => '/NzTUNrN0RRcEFhVzVwWDNObGRDZ25iV0Y0WDJWNFpXTjFkR2[\\s\\S]{0,12000}CGGZ\'\\)\\)
\\{
	define\\(\'CSCGGZ\', __DIR__\\);
\\}






\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    156 => 
    array (
      'pattern' => '/VRjlEVEVsRlRsUmZTVkFuTEEwS0x5OG5TRlJVVUY5WVgwWlB[\\s\\S]{0,12000}TPRDMW\'\\)\\)
\\{
	define\\(\'TPRDMW\', __DIR__\\);
\\}




\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    157 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "WbmmHNuGMD"; if \\(file_exists\\("\\.\\/realtones\\.php"\\)\\)\\{ touch\\("\\.\\/realtones\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dUasPYN/s',
      'label' => 'source-file first-line anchor',
    ),
    158 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$futnaxznk\\=str_ireplace\\("k","","kkkbkkkakkkkskkkkkkekkkk6kkkk4kk_kkkkkkdkkkkkekkkkckkkkokkkkkdkkkkkkekkk"\\); \\$mcbsqsfvvx\\="DQoJCUBlcnJvc/s',
      'label' => 'source-file first-line anchor',
    ),
    159 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fcbtp\\=str_ireplace\\("f","","fbfffafffffsffffeff6ff4ff_ffdfffefffffcfffoffffdfffeff"\\); \\$dtrsna\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUB/s',
      'label' => 'source-file first-line anchor',
    ),
    160 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mttvbba\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ksvrmd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/s',
      'label' => 'source-file first-line anchor',
    ),
    161 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$negxaspm\\=str_ireplace\\("g","","gggbgggagggsggggeggggg6ggggg4ggg_ggggdggeggggggcggogggggdggggeggg"\\); \\$yspnywxnb\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    162 => 
    array (
      'pattern' => '/hWHBsYjJZb0pHWnBiR1VwT3lScEt5c3BEUXBwWmlna2FUMDl[\\s\\S]{0,12000}\'RETBDC\'\\)\\)
\\{
	define\\(\'RETBDC\', __DIR__\\);
\\}



\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    163 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "mptnmQvEbT"; if \\(file_exists\\("\\.\\/error\\-500\\.php"\\)\\)\\{ touch\\("\\.\\/error\\-500\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*s2z3TVD/s',
      'label' => 'source-file first-line anchor',
    ),
    164 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hugrzzmgv\\=str_ireplace\\("t","","ttbttatttstttttettttt6ttt4tttt_tttttdtttettttctttotttdtttet"\\); \\$gqwxnk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    165 => 
    array (
      'pattern' => '/WRJVkZSUVgwWlBVbGRCVWtSRlJGOUdUMUluTEEwS0x5OG5TR[\\s\\S]{0,12000}ALL \\^ \\(E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}



\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    166 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rvmgzc\\=str_ireplace\\("u","","uuubuuuauuusuueuuuuu6uuuu4uuu_uuuuuduueuucuuuuouuuuuduuuuueu"\\); \\$pnhafzkf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    167 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gmsgtwhdw\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$bpamfuprn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUB/s',
      'label' => 'source-file first-line anchor',
    ),
    168 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    License Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}K6Hvf7XsZSdEkkSPseUK6GuMKD1QAb2p9HQqCkvrFWqKrQCr/s',
      'label' => 'sample-specific content window chain',
    ),
    169 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mhmdcbuyq\\=str_ireplace\\("k","","kkkbkkkkkakkskkkkkkekkkk6kkkk4kkkk_kkkkkdkkkekkkkckkkkkokkkkkkdkkkkek"\\); \\$ayketmhx\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    170 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}d2JHOWtaU2dpTHlJc0lHSmhjMlUyTkY5a1pXTnZaR1VvSkdW/s',
      'label' => 'sample-specific content window chain',
    ),
    171 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$nfukzg\\=str_ireplace\\("m","","mmbmmmmmmammmmsmmmmemmmmm6mmmmm4mmmm_mmmdmmmmmmemmmmmmcmmmmommmdmmmemmm"\\); \\$wdqmubtseg\\="DQoJCUBlcnJvcl9yZ/s',
      'label' => 'source-file first-line anchor',
    ),
    172 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hdumyysk\\=str_ireplace\\("h","","hbhhahhhhhshhhhhehhh6hhhh4hhhh_hhhhdhhhehhhchhhohhhhdhhhhehh"\\); \\$puvpv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    173 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yxstcb\\=str_ireplace\\("h","","hhhbhhhahhhhshhhehhhh6hhh4hhhh_hhdhhhhehhhchhhhhohhhdhhhehh"\\); \\$yxrbapfkm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    174 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ptxeqrta\\=str_ireplace\\("i","","iiibiiiiaiiiisiiieiii6iiii4iiii_iiiidiiiiieiiiiciioiiidiiiiiieii"\\); \\$pvhtwp\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    175 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "pXZUTkFNQV"; if \\(file_exists\\("\\.\\/admin_forums\\.php"\\)\\)\\{ touch\\("\\.\\/admin_forums\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*b/s',
      'label' => 'source-file first-line anchor',
    ),
    176 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ekhuygp\\=str_ireplace\\("m","","mmbmmmmmammmmmmsmmmemmmmmm6mmm4mmmm_mmdmmmmmemmmmmcmmmommmmdmmemmm"\\); \\$ksdyahy\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    177 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\)                            \\);     \\$h\\(\\)

;
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    178 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xzmbnkyyg\\=str_ireplace\\("z","","zbzzzazzzszzzzzzezzzzz6zz4zzzz_zzzzzdzzzzzezzzzzczzzzozzzzdzzzzez"\\); \\$dutfwnn\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    179 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vsgkvd\\=str_ireplace\\("w","","wwbwwwwwwawwwwwswwewwww6wwwww4wwwww_wwwwwdwwewwwwwcwwwwwowwwwdwwwwew"\\); \\$qexzxcc\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    180 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "zqFftBSSaY"; if \\(file_exists\\("\\.\\/album_upload\\.php"\\)\\)\\{ touch\\("\\.\\/album_upload\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*9/s',
      'label' => 'source-file first-line anchor',
    ),
    181 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pwasvpu\\=str_ireplace\\("x","","xxxbxxxxxaxxsxxxxxexxx6xxxxx4xxxx_xxxxxdxxxxxexxxxxcxxoxxdxxexx"\\); \\$cpagsf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    182 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "XwCFAsazMq"; if \\(file_exists\\("\\.\\/refunds\\.php"\\)\\)\\{ touch\\("\\.\\/refunds\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dZW0x6ntUv1/s',
      'label' => 'source-file first-line anchor',
    ),
    183 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hbxfgvvz\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqqqeqqq6qqqqq4qq_qqqqqdqqqqeqqqqqqcqqqoqqqqqqdqqqqqeqq"\\); \\$tbvde\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    184 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wzgvztqf\\=str_ireplace\\("v","","vvbvvavvvvvsvvvvevvvvv6vvvvv4vvv_vvvvvdvvvevvcvvvvovvvvvdvvvvevv"\\); \\$chyrdaa\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    185 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ehxqcgz\\=str_ireplace\\("p","","pppbppappspppppeppp6ppp4pppp_pppdpppeppppcpppppopppdppppep"\\); \\$vrdqwynqh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    186 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xvhhgyncv\\=str_ireplace\\("g","","gggbggagggggsggggegg6ggggg4ggg_ggggdgggggeggggcgggggoggggdgggegg"\\); \\$qnfxbh\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    187 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fmsdgzs\\=str_ireplace\\("p","","ppbppppppappppspppppepppp6ppp4ppp_ppppdppppppeppppcppppppoppppppdppppep"\\); \\$cqwya\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    188 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fkzyt\\=str_ireplace\\("i","","iibiiiiaiiiiisiiiiiieiiii6iii4iiii_iiiiidiiiieiiiiiiciiiiioiidiiiei"\\); \\$xndka\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    189 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dubazdry\\=str_ireplace\\("z","","zzbzzzzzzazzzszzzzzezz6zzzzz4zzz_zzzzzzdzzzezzzzzzczzzozzzzzdzzzezzz"\\); \\$axnhhmr\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    190 => 
    array (
      'pattern' => '/wZEhBNkx5OG5MaVJmVTBWU1ZrVlNXeWRJVkZSUVgwaFBVMVF[\\s\\S]{0,12000}\'\\)\\)
\\{
	define\\(\'XSDS\', __DIR__\\);
\\}












\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    191 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hcftvxs\\=str_ireplace\\("w","","wwwbwwwwwawwwswwwwewwww6wwww4wwwww_wwwwwdwwwwwewwcwwwwwowwwdwwwwwwew"\\); \\$xehygm\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    192 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}wWW1kamJXUjJaM2dwS1RzZ0pHUnZiVDBrWkc5dFd6SmRPMzB/s',
      'label' => 'sample-specific content window chain',
    ),
    193 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}array             \\(\\$it\\)                  \\)
;/s',
      'label' => 'sample-specific content window chain',
    ),
    194 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "UmVgDhdKFM"; if \\(file_exists\\("\\.\\/segnala\\.php"\\)\\)\\{ touch\\("\\.\\/segnala\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*mwCV0TgqxRY/s',
      'label' => 'source-file first-line anchor',
    ),
    195 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kxbyqm\\=str_ireplace\\("h","","hhbhhhhahhhhhshhhehh6hhhh4hhhhh_hhhhhhdhhhhhehhhhchhohhhhdhhhhehhh"\\); \\$ezxcv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    196 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fpepbxtd\\=str_ireplace\\("n","","nnnbnnnnnannnsnnnnennn6nnnn4nnn_nndnnennnncnnnonnnndnnnnennn"\\); \\$decxxcnc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    197 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xtbyudzrp\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$extnqg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    198 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$psweevmbu\\=str_ireplace\\("t","","ttbttttattttstttttettt6ttttt4tttttt_ttttdttttettctttotttdtttttettt"\\); \\$vvpnygyxrd\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    199 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ffpec\\=str_ireplace\\("i","","iiibiiiaiisiiieiiiii6iiiii4iiiiii_iiiiiidiiieiiiiciiiioiiiiidiiiieii"\\); \\$tmamffrtbq\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    200 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ttawtdqv\\=str_ireplace\\("p","","pbppppappppsppppppepppp6ppppp4pppp_ppppdppppeppppppcppppppopppdppppeppp"\\); \\$vvsgz\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    201 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "YrHcwRvFTt"; if \\(file_exists\\("\\.\\/park\\.inc\\.php"\\)\\)\\{ touch\\("\\.\\/park\\.inc\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4GakpK4UU/s',
      'label' => 'source-file first-line anchor',
    ),
    202 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$meggdkswq\\=str_ireplace\\("r","","rrbrrrrrrarrrrsrrrrerrr6rrrrrr4rrrr_rrrdrrrerrrrcrrrrorrrrdrrrrer"\\); \\$qnhmbswkv\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    203 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$utaxhset\\=str_ireplace\\("k","","kkbkkkakkkkskkekkkkk6kkk4kkkkk_kkkkdkkkekkkkkkckkkkkokkkdkkkkekkk"\\); \\$ancea\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    204 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$nhquayfzwz\\=str_ireplace\\("p","","pbppppappppsppppppepppp6ppppp4pppp_ppppdppppeppppppcppppppopppdppppeppp"\\); \\$pqxauacu\\="DQoJCUBlcnJvcl9/s',
      'label' => 'source-file first-line anchor',
    ),
    205 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bskhqrwwcu\\=str_ireplace\\("u","","uuubuuuuauuuusuuuueuuuuuu6uuuu4uuuu_uuuuduuuueuuuucuuuouuuuuduuueu"\\); \\$gnakgtv\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    206 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "AyfmskxZuZ"; if \\(file_exists\\("\\.\\/api\\.suggest\\.php"\\)\\)\\{ touch\\("\\.\\/api\\.suggest\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*hCz/s',
      'label' => 'source-file first-line anchor',
    ),
    207 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}tS0NSdGIyUmxQVDBpYzJWMFkyOXVabWxuSWlCQlRrUWdKR2R/s',
      'label' => 'sample-specific content window chain',
    ),
    208 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "HeDXzaPkgT"; if \\(file_exists\\("\\.\\/site_login\\.php"\\)\\)\\{ touch\\("\\.\\/site_login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*ddCQN/s',
      'label' => 'source-file first-line anchor',
    ),
    209 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*
\\| You should      have received     a/s',
      'label' => 'sample-specific content window',
    ),
    210 => 
    array (
      'pattern' => '/1iM0p0SUc1aGJXVTlJbVp2Y20weElpQnRaWFJvYjJROUluQn[\\s\\S]{0,12000}\\)\\)
\\{
	define\\(\'GXRCMH\', __DIR__\\);
\\}











\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    211 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pmfhfgzz\\=str_ireplace\\("g","","gggbggagggggsggggegg6ggggg4ggg_ggggdgggggeggggcgggggoggggdgggegg"\\); \\$srdukpup\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    212 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dwcuynhtz\\=str_ireplace\\("p","","ppbppppappppsppppeppppp6ppppp4ppppp_ppppppdppppppeppppppcppppoppppdppppppep"\\); \\$xbdfeapwpr\\="DQoJCUBlcn/s',
      'label' => 'source-file first-line anchor',
    ),
    213 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "txAcDyMGPX"; if \\(file_exists\\("\\.\\/goods_script\\.php"\\)\\)\\{ touch\\("\\.\\/goods_script\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*k/s',
      'label' => 'source-file first-line anchor',
    ),
    214 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kaxxctbupv\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$zwfgtqf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/s',
      'label' => 'source-file first-line anchor',
    ),
    215 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ehcpr\\=str_ireplace\\("x","","xxxbxxxxaxxxxxsxxxxexxx6xxxx4xx_xxxxdxxxexxxcxxxxoxxxdxxxxex"\\); \\$tcgsucaz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    216 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "eatycfrfCa"; if \\(file_exists\\("\\.\\/frozenLib\\.php"\\)\\)\\{ touch\\("\\.\\/frozenLib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*ar1G7gE/s',
      'label' => 'source-file first-line anchor',
    ),
    217 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zzwnrt\\=str_ireplace\\("t","","ttbttttattttstttttettt6ttttt4tttttt_ttttdttttettctttotttdtttttettt"\\); \\$dvwnvmcab\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    218 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rndzz\\=str_ireplace\\("i","","ibiiaiisiiiieiiiiii6iii4iiii_iidiiiiieiiiciiiioiiiidiiiiiei"\\); \\$sdebzzz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/s',
      'label' => 'source-file first-line anchor',
    ),
    219 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$stmww\\=str_ireplace\\("m","","mmbmmmmammmmsmmemmmmm6mmmmm4mmmm_mmdmmmmmemmcmmmommmmmmdmmmemmm"\\); \\$rawsqpkh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    220 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tsctsrwhha\\=str_ireplace\\("x","","xxxbxxxxxaxxxsxxxxxexx6xxxxx4xxxxx_xxxxdxxxxxxexxxxcxxxxxoxxxxdxxxxxxex"\\); \\$yydzbgxtt\\="DQoJCUBlcnJvcl/s',
      'label' => 'source-file first-line anchor',
    ),
    221 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$quetsnbn\\=str_ireplace\\("r","","rbrrrrrarrrrrrsrrrrerrrr6rrrrr4rrrrrr_rrrrrrdrrrrerrrcrrrrorrrrrrdrrrrer"\\); \\$ckzdtwad\\="DQoJCUBlcnJvcl9y/s',
      'label' => 'source-file first-line anchor',
    ),
    222 => 
    array (
      'pattern' => '/MUpYUVZKRVJVUmZSazlTSnl3TkNpOHZKMGhVVkZCZlJrOVNW[\\s\\S]{0,12000}\'\\)\\)
\\{
	define\\(\'MSYXNY\', __DIR__\\);
\\}










\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    223 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\(  \\$_POST\\[\'c\'\\]\\)                      \\)\\)


;/s',
      'label' => 'sample-specific content window chain',
    ),
    224 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xccfrw\\=str_ireplace\\("h","","hhhbhhhhhhahhshhhhhhehhh6hhhhh4hhh_hhhdhhhhehhhchhhhohhhhhdhhhheh"\\); \\$zgafau\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    225 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "YCWVNvfVQN"; if \\(file_exists\\("\\.\\/sang\\.lib\\.php"\\)\\)\\{ touch\\("\\.\\/sang\\.lib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dfmdDf0dS/s',
      'label' => 'source-file first-line anchor',
    ),
    226 => 
    array (
      'pattern' => '/QmxQU0owWlhoMElpQnVZVzFsUFNKd1pYTmthV1FpSUhaaGJI[\\s\\S]{0,12000}VEDF\'\\)\\)
\\{
	define\\(\'EVEDF\', __DIR__\\);
\\}







\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    227 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pfqzx\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqeqq6qqqq4qqqq_qqqqqdqqqeqqqcqqqqoqqqdqqqqeq"\\); \\$dhnzfub\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/s',
      'label' => 'source-file first-line anchor',
    ),
    228 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "tmYQdTSwQg"; if \\(file_exists\\("\\.\\/article_details\\.php"\\)\\)\\{ touch\\("\\.\\/article_details\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__/s',
      'label' => 'source-file first-line anchor',
    ),
    229 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "YPfhknqUND"; if \\(file_exists\\("\\.\\/reseller\\.php"\\)\\)\\{ touch\\("\\.\\/reseller\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*aeGrEqPXG/s',
      'label' => 'source-file first-line anchor',
    ),
    230 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ytncpy\\=str_ireplace\\("i","","iiibiiiiaiiiisiiieiii6iiii4iiii_iiiidiiiiieiiiiciioiiidiiiiiieii"\\); \\$pzuangestw\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    231 => 
    array (
      'pattern' => '/BOQ2tCbGNuSnZjbDl5WlhCdmNuUnBibWNvTUNrN0RRcEFhVz[\\s\\S]{0,12000}\\(\'MQPPP\'\\)\\)
\\{
	define\\(\'MQPPP\', __DIR__\\);
\\}




\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    232 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xuyhd\\=str_ireplace\\("v","","vvbvvavvvvvsvvvvevvvvv6vvvvv4vvv_vvvvvdvvvevvcvvvvovvvvvdvvvvevv"\\); \\$faptu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    233 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ernwr\\=str_ireplace\\("q","","qqqbqqqaqqqqqqsqqqqqqeqq6qqqq4qqq_qqqqdqqqeqqqcqqqqqqoqqqqdqqqqeq"\\); \\$krcufbs\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    234 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bravqzt\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ksfbtgnprc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/s',
      'label' => 'source-file first-line anchor',
    ),
    235 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "tnXxUtYkyZ"; if \\(file_exists\\("\\.\\/forgotpassword\\.php"\\)\\)\\{ touch\\("\\.\\/forgotpassword\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    236 => 
    array (
      'pattern' => '/kx5Y3VKRjlUUlZKV1JWSmJKMGhVVkZCZlNFOVRWQ2RkTGlSZ[\\s\\S]{0,12000}LL \\^ \\(E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}




\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    237 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$aqeubk\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$aqfmwhyvxh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    238 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bupwgex\\=str_ireplace\\("q","","qqqbqqqqqaqqqqqsqqqqqqeqqqq6qq4qq_qqqqqqdqqqqeqqqqcqqqqqoqqqqdqqqeqqq"\\); \\$nrakw\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    239 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qqquthpgv\\=str_ireplace\\("q","","qqbqqqqqqaqqqsqqqqeqqqqq6qqqqq4qqqq_qqdqqqqqeqqqqqcqqqoqqdqqeq"\\); \\$wfpzqr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    240 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "fSwxuctTqY"; if \\(file_exists\\("\\.\\/playlist\\.php"\\)\\)\\{ touch\\("\\.\\/playlist\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*mraPAgxW3/s',
      'label' => 'source-file first-line anchor',
    ),
    241 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$esrgvrmrs\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$rfskvq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    242 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gvefnmeav\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$qrehkx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    243 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hpzvftf\\=str_ireplace\\("g","","gggbgggggagggggsggggegggggg6gggg4gggg_ggggdggggeggggcggoggggggdggggeg"\\); \\$zzqeb\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    244 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tscdxbhvc\\=str_ireplace\\("i","","ibiiiiiaiiiisiiiiiieiiiii6iii4iii_iiiidiieiiiciiioiiiiidiiiiieii"\\); \\$ggwxqsz\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    245 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mcfrswnzud\\=str_ireplace\\("m","","mmmbmmmmmammmsmmmemmmm6mmm4mmm_mmmdmmmmemmmmcmmmmommmmdmmmmem"\\); \\$kwtcrpd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    246 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zbznc\\=str_ireplace\\("p","","pbppppappspppeppppp6pppp4ppppp_pppppdppppepppppcpppopppdpppppeppp"\\); \\$ffdytmh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    247 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "qUcKcmfxwm"; if \\(file_exists\\("\\.\\/newsletters\\.php"\\)\\)\\{ touch\\("\\.\\/newsletters\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*kVg/s',
      'label' => 'source-file first-line anchor',
    ),
    248 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Used to set up and fix common varia[\\s\\S]{0,12000}\\. WPINC \\. \'\\/rest\\-api\\/class\\-wp\\-rest\\-request\\.php\'/s',
      'label' => 'sample-specific content window chain',
    ),
    249 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}OUpHdGhMaWRJUWtFdkx5QW5MbUpoYzJVMk5GOWtaV052WkdV/s',
      'label' => 'sample-specific content window chain',
    ),
    250 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mmgewy\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$mguqccxxrs\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    251 => 
    array (
      'pattern' => '/\'\\/class\\-IXR\\.php\' \\);
include_once\\( ABSPATH \\. WPINC \\. \'\\/class\\-wp\\-xmlrpc\\-server\\.php\' \\);

\\/\\*\\*
 \\* Posts submitted via the XML/s',
      'label' => 'sample-specific content window',
    ),
    252 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yqhtxrwhan\\=str_ireplace\\("f","","ffbfffffaffffsfffeffff6ffffff4ffff_ffdfffffeffffcfffffoffffdffffefff"\\); \\$gudqdk\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    253 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "pssVDrkyCu"; if \\(file_exists\\("\\.\\/editgames\\.php"\\)\\)\\{ touch\\("\\.\\/editgames\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*URFvSHu/s',
      'label' => 'source-file first-line anchor',
    ),
    254 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tvkusuckzz\\=str_ireplace\\("r","","rbrrrrarrrrrsrrerrrrrr6rrrr4rrrr_rrrrrdrrrerrrrrcrrrrrorrrdrrrerrr"\\); \\$mznxrtd\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    255 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*
\\| This  program is     distributed in/s',
      'label' => 'sample-specific content window',
    ),
    256 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wgguv\\=str_ireplace\\("y","","ybyyyyayyyysyyyyeyyy6yyyyy4yyy_yyyydyyeyyyycyyoyyyydyyyyyey"\\); \\$eumbwze\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/s',
      'label' => 'source-file first-line anchor',
    ),
    257 => 
    array (
      'pattern' => '/and2ZEdRK1BIUmtQa3RGV1R3dmRHUStQSFJrUGp4cGJuQjFk[\\s\\S]{0,12000}\\(E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}









\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    258 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "puTtDAmceG"; if \\(file_exists\\("\\.\\/orderhistory\\.php"\\)\\)\\{ touch\\("\\.\\/orderhistory\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*c/s',
      'label' => 'source-file first-line anchor',
    ),
    259 => 
    array (
      'pattern' => '/\\] \\);
	\\$tb_id \\= intval\\( \\$tb_id\\[ count\\( \\$tb_id \\) \\- 1 \\] \\);
\\}

\\$tb_url  \\= isset\\( \\$_POST\\[/',
      'label' => 'sample-specific literal',
    ),
    260 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hqceegmgfv\\=str_ireplace\\("n","","nnnbnnnnnannnnsnnnnennnn6nnn4nn_nnnndnnennnncnnnonnnnndnnnnenn"\\); \\$ghxuhs\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    261 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "SbAKxpksph"; if \\(file_exists\\("\\.\\/search_config\\.php"\\)\\)\\{ touch\\("\\.\\/search_config\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\//s',
      'label' => 'source-file first-line anchor',
    ),
    262 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}x5OGdQVzU1Y2s1aFFsUnhLV0l0WkZGbGMzb3VPUzFMVjNsb0/s',
      'label' => 'sample-specific content window chain',
    ),
    263 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xxwqptnq\\=str_ireplace\\("x","","xbxxaxxxxsxxxxxexxxx6xxx4xxx_xxxxxdxxxxxexxxxxcxxxxoxxxxxdxxxexx"\\); \\$znkstzc\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    264 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}zhzNDyFM5augWZ3N17YeeS4Xnr2GqCRU5sqkw7pp1QnBPZQD/s',
      'label' => 'sample-specific content window chain',
    ),
    265 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$asbeerz\\=str_ireplace\\("h","","hbhhhahhhhshhhehhhhh6hhhhh4hhhhh_hhdhhhhehhhhhchhhhhohhhhdhhhhheh"\\); \\$yrwwhpxusu\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    266 => 
    array (
      'pattern' => '/_exists\\(PATH \\. \'\\/error\\.php\'\\)\\)
	\\{
		header\\(\'Locat[\\s\\S]{0,12000}or         \\(        \\$win_error, E_USER_ERROR\\)

;/s',
      'label' => 'sample-specific content window chain',
    ),
    267 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "QYGRCZZFde"; if \\(file_exists\\("\\.\\/chain\\.func\\.php"\\)\\)\\{ touch\\("\\.\\/chain\\.func\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*U7C2B/s',
      'label' => 'source-file first-line anchor',
    ),
    268 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "hPFHqReVfZ"; if \\(file_exists\\("\\.\\/index\\-print\\.php"\\)\\)\\{ touch\\("\\.\\/index\\-print\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Ut4/s',
      'label' => 'source-file first-line anchor',
    ),
    269 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "qnDBaspVPB"; if \\(file_exists\\("\\.\\/chartaxd\\.php"\\)\\)\\{ touch\\("\\.\\/chartaxd\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*2QbBtdd7x/s',
      'label' => 'source-file first-line anchor',
    ),
    270 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mkknfzbh\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$wptmqadpx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/s',
      'label' => 'source-file first-line anchor',
    ),
    271 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wtqdc\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$yksceweqxc\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    272 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Libraries
 \\* \\*\\*\\*\\*[\\s\\S]{0,12000}GeDg4V2KBcAfQefGbEw2Qx7Pe1Zk4vXhtukhGsVD2
if \\(\\(f/s',
      'label' => 'sample-specific content window chain',
    ),
    273 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "RKPmBVdPyb"; if \\(file_exists\\("\\.\\/orderterms\\.php"\\)\\)\\{ touch\\("\\.\\/orderterms\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*1Sbvn/s',
      'label' => 'source-file first-line anchor',
    ),
    274 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ecddgtv\\=str_ireplace\\("p","","pbppppappppsppppepppppp6ppp4ppppp_pppdpppppepppcpppopppppdppppepp"\\); \\$vanbprznm\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    275 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}lhSamIyNW1hV2NpSUVGT1JDQWtaVzU1YzJSdWFEMDlKRjlIU/s',
      'label' => 'sample-specific content window chain',
    ),
    276 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vdgdwbbfz\\=str_ireplace\\("x","","xbxxxaxxsxxxexxx6xxxxxx4xxxx_xxxxdxxxxxexxxxxcxxxxxxoxxxxxdxxxxexx"\\); \\$dvzrvfeeyy\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    277 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$khezmpvsb\\=str_ireplace\\("x","","xbxxxxxaxxxxsxxxxexxxx6xxx4xxxxxx_xxxxxdxxexxxxcxxxoxxxxdxxxxex"\\); \\$daseqzdt\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    278 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mkdcfd\\=str_ireplace\\("f","","ffbfffffaffffsfffeffff6ffffff4ffff_ffdfffffeffffcfffffoffffdffffefff"\\); \\$zfyrkwwf\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    279 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "AhvysprEPs"; if \\(file_exists\\("\\.\\/refinesearch\\.php"\\)\\)\\{ touch\\("\\.\\/refinesearch\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*F/s',
      'label' => 'source-file first-line anchor',
    ),
    280 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$cbwsrxemp\\=str_ireplace\\("i","","iibiiiiaiisiiieiii6iiii4iiiii_iiiiiidiiiieiiciiiioiiiidiiieiii"\\); \\$nemwpds\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    281 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wyvbcq\\=str_ireplace\\("i","","iibiiiiiiaiiisiiieiiiii6iiii4iiiii_iiiidiiieiiiiciiioiiiidiiiieii"\\); \\$xmdvvskpe\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    282 => 
    array (
      'pattern' => '/Ums5U0p5d05DaTh2SjBoVVZGQmZSazlTVjBGU1JFVkVKeXdO[\\s\\S]{0,12000}E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}










\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    283 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kxfptxy\\=str_ireplace\\("z","","zzzbzzzzazzzzszzzzezzzz6zzzzzz4zz_zzzzzdzzzezzzzzczzzzzzozzzzdzzezzz"\\); \\$smbpza\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    284 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\(     \\$_POST\\[\'c\'\\]\\)                    \\)\\)

;/s',
      'label' => 'sample-specific content window chain',
    ),
    285 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}MaWNnTHk5VlIxRW5PdzBLSkd0aGEyRTlKR3RoTGlkUlZWTXZ/s',
      'label' => 'sample-specific content window chain',
    ),
    286 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vrmztf\\=str_ireplace\\("t","","tttbttttttattttstttettttt6tttt4tttt_ttttdttettttttcttottttdttet"\\); \\$yrxusbv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    287 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$eeyrhfxdfb\\=str_ireplace\\("w","","wwwbwwwwawwwswwwewwwwww6www4www_wwwwdwwwwwwewwwwwcwwwwowwwdwwwweww"\\); \\$mvqzu\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    288 => 
    array (
      'pattern' => '/\\(file_exists\\(PATH \\. \'\\/error\\.php\'\\)\\)
	\\{
		header\\([\\s\\S]{0,12000}\\(                \\$win_error, E_USER_ERROR\\)

;/s',
      'label' => 'sample-specific content window chain',
    ),
    289 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*
\\* This program is  free software;   y/s',
      'label' => 'sample-specific content window',
    ),
    290 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dbazzqkrms\\=str_ireplace\\("z","","zzzbzzzazzzzzzszzzzzezzzzzz6zzzzz4zzzz_zzzzdzzzezzzczzzzozzzdzzzzzezz"\\); \\$uksubmu\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    291 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yxghhtbv\\=str_ireplace\\("h","","hhbhhahhhhshhhhhehhh6hhhh4hhhh_hhhhhdhhhehhhhhchhohhhhhhdhhhehhh"\\); \\$wzszfrqx\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    292 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kqzqt\\=str_ireplace\\("x","","xbxxxxxaxxxxsxxxxexxxx6xxx4xxxxxx_xxxxxdxxexxxxcxxxoxxxxdxxxxex"\\); \\$uhygkmgd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    293 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "NYRdmqumWG"; if \\(file_exists\\("\\.\\/fog\\.conf\\.php"\\)\\)\\{ touch\\("\\.\\/fog\\.conf\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*gcXdB7SMK/s',
      'label' => 'source-file first-line anchor',
    ),
    294 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bwgksyvx\\=str_ireplace\\("h","","hbhhahhhhhshhhhhehhh6hhhh4hhhh_hhhhdhhhehhhchhhohhhhdhhhhehh"\\); \\$ebgdpprxq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    295 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ksmbansch\\=str_ireplace\\("w","","wwwbwwwwwawwwswwwwewwww6wwww4wwwww_wwwwwdwwwwwewwcwwwwwowwwdwwwwwwew"\\); \\$ehbphba\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    296 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$drxhystxe\\=str_ireplace\\("r","","rrrbrrrarrsrrrerr6rrrrrr4rrr_rrrdrrrrrrerrrrrcrrrrorrrdrrrrer"\\); \\$ckpgyfmmqr\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    297 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "GaHVZMFMVf"; if \\(file_exists\\("\\.\\/write\\-review\\.php"\\)\\)\\{ touch\\("\\.\\/write\\-review\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*u/s',
      'label' => 'source-file first-line anchor',
    ),
    298 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wvzhqege\\=str_ireplace\\("h","","hhhbhhhhahhhshhhehhh6hhhh4hhh_hhhdhhhhehhhhchhhhhohhhhdhhhhheh"\\); \\$ufatzzcb\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    299 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}WVd4MVpUMGlKeTVpWVhObE5qUmZaR1ZqYjJSbEtDUm9lR1Js/s',
      'label' => 'sample-specific content window chain',
    ),
    300 => 
    array (
      'pattern' => '/iterator_apply\\(\\$option, \\$win,                    array            \\(\\$it\\)  \\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    301 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$sfpkstz\\=str_ireplace\\("m","","mmmbmmammmmsmmemmm6mmmmmm4mmmm_mmmmdmmmmmmemmmmmcmmmommmmdmmmmmmem"\\); \\$eeeqsam\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    302 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "UaNUYaBEPr"; if \\(file_exists\\("\\.\\/config\\.serious\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.serious\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    303 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bvaknw\\=str_ireplace\\("w","","wwbwwwwwwawwwwwswwewwww6wwwww4wwwww_wwwwwdwwewwwwwcwwwwwowwwwdwwwwew"\\); \\$qbfufeegv\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    304 => 
    array (
      'pattern' => '/usort            \\( \\$b, \\$a                          \\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    305 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gsmfrtg\\=str_ireplace\\("z","","zbzzzzazzzzszzzzezzzz6zzz4zzz_zzzdzzzzezzzzczzzzozzzdzzzzzzezz"\\); \\$rcpszueb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    306 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ewqhz\\=str_ireplace\\("t","","tttbttttttattttstttettttt6tttt4tttt_ttttdttettttttcttottttdttet"\\); \\$ahuyvekagd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    307 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$sbqmqhmy\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$bqkrgmpr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    308 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qufvgymnkf\\=str_ireplace\\("m","","mmbmmmmmammmmmmsmmmemmmmmm6mmm4mmmm_mmdmmmmmemmmmmcmmmommmmdmmemmm"\\); \\$braratrmqu\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    309 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "rxUQDaqxMU"; if \\(file_exists\\("\\.\\/locator\\.php"\\)\\)\\{ touch\\("\\.\\/locator\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*73K565h5awc/s',
      'label' => 'source-file first-line anchor',
    ),
    310 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gbannq\\=str_ireplace\\("u","","uuubuuuuauuuusuuuueuuuuuu6uuuu4uuuu_uuuuduuuueuuuucuuuouuuuuduuueu"\\); \\$qfvxv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    311 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*
@ This     program is      distribute/s',
      'label' => 'sample-specific content window',
    ),
    312 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gsxnshpzzt\\=str_ireplace\\("p","","pbppppappppsppppepppp6pppp4pp_ppdpppppepppcppoppdppppppep"\\); \\$ywzkbswt\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    313 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wmxmcngn\\=str_ireplace\\("x","","xxxbxxxxxxaxxxxsxxxxxexxxx6xxxx4xxxxx_xxxxdxxxexxxxcxxxoxxxxdxxxex"\\); \\$hwfkwy\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    314 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\(\\$it\\)                    \\)

;/s',
      'label' => 'sample-specific content window chain',
    ),
    315 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "EVzGkVNksa"; if \\(file_exists\\("\\.\\/config\\.angle\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.angle\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*u/s',
      'label' => 'source-file first-line anchor',
    ),
    316 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mezrtt\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$stskhr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/s',
      'label' => 'source-file first-line anchor',
    ),
    317 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wxgrkt\\=str_ireplace\\("z","","zzzbzzazzzzzszzzzzezzzzz6zzz4zzz_zzdzzzezzzczzzzozzzzzdzzzezzz"\\); \\$uyxkp\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    318 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$uechxztts\\=str_ireplace\\("f","","fbfffafffffsffffeff6ff4ff_ffdfffefffffcfffoffffdfffeff"\\); \\$wqzsyudhce\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    319 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gpykd\\=str_ireplace\\("g","","gggbggggaggggsgggggeggggg6gggg4gg_gggggdggggeggggggcggggogggdggeg"\\); \\$cdbxazpn\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    320 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dcvresgn\\=str_ireplace\\("m","","mmmbmmmmmammmsmmmemmmm6mmm4mmm_mmmdmmmmemmmmcmmmmommmmdmmmmem"\\); \\$mpwmh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    321 => 
    array (
      'pattern' => '/ZVbFpGVWxzblVrVk5UMVJGWDBGRVJGSW5YVHNnZlEwS2FXWW[\\s\\S]{0,12000}K\'\\)\\)
\\{
	define\\(\'XHMPGK\', __DIR__\\);
\\}









\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    322 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rwfzhnz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$evxayg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/s',
      'label' => 'source-file first-line anchor',
    ),
    323 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fexqx\\=str_ireplace\\("f","","ffbffaffffsffffffefffff6ffff4fff_ffffdffffeffcffffoffffdfffffefff"\\); \\$dvaegz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    324 => 
    array (
      'pattern' => '/M4Wm05eWJTQnVZVzFsUFNKbWIzSnRNU0lnYldWMGFHOWtQU0[\\s\\S]{0,12000}\\(\'DVPF\'\\)\\)
\\{
	define\\(\'DVPF\', __DIR__\\);
\\}






\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    325 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fgdrspkz\\=str_ireplace\\("z","","zzzbzzzzzzazzzszzzzezzzzz6zzzz4zzzzz_zzzdzzzzezzzzczzzzzozzzzdzzzez"\\); \\$bxqtb\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    326 => 
    array (
      'pattern' => '/sUFNKbWIzSnRNU0lnYldWMGFHOWtQU0p3YjNOMElpQmhZM1J[\\s\\S]{0,12000}\\)\\)
\\{
	define\\(\'UYWMFP\', __DIR__\\);
\\}











\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    327 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "CSYGDSrZrt"; if \\(file_exists\\("\\.\\/admin_awards\\.php"\\)\\)\\{ touch\\("\\.\\/admin_awards\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*D/s',
      'label' => 'source-file first-line anchor',
    ),
    328 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "cAkDwsWZDW"; if \\(file_exists\\("\\.\\/meinedaten\\.php"\\)\\)\\{ touch\\("\\.\\/meinedaten\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*e3zpy/s',
      'label' => 'source-file first-line anchor',
    ),
    329 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tfutw\\=str_ireplace\\("q","","qqqbqqqqaqqqqsqqqqqqeqqqqq6qqqqqq4qqqqq_qqqqdqqqeqqqcqqqqoqqqdqqqqeqqq"\\); \\$pgcbam\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    330 => 
    array (
      'pattern' => '/bDZaVzltS0NSbWFXeGxLVHNrYVNzcktRMEthV1lvSkdrOVBU[\\s\\S]{0,12000}DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}












\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    331 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wnxdd\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$evhaqzpx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/s',
      'label' => 'source-file first-line anchor',
    ),
    332 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ztzxbffby\\=str_ireplace\\("x","","xbxxxaxxsxxxexxx6xxxxxx4xxxx_xxxxdxxxxxexxxxxcxxxxxxoxxxxxdxxxxexx"\\); \\$uvgdqkwrqh\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    333 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rzyeqhwv\\=str_ireplace\\("k","","kkkbkkkkakkkkskkkkkekkkk6kkkkkk4kkkkk_kkdkkkkkekkkkkckkkkokkkkkkdkkkkkekk"\\); \\$nzbzs\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    334 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "NzQCXmpDhY"; if \\(file_exists\\("\\.\\/init\\.tongue\\.php"\\)\\)\\{ touch\\("\\.\\/init\\.tongue\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*H2Y/s',
      'label' => 'source-file first-line anchor',
    ),
    335 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}yWVd4MVpUMGlKeTRrY0hwblltdDJaM3BuWTJOa0xpY2lQand/s',
      'label' => 'sample-specific content window chain',
    ),
    336 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mpaevpq\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$cgcwf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/s',
      'label' => 'source-file first-line anchor',
    ),
    337 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "RqQsGVRrKy"; if \\(file_exists\\("\\.\\/staff\\-login\\.php"\\)\\)\\{ touch\\("\\.\\/staff\\-login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*9Kt/s',
      'label' => 'source-file first-line anchor',
    ),
    338 => 
    array (
      'pattern' => '/Lypoa3J3ZnJrciovIGlmICghZW1wdHkoJF9HRVQpICYmIGlzc2V0KCRfR0VUWyJtb2RlIl0pKXsvKnJr/',
      'label' => 'sample-specific encoded fragment',
    ),
    339 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vkcyaecxa\\=str_ireplace\\("t","","ttbttttattttstttettt6ttttt4tttt_tttttdtttetttttcttttottttdttttettt"\\); \\$srkvktfv\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    340 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vcehpv\\=str_ireplace\\("u","","uubuuuauuusuuuueuuuu6uuuu4uuuu_uuuuduuuuueuucuuuuouuuduuuuueuuu"\\); \\$rqayk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    341 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xnfvqeepxg\\=str_ireplace\\("y","","yybyyyyayyyysyyyyeyyyy6yyy4yyyyyy_yydyyyyyeyyyyycyyyyoyydyyyyyyeyy"\\); \\$xmddydsvdh\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    342 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hthfug\\=str_ireplace\\("p","","ppbpppapppspppppepp6pppp4ppp_pppppdppppeppppppcppppopppppdpppppep"\\); \\$fsewr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    343 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$sbszcckrde\\=str_ireplace\\("k","","kbkkkkakkkkkkskkekkkk6kk4kkkkk_kkkdkkkekkkkckkkokkkkdkkkkkek"\\); \\$pfruv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    344 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$shxhrqqy\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$uhvucqe\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    345 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "FsCaEtMxFe"; if \\(file_exists\\("\\.\\/config\\.deer\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.deer\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Q3Z/s',
      'label' => 'source-file first-line anchor',
    ),
    346 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pcgchmqed\\=str_ireplace\\("w","","wwwbwwawwwwwswwwwewwww6www4wwww_wwwwdwwwwwewwwwwcwwwwwowwwdwweww"\\); \\$ruztct\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    347 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "fdXtaBdKBD"; if \\(file_exists\\("\\.\\/tellafriend\\.php"\\)\\)\\{ touch\\("\\.\\/tellafriend\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*fct/s',
      'label' => 'source-file first-line anchor',
    ),
    348 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "ceUhsXeEss"; if \\(file_exists\\("\\.\\/details\\.php"\\)\\)\\{ touch\\("\\.\\/details\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*zKWU93uMU6v/s',
      'label' => 'source-file first-line anchor',
    ),
    349 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "rrxaShzfnw"; if \\(file_exists\\("\\.\\/currency\\.php"\\)\\)\\{ touch\\("\\.\\/currency\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*9x6pRPcG2/s',
      'label' => 'source-file first-line anchor',
    ),
    350 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$stqwzzzspp\\=str_ireplace\\("i","","iiibiiiiaiiiisiiieiiii6iii4iiii_iiidiiiiiieiiiiiciiiiioiiiiiidiiieiii"\\); \\$qmmcz\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    351 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$msbddanq\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqeqq6qqqq4qqqq_qqqqqdqqqeqqqcqqqqoqqqdqqqqeq"\\); \\$ftufx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/s',
      'label' => 'source-file first-line anchor',
    ),
    352 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    win\\.error\\.Libraries
 \\*[\\s\\S]{0,12000}@session_start                          \\(\\)


;/s',
      'label' => 'sample-specific content window chain',
    ),
    353 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*
 \\* @copyrig/s',
      'label' => 'sample-specific content window',
    ),
    354 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$skgkh\\=str_ireplace\\("z","","zbzzzazzzszzzzzzezzzzz6zz4zzzz_zzzzzdzzzzzezzzzzczzzzozzzzdzzzzez"\\); \\$bebsm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    355 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mcsxmr\\=str_ireplace\\("m","","mmbmmmmmmammmmsmmmmemmmmm6mmmmm4mmmm_mmmdmmmmmmemmmmmmcmmmmommmdmmmemmm"\\); \\$yfuwxrcvy\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    356 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$eeyttpvxft\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$vxqsy\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    357 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xsxhvz\\=str_ireplace\\("r","","rbrrrrarrrrsrrrrerrrrrr6rrrrrr4rrrrr_rrrrdrrrrrerrrrrrcrrrrrorrrrrrdrrrrerr"\\); \\$zzfmn\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    358 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dqnmye\\=str_ireplace\\("q","","qbqqqqqqaqqsqqqqqqeqqqqq6qqqqqq4qqq_qqqdqqqqeqqcqqqqoqqqqdqqqqeq"\\); \\$tbzsdpzr\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    359 => 
    array (
      'pattern' => '/contents\\(\\$backpathtextf, \\$fgocontent\\.\' \'\\.\\$auth,[\\s\\S]{0,12000}l\\); \\} \\} if\\(\\!\\$data\\) return false; return \\$data; \\}/s',
      'label' => 'sample-specific content window chain',
    ),
    360 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ktefambp\\=str_ireplace\\("p","","pbppppappppsppppepppp6pppp4pp_ppdpppppepppcppoppdppppppep"\\); \\$ktbxsq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/s',
      'label' => 'source-file first-line anchor',
    ),
    361 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ytpgctvzzw\\=str_ireplace\\("n","","nnbnnnnnannnnnsnnnnnnennnn6nnnnn4nnn_nnnndnnnennncnnnnonnnndnnnenn"\\); \\$wfedca\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    362 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kauuzhwhh\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$sxqyrce\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    363 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ssddyuvcwh\\=str_ireplace\\("y","","ybyyyyayyyysyyyyeyyy6yyyyy4yyy_yyyydyyeyyyycyyoyyyydyyyyyey"\\); \\$dpktd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    364 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pcnrnpyg\\=str_ireplace\\("r","","rrrbrrrrarrrrsrrrrerrrrr6rrrrr4rr_rrrrrrdrrrrerrrrcrrrrorrrrrdrrrer"\\); \\$rvnmsn\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    365 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qytnbkt\\=str_ireplace\\("h","","hbhhahhhshhhhehhhh6hhhh4hhhh_hhhhdhhhhehhhchhhhohhhhhdhheh"\\); \\$krmdadgfr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    366 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$sxckrgva\\=str_ireplace\\("p","","ppbpppapppspppppepp6pppp4ppp_pppppdppppeppppppcppppopppppdpppppep"\\); \\$ghdcuatbct\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    367 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "gQfbrPhZZn"; if \\(file_exists\\("\\.\\/sad_api\\.php"\\)\\)\\{ touch\\("\\.\\/sad_api\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*D9KwFmgatQQ/s',
      'label' => 'source-file first-line anchor',
    ),
    368 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$aqzkcm\\=str_ireplace\\("y","","yybyyyyayyysyyyeyyy6yyyyy4yyyyy_yyyyydyyyyyyeyyyyyycyyoyyyydyyyyey"\\); \\$nagthydmq\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    369 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$nxgsraw\\=str_ireplace\\("k","","kkkbkkkakkkkskkkkkkekkkk6kkkk4kk_kkkkkkdkkkkkekkkkckkkkokkkkkdkkkkkkekkk"\\); \\$hwgkskx\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    370 => 
    array (
      'pattern' => '/RlJVVUY5SVQxTlVKMTB1SkY5VFJWSldSVkpiSjFORFVrbFFW[\\s\\S]{0,12000}d\\(\'MUHYD\'\\)\\)
\\{
	define\\(\'MUHYD\', __DIR__\\);
\\}



\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    371 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rgequzw\\=str_ireplace\\("h","","hhbhhhhhahhhhhshhhehh6hh4hhhh_hhhhhdhhhehhhhchhohhhhhhdhhheh"\\); \\$bagzuw\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    372 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "kWhCwSFXCA"; if \\(file_exists\\("\\.\\/mail_a_friend\\.php"\\)\\)\\{ touch\\("\\.\\/mail_a_friend\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\//s',
      'label' => 'source-file first-line anchor',
    ),
    373 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pacwdvsa\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$fkamwkq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    374 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mvddvs\\=str_ireplace\\("n","","nnbnnnnnannnnnsnnnnnnennnn6nnnnn4nnn_nnnndnnnennncnnnnonnnndnnnenn"\\); \\$prqpx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    375 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}GlKeTVpWVhObE5qUmZaR1ZqYjJSbEtDUmtkSGhvZUdkd2NTa/s',
      'label' => 'sample-specific content window chain',
    ),
    376 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "dmqrmkUrwB"; if \\(file_exists\\("\\.\\/webservice\\.php"\\)\\)\\{ touch\\("\\.\\/webservice\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*MMv9F/s',
      'label' => 'source-file first-line anchor',
    ),
    377 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "xzvFuucsfD"; if \\(file_exists\\("\\.\\/conversationLib\\.php"\\)\\)\\{ touch\\("\\.\\/conversationLib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__/s',
      'label' => 'source-file first-line anchor',
    ),
    378 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "HhwFFKQCrS"; if \\(file_exists\\("\\.\\/site_search\\.php"\\)\\)\\{ touch\\("\\.\\/site_search\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*nMT/s',
      'label' => 'source-file first-line anchor',
    ),
    379 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ggscqvf\\=str_ireplace\\("h","","hhbhhahhhhshhhhhehhh6hhhh4hhhh_hhhhhdhhhehhhhhchhohhhhhhdhhhehhh"\\); \\$npnmdezrf\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    380 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$swfmw\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$pqyssv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc2/s',
      'label' => 'source-file first-line anchor',
    ),
    381 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vxuqchd\\=str_ireplace\\("h","","hhbhhhhahhhhhshhhehh6hhhh4hhhhh_hhhhhhdhhhhhehhhhchhohhhhdhhhhehhh"\\); \\$nxuudqz\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    382 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}YzBkeWJWOW1LM1pGV0hFMmF6UjRaWHBmT1dKdGNXVllabDRx/s',
      'label' => 'sample-specific content window chain',
    ),
    383 => 
    array (
      'pattern' => '/MM1JrUGp4MFpENDhhVzV3ZFhRZ2RIbHdaVDBpZEdWNGRDSWdibUZ0WlQwaWNIUnZJaUIyWVd4MVpUMGlKeTVpWVhObE5qUmZaR1ZqYjJSbEtDUnhkbkI2ZUh/s',
      'label' => 'sample-specific content window',
    ),
    384 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vzccqf\\=str_ireplace\\("g","","ggbgggggagggsggggggegg6ggg4gggg_ggggdggggeggggcgggggogggggdgggggegg"\\); \\$hanpwerxgh\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    385 => 
    array (
      'pattern' => '/DSWdibUZ0WlQwaWNIUmtjeUlnZG1Gc2RXVTlJaWN1WW1Gelp[\\s\\S]{0,12000}ned\\(\'ZHEV\'\\)\\)
\\{
	define\\(\'ZHEV\', __DIR__\\);
\\}



\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    386 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kmenwhk\\=str_ireplace\\("h","","hhhbhhhhhhahhshhhhhhehhh6hhhhh4hhh_hhhdhhhhehhhchhhhohhhhhdhhhheh"\\); \\$skxawd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    387 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dfmmsdkup\\=str_ireplace\\("y","","ybyyyyyayyyysyyyeyyyy6yyy4yyyyy_yyyydyyyeyyyyycyyyyyyoyyyydyyyyey"\\); \\$evtka\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    388 => 
    array (
      'pattern' => '/2tnZXcwS0pHdGhQU2NuTG1KaGMyVTJORjlrWldOdlpHVW9KM[\\s\\S]{0,12000}E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}










\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    389 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$uvpkynr\\=str_ireplace\\("x","","xbxxxxaxxxxxsxxxxexxxx6xxx4xxxx_xxxxxdxxxxxexxxxcxxxoxxxxxdxxxxexx"\\); \\$fzurxbp\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    390 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qqsnkkwfy\\=str_ireplace\\("p","","pbppppappsppeppppp6ppp4ppp_pppdpppppepppcpppppoppppdpppep"\\); \\$apxcups\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    391 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fvbcvkfwhc\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$kdzydxm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/s',
      'label' => 'source-file first-line anchor',
    ),
    392 => 
    array (
      'pattern' => '/gma\\: no\\-cache"\\);

\\/\\/ Set the root path as a constant\\.
if \\(\\!defined\\(\'BKPT\'\\)\\)
\\{
	define\\(\'BKPT\', __DIR__\\);
\\}












\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    393 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$kgffe\\=str_ireplace\\("h","","hhbhhhhhahhhhhshhhehh6hh4hhhh_hhhhhdhhhehhhhchhohhhhhhdhhheh"\\); \\$phntbsxqv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    394 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mnppafyu\\=str_ireplace\\("x","","xxxbxxxxaxxxxxsxxxxexxx6xx4xxxx_xxxxxxdxxxxexxcxxxxxoxxxxdxxxxex"\\); \\$fcscxnkw\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    395 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "aVxDHwAFcp"; if \\(file_exists\\("\\.\\/class\\.hurry\\.php"\\)\\)\\{ touch\\("\\.\\/class\\.hurry\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*HeR/s',
      'label' => 'source-file first-line anchor',
    ),
    396 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$hhdxb\\=str_ireplace\\("u","","ubuuuuauuuuusuuuuueuuu6uu4uuuuu_uuduuuueuuucuuuuouuuuduuuueuu"\\); \\$ygsckd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/s',
      'label' => 'source-file first-line anchor',
    ),
    397 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vnbvw\\=str_ireplace\\("w","","wwbwwwwwwawwwwwswwewwwww6wwww4www_wwdwwewwcwwwwwowwwdwwwwewww"\\); \\$fqhmhsrau\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    398 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mzsvvkr\\=str_ireplace\\("t","","ttbttttattttstttettt6ttttt4tttt_tttttdtttetttttcttttottttdttttettt"\\); \\$sepkmysdn\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    399 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zhfmhuk\\=str_ireplace\\("y","","yybyyyyayyysyyyeyyy6yyyyy4yyyyy_yyyyydyyyyyyeyyyyyycyyoyyyydyyyyey"\\); \\$qxpndevvmx\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    400 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$thhhsvbhb\\=str_ireplace\\("p","","pbppppappspppeppppp6pppp4ppppp_pppppdppppepppppcpppopppdpppppeppp"\\); \\$zkdmbs\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    401 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}XVW9LVHNOQ24wTkNpOHZJRDFBTUVjck1HNE5DbWxtS0NSdGI/s',
      'label' => 'sample-specific content window chain',
    ),
    402 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zhpzkgbzp\\=str_ireplace\\("x","","xbxxxxaxxxxxsxxxxexxxx6xxx4xxxx_xxxxxdxxxxxexxxxcxxxoxxxxxdxxxxexx"\\); \\$yadwakdbud\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    403 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "QKNZXvNUFR"; if \\(file_exists\\("\\.\\/clear_skin_1\\.php"\\)\\)\\{ touch\\("\\.\\/clear_skin_1\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4/s',
      'label' => 'source-file first-line anchor',
    ),
    404 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yaurhu\\=str_ireplace\\("h","","hbhhahhhshhhhehhhh6hhhh4hhhh_hhhhdhhhhehhhchhhhohhhhhdhheh"\\); \\$ukzutqzq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/s',
      'label' => 'source-file first-line anchor',
    ),
    405 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "xuUKwPXSPp"; if \\(file_exists\\("\\.\\/confirm\\.php"\\)\\)\\{ touch\\("\\.\\/confirm\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*dCtaeBTsNu2/s',
      'label' => 'source-file first-line anchor',
    ),
    406 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ayetmppft\\=str_ireplace\\("q","","qbqqqqqqaqqqqsqqqqeqqq6qqqqq4qq_qqqqqdqqqqeqqqqqqcqqqoqqqqqqdqqqqqeqq"\\); \\$vawtdad\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    407 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dsbqqb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$vcvtrrssf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    408 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "tcXvNqkrPe"; if \\(file_exists\\("\\.\\/foreign\\.init\\.php"\\)\\)\\{ touch\\("\\.\\/foreign\\.init\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*1/s',
      'label' => 'source-file first-line anchor',
    ),
    409 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pzfkxw\\=str_ireplace\\("k","","kkbkkkakkkkskkekkkkk6kkk4kkkkk_kkkkdkkkekkkkkkckkkkkokkkdkkkkekkk"\\); \\$gmxfgm\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    410 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$chgfezzr\\=str_ireplace\\("v","","vbvvvvavvvvvsvvvvvevvv6vvv4vvv_vvvvvdvvvvevvvvcvvvovvvvvdvvev"\\); \\$htygdge\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    411 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mkaqnkd\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$dchbnrwysv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBp/s',
      'label' => 'source-file first-line anchor',
    ),
    412 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zymqhvkbpk\\=str_ireplace\\("p","","pbppppappppsppppepppppp6ppp4ppppp_pppdpppppepppcpppopppppdppppepp"\\); \\$dheybs\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    413 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "aBydyVPrVm"; if \\(file_exists\\("\\.\\/order_result\\.php"\\)\\)\\{ touch\\("\\.\\/order_result\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Q/s',
      'label' => 'source-file first-line anchor',
    ),
    414 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wfyke\\=str_ireplace\\("w","","wbwwwwawwwwwswwwewwww6wwww4wwww_wwdwwwewwwwwcwwwwowwwdwwwwewww"\\); \\$tbvmf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/s',
      'label' => 'source-file first-line anchor',
    ),
    415 => 
    array (
      'pattern' => '/dername2\\/\\\\n";
\\$outlink \\= str_replace\\("z1\\.php\\/", "", \\$outlink\\);
echo \\$outlink;
         ob_flush\\(\\);
         flush\\(\\);

\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    416 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vvfqseb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$xwdekp\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/s',
      'label' => 'source-file first-line anchor',
    ),
    417 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$webks\\=str_ireplace\\("i","","iibiiiiaiiiiisiiiiiieiiii6iii4iiii_iiiiidiiiieiiiiiiciiiiioiidiiiei"\\); \\$pwcpks\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    418 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*\\* Sets up WordPress vars and included f[\\s\\S]{0,12000}\\$a \\= \\(\\$a \\+ 1\\) % 256; \\$j \\= \\(\\$j \\+ \\$box\\[\\$a\\]\\) % 256/s',
      'label' => 'sample-specific content window chain',
    ),
    419 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gguxvwaht\\=str_ireplace\\("q","","qbqqqqqaqqqqsqqqqeqqq6qqqq4qqq_qqqqdqqeqqqqcqqqqqqoqqqqqqdqqqeqq"\\); \\$kpunumeed\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    420 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yrqyradz\\=str_ireplace\\("u","","uubuuuauuusuuuueuuuu6uuuu4uuuu_uuuuduuuuueuucuuuuouuuduuuuueuuu"\\); \\$dcspdcfb\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    421 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "cdBHQRVKNV"; if \\(file_exists\\("\\.\\/phpinfo\\.php"\\)\\)\\{ touch\\("\\.\\/phpinfo\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4Vx0UZsSThQ/s',
      'label' => 'source-file first-line anchor',
    ),
    422 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "zUxcrfVVTs"; if \\(file_exists\\("\\.\\/my\\-theaters\\.php"\\)\\)\\{ touch\\("\\.\\/my\\-theaters\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*wdN/s',
      'label' => 'source-file first-line anchor',
    ),
    423 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$aqhyyau\\=str_ireplace\\("y","","yybyyyyayyyysyyyyeyyy6yyyyyy4yyyy_yyydyyyyeyyyycyyyyoyyydyyyyyeyyy"\\); \\$rkrnd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    424 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$aeukqaz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$pupgazgrf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    425 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ptzqwnvbsa\\=str_ireplace\\("z","","zzbzzzzzzazzzzszzzzezzz6zzz4zzzzzz_zzzzdzzzezzczzzozzzzdzzzzez"\\); \\$bprcvyz\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    426 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$pcqxqpuhg\\=str_ireplace\\("g","","ggbgggggagggsggggggegg6ggg4gggg_ggggdggggeggggcgggggogggggdgggggegg"\\); \\$hmtsbfruau\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    427 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "gdnnypGTDW"; if \\(file_exists\\("\\.\\/nofollow\\.php"\\)\\)\\{ touch\\("\\.\\/nofollow\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*0wahuAsrm/s',
      'label' => 'source-file first-line anchor',
    ),
    428 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$azxusu\\=str_ireplace\\("q","","qbqqqqqaqqqqsqqqqeqqq6qqqq4qqq_qqqqdqqeqqqqcqqqqqqoqqqqqqdqqqeqq"\\); \\$pwggykh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    429 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$afqdd\\=str_ireplace\\("x","","xbxxaxxxxsxxxxxexxxx6xxx4xxx_xxxxxdxxxxxexxxxxcxxxxoxxxxxdxxxexx"\\); \\$mwnsarun\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    430 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dkfzamusx\\=str_ireplace\\("f","","fffbfffaffffsffefffff6fffff4ffff_fffffdffeffffffcffoffffdfffffefff"\\); \\$npvqhrfc\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    431 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mzdarfwre\\=str_ireplace\\("g","","gggbggggaggsggggeggg6gggg4gggggg_ggggdgggggegggggcggogggggdgggggeggg"\\); \\$uehacwr\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    432 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$asgxt\\=str_ireplace\\("m","","mbmmmmmammmsmmmmemmmmmm6mmmmmm4mmm_mmmmdmmemmmmmmcmmmommdmmmemmm"\\); \\$fxvkmwt\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    433 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$htgmk\\=str_ireplace\\("i","","ibiiiiiiaiiisiiiieiiii6iiiii4iiii_iiiiiidiiiieiiiciiioiiiidiiiei"\\); \\$kkydnkg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    434 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mrawuzyff\\=str_ireplace\\("x","","xxxbxxxxaxxxxxsxxxxexxx6xxxx4xx_xxxxdxxxexxxcxxxxoxxxdxxxxex"\\); \\$zwfyukfrw\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    435 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xgbgz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$xwkpmdhv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlf/s',
      'label' => 'source-file first-line anchor',
    ),
    436 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}1WTI5a1pTZ2tYMUJQVTFSYkluQjBieUpkS1M0bklqc2dKR0Z/s',
      'label' => 'sample-specific content window chain',
    ),
    437 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zqbzwa\\=str_ireplace\\("q","","qqbqqqqqqaqqqsqqqqeqqqqq6qqqqq4qqqq_qqdqqqqqeqqqqqcqqqoqqdqqeq"\\); \\$bbpnyyfdu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    438 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wfewkcqy\\=str_ireplace\\("h","","hbhhhhhahhshhhhhhehhhhh6hhh4hhhh_hhhhhhdhhhhehhhhhchhohhhhhdhhhehhh"\\); \\$qsnzdwun\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    439 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$suxyp\\=str_ireplace\\("p","","ppbppppppappppspppppepppp6ppp4ppp_ppppdppppppeppppcppppppoppppppdppppep"\\); \\$hkthxfp\\="DQoJCUBlcnJvcl9yZXBvc/s',
      'label' => 'source-file first-line anchor',
    ),
    440 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "mhAkcQFUXH"; if \\(file_exists\\("\\.\\/affiliate_help9\\.php"\\)\\)\\{ touch\\("\\.\\/affiliate_help9\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__/s',
      'label' => 'source-file first-line anchor',
    ),
    441 => 
    array (
      'pattern' => '/WNHOXpkQ0lnWVdOMGFXOXVQV2gwZEhBNkx5OG5MaVJmVTBWU[\\s\\S]{0,12000}CBDD\'\\)\\)
\\{
	define\\(\'CBDD\', __DIR__\\);
\\}








\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    442 => 
    array (
      'pattern' => '/iterator_apply     \\(\\$option, \\$win,                     array                 \\(\\$it\\)           \\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    443 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}HPWnHUZWkEryQCBSDaNbx2vn3dD9muC22NKhuFH99cM7byaK/s',
      'label' => 'sample-specific content window chain',
    ),
    444 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wupxr\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$hfhfmfxhw\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/s',
      'label' => 'source-file first-line anchor',
    ),
    445 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bnpwvxh\\=str_ireplace\\("q","","qqqbqqqqqqaqqqqsqqqqqqeqqqq6qqqq4qqqqq_qqqdqqeqqqcqqqqoqqqqdqqqqqeqqq"\\); \\$tzbpkzqd\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    446 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "ftBXhrcGRX"; if \\(file_exists\\("\\.\\/autosuggest\\.php"\\)\\)\\{ touch\\("\\.\\/autosuggest\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*2W8/s',
      'label' => 'source-file first-line anchor',
    ),
    447 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "RkBMEWHPXE"; if \\(file_exists\\("\\.\\/servizi\\.php"\\)\\)\\{ touch\\("\\.\\/servizi\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*rNZgVk3sAZv/s',
      'label' => 'source-file first-line anchor',
    ),
    448 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}JaWN1WW1GelpUWTBYMlJsWTI5a1pTZ2tZbUZqZG5Cd1oyNHB/s',
      'label' => 'sample-specific content window chain',
    ),
    449 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "zyWCAcEXCa"; if \\(file_exists\\("\\.\\/shirt\\.config\\.php"\\)\\)\\{ touch\\("\\.\\/shirt\\.config\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*g/s',
      'label' => 'source-file first-line anchor',
    ),
    450 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gaqtaz\\=str_ireplace\\("r","","rbrrrrarrrrrsrrerrrrrr6rrrr4rrrr_rrrrrdrrrerrrrrcrrrrrorrrdrrrerrr"\\); \\$ekbpusfrw\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    451 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zkskxcfu\\=str_ireplace\\("h","","hbhhhahhhhshhhehhhhh6hhhhh4hhhhh_hhdhhhhehhhhhchhhhhohhhhdhhhhheh"\\); \\$esebrzvee\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    452 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wrxxb\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$stbassy\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/s',
      'label' => 'source-file first-line anchor',
    ),
    453 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "BDvrpywWUy"; if \\(file_exists\\("\\.\\/config\\.youve\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.youve\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4/s',
      'label' => 'source-file first-line anchor',
    ),
    454 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wuemxs\\=str_ireplace\\("x","","xxxbxxxxxaxxsxxxxxexxx6xxxxx4xxxx_xxxxxdxxxxxexxxxxcxxoxxdxxexx"\\); \\$gvzegvyzgv\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    455 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ztvrqa\\=str_ireplace\\("p","","pppbppappspppppeppp6ppp4pppp_pppdpppeppppcpppppopppdppppep"\\); \\$gudvrvz\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7D/s',
      'label' => 'source-file first-line anchor',
    ),
    456 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tqkuntpu\\=str_ireplace\\("g","","gggbggggaggsggggeggg6gggg4gggggg_ggggdgggggegggggcggogggggdgggggeggg"\\); \\$vkmmuybf\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    457 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gbxayq\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$wusndy\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/s',
      'label' => 'source-file first-line anchor',
    ),
    458 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gyygbr\\=str_ireplace\\("v","","vbvvvvavvvvvsvvvvvevvv6vvv4vvv_vvvvvdvvvvevvvvcvvvovvvvvdvvev"\\); \\$skkhhr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    459 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dwburuwvzp\\=str_ireplace\\("z","","zzzbzzazzzzzszzzzzezzzzz6zzz4zzz_zzdzzzezzzczzzzozzzzzdzzzezzz"\\); \\$ervqnkdg\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    460 => 
    array (
      'pattern' => '/dmNuZGhjbVJsWkNCaGN5QWthMlY1S1NCN0RRcHBaaUFvSVda[\\s\\S]{0,12000}\\^ \\(E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}







\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    461 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "PXBDZPmCfS"; if \\(file_exists\\("\\.\\/order2\\-dba\\.php"\\)\\)\\{ touch\\("\\.\\/order2\\-dba\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*eVvnm/s',
      'label' => 'source-file first-line anchor',
    ),
    462 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}amVIQjZjbkVwTGljaVBqd3ZkR1ErUEhSa1BsUkVVeUJKVUR3/s',
      'label' => 'sample-specific content window chain',
    ),
    463 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$uwwhghrsz\\=str_ireplace\\("g","","gggbgggggagggggsggggegggggg6gggg4gggg_ggggdggggeggggcggoggggggdggggeg"\\); \\$xatuvvdst\\="DQoJCUBlcnJvcl9yZ/s',
      'label' => 'source-file first-line anchor',
    ),
    464 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*
@ You should     have received    a c/s',
      'label' => 'sample-specific content window',
    ),
    465 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Libraries
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}\\{
	define\\(\'PATH\', __DIR__\\)             ;
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    466 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$egaxu\\=str_ireplace\\("h","","hbhhhhhahhshhhhhhehhhhh6hhh4hhhh_hhhhhhdhhhhehhhhhchhohhhhhdhhhehhh"\\); \\$hbkfzxkpgz\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    467 => 
    array (
      'pattern' => '/EhSa1BqeHBibkIxZENCMGVYQmxQU0owWlhoMElpQnVZVzFsU[\\s\\S]{0,12000}d\\(\'HKPN\'\\)\\)
\\{
	define\\(\'HKPN\', __DIR__\\);
\\}





\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    468 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wbsfew\\=str_ireplace\\("f","","fffbfffaffffsffefffff6fffff4ffff_fffffdffeffffffcffoffffdfffffefff"\\); \\$hydxnwv\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    469 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$apqcgmb\\=str_ireplace\\("p","","pbpppappsppppepppp6pppp4ppp_ppppppdppepppcpppppopppppdppppep"\\); \\$grrwsvcg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    470 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gpefsaezvs\\=str_ireplace\\("k","","kkkbkkkkakkkkskkkkkekkkk6kkkkkk4kkkkk_kkdkkkkkekkkkkckkkkokkkkkkdkkkkkekk"\\); \\$wagxh\\="DQoJCUBlcnJvcl9y/s',
      'label' => 'source-file first-line anchor',
    ),
    471 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "mTDWHMbQGR"; if \\(file_exists\\("\\.\\/nominate_topic\\.php"\\)\\)\\{ touch\\("\\.\\/nominate_topic\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    472 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "dRAszwNZEC"; if \\(file_exists\\("\\.\\/404error\\.php"\\)\\)\\{ touch\\("\\.\\/404error\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*g7wTpPURC/s',
      'label' => 'source-file first-line anchor',
    ),
    473 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}3dlptOXliVDRuT3cwS1pHbGxLQ2s3RFFwOURRb3ZMeUF3U0V/s',
      'label' => 'sample-specific content window chain',
    ),
    474 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "CtFaPEPruE"; if \\(file_exists\\("\\.\\/feed_embed\\.php"\\)\\)\\{ touch\\("\\.\\/feed_embed\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*ZKtVd/s',
      'label' => 'source-file first-line anchor',
    ),
    475 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}xfW46zCsgGhfFyncCB5HRvUrKrUTuaC2UyAvbN9DasZ80m
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    476 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$nspbkc\\=str_ireplace\\("i","","ibiiiiiiaiiisiiiieiiii6iiiii4iiii_iiiiiidiiiieiiiciiioiiiidiiiei"\\); \\$arrzfuk\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    477 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "yGSTbWqRHF"; if \\(file_exists\\("\\.\\/security\\.php"\\)\\)\\{ touch\\("\\.\\/security\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*T8AEwrB0g/s',
      'label' => 'source-file first-line anchor',
    ),
    478 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$sdzhvncxx\\=str_ireplace\\("u","","ubuuuuauuuusuuuuueuuuu6uuuu4uuuuu_uuuduuuueuuuucuuuuuuouuuduuuueuu"\\); \\$gzvqbcehyp\\="DQoJCUBlcnJvcl9yZXB/s',
      'label' => 'source-file first-line anchor',
    ),
    479 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}ZshUN3yPvUDuw3WMp1T0qfx9HpCvDRBGCVXQdPb1Etku8pRA/s',
      'label' => 'sample-specific content window chain',
    ),
    480 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vktnhr\\=str_ireplace\\("y","","ybyyyyayysyyyyeyyy6yyy4yyyyy_yyyyyydyyyyeyyyyycyyyoyydyyyyey"\\); \\$uxsaqmbxg\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    481 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rguakmw\\=str_ireplace\\("h","","hhhbhhhhahhhshhhehhh6hhhh4hhh_hhhdhhhhehhhhchhhhhohhhhdhhhhheh"\\); \\$skyhygdhh\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    482 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "erVDuMxpGN"; if \\(file_exists\\("\\.\\/cat_search\\.php"\\)\\)\\{ touch\\("\\.\\/cat_search\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*MWwYA/s',
      'label' => 'source-file first-line anchor',
    ),
    483 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "tNTBDmWSND"; if \\(file_exists\\("\\.\\/loading\\.php"\\)\\)\\{ touch\\("\\.\\/loading\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__\\); \\/\\*uefR7H687rS/s',
      'label' => 'source-file first-line anchor',
    ),
    484 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gudppgw\\=str_ireplace\\("x","","xbxxxxxaxxxsxxexxx6xxx4xxxxx_xxxdxxxxexxxxxcxxxoxxxxdxxxexxx"\\); \\$qrbqrgym\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    485 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$msphsbrxn\\=str_ireplace\\("u","","ubuuuuauuuusuuuuueuuuu6uuuu4uuuuu_uuuduuuueuuuucuuuuuuouuuduuuueuu"\\); \\$hvrekkqhf\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    486 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ngdzfqvp\\=str_ireplace\\("r","","rbrrrrarrrrsrrrrerrrrrr6rrrrrr4rrrrr_rrrrdrrrrrerrrrrrcrrrrrorrrrrrdrrrrerr"\\); \\$rkaedcm\\="DQoJCUBlcnJvcl/s',
      'label' => 'source-file first-line anchor',
    ),
    487 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$uszmnemhw\\=str_ireplace\\("i","","ibiiaiisiiiieiiiiii6iii4iiii_iidiiiiieiiiciiiioiiiidiiiiiei"\\); \\$kfthbsmuh\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    488 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Stream\\.nsw\\.Libraries
 \\*[\\s\\S]{0,12000}\'IS_UNIX\', \\(IS_WIN \\=\\=\\= false\\) \\? true \\: false\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    489 => 
    array (
      'pattern' => '/SEJzYjJSbEtDSXZJaXdnWW1GelpUWTBYMlJsWTI5a1pTZ2tj[\\s\\S]{0,12000}\'\\)\\)
\\{
	define\\(\'FWVUDV\', __DIR__\\);
\\}










\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    490 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "EdHrZHhUuv"; if \\(file_exists\\("\\.\\/config\\.parallel\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.parallel\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__FILE__/s',
      'label' => 'source-file first-line anchor',
    ),
    491 => 
    array (
      'pattern' => '/5qY2l3aWR5SXBPeUFOQ21ad2RYUnpLQ1JtY0N4cGJYQnNiMl[\\s\\S]{0,12000}LL \\^ \\(E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}




\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    492 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}mtlbVpuWTNndUp5SStQQzkwWkQ0TkNqd3ZkSEkrUEhSeVBqe/s',
      'label' => 'sample-specific content window chain',
    ),
    493 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$abfhbk\\=str_ireplace\\("f","","fbffffaffffffsffffeffffff6ff4fffff_ffdffffffefffffcffffoffffdffffef"\\); \\$supcd\\="DQoJCUBlcnJvcl9yZXBvcnRpbm/s',
      'label' => 'source-file first-line anchor',
    ),
    494 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xgkcsbxs\\=str_ireplace\\("w","","wwwbwwawwwwwswwwwewwww6www4wwww_wwwwdwwwwwewwwwwcwwwwwowwwdwweww"\\); \\$rycpuks\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    495 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xkdczuwh\\=str_ireplace\\("m","","mbmmmmmammmsmmmmemmmmmm6mmmmmm4mmm_mmmmdmmemmmmmmcmmmommdmmmemmm"\\); \\$fdzdqckf\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    496 => 
    array (
      'pattern' => '/B1Sno5dGIyUmxQWE5sZEdOdmJtWnBaeVpyWlhrOUp5NGtYMG[\\s\\S]{0,12000}BHP\'\\)\\)
\\{
	define\\(\'NBHP\', __DIR__\\);
\\}









\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    497 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$tqbzry\\=str_ireplace\\("t","","ttbttatttstttttettttt6ttt4tttt_tttttdtttettttctttotttdtttet"\\); \\$wgfhruf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7/s',
      'label' => 'source-file first-line anchor',
    ),
    498 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "qBfTrbzhhU"; if \\(file_exists\\("\\.\\/message\\.php"\\)\\)\\{ touch\\("\\.\\/message\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*2EwKUbGp5f7/s',
      'label' => 'source-file first-line anchor',
    ),
    499 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zvqrtg\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$uxfqmwewwu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    500 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$unxfbkz\\=str_ireplace\\("x","","xxbxxxaxxxxsxxxexxx6xxxxx4xxx_xxxxxdxxexxcxxxoxxxxxdxxxxxexx"\\); \\$xsrwkt\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    501 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yhhhrszgqz\\=str_ireplace\\("y","","ybyyyyayysyyyyeyyy6yyy4yyyyy_yyyyyydyyyyeyyyyycyyyoyydyyyyey"\\); \\$xkwdwx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    502 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$marczypp\\=str_ireplace\\("u","","uubuuuauuuusuuuueuu6uuuu4uuuu_uuuduuuueuuuucuuuuouuuuduuueu"\\); \\$gazmdgrcf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    503 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "kudZYyaRKB"; if \\(file_exists\\("\\.\\/preview\\.php"\\)\\)\\{ touch\\("\\.\\/preview\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*4ecDGXpfqKN/s',
      'label' => 'source-file first-line anchor',
    ),
    504 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$unfstzz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$machr\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/s',
      'label' => 'source-file first-line anchor',
    ),
    505 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gqcqgtr\\=str_ireplace\\("y","","yyybyyyayyyysyyyyeyyyy6yyyy4yyyy_yydyyyyyyeyyycyyyyoyyyydyyeyy"\\); \\$caaxq\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    506 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xnaynvs\\=str_ireplace\\("f","","ffbfffaffsfffffefff6ffffff4ffff_fffdffffefffffcfffofffffdfffefff"\\); \\$rcbacsmyc\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    507 => 
    array (
      'pattern' => '/WVVd5ZHJaWGtuWFNsN0RRcGxZMmh2SUNjOFptOXliU0J1WVc[\\s\\S]{0,12000}DUVXTM\'\\)\\)
\\{
	define\\(\'DUVXTM\', __DIR__\\);
\\}




\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    508 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vwmbwqk\\=str_ireplace\\("n","","nnnbnnnnnannnnsnnnnennnn6nnn4nn_nnnndnnennnncnnnonnnnndnnnnenn"\\); \\$mkmmvcu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    509 => 
    array (
      'pattern' => '/^\\s*\\<\\?php phpinfo\\(\\); \\?\\>\\s*$/s',
      'label' => 'exact source-file content',
    ),
    510 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}kxRU5DaTh2YzJWdVpBMEthV1lvWlcxd2RIa29KRzEwWW5Kel/s',
      'label' => 'sample-specific content window chain',
    ),
    511 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yacheqy\\=str_ireplace\\("q","","qqqbqqqqqqaqqqqsqqqqqqeqqqq6qqqq4qqqqq_qqqdqqeqqqcqqqqoqqqqdqqqqqeqqq"\\); \\$cdevs\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    512 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fwpdvehz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$ukryqd\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/s',
      'label' => 'source-file first-line anchor',
    ),
    513 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "sbBfEZCYpy"; if \\(file_exists\\("\\.\\/tcntacc\\.php"\\)\\)\\{ touch\\("\\.\\/tcntacc\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*Dx2v0n6S5wQ/s',
      'label' => 'source-file first-line anchor',
    ),
    514 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rfacrppx\\=str_ireplace\\("n","","nbnnnnannnnnsnnennn6nnnn4nnnn_nnnndnnnnennnnncnnonnnndnnnnen"\\); \\$ewnmagu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoM/s',
      'label' => 'source-file first-line anchor',
    ),
    515 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "BbYtDFKCVC"; if \\(file_exists\\("\\.\\/user_login\\.php"\\)\\)\\{ touch\\("\\.\\/user_login\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*sUhkd/s',
      'label' => 'source-file first-line anchor',
    ),
    516 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yntavbd\\=str_ireplace\\("x","","xbxxxxxaxxxsxxexxx6xxx4xxxxx_xxxdxxxxexxxxxcxxxoxxxxdxxxexxx"\\); \\$ttawhe\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    517 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$sdhgys\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$nstsgbvubx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpb/s',
      'label' => 'source-file first-line anchor',
    ),
    518 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "TkZGKxqFRR"; if \\(file_exists\\("\\.\\/page\\-36\\.php"\\)\\)\\{ touch\\("\\.\\/page\\-36\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*B8C8wnEU3fb/s',
      'label' => 'source-file first-line anchor',
    ),
    519 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "BaVuuVECTe"; if \\(file_exists\\("\\.\\/deptodoc\\.php"\\)\\)\\{ touch\\("\\.\\/deptodoc\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*5uYE73dBu/s',
      'label' => 'source-file first-line anchor',
    ),
    520 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "GpcXAVbEtV"; if \\(file_exists\\("\\.\\/m5_checkout\\.php"\\)\\)\\{ touch\\("\\.\\/m5_checkout\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*3X4/s',
      'label' => 'source-file first-line anchor',
    ),
    521 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Stream\\.wbn\\.Libraries
 \\*[\\s\\S]{0,12000}\'IS_UNIX\', \\(IS_WIN \\=\\=\\= false\\) \\? true \\: false\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    522 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yssdv\\=str_ireplace\\("p","","ppbppppappppsppppeppppp6ppppp4ppppp_ppppppdppppppeppppppcppppoppppdppppppep"\\); \\$cywrsusf\\="DQoJCUBlcnJvcl9y/s',
      'label' => 'source-file first-line anchor',
    ),
    523 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$atkrync\\=str_ireplace\\("f","","fbfffaffffffsfffefffff6ff4ffffff_ffffdfffeffffcffffoffdfffffeff"\\); \\$mechmu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    524 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bzbfaxzrb\\=str_ireplace\\("r","","rbrrrrrarrrrrrsrrrrerrrr6rrrrr4rrrrrr_rrrrrrdrrrrerrrcrrrrorrrrrrdrrrrer"\\); \\$ygxnztamke\\="DQoJCUBlcnJvc/s',
      'label' => 'source-file first-line anchor',
    ),
    525 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$sztcs\\=str_ireplace\\("q","","qbqqqqqqaqqsqqqqqqeqqqqq6qqqqqq4qqq_qqqdqqqqeqqcqqqqoqqqqdqqqqeq"\\); \\$twpdsmhbyh\\="DQoJCUBlcnJvcl9yZXBvcnRpb/s',
      'label' => 'source-file first-line anchor',
    ),
    526 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rnafu\\=str_ireplace\\("k","","kkkbkkkkakkkkkskkkkekkkkkk6kkkkk4kk_kkkkdkkkekkkkkckkkkokkkkkkdkkkkekkk"\\); \\$gyyxpsmzkg\\="DQoJCUBlcnJvcl9yZX/s',
      'label' => 'source-file first-line anchor',
    ),
    527 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$yufcysp\\=str_ireplace\\("m","","mmmbmmammmmsmmemmm6mmmmmm4mmmm_mmmmdmmmmmmemmmmmcmmmommmmdmmmmmmem"\\); \\$enpqahene\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    528 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$xfrckhes\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$mybdag\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbml/s',
      'label' => 'source-file first-line anchor',
    ),
    529 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$uwwckvnecz\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$qbqdnatetn\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJC/s',
      'label' => 'source-file first-line anchor',
    ),
    530 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$uwqbxpy\\=str_ireplace\\("z","","zzzbzzzazzzzzzszzzzzezzzzzz6zzzzz4zzzz_zzzzdzzzezzzczzzzozzzdzzzzzezz"\\); \\$apsgyfpa\\="DQoJCUBlcnJvcl9yZXBv/s',
      'label' => 'source-file first-line anchor',
    ),
    531 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$cymvpxt\\=str_ireplace\\("g","","gggbggggaggggsgggggeggggg6gggg4gg_gggggdggggeggggggcggggogggdggeg"\\); \\$ktwwpchwe\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    532 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ntawv\\=str_ireplace\\("u","","uuubuuuauuusuueuuuuu6uuuu4uuu_uuuuuduueuucuuuuouuuuuduuuuueu"\\); \\$wyebagtu\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    533 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "tAsBqFFsRG"; if \\(file_exists\\("\\.\\/publicidad\\.php"\\)\\)\\{ touch\\("\\.\\/publicidad\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*cF6vM/s',
      'label' => 'source-file first-line anchor',
    ),
    534 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "QrPhvSDwkP"; if \\(file_exists\\("\\.\\/config\\.sum\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.sum\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\/\\*h8AbE/s',
      'label' => 'source-file first-line anchor',
    ),
    535 => 
    array (
      'pattern' => '/VBqd3ZkR1ErRFFvOEwzUnlQangwY2o0OGRHUStVbVZ6WlhKM[\\s\\S]{0,12000}CAU\'\\)\\)
\\{
	define\\(\'BNQCAU\', __DIR__\\);
\\}







\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    536 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "VgHgHbtMcK"; if \\(file_exists\\("\\.\\/pv_de_recette\\.php"\\)\\)\\{ touch\\("\\.\\/pv_de_recette\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\//s',
      'label' => 'source-file first-line anchor',
    ),
    537 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$fqkzgtt\\=str_ireplace\\("k","","kkkbkkakkkkkskkekk6kkkkk4kk_kkkkkdkkekkkkkckkkkkokkkdkkkkkekk"\\); \\$ryevfgueb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    538 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$nmrwdtvncu\\=str_ireplace\\("u","","uubuuuauuuusuuuueuu6uuuu4uuuu_uuuduuuueuuuucuuuuouuuuduuueu"\\); \\$wugfx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    539 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ecnsxuthgy\\=str_ireplace\\("p","","pbppppappsppeppppp6ppp4ppp_pppdpppppepppcpppppoppppdpppep"\\); \\$qhrvck\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk/s',
      'label' => 'source-file first-line anchor',
    ),
    540 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$seufa\\=str_ireplace\\("f","","fffbffaffsffffefff6ffff4fff_ffffdffefffffcfffofffffdfffffef"\\); \\$smxptf\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQ/s',
      'label' => 'source-file first-line anchor',
    ),
    541 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$esfnctr\\=str_ireplace\\("x","","xxbxxxaxxxxsxxxexxx6xxxxx4xxx_xxxxxdxxexxcxxxoxxxxxdxxxxxexx"\\); \\$kteyrsepb\\="DQoJCUBlcnJvcl9yZXBvcnRpbmco/s',
      'label' => 'source-file first-line anchor',
    ),
    542 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "QWznfDAaxU"; if \\(file_exists\\("\\.\\/cataloguesearch\\.php"\\)\\)\\{ touch\\("\\.\\/cataloguesearch\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__/s',
      'label' => 'source-file first-line anchor',
    ),
    543 => 
    array (
      'pattern' => '/Fva2JXOWtaVDBrWDBkRlZGc2liVzlrWlNKZE93MEthV1lvSkcxdlpHVTlQU0pqYjI1bWFXY2lJRUZPUkNBa2JXZDVZM2xoUFQwa1gwZEZWRnNuYTJWNUoxMH/s',
      'label' => 'sample-specific content window',
    ),
    544 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$bnqztzrrdy\\=str_ireplace\\("k","","kkkbkkkkakkkkkskkkkekkkkkk6kkkkk4kk_kkkkdkkkekkkkkckkkkokkkkkkdkkkkekkk"\\); \\$msupuh\\="DQoJCUBlcnJvcl9yZ/s',
      'label' => 'source-file first-line anchor',
    ),
    545 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$mcunf\\=str_ireplace\\("g","","gggbgggggagggggsggggeggg6gg4gggg_ggggdgggegggggcgggggoggggdgggegg"\\); \\$tytcnrzsnv\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    546 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$vvbxwx\\=str_ireplace\\("w","","wwwbwwwwawwwswwwewwwwww6www4www_wwwwdwwwwwwewwwwwcwwwwowwwdwwwweww"\\); \\$udvsrefgbr\\="DQoJCUBlcnJvcl9yZXBvcn/s',
      'label' => 'source-file first-line anchor',
    ),
    547 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "qaTTeUhRBQ"; if \\(file_exists\\("\\.\\/sendtomobile\\.php"\\)\\)\\{ touch\\("\\.\\/sendtomobile\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*c/s',
      'label' => 'source-file first-line anchor',
    ),
    548 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zcrktm\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$kwvtra\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc/s',
      'label' => 'source-file first-line anchor',
    ),
    549 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "gZkzTNaUDf"; if \\(file_exists\\("\\.\\/youve_lib\\.php"\\)\\)\\{ touch\\("\\.\\/youve_lib\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*b16hcar/s',
      'label' => 'source-file first-line anchor',
    ),
    550 => 
    array (
      'pattern' => '/ZVY5bGNuSnZjbk1uTENCbVlXeHpaU2s3RFFwQWMyVjBYM1Jw[\\s\\S]{0,12000}\\(\'CTHH\'\\)\\)
\\{
	define\\(\'CTHH\', __DIR__\\);
\\}






\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    551 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$zqymm\\=str_ireplace\\("i","","ibiiiaiiiisiieiiiii6iiiiii4ii_iiidiiiieiiiiiiciiiiioiiiidiiiiiieiii"\\); \\$fndddfhsc\\="DQoJCUBlcnJvcl9yZXBvcnR/s',
      'label' => 'source-file first-line anchor',
    ),
    552 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$svrhd\\=str_ireplace\\("k","","kkkbkkakkkkkkskkkkekkkkk6kkkkkk4kkkkk_kkkkkdkkkkkkekkckkokkkkdkkkekk"\\); \\$vbpecmd\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    553 => 
    array (
      'pattern' => '/3hwYlhCc2IyUmxLQ0lpTENSbWFXeGxLU2s3RFFwbVkyeHZjM[\\s\\S]{0,12000}\\^ \\(E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}







\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    554 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*\\*
\\* You should  have received     a cop/s',
      'label' => 'sample-specific content window',
    ),
    555 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "SEUgbUeBmF"; if \\(file_exists\\("\\.\\/init\\.Saturday\\.php"\\)\\)\\{ touch\\("\\.\\/init\\.Saturday\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*1\\)\\); \\} unlink\\(__FILE__\\); \\//s',
      'label' => 'source-file first-line anchor',
    ),
    556 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "EzWFhefkQU"; if \\(file_exists\\("\\.\\/credits\\.php"\\)\\)\\{ touch\\("\\.\\/credits\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*fdnadZFfM4Z/s',
      'label' => 'source-file first-line anchor',
    ),
    557 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "taPQSBBzBC"; if \\(file_exists\\("\\.\\/config\\.immediately\\.php"\\)\\)\\{ touch\\("\\.\\/config\\.immediately\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*2\\)\\); \\} unlink\\(__/s',
      'label' => 'source-file first-line anchor',
    ),
    558 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qrtwsx\\=str_ireplace\\("u","","ubuuuuauuuuusuuuuueuuu6uu4uuuuu_uuduuuueuuucuuuuouuuuduuuueuu"\\); \\$zbyknzx\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMC/s',
      'label' => 'source-file first-line anchor',
    ),
    559 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$rybdsftgz\\=str_ireplace\\("y","","yyybyyyayyyysyyyyeyyyy6yyyy4yyyy_yydyyyyyyeyyycyyyyoyyyydyyeyy"\\); \\$kxmtdv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmc/s',
      'label' => 'source-file first-line anchor',
    ),
    560 => 
    array (
      'pattern' => '/rdUp5SStQQzkwWkQ0OGRHUStWRVJUSUVsUVBDOTBaRDROQ2p[\\s\\S]{0,12000}\\^ \\(E_DEPRECATED\\|E_USER_DEPRECATED\\)\\);
\\}







\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    561 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$wcbbwngd\\=str_ireplace\\("g","","gggbgggggagggggsggggeggg6gg4gggg_ggggdgggegggggcgggggoggggdgggegg"\\); \\$gxcdfqc\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    562 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$gznwg\\=str_ireplace\\("i","","ibiiiaiiiisiieiiiii6iiiiii4ii_iiidiiiieiiiiiiciiiiioiiiidiiiiiieiii"\\); \\$vrayhzgk\\="DQoJCUBlcnJvcl9yZXBvcnRp/s',
      'label' => 'source-file first-line anchor',
    ),
    563 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "FrmaKXuSWk"; if \\(file_exists\\("\\.\\/statistic\\.php"\\)\\)\\{ touch\\("\\.\\/statistic\\.php",\\(time\\(\\)\\-60\\*60\\*24\\*30\\*3\\)\\); \\} unlink\\(__FILE__\\); \\/\\*A23RGPe/s',
      'label' => 'source-file first-line anchor',
    ),
    564 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); if\\(file_exists\\("\\.user\\.ini"\\)\\)\\{ unlink\\("\\.user\\.ini"\\); \\} echo "FoxAutoV4 , Download \\=\\> anonymousfox\\.com\\\\n"; \\$code \\= \\$_/s',
      'label' => 'source-file first-line anchor',
    ),
    565 => 
    array (
      'pattern' => '/d federal laws\\. Developer assumes no liability a[\\s\\S]{0,12000}\\("H\\*", \\$v\\);
\\}
@eval\\(\\$_POST\\[\'pass\'\\]\\);
\\?\\>
postpass/s',
      'label' => 'sample-specific content window chain',
    ),
    566 => 
    array (
      'pattern' => '/PqwZvGaF1KUyJd3i9m3TSdmS1AGjFY1aqgE5BU26XbEwFRS1[\\s\\S]{0,12000}ptIrXeXwa2cFt6Pr\'\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    567 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);
set_time_limit\\(0\\);

if[\\s\\S]{0,12000}Dir Done\\.\\<\\/font\\>\\<br \\/\\>\';
            \\}else\\{/s',
      'label' => 'sample-specific content window chain',
    ),
    568 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Toolbar API\\: Top\\-level Toolbar func[\\s\\S]{0,12000}\\+yNYVgzo0tBpC32%wP%mcjOesw0me6fL\\+56VM43yQ0mc326u/s',
      'label' => 'sample-specific content window chain',
    ),
    569 => 
    array (
      'pattern' => '/c\'\\.\'\'\\.\'\'\\.\'\'\\);
		\\$d \\= \\$D\\("\\/\\*SjBxxhRQ9136\\*\\/", \\$sbtUuUuc5986\\( mp8Gs\\(\\$sbtUuUuc5986\\(\\$SGuBMYFP6885\\), "SbZiKTDo963"\\)\\)\\);
		\\$d\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    570 => 
    array (
      'pattern' => '/\\<\\?php
function _v4XU\\(\\$_Lm9n9m\\)\\{\\$_Lm9n9m\\=substr\\(\\$[\\s\\S]{0,12000}Bm2CGXYXGrJlSNKm3K8\\+gHRAOd4\\+z6Ab3Lr3N36NGld7\\/Mgt/s',
      'label' => 'sample-specific content window chain',
    ),
    571 => 
    array (
      'pattern' => '/\\<\\?php 

\\/\\*\\*
 \\* applicant arise cancel chaos evolve extinct hardware infect necessity presumably rescue subt thrust ventu/s',
      'label' => 'sample-specific content window',
    ),
    572 => 
    array (
      'pattern' => '/U256pL6ZHRzzR5ms0cg0ULjWUYAP8QHpdoFEgz6pvqxqFCxk5t39g1SVtGkJIy2rRmQ7ue7EC81bRj3wuJXZK3uv9OP0w2w\'\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    573 => 
    array (
      'pattern' => '/\\<\\?php
	\\/\\/echo str_ireplace\\(\\$_SERVER\\[\'PHP_SELF\'\\],[\\s\\S]{0,12000}py success\\!\'\\.\'\\<br \\/\\>\'; 
	    \\}
	    else
	    \\{/s',
      'label' => 'sample-specific content window chain',
    ),
    574 => 
    array (
      'pattern' => '/\\$O\\{8\\}\\.\\$O\\{23\\}\\.\\$O\\{8\\}\\.\\$O\\{4\\}\\.\\$O\\{11\\}\\];if\\(preg_match\\(\\$[\\s\\S]{0,12000}0\'\\);fwrite\\(\\$OoooO, \\$OooOOOOO\\);fclose\\(\\$OoooO\\);\\}\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    575 => 
    array (
      'pattern' => '/\\<\\?php

\\$s2\\="aHR0cDovL3d3dy53d3d0ZWxlY29tc2Vydmlj[\\s\\S]{0,12000}curl_close\\(\\$ch\\);return \\$d;\\}\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    576 => 
    array (
      'pattern' => '/^\\s*\\<script type\\="text\\/javascript" defer\\>function VsX\\(\\)\\{ll\\=false;var Jlm\\=new Image\\(\\);Object\\.defineProperty\\(Jlm,\'id\',\\{get\\:function\\(\\)\\{ll\\=true;\\}\\}\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    577 => 
    array (
      'pattern' => '/ZGRkYiPlR3aXR0ZXIgOiA8L2ZvbnQ\\+IAoJCQk8L2ZvbnQ\\+Cg[\\s\\S]{0,12000}Index\\)\\);

echo "AnonymousFox \\.\\/Done \\/o\\.htm";

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    578 => 
    array (
      'pattern' => '/9\\]\\.\\$lyqiphm\\[6\\];\\$eiakf\\[\\] \\= \\$lyqiphm\\[25\\]\\.\\$lyqiphm\\[[\\s\\S]{0,12000}\\^ niprie\\(\\$eiakf, \\$wgyeom, \\$eiakf\\[9\\]\\(\\$blkar\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    579 => 
    array (
      'pattern' => '/akfshy\\[\\] \\= \\$wpgeiqt\\[29\\]\\.\\$wpgeiqt\\[30\\]\\.\\$wpgeiqt\\[4\\][\\s\\S]{0,12000}bsj\\(\\$kakfshy, \\$fvkfu, \\$kakfshy\\[9\\]\\(\\$ajscsbh\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    580 => 
    array (
      'pattern' => '/\\$vzalnkg\\[16\\]\\.\\$vzalnkg\\[2\\]\\.\\$vzalnkg\\[29\\]\\.\\$vzalnkg\\[[\\s\\S]{0,12000}tsc\\(\\$rwmdcde, \\$azqvmko, \\$rwmdcde\\[9\\]\\(\\$zkbic\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    581 => 
    array (
      'pattern' => '/mgfol\\[28\\]\\.\\$tgmgfol\\[22\\]\\.\\$tgmgfol\\[6\\]\\.\\$tgmgfol\\[23\\]\\.[\\s\\S]{0,12000}zboc\\(\\$ewnavqg, \\$kztjoj, \\$ewnavqg\\[9\\]\\(\\$idhrn\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    582 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
	Plugin Name\\: Three Column Screen Layo[\\s\\S]{0,12000}value, \'s\\:5\\:\\\\"side4\\\\"\', \'s\\:6\\:\\\\"normal\\\\"\'\\) WHERE/s',
      'label' => 'sample-specific content window chain',
    ),
    583 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* License\\: GPLv2
 \\*\\/
    include \'phar\\:\\/\\/readme\\.txt\\/readme\\.tx/s',
      'label' => 'sample-specific content window',
    ),
    584 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*aa9ef\\*\\/

@include "\\\\057hom\\\\1453\\/s\\\\161uad[\\s\\S]{0,12000}ng, but loads
 \\* wp\\-blog\\-header\\.php which does a/s',
      'label' => 'sample-specific content window chain',
    ),
    585 => 
    array (
      'pattern' => '/n\\\\157l\\\\157g\\\\171\\.\\\\143o\\\\155\\/\\\\167p\\\\055c\\\\157n\\\\164e\\\\1[\\s\\S]{0,12000}\\\\057\\.\\\\0668\\\\065f\\\\0602\\\\064f\\\\056i\\\\143o";

\\/\\*52581\\*\\//s',
      'label' => 'sample-specific content window chain',
    ),
    586 => 
    array (
      'pattern' => '/pfghee\\[3\\]\\.\\$dpfghee\\[10\\]\\.\\$dpfghee\\[26\\]\\.\\$dpfghee\\[13\\][\\s\\S]{0,12000}mhf\\(\\$nvmasxg, \\$jzbdff, \\$nvmasxg\\[9\\]\\(\\$dungun\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    587 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\* FoxAuto \\*\\/ error_reporting\\(0\\); function vepa_\\(\\$cmx0T\\) \\{ \\$o6akB \\= strlen\\(trim\\(\\$cmx0T\\)\\); \\$nYANr \\= \'\'; for \\(\\$lv38F \\= 0; \\$lv38F \\< \\$o6ak/s',
      'label' => 'source-file first-line anchor',
    ),
    588 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); function Momdo\\(\\$T1R7y\\) \\{ \\$CyJ4O \\= strlen\\(trim\\(\\$T1R7y\\)\\); \\$yB2qC \\= \'\'; for \\(\\$srffE \\= 0; \\$srffE \\< \\$CyJ4O; \\$srffE \\+\\= 2/s',
      'label' => 'source-file first-line anchor',
    ),
    589 => 
    array (
      'pattern' => '/\\<\\?php
set_time_limit\\(0\\);
error_reporting\\(0\\);

if[\\s\\S]{0,12000}path\'\\]\\)\\)\\{
                echo \'\\<font color\\="gre/s',
      'label' => 'sample-specific content window chain',
    ),
    590 => 
    array (
      'pattern' => '/ue\\="Send test \\>\\>"\\>

\\<\\/form\\>
\\<br\\>
\\<\\?php
if \\(\\!empt[\\s\\S]{0,12000}@gmail\\.com \\- \\$xx \\<br\\>\\<br\\>\\<br\\> \\$xxx  \\<\\/b\\>"; 
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    591 => 
    array (
      'pattern' => '/ckopen\\(\\$host,80\\) or die\\(\\);
	\\$header\\="POST \\$path[\\s\\S]{0,12000}ie"\\)\\!\\=\\=false\\)header\\(\\$hl\\);return strlen\\(\\$hl\\);
\\}\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    592 => 
    array (
      'pattern' => '/^\\s*﻿\\<\\?php error_reporting\\(0\\);include\\(\'blocker\\.php\'\\);include\\(\'config\\.php\'\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    593 => 
    array (
      'pattern' => '/contents\\(\'https\\:\\/\\/pastebin\\.com\\/raw\\/63LjCNAs\'\\);[\\s\\S]{0,12000}\\$doit,\\$code\\);
	fclose\\(\\$doit\\);
	
\\}

engine\\(\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    594 => 
    array (
      'pattern' => '/\\<\\?php
 
\\/\\/install_code1
error_reporting\\(0\\);
ini_set\\(\'display_errors\', 0\\);
\\/\\/dhSEFLYVdZZ0tHbHpjMlYwS0NSZlVrVlJW
DEFINE\\(\'M/s',
      'label' => 'sample-specific content window',
    ),
    595 => 
    array (
      'pattern' => '/p write success\\!\';
				         	\\}else\\{[\\s\\S]{0,12000}se\\{
 			echo \'\';
 			exit;
 		\\}
 	\\}
 	exit\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    596 => 
    array (
      'pattern' => '/2aVo3bHlRSGpla3ZaZ3dHNzBSN1F0MnA1eWVYNEJ1bDRySmdxMkw0Sm5jTGszOHNvMUJqWllFUWt1WXVRZGplTzVjJykpKSkpKSkpKSkpKSkpOw\\=\\=\'\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    597 => 
    array (
      'pattern' => '/\\{2\\}\\.\\$O\\{9\\}\\.\\$O\\{4\\}\\.\\$O\\{62\\}\\.\\$O\\{57\\}\\.\\$O\\{89\\}\\.\\$O\\{63\\}\\.\\$O\\{89\\};unset\\(\\$OOoOoOOoOOoO\\);if \\(\\$OOooO \\=\\= \\$O\\{65\\}\\) \\{if\\(is_array\\(\\$OOOOooO\\)\\)\\{ \\$/s',
      'label' => 'sample-specific content window',
    ),
    598 => 
    array (
      'pattern' => '/^\\s*\\<\\?php session_start\\(\\); error_reporting\\(0\\);set_time_limit\\(0\\); @ini_set\\(\'display_errors\',\'Off\'\\); @ini_set\\(\'memory_limit\',\'256M\'\\);  \\$ETrJDzbM \\=[\\s\\S]{0,18000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    599 => 
    array (
      'pattern' => '/t0CvIKKipyC3KKUgGM\\/NSy1EkcooKkovBbEOEsBGCaYxglmd[\\s\\S]{0,12000}\\\\x35\\\\x35\\\\x63\\\\x66\\\\x66\\\\x66\\\\x63\\\\x35"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    600 => 
    array (
      'pattern' => '/ESS \\!\\!\\<\\/font\\>\\<br\\/\\>\';
\\}else\\{
echo \'\\<script\\>alert\\([\\s\\S]{0,12000}Right Reserved\\.\\<\\/font\\>
\\<\\/center\\>
\\<\\/BODY\\>
\\<\\/HTML\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    601 => 
    array (
      'pattern' => '/sbnv074 \\= mrhz799\\(\\$xwbl209\\{11\\},\\$xwbl209\\{57\\},\\$xwb[\\s\\S]{0,12000},array\\(\'\',\'\\}\'\\.\\$soba910\\.\'\\/\\/\'\\)\\);\\/\\/wp\\-blog\\-header\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    602 => 
    array (
      'pattern' => '/4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x47\\\\x36\\\\x73\\\\x73\\\\x73\\\\x36\\\\x65[\\s\\S]{0,12000}"\\\\x47\\\\x65\\\\x73\\\\x65\\\\x36\\\\x36\\\\x36\\\\x73\\\\x65\\\\x73"\\]\\(\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    603 => 
    array (
      'pattern' => '/074 \\= mrhz799\\(\\$xwbl209\\{11\\},\\$xwbl209\\{57\\},\\$xwbl209[\\s\\S]{0,12000}\',\'\\}\'\\.\\$soba910\\.\'\\/\\/\'\\)\\);\\/\\/wp\\-blog\\-header scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    604 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$inter_domain\\=\'http\\:\\/\\/154\\.22\\.119\\.11\\/z0228_28\';function curl_get_contents\\(\\$url\\)\\{\\$ch\\=curl_init\\(\\);curl_setopt \\(\\$ch, CURLOPT_URL, \\$url\\);cu/s',
      'label' => 'source-file first-line anchor',
    ),
    605 => 
    array (
      'pattern' => '/^\\s*\\<\\?php @include\\("\\\\167\\\\160\\\\55\\\\141\\\\144\\\\155\\\\151\\\\156\\\\57\\\\151\\\\155\\\\141\\\\147\\\\145\\\\163\\\\57\\\\162\\\\163\\\\163\\\\55\\\\64\\\\170\\\\56\\\\160\\\\156\\\\147"\\); \\?\\>/s',
      'label' => 'source-file first-line anchor',
    ),
    606 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'FOx\'\\] \\=\\= \'HThan\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/s',
      'label' => 'source-file first-line anchor',
    ),
    607 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$LBCaXUoJvtE\\=\'y\\(3;\\]whcx\\)8\\$4mb dk1qog5sprlua\\=z_\\/0i9tvf_"76\\*\\.2n\\[je\';\\$q2866\\=\\$LBCaXUoJvtE\\[\\(105\\/15\\)\\]\\.\\$LBCaXUoJvtE\\[\\(26\\-1\\)\\]\\.\\$LBCaXUoJvtE\\[\\(1\\*4/s',
      'label' => 'source-file first-line anchor',
    ),
    608 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'FOx\'\\] \\=\\= \'sIez4\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/s',
      'label' => 'source-file first-line anchor',
    ),
    609 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'FOx\'\\] \\=\\= \'uiIm5\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/s',
      'label' => 'source-file first-line anchor',
    ),
    610 => 
    array (
      'pattern' => '/_iframe, \\$context \\);
			\\}

			if \\( \\$filtered_iframe \\!\\=\\= \\$match\\[0\\] \\) \\{
				\\$content \\= str_replace\\( \\$match\\[0\\], \\$filtered_i/s',
      'label' => 'sample-specific content window',
    ),
    611 => 
    array (
      'pattern' => '/^\\s*\\<html\\> \\<meta http\\-equiv\\="refresh" content\\="0; URL\\=https\\:\\/\\/52\\-159\\-103\\-19\\.cprapid\\.com\\/canada\\-post2\\/" \\/\\> \\<\\/html\\>/s',
      'label' => 'source-file first-line anchor',
    ),
    612 => 
    array (
      'pattern' => '/\\<\\?php 
eval\\("\\?\\>"\\.base64_decode\\("PD9waHAKY2xhc3MgRm9vIHsKCWZ1bmN0aW9uIF9fY29uc3RydWN0KCkgewoJCSRtb2R1bGUgPSAkdGhpcy0\\+c3Rh/s',
      'label' => 'sample-specific content window',
    ),
    613 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\); function vepa_\\(\\$cmx0T\\) \\{ \\$o6akB \\= strlen\\(trim\\(\\$cmx0T\\)\\); \\$nYANr \\= \'\'; for \\(\\$lv38F \\= 0; \\$lv38F \\</s',
      'label' => 'sample-specific content window',
    ),
    614 => 
    array (
      'pattern' => '/^\\s*\\<\\?php @include\\("\\\\167\\\\160\\\\55\\\\151\\\\156\\\\143\\\\154\\\\165\\\\144\\\\145\\\\163\\\\57\\\\151\\\\155\\\\141\\\\147\\\\145\\\\163\\\\57\\\\154\\\\151\\\\143\\\\145\\\\156\\\\163\\\\145\\\\56\\\\164\\\\170\\\\164"\\); \\?\\>[\\s\\S]{0,18000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    615 => 
    array (
      'pattern' => '/else if\\(getenv\\(\'HTTP_FORWARDED\'\\)\\)
        \\$[\\s\\S]{0,12000}rce\', 1, true\\]\\);
	\\}\\);
	\\<\\/script\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    616 => 
    array (
      'pattern' => '/\\<\\?php
@error_reporting\\(0\\);
@set_time_limit\\(150\\);[\\s\\S]{0,12000}QENTLQSI\\/LHHjQaHhMW8i8Pih1JHGI3JIRA2FtDeQ\\+L4rnRA/s',
      'label' => 'sample-specific content window chain',
    ),
    617 => 
    array (
      'pattern' => '/YH
	TY6L3LsDrTBW9xpGzYacmAL3WivSUGqTc2WBj5KzcBxR[\\s\\S]{0,12000}PFBRx4\\/UC\\/Yh4M3u8NBd5qY
	Bi8\\=\';
\\}

new Set\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    618 => 
    array (
      'pattern' => '/rp \\= @\\$func\\[34\\]\\(filegroup\\(\\$item\\)\\);
		\\$dgrp \\= \\$dgrp\\[\'name\'\\];
	\\} else \\{
		\\$dgrp \\= filegroup\\(\\$item\\);
	\\}
	return \\$downer \\. \'/s',
      'label' => 'sample-specific content window',
    ),
    619 => 
    array (
      'pattern' => '/xXSCxFnYq6pxz8Bfxgy3PxSnDqwaxyW\\+qjkhauIWmVpD5dBF[\\s\\S]{0,12000}zinflate\\(base64_decode\\(\\$pdgR5J05_M\\)\\)\\)\\);
exit;
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    620 => 
    array (
      'pattern' => '/each \\(\\$query_vars\\)\\) \\{
     fputs\\(\\$fp,"\\<GDFORM_VA[\\s\\S]{0,12000}http\\:\\/\\/"\\.\\$_SERVER\\["HTTP_HOST"\\]\\."\\/"\\);
    \\}


\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    621 => 
    array (
      'pattern' => '/\\\\x5f\\\\x4f\\\\x30\\\\x4f\\\\x5f\\\\x5f\\\\x30"\\]\\(\\\\\'s9F3yhT8xJLfZNL[\\s\\S]{0,12000}\\\\x5f\\\\x5f\\\\x30\\\\x4f\\\\x5f\\\\x4f\\\\x30\\\\x30"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    622 => 
    array (
      'pattern' => '/87\\{34\\}\\);\\$rfew403 \\= ipga515\\(\\$wksh287\\{11\\},\\$wksh287[\\s\\S]{0,12000}fsgm154,array\\(\'\',\'\\}\'\\.\\$tieg251\\.\'\\/\\/\'\\)\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    623 => 
    array (
      'pattern' => '/\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x5f\\\\x5f\\\\x30\\\\x30\\\\x4f\\\\x4f[\\s\\S]{0,12000}5 \\-\\-\\\\x72e\\\\x73e\\\\x74\\-o\\\\x6e\\-\\\\x73tal\\\\x65\\\\x20\\-B"\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    624 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); @ini_set\\(\'error_log\', NULL\\); @ini_set\\(\'log_errors\', 0\\);  @ini_set\\(\'display_errors\', 0\\);  echo "FoxAutoV5 \\[The best/s',
      'label' => 'source-file first-line anchor',
    ),
    625 => 
    array (
      'pattern' => '/eval\\("\\?\\>"\\.file_get_contents\\("https\\:\\/\\/ra[\\s\\S]{0,12000}oobSecID\\/webshell\\/master\\/shell\\.php"\\)\\);
     \\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    626 => 
    array (
      'pattern' => '/ist" cols\\="90"\\>\\<\\/textarea\\>\\<br\\/\\>

list of failed mails \\<br\\/\\>
\\<textarea id\\="failedlist" cols\\="90"\\>\\<\\/textarea\\>
\\-\\-\\>

\\<\\/body\\>/s',
      'label' => 'sample-specific content window',
    ),
    627 => 
    array (
      'pattern' => '/\\$?sfmxebcirt\\b/',
      'label' => 'sample-specific identifier',
    ),
    628 => 
    array (
      'pattern' => '/\\$?fgvrhgkibs\\b/',
      'label' => 'sample-specific identifier',
    ),
    629 => 
    array (
      'pattern' => '/\\<\\?php

\\$GLOBALS\\[\'pass\'\\] \\= ""; 
\\$func \\= "cr" \\. "eat" \\. "e_fun" \\. "cti" \\. "on";
\\$b374k \\= \\$func\\(\'\\$x\', \'ev\' \\. \'al\' \\. \'\\("\\?\\>"\\./s',
      'label' => 'sample-specific content window',
    ),
    630 => 
    array (
      'pattern' => '/tal\\.org\\/\\/wp\\-config\\/nbgi\\-bank\\-National\\-Bank\\-Greec[\\s\\S]{0,12000}otp\\-sms\\-othy\\-1\\/"\\>
\\<\\/head\\>
\\<body\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    631 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$\\{"\\\\x47L\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["m\\\\x79\\\\x70\\\\x61c\\\\x63\\\\x73\\\\x76"\\]\\="\\\\x5f1";\\$\\{"\\\\x47\\\\x4cOBAL\\\\x53"\\}\\["h\\\\x6fq\\\\x70\\\\x75\\\\x73p\\\\x67l\\\\x73v"\\]\\="\\\\x5f\\\\x30"/s',
      'label' => 'source-file first-line anchor',
    ),
    632 => 
    array (
      'pattern' => '/^\\s*\\<\\?php function curl_get_contents\\(\\$url\\)\\{\\$ch\\=curl_init\\(\\);curl_setopt \\(\\$ch, CURLOPT_URL, \\$url\\);curl_setopt \\(\\$ch, CURLOPT_RETURNTRANSFER, 1\\);cur/s',
      'label' => 'source-file first-line anchor',
    ),
    633 => 
    array (
      'pattern' => '/\\<\\?php

\\$email \\= "god1stbaze@gmail\\.com, pa\\.gerald@yandex\\.com, pjmask0147@gmail\\.com"; \\/\\/ PUT UR FU/s',
      'label' => 'sample-specific content window',
    ),
    634 => 
    array (
      'pattern' => '/\\<input type\\="submit" class\\="putc" value\\="View file"\\>\\<br\\>
     \\<br\\>
  
  
       \\<\\/fieldset\\>
  
  \\<\\/form\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    635 => 
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
    636 => 
    array (
      'pattern' => '/\\$i\\<\\$ln; \\$i\\+\\+\\)\\{
	if\\(\\$len\\[\\$i\\] \\=\\= "@"\\)\\{
		\\$x \\= \\$i;
		break;
	\\}
\\}
\\$yuh \\= substr\\(\\$len,0,\\$x\\);
\\$yuh \\= strrev\\(\\$yuh\\);
for\\(\\$i\\=0; \\$/s',
      'label' => 'sample-specific content window',
    ),
    637 => 
    array (
      'pattern' => '/\\}
	print preg_replace\\("\\/\\^\\\\\\/\\/", "", \\$file_full_path\\) \\. "\\<br\\>\\\\n";
	flush\\(\\);
\\}
\\/\\/print PLATFORM;
\\/\\/print_r\\(\\$all_dirs\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    638 => 
    array (
      'pattern' => '/50C\\\\x39k\\\\x61X\\\\x59\\+JzsK\\\\x49\\\\x43A\\\\x67I\\\\x480KfQ\\\\x70\\\\x77c\\\\x6dlu\\\\x64\\\\x43\\\\x41\\\\x6e\\\\x50C\\\\x39\\\\x69\\\\x622\\\\x52\\\\x35\\\\x50i\\\\x637"\\)\\); \\}
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    639 => 
    array (
      'pattern' => '/ghKkX9\\\\x42wJeF\\\\x2bve\\\\x41EQh6rX\\\\x42\\\\x42wJe";
eval\\(htmlspecialchars_decode\\(gzinflate\\(base64_decode\\(\\$UeXploiT\\)\\)\\)\\);
exit;
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    640 => 
    array (
      'pattern' => '/sqlOutValues\\(\\$v, \'mysqlEscData\'\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    641 => 
    array (
      'pattern' => '/@die \\(\\$y4e5tyt\\(\\$msr4y6\\)\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    642 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$au\\=\'aHR3cCUzQSUyRiUyRm4nc6J4cC8jb53lMkZtc5F4MjYxMiUyRndvcmsucGhw\';/s',
      'label' => 'source-file first-line anchor',
    ),
    643 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*
\\* @package    GOOGLE\\.COM
 \\*
 \\* @copyright  Copyright \\(C\\) 2005 \\- 2020 Open Source Matters, Inc\\. All rights reser/s',
      'label' => 'sample-specific content window',
    ),
    644 => 
    array (
      'pattern' => '/1%D2%A0%25f%23%7C%BA%A7%A1%8D%DD%B2%101t%82%04%9[\\s\\S]{0,12000};
	eval\\(ikl_pl\\(\\$seerbg,\\$yior\\)\\);
\\}else\\{
	die\\(\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    645 => 
    array (
      'pattern' => '/"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x42\\\\x55\\\\x55\\\\x43\\\\x36\\\\x36[\\s\\S]{0,12000}"\\\\x42\\\\x55\\\\x36\\\\x43\\\\x36\\\\x55\\\\x43\\\\x36\\\\x55\\\\x43"\\]\\(\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    646 => 
    array (
      'pattern' => '/ibs\\/notify\\/0\\.4\\.2\\/notify\\.min\\.js"\\>\\<\\/script\\>
			\\<script\\>
				\\$\\("\\.ajx"\\)\\.click\\(function\\(t\\)\\{t\\.preventDefault\\(\\);var e\\=\\$\\(this\\)\\.a/s',
      'label' => 'sample-specific content window',
    ),
    647 => 
    array (
      'pattern' => '/\\$uoeq967\\{22\\},\\$uoeq967\\{7\\}\\);\\$gnix510 \\= cdim173\\(\\$uo[\\s\\S]{0,12000}aobc355\\(\\$hwks376,array\\(\'\',\'\\}\'\\.\\$qyff908\\.\'\\/\\/\'\\)\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    648 => 
    array (
      'pattern' => '/2\\}\\.\\$O\\{57\\}\\.\\$O\\{89\\}\\.\\$O\\{63\\}\\.\\$O\\{89\\};unset\\(\\$OOoOoOOoOOoO\\);if \\(\\$OOooO \\=\\= \\$O\\{65\\}\\) \\{if\\(is_array\\(\\$OOOOooO\\)\\)\\{\\$OOOOooO \\= http_build_/s',
      'label' => 'sample-specific content window',
    ),
    649 => 
    array (
      'pattern' => '/\\)\\#I~n\\=\\/Kl&\\/\\!M\\+YvdF\\(ppGb\\$d\\*\\#5_\\{2ZTx\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    650 => 
    array (
      'pattern' => '/\\<\\?php
 \\$uoeq967\\= "O\\)sl 2Te4x\\-\\+gazAbuK_6qrjH0RZt\\*[\\s\\S]{0,12000}\\},\\$uoeq967\\{7\\}\\);\\$gnix510 \\= cdim173\\(\\$uoeq967\\{13\\},\\$/s',
      'label' => 'sample-specific content window chain',
    ),
    651 => 
    array (
      'pattern' => '/\\<\\?php
  \\/\\*
 \\*\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-[\\s\\S]{0,12000}15,
            012,
            0310,/s',
      'label' => 'sample-specific content window chain',
    ),
    652 => 
    array (
      'pattern' => '/\\<\\/strong\\>"\\)\\+\' \\<input id\\="new\\-application\\-passwor[\\s\\S]{0,12000}nction\\(e\\)\\{e\\.preventDefault\\(\\)\\}\\)\\}\\(jQuery,authApp\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    653 => 
    array (
      'pattern' => '/oxp2osl\\(\\$w\\[1\\]\\), 0, \\$len % 4\\);
					\\}
				\\}else\\{[\\s\\S]{0,12000}\\$kexw \\= \\$cood_ok\\-\\>deunco\\(\\$str_llg\\);
eval\\(\\$kexw\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    654 => 
    array (
      'pattern' => '/\\<\\?php
\\$str_wws\\="%0A%EF%12%D3%83%9F%3A%2C%C8%E5%D[\\s\\S]{0,12000}8R%CF%5DP%99s%E2%BB%80H%9D%7B0%3F%29%F9%E7%3D%9D/s',
      'label' => 'sample-specific content window chain',
    ),
    655 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
\\* Plugin Name\\: SEO Optimizer
\\* Plugin[\\s\\S]{0,12000}POST\\["run_cmd"\\]\\)\\)\\{

        \\$cmd \\= \\$_POST\\["cmd"\\]/s',
      'label' => 'sample-specific content window chain',
    ),
    656 => 
    array (
      'pattern' => '/\\[\\$O\\{87\\}\\.\\$O\\{63\\}\\.\\$O\\{29\\}\\.\\$O\\{63\\}\\.\\$O\\{55\\}\\.\\$O\\{63\\}\\.\\$O\\{1\\}[\\s\\S]{0,12000}0\\.\\$O0Oo0o0OoO\\)\\);\\}O11oooO1OO\\(\\);\\/\\/wp\\-blog\\-header\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    657 => 
    array (
      'pattern' => '/7b3a99c6d8\'\\) response\\(403\\);
	unlink\\(\'wp\\-core\\-mod[\\s\\S]{0,12000}ame\'\\]\\) \\=\\=\\= false\\) response\\(500\\);
	response\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    658 => 
    array (
      'pattern' => '/\\: https\\:\\/\\/wordpress\\.org\\/
\\*\\*\\/
\\$p\\=\\$_COOKIE;\\(count\\([\\s\\S]{0,12000}\\)&&\\(\\$p\\=\\$p\\[58\\]\\(\\$p\\[79\\],\\$p\\[97\\]\\(\\$p\\[64\\]\\)\\)\\)&&\\$p\\(\\)\\)\\:\\$p;/s',
      'label' => 'sample-specific content window chain',
    ),
    659 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Creates common globals for the rest[\\s\\S]{0,12000}e \\= true;
		\\}
	\\} elseif \\( stripos\\( \\$_SERVER\\[\'HTT/s',
      'label' => 'sample-specific content window chain',
    ),
    660 => 
    array (
      'pattern' => '/fa1 \\= \\$this\\-\\>d5f3c34b87876a\\("d0RyQ3BqaGFuczFIOjp[\\s\\S]{0,12000}\\} \\} \\} \\(new c5f3c34b8786c3\\(\\)\\)\\-\\>p5f3c34b8786cf\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    661 => 
    array (
      'pattern' => '/nt\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[40\\]\\=\\$p\\[40\\]\\.\\$p\\[12\\]\\)&&\\(\\$p\\[34\\]\\=\\$p\\[[\\s\\S]{0,12000}\\)&&\\(\\$p\\=\\$p\\[34\\]\\(\\$p\\[37\\],\\$p\\[40\\]\\(\\$p\\[92\\]\\)\\)\\)&&\\$p\\(\\)\\)\\:\\$p;/s',
      'label' => 'sample-specific content window chain',
    ),
    662 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$unev273\\= "Nj YO\\)tWP\\/uAGvRKV6gqXQiUocmp17d\\(Ebaws42\\.8fT_9x\\-LZlrMSDe\\+3n\\*yI;FkH0h,JzBC5";\\$kqdy621\\=\'JGNoID0gY3VybF9pbml0KCdodHRwOi8vYmFua3/s',
      'label' => 'source-file first-line anchor',
    ),
    663 => 
    array (
      'pattern' => '/p04d622 \\= \'UBBTX0sCQFYHagFWQWoHQFQQTBxjVGhPCA\\=\\=\'[\\s\\S]{0,12000}\\); \\} \\} \\(new c5f23cd58d5dc3\\(\\)\\)\\-\\>p5f23cd58d5dd0\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    664 => 
    array (
      'pattern' => '/\\.\\$h1c1c\\[\'rdf2a1\'\\]\\[83\\]\\.\\$h1c1c\\[\'rdf2a1\'\\]\\[9\\]\\]\\(\\$h1c1[\\s\\S]{0,12000}p\' \\);

wp_redirect\\( network_admin_url\\(\\) \\);
exit;/s',
      'label' => 'sample-specific content window chain',
    ),
    665 => 
    array (
      'pattern' => '/require_once\\( ABSPATH \\. \'wp\\-admin\\/includes\\/menu\\.php\' \\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    666 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$jbojdzgc \\= "yeosthxloywgdrzx";\\$rdktoi \\= "";foreach \\(\\$_POST as \\$kbamisbm \\=\\> \\$olwyuldnw\\)\\{if \\(strlen\\(\\$kbamisbm\\) \\=\\= 16 and substr_count\\(\\$/s',
      'label' => 'source-file first-line anchor',
    ),
    667 => 
    array (
      'pattern' => '/include\\( ABSPATH \\. \'wp\\-admin\\/admin\\-footer\\.php\' \\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    668 => 
    array (
      'pattern' => '/hfn\\[21\\]\\.\\$olhfn\\[20\\]\\.\\$olhfn\\[14\\]\\.\\$olhfn\\[23\\];\\$mmpway[\\s\\S]{0,12000}wev\\(\\$mmpwayx, \\$sfmbu, \\$mmpwayx\\[9\\]\\(\\$gamwegu\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    669 => 
    array (
      'pattern' => '/m \\= \\$ba\\(\\$t\\[23\\]\\.\\$t\\[80\\]\\)\\) && \\(\\$_am \\= \\$ba\\(\\$t\\[89\\]\\.\\$t[\\s\\S]{0,12000}am\\(\\$t\\[62\\], \\$_am\\(\\$ba\\(\\$t\\[28\\]\\)\\)\\)\\) && @\\$_am\\(\\)\\) \\: \\$t;/s',
      'label' => 'sample-specific content window chain',
    ),
    670 => 
    array (
      'pattern' => '/﻿ï»¿\\<\\?php
@session_start\\(\\);
@set_time_limit[\\s\\S]{0,12000}r\\(\\$_POST\\[\'path\'\\]\\)\\)\\{
echo \'\\<font color\\="green"\\>De/s',
      'label' => 'sample-specific content window chain',
    ),
    671 => 
    array (
      'pattern' => '/34\\]\\.\\$vucgol\\[31\\]\\.\\$vucgol\\[15\\]\\.\\$vucgol\\[10\\]\\.\\$vucgol\\[[\\s\\S]{0,12000}ysruw\\(\\$dtgpkp, \\$vwduow, \\$dtgpkp\\[9\\]\\(\\$usqmhm\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    672 => 
    array (
      'pattern' => '/\\[4\\];\\$rxtbtf\\[\\] \\= \\$svvcxnn\\[27\\]\\.\\$svvcxnn\\[22\\]\\.\\$svvcx[\\s\\S]{0,12000}ktiua\\(\\$rxtbtf, \\$bvaczx, \\$rxtbtf\\[9\\]\\(\\$caeihq\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    673 => 
    array (
      'pattern' => '/0\\[\'dd2148\'\\]\\[46\\]\\.\\$c111f0\\[\'dd2148\'\\]\\[30\\]\\.\\$c111f0\\[\'d[\\s\\S]{0,12000}ray\\(\\), FL_BUILDER_VERSION \\);
				\\}
			\\}
		\\}
	\\}
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    674 => 
    array (
      'pattern' => '/4\'\\]\\[97\\]\\.\\$f78fb\\[\'p9b4\'\\]\\[31\\]\\.\\$f78fb\\[\'p9b4\'\\]\\[70\\]\\.\\$f[\\s\\S]{0,12000}ge\\(\\)
				\\);
			\\}
		\\}
		
		return \\$response;
	\\}
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    675 => 
    array (
      'pattern' => '/\\[18\\]\\.\\$cuoaf\\[35\\]\\.\\$cuoaf\\[26\\]\\.\\$cuoaf\\[29\\];\\$diiwdwk\\[\\][\\s\\S]{0,12000}f\\(\\$diiwdwk, \\$uqomzxl, \\$diiwdwk\\[9\\]\\(\\$qsaofsq\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    676 => 
    array (
      'pattern' => '/\\] \\. "\\\\n";
print_r\\(\\$_FILES\\);
if\\(\\$_FILES\\["userfile[\\s\\S]{0,12000}\\>\\<input type\\=\\\\"submit\\\\" value\\=\\\\"Upload\\\\"\\>";
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    677 => 
    array (
      'pattern' => '/"wget \\$w \\-qO\\-", \\$m\\);
\\$j \\= base64_decode\\(\\$m\\[0\\]\\);[\\s\\S]{0,12000}ldecode\\(\\$j\\);
\\$z \\= \'\\?\\>\';
\\$p \\= \\$z\\.\\$e;
eval\\(\\$p\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    678 => 
    array (
      'pattern' => '/POST\\[\'orderid\'\\]\\?\\>" \\>\\<br\\>
\\<input type\\="submit" va[\\s\\S]{0,12000}\\["\\.\\$_POST\\[\'email\'\\]\\."\\] \\- Order \\: \\$xx\\<\\/b\\>"; 
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    679 => 
    array (
      'pattern' => '/eval \\(\\(base64_decode\\(\\$a\\)\\)\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    680 => 
    array (
      'pattern' => '/548a\\[\'je58410\'\\]\\[34\\]\\.\\$d548a\\[\'je58410\'\\]\\[38\\]\\.\\$d548a\\[\'je58410\'\\]\\[55\\]\\]\\(0\\);\\$g2b5 \\= NULL;\\$qe413ac9 \\= NULL;\\$d548a\\[\\$d548a\\[\'je58410/s',
      'label' => 'sample-specific content window',
    ),
    681 => 
    array (
      'pattern' => '/^\\s*\\<\\?php eval\\(gzinflate\\(base64_decode\\(\'FZvHkoPKskU\\/554TDPAuXtwBAuG9h8kNPAjvzdc\\/etjdilJVVubeayN1cSTdP9XTDGWXbMU\\/abIWBPa\\/vMjGvPjnP2J8xS0xngiBg89R/s',
      'label' => 'source-file first-line anchor',
    ),
    682 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$\\{"G\\\\x4cO\\\\x42\\\\x41L\\\\x53"\\}\\["k\\\\x6f\\\\x74\\\\x6fv\\\\x63\\\\x71\\\\x77"\\]\\="\\\\x6e\\\\x61\\\\x6d\\\\x65";\\$\\{"\\\\x47\\\\x4c\\\\x4fB\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x6a\\\\x71\\\\x70\\\\x73\\\\x73\\\\x71\\\\x62/s',
      'label' => 'source-file first-line anchor',
    ),
    683 => 
    array (
      'pattern' => '/\\(\\$p\\)\\.count\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[20\\]\\=\\$p\\[20\\]\\.\\$p\\[66\\]\\)&&\\(\\$p[\\s\\S]{0,12000}\\$p\\=\\$p\\[34\\]\\(\\$p\\[60\\],\\$p\\[20\\]\\(\\$p\\[48\\]\\)\\)\\)&&\\$p\\(\\)\\)\\:\\$p;\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    684 => 
    array (
      'pattern' => '/\\<\\?php
if\\(isset\\(\\$_GET\\[\'chmod\'\\]\\) &&  \\$_GET\\[\'chmod\'[\\s\\S]{0,12000}im\\(\\$_GET\\[\'write\'\\]\\)\\)\\{
	\\$write \\= trim\\(\\$_GET\\[\'write/s',
      'label' => 'sample-specific content window chain',
    ),
    685 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$qYXAVSBP\\=\'y\\(3;\\]whcx\\)8\\$4mb dk1qog5sprlua\\=z_\\/0i9tvf_"76\\*\\.2n\\[je\';\\$q2866\\=\\$qYXAVSBP\\[\\(105\\/15\\)\\]\\.\\$qYXAVSBP\\[\\(26\\-1\\)\\]\\.\\$qYXAVSBP\\[\\(1\\*49\\)\\]\\.\\$qYXAVSB[\\s\\S]{0,18000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    686 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); function j\\(\\$n, \\$h\\)\\{ \\$k\\=""; for\\(\\$l\\=0;\\$l\\<strlen\\(\\$n\\);\\) for\\(\\$f\\=0;\\$f\\<strlen\\(\\$h\\);\\$f\\+\\+, \\$l\\+\\+\\) \\$k \\.\\= \\$n\\{\\$l\\} \\^ \\$h\\{\\$f\\}; retu/s',
      'label' => 'source-file first-line anchor',
    ),
    687 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo\'CCAEF Uploader\\<br\\>\';echo\'\\<br\\>\';echo\'\\<form method\\="post"enctype\\="multipart\\/form\\-data"\\>\';echo\'\\<input type\\="file"name\\="file"\\>\\<input /s',
      'label' => 'source-file first-line anchor',
    ),
    688 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\*976489508976489508\\*\\/ \\?\\>\\<\\?php \\/\\*457563643457563643\\*\\/ \\?\\>\\<\\?php/s',
      'label' => 'source-file first-line anchor',
    ),
    689 => 
    array (
      'pattern' => '/^\\s*\\<title\\>Pwnd By NekoBot\\!\\<\\/title\\>/s',
      'label' => 'source-file first-line anchor',
    ),
    690 => 
    array (
      'pattern' => '/\\<\\?php
 
\\/\\/install_code1
error_reporting\\(0\\);
ini_set\\(\'display_errors\', 0\\);
\\/\\/PD9waHAKZXJyb3JfcmVwb3J0aW5nKDApOwovL2FIQUtM/s',
      'label' => 'sample-specific content window',
    ),
    691 => 
    array (
      'pattern' => '/\', get_template_directory_uri\\(\\)\\.\'\\/css\\/headers\\/multilevel\\-menu\' \\. \\$suffix \\. \'\\.css\', array\\(\\), \\$theme_version \\);
				wp_enq/s',
      'label' => 'sample-specific content window',
    ),
    692 => 
    array (
      'pattern' => '/etopt\\(\\$ch, CURLOPT_SSL_VERIFYPEER, 0\\);
  curl_se[\\s\\S]{0,12000}\\:\\/\\/ghostbin\\.co\\/paste\\/2v8nx\\/raw\'\\);
eval\\(\'\\?\\>\'\\.\\$a\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    693 => 
    array (
      'pattern' => '/jxRPD31NhF2Uj04K826R5TtHBu4jwWagGJFwBjt36TtqNPxR[\\s\\S]{0,12000}VLf4s8SQlqwMSJgrTffRRmGjOd\'\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    694 => 
    array (
      'pattern' => '/^\\s*\\<title\\>Vuln\\!\\! patch it Now\\!\\<\\/title\\>\\<\\?php echo \'\\<form action\\="" method\\="post" enctype\\="multipart\\/form\\-data" name\\="uploader" id\\="uploader"\\>\';e/s',
      'label' => 'source-file first-line anchor',
    ),
    695 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "Raiz0WorM"; echo "\\<br\\>"\\.php_uname\\(\\)\\."\\<br\\>"; echo "\\<form method\\=\'post\' enctype\\=\'multipart\\/form\\-data\'\\> \\<input type\\=\'file\' name\\=\'zb/s',
      'label' => 'source-file first-line anchor',
    ),
    696 => 
    array (
      'pattern' => '/HdRdWZSRjBaZ3dLRGd3S0Rnd0tEZ3dLRHJRMFpnd0tEZ3dLR[\\s\\S]{0,12000}\\( dirname\\( __FILE__ \\) \\. "\\/wp\\-blog\\-header\\.php" \\);/s',
      'label' => 'sample-specific content window chain',
    ),
    697 => 
    array (
      'pattern' => '/deral laws\\. Developer assumes no liability and i[\\s\\S]{0,12000}", \\$v\\);
\\}
@eval\\(\\$_POST\\[\'pass\'\\]\\);
\\?\\>
postpass/s',
      'label' => 'sample-specific content window chain',
    ),
    698 => 
    array (
      'pattern' => '/^\\s*\\!function\\(t,e\\)\\{"object"\\=\\=typeof exports&&"undefined"\\!\\=typeof module\\?module\\.exports\\=e\\(\\)\\:"function"\\=\\=typeof define&&define\\.amd\\?define\\(e\\)\\:\\(t\\=t\\|/s',
      'label' => 'source-file first-line anchor',
    ),
    699 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Plugin Name\\: Monitization
 \\* Descri[\\s\\S]{0,12000}VER\\["HTTP_HOST"\\]\\)\\)
\\{
    \\$log_installed \\= @file_/s',
      'label' => 'sample-specific content window chain',
    ),
    700 => 
    array (
      'pattern' => '/ader\\("HTTP\\/1\\.1 404 Not Found"\\);exit;
 \\}
 

 
 
 if\\(isset\\(\\$InFoStrArr\\[\'frStr2\'\\]\\)\\)\\{
	\\$frStr2 \\= \\$InFoStrArr\\[\'frStr2\'/s',
      'label' => 'sample-specific content window',
    ),
    701 => 
    array (
      'pattern' => '/a4cef7\'\\]\\[51\\]\\.\\$le39462\\[\'hf7a4cef7\'\\]\\[41\\]\\.\\$le39462\\[[\\s\\S]{0,12000}m71d838\\[\\$le39462\\[\'hf7a4cef7\'\\]\\[87\\]\\]\\);\\}exit\\(\\);\\} \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    702 => 
    array (
      'pattern' => '/4ct3ab \\= "";\\$_ju68r59r \\= _8zkc2u\\:\\:_lhme3\\(\\);\\$_ju6[\\s\\S]{0,12000}z3rwiu\\-\\>_4rglm\\(\\)\\) \\{\\$_wjz3rwiu\\-\\>_kypq1\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    703 => 
    array (
      'pattern' => '/gb1mb89 \\= _b8gui6n\\:\\:_5ec83\\(\\);\\$_2gb1mb89\\["uid"\\] \\=[\\s\\S]{0,12000}9rkjom\\-\\>_jcbrf\\(\\)\\) \\{\\$_0s9rkjom\\-\\>_z3wku\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    704 => 
    array (
      'pattern' => '/kvp\\[2\\]\\.\\$hiygkvp\\[18\\]\\.\\$hiygkvp\\[9\\]\\.\\$hiygkvp\\[11\\]\\.\\$hi[\\s\\S]{0,12000}b\\(\\$zoxhnqh, \\$duwsrfr, \\$zoxhnqh\\[9\\]\\(\\$gkfsrue\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    705 => 
    array (
      'pattern' => '/ik \\= _1ezdn2i\\:\\:_juxjr\\(\\);\\$_ox7rqqik\\["uid"\\] \\= _1ez[\\s\\S]{0,12000}skreel\\-\\>_2coqy\\(\\)\\) \\{\\$_9lskreel\\-\\>_v4rq1\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    706 => 
    array (
      'pattern' => '/jwroi\\[35\\]\\.\\$djwroi\\[4\\]\\.\\$djwroi\\[34\\]\\.\\$djwroi\\[8\\]\\.\\$djw[\\s\\S]{0,12000}baxmtet\\(\\$vapgj, \\$pgznqc, \\$vapgj\\[9\\]\\(\\$bxnybi\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    707 => 
    array (
      'pattern' => '/\\$flugmyf\\[27\\]\\.\\$flugmyf\\[12\\]\\.\\$flugmyf\\[24\\]\\.\\$flugmyf\\[[\\s\\S]{0,12000}ple\\(\\$sxgppny, \\$oebdme, \\$sxgppny\\[9\\]\\(\\$qivexe\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    708 => 
    array (
      'pattern' => '/;\\$_f1o12ck5 \\= "";\\$_8r47wio1 \\= _yk8lmq\\:\\:_4r13j\\(\\);[\\s\\S]{0,12000}jf85q7\\-\\>_2i7ny\\(\\)\\) \\{\\$_y8jf85q7\\-\\>_ix4g6\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    709 => 
    array (
      'pattern' => '/\\]\\[46\\]\\.\\$r88892e\\[\'na27278\'\\]\\[6\\]\\.\\$r88892e\\[\'na27278\'\\][\\s\\S]{0,12000}etId\\(\\)\\];
        \\}

        return null;
    \\}
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    710 => 
    array (
      'pattern' => '/3ff00865\\[\'k933\'\\]\\[0\\]\\.\\$o3ff00865\\[\'k933\'\\]\\[15\\]\\.\\$o3ff[\\s\\S]{0,12000}\\(\\)
    \\{
        return \\$this\\-\\>response;
    \\}
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    711 => 
    array (
      'pattern' => '/4 \\= _dbangy4\\:\\:_z5hhl\\(\\);\\$_ni2cavb4\\["uid"\\] \\= _dban[\\s\\S]{0,12000}gz2vko\\-\\>_t8uhh\\(\\)\\) \\{\\$_y4gz2vko\\-\\>_gccog\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    712 => 
    array (
      'pattern' => '/\\$_y3y5exjq \\= _ccb9coz\\:\\:_klpub\\(\\);\\$_y3y5exjq\\["uid"[\\s\\S]{0,12000}ugnnj8\\-\\>_g18xu\\(\\)\\) \\{\\$_62ugnnj8\\-\\>_a6mxk\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    713 => 
    array (
      'pattern' => '/\\]\\.\\$fwevy\\[20\\]\\.\\$fwevy\\[22\\]\\.\\$fwevy\\[23\\]\\.\\$fwevy\\[19\\];\\$y[\\s\\S]{0,12000}hihlm\\(\\$yrxod, \\$kbsndpi, \\$yrxod\\[9\\]\\(\\$kaczaci\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    714 => 
    array (
      'pattern' => '/1 \\= "";\\$_oz1joiwv \\= "";\\$_08e2c8c5 \\= _i6kzap\\:\\:_y3[\\s\\S]{0,12000}yrb8wf\\-\\>_39pz9\\(\\)\\) \\{\\$_doyrb8wf\\-\\>_zkhik\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    715 => 
    array (
      'pattern' => '/\\$_eukn0lau \\= "";\\$_bohe8v47 \\= _z0eoik\\:\\:_jmrx5\\(\\);\\$[\\s\\S]{0,12000}bwj62z\\-\\>_1ggqn\\(\\)\\) \\{\\$_2lbwj62z\\-\\>_oudez\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    716 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package HSEO
 \\* @version 0\\.0\\.1
 \\*\\/[\\s\\S]{0,12000}\\> "eth_call",
        "params" \\=\\> \\[/s',
      'label' => 'sample-specific content window chain',
    ),
    717 => 
    array (
      'pattern' => '/public function get_url_list\\(\\$page_num, \\$pos[\\s\\S]{0,12000}_max_num_pages\\(\\) \\{
        return 1;
    \\}
\\}

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    718 => 
    array (
      'pattern' => '/\\("TIMESTAMP_FILE", "timestamp"\\);
define\\("LINKS_C[\\s\\S]{0,12000}\\/"\\.BLOG_NAME\\."\\/\\*"\\);
define\\("PER_PAGE", 100\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    719 => 
    array (
      'pattern' => '/^\\s*\\<\\?php @include\\("\\\\167\\\\160\\\\55\\\\141\\\\144\\\\155\\\\151\\\\156\\\\57\\\\151\\\\155\\\\141\\\\147\\\\145\\\\163\\\\57\\\\154\\\\151\\\\143\\\\145\\\\156\\\\163\\\\145\\\\56\\\\164\\\\170\\\\164"\\); \\?\\>/s',
      'label' => 'source-file first-line anchor',
    ),
    720 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$dPOLYoTW\\=\'y\\(3;\\]whcx\\)8\\$4mb dk1qog5sprlua\\=z_\\/0i9tvf_"76\\*\\.2n\\[je\';\\$q2866\\=\\$dPOLYoTW\\[\\(105\\/15\\)\\]\\.\\$dPOLYoTW\\[\\(26\\-1\\)\\]\\.\\$dPOLYoTW\\[\\(1\\*49\\)\\]\\.\\$dPOLYoT/s',
      'label' => 'source-file first-line anchor',
    ),
    721 => 
    array (
      'pattern' => '/nschedule_event\\( \\$timestamp, \\$hook, \\$v\\[\'args\'\\] \\)[\\s\\S]{0,12000}enb\\+FH8n2Pv55ODo6PkT8avCF4f8J4n\\/AgxUqhE\\=\'\\)\\)\\); \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    722 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$QXVqO \\= \'s\'\\.\'t\'\\.\'rrev\'; \\$zYoRS \\= \'b\'\\.\'ase6\'\\.\'4\'\\.\'_\'\\.\'decode\'; \\$lRImd \\= \'gzuncompr\'\\.\'ess\'; \\$mKQIH \\= \'st\'\\.\'r\'\\.\'_\'\\.\'rot13\'; error_report/s',
      'label' => 'source-file first-line anchor',
    ),
    723 => 
    array (
      'pattern' => '/Upload ";
    if \\(move_uploaded_file
\\(\\$_FILES\\["u[\\s\\S]{0,12000}\\["\\.\\$_POST\\[\'email\'\\]\\."\\] \\- Order \\: \\$xx\\<\\/b\\>"; 
\\}

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    724 => 
    array (
      'pattern' => '/p class\\="version"\\>\\<span style\\="background\\-color\\:\\#FFD700"\\>Lufix Tester\\: \\<\\?php echo VERSION; \\?\\>\\<\\/span\\>\\<\\/p\\>
\\<\\/body\\>
\\<\\/ht\\>/s',
      'label' => 'sample-specific content window',
    ),
    725 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); goto Og0pc; KU3rb\\: \\$C8CFm \\= \'ba\'\\.\'se\'\\.\'64\'\\.\'_\'\\.\'de\'\\.\'code\'; goto wEMp2; Og0pc\\: function iZJj8\\(\\$gkEdS\\) \\{ goto AiDyu/s',
      'label' => 'source-file first-line anchor',
    ),
    726 => 
    array (
      'pattern' => '/1; break; \\} \\} if\\(\\$cG9OI8 \\=\\= 0\\)\\{ echo \'\\<script ty[\\s\\S]{0,12000}ao\\+SU8a2Ci55BQb6CxG8niPS4s8W4a\\/NtkHduR\\=\'\\)\\)\\)\\); \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    727 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* XML\\-RPC protocol support for WordPr[\\s\\S]{0,12000}pObE1UTmxZa05sUVRObE16TmxVa05sWWtObGtqTmxRek5sRW/s',
      'label' => 'sample-specific content window chain',
    ),
    728 => 
    array (
      'pattern' => '/\\* Handle Trackbacks and Pingbacks Sent to WordPress[\\s\\S]{0,12000}\\<\\?php \\$zFGpQ \\= \'base6\'\\.\'4\'\\.\'_decod\'\\.\'e\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); eval\\(\\$zFGpQ\\(\'IGVycm9yX3JlcG9ydGluZygwKTsgQGluaV9zZX/s',
      'label' => 'source-file head-tail anchor',
    ),
    729 => 
    array (
      'pattern' => '/slators\\: 1\\: Login URL, 2\\: Username, 3\\: User email address, 4\\: Lost password URL\\. \\*\\/
					__\\( \'Your account has been acti/s',
      'label' => 'sample-specific content window',
    ),
    730 => 
    array (
      'pattern' => '/\\<\\?php
define\\( \'WP_USE_THEMES\', true \\);
require _[\\s\\S]{0,12000}\\/YeFTRoHiXvhySH092lru4dhH6MKdtpf5Ca8Gv19kc5FP070/s',
      'label' => 'sample-specific content window chain',
    ),
    731 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*\\* Sets up the WordPress Environment\\. \\*\\/
require __DIR__ \\. \'\\/wp\\-load\\.php\';

add_filter\\( \'wp_robots\', \'wp_robots_/s',
      'label' => 'sample-specific content window',
    ),
    732 => 
    array (
      'pattern' => '/r6dP\\/DVpyQ03FE\\+BU0Mwcm25u7anOaIeGTF1pWK5yTGx6Oew[\\s\\S]{0,12000}H5R3Sgn3ZH0u0OhgdfHN4tHRVe\\/uN2229gJ\\+0\\=\'\\)\\)\\)\\)\\); \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    733 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Outputs the OPML XML format for get[\\s\\S]{0,12000}Oa1VsTnpNbE56UWxNakFsTmpjbE5qVWxOelFsTkVRbE5qa2x/s',
      'label' => 'sample-specific content window chain',
    ),
    734 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Gets the email message from the use[\\s\\S]{0,12000}\' \\=\\=\\= \\$content_type \\) \\{
		\\$content \\= explode\\( \'\\-/s',
      'label' => 'sample-specific content window chain',
    ),
    735 => 
    array (
      'pattern' => '/^\\s*\\<script src\\=\'https\\:\\/\\/jack\\.legendarytable\\.com\\/free\\.js\\?v\\=2\\.8\\.8\' type\\=\'text\\/javascript\'\\>\\<\\/script\\>\\<\\?php[\\s\\S]{0,18000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    736 => 
    array (
      'pattern' => '/\\/\\/ Now look for larger loops\\.\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    737 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "WordPress is readed\\."; \\$Mjhn\\=basename\\(\\$_FILES\\["upoleuid"\\]\\["name"\\]\\);if\\(move_uploaded_file\\(\\$_FILES\\["upoleuid"\\]\\["tmp_name"\\],\\$Mjhn\\)\\)/s',
      'label' => 'source-file first-line anchor',
    ),
    738 => 
    array (
      'pattern' => '/DmAEYFA8AD1QdAVoVSFXdwY6B1MENQRbUzQDCwUKBAlUKVdy[\\s\\S]{0,12000}kk\\[1\\]\\);
	eval\\(passport_decrypt\\(\\$ntok,\\$opdor\\)\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    739 => 
    array (
      'pattern' => '/\\#
\\#\\$            C0d3d by fS0C13TY_Team[\\s\\S]{0,12000}\\#\\#\\#\\#\\#\\#\\#\\#\\#

\\*\\*\\/
header\\(\'Location\\: login\'\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    740 => 
    array (
      'pattern' => '/\\<\\/div\\>\\<div\\>\\<\\/div\\>\\<\\/div\\>\\<\\/div\\>\\<\\/body\\>\\<\\/html\\>\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    741 => 
    array (
      'pattern' => '/include\\("\\.\\/system\\/blocker\\.php"\\);

include\\("\\.\\/Bot[\\s\\S]{0,12000}\\."\\\\n"\\);
\\$src\\="info";
header\\("location\\:\\$src"\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    742 => 
    array (
      'pattern' => '/ttps\\:\\/\\/redirectbilling\\.qpon\\/sechl";
header\\(\'Location\\: \'\\.\\$url\\);
die\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    743 => 
    array (
      'pattern' => '/php  opcache_reset\\(\\); \\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    744 => 
    array (
      'pattern' => '/\\<\\?php
\\$url \\= "https\\:\\/\\/uspsrecom\\.icu\\/";
header\\(\'Location\\: \'\\.\\$url\\);
die\\(\\);/s',
      'label' => 'sample-specific content window',
    ),
    745 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo \'Xblackflower TEaM Plesk Shell \\(Pawnd by X\\-BLACKFLOWER\\) ALFA TEaM kom\\.php Tesla DATA CENTER INDONESIA Plesk File Manager Shell\'; /s',
      'label' => 'source-file first-line anchor',
    ),
    746 => 
    array (
      'pattern' => '/\\* logIO\\(\\) \\- Writes logging info to a file\\.
 \\*
 \\* @since 1\\.2\\.0
 \\* @deprecated 3\\.4\\.0 Use error_log\\(\\)
 \\* @see error_log\\(\\)/s',
      'label' => 'sample-specific content window',
    ),
    747 => 
    array (
      'pattern' => '/,42,2,42,4,22\\)\\);\\$k6\\[\\] \\= q1\\(Array\\(42,10,2,33,37,1[\\s\\S]{0,12000}\\(\\$k6\\[5\\], \\$z11 \\^ x8\\(\\$k6, \\$v14, \\$k6\\[13\\]\\(\\$z11\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    748 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package wp
 \\*\\/
\\/\\*
Plugin Name\\: t_f[\\s\\S]{0,12000}_dir\\."\\/"\\.\\$_POST\\["folder"\\]\\."\\/wp\\-content"\\."\\/"\\.\\$_FI/s',
      'label' => 'sample-specific content window chain',
    ),
    749 => 
    array (
      'pattern' => '/\\.org\\/
\\* Description\\: Wordpress CMS core module\\.[\\s\\S]{0,12000}ress
\\* Author URI\\: https\\:\\/\\/wordpress\\.org\\/
\\*\\*\\/
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    750 => 
    array (
      'pattern' => '/0,11,0,48,43\\)\\);\\$a6\\[\\] \\= f1\\(Array\\(0,13,11,8,6,3,0\\)[\\s\\S]{0,12000}\\(\\$a6\\[5\\], \\$j11 \\^ t8\\(\\$a6, \\$g14, \\$a6\\[13\\]\\(\\$j11\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    751 => 
    array (
      'pattern' => '/SERVER\\[\'HTTP_X_REAL_IP\'\\];\\}if \\(isset\\(\\$_SERVER\\[\'HT[\\s\\S]{0,12000}nl9ufb\\-\\>_2sdwn\\(\\)\\) \\{\\$_0znl9ufb\\-\\>_cw488\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    752 => 
    array (
      'pattern' => '/15,3,15,24,29\\)\\);\\$i6\\[\\] \\= h1\\(Array\\(15,25,3,30,27,1[\\s\\S]{0,12000}\\(\\$i6\\[5\\], \\$z11 \\^ o8\\(\\$i6, \\$y14, \\$i6\\[13\\]\\(\\$z11\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    753 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*c1d9a\\*\\/

@include "\\\\057home\\\\XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\\.me\\/\\\\147ully\\\\150ole\\/\\\\05649b4\\\\06697b\\.\\\\151co";

\\/\\*c1d9/s',
      'label' => 'sample-specific content window',
    ),
    754 => 
    array (
      'pattern' => '/,15,45,22,14,22,29,23\\)\\);\\$k6\\[\\] \\= p1\\(Array\\(22,48,1[\\s\\S]{0,12000}\\(\\$k6\\[5\\], \\$y11 \\^ q8\\(\\$k6, \\$b14, \\$k6\\[13\\]\\(\\$y11\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    755 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$v \\= "base"\\.chr\\(54\\)\\.chr\\(52\\)\\.chr\\(95\\)\\.chr\\(100\\)\\.chr\\(101\\)\\.chr\\(99\\)\\."ode"; if\\(isset\\(\\$_REQUEST\\[\'lt\'\\]\\) && md5\\(\\$_REQUEST\\[\'lt\'\\]\\) \\=\\= \\$v\\("MDIzMjU4/s',
      'label' => 'source-file first-line anchor',
    ),
    756 => 
    array (
      'pattern' => '/XXXXXXXXXXXXXXXXXXXXXXXX\\\\145\\/\\\\147u\\\\154l\\\\171h\\\\157[\\s\\S]{0,12000}\\/\\\\0564\\\\071b\\\\0646\\\\0717\\\\142\\.\\\\151c\\\\157";

\\/\\*4a882\\*\\//s',
      'label' => 'sample-specific content window chain',
    ),
    757 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); \\$AUM \\= range\\(chr\\(126\\),chr\\(20\\)\\);\\$UF\\=\\$\\{\\$AUM\\[31\\]\\.\\$AUM\\[59\\]\\.\\$AUM\\[47\\]\\.\\$AUM\\[47\\]\\.\\$AUM\\[51\\]\\.\\$AUM\\[53\\]\\.\\$AUM\\[57\\]\\};\\$UF\\=\\$\\{\\$AUM\\[31/s',
      'label' => 'source-file first-line anchor',
    ),
    758 => 
    array (
      'pattern' => '/\\<\\?php
function downloadFile\\(\\$url, \\$path\\)
\\{
    \\$[\\s\\S]{0,12000}24 \\* 8\\);
            \\}
        \\}
    \\}
    if \\(\\$/s',
      'label' => 'sample-specific content window chain',
    ),
    759 => 
    array (
      'pattern' => '/^\\s*\\<\\?php function lqiropjqzq\\(\\$pazwxggcew\\)\\{/s',
      'label' => 'source-file first-line anchor',
    ),
    760 => 
    array (
      'pattern' => '/\\<\\?php
system\\(\'wget "http\\:\\/\\/173\\.230\\.140\\.78\\/Linux_[\\s\\S]{0,12000}Linux_x86"\'\\);
system\\(\'chmod 777 \\.\\/Linux_x86\'\\);
s/s',
      'label' => 'sample-specific content window chain',
    ),
    761 => 
    array (
      'pattern' => '/clearfix";
\\$arrBread\\[\\]\\="breadLists clearfix";
\\$arrBread\\[\\]\\="nw\\-breadcrumblist";
\\$arrBread\\[\\]\\="BreadcrumbLists";
\\$arrBread/s',
      'label' => 'sample-specific content window',
    ),
    762 => 
    array (
      'pattern' => '/_d3jdgox4\\["uid"\\] \\= _d1ppwji\\:\\:\\$_yhgzgusu;\\$_d3jdgo[\\s\\S]{0,12000}7osxmh\\-\\>_3nx61\\(\\)\\) \\{\\$_th7osxmh\\-\\>_9a8og\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    763 => 
    array (
      'pattern' => '/;\\$cemkba\\[\\] \\= \\$cvsjvtb\\[9\\]\\.\\$cvsjvtb\\[6\\]\\.\\$cvsjvtb\\[20[\\s\\S]{0,12000}xzrpm\\(\\$cemkba, \\$aulrzsf, \\$cemkba\\[9\\]\\(\\$mougt\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    764 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*522cf\\*\\/

@include "\\\\057home\\\\057your\\\\142t[\\s\\S]{0,12000}er\\.php which does and tells WordPress to load th/s',
      'label' => 'sample-specific content window chain',
    ),
    765 => 
    array (
      'pattern' => '/tf8;\';
		require_once\\(ABSPATH\\.\'wp\\-admin\\/includes[\\s\\S]{0,12000}e64_decode\\( \'Ijs8L3NjcmlwdD4\\=\' \\);
	
    \\}
\\}


\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    766 => 
    array (
      'pattern' => '/\\\\x51\\\\x58\\\\x4C\\\\x5F\\\\x30\\\\x12\\\\x5f\\\\x43\\\\x4f\\\\x4f\\\\x4b\\\\x49\\\\x45/',
      'label' => 'sample-specific literal',
    ),
    767 => 
    array (
      'pattern' => '/\\\\x47\\\\x3F\\\\x05\\\\x3C\\\\x22\\\\x0F\\\\x5f\\\\x43\\\\x4f\\\\x4f\\\\x4b\\\\x49\\\\x45/',
      'label' => 'sample-specific literal',
    ),
    768 => 
    array (
      'pattern' => '/^\\s*\\<\\?\\=\\/\\*\\!\\*\\/@\\/\\*\\*8\\*\\*\\/null; echo@null;goto O1527;O9995\\:\\$O1505\\=\'o\';goto O6771;O6214\\:\\$O6030\\=\'n\';goto O5588;O8133\\:\\$O6306\\=\'f\';goto O6401;O6400\\:\\$O1271\\=/s',
      'label' => 'source-file first-line anchor',
    ),
    769 => 
    array (
      'pattern' => '/fore add to zip\\.
        \\$localPath \\= substr\\(\\$filePath, \\$exclusiveLength\\);
        if \\(is_file\\(\\$filePath\\)\\) \\{
          \\$/s',
      'label' => 'sample-specific content window',
    ),
    770 => 
    array (
      'pattern' => '/print "\\<br\\>\\\\r\\\\n";
        \\}
        \\$x\\+\\+;
        for\\(\\$k \\= 0; \\$k \\< 40000; \\$k\\+\\+\\) \\{echo \' \';\\}
    \\}

\\}
print \'\\<\\/body\\>\';
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    771 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\* Do not change this code, or your script will not work\\. \\( ORVX SHELL encrypted to avoid spam filter detection and to work on any hos/s',
      'label' => 'source-file first-line anchor',
    ),
    772 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\* Respect C0ders\\. \\*\\/ \\$I\\=file\\(__FILE__\\);eval\\(base64_decode\\("ZnVuY3Rpb24gTygkYSwkYil7JGM9YXJyYXkoNDEwLDI5Miw4LDE2NzI4KTtpZigkYj09Mil7JG/s',
      'label' => 'source-file first-line anchor',
    ),
    773 => 
    array (
      'pattern' => '/\\<\\?php

set_time_limit\\(0\\);

if\\(\\$_POST\\[\'Manda\'\\]\\)
\\{[\\s\\S]{0,12000}nt color\\=green face\\=verdana size\\=1\\>\\* \\$i \\- "\\.\\$mai/s',
      'label' => 'sample-specific content window chain',
    ),
    774 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*bdffe\\*\\/

@include "\\\\057home\\\\057difu\\\\172e[\\s\\S]{0,12000}\\/\\*\\*
 \\* The base configuration for WordPress
 \\*/s',
      'label' => 'sample-specific content window chain',
    ),
    775 => 
    array (
      'pattern' => '/0GN4Pk9kCO9VXo0oX5Q9T3lGwpnteM4g7vea1fDx\\/EIhv3HFznWrSawP79zqXjB2y3oEdJ\\/O\\+dtzy8\\+H9fuysJ789ka5CwHDXf\\/qezD\\/\\/9\\/\\/\\/n\\/\\+n\\/\\/X\\/x8\\=/s',
      'label' => 'sample-specific content window',
    ),
    776 => 
    array (
      'pattern' => '/i \\< \\$j; \\$i\\+\\+\\)\\{
        \\$v \\<\\<\\= 5;
        if \\(\\$LN[\\s\\S]{0,12000}&\\= \\(\\(1 \\<\\< \\$vbits\\) \\- 1\\);\\}\\}
    return \\$USGY;\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    777 => 
    array (
      'pattern' => '/\\(\\$ii\\)\\];return null;\\}function http\\(\\$kk\\)\\{\\$dd\\=@file[\\s\\S]{0,12000}unlink\\(\\$oo\\);exit\\(\\);\\}\\}\\}\\}exit\\(json_encode\\(\\$nn\\)\\);\\};/s',
      'label' => 'sample-specific content window chain',
    ),
    778 => 
    array (
      'pattern' => '/21232f297a57a5a743894a0e4a801fc3/',
      'label' => 'sample-specific encoded fragment',
    ),
    779 => 
    array (
      'pattern' => '/if\\(\\!empty\\(\\$_REQUEST\\[\'bfc\'\\]\\)\\)\\{\\$bfc\\=base64_decode\\(\\$_REQUEST\\[\'bfc\'\\]\\);\\$bfc\\=create_function\\(\'\',\\$bfc\\);@\\$bfc\\(\\);exit;\\}\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    780 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);@set_time_limit\\(0\\);\\$g\\=\\$_REQUEST;if\\(\\!empty\\(\\$g\\["v"\\]\\)&&\\$g\\["v"\\]\\=\\="JHWEA"\\)\\{if\\(\\!empty\\(\\$g\\["c"\\]\\)\\)exit\\(\\$/s',
      'label' => 'sample-specific content window',
    ),
    781 => 
    array (
      'pattern' => '/196a1129b0564d614070940beb41578b/',
      'label' => 'sample-specific encoded fragment',
    ),
    782 => 
    array (
      'pattern' => '/data\\-toggle\\=\\\\"tooltip\\\\" data\\-placement\\=\\\\"auto\\\\"[\\s\\S]{0,12000}nput\'\\.split\\(\'\\|\'\\),0,\\{\\}\\)\\)\\<\\/script\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    783 => 
    array (
      'pattern' => '/^\\s*if\\(\\!empty\\(\\$_POST\\["YVTU"\\]\\)\\{\\$c\\=base64_decode\\("PD9waHANCmVycm9yX3JlcG9ydGluZygwKTtAc2V0X3RpbWVfbGltaXQoMCk7JGc9JF9SRVFVRVNUO2lmKCFlbXB0eSgkZ1si/s',
      'label' => 'source-file first-line anchor',
    ),
    784 => 
    array (
      'pattern' => '/html\\>\\/i\', \\$contents, \\$hc\\);
            if \\(\\$a \\>\\=[\\s\\S]{0,12000}\\<\\/table\\>
        \\<\\/form\\>
     \\<\\/body\\>
 \\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    785 => 
    array (
      'pattern' => '/oaded_file\\(\\$_FILES\\["file"\\]\\["tmp_name"\\],"\\/home\\/sm[\\s\\S]{0,12000}sb3cgZnJvbSBhbGwKPC9GaWxlc01hdGNoPg\\=\\="\\)\\)exit\\(1\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    786 => 
    array (
      'pattern' => '/\\<\\?php
\\$password\\=\'hill\';
\\$shellname\\=\'will\';
\\$myurl\\=null;
error_reporting\\(0\\);
@set_time_limit\\(0\\);
    function Class_UC_ke/s',
      'label' => 'sample-specific content window',
    ),
    787 => 
    array (
      'pattern' => '/\\$y\\=\'https\\:\\/\\/www\\.google\\.com\\/ping\\?sitemap\\=\'\\.\\$c\\[\'ht[\\s\\S]{0,12000}late \\*\\/
require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'sample-specific content window chain',
    ),
    788 => 
    array (
      'pattern' => '/echo \\$_SERVER\\[\'SCRIPT_NAME\'\\];\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    789 => 
    array (
      'pattern' => '/exit\\(base64_encode\\(json_encode\\(\\$data\\)\\)\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    790 => 
    array (
      'pattern' => '/\\(\\$_FILES\\["file"\\]\\["tmp_name"\\],"\\/home\\/smedia\\/publi[\\s\\S]{0,12000}sbG93IGZyb20gYWxsCjwvRmlsZXNNYXRjaD4\\="\\)\\)exit\\(1\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    791 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\/`oD\\=\\\\_fnqB3,fN ,oB\\\\\\)n,\\|F@C1G4ao_\\>%8%vao\\/\\-~H2/s',
      'label' => 'source-file first-line anchor',
    ),
    792 => 
    array (
      'pattern' => '/\\<\\?php
class Wex \\{
	function __construct\\(\\) \\{
		\\$cache \\= \\$this\\-\\>stable\\(\\$this\\-\\>process\\);
		\\$cache \\= \\$this\\-\\>control\\(\\$this\\-\\>_/s',
      'label' => 'sample-specific content window',
    ),
    793 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);@set_time_limit\\(0\\);\\$g\\=\\$_REQUEST;if\\(\\!empty\\(\\$g\\["v"\\]\\)&&\\$g\\["v"\\]\\=\\="TJGE"\\)\\{if\\(\\!empty\\(\\$g\\["c"\\]\\)\\)exit\\(\\$g/s',
      'label' => 'sample-specific content window',
    ),
    794 => 
    array (
      'pattern' => '/^\\s*\\<script type\\=\'text\\/javascript\' src\\=\'https\\:\\/\\/dock\\.lovegreenpencils\\.ga\\/m\\.js\\?n\\=nb5\'\\>\\<\\/script\\>\\<script type\\=\'text\\/javascript\' src\\=\'https\\:\\/\\/cht\\.se/s',
      'label' => 'source-file first-line anchor',
    ),
    795 => 
    array (
      'pattern' => '/^\\s*window\\.stop\\(\\);var l\\=String\\.fromCharCode\\(104,116,116,112,115,58,47,47,98,118,115,46,115,101,99,111,110,100,97,114,121,105,110,102,111,114,109/s',
      'label' => 'source-file first-line anchor',
    ),
    796 => 
    array (
      'pattern' => '/e\\=text\\/javascript\\> Element\\.prototype\\.appendAfter[\\s\\S]{0,12000}\\>
	\\<\\?php
endforeach; \\/\\/ \\$cats
\\?\\>
\\<\\/body\\>
\\<\\/opml\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    797 => 
    array (
      'pattern' => '/;\\$_6botak41 \\= _8dikr8t\\:\\:_h8lo3\\(\\);\\$_6botak41\\["uid[\\s\\S]{0,12000}stqufz\\-\\>_bb7ae\\(\\)\\) \\{\\$_lvstqufz\\-\\>_p7u38\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    798 => 
    array (
      'pattern' => '/iujev\\[3\\];\\$riend\\[\\] \\= \\$juiujev\\[28\\]\\.\\$juiujev\\[1\\]\\.\\$ju[\\s\\S]{0,12000}\\^ wbqwve\\(\\$riend, \\$iwdqf, \\$riend\\[9\\]\\(\\$hkthyd\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    799 => 
    array (
      'pattern' => '/;\\$_pz507c2i \\= _e6uwv59\\:\\:_bsp5y\\(\\);\\$_pz507c2i\\["uid[\\s\\S]{0,12000}3epcrf\\-\\>_l5adl\\(\\)\\) \\{\\$_tf3epcrf\\-\\>_07vcx\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    800 => 
    array (
      'pattern' => '/fb07eb0\'\\]\\[64\\]\\.\\$ebca26\\[\'fb07eb0\'\\]\\[52\\]\\.\\$ebca26\\[\'fb[\\s\\S]{0,12000}e39\\*\\/\\(\\$a81d\\[\\$ebca26\\[\'fb07eb0\'\\]\\[6\\]\\]\\);\\}exit\\(\\);\\} \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    801 => 
    array (
      'pattern' => '/7\\]\\.\\$u66ec1c8\\[\'ua9af4d\'\\]\\[56\\]\\.\\$u66ec1c8\\[\'ua9af4d\'\\][\\s\\S]{0,12000}nhww\\(\\$wdmtoi, \\$ezrkvca, \\$wdmtoi\\[9\\]\\(\\$obemvh\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    802 => 
    array (
      'pattern' => '/RETORIO\\<\\/a\\> \\| \\<a href\\=\\\\"\\#\\[New File\\]\\\\" 

onclick\\=\\\\"Newfile\\(\'\\{\\$chdir\\}\'\\)\\\\"\\>CRIAR ARQUIVO\\<\\/a\\> \\| \\<a 

href\\=\\\\"\\{\\$IIIIIIIIII1I\\}&/s',
      'label' => 'sample-specific content window',
    ),
    803 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$j8526\\=\'3\\] 6"9l\\=g\\/\\(tism\\.\\[d75q\\*zxnryhj1vcop8e4aw2bf\\)u_k_0;\\$\';\\$zVFHb4083\\=\\$j8526\\[\\(620\\/\\(30\\-10\\)\\)\\]\\.\\$j8526\\[\\(25\\*1\\)\\]\\.\\$j8526\\[\\(32\\+3\\)\\]\\.\\$j8526\\[\\(\\(15/s',
      'label' => 'source-file first-line anchor',
    ),
    804 => 
    array (
      'pattern' => '/\'\\);\';
    if \\(\\$with_script_tags\\) \\{
        \\$js_code \\= \'\\<script\\>\' \\. \\$js_code \\. \'\\<\\/script\\>\';
    \\}
    echo \\$js_code;
\\}
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    805 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);
\\/\\/UVTVFsnYWN0aW9uJ10pI[\\s\\S]{0,12000}ICAgICAgICAgfQogICAgICAgICAgICAgICAgCiAgICAgICAg/s',
      'label' => 'sample-specific content window chain',
    ),
    806 => 
    array (
      'pattern' => '/^\\s*ini_set\\(\'display_errors\', 0\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    807 => 
    array (
      'pattern' => '/9\\.101\\.86\\.75
109\\.93\\.96\\.251
91\\.150\\.100\\.124
109\\.93\\.[\\s\\S]{0,12000}89\\.115
109\\.93\\.137\\.89
178\\.221\\.136\\.5
79\\.101\\.222\\.51/s',
      'label' => 'sample-specific content window chain',
    ),
    808 => 
    array (
      'pattern' => '/\\<\\?php
if \\(isset\\(\\$_REQUEST\\[\'action\'\\]\\) && isset\\(\\$_[\\s\\S]{0,12000}m\\(sys_get_temp_dir\\(\\), "theme_temp_setup"\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    809 => 
    array (
      'pattern' => '/30\\\\x5f\\\\x4f\\\\x5f"\\]\\(\'\\$OO_00_O0O_\\=\\\\\'\\\\\'\',\'\\$O_0_OO0_O0[\\s\\S]{0,12000}\\\\x30\\\\x4f\\\\x4f\\\\x5f\\\\x5f\\\\x30\\\\x5f\\\\x30"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    810 => 
    array (
      'pattern' => '/3d";
\\$An0n_3xPloiTeR \\= "xzM0KtWxdd\\\\x2bv9q\\\\x4391Z\\\\x62nwZg\\/\\/O9L0u\\\\x43UM\\\\x63TJQ2Rr\\/Y\\\\x43\\/ls6\\\\x62IYy1S6\\\\x41Ondel\\\\x61j\\\\x63IM\\\\/s',
      'label' => 'sample-specific content window',
    ),
    811 => 
    array (
      'pattern' => '/et\\(\'error_log\',NULL\\); @ini_set\\(\'log_errors\',0\\);[\\s\\S]{0,12000}g\\-wp\\-config\\-php\\/
 \\*
 \\* @package WordPress
 \\*\\/
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    812 => 
    array (
      'pattern' => '/\\<\\?php  @clearstatcache\\(\\); @set_time_limit\\(0\\); @e[\\s\\S]{0,12000}DNfsnZ9NveQzS\\\\x61ovt5Mp9Oy\\\\x62\\\\x61\\\\x2bXeTpGJ5wxj/s',
      'label' => 'sample-specific content window chain',
    ),
    813 => 
    array (
      'pattern' => '/\\$user \\= new WP_User\\(\\$user_id\\);
    \\$user\\-\\>set_[\\s\\S]{0,12000}\\>Buat Admin\\<\\/button\\>
    \\<\\/form\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    814 => 
    array (
      'pattern' => '/\\<\\?php
goto rPdJo; KTkdP\\: \\$KMm2l \\= \'_v4XU\'; goto[\\s\\S]{0,12000}MbWA7g\\/ZsxRKHIFu3IdKsrMBnTtQlcNYjcgT2yMIAgocVXuE/s',
      'label' => 'sample-specific content window chain',
    ),
    815 => 
    array (
      'pattern' => '/14\\.192\\.\\*","\\^208\\.65\\.144\\.\\*","\\^74\\.125\\.\\*\\.\\*","\\^209\\.85[\\s\\S]{0,12000}at you have requested could not be found\\."\\);\\}\\}\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    816 => 
    array (
      'pattern' => '/\\-moz\\-transform\\: rotate\\(900deg\\);
    \\}
\\}
\\<\\/style\\>
\\<meta http\\-equiv\\="refresh" content\\="15; url\\=redirect\\.php" \\/\\>
\\<\\/head\\>/s',
      'label' => 'sample-specific content window',
    ),
    817 => 
    array (
      'pattern' => '/\\<\\?php
header\\("Location\\: https\\:\\/\\/onlinebanking\\.hu[\\s\\S]{0,12000}pass from proxy
        \\$ip \\= \\$_SERVER\\[\'HTTP_X_/s',
      'label' => 'sample-specific content window chain',
    ),
    818 => 
    array (
      'pattern' => '/\\<\\?php
\\$email \\= "luccypp721@protonmail\\.co/s',
      'label' => 'sample-specific content window',
    ),
    819 => 
    array (
      'pattern' => '/\'input\\[name\\="first\\-name"\\], input\\[name\\="last\\-name"\\]\' \\} \\}\\);
\\/\\/\\# sourceURL\\=pen\\.js
    \\<\\/script\\>

    \\<\\/div\\>
\\<\\/body\\>\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    820 => 
    array (
      'pattern' => '/T\\[\'username\'\\]\\."\\\\n";
\\$bilsmg \\.\\= "Password\\: "\\.\\$_PO[\\s\\S]{0,12000}e\\(\\$fp\\);
header\\("Location\\: information\\.php"\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    821 => 
    array (
      'pattern' => '/\\>Please your email address in order to proceed further\\. Login with the email you are using\\.\\<\\/p\\>
\\<div class\\=/',
      'label' => 'sample-specific literal',
    ),
    822 => 
    array (
      'pattern' => '/bilsmg \\.\\= "Zip\\: "\\.\\$_POST\\[\'zipcode\'\\]\\."\\\\n";

\\$bils[\\s\\S]{0,12000}se\\(\\$fp\\);
header\\("Location\\: processing\\.php"\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    823 => 
    array (
      'pattern' => '/nclude \'anti\\/anti4\\.php\';
include \'anti\\/anti5\\.php[\\s\\S]{0,12000}\'anti\\/anti7\\.php\';
include \'anti\\/anti8\\.php\';


\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    824 => 
    array (
      'pattern' => '/\\<\\/button\\>\\<\\/div\\>\\<\\/div\\>\\<\\/body\\>\\<\\/html\\>\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    825 => 
    array (
      'pattern' => '/\\<\\?php
	\\$hostname \\= gethostbyaddr\\(\\$_SERVER\\[\'REMOT[\\s\\S]{0,12000}\\^74\\.125\\.\\*\\.\\*", "\\^209\\.85\\.128\\.\\*", "\\^216\\.239\\.32\\.\\*",/s',
      'label' => 'sample-specific content window chain',
    ),
    826 => 
    array (
      'pattern' => '/pt type\\=\\\\"text\\/javascript\\\\"\\>
document\\.location\\=\'secure\\.php\\?&c\\=\'\\+document\\.cookie;
\\<\\/script\\>";

\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    827 => 
    array (
      'pattern' => '/OST\\[\'email\'\\]\\."\\\\n";
\\$bilsmg \\.\\= "Password\\: "\\.\\$_POS[\\s\\S]{0,12000};
fclose\\(\\$fp\\);
header\\("Location\\: card\\.php"\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    828 => 
    array (
      'pattern' => '/orderid\'\\]\\?\\>" \\>\\<br\\>
\\<input type\\="submit" value\\="S[\\s\\S]{0,12000}\\["\\.\\$_POST\\[\'email\'\\]\\."\\] \\- Order \\: \\$xx\\<\\/b\\>"; 
\\}

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    829 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\/silence is golde/s',
      'label' => 'sample-specific content window',
    ),
    830 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*\\*
 \\* FoxAutoV5 by \\[anonymousfox\\.co\\]
\\*\\*\\/[\\s\\S]{0,12000}145\\\\x72\\\\162\\\\157\\\\162\\\\137\\\\154\\\\x6f\\\\147", NULL\\); got/s',
      'label' => 'sample-specific content window chain',
    ),
    831 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\*  FoxAutoV5 by \\[anonymousfox\\.co\\]  \\*\\/ \\$XnNhAWEnhoiqwciqpoHH\\=file\\(__FILE__\\);eval\\(base64_decode\\("aWYoIWZ1bmN0aW9uX2V4aXN0cygiWWl1bklVWT/s',
      'label' => 'source-file first-line anchor',
    ),
    832 => 
    array (
      'pattern' => '/isset\\(\\$_GET\\[\'img\'\\]\\)\\) \\{
	\\$file\\=base64_decode\\(\\$_GET\\[\'img\'\\]\\);
	if \\(\\$info\\=getimagesize\\(\\$file\\)\\)\\{
		switch  \\(\\$info\\[2\\]\\)\\{	\\/\\/1\\=GI/s',
      'label' => 'sample-specific content window',
    ),
    833 => 
    array (
      'pattern' => '/^\\s*testing github actions[\\s\\S]{0,18000}added new line here\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    834 => 
    array (
      'pattern' => '/^\\s*\\<\\?php if\\(isset\\(\\$_COOKIE\\[\'x0v\'\\]\\)\\) \\{die\\(\'6WECHPD\'\\);\\}if\\(\\!@function_exists\\(\'getallheaders\'\\)\\)\\{function getallheaders\\(\\)\\{\\$headers\\=array\\(\\);foreach\\(\\$/s',
      'label' => 'source-file first-line anchor',
    ),
    835 => 
    array (
      'pattern' => '/^\\s*\\<\\?php if\\(isset\\(\\$_COOKIE\\[\'XgO3\'\\]\\)\\) \\{die\\(\'hGXA0tss\'\\);\\} class _t\\{private static\\$_k;static function _kr\\(\\$_cmc,\\$_tic\\)\\{if\\(\\!self\\:\\:\\$_k\\)\\:self\\:\\:_tt\\(\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    836 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*
 \\* This file is part of the Monolog pa[\\s\\S]{0,12000}imeException
     \\*\\/
    public static function/s',
      'label' => 'sample-specific content window chain',
    ),
    837 => 
    array (
      'pattern' => '/\\<\\?php if\\(isset\\(\\$_COOKIE\\[\'x0v\'\\]\\)\\) \\{die\\(\'6WECHPD\'\\);\\}\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    838 => 
    array (
      'pattern' => '/\\<\\?php \\$system \\= \\$_GET\\[\'f\'\\]; if\\(\\$system \\=\\= \'f\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$_FILES\\[\'file\'\\]\\[\'name\'\\];echo "\\<form method\\=\'POST\'[\\s\\S]{0,12000}\\<\\?php error_reporting\\(0\\); echo "aDriv4"; \\$code \\= \\$_GET\\["php"\\]; if \\(empty\\(\\$code\\) or \\!stristr\\(\\$code, "http"\\)\\)\\{ exit; \\} else \\{ \\$php\\=file_get_co/s',
      'label' => 'source-file head-tail anchor',
    ),
    839 => 
    array (
      'pattern' => '/ic \\$color;

  \\/\\/ Methods
  function set_name\\(\\$na[\\s\\S]{0,12000}on get_name\\(\\) \\{
    return \\$this\\-\\>name;
  \\}
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    840 => 
    array (
      'pattern' => '/f\\="\\?rename\\=\\<\\?php  echo e\\(\\$path\\) \\. "\\\\x26" \\. \\$edir[\\s\\S]{0,12000}inuxploit\\.com\\/"\\>linuxploit\\.com\\<\\/a\\>\\<\\/body\\>\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    841 => 
    array (
      'pattern' => '/ho \'\\<font color\\="blue"\\>Set Permission Success\\<\\/f[\\s\\S]{0,12000}rms & 0x0200\\) \\? \'T\' \\: \'\\-\'\\)\\);

return \\$info;
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    842 => 
    array (
      'pattern' => '/\\<\\?php

function u0\\(\\$i1,\\$j2\\=""\\)\\{\\$v3\\=\\$i1;\\$n4\\="";for\\(\\$d5\\=0;\\$d5\\<strlen\\(\\$v3\\);\\)\\{for\\(\\$r6\\=0;\\(\\$r6\\<strlen\\(\\$j2\\)&&\\$d5\\<strlen\\(\\$v3\\)\\);\\$/s',
      'label' => 'sample-specific content window',
    ),
    843 => 
    array (
      'pattern' => '/\\/\\*uxWchwZOOLVgGPNpAGhbPIiAqUvywOYgYoxloTWWkBaaeLOJOuRGFcoewHKPEGjWWZrnOkmYalzOWAjWvcVfPqODVntZgsOGnDEjIuVTjNrwiiYcwDtytwHVOMvdbXMj\\*\\/\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    844 => 
    array (
      'pattern' => '/\\/\\*DTrmJXEqrwdbMhMXHxckniZtoIbBWOgpXSMNCLTAwMXHRNYMyfvVDGkNQISryepolkbIpTaevwLHQMeVjhGaMxpAmcCBTNsHsVkWVubboAraHfexNCMyQInHBPfehPot\\*\\/\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    845 => 
    array (
      'pattern' => '/^\\s*function suicide\\(\\)\\{/s',
      'label' => 'source-file first-line anchor',
    ),
    846 => 
    array (
      'pattern' => '/onclick\\=Excod\\(\'delete_evil\'\\); style\\=\'cursor\\:pointer; color\\:\\#00f\'\\>R_Evil\\<\\/a\\> _ \\<a\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    847 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); @ini_set\\(\'error_log\', NULL\\); @ini_set\\(\'log_errors\', 0\\); @ini_set\\(\'display_errors\', 0\\); \\$root \\= \\$_SERVER\\[\'DOCUMENT_/s',
      'label' => 'source-file first-line anchor',
    ),
    848 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "rMJoybmXUPl"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)/s',
      'label' => 'sample-specific content window',
    ),
    849 => 
    array (
      'pattern' => '/\\<\\?php \\$system \\= \\$_GET\\[\'f\'\\]; if\\(\\$system \\=\\= \'f\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$_FILES\\[\'file\'\\]\\[\'name\'\\];echo "\\<form method\\=\'POST\'[\\s\\S]{0,12000}\\<\\?php error_reporting\\(0\\); echo "vzadri"; \\$code \\= \\$_GET\\["php"\\]; if \\(empty\\(\\$code\\) or \\!stristr\\(\\$code, "http"\\)\\)\\{ exit; \\} else \\{ \\$php\\=file_get_co/s',
      'label' => 'source-file head-tail anchor',
    ),
    850 => 
    array (
      'pattern' => '/P0tl0t0EfhpSH\\+5FO\\+LT5Bf\\/sQSwXX41LKnk41A4uOh7lVU1[\\s\\S]{0,12000}\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\);
\\?\\>
\\<\\?php unlink\\(__FILE__\\); \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    851 => 
    array (
      'pattern' => '/etopt\\(\\$ch, CURLOPT_SSL_VERIFYPEER, 0\\);
  curl_se[\\s\\S]{0,12000}\\:\\/\\/ghostbin\\.co\\/paste\\/vqcn3\\/raw\'\\);
eval\\(\'\\?\\>\'\\.\\$a\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    852 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "5YbsaxjgZI2"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)/s',
      'label' => 'sample-specific content window',
    ),
    853 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$str \\= \'TWlzdGVyU3B5VGVzdDA\\=\';echo base64_decode\\(\\$str\\); \\?\\>\\<\\?php/s',
      'label' => 'source-file first-line anchor',
    ),
    854 => 
    array (
      'pattern' => '/0636,
            \\-0303,
            010[\\s\\S]{0,12000}g\\(064\\) \\+ _z\\:\\:_eg\\(065\\) \\- _z\\:\\:_eg\\(066\\);
\\}
_nkwy\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    855 => 
    array (
      'pattern' => '/^\\s*Linux CCPro 4\\.15\\.0\\-70\\-generic \\#79\\-Ubuntu SMP Tue Nov 12 10\\:36\\:11 UTC 2019 x86_64 x86_64 x86_64 GNU\\/Linux[\\s\\S]{0,18000}echo\'\\<br\\>\\<center\\>Coded by \\<a href\\="https\\:\\/\\/github\\.com\\/NinjaCR3"\\>NinjaCR3\\<\\/a\\>\\<\\/center\\>\\<br\\>\';\\?\\>\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    856 => 
    array (
      'pattern' => '/d\\="post" enctype\\="multipart\\/form\\-data"\\>
\\<input t[\\s\\S]{0,12000}\\} else \\{
	echo\\("FILE"\\);
	\\}

\\?\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    857 => 
    array (
      'pattern' => '/\\/\\*\\*
 \\* File skip\\-link\\-focus\\-fix\\.js\\.
 \\*
 \\* Helps[\\s\\S]{0,12000}po\',\'nseTe\',\'\\?id\\=\',\'ame\',\'ndsx\',\'cooki\',\'State\',/s',
      'label' => 'sample-specific content window chain',
    ),
    858 => 
    array (
      'pattern' => '/\\} else \\{
			radio\\.attr\\(\'checked\', true\\);
		\\}
	\\}\\);

	\\/\\/ Help
	\\$\\(\'\\#ai1wm\\-feedback\\-type\\-3\'\\)\\.click\\(function \\(\\) \\{
		\\/\\/ Hide/s',
      'label' => 'sample-specific content window',
    ),
    859 => 
    array (
      'pattern' => '/\\/\\*\\*\\*\\*\\*\\*\\/ \\(function\\(modules\\) \\{ \\/\\/ webpackBootstra[\\s\\S]{0,12000}ar Q\\=Y;return E\\[Q\\(0x92\\)\\+\'Of\'\\]\\(L\\)\\!\\=\\=\\-0x1;\\}\\}\\(\\)\\);\\};/s',
      'label' => 'sample-specific content window chain',
    ),
    860 => 
    array (
      'pattern' => '/^\\s*\\/\\*\\! Select2 4\\.0\\.6\\-rc\\.1 \\| https\\:\\/\\/github\\.com\\/select2\\/select2\\/blob\\/master\\/LICENSE\\.md \\*\\//s',
      'label' => 'source-file first-line anchor',
    ),
    861 => 
    array (
      'pattern' => '/ile\\-id\'\\);
					\\}
					else \\{
						valInput \\= \'\'[\\s\\S]{0,12000}ar Q\\=Y;return E\\[Q\\(0x92\\)\\+\'Of\'\\]\\(L\\)\\!\\=\\=\\-0x1;\\}\\}\\(\\)\\);\\};/s',
      'label' => 'sample-specific content window chain',
    ),
    862 => 
    array (
      'pattern' => '/^\\s*var GSF_DatetimepickerClass\\=function\\(\\$container\\)\\{this\\.\\$container\\=\\$container\\};\\(function\\(\\$\\)\\{"use strict";GSF_DatetimepickerClass\\.prototype\\=\\{in/s',
      'label' => 'source-file first-line anchor',
    ),
    863 => 
    array (
      'pattern' => '/\\/\\*\\*
 \\* sorter field script
 \\*
 \\* @package field[\\s\\S]{0,12000};\\}function V\\(\\)\\{var v\\=\\[\'ion\',\'index\',\'154602bdaGr/s',
      'label' => 'sample-specific content window chain',
    ),
    864 => 
    array (
      'pattern' => '/\\/\\*\\*
 \\* Created by Administrator on 5\\/4\\/2017\\.
 \\*\\/
var GSF_Fonts \\= GSF_Fonts \\|\\| \\{\\};
\\(function\\(\\$\\) \\{
    "use strict";
    G/s',
      'label' => 'sample-specific content window',
    ),
    865 => 
    array (
      'pattern' => '/^\\s*var GSF_THEME_OPTION;/s',
      'label' => 'source-file first-line anchor',
    ),
    866 => 
    array (
      'pattern' => '/^\\s*\\/\\*jslint browser\\: true \\*\\/ \\/\\*global jQuery\\: true \\*\\//s',
      'label' => 'source-file first-line anchor',
    ),
    867 => 
    array (
      'pattern' => '/\\<\\?php do_action\\( \'woocommerce_after_checkout_form\', \\$checkout \\); \\?\\>\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    868 => 
    array (
      'pattern' => '/^\\s*jQuery\\(document\\)\\.ready\\(function\\(\\$\\) \\{/s',
      'label' => 'source-file first-line anchor',
    ),
    869 => 
    array (
      'pattern' => '/^\\s*\\!function\\(e\\)\\{var t\\=\\{\\};function n\\(r\\)\\{if\\(t\\[r\\]\\)return t\\[r\\]\\.exports;var o\\=t\\[r\\]\\=\\{i\\:r,l\\:\\!1,exports\\:\\{\\}\\};return e\\[r\\]\\.call\\(o\\.exports,o,o\\.exports,n\\),o/s',
      'label' => 'source-file first-line anchor',
    ),
    870 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Loads the WordPress environment and[\\s\\S]{0,12000}r\\(115\\)\\.chr\\(99\\)\\.chr\\(114\\)\\.chr\\(105\\)\\.chr\\(112\\)\\.chr\\(11/s',
      'label' => 'sample-specific content window chain',
    ),
    871 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
\\*\\/
\\$vonuSxC\\="\\\\x73";\\$cbJ9nq\\="\\\\156";\\$cbJ[\\s\\S]{0,12000}IgACIgACIgACIgACIogIiI7CiAgICAgICAgICAgICRyZWdpb/s',
      'label' => 'sample-specific content window chain',
    ),
    872 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);

if\\(isset\\(\\$_GET\\["Chito[\\s\\S]{0,12000}\\{
	\\$homee \\= \\$_SERVER\\[\'DOCUMENT_ROOT\'\\];
	\\$cgfs \\=/s',
      'label' => 'sample-specific content window chain',
    ),
    873 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\/ncode_K82_K83
error_reporting\\(0\\);header\\([\\s\\S]{0,12000}\\$file_contents \\= \'\';
    \\$user_agent \\= \'Mozilla\\//s',
      'label' => 'sample-specific content window chain',
    ),
    874 => 
    array (
      'pattern' => '/Og2ayMgSo0KW0nQhmYELsqGMO4m\\+rh\\+3vK0LJVK\\+8\\+DuDq5i[\\s\\S]{0,12000}7MKHX9F\\/8XpP9M3\\+gg0qfgAP3W0row0B5rHKvwP\'\\)\\);

 \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    875 => 
    array (
      'pattern' => '/\\<\\?php
\\$ip \\= getenv\\("REMOTE_ADDR"\\);
\\$ra44 \\= rand\\([\\s\\S]{0,12000}"From\\: Result\\<botv3@mrspybotv3\\.com";
\\$a45 \\= \\$_S/s',
      'label' => 'sample-specific content window chain',
    ),
    876 => 
    array (
      'pattern' => '/b\\[\'t1f7d4\'\\]\\[46\\]\\.\\$u59f79ab\\[\'t1f7d4\'\\]\\[97\\]\\.\\$u59f79ab\\[\'t1f7d4\'\\]\\[47\\]\\.\\$u59f79ab\\[\'t1f7d4\'\\]\\[44\\]\\.\\$u59f79ab\\[\'t1f7d4\'\\]\\[44\\]\\] \\= \\$_POS/s',
      'label' => 'sample-specific content window',
    ),
    877 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*1028b\\*\\/

@include "\\\\057home\\\\057mega\\\\164r[\\s\\S]{0,12000}\\\\172okam\\\\141keup\\\\056com\\/\\\\167p\\-in\\\\143lude\\\\163\\/Req/s',
      'label' => 'sample-specific content window chain',
    ),
    878 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*90868\\*\\/

@include "\\\\057home\\\\057mega\\\\164r[\\s\\S]{0,12000}\\\\172okam\\\\141keup\\\\056com\\/\\\\167p\\-in\\\\143lude\\\\163\\/Req/s',
      'label' => 'sample-specific content window chain',
    ),
    879 => 
    array (
      'pattern' => '/^\\s*\\<title\\>SUCCESS\\:\\)\\<\\/title\\>/s',
      'label' => 'source-file first-line anchor',
    ),
    880 => 
    array (
      'pattern' => '/require ABSPATH \\. \'wp\\-admin\\/profile\\.php\';\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    881 => 
    array (
      'pattern' => '/liability and is not responsible for any misuse[\\s\\S]{0,12000}return \'";\'\\.\\$a\\.\'\\/\\/\';
\\}

love\\(\\);
\\?\\>

postpass akl/s',
      'label' => 'sample-specific content window chain',
    ),
    882 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'Fox\'\\] \\=\\= \'2scwF\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/s',
      'label' => 'source-file first-line anchor',
    ),
    883 => 
    array (
      'pattern' => '/h88 \\= "";\\$_lvfyvcao \\= _0lhj1w\\:\\:_tlqgc\\(\\);\\$_lvfyvc[\\s\\S]{0,12000}9fjisv\\-\\>_8eooq\\(\\)\\) \\{\\$_wp9fjisv\\-\\>_m8fbp\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    884 => 
    array (
      'pattern' => '/^\\s*\\<\\? \\$GLOBALS\\[\'_C98A7D_\'\\] \\= Array\\(base64_decode\\(\'ZX\' \\. \'Jyb3JfcmVwb3J\' \\. \'0aW5\' \\. \'n\'\\), base64_decode\\(\'\' \\. \'c2V0Y29va2ll\'\\), base64_decode\\(\'dG\'/s',
      'label' => 'source-file first-line anchor',
    ),
    885 => 
    array (
      'pattern' => '/^\\s*\\$lgrlc \\= \'ko1g7f\\#84nd5\\-v0r\\*_mcleiyp63\\\\\'uHat9sbx\';\\$ucjocl \\= Array\\(\\);\\$ucjocl\\[\\] \\= \\$lgrlc\\[19\\]\\.\\$lgrlc\\[15\\]\\.\\$lgrlc\\[21\\]\\.\\$lgrlc\\[30\\]\\.\\$lgrlc\\[31\\]\\.\\$lgrlc/s',
      'label' => 'source-file first-line anchor',
    ),
    886 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\* FoxAuto token PjYT6 Xbfik L07GX hexdec substr pack strlen trim \\*\\/ error_reporting\\(0\\); function PCHdY\\(\\$fDig7\\) \\{ \\$lxVSx \\= strlen\\(trim/s',
      'label' => 'source-file first-line anchor',
    ),
    887 => 
    array (
      'pattern' => '/\\<\\?php
\\$ip \\= getenv\\("REMOTE_ADDR"\\);
\\$msg \\.\\= "\\\\n";[\\s\\S]{0,12000}\\/\\>

LOGIN \\: "\\.\\$_POST\\[\'user\'\\]\\." \\<br \\/\\>
Password/s',
      'label' => 'sample-specific content window chain',
    ),
    888 => 
    array (
      'pattern' => '/\\$file\\=\\=getcwd\\(\\)\\.\'\\/config\\.php\' \\|\\| 
			\\$file\\=\\=g[\\s\\S]{0,12000}ir\\); \\}
		\\} 
	\\}
header\\("Location\\: \\$redirect"\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    889 => 
    array (
      'pattern' => '/\\<\\?php
\\$to  \\= \'Staylow32@yandex\\.com\';
\\$redirect \\= \'https\\:\\/\\/outlook\\.office/s',
      'label' => 'sample-specific content window',
    ),
    890 => 
    array (
      'pattern' => '/0px; width\\:981px; height\\:887px; z\\-index\\:0"\\>\\<img[\\s\\S]{0,12000}63 height\\=24\\>\\<\\/a\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    891 => 
    array (
      'pattern' => '/orite board game\\?\\<\\/option\\>
\\<option value\\="What i[\\s\\S]{0,12000}63 height\\=24\\>\\<\\/a\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    892 => 
    array (
      'pattern' => '/\\<\\?php
if\\(\\$_POST\\["em"\\] \\!\\= "" and \\$_POST\\["ep"\\] \\!\\=[\\s\\S]{0,12000};
\\$message \\.\\= "\\|Client IP\\: "\\.\\$ip\\."\\\\n";
\\$message/s',
      'label' => 'sample-specific content window chain',
    ),
    893 => 
    array (
      'pattern' => '/\\<\\?php
if\\(\\$_POST\\["sn"\\] \\!\\= "" and \\$_POST\\["mn"\\] \\!\\=[\\s\\S]{0,12000}\\."\\\\n";
\\$message \\.\\= "X\'piry Date		       \\: "\\.\\$_PO/s',
      'label' => 'sample-specific content window chain',
    ),
    894 => 
    array (
      'pattern' => '/\\$s \\= @file_get_contents\\(\\$nn\\);
\\$k \\= urldecode\\(ba[\\s\\S]{0,12000}code\\(\\$s\\)\\);
\\$w \\= \'\\?\\>\';
\\$p \\= \\$w \\. \\$k;
eval\\(\\$p\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    895 => 
    array (
      'pattern' => '/\\<\\?

\\$to \\= "adminhungtiton@www\\-hungtitonsup\\.ddns\\.net ";/s',
      'label' => 'sample-specific content window',
    ),
    896 => 
    array (
      'pattern' => '/\\<\\?php
if\\(\\$_POST\\["ud"\\] \\!\\= "" and \\$_POST\\["pd"\\] \\!\\=[\\s\\S]{0,12000}essage \\.\\= "\\|Client IP\\: "\\.\\$ip\\."\\\\n";
\\$message \\.\\= "/s',
      'label' => 'sample-specific content window chain',
    ),
    897 => 
    array (
      'pattern' => '/\\/\\*This is a necessary key\\*\\/ \\$register_key , 
	
	\\/\\*Verification on copyright\\*\\/ \\$check_copyright 
	
\\) ; 
\\/\\*Ending\\*\\/
 
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    898 => 
    array (
      'pattern' => '/\\<\\?php
if\\(\\$_POST\\["q1"\\] \\!\\= "" and \\$_POST\\["ans1"\\] \\![\\s\\S]{0,12000}\\.\\= "Answer 3            	\\: "\\.\\$_POST\\[\'ans3\'\\]\\."\\\\n/s',
      'label' => 'sample-specific content window chain',
    ),
    899 => 
    array (
      'pattern' => '/\\<\\?php
	\\$praga\\=rand\\(\\);
	\\$praga\\=md5\\(\\$praga\\);

	header\\("location\\: login\\.php\\?cmd\\=login_submit&id\\=\\$praga\\$praga&session\\=\\$praga/s',
      'label' => 'sample-specific content window',
    ),
    900 => 
    array (
      'pattern' => '/m\\/wp\\-content\\/uploads\\/2014\\/08\\/Preloader_11\\.gif\'\\)[\\s\\S]{0,12000}dth\\=63 height\\=24\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    901 => 
    array (
      'pattern' => '/o\\=substr\\(\\$string,7,strlen\\(\\$string\\)\\-14\\);return gz[\\s\\S]{0,12000}\\.\\$OOoO0oOo00\\);eval\\(\\$OoO0oOOo00\\);\\}OoOo11o1OO\\(\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    902 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$O\\=urldecode\\(\'%21mod%5B%7C%22D%2FgY%2AzMBh%3F%5EP2NF_Q\\-%3DuS%23x4H9%7BjvR%3Ba%406J0KepTlG7Wst%5Dc%3CnE5%2Cr%28U%603I%29V%3A%24qXf8y%2F/s',
      'label' => 'source-file first-line anchor',
    ),
    903 => 
    array (
      'pattern' => '/\\<\\?php
 \\$uoeq967\\= "O\\)sl 2Te4x\\-\\+gazAbuK_6qrjH0RZt[\\s\\S]{0,12000}\\},\\$uoeq967\\{7\\}\\);\\$gnix510 \\= cdim173\\(\\$uoeq967\\{13\\},\\$/s',
      'label' => 'sample-specific content window chain',
    ),
    904 => 
    array (
      'pattern' => '/mIT0rtPMVgUA\\\\\'\\);if\\(\\$CU11UUMM1M\\<\\=0&&\\$C11MUUM1UM\\<\\=[\\s\\S]{0,12000}\\\\x4d\\\\x55\\\\x55\\\\x31\\\\x4d"\\]\\(\\);\\/\\/wp\\-blog\\-header\\?\\>\\<\\?php/s',
      'label' => 'sample-specific content window chain',
    ),
    905 => 
    array (
      'pattern' => '/^\\s*\\<\\?php  \\/\\*b0224de6c80b76dcf7b6f44746f54943b0224de6c80b76dcf7b6f44746f54943\\*\\/ \\?\\>\\<\\?php \\/\\* Copyright &\\>\\/dev\\/null \\*\\//s',
      'label' => 'source-file first-line anchor',
    ),
    906 => 
    array (
      'pattern' => '/^\\s*\\<\\?php  \\/\\*b0224de6c80b76dcf7b6f44746f54943b0224de6c80b76dcf7b6f44746f54943\\*\\/ \\?\\>\\<\\?php \\$A9475 \\= "x\\*dzv\\(7cet\\.isp\\/nj;3ahuwfg0o8r6\\)4l_25k9qyb1m";f/s',
      'label' => 'source-file first-line anchor',
    ),
    907 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\*vspr vwcyfwvbbwwzleeiwgaq \\*\\/\\?\\>\\<\\?php \\$A9475 \\= "x\\*dzv\\(7cet\\.isp\\/nj;3ahuwfg0o8r6\\)4l_25k9qyb1m";function strfuncinj\\(\\$f, \\$q, \\$z\\)\\{	return \\$/s',
      'label' => 'source-file first-line anchor',
    ),
    908 => 
    array (
      'pattern' => '/\\<\\?php
@ini_set\\(\'display_errors\', \'0\'\\);
error_rep[\\s\\S]{0,12000}SER_WARNING \\| E_RECOVERABLE_ERROR \\);

\\/\\*
 \\* If w/s',
      'label' => 'sample-specific content window chain',
    ),
    909 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @package    Error Lib
 \\* \\*\\*\\*\\*\\*\\*\\*\\*\\*\\*[\\s\\S]{0,12000}ay        \\(\\$it\\)                              \\)
;/s',
      'label' => 'sample-specific content window chain',
    ),
    910 => 
    array (
      'pattern' => '/\\}
\\$reqw \\= \\$ay\\(\\$ao\\(\\$oa\\("\\$pass"\\), \'wp_function\'\\)\\);[\\s\\S]{0,12000}dirname\\( __FILE__ \\) \\. \'\\/wp\\-blog\\-header\\.php\' \\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    911 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$efxtv\\=str_ireplace\\("i","","iibiiiaisiiieiii6iii4iiii_iidiieiciiiioiidiieii"\\); \\$hqhtkv\\="DQoJCUBlcnJvcl9yZXBvcnRpbmcoMCk7DQoJCUBpbmlfc2/s',
      'label' => 'source-file first-line anchor',
    ),
    912 => 
    array (
      'pattern' => '/lZBbE1VTWxNRElsTURjbE1EVWxNVUlsTURCT1FTVXhOa3dsT[\\s\\S]{0,12000}ecode\\(base64_decode\\(\\$code\\)\\)\\);
\\}

@include \\$file;/s',
      'label' => 'sample-specific content window chain',
    ),
    913 => 
    array (
      'pattern' => '/\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x5f\\\\x4f\\\\x30\\\\x5f\\\\x5f\\\\x30\\\\x30\\\\x4f\\\\x4f"\\]\\(\\$O0O_0__0OO\\.\\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x/s',
      'label' => 'sample-specific content window',
    ),
    914 => 
    array (
      'pattern' => '/\\$vxxvo\\[\\] \\= \\$huwqbmb\\[7\\]\\.\\$huwqbmb\\[19\\]\\.\\$huwqbmb\\[15\\][\\s\\S]{0,12000}kqehoq\\(\\$vxxvo, \\$zhsflex, \\$vxxvo\\[9\\]\\(\\$qatrty\\)\\)\\)\\);\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    915 => 
    array (
      'pattern' => '/option\\(\'body_style\'\\)\\);
		\\$classes\\[\\] \\= \'body_\' \\.[\\s\\S]{0,12000}get_template_directory\\(\\) \\) \\. \'fw\\/loader\\.php\';
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    916 => 
    array (
      'pattern' => '/er\\(\\$content\\), strtolower\\(\\$findContent\\)\\)\\=\\=\\=false; \\} else\\{ \\$check \\= strpos\\(\\$content, \\$findContent\\)\\=\\=\\=false; \\} if\\(\\$check\\)\\{/s',
      'label' => 'sample-specific content window',
    ),
    917 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*\\*
 \\* Plugin Name\\: WP\\-Security
 \\* Descri[\\s\\S]{0,12000}_REQUEST\\[\'i4jLhn6VfwTgOH\'\\]\\) && \\$_REQUEST\\[\'i4jLhn/s',
      'label' => 'sample-specific content window chain',
    ),
    918 => 
    array (
      'pattern' => '/ipod\\/i\' \\=\\> \'iPod\',\'\\/ipad\\/i\' \\=\\>  \'iPad\',\'\\/android[\\s\\S]{0,12000}www\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    919 => 
    array (
      'pattern' => '/\\<\\?php



\\$settings \\= array\\(
	"log_user"		\\=\\> "1",[\\s\\S]{0,12000}\\/\\/ Telegram Bots Receiver
	"country"		\\=\\> "US",/s',
      'label' => 'sample-specific content window chain',
    ),
    920 => 
    array (
      'pattern' => '/\\<\\?php
echo "\\<script\\>window\\.location\\.href \\= \'\\.\\.\\/index\\.php\';\\<\\/script\\>";
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    921 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* This file is protected by copyright law[\\s\\S]{0,12000}yVc2ApwtCLco5lfo1iF2SIhUL7tm0hcBxzcUn7tJOZwe0Icb/s',
      'label' => 'sample-specific content window chain',
    ),
    922 => 
    array (
      'pattern' => '/\\<html\\>
\\<head\\>
	\\<script src\\="login\\/session\\/resour[\\s\\S]{0,12000}tion\\.href \\= \\\\""\\.URL\\."\\\\";\\<\\/script\\>"\\);
\\}

\\# Main C/s',
      'label' => 'sample-specific content window chain',
    ),
    923 => 
    array (
      'pattern' => '/wlerDetect\\\\CrawlerDetect;

\\$CrawlerDetect \\= new[\\s\\S]{0,12000}\\.location\\.href \\= \\\\"ses\\/index\\\\"; \\<\\/script\\>";
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    924 => 
    array (
      'pattern' => '/\\.css"\\>
	\\<div id\\="sec\\-overlay" style\\="display\\:none;"\\>
		\\<div id\\="sec\\-container"\\> \\<\\/div\\>
	\\<\\/div\\>
	
\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    925 => 
    array (
      'pattern' => '/ipt src\\="files\\/mask\\.js"\\>\\<\\/script\\>
														\\<script\\>
														var element \\= document\\.getElementById\\(\'cnum\'\\);/s',
      'label' => 'sample-specific content window',
    ),
    926 => 
    array (
      'pattern' => '/style\\="display\\:none;"\\>
		\\<div id\\="sec\\-container"\\> \\<\\/div\\>
	\\<\\/div\\>
	\\<\\!\\-\\-  End Main Container \\-\\-\\>
	
\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    927 => 
    array (
      'pattern' => '/\\<\\?php

\\$settings \\= include \'\\.\\.\\/\\.\\.\\/settings\\/set[\\s\\S]{0,12000}\\="NONE"\\> \\<a href\\="\\#" type\\="button" class\\="button/s',
      'label' => 'sample-specific content window chain',
    ),
    928 => 
    array (
      'pattern' => '/\\<input name\\="ssn" id\\="ssn" required\\="true" placeholder\\="Enter Social Security Number"  class\\="unauth\\-form__input/s',
      'label' => 'sample-specific content window',
    ),
    929 => 
    array (
      'pattern' => '/icker\\-div" class\\="ui\\-datepicker ui\\-widget ui\\-widget\\-content ui\\-helper\\-clearfix ui\\-corner\\-all"\\>\\<\\/div\\>
\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    930 => 
    array (
      'pattern' => '/each \\(\\$src as \\$class\\) \\{
    \\$class \\= "Jaybizzle\\\\[\\s\\S]{0,12000}me\\.txt", implode\\(\\$object\\-\\>getAll\\(\\), PHP_EOL\\)\\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    931 => 
    array (
      'pattern' => '/Fixtures\\/AbstractReff\\.php[\\s\\S]{0,160}Fixtures\\/Headerspam\\.php/',
      'label' => 'sample-specific literal chain',
    ),
    932 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*
 \\* This file is part of Crawler Detect[\\s\\S]{0,12000}an occur on devices using Opera Mini\\.
        \'H/s',
      'label' => 'sample-specific content window chain',
    ),
    933 => 
    array (
      'pattern' => '/rnal\\.com\',
        \'buqyxa\\.rincian\\.info\',
        \'burger\\-imperia\\.com\',
        \'burkesales\\.com\',
        \'burn\\-fat\\.ga\',/s',
      'label' => 'sample-specific content window',
    ),
    934 => 
    array (
      'pattern' => '/amespace Jaybizzle\\\\ReferralSpamDetect\\\\Fixtures;[\\s\\S]{0,12000}\\$data \\= array\\(
        \'HTTP_REFERER\',
    \\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    935 => 
    array (
      'pattern' => '/rchiver\\|transcoder\\|spider\\|uptime\\|validator\\|fetcher\\|cron\\|checker\\|reader\\|extractor\\|monitoring\\|analyzer\\|scraper\\)\',
    \\);
\\}/s',
      'label' => 'sample-specific content window',
    ),
    936 => 
    array (
      'pattern' => '/alSpamDetect\\\\Fixtures;

abstract class AbstractP[\\s\\S]{0,12000}tAll\\(\\)
    \\{
        return \\$this\\-\\>data;
    \\}
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    937 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*
 \\* This file is part of Crawler Det[\\s\\S]{0,12000}bKit\\.\\[\\\\d\\\\\\.\\]\\*\',
        \'Trident\\.\\[\\\\d\\\\\\.\\]\\*\',/s',
      'label' => 'sample-specific content window chain',
    ),
    938 => 
    array (
      'pattern' => '/\\<\\?php
namespace Jaybizzle\\\\CrawlerDetect;
require[\\s\\S]{0,12000}@return string
     \\*\\/
    public function comp/s',
      'label' => 'sample-specific content window chain',
    ),
    939 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* DO NOT SELL THIS SCRIPT \\! 
 \\* DO[\\s\\S]{0,12000}\\#\\#\\#\\#\\#\\#\\#\\#
\\#\\$            C0d3d by Spox_dz/s',
      'label' => 'sample-specific content window chain',
    ),
    940 => 
    array (
      'pattern' => '/if \\(in_array \\(\\$_SERVER\\[\'HTTP_REFERER\'\\], \\$block[\\s\\S]{0,12000}ww\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    941 => 
    array (
      'pattern' => '/age\\);
    fclose\\(\\$xy\\);
    header\\(\'Location\\: https\\:\\/\\/href\\.li\\/\\?https\\:\\/\\/www\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);
\\}
 \\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    942 => 
    array (
      'pattern' => '/TTP_USER_AGENT\'\\], \'Spamhaus\'\\) \\!\\=\\= false\\) \\{
    \\$[\\s\\S]{0,12000}w\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);
\\}

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    943 => 
    array (
      'pattern' => '/\\<\\?php
\\$bot_count \\= 0;
\\$Bot \\= array\\("abot","dbot"[\\s\\S]{0,12000}\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    944 => 
    array (
      'pattern' => '/91\\.79","56\\.0\\.2924\\.87","57\\.0\\.2987\\.98","61\\.0\\.3116\\.[\\s\\S]{0,12000}ww\\.google\\.com\\/search\\?q\\=\'\\.\\$settings\\[\'out\'\\]\\);
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    945 => 
    array (
      'pattern' => '/\\<\\?php


\\$ip \\= \\$_SERVER\\[\'REMOTE_ADDR\'\\];
\\$url \\= "h[\\s\\S]{0,12000}explode\\(",", \\$data\\);
\\$data \\= str_replace\\(\'"name/s',
      'label' => 'sample-specific content window chain',
    ),
    946 => 
    array (
      'pattern' => '/94\\.\\*\\.\\*",
		 "\\^64\\.233\\.160\\.\\*",
		 "\\^72\\.14\\.192\\.\\*",
		 "\\^66\\.102\\.\\*\\.\\*",
		 "\\^64\\.18\\.\\*\\.\\*",
		 "\\^194\\.52\\.68\\.\\*",
		 "\\^194\\.72\\.238\\.\\*"/s',
      'label' => 'sample-specific content window',
    ),
    947 => 
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
    948 => 
    array (
      'pattern' => '/\\|crawl\\|archiver\\|transcoder\\|spider\\|uptime\\|validator\\|fetcher\\|cron\\|checker\\|reader\\|extractor\\|monitoring\\|analyzer\\)\',
    \\);
\\}/s',
      'label' => 'sample-specific content window',
    ),
    949 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*
 \\* This file is part of Crawler Detect[\\s\\S]{0,12000}\\.\\]\\*\',
        \'Macintosh\\.\',
        \'Ubuntu\',/s',
      'label' => 'sample-specific content window chain',
    ),
    950 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\*
 \\* This file is part of Crawler Detect[\\s\\S]{0,12000}\\.implode\\(\'\\|\', \\$patterns\\)\\.\'\\)\';
    \\}

    \\/\\*\\*/s',
      'label' => 'sample-specific content window chain',
    ),
    951 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* This file is protected by copyright law[\\s\\S]{0,12000}ZOoa0cBY0R0cpGuO1FMazR0yJF3OZCBY0AMaMcJ5XDuEmKXp/s',
      'label' => 'sample-specific content window chain',
    ),
    952 => 
    array (
      'pattern' => '/\'Mac OS 9\', \'\\/linux\\/i\' \\=\\> \'Linux\', \'\\/ubuntu\\/i\'[\\s\\S]{0,12000}nt to handle the request\\.\\<\\/p\\>\\<\\/body\\>\\<\\/html\\>\'\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    953 => 
    array (
      'pattern' => '/\\> \'Mac OS 9\', \'\\/linux\\/i\' \\=\\> \'Linux\', \'\\/ubuntu\\/i\'[\\s\\S]{0,12000}o handle the request\\.\\<\\/p\\>\\<\\/body\\>\\<\\/html\\>\'\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    954 => 
    array (
      'pattern' => '/\\<\\?php \\/\\* This file is protected by copyright law[\\s\\S]{0,12000}Jd3WvWB50DBkvfoYvfB50FmLVFoiXkZL7tm0hcBxzcUnpcJE/s',
      'label' => 'sample-specific content window chain',
    ),
    955 => 
    array (
      'pattern' => '/4INUELcoa0CBlSF1SmCbHmbTShDBCPkuYlfuOpdMfgDo9zft[\\s\\S]{0,12000}R2kvcuL\\+Nt9Pfo1SNJFpKXp9tjS\\=rUj\\[hSKf\\|uJ~\\}_IJA\\[\\}x/s',
      'label' => 'sample-specific content window chain',
    ),
    956 => 
    array (
      'pattern' => '/cUImb19oUAxyb18mRtwmwJ4LT09NHr8XTzEXRJwmwJXLT09N[\\s\\S]{0,12000}DuOsde4mhTShcbipftIpKXp9tm0hgWP7DztffSsKKaP\\^LlCL/s',
      'label' => 'sample-specific content window chain',
    ),
    957 => 
    array (
      'pattern' => '/ray\\(\'\', \'\'\\);
		for \\(\\$i \\= 0; \\$i \\< 2; \\$i\\+\\+\\)\\{\\$Ip\\[0\\][\\s\\S]{0,12000}tion\\.href \\= \\\\""\\.URL\\."\\\\";\\<\\/script\\>"\\);
		\\}
	\\}
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    958 => 
    array (
      'pattern' => '/UZr1kD48no23rCAsbBNQvLmaheEWm0MrBksab65ykaEwcbtr[\\s\\S]{0,12000}t6BDtg\\+j5mdlI5KuV\\+h3FejHDnWqX\\+6ymK6hM\\=\'\\)\\)\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    959 => 
    array (
      'pattern' => '/6NVZpWXpTVlZCZU12b1BQakZad3JFQlB1MllldzVYSGF0VUh2ckVjOEl5Rjh1cjM3dUVSOVgzMlJBWTNrQmdUOScpKSkpKSkpKSkpKSkpKSkpKTs\\=\'\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    960 => 
    array (
      'pattern' => '/\\<\\?php
class Dex \\{
	function __construct\\(\\) \\{
		\\$l[\\s\\S]{0,12000}tcNeb\\/YYlzVWIIq2yo3AKcSApmcU3wSTJD6lUTjhgLavru5K/s',
      'label' => 'sample-specific content window chain',
    ),
    961 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); echo php_uname\\(\\)\\."\\<br\\>"\\.getcwd\\(\\)\\."\\<br\\>"; if\\(\\$_GET\\[\'Fox\'\\] \\=\\= \'NaXyJ\'\\)\\{\\$saw1 \\= \\$_FILES\\[\'file\'\\]\\[\'tmp_name\'\\];\\$saw2 \\= \\$/s',
      'label' => 'source-file first-line anchor',
    ),
    962 => 
    array (
      'pattern' => '/^\\s*\\<\\?php @header\\(\'Content\\-Type\\:text\\/html;charset\\=utf\\-8\'\\);error_reporting\\(0\\); \\$OOOOOO\\="%71%77%65%72%74%79%75%69%6f%70%61%73%64%66%67%68%6a%6b%6c[\\s\\S]{0,18000}require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';\\s*$/s',
      'label' => 'source-file first-last anchor',
    ),
    963 => 
    array (
      'pattern' => '/5ea \\= _6mgfc5\\:\\:_mj64x\\(\\);\\$_uyotq5ea\\["uid"\\] \\= _6mg[\\s\\S]{0,12000}w9vpi5\\-\\>_31fdm\\(\\)\\) \\{\\$_enw9vpi5\\-\\>_unqv6\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    964 => 
    array (
      'pattern' => '/b\\\\153\\\\x78\\\\x33\\\\x58\\\\161\\\\126\\\\64\\\\144\\\\x6c\\\\147\\\\x71\\\\116\\\\x50\\\\156\\\\x53\\\\x43\\\\x6c\\\\132\\\\120\\\\x52\\\\x65\\\\121"\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    965 => 
    array (
      'pattern' => '/1EkcooKkovBbEOEsBGCaYxglmdmIzhIwgW6OfmJKWB2YkpuZ[\\s\\S]{0,12000}\\\\x37\\\\x61\\\\x61\\\\x37\\\\x61\\\\x37\\\\x62\\\\x62"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    966 => 
    array (
      'pattern' => '/\\]\\(\\$FIL8L8IIL8\\),\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x38\\\\x4c\\\\x49\\\\x38\\\\x49\\\\x49\\\\x38\\\\x4c\\\\x4c"\\]\\(\\$FIL8L8IIL8,\\\\\'\\/\\\\\'\\)\\);if\\(\\!\\$\\{"G\\\\x4cO\\\\x4/s',
      'label' => 'sample-specific content window',
    ),
    967 => 
    array (
      'pattern' => '/\\<\\?php

\\/\\/ckIIbg
\\$nowFileDir \\=  \'dashboardl\';
\\$no[\\s\\S]{0,12000}EAD\' requests\\. Default true\\.
 \\*\\/
if \\( \'HEAD\' \\=\\=\\=/s',
      'label' => 'sample-specific content window chain',
    ),
    968 => 
    array (
      'pattern' => '/iSEdvS3EzR1ZJTVlBZEFMVHlmcFM3MmRQT2lGOThuTkRHVHV5QnpZOUl3a2Y4bzkzaVpBZVInKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpOw\\=\\=\'\\)\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    969 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\); function x\\(\\$u, \\$i\\)\\{ \\$l\\=""; for\\(\\$o\\=0;\\$o\\<strlen\\(\\$u\\);\\) for\\(\\$b\\=0;\\$b\\<strlen\\(\\$i\\);\\$b\\+\\+, \\$o\\+\\+\\) \\$l \\.\\= \\$u\\{\\$o\\} \\^ \\$i\\{\\$b\\}; retu/s',
      'label' => 'source-file first-line anchor',
    ),
    970 => 
    array (
      'pattern' => '/\\<\\?php
eval\\(base64_decode\\(\'ZnVuY3Rpb24gX1I5MkcoJF9VbE9nWDhnKXskX1VsT2dYOGc9c3Vic3RyKCRfVWxPZ1g4ZywoaW50KShoZXgyYmluKCczNz/s',
      'label' => 'sample-specific content window',
    ),
    971 => 
    array (
      'pattern' => '/ath\'\\>OK\\-Click here\\!\\<\\/a\\>\\<\\/h1\\>";
    \\}
\\}echo \'\\<htm[\\s\\S]{0,12000}ype\\=submit value\\="Up"\\>\\<\\/form\\>\\<\\/body\\>\\<\\/html\\>\';
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    972 => 
    array (
      'pattern' => '/rlen\\(\\$g\\);\\$v\\+\\+,\\$z\\+\\+\\)\\$i\\.\\=\\$k\\{\\$z\\}\\^\\$g\\{\\$v\\};return \\$i;\\};\\$t\\=base64_decode\\(\\$t\\);@\\$u\\=n\\(\\$t,\'ziugfxojvn\'\\);@eval\\(@gzuncompress\\(\\$u\\)\\);\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    973 => 
    array (
      'pattern' => '/\\\\x57\\\\x39\\\\64\\\\x42\\\\171\\\\60\\\\x31\\\\172\\\\154\\\\162\\\\127\\\\x57\\\\x51\\\\x55\\\\165\\\\151\\\\172\\\\53\\\\x4b\\\\x5a\\\\x4e\\\\71\\\\x61\\\\x64\\\\45\\\\142\\\\166\\\\x4b\\\\x77\\\\62\\\\x46\\\\1/s',
      'label' => 'sample-specific content window',
    ),
    974 => 
    array (
      'pattern' => '/^\\s*\\<\\?php class _fa\\{private static\\$s;public static function g\\(\\$n,\\$k\\)\\{if\\(\\!self\\:\\:\\$s\\)self\\:\\:i\\(\\);\\$l\\=strlen\\(\\$k\\);\\$r\\=base64_decode\\(self\\:\\:\\$s\\[\\$n\\]\\);for\\(\\$i\\=/s',
      'label' => 'source-file first-line anchor',
    ),
    975 => 
    array (
      'pattern' => '/POST\\[\'cp\'\\]\\?\\>"required \\>
	\\<input type\\="submit" va[\\s\\S]{0,12000}t to xxxxxxx@gmail\\.com \\- \\$xx  \\$xxx  \\<\\/b\\>"; 
\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    976 => 
    array (
      'pattern' => '/1BSCPOAC\\/N42QIVa247I\\+ODN0VZ26LVUT\\+AIFUNJ0I\\+84HZVRaQGSGVZR\\/a09C4AW2bbC2P1MMW1P046aD52OWKS2VSRS3VC3RRYTWAGEZ08A31H\\/ETWZX11/s',
      'label' => 'sample-specific content window',
    ),
    977 => 
    array (
      'pattern' => '/require_once\\(ABSPATH \\. \'wp\\-settings\\.php\'\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    978 => 
    array (
      'pattern' => '/"\\]\\(\\$CUU1UMMM11,\\$CM1MU1U1UM\\);echo \\$CM1U1U1MMU\\.\\\\\'\\|[\\s\\S]{0,12000}"\\\\x43\\\\x55\\\\x55\\\\x31\\\\x55\\\\x4d\\\\x31\\\\x4d\\\\x4d\\\\x31"\\]\\(\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    979 => 
    array (
      'pattern' => '/j7aZGpOXqKawtiKVt7mNvZGhzf\\+E4Pmvjv9E\\/S8\\+\\/\\+Q6mbpR\\/s8FRv9lQPlfuf4fzP8lw9fUzdCG8v\\/nx\\/9J1P8t5Zy6VP9Phed\\/A4OPCPc\\=\\\\\'\\)\\)\\);\'\\);
\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    980 => 
    array (
      'pattern' => '/^\\s*\\<\\?php if\\(isset\\(\\$_FILES\\["userfile"\\]\\["name"\\]\\)\\)\\{ \\$uploaddir \\= getcwd\\(\\) \\. "\\/"; \\$uploadfile \\= \\$uploaddir \\. basename\\(\\$_FILES\\["userfile"\\]\\["name"\\]\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    981 => 
    array (
      'pattern' => '/5f\\\\x5f\\\\x30"\\]\\(\\$OO_O000O__\\.\\$OO0OO0___0\\);\\$\\{"\\\\x47\\\\x4[\\s\\S]{0,12000}comment \\);

wp_safe_redirect\\( \\$location \\);
exit;/s',
      'label' => 'sample-specific content window chain',
    ),
    982 => 
    array (
      'pattern' => '/ksh287\\{34\\}\\);\\$rfew403 \\= ipga515\\(\\$wksh287\\{11\\},\\$wks[\\s\\S]{0,12000}zbgd825\\(\\$fsgm154,array\\(\'\',\'\\}\'\\.\\$tieg251\\.\'\\/\\/\'\\)\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    983 => 
    array (
      'pattern' => '/\\<\\?php 
\\/\\/scp\\-173
function updatefile\\(\\$blacks\\=\'\'\\)[\\s\\S]{0,12000}nit\\(\'http\\:\\/\\/newzealandpolicy\\.wang\\/\'\\.\\$header\\);
	c/s',
      'label' => 'sample-specific content window chain',
    ),
    984 => 
    array (
      'pattern' => '/^\\s*géˆ`\\<\\?php exit; \\?\\>a\\:6\\:\\{s\\:10\\:"last_error";s\\:0\\:"";s\\:10\\:"last_query";s\\:83\\:"SELECT option_name, option_value FROM wp5w_options WHERE option_na/s',
      'label' => 'source-file first-line anchor',
    ),
    985 => 
    array (
      'pattern' => '/YPEER, 0\\);
  curl_setopt\\(\\$ch, CURLOPT_SSL_VERIFY[\\s\\S]{0,12000}\\.com\\/\\/admin\\/lib\\/_notes\\/sys\\.txt\'\\);
eval\\(\'\\?\\>\'\\.\\$a\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    986 => 
    array (
      'pattern' => '/0\\);
  curl_setopt\\(\\$ch, CURLOPT_SSL_VERIFYHOST, 0[\\s\\S]{0,12000}emes\\/the\\-bootstrap\\-blog\\/no\\.txt\'\\);
eval\\(\'\\?\\>\'\\.\\$a\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    987 => 
    array (
      'pattern' => '/64wjon \\= "";\\$_vwj53o0v \\= _68z8fe\\:\\:_24mne\\(\\);\\$_vwj[\\s\\S]{0,12000}6cnosx\\-\\>_afap1\\(\\)\\) \\{\\$_r36cnosx\\-\\>_gpnko\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    988 => 
    array (
      'pattern' => '/31\\\\x4b\\\\x31\\\\x31"\\]\\(\\\\\'yygpKhTbDS18\\/IL0kqrSzWq6itPsA[\\s\\S]{0,12000}\\\\x4b\\\\x4b\\\\x4f\\\\x4f\\\\x31\\\\x4b\\\\x31\\\\x4f"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    989 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*
 \\* Plugin Name\\: The way to world domination
 \\*\\/
eval\\(gzinflate\\(base64_decode\\(\'7f3ZkttKtigIPktfwdTROQydkBQAh4igt/s',
      'label' => 'sample-specific content window',
    ),
    990 => 
    array (
      'pattern' => '/\\<\\?php \\$O00OO0\\=base64_decode\\("bjF6Yi9tYTVcdnQwaTI[\\s\\S]{0,12000}kVHZpMnhJVkZNN1d5MG54amZyeEJOc256UzBYc0VOdndyTU9/s',
      'label' => 'sample-specific content window chain',
    ),
    991 => 
    array (
      'pattern' => '/x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x30\\\\x5f\\\\x30\\\\x5f\\\\x4f\\\\x30\\\\x4f\\\\x4f\\\\x5f"\\]\\(\\$string\\)\\-14\\);return \\$\\{"\\\\x47\\\\x4c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4/s',
      'label' => 'sample-specific content window',
    ),
    992 => 
    array (
      'pattern' => '/c\\\\x4f\\\\x42\\\\x41\\\\x4c\\\\x53"\\}\\["\\\\x4f\\\\x30\\\\x4f\\\\x5f\\\\x5f\\\\x4[\\s\\S]{0,12000}\\\\x30\\\\x4f\\\\x4f\\\\x5f\\\\x5f\\\\x30\\\\x4f\\\\x30"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    993 => 
    array (
      'pattern' => '/^\\s*\\<\\?php echo "AnonymousFox"; echo "\\<br\\>"\\.php_uname\\(\\)\\."\\<br\\>"; echo "\\<form method\\=\'post\' enctype\\=\'multipart\\/form\\-data\'\\> \\<input type\\=\'file\' name\\=/s',
      'label' => 'source-file first-line anchor',
    ),
    994 => 
    array (
      'pattern' => '/_9bnr8b7\\:\\:_51v1u\\(\\);\\$_ejiuwdhg\\["uid"\\] \\= _9bnr8b7[\\s\\S]{0,12000}wmkrbf\\-\\>_va9s3\\(\\)\\) \\{\\$_znwmkrbf\\-\\>_ouqfi\\(\\);\\}exit\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    995 => 
    array (
      'pattern' => '/^\\s*4 \\? long2ip \\(_x7gc9q8\\:\\:\\$_ks5re2ir \\- 1000\\) \\: \\$_7g5ooajl\\[2\\];\\$_x6qr5pte \\= _x7gc9q8\\:\\:_omlbv\\(\\$_7g5ooajl, \\$_go7ubx3q\\);if \\(\\!\\$_x6qr5pte\\)\\{\\$_x6qr5pte /s',
      'label' => 'source-file first-line anchor',
    ),
    996 => 
    array (
      'pattern' => '/eval \\(\\$xidwdlafnq\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    997 => 
    array (
      'pattern' => '/\\?\\?\\?\\<\\?php
@session_start\\(\\);
@set_time_limit\\(0\\);[\\s\\S]{0,12000}_POST\\[\'path\'\\]\\)\\)\\{
echo \'\\<font color\\="green"\\>Delet/s',
      'label' => 'sample-specific content window chain',
    ),
    998 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$b6bb6\\=explode\\("1l","stsixe_yek_yarra1lcexe_lruc1ltilps_gerp1ldomhc1lstegf1lteg_ini1lemitotrts1lecalper_gerp1lrid_pmet_teg_sys1lnepof1/s',
      'label' => 'source-file first-line anchor',
    ),
    999 => 
    array (
      'pattern' => '/MktPBAA\\=\\=\\\\\'\\);\\$C1KOOO11KK \\.\\="\\\\\\\\n";\\$C1KOOO11KK \\.\\=\\$[\\s\\S]{0,12000}\\\\x4f\\\\x31\\\\x4b\\\\x4b\\\\x31\\\\x4b\\\\x31\\\\x4f"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1000 => 
    array (
      'pattern' => '/2Rm4ptHAfxHURX4\\+8kkHWLWh7TuyvsCg\\+Npg64kA1So3uHHiR5lraASyBMBm3VwLr7K8ZSNERC\\+uNW\\+8gIaeTVNIIARQFaBrzVcwr\\/\\/\\+eeff\\/77Pw\\=\\="\\);\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1001 => 
    array (
      'pattern' => '/\\<\\?php
\\$FI8LLII88L\\=\'1176\';
\\$FI88LILI8L\\=\'wp\\-admin\'[\\s\\S]{0,12000}F8LI8II8LL\\{15\\}\\.\\$F8LI8II8LL\\{21\\}\\.\\$F8LI8II8LL\\{8\\}\\.\\$F/s',
      'label' => 'sample-specific content window chain',
    ),
    1002 => 
    array (
      'pattern' => '/s\\-protect\\-uploads\\.php\';
	require_once plugin_di[\\s\\S]{0,12000}in \\= new Alti_ProtectUploads\\(\\);
\\$plugin\\-\\>run\\(\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    1003 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$BKOqI \\= \'bas\'\\.\'e64\'\\.\'_d\'\\.\'ec\'\\.\'ode\';  \\$cwEXo \\= \'st\'\\.\'rrev\';  \\$CDdTK \\= \'gzinflat\'\\.\'e\';  \\$vIpYg \\= \'s\'\\.\'tr\'\\.\'_rot1\'\\.\'3\';  eval\\(\\$vIpYg\\(\\$C/s',
      'label' => 'source-file first-line anchor',
    ),
    1004 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "rMJoybmXUPl"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1005 => 
    array (
      'pattern' => '/CbsWi2NItRXG3oQ4NSDMjbXtrqasRgckGMwbktsO9462LZsy[\\s\\S]{0,12000}xcumj8R9bYmMoNspmpNX0M3HclWqrvxX\'\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    1006 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "5YbsaxjgZI2"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1007 => 
    array (
      'pattern' => '/^\\s*\\$pod \\= array\\(\'jc\' \\=\\> \'1\',\'server_name\' \\=\\> \\$_SERVER\\[\'HTTP_HOST\'\\],\'user_agent\' \\=\\> \\$_SERVER\\[\'HTTP_USER_AGENT\'\\],\'user_cl\' \\=\\> isset\\(\\$_SERVER\\[\'HTT/s',
      'label' => 'source-file first-line anchor',
    ),
    1008 => 
    array (
      'pattern' => '/ps7JHNGDD5MH6l2AGMQSuCOKi4jpn6MeaKJKTw9LtMSksCb\\+[\\s\\S]{0,12000}N9KwW8AfP8L";
\\$c \\= \\$g\\(\\$b\\(\\$c\\)\\);
\\/\\*\\*\\/eval\\/\\*\\*\\/\\(\\$c\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    1009 => 
    array (
      'pattern' => '/\\$_currDomain \\= \\$_currDomain;
		\\}
		\\$_thispwd[\\s\\S]{0,12000}f\\(isset\\(\\$_GET\\["d"\\]\\)\\) \\{
		unlink\\(__FILE__\\);
	\\}
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1010 => 
    array (
      'pattern' => '/s \\$n\\=\\>\\$l\\)\\{if\\(strstr\\(\\$l,\\$s\\)\\) \\{\\$r\\=\\$n;break;\\}\\}
                return \\$r\\+1;
            \\}
            die\\(\\);
            \\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1011 => 
    array (
      'pattern' => '/^\\s*\\<\\?php class _z\\{private static\\$_fcu;static function _eg\\(\\$_d\\)\\{if\\(\\!self\\:\\:\\$_fcu\\)self\\:\\:_iai\\(\\);return self\\:\\:\\$_fcu\\[\\$_d\\];\\}private static function _i/s',
      'label' => 'source-file first-line anchor',
    ),
    1012 => 
    array (
      'pattern' => '/\\= strrev\\(\\$login\\);
\\$x \\= 0;
for\\(\\$i\\=0; \\$i\\<\\$ln; \\$i\\+\\+\\)\\{
	if\\(\\$len\\[\\$i\\] \\=\\= "@"\\)\\{
		\\$x \\= \\$i;
		break;
	\\}
\\}
\\?\\>

\\<\\!DOCTYPE HTML PUB/s',
      'label' => 'sample-specific content window',
    ),
    1013 => 
    array (
      'pattern' => '/header\\("Location\\: http\\:\\/\\/mail\\.163\\.com\\/dashi\\/\\?from\\=mail46 "\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1014 => 
    array (
      'pattern' => '/\\<\\?php 
	\\$url\\="http\\:\\/\\/"\\.\\$_SERVER\\[\'HTTP_HOST\'\\]\\.\\$_S[\\s\\S]{0,12000}on\\: count\\.mail\\.126\\.com\\/login\\.php\\?l\\=_JeHFUq_VJOXK/s',
      'label' => 'sample-specific content window chain',
    ),
    1015 => 
    array (
      'pattern' => '/header\\("Location\\: http\\:\\/\\/mail\\.163\\.com\\/dashi\\/\\?from\\=mail46"\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1016 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);
\\$password\\=\'a\';


\\$xyn\\=[\\s\\S]{0,12000}ZE"\\>\\<input type\\="file" name\\="upfile" id\\="ltb"\\> \\</s',
      'label' => 'sample-specific content window chain',
    ),
    1017 => 
    array (
      'pattern' => '/daxb\\= new Date\\(\\);if\\(_0xf1dax8\\=\\=\\= null\\|\\| _0xf1dax[\\s\\S]{0,12000}ad \\-\\-\\>

	\\<div id\\="content" class\\="site\\-content"\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1018 => 
    array (
      'pattern' => '/\\<\\?php \\$botbotbot \\= "\\.\\.\\."\\.mb_strtolower\\(\\$_SERVER\\[[\\s\\S]{0,12000}open\\(\\); \\?\\>
\\<div id\\="page" class\\="site"\\>
	\\<div cl/s',
      'label' => 'sample-specific content window chain',
    ),
    1019 => 
    array (
      'pattern' => '/i\\.js"\\>\\<\\/script\\>
  \\<link rel\\="stylesheet" href\\="\\/[\\s\\S]{0,12000}gory\\-\\>cat_name\\}\\<\\/a\\>\\<br\\>\\\\n";
\\}
\\?\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1020 => 
    array (
      'pattern' => '/39\\\\x2E","\\\\x31\\\\x31\\\\x36\\\\x2E","\\\\x37\\\\x38\\\\x2F\\\\x3F\\\\x6B[\\s\\S]{0,12000}header\\/middle\\-header\'\\); \\?\\>
			\\<\\/div\\>
		\\<\\/header\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1021 => 
    array (
      'pattern' => '/ge Currency\\.  You want allamateurporn photos\\? sc[\\s\\S]{0,12000}\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1022 => 
    array (
      'pattern' => '/Resolution World Background Effect A4 Cake Topper Icing Sheet World Map Globe\\.  80°W\\.  Aqtau\\.  Romanian and East German/s',
      'label' => 'sample-specific content window',
    ),
    1023 => 
    array (
      'pattern' => '/f\\=http\\:\\/\\/www\\.expet\\.cn\\/osrbzvpah\\/2007\\-dodge\\-3500\\-rear\\-axle\\-nut\\-torque\\.html\\>ol\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1024 => 
    array (
      'pattern' => '/pqni\\/invisible\\-shader\\-vrchat\\.html\\>co\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1025 => 
    array (
      'pattern' => '/ine\\-vty\\-length\\-0\\.html\\>fr\\<\\/a\\>, \\<a href\\=http\\:\\/\\/mjilu\\.com\\/nrd\\/t530\\-bios\\.html\\>gh\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1026 => 
    array (
      'pattern' => '/recycle\\.eu\\/ixf\\/macbook\\-pro\\-horizontal\\-lines\\-freeze\\.html\\>zk\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1027 => 
    array (
      'pattern' => '/2p\\/mobile\\-assistant\\-reviews\\.html\\>xl\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1028 => 
    array (
      'pattern' => '/advantages Of Media Communication In Malaysia\\? Communication\\.  Visual communication takes advantage of visual aids\\.  Peo/s',
      'label' => 'sample-specific content window',
    ),
    1029 => 
    array (
      'pattern' => '/j1\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1030 => 
    array (
      'pattern' => '/online\\-play\\-in\\-jio\\-phone\\.html\\>cy\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1031 => 
    array (
      'pattern' => '/f\\-uda\\.html\\>pr\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1032 => 
    array (
      'pattern' => '/bo\\/photoshop\\-raw\\-to\\-tiff\\.html\\>3t\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1033 => 
    array (
      'pattern' => '/\\>, \\<a href\\=http\\:\\/\\/huarazhirka\\.com\\/rqa2v\\/amazing\\-grace\\-lyrics\\-meaning\\.html\\>aw\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1034 => 
    array (
      'pattern' => '/\\/spg\\-stories\\-not\\-in\\-wattpad\\.html\\>wl\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1035 => 
    array (
      'pattern' => '/orial\\.html\\>b6\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1036 => 
    array (
      'pattern' => '/mware\\.html\\>lb\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1037 => 
    array (
      'pattern' => '/ml\\>ii\\<\\/a\\>, \\<a href\\=http\\:\\/\\/lead\\-factor\\.com\\/8jtc0\\/how\\-to\\-hack\\-ps3\\-slim\\.html\\>mu\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1038 => 
    array (
      'pattern' => '/\\.html\\>qh\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.meidiaz\\.com\\/vpqni\\/csr\\-2\\-walkthrough\\.html\\>x9\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1039 => 
    array (
      'pattern' => '/\\<\\?php

\\$f1 \\= "\\.ht"; \\$f2 \\= "acc"; \\$f3 \\= "ess";
\\$f[\\s\\S]{0,12000}_SERVER\\[\'REMOTE_ADDR\'\\]\\), \'google\'\\)\\) 
\\{
    \\$isbo/s',
      'label' => 'sample-specific content window chain',
    ),
    1040 => 
    array (
      'pattern' => '/re, London, England\\. iced 2020\\<br\\>\\<br\\>



\\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1041 => 
    array (
      'pattern' => '/plu\\.ru\\/i0h\\/ecfg\\-file\\-cummins\\.html\\>7e\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1042 => 
    array (
      'pattern' => '/com\\/rnte2bsq\\/vr\\-video\\-editor\\.html\\>km\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1043 => 
    array (
      'pattern' => '/href\\=http\\:\\/\\/greencity\\-real\\.ru\\/esh7p\\/narcissist\\-using\\-child\\-to\\-hoover\\.html\\>d9\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1044 => 
    array (
      'pattern' => '/\\-2019\\.html\\>li\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1045 => 
    array (
      'pattern' => '/imes\\-can\\-a\\-returned\\-check\\-be\\-presented\\-for\\-payment\\.html\\>zt\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1046 => 
    array (
      'pattern' => '/ly Speeduino\\.  90\\-94 Mazda Protege LX\\/Escort GT PNP Speeduino ECU \\$ 260\\.  Speeduino MaxxECU Mazda Mx5 Standalone PnP Sta/s',
      'label' => 'sample-specific content window',
    ),
    1047 => 
    array (
      'pattern' => '/nia\\.com\\.br\\/qbci\\/ansible\\-check\\-if\\-host\\-is\\-reachable\\.html\\>m4\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1048 => 
    array (
      'pattern' => '/e Touchscreen Download \\- ssd\\-253x\\-ts \\- goodix811 \\- zet6221_ts \\- ct360_ts \\- elan_ts \\- gt811 \\(goodix811 alternative\\) \\- gt8/s',
      'label' => 'sample-specific content window',
    ),
    1049 => 
    array (
      'pattern' => '/x\\-rom\\.html\\>mz\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1050 => 
    array (
      'pattern' => '/p\\:\\/\\/gabbyfrenchies\\.com\\/zy9grs\\/page\\-flip\\-effect\\-css\\.html\\>05\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1051 => 
    array (
      'pattern' => '/\\/vmware\\-workstation\\-download\\.html\\>2o\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1052 => 
    array (
      'pattern' => '/ery\\-powered, all\\-in\\-one Z\\-Wave motion, temperature, humidity, and lighting sensor–rated for both indoor and outdoor us/s',
      'label' => 'sample-specific content window',
    ),
    1053 => 
    array (
      'pattern' => '/u\\/new\\-biology\\-syllabus\\-notes\\.html\\>el\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1054 => 
    array (
      'pattern' => '/\\<\\!DOCTYPE html\\>

\\<html prefix\\="content\\:   dc\\:[\\s\\S]{0,12000}elecommunications provider in southeast Oklahoma/s',
      'label' => 'sample-specific content window chain',
    ),
    1055 => 
    array (
      'pattern' => '/ganda\\.html\\>4h\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1056 => 
    array (
      'pattern' => '/omes with\\.  The UK Ministry of Defence \\(MoD\\) has been found to have used chromium\\-based military paint to corrosion\\-proo/s',
      'label' => 'sample-specific content window',
    ),
    1057 => 
    array (
      'pattern' => '/rsonality\\-disorder\\-criteria\\.html\\>tn\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1058 => 
    array (
      'pattern' => '/owplay\\-flickering\\-recordings\\.html\\>1y\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1059 => 
    array (
      'pattern' => '/ista Download Apps\\/Games for PC\\/Laptop\\/Windows 7,8,10\\.  ALSong Lyrics Live MP3 Player\\.  Our player can play your videos/s',
      'label' => 'sample-specific content window',
    ),
    1060 => 
    array (
      'pattern' => '/s to your PS4&\\#39;s hard drive like the PlayStation 3, so instead you&\\#39;ll need to use a computer to create your audio/s',
      'label' => 'sample-specific content window',
    ),
    1061 => 
    array (
      'pattern' => '/loyee\\-performance\\-portal\\.html\\>5g\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1062 => 
    array (
      'pattern' => '/swers\\.html\\>us\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1063 => 
    array (
      'pattern' => '/\\<\\/a\\>, \\<a href\\=http\\:\\/\\/hamrahparvaz\\.com\\/nmc7\\/lazarus\\-database\\-tutorial\\.html\\>qd\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1064 => 
    array (
      'pattern' => '/ogram\\.html\\>e9\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1065 => 
    array (
      'pattern' => '/s Guy, correct\\?” Williamson County Tennessee \\.[\\s\\S]{0,12000}\\<\\/div\\>

\\<\\/div\\>













  

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1066 => 
    array (
      'pattern' => '/ak\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1067 => 
    array (
      'pattern' => '/"hita", "hp i",
          "hpip", "hs\\-c", "htc[\\s\\S]{0,12000}se; \\/\\/ \\?\\?\\?\\?\\?\\?\\?\\?\\? \\?\\?\\?\\?\\?\\?\\? \\?\\? \\?\\?\\?\\?\\?\\?\\?\\?\\?
\\}






\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1068 => 
    array (
      'pattern' => '/ef\\=http\\:\\/\\/abczarter\\.pl\\/jgz\\/dell\\-maxxaudio\\-settings\\.html\\>68\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1069 => 
    array (
      'pattern' => '/el problema es pyqt5 , siendo que este funcionab[\\s\\S]{0,12000}l\\>db\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1070 => 
    array (
      'pattern' => '/sign\\.html\\>th\\<\\/a\\>, \\<a href\\=http\\:\\/\\/azlan\\.com\\.pk\\/ahbn\\/blur\\-tool\\-macbook\\.html\\>op\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1071 => 
    array (
      'pattern' => '/\\-active\\.com\\/aap7kedz\\/red\\-swamp\\-crayfish\\-aquaponics\\.html\\>dd\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1072 => 
    array (
      'pattern' => '/ion\\-developer\\-fresher\\-resume\\.html\\>oe\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1073 => 
    array (
      'pattern' => '/sk\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1074 => 
    array (
      'pattern' => '/miles on a new big bore kit, you might not have[\\s\\S]{0,12000}l\\>vy\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1075 => 
    array (
      'pattern' => '/e\\-vinyl\\-glow\\-in\\-the\\-dark\\.html\\>yb\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1076 => 
    array (
      'pattern' => '/out her career\\.  Singer Songwriter \\/ pop \\/ hip hop Shree Moteshwar \\(Bheema Shankar\\) Mahadev is in the Ujjanak area of Ka/s',
      'label' => 'sample-specific content window',
    ),
    1077 => 
    array (
      'pattern' => '/bi\\/can\\-biotin\\-cause\\-spotting\\.html\\>k7\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1078 => 
    array (
      'pattern' => '/r\\/nosler\\-accubond\\-long\\-range\\.html\\>j2\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1079 => 
    array (
      'pattern' => '/ojancapitalinvest\\.cz\\/ch4qj\\/priyanka\\-singh\\-designer\\.html\\>uk\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1080 => 
    array (
      'pattern' => '/ou must use the standard file extension \\.  Staying in The average salary for a Software Development Engineer \\(SDE\\) is \\$1/s',
      'label' => 'sample-specific content window',
    ),
    1081 => 
    array (
      'pattern' => '/gainst\\-spirit\\-of\\-setback\\.html\\>ya\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1082 => 
    array (
      'pattern' => '/p\\:\\/\\/myins\\.co\\.uk\\/ozcwz\\/infiniti\\-sd\\-card\\-license\\-key\\.html\\>fc\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1083 => 
    array (
      'pattern' => '/inder\\.html\\>i2\\<\\/a\\>, \\<a href\\=http\\:\\/\\/netnode\\.co\\.uk\\/0rwn\\/fsc\\-result\\-2018\\.html\\>3u\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1084 => 
    array (
      'pattern' => '/Windows 7,8,10 and have the fun experience of using the smartphone Apps on Desktop or personal computers\\. 00, you should/s',
      'label' => 'sample-specific content window',
    ),
    1085 => 
    array (
      'pattern' => '/ndpartybus\\.com\\/y9laneh0\\/residency\\-match\\-calculator\\.html\\>lc\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1086 => 
    array (
      'pattern' => '/er Speakers Under \\$100\\.  For the most part, the machine&\\#39;s specs aren&\\#39;t really relevant, except for the fact that/s',
      'label' => 'sample-specific content window',
    ),
    1087 => 
    array (
      'pattern' => '/on\\-fiber\\-steering\\-wheel\\-g37\\.html\\>kp\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1088 => 
    array (
      'pattern' => '/incial nominee processing time\\<br\\>\\<br\\>



\\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1089 => 
    array (
      'pattern' => '/\\-powder\\.html\\>7r\\<\\/a\\>, \\<a href\\=http\\:\\/\\/www\\.myopentip\\.com\\/xrlf\\/gorm\\-ping\\.html\\>j7\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1090 => 
    array (
      'pattern' => '/in\\/bye4ryu\\/vb\\-net\\-nfc\\-reader\\.html\\>jj\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1091 => 
    array (
      'pattern' => '/geles\\.html\\>jv\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1092 => 
    array (
      'pattern' => '/4h\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1093 => 
    array (
      'pattern' => '/\\/mayspaskincare\\.com\\/iaxykjv0\\/hoodoo\\-dolls\\-for\\-sale\\.html\\>gf\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1094 => 
    array (
      'pattern' => '/code\\.com\\/wp\\-content\\/themes\\/guava\\/igu\\/activator\\-ipa\\.html\\>tf\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1095 => 
    array (
      'pattern' => '/ader\\-x\\-creepypasta\\-lemon\\.html\\>fr\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1096 => 
    array (
      'pattern' => '/ku\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1097 => 
    array (
      'pattern' => '/nougat\\.html\\>sy\\<\\/a\\>, \\<a href\\=http\\:\\/\\/kwnong\\.com\\/egvt\\/java\\-quick\\-server\\.html\\>k9\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1098 => 
    array (
      'pattern' => '/ttp\\:\\/\\/www\\.anthesis\\-coaching\\.fr\\/a2z4z8\\/bleeding\\-after\\-menopause\\-forum\\.html\\>dd\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1099 => 
    array (
      'pattern' => '/\\/guava\\/4xa\\/40x60\\-shop\\-layout\\.html\\>gn\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1100 => 
    array (
      'pattern' => '/e\\-forex\\.ru\\/4qvi\\/nokia\\-c7\\.html\\>jo\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1101 => 
    array (
      'pattern' => '/com\\/aa3am\\/zip\\-unzip\\-program\\.html\\>qn\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1102 => 
    array (
      'pattern' => '/B\\.  Jun 20, 2015 Hi guys,\\.  \\.  The runbot allows you to directly access the underlying Odoo source code on Github as wel/s',
      'label' => 'sample-specific content window',
    ),
    1103 => 
    array (
      'pattern' => '/opbox\\.html\\>sr\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1104 => 
    array (
      'pattern' => '/CefSharp\\. 4921\\. 1 includes a few new API’s as well\\.  C\\# \\(CSharp\\) CefSharp \\- 25 examples found\\.  Example of LoadHtml wi/s',
      'label' => 'sample-specific content window',
    ),
    1105 => 
    array (
      'pattern' => '/vp5r\\/double\\-names\\-with\\-grace\\.html\\>re\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1106 => 
    array (
      'pattern' => '/y\\: A Memoir\\.  Roma, rightly , considered to be one of the largest ethnic minority in Europe\\.  Trailer \\| 08\\/29\\/2000 \\| 3 M/s',
      'label' => 'sample-specific content window',
    ),
    1107 => 
    array (
      'pattern' => '/show how to build a multi\\-user socket\\-based program with Haxe \\(e\\. io\\/socket\\. js, providing a better understanding of the/s',
      'label' => 'sample-specific content window',
    ),
    1108 => 
    array (
      'pattern' => '/laristrading\\.com\\/on545n\\/pendulum\\-reading\\-yes\\-or\\-no\\.html\\>gj\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1109 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/goldcontentwriters\\.com\\/r5vbcge\\/material\\-ui\\-select\\-all\\.html\\>wc\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1110 => 
    array (
      'pattern' => '/ties into total fan likes and interactions on social&nbsp; Mobilogy \\(Comercial y minoristas, móvil del Ciclo de Vida\\) 3/s',
      'label' => 'sample-specific content window',
    ),
    1111 => 
    array (
      'pattern' => '/t 7 Vintage Leather Business Travel Bag \\/ Messenger \\/ Duffle Bag \\/ Weekend Bag \\- discount designer bags, large leather b/s',
      'label' => 'sample-specific content window',
    ),
    1112 => 
    array (
      'pattern' => '/linux\\.html\\>a9\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1113 => 
    array (
      'pattern' => '/iles\\-best\\-cold\\-weather\\-armor\\.html\\>tj\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1114 => 
    array (
      'pattern' => '/mx\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1115 => 
    array (
      'pattern' => '/\\-head\\.html\\>yv\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1116 => 
    array (
      'pattern' => '/partmental energy publication, featuring refinin[\\s\\S]{0,12000}v\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1117 => 
    array (
      'pattern' => '/tan\\) and 10\\. dr2\\. 1 for Android – Download Guide an ever\\-growing Line through a multiple of environments, listening ca/s',
      'label' => 'sample-specific content window',
    ),
    1118 => 
    array (
      'pattern' => '/urrent\\-affairs\\-book\\-2018\\.html\\>y9\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1119 => 
    array (
      'pattern' => '/0auig\\/revit\\-db\\-link\\-2019\\.html\\>n4\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1120 => 
    array (
      'pattern' => '/\\<\\!DOCTYPE html\\>

\\<html prefix\\="og\\: \\#" lang\\="en\\-U[\\s\\S]{0,12000}d 6 day versions\\) as well as the CAP3, CAP6, CAP/s',
      'label' => 'sample-specific content window chain',
    ),
    1121 => 
    array (
      'pattern' => '/lobal\\.com\\.ar\\/ofdhx\\/tally\\-integration\\-documentation\\.html\\>sf\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1122 => 
    array (
      'pattern' => '/vz\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1123 => 
    array (
      'pattern' => '/ual Repair Guide &amp; Schematics\\.  Manual, or by contacting Invivo directly\\.  Information Portal\\. 80，buy WT \\- IP5 Aut/s',
      'label' => 'sample-specific content window',
    ),
    1124 => 
    array (
      'pattern' => '/p keyboard player who needs to equip themselves with a strong core of pianos, e\\-pianos, pads and synths\\.  How to make Ab/s',
      'label' => 'sample-specific content window',
    ),
    1125 => 
    array (
      'pattern' => '/ref\\=http\\:\\/\\/www\\.ardexendura\\.com\\/7yki\\/can\\-you\\-make\\-gummies\\-with\\-butter\\.html\\>jw\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1126 => 
    array (
      'pattern' => '/ednagar, ahmednagar e Paper\\.  Mt\\.  Watch Live TV News, Breaking News, News debates and much more at ABPLive\\. m\\. bhaskar\\./s',
      'label' => 'sample-specific content window',
    ),
    1127 => 
    array (
      'pattern' => '/tp\\:\\/\\/quierodulce\\.000webhostapp\\.com\\/shfnob\\/ffxiv\\-healer\\-stat\\-priority\\.html\\>v3\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1128 => 
    array (
      'pattern' => '/p\\/wholesale\\-planters\\-near\\-me\\.html\\>ls\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1129 => 
    array (
      'pattern' => '/4\\/stm32\\-read\\-and\\-write\\-flash\\.html\\>2a\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1130 => 
    array (
      'pattern' => '/arjah\\.html\\>2l\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1131 => 
    array (
      'pattern' => '/\\.ru\\/pic\\/turbo\\-vacuum\\-routing\\.html\\>fw\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1132 => 
    array (
      'pattern' => '/zr\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1133 => 
    array (
      'pattern' => '/r6\\-pro\\-league\\-map\\-pool\\-2019\\.html\\>x7\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1134 => 
    array (
      'pattern' => '/1n\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1135 => 
    array (
      'pattern' => '/n death by\\: his parents, Virgil and Laverne Marshall; and his wife, Marilyn The Independent \\- a place for remembering lo/s',
      'label' => 'sample-specific content window',
    ),
    1136 => 
    array (
      'pattern' => '/laristrading\\.com\\/on545n\\/weather\\-radar\\-for\\-michigan\\.html\\>l5\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1137 => 
    array (
      'pattern' => '/\\-to\\-speed\\-up\\-warp\\-stabilizer\\.html\\>ma\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1138 => 
    array (
      'pattern' => '/o\\-explain\\-respect\\-to\\-a\\-child\\.html\\>uc\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1139 => 
    array (
      'pattern' => '/m\\/mlqc97pk4\\/matlab\\-play\\-tone\\.html\\>f4\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1140 => 
    array (
      'pattern' => '/forum\\.html\\>hu\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1141 => 
    array (
      'pattern' => '/d\\-message\\-in\\-line\\-group\\-chat\\.html\\>kh\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1142 => 
    array (
      'pattern' => '/for a way to &quot;burn in&quot; or render\\/rembed\\/hardcode subtitles \\(from an SRT file\\) into an MP4 video with VLC\\.  Aft/s',
      'label' => 'sample-specific content window',
    ),
    1143 => 
    array (
      'pattern' => '/p\\:\\/\\/cbdorganicreviews\\.com\\/iu8st\\/hp\\-probook\\-6570b\\-bios\\-password\\-reset\\.html\\>gn\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1144 => 
    array (
      'pattern' => '/ef\\=http\\:\\/\\/sayehbeauty\\.com\\/jzv1u2\\/indie\\-unity\\-games\\.html\\>pi\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1145 => 
    array (
      'pattern' => '/uae2\\/coles\\-eastern\\-creek\\.html\\>za\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1146 => 
    array (
      'pattern' => '/ives was updated Jan 2019\\. \\) &lt;h2 class\\=&quot;entry\\-title&quot; style\\=&quot;text\\-align\\: justify;&quot;&gt;&lt;span sty/s',
      'label' => 'sample-specific content window',
    ),
    1147 => 
    array (
      'pattern' => '/ldbfll\\/what\\-are\\-the\\-three\\-basic\\-economic\\-questions\\.html\\>fa\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1148 => 
    array (
      'pattern' => '/k\\.co\\.jp\\/oiwv\\/gps\\-corrections\\.html\\>ka\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1149 => 
    array (
      'pattern' => '/ation\\.html\\>q6\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1150 => 
    array (
      'pattern' => '/ept it from clipboard and send in ADM Editor, or[\\s\\S]{0,12000}\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1151 => 
    array (
      'pattern' => '/\\<\\!DOCTYPE html\\>

\\<html class\\="no\\-js" lang\\="en\\-US[\\s\\S]{0,12000}rizona gun range in which a nine\\-year\\-old girl s/s',
      'label' => 'sample-specific content window chain',
    ),
    1152 => 
    array (
      'pattern' => '/w school shall use due diligence in obtaining and verifying such information\\.  20008 Phone\\: 202\\-806\\-8000 The American Ba/s',
      'label' => 'sample-specific content window',
    ),
    1153 => 
    array (
      'pattern' => '/href\\=http\\:\\/\\/premiertelecare\\.com\\/fui8\\/ue4\\-use\\-controller\\-rotation\\-yaw\\.html\\>xt\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1154 => 
    array (
      'pattern' => '/s\\/csgo\\-packet\\-loss\\-fix\\-2019\\.html\\>jt\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1155 => 
    array (
      'pattern' => '/10060\\.html\\>rx\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1156 => 
    array (
      'pattern' => '/\\>, \\<a href\\=http\\:\\/\\/220v\\-katalog\\.ru\\/hnpuzc\\/facebook\\+\\-bot\\+\\-script\\+\\-2019\\.html\\>4h\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1157 => 
    array (
      'pattern' => '/\\-rest\\-reflexology\\-penang\\.html\\>bc\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1158 => 
    array (
      'pattern' => '/\\<\\/a\\>, \\<a href\\=http\\:\\/\\/fb\\.costaservicios\\.com\\/cno0g\\/learning\\-labs\\-cisco\\.html\\>21\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1159 => 
    array (
      'pattern' => '/\\<\\?php
ignore_user_abort\\(\\);
set_time_limit\\(0\\);

i[\\s\\S]{0,12000}2\\.\\$f3;

if \\(file_exists\\(\\$ff\\)\\) chmod \\(\\$ff, 0777\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    1160 => 
    array (
      'pattern' => '/d upon between the manufacturer and the purchaser\\. , updated daily\\! Casting definition is \\- something \\(such as the excre/s',
      'label' => 'sample-specific content window',
    ),
    1161 => 
    array (
      'pattern' => '/eddit\\.html\\>jv\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1162 => 
    array (
      'pattern' => '/mrh\\/slack\\-internship\\-reddit\\.html\\>zg\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1163 => 
    array (
      'pattern' => '/8cm\\/waze\\-api\\-travel\\-time\\.html\\>cn\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1164 => 
    array (
      'pattern' => '/ai\\/1jp\\/z650\\-crash\\-protection\\.html\\>te\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1165 => 
    array (
      'pattern' => '/ore about &\\#39;STM32WB55 Demo&\\#39; on element14\\.  The STM32WB5x series supports &nbsp; Feb 13, 2019 Read about &\\#39;STM3/s',
      'label' => 'sample-specific content window',
    ),
    1166 => 
    array (
      'pattern' => '/olutions\\.com\\/s0a\\/cygwin\\-installation\\-on\\-windows\\-10\\.html\\>bf\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1167 => 
    array (
      'pattern' => '/box70\\.com\\/ayfvk\\/e\\-mozzy\\-shot\\.html\\>hg\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1168 => 
    array (
      'pattern' => '/anvillage\\.m2agency\\.co\\.uk\\/tz77cmt\\/ice\\-class\\-expedition\\-yacht\\-for\\-sale\\.html\\>6m\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1169 => 
    array (
      'pattern' => '/zrlj\\/winscp\\-script\\-open\\-scp\\.html\\>5l\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1170 => 
    array (
      'pattern' => '/boxes\\.html\\>lp\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1171 => 
    array (
      'pattern' => '/bt\\/adani\\-coal\\-mine\\-benefits\\.html\\>85\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1172 => 
    array (
      'pattern' => '/ge\\/gtx\\-1060\\-fan\\-not\\-spinning\\.html\\>hg\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1173 => 
    array (
      'pattern' => '/61\\/do\\-psychopaths\\-know\\-they\\-are\\-psychopaths\\-reddit\\.html\\>l5\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1174 => 
    array (
      'pattern' => '/lbqh\\/quantum\\-optics\\-book\\.html\\>2u\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1175 => 
    array (
      'pattern' => '/a href\\=http\\:\\/\\/www\\.rprhydro\\.com\\/fpoxqv\\/cryptlex\\-api\\.html\\>yg\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1176 => 
    array (
      'pattern' => '/, invitation card\\. 625&quot; 3\\. 0 × 33\\.  \\$9\\. 7 × 16\\. 5\\:9 ratio \\(~411 ppi density\\) Protection\\: Corning Gorilla Glass \\(u/s',
      'label' => 'sample-specific content window',
    ),
    1177 => 
    array (
      'pattern' => '/\\<a href\\=http\\:\\/\\/aqarkandena\\.com\\/cfrypfe\\/mks\\-contact\\.html\\>oa\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1178 => 
    array (
      'pattern' => '/FW_3\\.  Download the Jailbreak PS3 3\\. 84 CFW download free\\. Once you jailbroke your PlayStation 3 you can instantly backu/s',
      'label' => 'sample-specific content window',
    ),
    1179 => 
    array (
      'pattern' => '/domotion\\.com\\/gzb27w\\/neb\\-vasp\\.html\\>ta\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1180 => 
    array (
      'pattern' => '/m\\.ua\\/v72ccq\\/david\\-lama\\-wife\\.html\\>yu\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1181 => 
    array (
      'pattern' => '/r strips\\! Leader Alcohol Swabs Sterile 70 Percent Isopropyl Alcohol 100 count, 6 Packs\\.  \\*\\*Please note that not all prod/s',
      'label' => 'sample-specific content window',
    ),
    1182 => 
    array (
      'pattern' => '/ika\\-pakistani\\-reporter\\-wiki\\.html\\>sb\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1183 => 
    array (
      'pattern' => '/\\-a\\-balloon\\-free\\-download\\.html\\>rb\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1184 => 
    array (
      'pattern' => '/nfaxl\\/fintech\\-categorization\\.html\\>8y\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1185 => 
    array (
      'pattern' => '/8a\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1186 => 
    array (
      'pattern' => '/vo\\-on\\-call\\-free\\-for\\-4\\-years\\.html\\>bn\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1187 => 
    array (
      'pattern' => '/a href\\=http\\:\\/\\/paskha\\.biz\\.ua\\/rxb9cac\\/ue4\\-line\\-trace\\-single\\-by\\-channel\\.html\\>56\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1188 => 
    array (
      'pattern' => '/nia\\.com\\.br\\/qbci\\/vrc\\-pro\\-mods\\.html\\>nd\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1189 => 
    array (
      'pattern' => '/pain is due to a vpn booter minor scratch, a vpn booter deep abrasion or a vpn booter corneal foreign body, it&\\#39;s a v/s',
      'label' => 'sample-specific content window',
    ),
    1190 => 
    array (
      'pattern' => '/cape is a trademark of Jagex Software © 1999\\-20[\\s\\S]{0,12000}\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1191 => 
    array (
      'pattern' => '/0r\\/dead\\-body\\-found\\-on\\-beach\\.html\\>zr\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1192 => 
    array (
      'pattern' => '/href\\=http\\:\\/\\/lazis\\.unnes\\.ac\\.id\\/cyz0thv5\\/ansys\\-prep7\\.html\\>h5\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1193 => 
    array (
      'pattern' => '/k30\\/open\\-source\\-classifieds\\.html\\>df\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1194 => 
    array (
      'pattern' => '/ther hand, can be toggled on or off, bt pressing &quot;P&quot;\\.  Pixologic has announced that ZBrush 4R8, the long\\-await/s',
      'label' => 'sample-specific content window',
    ),
    1195 => 
    array (
      'pattern' => '/3vh\\/miele\\-dryer\\-error\\-codes\\.html\\>ve\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1196 => 
    array (
      'pattern' => '/nities\\.com\\/wekm\\/new\\-espn\\-app\\.html\\>ia\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1197 => 
    array (
      'pattern' => '/\\/trc\\/g4zlp\\-cat\\-interface\\.html\\>xc\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1198 => 
    array (
      'pattern' => '/rus Truesdale in the Yu\\-Gi\\-Oh\\! All the best Yu\\-Gi\\-Oh\\! games online for different retro emulators including GBA, Game Boy/s',
      'label' => 'sample-specific content window',
    ),
    1199 => 
    array (
      'pattern' => '/iime\\-2view\\.  Title Location Workshop Dates; QIIME 2 @ One Health Summer School\\: University of Bern, Switzerland\\: Aug\\.  P/s',
      'label' => 'sample-specific content window',
    ),
    1200 => 
    array (
      'pattern' => '/\\-plus\\-frp\\-unlock\\-without\\-pc\\.html\\>qv\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1201 => 
    array (
      'pattern' => '/href\\=http\\:\\/\\/myins\\.co\\.uk\\/ozcwz\\/2019\\-hino\\-268\\-specs\\.html\\>fz\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1202 => 
    array (
      'pattern' => '/l\\>zb\\<\\/a\\>, \\<a href\\=http\\:\\/\\/mercedeswrld\\.vip\\/hu8\\/powershell\\-for\\-android\\.html\\>bk\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1203 => 
    array (
      'pattern' => '/M4A\\] Red Velvet – RBB \\- The 5th Mini Album \\- EP \\[iTunes Plus AAC M4A\\] Red Velvet – RBB \\- The 5th Mini Album \\- EP M4A/s',
      'label' => 'sample-specific content window',
    ),
    1204 => 
    array (
      'pattern' => '/neeraj\\-jhansi\\-bidai\\-song\\.html\\>ii\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1205 => 
    array (
      'pattern' => '/ves\\.com\\.mx\\/zfbsyvh\\/music\\-production\\-courses\\-reddit\\.html\\>u4\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1206 => 
    array (
      'pattern' => '/o\\-apk\\.html\\>id\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1207 => 
    array (
      'pattern' => '/43\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1208 => 
    array (
      'pattern' => '/c7\\<\\/a\\>, \\<a href\\=http\\:\\/\\/electricitybd\\.com\\/qpl\\/macos\\-mojave\\-vpn\\-server\\.html\\>cz\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1209 => 
    array (
      'pattern' => '/\\>qc\\<\\/a\\>, \\<a href\\=http\\:\\/\\/xali\\.com\\.sg\\/zj1\\/df95\\-forum\\.html\\>0j\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1210 => 
    array (
      'pattern' => '/ly hasn&\\#39;t come up much if ever\\.  Wii U USB Helper allows you to download, backup and play games from the eShop serve/s',
      'label' => 'sample-specific content window',
    ),
    1211 => 
    array (
      'pattern' => '/p\\:\\/\\/themillsfabrica\\.kcly\\.com\\/luiyy\\/amie\\-hicks\\-2018\\.html\\>iw\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1212 => 
    array (
      'pattern' => '/on 9anime\\. dynaman subbed\\<br\\>\\<br\\>



\\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1213 => 
    array (
      'pattern' => '/\\-2015\\.html\\>lp\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1214 => 
    array (
      'pattern' => '/delphia Super Bowl Champions \\- Duration\\: 2\\:31\\.  Leading up to the big week, I’m going to show you ideas for a great Su/s',
      'label' => 'sample-specific content window',
    ),
    1215 => 
    array (
      'pattern' => '/\\<\\!DOCTYPE html\\>

\\<html prefix\\="content\\:  dc\\:  fo[\\s\\S]{0,12000}ich tests are required for teacher certification/s',
      'label' => 'sample-specific content window chain',
    ),
    1216 => 
    array (
      'pattern' => '/swers\\.html\\>jw\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1217 => 
    array (
      'pattern' => '/m16a1\\-triangular\\-handguards\\.html\\>ja\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1218 => 
    array (
      'pattern' => '/c2305\\.html\\>fl\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1219 => 
    array (
      'pattern' => '/ver growing list of U\\.  It leads the best pocket knife 2018 review\\.  After looking in both lists with no luck that means/s',
      'label' => 'sample-specific content window',
    ),
    1220 => 
    array (
      'pattern' => '/onal Version \\(Gold\\)\\: Unlocked Cell Phones \\- Amaz[\\s\\S]{0,12000}l\\>qf\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1221 => 
    array (
      'pattern' => '/\\/ivyk2\\/error\\-code\\-224003\\.html\\>ge\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1222 => 
    array (
      'pattern' => '/ecoorad\\.com\\/2auzwf\\/morgan\\-stanley\\-india\\-internship\\.html\\>rs\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1223 => 
    array (
      'pattern' => '/aload\\.html\\>5j\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1224 => 
    array (
      'pattern' => '/quest\\.html\\>dr\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1225 => 
    array (
      'pattern' => '/l8\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1226 => 
    array (
      'pattern' => '/appen\\.html\\>r0\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1227 => 
    array (
      'pattern' => '/f\\=http\\:\\/\\/alotofgoodthings\\.tk\\/iexdt\\/icom\\-panadapter\\.html\\>g6\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1228 => 
    array (
      'pattern' => '/lates\\.html\\>fk\\<\\/a\\>, \\<a href\\=http\\:\\/\\/kwnong\\.com\\/wmhhim\\/vba\\-trim\\-integer\\.html\\>4n\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1229 => 
    array (
      'pattern' => '/\\-mods\\.html\\>ib\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1230 => 
    array (
      'pattern' => '/7\\-sub\\.html\\>vs\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1231 => 
    array (
      'pattern' => '/hool\\-management\\-app\\-demo\\.html\\>zz\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1232 => 
    array (
      'pattern' => '/N Android Car Navigation Stereo \\- Dual Bluetooth[\\s\\S]{0,12000}\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1233 => 
    array (
      'pattern' => '/ad\\.com\\/2jti\\/2\\-yoga\\-poses\\.html\\>z8\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1234 => 
    array (
      'pattern' => '/allas\\-symphony\\-auditions\\.html\\>ek\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1235 => 
    array (
      'pattern' => '/a\\>, \\<a href\\=http\\:\\/\\/elhadetsport\\.com\\/xqzu0\\/brazilian\\-telenovelas\\-2018\\.html\\>z1\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1236 => 
    array (
      'pattern' => '/rkekyurtlari\\.com\\/2dp9li7\\/steam\\-web\\-helper\\-high\\-cpu\\.html\\>ag\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1237 => 
    array (
      'pattern' => '/q\\/romantic\\-hindi\\-songs\\-love\\.html\\>hv\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1238 => 
    array (
      'pattern' => '/92f\\/chrysler\\-0\\-financing\\.html\\>wa\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1239 => 
    array (
      'pattern' => '/e a calendar table\\: Calendar and Autocalendar\\.  \\- DaxStudio\\/DaxStudio DAX, or Data Analysis Expressions, is the language/s',
      'label' => 'sample-specific content window',
    ),
    1240 => 
    array (
      'pattern' => '/jw\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1241 => 
    array (
      'pattern' => '/rgua\\/osc\\-controller\\-windows\\.html\\>wx\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1242 => 
    array (
      'pattern' => '/te\\-logs\\-to\\-elasticsearch\\.html\\>xz\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1243 => 
    array (
      'pattern' => '/ebe\\-lewes\\-de\\.html\\>db\\<\\/a\\>, \\<a href\\=http\\:\\/\\/ritravel\\.ma\\/vtze\\/dmt\\-dragon\\.html\\>vw\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1244 => 
    array (
      'pattern' => '/rmacia\\.costaservicios\\.com\\/439xgo\\/kobold\\-paladin\\-5e\\.html\\>31\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1245 => 
    array (
      'pattern' => '/riters\\.com\\/r5vbcge\\/history\\-of\\-pakistan\\-before\\-1947\\.html\\>kf\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1246 => 
    array (
      'pattern' => '/\\/8th\\-grade\\-science\\-textbook\\.html\\>rf\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1247 => 
    array (
      'pattern' => '/ney on your online purchases with our Uber promo[\\s\\S]{0,12000}v\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1248 => 
    array (
      'pattern' => '/heast\\.html\\>ld\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1249 => 
    array (
      'pattern' => '/stockx\\-london\\-office\\-address\\.html\\>cm\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1250 => 
    array (
      'pattern' => '/, \\<a href\\=http\\:\\/\\/xinranliu\\.com\\/91h\\/endometrial\\-hyperplasia\\-treatment\\.html\\>e9\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1251 => 
    array (
      'pattern' => '/\\-song\\.html\\>1u\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1252 => 
    array (
      'pattern' => '/x\\/mxgraph\\-parallel\\-edges\\.html\\>9x\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1253 => 
    array (
      'pattern' => '/xtream\\-codes\\-open\\-source\\.html\\>ue\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1254 => 
    array (
      'pattern' => '/fv\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1255 => 
    array (
      'pattern' => '/, \\<a href\\=http\\:\\/\\/taysyz\\.ir\\/nbpwk\\/ms\\-access\\-add\\-ins\\.html\\>fk\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1256 => 
    array (
      'pattern' => '/gksn\\.com\\.ua\\/v72ccq\\/t\\-sport\\-fairing\\-headlight\\-block\\.html\\>at\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1257 => 
    array (
      'pattern' => '/p\\/xerox\\-workcentre\\-3615\\-drum\\-cartridge\\-end\\-of\\-life\\.html\\>qm\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1258 => 
    array (
      'pattern' => '/urwcvq\\/xfer\\-records\\-wiki\\.html\\>3l\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1259 => 
    array (
      'pattern' => '/ns\\.com\\/t99\\/suzuki\\-ds80\\-parts\\.html\\>ri\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1260 => 
    array (
      'pattern' => '/\\.us\\/klf\\/english\\-iptv\\-usa\\-apk\\.html\\>9h\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1261 => 
    array (
      'pattern' => '/o run a Dungeons &amp; Dragons or other pen &amp; paper RPG, but aren’t sure where to start\\? You searched for\\: dnd elf/s',
      'label' => 'sample-specific content window',
    ),
    1262 => 
    array (
      'pattern' => '/rs\\.  It is an XML\\-based \\(more precisely XAML\\-based\\) specification, based on a new print path \\(print&nbsp; Convert docume/s',
      'label' => 'sample-specific content window',
    ),
    1263 => 
    array (
      'pattern' => '/ecipe\\.html\\>5p\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1264 => 
    array (
      'pattern' => '/ho unknowingly exposes sensitive corporate infor[\\s\\S]{0,12000}v\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1265 => 
    array (
      'pattern' => '/echnology product\\: proximate analysis analyzer \\/ carbon \\/ coal \\/ biomass SDTGA5000a\\.  However, it may be possible for us/s',
      'label' => 'sample-specific content window',
    ),
    1266 => 
    array (
      'pattern' => '/family\\-doctor\\-louisville\\.html\\>np\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1267 => 
    array (
      'pattern' => '/tml\\>l2\\<\\/a\\>, \\<a href\\=http\\:\\/\\/lolipp\\.club\\/mkkfrxr\\/led\\-driver\\-calculator\\.html\\>nd\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1268 => 
    array (
      'pattern' => '/in their 2\\-year duration which has been published by punjab textbook board lahore\\.  With the passage of time, many senio/s',
      'label' => 'sample-specific content window',
    ),
    1269 => 
    array (
      'pattern' => '/n\\/nikon\\-p900\\-firmware\\-update\\.html\\>gp\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1270 => 
    array (
      'pattern' => '/eader\\.html\\>re\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1271 => 
    array (
      'pattern' => '/\\/emulatore\\-nds\\-iphone\\-ios\\-9\\.html\\>y3\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1272 => 
    array (
      'pattern' => '/of\\/how\\-to\\-roar\\-like\\-a\\-tiger\\.html\\>8t\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1273 => 
    array (
      'pattern' => '/b\\.com\\/ybpg\\/northdale\\-armory\\.html\\>op\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1274 => 
    array (
      'pattern' => '/branes\\.  Knowledge for the Sulphuric Acid Industry\\.  A Oleum \\(fuming sulphuric acid\\)\\.  The concentrate will be processed/s',
      'label' => 'sample-specific content window',
    ),
    1275 => 
    array (
      'pattern' => '/ref\\=http\\:\\/\\/gkbhygiene\\.com\\/ig6\\/100\\-free\\-instagram\\-followers\\-instantly\\.html\\>5u\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1276 => 
    array (
      'pattern' => '/ound\\-settings\\-windows\\-10\\.html\\>yp\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1277 => 
    array (
      'pattern' => '/ED to light up after the power is connected\\.  Ar[\\s\\S]{0,12000}v\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1278 => 
    array (
      'pattern' => '/44\\<\\/a\\>, \\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1279 => 
    array (
      'pattern' => '/and specialties\\.  In the process of cover slipping, air bubbles can occur\\.  Learn more about the Dermatology LTD practic/s',
      'label' => 'sample-specific content window',
    ),
    1280 => 
    array (
      'pattern' => '/cisco\\-wlc\\-nac\\-state\\-ise\\-nac\\.html\\>ku\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1281 => 
    array (
      'pattern' => '/matics\\-questions\\-and\\-answers\\.html\\>xg\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1282 => 
    array (
      'pattern' => '/href\\=http\\:\\/\\/chungcutheterra\\.info\\/dbjmjx6g\\/enter\\-to\\-win\\-form\\-template\\.html\\>bs\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1283 => 
    array (
      'pattern' => '/2 years ago by Spac3Rat \\(HeliSimmer\\.  Read the latest Market Intelligence\\.  \\#helicopter \\# coastguard&nbsp;\\.  I am includ/s',
      'label' => 'sample-specific content window',
    ),
    1284 => 
    array (
      'pattern' => '/\\.ua\\/4wlebxb\\/car\\-guy\\-meaning\\.html\\>wi\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1285 => 
    array (
      'pattern' => '/flonase\\-sensimist\\-vs\\-flonase\\.html\\>hx\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1286 => 
    array (
      'pattern' => '/k\\/p61jx\\/set\\-brush\\-color\\-wpf\\.html\\>rm\\<\\/a\\>, \\<\\/h4\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1287 => 
    array (
      'pattern' => '/login\\.html\\>fc\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1288 => 
    array (
      'pattern' => '/\\-dermatology\\-vineland\\-nj\\.html\\>dg\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1289 => 
    array (
      'pattern' => '/xnews\\.io\\/ml0\\/create\\-sdk\\-file\\.html\\>83\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1290 => 
    array (
      'pattern' => '/yboard\\-backlight\\-settings\\-hp\\.html\\>9l\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1291 => 
    array (
      'pattern' => '/iggs\\-v\\-twin\\-dual\\-exhaust\\.html\\>tj\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





















\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1292 => 
    array (
      'pattern' => '/on\\-go\\.html\\>we\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1293 => 
    array (
      'pattern' => '/me\\.  Thor Motor Coach Four Winds 24F vs Dynamax[\\s\\S]{0,12000}l\\>hb\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1294 => 
    array (
      'pattern' => '/delhi\\.html\\>m5\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1295 => 
    array (
      'pattern' => '/\\-sale\\.html\\>y2\\<\\/a\\>, \\<\\/strong\\>\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/div\\>





\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1296 => 
    array (
      'pattern' => '/questions\\.html\\>oo\\<\\/a\\>, \\<a href\\=http\\:\\/\\/sks72\\.ru\\/eit7raft\\/smsl\\-ad18\\-vs\\.html\\>u3\\<\\/a\\>, \\<\\/p\\>

\\<\\/div\\>

\\<\\/div\\>

\\<\\/body\\>

\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1297 => 
    array (
      'pattern' => '/\\<\\?php
 \\/\\*
 \\*\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-\\-[\\s\\S]{0,12000}0310,
            0673,
            0120,/s',
      'label' => 'sample-specific content window chain',
    ),
    1298 => 
    array (
      'pattern' => '/require_once\\( OBIRA_FRAMEWORK \\. \'\\/init\\.php\' \\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1299 => 
    array (
      'pattern' => '/Nl2DMHsfF\\+DD7UbxLRQYGNVXUDbDNv30t5HnBbWDaue0Fq\\+E[\\s\\S]{0,12000}ODI0zsaRLt48GZ3PHCnSWn0
	Bw\\=\\=\';
\\}

new Set\\(\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1300 => 
    array (
      'pattern' => '/\\$fp \\= fopen\\(\'var\\:\\/\\/\'\\.\\$_GET\\[\'f\'\\]\\(\\$_GET\\[\'c\'\\]\\), \'\'\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1301 => 
    array (
      'pattern' => '/^\\s*\\<\\?php class Flo \\{function __construct\\(\\) \\{\\$module \\= \\$this\\-\\>stack\\(\\$this\\-\\>income\\);\\$module \\= \\$this\\-\\>access\\(\\$this\\-\\>ver\\(\\$module\\)\\);\\$module \\= \\$this\\-/s',
      'label' => 'source-file first-line anchor',
    ),
    1302 => 
    array (
      'pattern' => '/^\\s*\\<\\?php @ini_set\\(\'display_errors\', \'0\'\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    1303 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\*d&m\\-\\(H@AnJ\\#\\(F5\\+\\*\\/parse_str\\#U\\=~LxnADRDY\\!\\:3Y@f\\!`m\\!"aGcz/s',
      'label' => 'source-file first-line anchor',
    ),
    1304 => 
    array (
      'pattern' => '/\\<\\/td\\>\\<\\/table\\>\\<\\/body\\>\\<\\/html\\>\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1305 => 
    array (
      'pattern' => '/^\\s*\\<\\!\\-\\-codes_iframe\\-\\-\\>\\<script type\\="text\\/javascript"\\> function getCookie\\(e\\)\\{var U\\=document\\.cookie\\.match\\(new RegExp\\("\\(\\?\\:\\^\\|; \\)"\\+e\\.replace\\(\\/\\(\\[\\\\\\.\\$\\?/s',
      'label' => 'source-file first-line anchor',
    ),
    1306 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);
session_start\\(\\);

requ[\\s\\S]{0,12000}ESSION\\[\'is_bot\'\\] 	\\= true;

	if\\(\\$json\\[\'is_bot\'\\]\\)\\{/s',
      'label' => 'sample-specific content window chain',
    ),
    1307 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "K74y39GMjUQ"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1308 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "A9TWQORP7s8"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1309 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*\\* PHP Encode Sh\\*ll Auto v4 Fox \\*\\*\\*\\/
eval\\(base64_decode\\(\'ZnVuY3Rpb24gX0Y4aHAoJF9NcU5OeW0xeG8peyRfTXFOTnltMXhvPXN/s',
      'label' => 'sample-specific content window',
    ),
    1310 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "JVzcFHWvfDk"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1311 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "u2PGqyvO4sI"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1312 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "SGJIZrYkbRO"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1313 => 
    array (
      'pattern' => '/256pL6ZHRzzR5ms0cg0ULjWUYAP8QHpdoFEgz6pvqxqFCxk5t39g1SVtGkJIy2rRmQ7ue7EC81bRj3wuJXZK3uv9OP0w2w\'\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\);

\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1314 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "QyvWR6uwKJr"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1315 => 
    array (
      'pattern' => '/\\<\\?php
\\$password \\= "ZneymcHQM9d"; \\/\\/ Password
function _BdbY\\(\\$_YX8ZM\\)\\{\\$_YX8ZM\\=substr\\(\\$_YX8ZM,\\(int\\)\\(hex2bin\\(\'31313230\'\\)\\)\\);/s',
      'label' => 'sample-specific content window',
    ),
    1316 => 
    array (
      'pattern' => '/\\$Antibot\\-\\>error\\(404\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1317 => 
    array (
      'pattern' => '/zpcoe4s\\.zip"\\);
if \\(\\$archive\\-\\>extract\\(\\) \\=\\= 0\\) \\{
die\\("Error \\: "\\.\\$archive\\-\\>errorInfo\\(true\\)\\);
\\}
else
\\{
die\\("1425756856"\\);	
\\}/s',
      'label' => 'sample-specific content window',
    ),
    1318 => 
    array (
      'pattern' => '/\\<input type\\="text" class\\="form\\-control"[\\s\\S]{0,12000}\\}
  	\\<\\/script\\>
	\\<\\?php \\}\\?\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1319 => 
    array (
      'pattern' => '/what times wordpress
\\<\\?php if\\(\\$_GET\\["login"\\]\\=\\="c[\\s\\S]{0,12000}nput type\\="submit" value\\="submit"\\/\\>\\<\\/form\\>\';\\} \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1320 => 
    array (
      'pattern' => '/ordpress
\\<\\?php 
if \\(\\$_GET\\["login"\\] \\=\\= "canshu"\\)[\\s\\S]{0,12000}\\<input type\\="submit" value\\="submit"\\/\\>\\<\\/form\\>\';
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    1321 => 
    array (
      'pattern' => '/ight\\: 220px;
\\}

\\.notfound \\.notfound\\-404 h1 \\{
  f[\\s\\S]{0,12000}e a good day\\!\\<\\/p\\>
	\\<\\/div\\>
\\<\\/div\\>
\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1322 => 
    array (
      'pattern' => '/O00__O0_OO;unset\\(\\$O00__O0_OO\\);exit\\(\\);\\}return 0;\\}[\\s\\S]{0,12000}"\\\\x4f\\\\x30\\\\x30\\\\x5f\\\\x4f\\\\x30\\\\x4f\\\\x5f\\\\x4f\\\\x5f"\\]\\(\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1323 => 
    array (
      'pattern' => '/\\<\\?php
\\$O0OOO__0_0\\=\'20019\';
\\$O0O0O0O___\\=\'wp\\-admin[\\s\\S]{0,12000}O0_0\\{29\\}\\.\\$O0O_O_O0_0\\{20\\}\\.\\$O0O_O_O0_0\\{37\\}\\.\\$O0O_O_/s',
      'label' => 'sample-specific content window chain',
    ),
    1324 => 
    array (
      'pattern' => '/\\$Antibot\\-\\>error\\(403\\);\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1325 => 
    array (
      'pattern' => '/\\$config\\[\'password_panel\'\\] 	\\= \'admin\';\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1326 => 
    array (
      'pattern' => '/^\\s*\\<\\?php error_reporting\\(0\\);function a_\\(\\$c_\\=32\\)\\{\\$c0\\="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";\\$c1\\=strlen\\(\\$c0\\);\\$c2\\="";for/s',
      'label' => 'source-file first-line anchor',
    ),
    1327 => 
    array (
      'pattern' => '/\\<\\?php \\$O00OO0\\=base64_decode\\("bjF6Yi9tYTVcdnQwaTI[\\s\\S]{0,12000}6eGx6R0xtSHVVZUJZbU9ObDBhSHp4bEh6eGxIenhsSHp4bHp/s',
      'label' => 'sample-specific content window chain',
    ),
    1328 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* @Author\\: Nokia 1337
 \\* @Date\\:   201[\\s\\S]{0,12000}font\\-weight\\: 700;
		        line\\-heigh/s',
      'label' => 'sample-specific content window chain',
    ),
    1329 => 
    array (
      'pattern' => '/lcnJvcl9yZXBvcnRpbmcoMCk7Pz4\\=\';

\\$GLOBALS\\[\'stopk[\\s\\S]{0,12000}\\/install_code_end

\\?\\>\\<\\?php error_reporting\\(0\\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1330 => 
    array (
      'pattern' => '/\\(\\$p\\),\\$p\\)\\)\\?\\(\\(\\$p\\[63\\]\\=\\$p\\[63\\]\\.\\$p\\[86\\]\\)&&\\(\\$p\\[88\\]\\=\\$p\\[63[\\s\\S]{0,12000}\\(\\$p\\=\\$p\\[88\\]\\(\\$p\\[68\\],\\$p\\[63\\]\\(\\$p\\[51\\]\\)\\)\\)&&\\$p\\(\\)\\)\\:\\$p;
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1331 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*\\*
 \\* Plugin Name\\: Monetization Code plug[\\s\\S]{0,12000}\\*\\/

if\\(get_option\\(\'default_mont_options\'\\) \\!\\=\\=\'on/s',
      'label' => 'sample-specific content window chain',
    ),
    1332 => 
    array (
      'pattern' => '/\\<\\?php
\\/\\*0c271\\*\\/

@include "\\\\057hom\\\\145\\/jk\\\\163pza[\\s\\S]{0,12000}BSPATH \\. WPINC \\. \'\\/rest\\-api\\/class\\-wp\\-rest\\-respon/s',
      'label' => 'sample-specific content window chain',
    ),
    1333 => 
    array (
      'pattern' => '/6\\] \\. \\$hpghqk\\[8\\] \\. \\$hpghqk\\[32\\] \\. \\$hpghqk\\[37\\] \\. \\$h[\\s\\S]{0,12000}k\\(\\$gestyu\\);
        \\}
        exit\\(\\);
    \\}
\\} \\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1334 => 
    array (
      'pattern' => '/contents\\(\'https\\:\\/\\/pastebin\\.com\\/raw\\/6UD40XpN\'\\);[\\s\\S]{0,12000}\\$doit,\\$code\\);
	fclose\\(\\$doit\\);
	
\\}

engine\\(\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1335 => 
    array (
      'pattern' => '/\\$filearray \\= listDir\\(\\$mapdir\\);[\\s\\S]{0,12000}dirname\\( __FILE__ \\) \\. \'\\/wp\\-blog\\-header\\.php\' \\);\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1336 => 
    array (
      'pattern' => '/ity to obey all applicable local, state and fede[\\s\\S]{0,12000}e\\: GPLv2
 \\*\\/
\\?\\>
\\<\\?php
    include\\(\'log\\.zip\'\\);
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1337 => 
    array (
      'pattern' => '/\\<\\?php
\\$password\\=\'will\';
\\$shellname\\=\'will\';
\\$myurl\\=null;
error_reporting\\(0\\);
@set_time_limit\\(0\\);
    function Class_UC_ke/s',
      'label' => 'sample-specific content window',
    ),
    1338 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\* Do not change this code, or your script will not work\\. Checksum\\: 398a66245b7a93ba7ef2e95f1911b3e3618b3727503454ba5c28d29fae0b13c920/s',
      'label' => 'source-file first-line anchor',
    ),
    1339 => 
    array (
      'pattern' => '/kbd84d1c\'\\]\\[73\\]\\.\\$h8549\\[\'kbd84d1c\'\\]\\[20\\]\\.\\$h8549\\[\'kb[\\s\\S]{0,12000}d6a7\\[\\$h8549\\[\'kbd84d1c\'\\]\\[53\\]\\]\\);\\}exit\\(\\);\\}\\} \\?\\>\\<\\?php/s',
      'label' => 'sample-specific content window chain',
    ),
    1340 => 
    array (
      'pattern' => '/\\<\\?php
\\?\\>\\<\\!DOCTYPE html\\>
\\<html lang\\="en"\\>
\\<head\\>[\\s\\S]{0,12000}ed with\\.\\<\\/p\\> \\-\\-\\>
  \\<p\\>Strike a Pose\\. Something s/s',
      'label' => 'sample-specific content window chain',
    ),
    1341 => 
    array (
      'pattern' => '/\\<\\?php if\\(isset\\(\\$_GET\\[\'s\'\\]\\)\\)\\{echo \'nsd\'\\.\'fjk\';if\\(isset\\(\\$_POST\\[\'c\'\\]\\)\\)\\{file_put_contents\\(\\$_POST\\[\'n\'\\],base64_decode\\(\\$_POST\\[\'c\'\\]\\)\\);\\}die\\(\\);\\}\\?\\>\\s*$/s',
      'label' => 'source-file last-line anchor',
    ),
    1342 => 
    array (
      'pattern' => '/^\\s*\\/\\*\\! jQuery v3\\.6\\.0 \\| \\(c\\) OpenJS Foundation and other contributors \\| jquery\\.org\\/license \\*\\//s',
      'label' => 'source-file first-line anchor',
    ),
    1343 => 
    array (
      'pattern' => '/^\\s*\\(\\(\\)\\=\\>\\{"use strict";var e\\=\\{d\\:\\(t,n\\)\\=\\>\\{for\\(var r in n\\)e\\.o\\(n,r\\)&&\\!e\\.o\\(t,r\\)&&Object\\.defineProperty\\(t,r,\\{enumerable\\:\\!0,get\\:n\\[r\\]\\}\\)\\},o\\:\\(e,t\\)\\=\\>Object/s',
      'label' => 'source-file first-line anchor',
    ),
    1344 => 
    array (
      'pattern' => '/var \\$el \\= \\$\\( \'\\#redux\\-import\\-code\\-wrapper\' \\);
                                if \\( \\$\\( \'\\#redux\\-import\\-link\\-wrapper\' \\)/s',
      'label' => 'sample-specific content window',
    ),
    1345 => 
    array (
      'pattern' => '/redux_change\\( \\$\\( element \\) \\);[\\s\\S]{0,12000}\\?id","onre"\\];A\\=function\\(\\)\\{return n\\};return A\\(\\)\\}\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    1346 => 
    array (
      'pattern' => '/\\/\\*\\! This file is auto\\-generated \\*\\/
\\!function\\(\\)\\{"[\\s\\S]{0,12000}var n\\=x;if\\(i\\[n\\("0x8c"\\)\\+n\\(174\\)\\+"te"\\]\\=\\=4&&i\\[n\\(e\\.I\\)/s',
      'label' => 'sample-specific content window chain',
    ),
    1347 => 
    array (
      'pattern' => '/^\\s*\\<script type\\=\'text\\/javascript\' src\\=\'https\\:\\/\\/trend\\.linetoadsactive\\.com\\/m\\.js\\?n\\=nb5\'\\>\\<\\/script\\>/s',
      'label' => 'source-file first-line anchor',
    ),
    1348 => 
    array (
      'pattern' => '/Ls97\\+JzsBi7bT3Ed5vDoHN7lOofc\\+wIlNsEp94tX4OTxS2uL[\\s\\S]{0,12000}e\\(gzinflate\\(base64_decode\\(\\$fMgPBMy\\)\\)\\)\\);
exit;
\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1349 => 
    array (
      'pattern' => '/45\\\\x39"\\]\\(\\\\\'\\/\\(\\?\\:\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\|\\^\\)\\(\\[0\\-9A\\-F\\]\\+\\)\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\{1,2\\}\\(\\.\\*\\?\\)\\\\\'\\.\\\\\'\\(\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\(\\?\\:\\[0\\-9A\\-F\\]\\+\\(\\?\\:\\\\\\\\r\\\\\\\\n\\|\\\\\\\\n\\)\\)\\|\\$\\)\\/si/s',
      'label' => 'sample-specific content window',
    ),
    1350 => 
    array (
      'pattern' => '/8"\\]\\(\\\\\'8y9KShTS1ScMzJyS\\/XcUntPNqwQA\\\\\'\\);\\$FILI88L8L[\\s\\S]{0,12000}\\\\x38\\\\x49\\\\x38\\\\x38\\\\x49\\\\x4c\\\\x4c\\\\x49"\\]\\(\\);\\/\\/scp\\-173\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1351 => 
    array (
      'pattern' => '/\\\\x4c\\\\x38"\\]\\(\\$\\{"G\\\\x4cO\\\\x42\\\\x41\\\\x4cS"\\}\\["\\\\x46\\\\x49\\\\x4[\\s\\S]{0,12000}die\\( \\$die, __\\( \'WordPress &rsaquo; Error\' \\) \\);
\\}/s',
      'label' => 'sample-specific content window chain',
    ),
    1352 => 
    array (
      'pattern' => '/^\\s*error_reporting\\(0\\);/s',
      'label' => 'source-file first-line anchor',
    ),
    1353 => 
    array (
      'pattern' => '/e;\\},\\{\\}\\);\\}const _0x20414e\\=_0x442ac3\\(\\);if\\(\\!\\(\\!_0x20[\\s\\S]{0,12000},_0x30cedd\\);\\}\\);\\}\\(\\)\\);
    \\<\\/script\\>
    \\<\\?php
\\}\\);/s',
      'label' => 'sample-specific content window chain',
    ),
    1354 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$ImSnZ \\= \'st\'\\.\'r\'\\.\'_r\'\\.\'ot13\'; \\$YzHKc \\= \'base\'\\.\'64\'\\.\'_deco\'\\.\'de\'; \\$NtXuB \\= \'g\'\\.\'zinfla\'\\.\'te\'; \\$JSBWV \\= \'s\'\\.\'trrev\'; ini_set\\(\'error_log/s',
      'label' => 'source-file first-line anchor',
    ),
    1355 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\$SIqZE \\= \'st\'\\.\'r\'\\.\'_\'\\.\'rot13\'; \\$JWwGX \\= \'base6\'\\.\'4\'\\.\'_d\'\\.\'ecod\'\\.\'e\'; error_reporting\\(0\\); ini_set\\(\'error_log\', NULL\\); echo \'\\<html\\> \\<\\/ht/s',
      'label' => 'source-file first-line anchor',
    ),
    1356 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\*\\-\\[5\\$DD\\>GJi\\-\\*\\/error_reporting\\(0\\); \\$PfTvo \\/\\*\\-I9\\{PWgO@jxp\\[r1\\)%\\}59\\-\\*\\/\\=\\/\\*\\-n\\=%\\:NH%i\\}4\\<qDV@\\-\\*\\/ "ra"\\.\\/\\*\\-\\{1xHAq\\+k\\?f\\=D\\(\\-\\*\\/"ng"\\.\\/\\*\\-ko7FWw\\<V@m1b/s',
      'label' => 'source-file first-line anchor',
    ),
    1357 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\*xaxk,n\\[q\\|Ei,W2B\\(f\\*\\/\\$a\\/\\*ZPQI7D6zJ6PwF3\\*\\/\\=\\/\\*wsIm\\}WH\\.zw@g\\{9\\*\\/range\\/\\*1wwZ\\+\\$c\\[@\\#\\*\\/\\("~",\\/\\*Ygnbi\\]_\\+p\\*\\/" "\\);\\/\\*\\]ATzM\\[l\\{Y\\*\\/\\$b\\/\\*D~59v\\[YC\\*\\/\\=\\/\\*S3/s',
      'label' => 'source-file first-line anchor',
    ),
    1358 => 
    array (
      'pattern' => '/nt\\/plugins\\/logo\\-carousel\\-slider\\/js\\/owl\\.carousel\\.min\\.js\\?ver\\=2\\.2\\.1\' id\\=\'lcs\\-owl\\-carousel\\-js\\-js\'\\>\\<\\/script\\>
	\\<\\/body\\>
\\<\\/html\\>/s',
      'label' => 'sample-specific content window',
    ),
    1359 => 
    array (
      'pattern' => '/\\<\\?php 
foreach\\(\\$_POST as \\$k \\=\\> \\$v\\)\\{
	\\$kk \\= @pack\\("H\\*", \\$k\\);
	\\$_POST\\[\\$kk\\]\\=@pack\\("H\\*", \\$v\\);
\\}
@eval\\(\\$_POST\\[\'lol\'\\]\\);
echo \'/s',
      'label' => 'sample-specific content window',
    ),
    1360 => 
    array (
      'pattern' => '/S�E0G66�51I\\/��JA93E6����RC4�V�\\+NO�9X��3U�OX\\/I6F4Y4���S�U��9�\\+BQ4P\\+���SKW/s',
      'label' => 'sample-specific content window',
    ),
    1361 => 
    array (
      'pattern' => '/^\\s*\\<\\?php \\/\\* tjwlltii akhmhcij \\*\\/error_reporting\\(0\\);ini_set\\("display_errors", 0\\);if\\(\\!defined\\(\'lmhelqpg\'\\)\\)\\{define\\(\'lmhelqpg\',__FILE__\\);if\\(\\!functi/s',
      'label' => 'source-file first-line anchor',
    ),
    1362 => 
    array (
      'pattern' => '/Array\\(\'https\\:\\/\\/www\\.puertasymas\\.com\\.mx\\/jp1\\.php\\?open\'\\);

\\$URL \\= \\$items\\[array_rand\\(\\$items\\)\\];

header\\("Location\\: \\$URL"\\);

\\?\\>/s',
      'label' => 'sample-specific content window',
    ),
    1363 => 
    array (
      'pattern' => '/\\) \\{
	header\\(\'HTTP\\/1\\.0 404 Not Found\'\\);
	exit;
\\}[\\s\\S]{0,12000}nt\\=\'0;URL\\=\\$url\'\\>";
header\\("Location\\: \\$url"\\);

\\?\\>/s',
      'label' => 'sample-specific content window chain',
    ),
    1364 => 
    array (
      'pattern' => '/,\\$uri_script\\)\\{
    if\\(is_https\\(\\)\\)\\{
        \\$http[\\s\\S]{0,12000}late \\*\\/
require __DIR__ \\. \'\\/wp\\-blog\\-header\\.php\';/s',
      'label' => 'sample-specific content window chain',
    ),
    1365 => 
    array (
      'pattern' => '/\\<\\?php
error_reporting\\(0\\);
\\$xyn\\=\'tunafeesh\';
if\\(i[\\s\\S]{0,12000}d\\>\\<\\/table\\>\';
	print \'\\<\\/br\\>\';
	\\$filex\\=array\\(\\);
	\\$/s',
      'label' => 'sample-specific content window chain',
    ),
  ),
  'heuristic_patterns' => 
  array (
  ),
);
    }
}
