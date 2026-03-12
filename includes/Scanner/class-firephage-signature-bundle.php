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
  'version' => '2026.03.12.000737',
  'high_confidence_hashes' => 
  array (
    0 => 
    array (
      'sha256' => '7b87bda6446ffe4f380fe3453f19a5d8fd0dfb00765fb43ff243e87ce1e8fedc',
      'label' => 'home_1773076723.php',
    ),
    1 => 
    array (
      'sha256' => '6fb6ce4fc4a8a9b486b8f8943da4c3a52f8393824d6f7dde4825c63fb6753b41',
      'label' => 'wp-edge.php',
    ),
    2 => 
    array (
      'sha256' => 'fc0dad8a1a4eb6ca04f0deb1c272f1be64b4c5f1c3a84f73d69b6cafa2e462b9',
      'label' => 'bypasses.php',
    ),
    3 => 
    array (
      'sha256' => '5868105dd547453d0ece304e89f754c2c105dcb58a7f0a341bea1b76f6a62527',
      'label' => 'dodgy.php',
    ),
    4 => 
    array (
      'sha256' => '611e04096c0dac9505971bf26b2f0c09b56b6d8999a9ed7dc36807386b3b0bfb',
      'label' => 'obfuscated.php',
    ),
    5 => 
    array (
      'sha256' => '48edc3173ebb5d89d7bc8091729291d93224088713579dc24f068fb0bf0753c6',
      'label' => 'ajaxshell.php',
    ),
    6 => 
    array (
      'sha256' => '154d4b14a33d1a2dcba287a1b12c47995d75c06f5874264c9835987ecda7bf9f',
      'label' => 'angel.php',
    ),
    7 => 
    array (
      'sha256' => '3ddc58afd030b7b65a52ae24dbffa0b6ad134ba3872b2c4594229409818b9ec8',
      'label' => 'b374k.php',
    ),
    8 => 
    array (
      'sha256' => 'd1f091328fea2fac425dce43372e29b60daacc8cb66a2026e0376a15513cce04',
      'label' => 'c100.php',
    ),
    9 => 
    array (
      'sha256' => '58c5c5801d3b45fb13fc950f4f77b6f9894fce4b487354ed1f9bd2657b4a3482',
      'label' => 'c99.php',
    ),
    10 => 
    array (
      'sha256' => '90ed4936c676c06df9806fbf60838d052d24c606e57572ea05a2e273866c6515',
      'label' => 'cyb3rsh3ll.php',
    ),
    11 => 
    array (
      'sha256' => '6d03196b01df177f24564173ba0906e076d5ad5ddec2748f9bcbb7a766659dff',
      'label' => 'r57.php',
    ),
    12 => 
    array (
      'sha256' => 'b2176ff9f4da9e9c51fe83d4bb6967e484e11dc25929da7a329657df13a0ed31',
      'label' => 'simattacker.php',
    ),
    13 => 
    array (
      'sha256' => 'cd650fd612344d95375199017ced484eac667fb635a14df6ee5ccd17f3627876',
      'label' => 'sosyete.php',
    ),
    14 => 
    array (
      'sha256' => '3a7c73f6c41d1c1959e98da0241554f8de751a0796da2a5048813910d6c3050b',
      'label' => 'cipher_design.php',
    ),
    15 => 
    array (
      'sha256' => '9d406c89d465f0f10a70e2fa622606e7aa3b3d5d5e2f6e67c4611f00813329b9',
      'label' => 'online_php_obfuscator.php',
    ),
    16 => 
    array (
      'sha256' => 'fedb39e384f2f59add3a3b28a8e156c29d007f30d0c543c69f1c15cf1b1da4d7',
      'label' => 'phpencode.php',
    ),
    17 => 
    array (
      'sha256' => 'df3021aa31efe9f9f75046b0c3cd945744f9a99307fd9ad9577ee0028419eecc',
      'label' => 'awvjtnz.php',
    ),
    18 => 
    array (
      'sha256' => 'f6c109e526cba3f1d39f1e06cc9efa47d848098bc70c8188769f79e3eaadb650',
      'label' => 'exceptions.php',
    ),
    19 => 
    array (
      'sha256' => '76bdc5918fc813bfe396d70850cd5220069e3127405a5fb1ef9ab046bb2da080',
      'label' => 'guidtz.php',
    ),
    20 => 
    array (
      'sha256' => 'ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521',
      'label' => 'ice.php',
    ),
    21 => 
    array (
      'sha256' => '614fd66655e2bb2515fbf24a20c00f34569042e8e3022e1fedde4f072971be02',
      'label' => 'include.php',
    ),
    22 => 
    array (
      'sha256' => '4b64123a3979435f7d222554bf4d077cad72737056b00c9f1ec3199cb4e14128',
      'label' => 'nano.php',
    ),
    23 => 
    array (
      'sha256' => '8fcb3d47e8cd8bc73887d35e65e5638d8765503634bf56365d31355bf4a2f53c',
      'label' => 'ninja.php',
    ),
    24 => 
    array (
      'sha256' => '5fc73588f99ab3d1722c39a748bfa8d37b3ef5faabb26605f950ee6710d71065',
      'label' => 'novahot.php',
    ),
    25 => 
    array (
      'sha256' => '970b3c191313781bbc28f01361c999ad9c31043340496522d54f68caae47ceac',
      'label' => 'srt.php',
    ),
    26 => 
    array (
      'sha256' => '57c604dbe143994dacf0189b0495d640796afe0d8e65155e83d9e25478ba5300',
      'label' => 'sucuri_2014_04.php',
    ),
    27 => 
    array (
      'sha256' => '5ef5eb652cde60379e97ddab2e653cab275d6b785555960ee776baef7008cccf',
      'label' => 'smart.php',
    ),
    28 => 
    array (
      'sha256' => 'dfe7b149a26efcdc70fc2b60efd6cc0b611de7cdbb059c8bf6ebec6a379da4bb',
      'label' => 'cpanel.php',
    ),
    29 => 
    array (
      'sha256' => 'c11c4d220378ff3c368bfd02db037b6de1eac80f0546b0f37f7a812393b29619',
      'label' => 'freepbx.php',
    ),
    30 => 
    array (
      'sha256' => 'f061b70af949afa98e678f45c4e363edf00c6aef57a8525544a989aff4295223',
      'label' => '35be5.php',
    ),
    31 => 
    array (
      'sha256' => 'eef085cf8953b2d906ba0e29d60ecf524f63f255ac3e77c8635dc2807fbffecf',
      'label' => 'ganteng.php',
    ),
    32 => 
    array (
      'sha256' => '58ad93f2f138fcaa225c4ffe70b23461a4738c85a925a9ccacce477ce3724ac3',
      'label' => 'ab19cleaf.php',
    ),
    33 => 
    array (
      'sha256' => 'ecd0423d1db5f6845c0478fe42dadab39d1d804604f3cdafa62565de7e92f7f4',
      'label' => 'admin-ajax.php',
    ),
    34 => 
    array (
      'sha256' => 'c88efa7f9a2b6026a80eacbe3ae2b45e70e5d8b36bfb67241f1844ff58a2f7c8',
      'label' => 'itukyj.php',
    ),
    35 => 
    array (
      'sha256' => 'e4d80e521456ad4fb6c34ef4f11673116217852a151dca76fe9c33675e82a375',
      'label' => 'wp-engine.php',
    ),
    36 => 
    array (
      'sha256' => '15f34dd6e2a8e516b0ae386cbe6649a3531e2a907206230627fca3729b2d4358',
      'label' => 'index.php',
    ),
    37 => 
    array (
      'sha256' => '0e9028e3d9243348ad51f3f0f6777d99035e1659872d2c2bb9e5a1cb73bec047',
      'label' => 'uploadify.php',
    ),
    38 => 
    array (
      'sha256' => 'd3a6489cb756f7937fceb406db44f754d0533058072c02bf45cbfdf5c21f7322',
      'label' => 'f0x.php',
    ),
    39 => 
    array (
      'sha256' => '86e85351ed3addf463e76eb4ea10199b2041d00766d389ab203fbc8355cf958d',
      'label' => 'apikey.php',
    ),
    40 => 
    array (
      'sha256' => '00348292b76ccef666a54ac26513706a4959ae20a150278adeec05ecae423c02',
      'label' => 'rtivpdvu.php',
    ),
    41 => 
    array (
      'sha256' => 'b538675535dc766fc438a5664860efaee3f9da70aee0aa17a7f3796f3c4531b4',
      'label' => 'index.php-b538675535dc',
    ),
    42 => 
    array (
      'sha256' => 'bf5319cc08f7aeaa884cff116df9c4e0d00c10c080383970462af3281163d0e2',
      'label' => 'index.php-bf5319cc08f7',
    ),
    43 => 
    array (
      'sha256' => '833974bafad43f4737f05053056cda7b648deadaa1ca5fa5b2e8a926748fdf0c',
      'label' => 'email.php',
    ),
    44 => 
    array (
      'sha256' => 'a9a324005b82110d80a5ac06329088d36198589db2018e76ff30fb19d5747dea',
      'label' => 'index.php-a9a324005b82',
    ),
    45 => 
    array (
      'sha256' => '484607d3bbe58d9fc3bf55fd8ed034812096a44a5dbb0d34ad5619054e21dfa0',
      'label' => 'next.php',
    ),
    46 => 
    array (
      'sha256' => 'e23203109684f3e6026b96282326e7f2bae226f89c0481d92f30c24df2a623b9',
      'label' => 'wp-blogs.php',
    ),
    47 => 
    array (
      'sha256' => '88a7120228498632acf85c03cdeb0416e0f07c237cf2d96f0742f77324312f5a',
      'label' => 'cwhpolya.php',
    ),
    48 => 
    array (
      'sha256' => '2ccc82c1d646a220c48ffa964e0e5e30c40c7213a8b23ca216eafd30f89a2c38',
      'label' => 'index.php-2ccc82c1d646',
    ),
    49 => 
    array (
      'sha256' => 'c8444a90c52c9c8b036bdeeef74dc9a42d0d74fa1b5e856f8b266a2c2064c4d7',
      'label' => 'wp-lazyload.php',
    ),
    50 => 
    array (
      'sha256' => '45bef166df0355bd3616428ff14c9829bfa567222af098dc08d784325de9e00a',
      'label' => 'lefxwfyd.php',
    ),
    51 => 
    array (
      'sha256' => '13dcebd6ece8ada467ad123762fd0f58377a4c79867575262f8e3f370dca3ceb',
      'label' => 'index.php-13dcebd6ece8',
    ),
    52 => 
    array (
      'sha256' => '51acdbb0844fde88e91d6e28308ea851e5814661f598a2716c2d5bf6083f3ec6',
      'label' => 'wp-lazyload-module.php',
    ),
    53 => 
    array (
      'sha256' => '09380e0629d634cddfbf9370c58a20f9cf1f42ba09a5ec41822d61a6223336c6',
      'label' => 'index.php-09380e0629d6',
    ),
    54 => 
    array (
      'sha256' => '5a5c6f59fb4a9e138fb668744042d3fb7f33346a274ae529984e24b9b2d9aa2a',
      'label' => 'bdhrIGW3ARq.php',
    ),
    55 => 
    array (
      'sha256' => '931258b2ceda152bd318231dbcc8283f6bea45e014a8d81761d8d773a83ffd1e',
      'label' => 'serializer.php',
    ),
    56 => 
    array (
      'sha256' => '12be653ebd3e3ebb8994af7a36e08c1adcbdc425d5e7dc041418f8341757e328',
      'label' => 'replace.php',
    ),
    57 => 
    array (
      'sha256' => '3723596b6d5bcbf14ab16e373f94d8ba1b51a03c407159769a9d32661552478b',
      'label' => 'zc8drqi5.php',
    ),
    58 => 
    array (
      'sha256' => '56eb49a9483fd1f2f83384fa7270b0ad49b01c107c182ab425f44c4710887276',
      'label' => 'cm690ah4.php',
    ),
    59 => 
    array (
      'sha256' => 'b663996a1a8967a77c47103d2e353ca86983a22ba2a7fb40eb44309599c56ded',
      'label' => 'i26v24be.php',
    ),
    60 => 
    array (
      'sha256' => 'fd7dd6ab635d3a38ecc7687ff74f785ea9b31a06cd31b5666ae5bfe99c4d44ee',
      'label' => 'curl.php',
    ),
    61 => 
    array (
      'sha256' => '669ecb200f07c916ceaab5dbe07ee70a5bff0c65ca18f303fb453e2d0155851e',
      'label' => 'index.php-669ecb200f07',
    ),
    62 => 
    array (
      'sha256' => '6b528a13327773c73e8e74cd961e9f1ce356299fffeb1df0ff3cdfde66ff5398',
      'label' => 'index.php-6b528a133277',
    ),
    63 => 
    array (
      'sha256' => '899c0389d4a0c71a13f1e96c77cb39f84d59bfb761c709bbf7066a2e8ab65604',
      'label' => 'gas.php',
    ),
    64 => 
    array (
      'sha256' => '69b8e658e9bf7625ffbad7d41532eb4324d785c0d8f92e41648a537ef1354193',
      'label' => 'unzipper.php',
    ),
    65 => 
    array (
      'sha256' => '51d29e255d7377127d98bb120ebf58ce07ab3227202b0141991bb2b68d11ebbf',
      'label' => 'index2.php',
    ),
    66 => 
    array (
      'sha256' => '59cfe27700d2eb8547dfb9c19628c6672a596635df35cbad02f73f4bbbe342e0',
      'label' => 'i.php',
    ),
    67 => 
    array (
      'sha256' => 'bdd416b69b1911acac95608957154a83f08dc84cf84d3c4db0289ec1c67fff04',
      'label' => '7bEMANYu_index.php',
    ),
    68 => 
    array (
      'sha256' => 'c38578c7f669371f7456c135a65966ee48b21c6528ce03e2ef70f7fca59c6158',
      'label' => 'zwckn.php',
    ),
    69 => 
    array (
      'sha256' => 'd69c11b2f12024a14ea5b2c2e6f0913a324786e20438c46efbad60195b4f0f7d',
      'label' => 'zh2.php',
    ),
    70 => 
    array (
      'sha256' => '5a15bc86a104f11206f6ee3269f9cdaf5d8d16f3f87563b4ecfe43ccfed30935',
      'label' => 'xmjmrjk.php',
    ),
    71 => 
    array (
      'sha256' => '0b853843b244cfab4b0d4e3746be37a5872e9586947a0764fd612da21bb7332c',
      'label' => 'xl7.php',
    ),
    72 => 
    array (
      'sha256' => 'a6212e03318ebbf5b3f0cead9d739fdfabc9170b23ca0b749b41b936a929927f',
      'label' => 'y8mh3i.php',
    ),
    73 => 
    array (
      'sha256' => '90342fa86b59e5b47eb0fec3448a0f4a3d4b0774e9165f3d9473bec4f7d4dab8',
      'label' => 'test.php',
    ),
    74 => 
    array (
      'sha256' => 'ea4667ed00b746d3ccb6ee8be49bc09ab1c3298144a38c6f83fc26dfcaaed698',
      'label' => 'yvguud.php',
    ),
    75 => 
    array (
      'sha256' => 'a01b216afe6d26e0ad91b175003cb2ee87069571091e3b531c93652430548a4c',
      'label' => 'index.php-a01b216afe6d',
    ),
    76 => 
    array (
      'sha256' => '88539865c6244b80e2acb91ac81f27c6091fc693a6b49c6f890bcacb101ddb1a',
      'label' => 'zkp32l.php',
    ),
    77 => 
    array (
      'sha256' => '760758580aeb1d11e24fbb352fbba9e62fe8ce55ab13628cc46b538b80c8cc8a',
      'label' => 'a.php',
    ),
    78 => 
    array (
      'sha256' => '056aa5d7af24a481e8ce16c401895fd9d5925be68d3f4228f5390817bcd4b93e',
      'label' => 'CXfmwPlE36q.php',
    ),
    79 => 
    array (
      'sha256' => '658207891ba861b15243d061baf494e7d0f50eefa6438e793824a8603d78f4c1',
      'label' => 'um9be.php',
    ),
    80 => 
    array (
      'sha256' => 'fbcfcb72a47a038bce9fdd76e5a0330854db0bb0c67819e74886c1c97c9647ee',
      'label' => 'ChunkInterface.php',
    ),
    81 => 
    array (
      'sha256' => '3bc51d2a372ea78df229e323425f284cc20c88e84308484d410d5100ae5c0bd8',
      'label' => 'WebService.php',
    ),
    82 => 
    array (
      'sha256' => '8ffb0f11b22eae627b2da7d47a412d46e00b73263fceb3ac6510239cdda61254',
      'label' => 'index.php-8ffb0f11b22e',
    ),
    83 => 
    array (
      'sha256' => 'e26ba197dbeb9258ca26514483e1a5fbc08d2725f256171cca2460b95cf14721',
      'label' => 'ETuyk8OSIiD.php',
    ),
    84 => 
    array (
      'sha256' => '593c776bd0ff516a96d528939844ddf959ccf4e3793550c24d23e37ba27f4760',
      'label' => 'core.process.php',
    ),
    85 => 
    array (
      'sha256' => '2c2f0b70cd164abd5a7857bb10b1bc470ba9ae5304afaa6d3bd871ff0d36fa48',
      'label' => 'generate_sitemap.php',
    ),
    86 => 
    array (
      'sha256' => '330a709d747547db3535a98bb01f25c9586c474e1aa01c53ca8487fb44501279',
      'label' => 'wp-zofxyf.php',
    ),
    87 => 
    array (
      'sha256' => '14ce0b03bc6e8225d80503ec512cf2a529feb5b38a620558224794254bda64ed',
      'label' => 'worker.php',
    ),
    88 => 
    array (
      'sha256' => '5c3296b59edb8d9627cd8c3811c0f0809fc0966711ba9162d4c2f16c6ebcdc3d',
      'label' => 'mhpuksh.php',
    ),
    89 => 
    array (
      'sha256' => '51b5720ac2995ef743d99ac74f64b7eebd25d584d5e30d866b4764812428d2cc',
      'label' => 'RvYXfjQc.php',
    ),
    90 => 
    array (
      'sha256' => '40091b48e5e74babc876bb84c4f3a5645fb118caf64ad07ec4b89c03d339995d',
      'label' => 'archivo.php',
    ),
    91 => 
    array (
      'sha256' => '2241c958414d3e01757789a0d85bb06cd5e44ab2b50ee308882481a75902c2d5',
      'label' => 'shtcm.php',
    ),
    92 => 
    array (
      'sha256' => 'c7228c074e4aa08c9623b8fef7cbb09b45954e10245c86b5ad7afa5b717b5818',
      'label' => 'mxqvf.php',
    ),
    93 => 
    array (
      'sha256' => 'd8ba18c11b140b2552354ea92e4c805428810356e06104fdab1f5aa7e8df129c',
      'label' => 'bqmzs.php',
    ),
    94 => 
    array (
      'sha256' => '852e6531642fedcca02f4fda16ea18110a46f25c82d0ce8333619a5968629a54',
      'label' => 'eupfebq.php',
    ),
    95 => 
    array (
      'sha256' => '8443518a9e46275796d7d8cbc76920a0156d2be3411146c058caf6dd1ba75aad',
      'label' => 'myaetvdq.php',
    ),
    96 => 
    array (
      'sha256' => '6664d587d96dd6d743f63ef432feb9b0076a8f32a79d463c85a16a4e2aee2f35',
      'label' => 'z.php',
    ),
    97 => 
    array (
      'sha256' => '0b25c02ea4c716ea25df293cd1d0c0cfcc242b4e3a5dcd188ab8d80a92ee89cd',
      'label' => 'bbydtgdyq.php',
    ),
    98 => 
    array (
      'sha256' => '44ed9d9a7bd862374a3244cbf9b2469151f15346c4f170aff6fbc283c60c5ba4',
      'label' => 'umcfp.php',
    ),
    99 => 
    array (
      'sha256' => '1fc50d53f9b6f39d43f6788c42e9c1e496bcedc27d3682686b6b048dd6a1d4f4',
      'label' => 'orderhistory.php',
    ),
    100 => 
    array (
      'sha256' => '8c520b19f532fcf9d30c37c0bbb595f75f5fbb9ead45d1ef72aadc3302d827bf',
      'label' => 'rnzyd.php',
    ),
    101 => 
    array (
      'sha256' => '56f571cec111a738d1a6fc169795dbdbdf9926f92a9b7fdb1e5f258942ff3e3c',
      'label' => 'IoYYhwFKdddd.php',
    ),
    102 => 
    array (
      'sha256' => '0f215b8f1f5c8d77e5c3ae9dcad60c5f753a93b42d427375db7e94d84b5f344b',
      'label' => 'd00027.php',
    ),
    103 => 
    array (
      'sha256' => 'c0732a5ffadec3b154e9b281eeb628d49228e3d459b7f3cd8d0c82be7caad5b7',
      'label' => 'mgqsqeghyk.php',
    ),
    104 => 
    array (
      'sha256' => 'b0188ca2440a660ce04c12eb6664c8f5c7e74153780a4eb9e8785c9a2071f985',
      'label' => 'hvhdchb.php',
    ),
    105 => 
    array (
      'sha256' => '1444719b1b40a3f92624d4872cadee3f6e5f2f01f9609259ba731f292fbfb0aa',
      'label' => 'BFmAJSxX.php',
    ),
    106 => 
    array (
      'sha256' => '630853ccab89d2d5d92fa6da15e4528fa0f99a1943e4bf7411b9832055fd6d81',
      'label' => 'sdqzdwkf.php',
    ),
    107 => 
    array (
      'sha256' => 'd2c0ffb9b34f7c919b9a3a7c3fad185e1a0f40985d30b76d0c3ac1c19e8f1283',
      'label' => 'config.serious.php',
    ),
    108 => 
    array (
      'sha256' => 'a575cf7d762202a7dff037487dd85f671f03f889a2b6ed6869dc65a49827c514',
      'label' => 'shirt.config.php',
    ),
    109 => 
    array (
      'sha256' => '58167141b4ddf513a8287ef19c1051a0915b998f3793d60355ac38c54877304b',
      'label' => 'hezvznsgw.php',
    ),
    110 => 
    array (
      'sha256' => 'ad175262a1f2e2054f911b4cc30ec14eb0dca49f9e9a2d396708c210f35e040f',
      'label' => 'mail_a_friend.php',
    ),
    111 => 
    array (
      'sha256' => 'a5c06e07cc4c6c7cf425b34f239c6913f8b7506e92fe143ee54001554c4da389',
      'label' => 'bhnzr.php',
    ),
    112 => 
    array (
      'sha256' => 'bd8bdcd23331659297786b26b05b9811ea389eeb4ed82a5ad070c4251f969225',
      'label' => 'rsfktbw.php',
    ),
    113 => 
    array (
      'sha256' => 'ee9516f1cde03e4de50afdd02ce4e88297a6f503db30776341d1351c644b44f1',
      'label' => 'pv_de_recette.php',
    ),
    114 => 
    array (
      'sha256' => 'ff12329618bb632e1cabf3572dc3d7ebfa809e7d02caff983a17e1ef85f3dd1b',
      'label' => 'eyftu.php',
    ),
    115 => 
    array (
      'sha256' => 'c91dcde1ad90e8deebfc7a2609f0710b0159126688311f5a8cc7c76691d74cda',
      'label' => 'aepefwu.php',
    ),
    116 => 
    array (
      'sha256' => 'ed1f9eca85f7b52be2a2e03339faea7268533b0c1d6527324dbf29c0af409561',
      'label' => 'realtones.php',
    ),
    117 => 
    array (
      'sha256' => 'a51c00839711b04f5ed4aef84ad282184173666de2622e1227ffa36a88c3458d',
      'label' => 'wqaxwsnc.php',
    ),
    118 => 
    array (
      'sha256' => '9b3512fb1c2155614cb86657d1d87e9db18fa44f3019c5e97f559ff6b38b3954',
      'label' => 'zdxvwttfh.php',
    ),
    119 => 
    array (
      'sha256' => '66c59d807b2622ce444398a3ba19055b645f68373f7e7ac090c2b02ebba449f4',
      'label' => 'umupwgvv.php',
    ),
    120 => 
    array (
      'sha256' => '7ba1396b48b8b01bac4a146704d035a76c27c304232771df6c49d5bbe840c5cd',
      'label' => 'hmbhpbhru.php',
    ),
    121 => 
    array (
      'sha256' => '42026019cc05e7c19ff22f39021b52423f4b5279b0a8a9f3b369c69da573da81',
      'label' => 'xgzsky.php',
    ),
    122 => 
    array (
      'sha256' => '4a459df6b00100d9c6a30b3a2a2cfdf1497c3f3f49d5d2439f89fec6daaa1bbf',
      'label' => 'deptodoc.php',
    ),
    123 => 
    array (
      'sha256' => 'bc85bc6cb23af8c104d77055435a22017bce6198bc2ca4aa348e3d0ba5823b12',
      'label' => 'exfwbthuff.php',
    ),
    124 => 
    array (
      'sha256' => 'c4894c4836b4f863af1e1200ca0f21c2c380934a44bf2ad5650ca6d92da837ec',
      'label' => 'page-36.php',
    ),
    125 => 
    array (
      'sha256' => '6ae863f1f763a59f653dddbe1e47c7c5087be13d49b249df3bfb9ee7e608fe64',
      'label' => 'bgebawr.php',
    ),
    126 => 
    array (
      'sha256' => 'd042110d1732d26ef1a8f3be48e8a1187affe28d54d706468e17b33e65f5e9fc',
      'label' => 'vffbzx.php',
    ),
    127 => 
    array (
      'sha256' => 'd4983b2a02a080e68747b5f2f85f1605a733efafde37405c3641504672d16be0',
      'label' => 'akqbuc.php',
    ),
    128 => 
    array (
      'sha256' => '24cd0f4f801ebd3ed01e169305f9ffcc327912918eeea280002d1f5be041e68e',
      'label' => 'sgeqsxenb.php',
    ),
    129 => 
    array (
      'sha256' => '67649535d30023a015f34a3da5fae7ca3af6df2bdd376d5ee44477e7f996205a',
      'label' => 'gddftfxd.php',
    ),
    130 => 
    array (
      'sha256' => 'e8e0a3bd4e6181194100d19435016f43fb8dc77a9ffebdc07171b931550ea47a',
      'label' => 'frwfqtgv.php',
    ),
    131 => 
    array (
      'sha256' => '21ff159cc1d54e9c69c75d3b22035913df1a4a4ad5e1b33f49488149a7e7bb76',
      'label' => 'qwhskkrcgy.php',
    ),
    132 => 
    array (
      'sha256' => '7e534d3fa2a8e4b36b7d5dba770dc8667f57a99533443d044f50154781112566',
      'label' => 'tptnsu.php',
    ),
    133 => 
    array (
      'sha256' => 'b8700dc57a9e865970180d13f6d150505e1f11c888320ad040b2c1bcaf27faea',
      'label' => 'eavmwwvx.php',
    ),
    134 => 
    array (
      'sha256' => 'a86564ebc605440cccd42c63661a914ea1d661f634aaf2f659c0885414b29006',
      'label' => 'kkxtucrbz.php',
    ),
    135 => 
    array (
      'sha256' => '2a9474406757d7cbeb1e06852231290e27054d9420c19ddfc0af6c114fd9904c',
      'label' => 'vmnyvhs.php',
    ),
    136 => 
    array (
      'sha256' => '268e36e8c108bb2a3a362d07dd0b046dd9b1f4122a56f84889068a519756094e',
      'label' => 'function.lesson.php',
    ),
    137 => 
    array (
      'sha256' => 'b095dc149b2f97ed7481f6fdb58b902d25626af4674223661bd4241da3a6a5c1',
      'label' => 'fog.conf.php',
    ),
    138 => 
    array (
      'sha256' => 'b52c56d9f28635373eae9d7358bf4a0a3afe323284a03f32c431b303e863c895',
      'label' => 'uyunenfbg.php',
    ),
    139 => 
    array (
      'sha256' => '01c3351e622d69914baebca646bc2210a9962808693c557aa6841ff6a6fb7e4c',
      'label' => 'hhttxhnf.php',
    ),
    140 => 
    array (
      'sha256' => '405655830c5010d2cf6b56badd3ef13000464cf8a402a770893f44405bda0777',
      'label' => 'bwyfyqpzvn.php',
    ),
    141 => 
    array (
      'sha256' => 'd5e2587da50b83ca24dbb6244d367acdb3f100bb3e6c338c5897ef4e56827066',
      'label' => 'tmhdphgxz.php',
    ),
    142 => 
    array (
      'sha256' => 'f504247d2f4cd81e7a32c65028f4610ca6fb54b60b8a516ffd95c21f4d481205',
      'label' => 'class.rays.php',
    ),
    143 => 
    array (
      'sha256' => '65e08e9dfeec24a11ab73d07426be6e6032ddf508527777842660a5c1825b9b8',
      'label' => 'rnxzwzxdux.php',
    ),
    144 => 
    array (
      'sha256' => 'e27f66f07b4d103b1f643b95a55f567a5b58a82bd17cc01b8f1c2443492e3ae3',
      'label' => 'gfuumczxw.php',
    ),
    145 => 
    array (
      'sha256' => 'e45c6b45580eeee6a8cdcb129f81589bab99d69ae0bce69647ae11f688176fa4',
      'label' => 'kyngwv.php',
    ),
    146 => 
    array (
      'sha256' => '5a861f456be9e9d81839e3209aaae4277bc4cea42ec727606dc995db0a995141',
      'label' => 'phpinfo.php',
    ),
    147 => 
    array (
      'sha256' => '467ca85024df51978840d06895ef38812959d1cfe91fedbc8dacbc12a530153d',
      'label' => 'fdhuzerqb.php',
    ),
    148 => 
    array (
      'sha256' => 'd8a8b499ca0a92995482d7dc76f213ac3e494f10369da2335bf957be27579cd8',
      'label' => 'tuhqy.php',
    ),
    149 => 
    array (
      'sha256' => 'e17682220c924ba0fdcd8cd1d8e96c833bf5b5d463e713f8420ed33dca188e72',
      'label' => 'hqutsucq.php',
    ),
    150 => 
    array (
      'sha256' => '35ee362d6c34006a6ea2d872c2119f79af2730dbe4271512d95bf352b33df8a7',
      'label' => 'config.parallel.php',
    ),
    151 => 
    array (
      'sha256' => 'fb5e06ec243bef657239485f0f362aebedb978cb5f51a7a9a0d2acb2d3e989a5',
      'label' => 'reseller.php',
    ),
    152 => 
    array (
      'sha256' => 'cf523407f5f9b85674d6c3d31880a4168b222a2f998f84e5cce9ab41aa070948',
      'label' => 'requestinfo.php',
    ),
    153 => 
    array (
      'sha256' => 'bb180240673a4a6c2442c2c7754a86f190c350bb480eff9e1715cb5d2c2e93c7',
      'label' => 'watch_video.php',
    ),
    154 => 
    array (
      'sha256' => '1f1e13b44a2f922978be16ebc46a43b37036117c3539f5895b883e2f43f460a2',
      'label' => 'pbzrak.php',
    ),
    155 => 
    array (
      'sha256' => '4fe84babc0bcee7873df04c49454b1fba706dfac8975654c896bb1641a5af278',
      'label' => 'ygrbq.php',
    ),
    156 => 
    array (
      'sha256' => '28d7832339778812c358587124d025b17b4ba1da64d0feaf8c9fef30e964bb91',
      'label' => 'register2.php',
    ),
    157 => 
    array (
      'sha256' => '91cf9eb167bf452228c12367cb2065a7f3fa02ba9e3b769d310be254d1c2befb',
      'label' => 'forgotpassword.php',
    ),
    158 => 
    array (
      'sha256' => '59c731eb9b4fdc0ccdf47d1b69707490a7dc545eac92a462d3984ed66fcad5dc',
      'label' => 'npwccabqrw.php',
    ),
    159 => 
    array (
      'sha256' => '05da4bf4115fd61d7b1a464dbcebc0c37368ef18ce4dea4abd615ab21dfc8941',
      'label' => 'tpnygm.php',
    ),
    160 => 
    array (
      'sha256' => 'afe534e2fbf8db5b67da12d7c5e7dbb37b27df34efa24c9d305863303621d0cd',
      'label' => 'cpnmtancu.php',
    ),
    161 => 
    array (
      'sha256' => 'ac0cd72ac2712cc9fe4e6d588e5d136a5771c42d7c8f0b229ce1e820f6dab5ce',
      'label' => 'wvemvds.php',
    ),
    162 => 
    array (
      'sha256' => '51784383686cd5329c9ce43c59476b82695305ffa2a7fc773b9ea878d1da0047',
      'label' => 'tnmzxz.php',
    ),
    163 => 
    array (
      'sha256' => 'e09be72945bfa59ad80abae388c3cbeafdd99f1578316c7df1346add23c062ca',
      'label' => 'meinedaten.php',
    ),
    164 => 
    array (
      'sha256' => 'c36c393ba415a2d9a99388d1b6e886be3002583304ec21ae665a3ed0caab9b74',
      'label' => 'qyrkz.php',
    ),
    165 => 
    array (
      'sha256' => '3d3bc1d8206501391ba0ebd9ba6a85d3929d3f6dc41039cec9731491e4fa2893',
      'label' => 'apzfty.php',
    ),
    166 => 
    array (
      'sha256' => '231a602e21a18bd06c4cf46846810d866e5239ad55053afccb5254bb3766efb5',
      'label' => 'newsletters.php',
    ),
    167 => 
    array (
      'sha256' => 'bcb24636e5649de1a846b04a95acb525c5cf4ea8b3b9c424f1a11555cda08157',
      'label' => 'swqnxacbya.php',
    ),
    168 => 
    array (
      'sha256' => '8d5b7ba136fcdd94f2df020b04a5733649f284ad2f2430c20dfc6a0241a80fc4',
      'label' => 'exxyp.php',
    ),
    169 => 
    array (
      'sha256' => 'ad4fca3cd23e62463193926299eb0e502583a4219c2460859a8ee9210a2c34a1',
      'label' => 'config.youve.php',
    ),
    170 => 
    array (
      'sha256' => '35d8d9f00528e68716a10392ba52b174d3a00e493785bd8fa4cc24e92f63b8c8',
      'label' => 'gprpugf.php',
    ),
    171 => 
    array (
      'sha256' => '6dbe0fe82d6dbfdc2cdf0ecb866746be76818293298754a21da920c61ff93d64',
      'label' => 'credits.php',
    ),
    172 => 
    array (
      'sha256' => '3df0320ba1052e4e2413810290e763d60ebd4bcf571e9c77279cc62c85beb517',
      'label' => 'fpfbvde.php',
    ),
    173 => 
    array (
      'sha256' => '0e4788f4341360518a7f9cf82e2bce72d557797cdf8db045630669092a6e42c8',
      'label' => 'keapduxxnu.php',
    ),
    174 => 
    array (
      'sha256' => '894ec85123c84cb6aa8e380581fb9ea84c130000638d39203e6b1b16e6df3e76',
      'label' => 'fbtfy.php',
    ),
    175 => 
    array (
      'sha256' => 'fdf6ade1ca6b244a48f409abffaf7bf567f8a1b407e41eff21a1bbb689aa51b1',
      'label' => 'wxahfe.php',
    ),
    176 => 
    array (
      'sha256' => '0dc0c0fa36971bfc212452cf9ecb2d1202f65d56f775166d03b540c6fa52d281',
      'label' => 'ghgmhfryf.php',
    ),
    177 => 
    array (
      'sha256' => '481c65b0f3e8e07a5d378efab3e28014b5cd59308a41ed40300a92aaee58945b',
      'label' => 'xyabr.php',
    ),
    178 => 
    array (
      'sha256' => '350e02fac71344e246e2115e12fda75e99c9b0034e5e2301f01411c730dd45e2',
      'label' => 'init.partly.php',
    ),
    179 => 
    array (
      'sha256' => 'c56c1780b0bac8e087bf178640c65d5e70a088437a3058a36192902a04fcef28',
      'label' => 'cygtnarxm.php',
    ),
    180 => 
    array (
      'sha256' => '21fdf7067bd615f136e4077cd21bd48aca823f27d20356af2bdde3e77352d579',
      'label' => 'ctndtu.php',
    ),
    181 => 
    array (
      'sha256' => '1453eec49f30b690360d58a431691caababdbd098c2316ed81365500a3feb8cb',
      'label' => 'wgrapqym.php',
    ),
    182 => 
    array (
      'sha256' => 'd2b5ebc06a7d2706ea97c487d1987c36bbf0f8e047ce0a062d82bcbc905700ba',
      'label' => 'zyxvxn.php',
    ),
    183 => 
    array (
      'sha256' => '5320bbcabbeab46edf9241989526ba384bfc52ea6bc63d1e2695fb980208694b',
      'label' => 'pdmfy.php',
    ),
    184 => 
    array (
      'sha256' => '9a7f89165ea17a5a44fbaa51126ae38644483420ca8b579722aaa1b651041103',
      'label' => 'decsfh.php',
    ),
    185 => 
    array (
      'sha256' => 'c369c1323a831ae3bb89e0f1df5a0456345a38fafbd9e47561ed2b0cbc812cb4',
      'label' => 'uanxugf.php',
    ),
    186 => 
    array (
      'sha256' => '6b6282e20d54d33d0690b489cf2750c5ecf90f42f04585aa64ceff299cedf75e',
      'label' => 'cgunztf.php',
    ),
    187 => 
    array (
      'sha256' => '87182a894b6084eeaae0bef92faa7157c24f0ef8003e2b1ac3cb93a4c75d1a81',
      'label' => 'tydycwvwxt.php',
    ),
    188 => 
    array (
      'sha256' => '1be9a76339b88a142ade5f64b65ec997cc3078fab8c61e2ab476992801fb131e',
      'label' => 'kvmfqzdmqx.php',
    ),
    189 => 
    array (
      'sha256' => '45194baf4dd46c2ae3f7ca59c12a3c6eb7b164835680dec1b2e17d3c77fdcc8e',
      'label' => 'axudcay.php',
    ),
    190 => 
    array (
      'sha256' => 'ca6d518dc6995133c2f94bf140b9d8b962aeabfe9c04bb83cd848c41812a3ccc',
      'label' => 'vsusgzzmq.php',
    ),
    191 => 
    array (
      'sha256' => '7e576753c7dd2de39d26533800ae954909afb7a0d5dd570b2989bfbac62a95b7',
      'label' => 'tellafriend.php',
    ),
    192 => 
    array (
      'sha256' => '1d2047904a44406e71b7ba5dff5848b49f5cc0ff20f82253968da43dfa861e25',
      'label' => 'mhffnts.php',
    ),
    193 => 
    array (
      'sha256' => 'c6a29c64abadaac862b1949926c27d6e30e202240430d5ea6ecc5a161aefdc7b',
      'label' => 'search_config.php',
    ),
    194 => 
    array (
      'sha256' => 'deeac6c7502c16081f182b4f6450cc78c538c4eba2da1f85dd82b3ca9251b64b',
      'label' => 'sad_api.php',
    ),
    195 => 
    array (
      'sha256' => 'e0699006870739791f14010bdb42e8a0779c04e37e7b5a7adbeb89df1250ac40',
      'label' => 'vfpcvbaa.php',
    ),
    196 => 
    array (
      'sha256' => '8becd0a1376110cf6abcb92782aabe47a73e3fafb591f4498080dbb65040d41b',
      'label' => 'mcesy.php',
    ),
    197 => 
    array (
      'sha256' => '79380718242c97ca6e8f9cde75b084a37014da658c6ca13b222136f0540838b0',
      'label' => 'sdgtkt.php',
    ),
    198 => 
    array (
      'sha256' => 'cd0cba3f85f7e1bf27ef6ab88b594adbb17b2926791dce4cd39714ce3be8d2b7',
      'label' => 'fgtaekbqnz.php',
    ),
    199 => 
    array (
      'sha256' => '39ec89cda6787e0b4c406bb7fe39942e41c40298951c78283195bdf2bb575b38',
      'label' => 'sczdtywqzk.php',
    ),
    200 => 
    array (
      'sha256' => '68a57dd759a1a99df6e25b4d9aeedafae547f684a1ef6590ee3aaea8da555f51',
      'label' => 'cmhzduss.php',
    ),
    201 => 
    array (
      'sha256' => 'cd48594628f1dc08043a7a51bc7b546c640af485454be1c878f384e2585970ef',
      'label' => 'ssnpusc.php',
    ),
    202 => 
    array (
      'sha256' => '6dfd63d706778bf5797b4cd553f70821b9a20dc1db43d6249a424f6198613c3e',
      'label' => 'bapfxdk.php',
    ),
    203 => 
    array (
      'sha256' => '23fc056e5729075f5f027c06c813e0f0c32cebe6d8ebc29c9c16806f6ea819e4',
      'label' => 'hthyuwv.php',
    ),
    204 => 
    array (
      'sha256' => 'be6cc6e08f704e974051d72d32a7a21933e188f64a4832ff7a4985fda66ec2bd',
      'label' => 'wbyqhcpu.php',
    ),
    205 => 
    array (
      'sha256' => '44bff21bfca409b320d6d26c3febafa8fe61cad8fb6267d58bd3574e9830854e',
      'label' => 'sqwrh.php',
    ),
    206 => 
    array (
      'sha256' => '34ab3eca1ceb6dc022e6ece6d169a24832cb0c6df751f9e2ef5a9fd883561d11',
      'label' => 'scnbfrhnfs.php',
    ),
    207 => 
    array (
      'sha256' => '356071f1e9344b3d0a8d0ccca7e745857c02909ec3b3bc26abb033e59068dee9',
      'label' => 'gewmufv.php',
    ),
    208 => 
    array (
      'sha256' => '3fcf3676e089cdd458d09170d78d1b48900b0cb14a872099b13d03a8c4452349',
      'label' => 'tcntacc.php',
    ),
    209 => 
    array (
      'sha256' => '7e08302d3ce1382f0d2d9fa94003429329b3659f4d2a8824b09803edfbb2da34',
      'label' => 'gppwdp.php',
    ),
    210 => 
    array (
      'sha256' => 'e9f841cc2ca5d4f7c1232d6841561c53726ffac424bfe08948f912d68aed4931',
      'label' => 'loading.php',
    ),
    211 => 
    array (
      'sha256' => '4e75978d17b3d5cea3a488b06424fe4740db6430245d65b1f2063ad5a5e4dc17',
      'label' => 'signaler.php',
    ),
    212 => 
    array (
      'sha256' => 'ada738410266130f33e9df8d81c9d0ebe9627e4afaf8195c58ed85e29dd389ac',
      'label' => 'zvfqy.php',
    ),
    213 => 
    array (
      'sha256' => '55bf23169f368a78d49c3e51c6f034f88c17d1456152a8538479fde6a9087904',
      'label' => 'daxzrtkkfv.php',
    ),
    214 => 
    array (
      'sha256' => '55df061768f27ee81bc3a7ca9ac175f206175117d5b621c253da5af3bc188b5c',
      'label' => 'utumcuzxdm.php',
    ),
    215 => 
    array (
      'sha256' => '085709afb4a07154cd4f88dd49237801b1c2af25c9c1b56b22bcc1be46394dfd',
      'label' => 'bdzswgnhsb.php',
    ),
    216 => 
    array (
      'sha256' => 'e2c002330f7efeca72646496a923f46b550e1b1b65c4b340d9fa1faa8791555c',
      'label' => 'xtbwmm.php',
    ),
    217 => 
    array (
      'sha256' => 'c48a101e4af80cf678f9584d407e48be5dec5dff1e21001410e074afdf228e0e',
      'label' => 'ynnnaap.php',
    ),
    218 => 
    array (
      'sha256' => 'd48e3925ec2948a806195de808d09f3cada794b93087a9370d8ff8a8945a21ff',
      'label' => 'hmeychwq.php',
    ),
    219 => 
    array (
      'sha256' => '213c1471ec138a65b0ae20a1003de35dbf4504c74e9bd9dce0c4242cbc1d5870',
      'label' => 'gxkddvcb.php',
    ),
    220 => 
    array (
      'sha256' => '0a447e552c1842d1392e42bb84a7f814bb33b280cce7804505fe41d32e88656f',
      'label' => 'asgvyx.php',
    ),
    221 => 
    array (
      'sha256' => '01e83474ce38537d458d5d9fd1ca72d7bf6408ffb87bd284f22ed995b7b744e7',
      'label' => 'zgngxywzc.php',
    ),
    222 => 
    array (
      'sha256' => '006a2c2cd4759d52261280aea79aa326d525bcde1d58588e74f505831599af64',
      'label' => 'fkzkab.php',
    ),
    223 => 
    array (
      'sha256' => 'cc4e57b69676244593178332c71d577a33b704bd532574570832afb6afc6dc3e',
      'label' => 'webservice.php',
    ),
    224 => 
    array (
      'sha256' => '26a598d81988c85dcd4a3100bc1dacc3a8cc3e7f3924dd0576e7e0466b982f64',
      'label' => 'config.angle.php',
    ),
    225 => 
    array (
      'sha256' => '74b6009a8f406112b26e25231270d7743b21fd9d87c314e58c4c52bf58cd09b4',
      'label' => 'nfzsdbvshm.php',
    ),
    226 => 
    array (
      'sha256' => 'e70dfadcff1b67d11673de1871584adce6a05da72a404a86e3ddbe48b3654fab',
      'label' => 'ccecgappu.php',
    ),
    227 => 
    array (
      'sha256' => 'fc7018ad8ad28b6780d48a6f3cf6dfdcbfaeea26f9399ce7226ec17995eebc27',
      'label' => 'contactthanks.php',
    ),
    228 => 
    array (
      'sha256' => '43aa7f2d1bf188f8a73c0ea940f281449735eca38f898232cacb55ecd957ea68',
      'label' => 'nstkmmpvg.php',
    ),
    229 => 
    array (
      'sha256' => '8bb216607ec67a42737ed086272049b47306b3d17db42b10093bf31876f70296',
      'label' => 'pegsk.php',
    ),
    230 => 
    array (
      'sha256' => 'b05f3e75b4ed549aa8abb7113271747fa7ddd51610eeb24eb6ed77fe63006fdf',
      'label' => 'ngnsexvt.php',
    ),
    231 => 
    array (
      'sha256' => 'c78aa7bb86f836545650e7343f6071fd68dacd98e416358e9973af3552ec1ee8',
      'label' => 'qqpwtb.php',
    ),
    232 => 
    array (
      'sha256' => '792a262eec44e2858a999e60470101ed2eecba87897de8a966bf28b0da4d1242',
      'label' => 'refunds.php',
    ),
    233 => 
    array (
      'sha256' => '64ae998a2cbffb268f2fb1b646209f3da8dfccd1a81de1961d0742f653a131e5',
      'label' => 'wgrhubq.php',
    ),
    234 => 
    array (
      'sha256' => '174855debe234ed7116acd1eebe65254f12dbeef50a593b03f903771824de172',
      'label' => 'dxbha.php',
    ),
    235 => 
    array (
      'sha256' => '242d9d80e303459f14f77ff6f29cac6452df6fed35e2aecba244ecc529cdee6a',
      'label' => 'qefycpyt.php',
    ),
    236 => 
    array (
      'sha256' => 'db337410b8f7fb8179c6e4a51da214d0217e55750049476792b3c938bcccef9f',
      'label' => 'qxavevts.php',
    ),
    237 => 
    array (
      'sha256' => '044e923a363db653de428bb295f2389a93d28f8fd00d27827cedcfc1e4aea007',
      'label' => 'feed_embed.php',
    ),
    238 => 
    array (
      'sha256' => '02127c1a4ed76ac50471cfc4277352214fcf1bc1fdafa67985ae556b72a72c50',
      'label' => 'eapzdv.php',
    ),
    239 => 
    array (
      'sha256' => '7fbeab834478c4a40ac253f229a25c1d265bd29d79fb3bde8a027098ed2600b2',
      'label' => 'ccgwnsdnm.php',
    ),
    240 => 
    array (
      'sha256' => 'f3e8c5ba51c3cea0ba84b633fcd3917db8f063a259230a6d75e2d244d2b6ab80',
      'label' => 'yppafbbkfr.php',
    ),
    241 => 
    array (
      'sha256' => '4eb80c418965821c24789f236a11f06040fc7e7aaa4e624e682ff17231cd2502',
      'label' => 'vvabtpnryu.php',
    ),
    242 => 
    array (
      'sha256' => '4e92b66aa89eed81612c7e916f60f8862961e5cd08716df0a1f280b276cebdeb',
      'label' => 'uuwhs.php',
    ),
    243 => 
    array (
      'sha256' => 'ae8794cba4ae328a14c0a851dd0af28fd4459b792c125ac4d6e1f83a1f5f93e2',
      'label' => 'xkuxczerr.php',
    ),
    244 => 
    array (
      'sha256' => 'd3b1cd176dc5d7ef722f122322481f531fab9f2969a17d4e9158a903d29788a2',
      'label' => 'xvcggzm.php',
    ),
    245 => 
    array (
      'sha256' => '14d9ce41880e8ab47f0211aaefa0e9ffe8e99009da7d9ba9b6947612593cf023',
      'label' => 'hqwkr.php',
    ),
    246 => 
    array (
      'sha256' => '1f8f9db868b8b3be10b60474516c54c390c35e7fd046b9ccccc4f37d06a3b5d7',
      'label' => 'dtusd.php',
    ),
    247 => 
    array (
      'sha256' => '81790fabb5ce2150fdad1f5e94ca33592ca2c31be369edb2a48a4f1da68beda5',
      'label' => 'dxhpcx.php',
    ),
    248 => 
    array (
      'sha256' => 'fadec56ca53dc0d258c61f2c9b026bdb906b079052435ecb636e519e902428cb',
      'label' => 'ktfxxq.php',
    ),
    249 => 
    array (
      'sha256' => 'd66e16ed6848e7b91066c28ad3d987a0498b2f813cbbb33ac2c152007f7942ab',
      'label' => 'wp-settings.php',
    ),
    250 => 
    array (
      'sha256' => '425ced74abf21b5f5a010e6b1aeff353697ce606d1492ae9b2b73f82f7bb1b01',
      'label' => 'currency.php',
    ),
    251 => 
    array (
      'sha256' => '51446c53363e7a8e41a8db129eb1359b8ae9e906800c232ddb0f084324d041ee',
      'label' => 'wbeunbbn.php',
    ),
    252 => 
    array (
      'sha256' => 'a13954853b1101f805cf10edf57cc03994529e28ccde247bb2ab26fd578ebfe7',
      'label' => 'xmlrpc.php',
    ),
    253 => 
    array (
      'sha256' => 'c86a7fbf06d20dd30853bd7cae311d8b15b2cb67edf093f20312fa9514ed3968',
      'label' => 'nbzkneshq.php',
    ),
    254 => 
    array (
      'sha256' => '4a60a754bce66e7d7c8759e97b34ba1e107e4ef2765a87212cf6d25a8fb9c7b8',
      'label' => 'waqfyqhwz.php',
    ),
    255 => 
    array (
      'sha256' => '292c4674bd2bbbf5ea6aa4c778233ba54d0e2ea106f5f69071f086e3ce986939',
      'label' => 'ywcqd.php',
    ),
    256 => 
    array (
      'sha256' => 'cd521b685839f16639f9ce5df9606dc88e24a436debc4fe99e336e65d1dab357',
      'label' => 'staff-login.php',
    ),
    257 => 
    array (
      'sha256' => '9883c6f43c11cc40c07846f1847724694e261ab7c4a9114113f33ebc31efd539',
      'label' => 'futrpbgp.php',
    ),
    258 => 
    array (
      'sha256' => 'c9a262754454915e6393dbb072bf4f0ce49121f83da87fa3da4cb798dc24a6e5',
      'label' => 'site_login.php',
    ),
    259 => 
    array (
      'sha256' => 'edcae89960698a8d6488ba5e3653c6e87e1114234b27d7d5407ed30696dbd0a1',
      'label' => 'rhqevyyuky.php',
    ),
    260 => 
    array (
      'sha256' => '7666c800e0a5d5119822782fcb30712a33c3d488e55c4fa28f89981e7ffa2997',
      'label' => 'wp-trackback.php',
    ),
    261 => 
    array (
      'sha256' => '17ed585a873a1698f194ebe42cafd9675920050f3621c5bd444c925710957c75',
      'label' => 'gxsudtkhb.php',
    ),
    262 => 
    array (
      'sha256' => 'fc68576c8e11cc7167979188ed6d1b5cd72658afe2e4d3eb7b21a2e8096fb96b',
      'label' => 'fvktwpdpby.php',
    ),
    263 => 
    array (
      'sha256' => '11b853ca4753993b49525c265fc40fd855ec4be2dcf274437ba6b6f76d301989',
      'label' => 'autosuggest.php',
    ),
    264 => 
    array (
      'sha256' => '2ddf7b969fc69c41262715940632bf7d1d757592e296cd1fe1cd7af2fe087ef1',
      'label' => 'bekvxw.php',
    ),
    265 => 
    array (
      'sha256' => '4e1ec4594160baa12eca7fac65ad6c337c430f588158eecb1d8ec4b532396613',
      'label' => 'foreign.init.php',
    ),
    266 => 
    array (
      'sha256' => '249eee9dd1597fa6255415fc36c68a465e7bbf223a3bbe339ad52264dfed906a',
      'label' => 'gxwygf.php',
    ),
    267 => 
    array (
      'sha256' => 'a02c2f1019f81230992ea6128c1e570e55e7b9cbf7df46fb7064212502188090',
      'label' => 'loose_lib.php',
    ),
    268 => 
    array (
      'sha256' => '2583e0704b21678cb135caf30cd80440b7433217ff341f5c0fa15d2af3a67160',
      'label' => 'pxuzzufuhx.php',
    ),
    269 => 
    array (
      'sha256' => '876bdf685f36695df65145661820c094ab63f86290f14a3295c80978490a86ae',
      'label' => 'fqyrthe.php',
    ),
    270 => 
    array (
      'sha256' => 'a7ef793bf6e21167f1d39d5158864a40c2f6b96f6e20f2bc023ab01bb80a0a7a',
      'label' => 'cybwqgfkgu.php',
    ),
    271 => 
    array (
      'sha256' => '51b5da32fc7059f8614777146214df326a33ad28f24c4c516224ff3160984ed7',
      'label' => 'mzazrfrwef.php',
    ),
    272 => 
    array (
      'sha256' => '60f9518c4abc43ee5452a09d5721a4f548cd2d06471b2528009fb2daadb3aceb',
      'label' => 'rrdvzquqk.php',
    ),
    273 => 
    array (
      'sha256' => 'd461e773aa297678bd5588747fc89e4d814032a201f93adbb7e4b2ca6079e11e',
      'label' => 'conversationLib.php',
    ),
    274 => 
    array (
      'sha256' => 'a877c73d1526f16a0b2563deb7d742b915e946b47510fc13a16ee2130847a44f',
      'label' => 'hswrtw.php',
    ),
    275 => 
    array (
      'sha256' => '36d987b85447da8cb4a2574c082a96db30dbac3c9f7b429915f7e027ac5b9189',
      'label' => 'cgtcrvc.php',
    ),
    276 => 
    array (
      'sha256' => 'ce0b3c185d83fc9378712a9d1cdeb25c2ac79ec12b334dfcec3027bf7ceea8c1',
      'label' => 'security.php',
    ),
    277 => 
    array (
      'sha256' => '38f2fa04be62f0b95d724b6f2f7e7b4997e953d42e8fba96c51c62761adb55ea',
      'label' => 'xwztrhyhry.php',
    ),
    278 => 
    array (
      'sha256' => '1f30c2cb5b8be0da8ddb5bb2b7c526107f979733c11779a759fa5e1b0eb85e1f',
      'label' => 'zgqhnf.php',
    ),
    279 => 
    array (
      'sha256' => 'e4325ae8e238b7de6e203558f5a1d978b3fcbc14110ed2e7af91eba5045d761d',
      'label' => 'vxzzb.php',
    ),
    280 => 
    array (
      'sha256' => '4b8cda0e0e847f21faf376a0f7fbec9c386333aab28802cb7f78600d8dc7f763',
      'label' => 'ahafuyfqk.php',
    ),
    281 => 
    array (
      'sha256' => 'b56ef6d0609b2dd0bbea1d14a6729645831f94d4132da900cbbbb0e3725c932f',
      'label' => 'fzdpmsxf.php',
    ),
    282 => 
    array (
      'sha256' => '916989109a9c4962fe412ba7eee688f105d7b74c3a60c5ee092e7a8ea7d5fad0',
      'label' => 'bfbxpg.php',
    ),
    283 => 
    array (
      'sha256' => 'b27b2bb42d56c522210c3e7a1a84b5ef8215f8e784c62ef6c5c0dbe103d8cddf',
      'label' => 'nofollow.php',
    ),
    284 => 
    array (
      'sha256' => '879922997a2a615687a962fc1be54401fb09f9de8589a282e523b09f833e6a72',
      'label' => 'umugznbbq.php',
    ),
    285 => 
    array (
      'sha256' => 'c7aef6ba58abe68b21d1d80df76860a2d7f0304cc9a80325435afafd9e0bc803',
      'label' => 'config.immediately.php',
    ),
    286 => 
    array (
      'sha256' => '8dcc48bdb213b0d08f3783e72b93311b7a7a62dfeeb069080ce5cb85f32e6742',
      'label' => 'order_result.php',
    ),
    287 => 
    array (
      'sha256' => '355870a2c3bf5a2fdbe7f610da3811e2cc31dace7300c7386b40f858b96bbb9d',
      'label' => 'gxfywfm.php',
    ),
    288 => 
    array (
      'sha256' => 'f8f3aca9df00e2c6b6621feae2db0760ea0d650bec9d4de012bc9857a081030f',
      'label' => 'xwvhgp.php',
    ),
    289 => 
    array (
      'sha256' => '3546dac50f6e4f71eb1f140baafdcadf2e3180d9f605782b7cd788a651d56a75',
      'label' => 'sang.lib.php',
    ),
    290 => 
    array (
      'sha256' => '8255b34ac6fbbfe549b1788829f6935f1dadb2cab062446d5378afb4fe26d779',
      'label' => 'confirm.php',
    ),
    291 => 
    array (
      'sha256' => '887706efb3e203f7d73253797f1cc717ddca8fa4669b2322a137e4b7d6aa9ae4',
      'label' => 'whwsw.php',
    ),
    292 => 
    array (
      'sha256' => '38f2ef7d75295f9c22340afc12987459a6a5a5059e17644d99121c44ff181ff9',
      'label' => 'hsphd.php',
    ),
    293 => 
    array (
      'sha256' => '2c57ad4c4d9df917b02e35708fbe2fe87244e57f1e77dcbe98e0f1a9e600be47',
      'label' => 'tydsbqqdsn.php',
    ),
    294 => 
    array (
      'sha256' => 'b60d5c7b1960fbe5ac345ded7a9b38c3809dfee2c781256ecc83b4ca7503831d',
      'label' => 'cncbxzsqk.php',
    ),
    295 => 
    array (
      'sha256' => 'a56c3f50ebc99e3f284076e9e0c7fc504b54ce63194d8c2c69a5a10f85bc940a',
      'label' => 'qedpsr.php',
    ),
    296 => 
    array (
      'sha256' => 'ceca8103e9d2a50c32d04d835a6870867eb278d7e60e9033793f5b51be519d76',
      'label' => 'bbewkax.php',
    ),
    297 => 
    array (
      'sha256' => 'ea1930f8947972ff78739946fc9fdde55935c696e8fbbb74ec58ef666da61888',
      'label' => 'bdabqbq.php',
    ),
    298 => 
    array (
      'sha256' => '9805ec9de68b10378f92fd2dceb3ca10bc1e0065c071a335e7fe9ff877750418',
      'label' => 'zvsachbg.php',
    ),
    299 => 
    array (
      'sha256' => 'eed936e4c37022295f5c64191539d57e38be4c3499adffe9c597d1a32734303e',
      'label' => 'udkpprf.php',
    ),
    300 => 
    array (
      'sha256' => 'cfb8f9cc9d5f13e715117d21f3d67c163e6fd9d90865049d37249338d84d997c',
      'label' => 'site_search.php',
    ),
    301 => 
    array (
      'sha256' => '0c38b689a34f65bf96e5bfa441a574f20b59c7d1933207353288d16ee94b3f4e',
      'label' => 'init.tongue.php',
    ),
    302 => 
    array (
      'sha256' => '881e27ac7bbb8b60a8ad6ef3520df36ee134c966e435f5e6304fcfefbecbdf93',
      'label' => 'xbwnybxet.php',
    ),
    303 => 
    array (
      'sha256' => 'd55b8a415c7226409e332b1ebc4f23467ddf139ac38de60b0dadc27ae08a8aed',
      'label' => 'sesaqvnpt.php',
    ),
    304 => 
    array (
      'sha256' => '625682ab3aba499b6210f5ae085d170a7d4739b1c9dc35868346877bafc2a607',
      'label' => 'dgvsveaahf.php',
    ),
    305 => 
    array (
      'sha256' => 'b09f43ca3471f8cfa03a2720bef3975e2b9d9ba0ce0fcdea1054a5541ec9ffbf',
      'label' => 'park.inc.php',
    ),
    306 => 
    array (
      'sha256' => 'a778a74214fa7da1988ec69c1bed814328bf9226c7f820583a5a479e3fc52438',
      'label' => 'uayqrgwg.php',
    ),
    307 => 
    array (
      'sha256' => '12b698542e84c82db655cfde2f33e6f1cc876837415e03a79cdad5198badac22',
      'label' => 'vhstdx.php',
    ),
    308 => 
    array (
      'sha256' => '8fa457e377e1ec304897e8a4147d8be88d57767012e5b3cc065d20d6e2e166d5',
      'label' => 'zbvmdhak.php',
    ),
    309 => 
    array (
      'sha256' => '79097cc8fa490096f20a2ea05626c21b9e8d9a4725ef66b1d6f29409d5872983',
      'label' => 'mpmfdxv.php',
    ),
    310 => 
    array (
      'sha256' => 'c00b2fe353dc041969b5675f8171928ebbd8cb20effb7b47838a039f4f539980',
      'label' => 'cnubzsrda.php',
    ),
    311 => 
    array (
      'sha256' => 'b5b2f6cb8b97f138f842db368418b14b3c09c57027285e215adad3dee1c32b4f',
      'label' => 'mxkknb.php',
    ),
    312 => 
    array (
      'sha256' => '0696b5f6a947058891eaa30b93de1c83c7a65b4cc8885f9f0ade0ffeff054e38',
      'label' => 'sendtomobile.php',
    ),
    313 => 
    array (
      'sha256' => '35b2dd492a5ff171c91ab1d37d528fa8e02b9a9d79d82a3e3168abee43baf579',
      'label' => 'rsatgvk.php',
    ),
    314 => 
    array (
      'sha256' => '3fd3643f38dbd816b0d114285b7f5f43109f489ac85dee78bfd412c123fcc401',
      'label' => 'vtbnzckwy.php',
    ),
    315 => 
    array (
      'sha256' => 'a0093f85c566e79a26dd7ac98533bbcd9f1da88a08449771898602e2ee2cbe0b',
      'label' => 'class.hurry.php',
    ),
    316 => 
    array (
      'sha256' => 'bd8c293f61f9c50fe4f253fa0128ee1f1b39d43a2b81f6c03e38d2a3f545e92d',
      'label' => 'nwbypzkz.php',
    ),
    317 => 
    array (
      'sha256' => '1023000a2b3fc4736ece46a243d0e2dbf8459411a84a895056a78678a768ea84',
      'label' => 'zksncxyt.php',
    ),
    318 => 
    array (
      'sha256' => '85b2450fd46a70ff9c844942d52740d0f7f71aaf34d25973b5fc2df6d9666ed2',
      'label' => 'ayznpw.php',
    ),
    319 => 
    array (
      'sha256' => 'c8bfec35a7e250d0451da30716e40ebc72df4df45c8e250872b472b5914edaf2',
      'label' => 'dqmynz.php',
    ),
    320 => 
    array (
      'sha256' => '765ace53e75876096ba700d0e5fedfa3426ada5d233a264b0ed1900d58c86364',
      'label' => 'gtyhmf.php',
    ),
    321 => 
    array (
      'sha256' => '4785f6e49bbbb0feb6ea9a4ed3861c8833ff83d41dd035d287b7904138642dec',
      'label' => 'hhtawxa.php',
    ),
    322 => 
    array (
      'sha256' => '7ec8d289d8557f66fbf2d09d12b6dc29af44f295dfb50d5b31781d3cc360fce7',
      'label' => 'my-theaters.php',
    ),
    323 => 
    array (
      'sha256' => '98ea2bad588ab91ac01577b7c64380f4503453c4dbd1369e01fe9d7ffe2089f9',
      'label' => 'ezmfv.php',
    ),
    324 => 
    array (
      'sha256' => 'c2c7bd1b67d2e2cc8f69671a9335b7073d045675efc366fc2b29f8d2413edb63',
      'label' => 'bbfpvecptt.php',
    ),
    325 => 
    array (
      'sha256' => '61d34866155b3ceeb695e49fad7f636e9d5a802574cde55bcc2276e6c67b792a',
      'label' => 'moderate.php',
    ),
    326 => 
    array (
      'sha256' => '7b3398ddaf51b0332edd71fa42f2fc5158a4dbaa2058ce43e11cb31bcf5b35e8',
      'label' => 'aepvm.php',
    ),
    327 => 
    array (
      'sha256' => '901dba2710aebe9ba0eb59775b84a26b3613bdf8a1ffc69685f23377791def6a',
      'label' => 'write-review.php',
    ),
    328 => 
    array (
      'sha256' => 'bf6b85e4dea269967f30d57f2ec50e85aeabf0575492bcf36194555456f5b059',
      'label' => 'smazwtndh.php',
    ),
    329 => 
    array (
      'sha256' => '17d95528831a761da0ee787070dc5212146a50085f74be38ebeb113cb745bee9',
      'label' => 'rmykhkvq.php',
    ),
    330 => 
    array (
      'sha256' => 'e6191819522c7dccffd33c77ec1b5630fd27f6507eb9d6ae797be02cd7688aab',
      'label' => 'zmtqphbz.php',
    ),
    331 => 
    array (
      'sha256' => '82097ba04874e461c0d2370160fe527bec0f9da395751d6190f2d04f8b13124d',
      'label' => 'user_login.php',
    ),
    332 => 
    array (
      'sha256' => 'edd20768886250504996eca10d64884eed28e002becbe0453562a59a8fa90648',
      'label' => 'bprfkfb.php',
    ),
    333 => 
    array (
      'sha256' => '68405dc19e4796c58345cc4bdad17870e55427cd0b7b412db81a5ca622679490',
      'label' => 'uxgbnd.php',
    ),
    334 => 
    array (
      'sha256' => '6dac19a9705c5aa3156d0d78fa8a2f654920109017ec29128a135000fcfb4521',
      'label' => 'amarsdyvgy.php',
    ),
    335 => 
    array (
      'sha256' => '8e8c6bc0455bf92c191c5634517fb498b36a22f1e843a6dea642afa3331038c9',
      'label' => 'vzbkpp.php',
    ),
    336 => 
    array (
      'sha256' => 'a499f07ce53d6672d4663980f3be09226aa68fbade4d5c1bdc6d5006f4d5d02f',
      'label' => 'goods_script.php',
    ),
    337 => 
    array (
      'sha256' => '32624f60f6032f542a544edbeb94c70ac31b9174b68afc3b32b53d975841d9f6',
      'label' => 'uucgnd.php',
    ),
    338 => 
    array (
      'sha256' => 'ef1922a6fe87b3e92df2850c6f50b5a7bae63826bc93a7d6155cfb37add2c8b4',
      'label' => 'kamnhbdhub.php',
    ),
    339 => 
    array (
      'sha256' => '2047fd02f45d6597ea364a1ddf9006b95061870de7f8cba8222cbb2b9ae276cf',
      'label' => 'orderterms.php',
    ),
    340 => 
    array (
      'sha256' => '4a60314bc813807ad3d4ea572d328f1d909ccc194806745ab690fa7e8b9c6085',
      'label' => 'gmveb.php',
    ),
    341 => 
    array (
      'sha256' => 'bcdf3d30faedd560ea0fd243957eca57c06f89f6a5be2fb55fd364568350528b',
      'label' => 'nbuzz.php',
    ),
    342 => 
    array (
      'sha256' => '49620f42e1695e157b1f2c2c2bbfdee6468d813bf59f26b08d521898cda48810',
      'label' => 'aasfmfgnk.php',
    ),
    343 => 
    array (
      'sha256' => '3ef909edd6a407c373d68e24e60878cc58130422f851cbfdfcd4f1931b6549b9',
      'label' => 'ryafwh.php',
    ),
    344 => 
    array (
      'sha256' => 'ee9d01d5a318552ca5b1de8f3197495c8e15227e6de8591d31500573f9736c4c',
      'label' => 'vxtngqy.php',
    ),
    345 => 
    array (
      'sha256' => '5222081ff2edf87303f57b2403887efe9dc9132d48dd366671a297362f26d8f1',
      'label' => 'atwnctuw.php',
    ),
    346 => 
    array (
      'sha256' => '56e5cbeb7720cfed52c071c9b41aefb04af26ace4bc30e25b46df40e51f7b221',
      'label' => 'ebwgesdbdd.php',
    ),
    347 => 
    array (
      'sha256' => '9b980cfec55aaf69b22c948f8d90bb08a7480efb46504b8e368dbb35a27e19d3',
      'label' => 'encedk.php',
    ),
    348 => 
    array (
      'sha256' => 'b85150178616be9abc39c9d8378eddb35fc4e12f81c80d06db044044d0f5d6d5',
      'label' => 'raqcqpsn.php',
    ),
    349 => 
    array (
      'sha256' => 'bd81bad13a633c516ca9f476c84684aeb28c525dfd82f7437c4fa454ae56df6f',
      'label' => 'rsgxwyvbv.php',
    ),
    350 => 
    array (
      'sha256' => 'c45ed9c6ec7686f2062076cfe7f4fc54b321480ed0f11606e2a5e8234e782547',
      'label' => 'vmxfc.php',
    ),
    351 => 
    array (
      'sha256' => '0760b6c060ae48a3fdf6e8e60a19956b85de4e30a1096c19764ca241bbb10d0a',
      'label' => 'bvzhewkay.php',
    ),
    352 => 
    array (
      'sha256' => '473ada949956dddc0fd6e81c5761b6c6e90b9da35fe11bd4f4fba0ac153d82b5',
      'label' => 'vgxzh.php',
    ),
    353 => 
    array (
      'sha256' => '8ff125dd2f8e6020e3bd630b46c76532830451fa839fcc0898ff5a5d10efdbab',
      'label' => 'function.card.php',
    ),
    354 => 
    array (
      'sha256' => '482f896dd2682d2fdf61fbb8ebee58ff15b53bbb96a2739e2c38624dd4eca6a0',
      'label' => 'api.suggest.php',
    ),
    355 => 
    array (
      'sha256' => '867853fc024e49144bcbb65bc6204acb96e886e9cf2a019aabe59af2b98ffb2f',
      'label' => 'gwnubcbmmf.php',
    ),
    356 => 
    array (
      'sha256' => '700b3d8b20262369050784be1fadfd8446fcbc6684cf990112974205f8020762',
      'label' => 'ukcnwam.php',
    ),
    357 => 
    array (
      'sha256' => 'f466cebb01fd5f55f004a8a1afed983a5a7f0bd07940fe037f9060e88cb3189e',
      'label' => 'rtyzrk.php',
    ),
    358 => 
    array (
      'sha256' => '4cf617afe8da58272d64348fb037cca1dd3a204d464b3c3df1b51421196ddfdb',
      'label' => 'wevtbhrheg.php',
    ),
    359 => 
    array (
      'sha256' => '240e7c58fccd2fa931744aefccedb4f76ec476061a9f3bdbfe30d3beecdc6e08',
      'label' => 'hkkucsuv.php',
    ),
    360 => 
    array (
      'sha256' => '6defad69ef4be4aa0484130325833278cf31beb484dbca92fa43e6eb63c29f1d',
      'label' => 'index.php-6defad69ef4b',
    ),
    361 => 
    array (
      'sha256' => '71a2417f0868c4466ee462b4a0abf4bd7e185e15bc332c777f0efa1c572504c6',
      'label' => 'akyzenkguu.php',
    ),
    362 => 
    array (
      'sha256' => '56088ff9e2d4417fe205e3f09db422f0f6b4d5c57ac67c0f866f9aafe9bff315',
      'label' => 'enadpckpz.php',
    ),
    363 => 
    array (
      'sha256' => 'e8bc46a39e783eb8846311c8fa0d222728cf569f922cd6740615c04d592c078d',
      'label' => 'erqzf.php',
    ),
    364 => 
    array (
      'sha256' => '298a85ea65e46f2a49a350b78d2a691e6d9b10dbc53cbe68f2276e73019f286f',
      'label' => 'xzdbexpsp.php',
    ),
    365 => 
    array (
      'sha256' => 'e580aa4e03acafeb9d7fc3f70fe7dc8890de59082d9d60075a9c3d1c8299f753',
      'label' => 'qtrcy.php',
    ),
    366 => 
    array (
      'sha256' => 'b84446a8c56ffe9b546e30146ec903241db021115574322d3a3a24d8552505cc',
      'label' => 'rfqzkt.php',
    ),
    367 => 
    array (
      'sha256' => '204d6f07573b6117d9e652e0a9f17d9e38305b57053ca8d0fa1b7e4934a6fe6a',
      'label' => 'tkfgwtc.php',
    ),
    368 => 
    array (
      'sha256' => '126e567ba609a83fcbc9986be62a9a0c1f9d4f5437bcd136ed65d053961aa3a5',
      'label' => 'huvfhf.php',
    ),
    369 => 
    array (
      'sha256' => 'a2ee1d33bcb23c0500999761ded6d5756ce701e61958628e9e142ed4773b9136',
      'label' => 'acxzbhazkr.php',
    ),
    370 => 
    array (
      'sha256' => '5b698f74c303f6d71cb5886fa383f220c24586315949562d30d044f4497fe27a',
      'label' => 'htpuw.php',
    ),
    371 => 
    array (
      'sha256' => '400fc19d0c606edfd44d984386adab657cf97ef3eac0fe2dafc7e3bf6fd161c5',
      'label' => 'm5_checkout.php',
    ),
    372 => 
    array (
      'sha256' => '6e44a8c74af02afc91cf4f35e9afc2b9528c5eb17842405dd26e9b7e11735d1b',
      'label' => 'dsrddbmua.php',
    ),
    373 => 
    array (
      'sha256' => '88288180fc80ff256b86bf09a9feb35fbac4a4fbb1694668c0e06394e97af8e3',
      'label' => 'vsusn.php',
    ),
    374 => 
    array (
      'sha256' => 'e66490af33437d33d9629c0d98d30d00400d20145f87cf1976c90b1ac1b173aa',
      'label' => 'edcbtnz.php',
    ),
    375 => 
    array (
      'sha256' => '330ad1c782df282e73eec8309db3b68ecfb49851e630112190935e027bbb1e66',
      'label' => 'epprmeguf.php',
    ),
    376 => 
    array (
      'sha256' => '02c240c42b13df3431cb040bdf5a48d0f9e79f7ea8cec2e5cfe7620db7d9e955',
      'label' => 'details.php',
    ),
    377 => 
    array (
      'sha256' => 'db324ecb373b9b0d4cbad1e5109155670db311425bcac57850cddabd3f17096b',
      'label' => 'dzcgr.php',
    ),
    378 => 
    array (
      'sha256' => '4083491bce9fcc339a0a903a284edfbc51f5efb77f152f1951c69cec0ca94dd0',
      'label' => 'uzguqruh.php',
    ),
    379 => 
    array (
      'sha256' => 'ae9242295d28301f1f5190f7cd7cff37e988cedc1eafc26d79d8d0a30c2cb793',
      'label' => 'bsuewx.php',
    ),
    380 => 
    array (
      'sha256' => '9da3dbda7db7150a8fafbf2f31f0bf8d08ad7f41973dad8b58895202539b8303',
      'label' => 'gqmetgekzg.php',
    ),
    381 => 
    array (
      'sha256' => '7bea8762bbf4ffdcfc4ba0f4a1a1acc6c28dc8d0db800b4013934db19bc287ef',
      'label' => 'wnarhnbwzy.php',
    ),
    382 => 
    array (
      'sha256' => '2ac9e4f6634787b18778129b769899b565d174eec607e621ea08f50d5ed21289',
      'label' => 'tgecqnm.php',
    ),
    383 => 
    array (
      'sha256' => 'efc331506cfd3b9b7577489f6913f6611e0025cca6c8d758c759cfa6ef42ea50',
      'label' => 'servizi.php',
    ),
    384 => 
    array (
      'sha256' => '4981862f867c7d352a2fb11195ccbe38c61c82616b109545a788b3a6b6ffb691',
      'label' => 'nominate_topic.php',
    ),
    385 => 
    array (
      'sha256' => 'fdf41092765f8d745a979aa3e4a20a03b9d7dc631c3de27f45dbeafc0665ffd5',
      'label' => 'tqrvk.php',
    ),
    386 => 
    array (
      'sha256' => 'd81f2821c0bbcd003cea422aa0265c99857d004bb71f2fedff2bd1d594cd06c6',
      'label' => 'playlist.php',
    ),
    387 => 
    array (
      'sha256' => '74f1fe8d6c3e9001551180e7852b091e2cc7903e7c5f7e4f269443e69726a44d',
      'label' => 'vwdmn.php',
    ),
    388 => 
    array (
      'sha256' => '71aa36a096c5200054f6de90f316c2e100a322eae8ea02f7927bf4fecf43eb80',
      'label' => 'zaecrt.php',
    ),
    389 => 
    array (
      'sha256' => 'f8d555a489710eee6b31f98a4846c798611aee02c8eaeadf6322cc97146e71d2',
      'label' => 'clear_skin_1.php',
    ),
    390 => 
    array (
      'sha256' => 'de70f183c4858a71cebea288c598fa5b566d53e2508ec5a7916724322846f09a',
      'label' => 'aqacke.php',
    ),
    391 => 
    array (
      'sha256' => 'e471f5a74e02484cce36e54224472500f4e7a8ad872e492ee7e2983821dd63f2',
      'label' => 'egrqpz.php',
    ),
    392 => 
    array (
      'sha256' => '75ae234f4335f476564a41b4220d14ff2f2ca4fd0745b586cfd30d2efb980b2a',
      'label' => 'snmrtgbrmq.php',
    ),
    393 => 
    array (
      'sha256' => '072ba8a86c03bee635964ac7895edccc7c65fbc00927419c601e61e35d97aa7a',
      'label' => 'preview.php',
    ),
    394 => 
    array (
      'sha256' => 'ad1e4d47b8de036d6fdcdb91e3b73f20db6932f52ae4c9ddc1b29f2cf9325d64',
      'label' => 'qufnp.php',
    ),
    395 => 
    array (
      'sha256' => 'bd058c31d9c072076599f8dc005bdb73c12451d09e0f0352092751c8517383b6',
      'label' => 'atqerwu.php',
    ),
    396 => 
    array (
      'sha256' => '3818d9ff3f39172b47478dd9f98419c981808f70eead6eeeb9e4e67aebf30161',
      'label' => 'grnyzfhb.php',
    ),
    397 => 
    array (
      'sha256' => 'e15d438fc2ff7a002fafe398367b67f0c9bfee49b5ff687b04fb94b9d2883492',
      'label' => 'wp-signup.php',
    ),
    398 => 
    array (
      'sha256' => '6262871c6e35ffa05a147159c15d9ddadb55b5de93753b3067ae069059338107',
      'label' => 'vcwpu.php',
    ),
    399 => 
    array (
      'sha256' => '1c0cee02bd7aec61a149954cbaff727f44e09a6d0006c9646c995f27889c0ad6',
      'label' => 'ybeymvey.php',
    ),
    400 => 
    array (
      'sha256' => 'fd02f7f5820c0e529fa29ad3b19e15583e8b61f18e1a3bf03121184ecebe5788',
      'label' => 'abyxbhvhhg.php',
    ),
    401 => 
    array (
      'sha256' => '5530075df375d559c1d515e49446659d4e822550a9b4cb8b70472362368416dc',
      'label' => 'tehwhhmp.php',
    ),
    402 => 
    array (
      'sha256' => '862a23694e56c1028b456b9ae1916c7dede0bb4ce69b4813a8618f82aaf2b628',
      'label' => 'pugugwrt.php',
    ),
    403 => 
    array (
      'sha256' => 'bad9c5787aa7901bc9f9ccbc57ff5493f3d1df752c496ac80ae165994ba59d4e',
      'label' => 'refinesearch.php',
    ),
    404 => 
    array (
      'sha256' => '7d398c84d84c24e8f5c29b456d7d6cd1fb4fdb52329ed1289d8d0e06681163df',
      'label' => 'qqapr.php',
    ),
    405 => 
    array (
      'sha256' => '19743447b14e8953ca0d0e56c694a9ebd292a0c611ef974d3867b1864db852f0',
      'label' => 'hqbuf.php',
    ),
    406 => 
    array (
      'sha256' => '56aec29e4f4956865fd8190104cb5f4de8c3d2ed806a450c0a31dc2434ce045e',
      'label' => 'myzwfu.php',
    ),
    407 => 
    array (
      'sha256' => '44309276ec34c978965c6e938262596c55c637273b6e3bedba9ee7f98da66c2e',
      'label' => 'eedkbbx.php',
    ),
    408 => 
    array (
      'sha256' => 'f1da9d49ae35ded12a8192b9a06a81175fb0eb84cf3332462885e512db2f9640',
      'label' => 'acaaprfedf.php',
    ),
    409 => 
    array (
      'sha256' => '42c29a3c10898e899678236971f904282f9f97ca89a289fd388c049c6b797b70',
      'label' => 'hyacaksynu.php',
    ),
    410 => 
    array (
      'sha256' => 'e11f0e2f2f16184f7a6d3cdbf0afd8ac163c164b263dabbbca0ca86da7407095',
      'label' => 'akdyh.php',
    ),
    411 => 
    array (
      'sha256' => 'e2c35745a412d9f009b668a55355aa986adba9e2eeefb88e8e67f420d7ace591',
      'label' => 'svqqxr.php',
    ),
    412 => 
    array (
      'sha256' => '22e72a5de95c757547930621c883efa954ebbf2d63f393ca0910a25b947dbf01',
      'label' => 'ksncvvqd.php',
    ),
    413 => 
    array (
      'sha256' => 'dacc6728cca657390adbf0f3a3664aed800e918da9aa59a7057635a77c5cbe6d',
      'label' => 'mkapuc.php',
    ),
    414 => 
    array (
      'sha256' => '27272409bac93ad373404e9f816abbfd001e3e7b56c9847c2ea7263eeb51c78a',
      'label' => 'pprdpquv.php',
    ),
    415 => 
    array (
      'sha256' => '4d66bacbc4f03059e85c672de91b9ea6e618661558de5ccb2b390797f417c4c4',
      'label' => 'yfamxqrq.php',
    ),
    416 => 
    array (
      'sha256' => 'cb73581b93b8ff45a5fb01373be8589dd8660f5612b565696a9e9835f960beef',
      'label' => 'wuytv.php',
    ),
    417 => 
    array (
      'sha256' => 'ee1488882cde1c2dda03f45d3e8dc3ef300bdf5fc932fad2505125fc23987cd4',
      'label' => 'z1.php',
    ),
    418 => 
    array (
      'sha256' => 'b537218849e24a18b6a3c076a48b2026dbe96b3176aeda50de58219271037110',
      'label' => 'bgqvsz.php',
    ),
    419 => 
    array (
      'sha256' => 'b0deab47798ee9ac9d84bf78568cc42322a78835c9e7bcc514bc126ee54d4e3d',
      'label' => 'yypnw.php',
    ),
    420 => 
    array (
      'sha256' => '03906957f05c4b0b0d292e0e86afc84c0016caaa0cdf6a18ca261ad5c75d1b6f',
      'label' => 'wp-config.php',
    ),
    421 => 
    array (
      'sha256' => '14b6c60628b9c2cd80bf594935524694b2fae6a1590ab3b13b6d91c0212fde39',
      'label' => 'gvshuqzzh.php',
    ),
    422 => 
    array (
      'sha256' => '09fca3c896e6dff784973de8d830598012de2784d7f703e8acae9ebbca1ad37c',
      'label' => 'zxmpyt.php',
    ),
    423 => 
    array (
      'sha256' => 'd7f557212b7c9714ac88c5f414440fa4612da87444ec414199b2c9cad1bba6ac',
      'label' => 'svvbv.php',
    ),
    424 => 
    array (
      'sha256' => '7d8a73971e9c6e48c7524a45d021a5ffa6646ed4f21f42f8f90af72e4f38bf08',
      'label' => 'ccgmd.php',
    ),
    425 => 
    array (
      'sha256' => '53c958996e6e4eedce5310e119d25295829ee0bf53f423d39fcea33f342d0daf',
      'label' => 'qqrfwzd.php',
    ),
    426 => 
    array (
      'sha256' => 'c90492d369a26c37e4bf6e91981a73aaa84a6c79f188fe377a86b691bad36061',
      'label' => 'gptddzg.php',
    ),
    427 => 
    array (
      'sha256' => '3fd8516cc0b038764d9de500c0234f6b92748a6e1535e236e16d5263b7bd82f9',
      'label' => 'cewytm.php',
    ),
    428 => 
    array (
      'sha256' => '4b3764bd4c0209a5e6d4aaac311a57e8160e5c6535efd6c0218a88d1a9dd965f',
      'label' => 'ezwvs.php',
    ),
    429 => 
    array (
      'sha256' => '4ceaf1cb3cdfba83498eeeeacf0cccd6fb712d4f3d13c8c27997e576ad75b669',
      'label' => 'awrrrw.php',
    ),
    430 => 
    array (
      'sha256' => '7305106744bb2fc4426c8a75b091802773addc3beecc8cab38bfbe6ff7b9b57c',
      'label' => 'wvmztbk.php',
    ),
    431 => 
    array (
      'sha256' => '9757221121a5840bec689c354799bf2e3d9ea493c944cd75347eca83da141037',
      'label' => 'kygxgknsb.php',
    ),
    432 => 
    array (
      'sha256' => 'a4fb52b49d398043051fa2498e4b86352c4f6dda07fb5050dc8c0ad9c8ebee30',
      'label' => 'dmgdgr.php',
    ),
    433 => 
    array (
      'sha256' => 'a1bad89cbc04503862ee22a71ba333bc7f1d1864ac611d6a14ad0d287d9bcb46',
      'label' => 'cdweybd.php',
    ),
    434 => 
    array (
      'sha256' => 'ba788bb285834ed3994050e09e917b76cdacc0d913c49700b9bf7916461e2edf',
      'label' => 'qmemepgw.php',
    ),
    435 => 
    array (
      'sha256' => 'ab020ef1839df7359b9158482ac24c7d900042fa57808c2987df9480510cede0',
      'label' => 'tqpknxzbng.php',
    ),
    436 => 
    array (
      'sha256' => '7c7de672e5158acb0f82e6b6270a1c4f999e614d4c57b57e1f82c0960478c452',
      'label' => 'vnqwfcptmb.php',
    ),
    437 => 
    array (
      'sha256' => '598078d5ecd87b04381589206607ddd431bfed654b57f5f0fdbeedd47ab6e6aa',
      'label' => 'cnmfsppb.php',
    ),
    438 => 
    array (
      'sha256' => '4662d8373aa7e2d1a3c9e6d436ac7ff64942e5124f7cd8afc8a85e09d40c37b2',
      'label' => 'error-500.php',
    ),
    439 => 
    array (
      'sha256' => '0ba4da3bb0672009a3057881c1961af03fece11eccfa3188f7c28037c86dec7e',
      'label' => 'yvhnwzpn.php',
    ),
    440 => 
    array (
      'sha256' => 'cef26776e094dc3309764b2b6ee1a96b2df4c0b3e691e674ffa6743c775cae07',
      'label' => 'wnwacre.php',
    ),
    441 => 
    array (
      'sha256' => '1f4b165269c1512af780fc8199e63afb764b57ba0b2a73febeafec2a39e3b863',
      'label' => 'framnaxu.php',
    ),
    442 => 
    array (
      'sha256' => '7b8724386c3ecf2bbd73d2a846590c3619ed62aa224bd75ab483be72c18c5693',
      'label' => 'umauphmvwh.php',
    ),
    443 => 
    array (
      'sha256' => '03adc5cfaed4c827ed87a355341d7f3ed42d29bda6af64dd86fe180ab79889f6',
      'label' => 'publicidad.php',
    ),
    444 => 
    array (
      'sha256' => 'c8da7924268f78e89c4a959108e210b6322a050799c86985e27faf882ebb5f7a',
      'label' => 'youve_lib.php',
    ),
    445 => 
    array (
      'sha256' => 'b8c2a0fd0d95e3cafbaf4c364d23b6254aac511cf89160fc147a7612c02d4185',
      'label' => 'chain.func.php',
    ),
    446 => 
    array (
      'sha256' => '00b4918c258c77f0685a17b114c8a817bc11847a955dfc06ad8cdfe132e98b67',
      'label' => 'wchzgz.php',
    ),
    447 => 
    array (
      'sha256' => '5400785a97749facd5c4025c5f79b9fb1ad0604d394d5676d2b4749d78a43b60',
      'label' => 'xccsm.php',
    ),
    448 => 
    array (
      'sha256' => '1b4d1156c4fd763f84928001d06a3a03284c4942541b3d3085c8004611982ae4',
      'label' => 'wgwup.php',
    ),
    449 => 
    array (
      'sha256' => '2b9c544b2d71ba19d1d7827f06507236fb5d184ab5270112ce09e5c425ea6ad8',
      'label' => 'hngeh.php',
    ),
    450 => 
    array (
      'sha256' => '1def7e0cb1fa1679b57941a9941aaceb736f305fc6d009b58162b7f354e9a4d2',
      'label' => 'order2-dba.php',
    ),
    451 => 
    array (
      'sha256' => '14e67e0412d239a60c2e0f40de74e52f31ab9d2e0fb390dbf0482471976938c0',
      'label' => 'brsury.php',
    ),
    452 => 
    array (
      'sha256' => 'b477231903dd0e1e274b174ce14954ab5557ab29039bf1657159016a65e4b7a6',
      'label' => 'uugahav.php',
    ),
    453 => 
    array (
      'sha256' => 'ef33ddb266ec28c21a8127cb8c628b860866122244736d7783aadb25c37d02e7',
      'label' => 'hztwwxrwuw.php',
    ),
    454 => 
    array (
      'sha256' => '2f38d7c55829916544984b96ce0ba908146c6020e622e45e34c418a2bc120521',
      'label' => 'dqpbkac.php',
    ),
    455 => 
    array (
      'sha256' => '7535e8b2c8ce2b794cf34a4276a39a8508b9279f066eb0a014a0662257b4c518',
      'label' => 'pfdnd.php',
    ),
    456 => 
    array (
      'sha256' => '43b9565f1e7c67a5d549d9902f9cd2f924ee1874ed5e06b9870c717d49a9180c',
      'label' => 'kwpxydfazn.php',
    ),
    457 => 
    array (
      'sha256' => 'ab1bd390377fbd6ba73fb3a6829f6f50b1364a49e3172db4811005ecdc12b090',
      'label' => 'hwwmbuczpb.php',
    ),
    458 => 
    array (
      'sha256' => '600995eab21d5f29515f686f59f02dd6e0e2f0018e67011de405daaaa6e27534',
      'label' => 'nyudvz.php',
    ),
    459 => 
    array (
      'sha256' => 'e32f7c9c13c93489c8477a887a03e313cd34049af5cf59340fe5ad69a87a3aa0',
      'label' => 'eyaxx.php',
    ),
    460 => 
    array (
      'sha256' => '2c66228b37ba1cf6f37986796d9607fcaa881c6e8f7d59e127220c8cf7a27f96',
      'label' => 'dahbecdbt.php',
    ),
    461 => 
    array (
      'sha256' => 'd21bce82b24d672091ba55c95f8a5d1bd28d5c2a8add9b15f77598b9fd891da5',
      'label' => 'tarrmkbbdn.php',
    ),
    462 => 
    array (
      'sha256' => 'f1ecbb96b698107b8a13af5da2049ec7be5d4e68bc24ca4f055296dd618e046c',
      'label' => 'statistic.php',
    ),
    463 => 
    array (
      'sha256' => 'e0289e2091b201f058ed19b5f50436c3ee69579f0102518c8cb99b2633f7d0bb',
      'label' => 'czzdu.php',
    ),
    464 => 
    array (
      'sha256' => 'f8a7aeb81bab67ed4cfd589ffd82e99c644734a8883ff61735057dad10a9d50c',
      'label' => 'testimonial.php',
    ),
    465 => 
    array (
      'sha256' => '5cf519f0859527f53cefde2d815f262e3ea879dd2fb200da20ac3a3a3a340ade',
      'label' => 'xwppu.php',
    ),
    466 => 
    array (
      'sha256' => '9105f59a8fbb1aa9b4991809dba32bb6b0e085e1168cd4cdcd56d4c4eb238737',
      'label' => 'admin_forums.php',
    ),
    467 => 
    array (
      'sha256' => '68537a433c7c4b3d64d4f5c5b7333d0258713282f2d4757980b3aded8e517ac8',
      'label' => 'api.rubber.php',
    ),
    468 => 
    array (
      'sha256' => '124314e033a7a1b6b2237da13e17f048a4a4ce1d1ce30405022299b73ed35a1b',
      'label' => 'rzvuyamp.php',
    ),
    469 => 
    array (
      'sha256' => 'bb4e988615c22e2ee666671b2f80dd22ff4a64294ca0ad51834763095ac32bd5',
      'label' => 'embassy-list.php',
    ),
    470 => 
    array (
      'sha256' => '9ba512f6966340a7a30b8c93acb8e539e7bece01fb8caaa8dc2a8ee8e8f47800',
      'label' => 'czqhnwrvw.php',
    ),
    471 => 
    array (
      'sha256' => 'f5fa3f0c6af011229658eee4b5c5ada902ab4fa314488db434765153718d64dd',
      'label' => 'bbmfghbxpr.php',
    ),
    472 => 
    array (
      'sha256' => 'abc6480f66c22f362f9e04d1f9b5ca1150553bfaefe3c29e50e574e2cfa1eab9',
      'label' => 'qncweh.php',
    ),
    473 => 
    array (
      'sha256' => '20c264ea20a8fbaf59dcc2564bd81b02c726853ad43774e55c551390486f3dc9',
      'label' => 'uqxfvdbkft.php',
    ),
    474 => 
    array (
      'sha256' => '3344b69f9788f7b1ed5ce56c33584b68b16797463032fbf83acbf75a46aa30e0',
      'label' => 'bpcwhred.php',
    ),
    475 => 
    array (
      'sha256' => '08d940892b34fd1a34cb2590f8a75d810ab85c42a8631701c6a02e62d4364e33',
      'label' => 'gutscheine.php',
    ),
    476 => 
    array (
      'sha256' => '9291ab0965b5bdb40e74100573a2bcd1cebb60a669eaf79b912e5ecb4a48e045',
      'label' => 'evrybv.php',
    ),
    477 => 
    array (
      'sha256' => 'ddffa16026e3e0349a7d595e06223220cd0c251fd508fbaae474d8ea8df241d7',
      'label' => 'init.Saturday.php',
    ),
    478 => 
    array (
      'sha256' => 'e63e8164914588b2ba216c41bf6180a45202481d23281381599c53fe57a15823',
      'label' => 'wceefwfdp.php',
    ),
    479 => 
    array (
      'sha256' => '5727327ad860eda12af660cdd2698dfde6be36ccf4e661413126333674d46532',
      'label' => 'vvyxfskc.php',
    ),
    480 => 
    array (
      'sha256' => '56ad67f4c79b43f1c5ffa34721f63ec3e4da7bb5079284032deffba5a57e40aa',
      'label' => 'vpgcdpt.php',
    ),
    481 => 
    array (
      'sha256' => 'b7d2cf95ea9d6d8c2119b85b286ddc67b8696b19100a4e96e6cd80ee6b0299b9',
      'label' => 'config.deer.php',
    ),
    482 => 
    array (
      'sha256' => '22ff4a08859efaca4ceeb5a569779e71c9698aa1b89a7619b00b8d90626aa7e8',
      'label' => 'cnvznbns.php',
    ),
    483 => 
    array (
      'sha256' => 'e97086441b0dbefc4ab9cee960ac252f93881370cefaf7a7165035797e70dd33',
      'label' => 'wzfxxnyvwg.php',
    ),
    484 => 
    array (
      'sha256' => '7a822a193680078396da3622d2c1253e311b7e2df8de8b71d0d75038068cba73',
      'label' => 'tscgvbg.php',
    ),
    485 => 
    array (
      'sha256' => '5d8a7bff9f498f5e69a52af0f90caa0a8d86b0df49bcb68a8abf79473cef256d',
      'label' => 'amsmmaczrz.php',
    ),
    486 => 
    array (
      'sha256' => '24fcaecb7e8f62d25120e40ba14f1800f170ef1f6440379f6d4f6a311e5ad8d4',
      'label' => 'dpbmubnyc.php',
    ),
    487 => 
    array (
      'sha256' => 'b8fd43f782169acc47fc1e0ac9eba6610a1dd0714e3e4d3fd261954616a0e921',
      'label' => 'dhzuhr.php',
    ),
    488 => 
    array (
      'sha256' => 'dd9d9943213b4b33bc6cea184e1beb440f7b826d68fa4bb21c45f03e56fe0ba4',
      'label' => 'gzrrduwqd.php',
    ),
    489 => 
    array (
      'sha256' => '476877214ae347d727dcddf3589883b45f10a824aee25156cbed1797637fa926',
      'label' => 'csfkz.php',
    ),
    490 => 
    array (
      'sha256' => '5ab68dc0f8b7b7f43c42af2dbaa855a3d8fd9879661743d15a997e7c465782b3',
      'label' => 'frozenLib.php',
    ),
    491 => 
    array (
      'sha256' => 'c717cffec4f7c72847d2e3b04a9967dd624179a413cb3594af045dabd7fac284',
      'label' => 'chartaxd.php',
    ),
    492 => 
    array (
      'sha256' => 'c705ed35d4aaacb8242295858709f6df1f7ca69e4bacaec6b7dffe42be3a4bea',
      'label' => 'trkuadsrp.php',
    ),
    493 => 
    array (
      'sha256' => '40ad9db797f74e9794212e3653f985f118c98a50733093716395be3fefae5a67',
      'label' => 'locator.php',
    ),
    494 => 
    array (
      'sha256' => '073f1cbdca37dd4bf810673d772ef6ebfe3805f0e4374a55c6e1a6c9dce34bbd',
      'label' => 'message.php',
    ),
    495 => 
    array (
      'sha256' => '02a2fb33a702fcb73235d7bb8971dd497e5f9af25745dc9a034dc783d6476441',
      'label' => 'zhegcpe.php',
    ),
    496 => 
    array (
      'sha256' => '8aea536ad75b392c37e3d39cbe00426c40e40bffc149a4183d1498029ac92ae0',
      'label' => 'yssdkha.php',
    ),
    497 => 
    array (
      'sha256' => '6fd715077c38f8573bfe980493f9d56be3ec746ca03052ce5fbc0d9b0cd14e9a',
      'label' => 'ktvbnhexht.php',
    ),
    498 => 
    array (
      'sha256' => '6d8b398748f6daefb5864734394a00f8ce10d126b276cf192aaeb575a3ddd074',
      'label' => 'editgames.php',
    ),
    499 => 
    array (
      'sha256' => '1350cf698516a4c40ca52e45169660842bff4d1a51746870295f6f92ec0054ec',
      'label' => 'hdzbkmzpag.php',
    ),
    500 => 
    array (
      'sha256' => '5a92329985cf8086b297f5f758d3cb8e2be529672d101d75ca236c79d3d27716',
      'label' => 'hktyke.php',
    ),
    501 => 
    array (
      'sha256' => '00bd875af41545b3c3c351059cfe958bdc71115fb2b420c80efd89b3ed2a0577',
      'label' => 'seqhzhf.php',
    ),
    502 => 
    array (
      'sha256' => '510cb8ee134e493ee324b79053ac0f23ea6b094b83e41b8f83e3bc32898b4482',
      'label' => 'unctbun.php',
    ),
    503 => 
    array (
      'sha256' => 'b55dd32d84d9f75d91444d8e269e18b85b70c8ef8ea8b221497c9f08c0a66764',
      'label' => 'gxtzxwx.php',
    ),
    504 => 
    array (
      'sha256' => '9c9effb4df4986c0173b1ed9ebe4d549bbfd69f8f546c98b32b8f337d71d23eb',
      'label' => 'vyqedysqu.php',
    ),
    505 => 
    array (
      'sha256' => '77a46b03db67564ec62e7f89e613c114dbc604f7632d1adab2440ac60889b8a4',
      'label' => 'gvnhuae.php',
    ),
    506 => 
    array (
      'sha256' => '833cabb645736be29e5e2da2464065bf5331cba93350f86abde85b835c4a2e1f',
      'label' => 'cmkfpsnfbt.php',
    ),
    507 => 
    array (
      'sha256' => '41a3298720ea077606e7788f062f5bfb67e44c1e3c331a0219e2ddbd8c4d281b',
      'label' => 'ehpwz.php',
    ),
    508 => 
    array (
      'sha256' => '962c373921c2cc0928eb2f961a86c23273764f1614d057e47553554ee1bca0e7',
      'label' => 'duhnkcmgv.php',
    ),
    509 => 
    array (
      'sha256' => '8edf8b0a71df142f291fe546f3789b71caa531a1c897f249120a010318f65dfd',
      'label' => 'changecurrency.php',
    ),
    510 => 
    array (
      'sha256' => '9c38e593fb31e19f03f32e1bf9823d3d8de3992bbb600bbb1d8b400425e2ce42',
      'label' => 'cqzzggx.php',
    ),
    511 => 
    array (
      'sha256' => '075368f947e7b5399efee4f002b99c8cdc704276e63b46adae9a46256ddf1eb8',
      'label' => 'wp-phpinfo.php',
    ),
    512 => 
    array (
      'sha256' => '4546f8097e4280a352ce3c5886889a48c15c65fd322c4e028c5b172080ef7a89',
      'label' => 'segnala.php',
    ),
    513 => 
    array (
      'sha256' => 'bbc67a33d785a9d818770b37a306249a10535b60567d528c88022c4dca123021',
      'label' => 'zztmy.php',
    ),
    514 => 
    array (
      'sha256' => 'd406c9e202f9dca8c8e1efffe9f0e461701951c78c18395ef43a626a6cc7617e',
      'label' => 'eaapvu.php',
    ),
    515 => 
    array (
      'sha256' => '032e55e4e84693e25046ea76bd76bc19574682eaa3140c044b909bb6eac48ab5',
      'label' => 'dzcfrgfkdz.php',
    ),
    516 => 
    array (
      'sha256' => 'c4bf6a02aab6704d42db1a54a63f3d3ccdbcb3148c6c6ac219cc2532213ad893',
      'label' => 'bzwmdadc.php',
    ),
    517 => 
    array (
      'sha256' => '103ed2520292598b7bcccece574b7a67ff8357f2539d0bccb532accf92e06da2',
      'label' => 'dsfpybsr.php',
    ),
    518 => 
    array (
      'sha256' => 'c09fa813a160b9c9e0037f132a114e5d45b1552708e66c5a56144b71ef167b77',
      'label' => 'zrpuxefgt.php',
    ),
    519 => 
    array (
      'sha256' => '1b767d9c9d6cb3494a115d300b4a303ab02e71e50f71010736b869d89888a710',
      'label' => 'dhsssscsxg.php',
    ),
    520 => 
    array (
      'sha256' => '943791545cf32b4276ed13673f0f49bef7a98910564262335b6f18d8076c301f',
      'label' => 'sdhzqms.php',
    ),
    521 => 
    array (
      'sha256' => '4a0cf39dfc53eaf1c2bda0df9f2192b309b316df5eb5039ac8f0cba364df7e8b',
      'label' => 'ehmwqghazh.php',
    ),
    522 => 
    array (
      'sha256' => 'c2b7d76a0ff107aa5de336cb8b3658a4ce8943002d1f589ce9bdc8663b328205',
      'label' => 'uuqbtxgnst.php',
    ),
    523 => 
    array (
      'sha256' => '4eb9e0a8721f529147b18abf44898a507c5290ddaf0fdb6b8a08f1af84f7ab02',
      'label' => 'config.sum.php',
    ),
    524 => 
    array (
      'sha256' => 'ebfed5703dc23853fcf06b37b3ede6a8369ea773197697e1ff29ac2f6d126881',
      'label' => 'gxrzepbkt.php',
    ),
    525 => 
    array (
      'sha256' => 'cf81e1f9c17166492ae50251af7d6cb3d9fb85bd32912be33eafc0414760da83',
      'label' => 'hvysaysct.php',
    ),
    526 => 
    array (
      'sha256' => '19eb9fd00da549c49992107ff7545601dd173fcdc96269e1f56ea24a4ed2e6f8',
      'label' => 'yyadagxebk.php',
    ),
    527 => 
    array (
      'sha256' => '47be1f07b2c5aaf747a38c2460002294ac2926c7032fda297ce55573815b7a70',
      'label' => 'zfszuyfu.php',
    ),
    528 => 
    array (
      'sha256' => '9d3e0932ff4fed88288851d1f943d040fbf158e509f363a39dffbc00ad03466c',
      'label' => 'heavnwhfd.php',
    ),
    529 => 
    array (
      'sha256' => '8aa15ae4831d58aff6810142c9961c5608230817b0cfee2eb9eacc616f9cc2fe',
      'label' => 'wdgrtbquzx.php',
    ),
    530 => 
    array (
      'sha256' => 'd85023bba201093ab85e58fd56c5140a631be7f195321fc9b3e3ee6d0c9d3532',
      'label' => 'ctmdnvghc.php',
    ),
    531 => 
    array (
      'sha256' => 'bb470baa3ce8f347ce843a69ea0b574d4b616aa232d8a92d66e45fd31ec23b96',
      'label' => 'axcqdm.php',
    ),
    532 => 
    array (
      'sha256' => '90a4285fd3e48a8a8825e7c47e0b04fdd5d8d18e7fc15b795471a583b9225589',
      'label' => 'vuvfxntcak.php',
    ),
    533 => 
    array (
      'sha256' => '03e2223df086a5eb5847a65d78c1baf0574c6688efde620c0c9c843d523b77ee',
      'label' => 'hbqudhp.php',
    ),
    534 => 
    array (
      'sha256' => '4edad0108eceab81c235ceb55188aaba47d9431d6141b9ef515222b39094efb4',
      'label' => 'rnhxhkbup.php',
    ),
    535 => 
    array (
      'sha256' => '2cb3b11cce0d52924a8651bd129b3aae5952a7808a9dd903b30618849b8a5db7',
      'label' => 'dfggfbb.php',
    ),
    536 => 
    array (
      'sha256' => 'c6ef6ec1e815ddf62ee9cb1d7f52623e09902de6419518c10e7fedc1178c9b8a',
      'label' => 'etagmrdap.php',
    ),
    537 => 
    array (
      'sha256' => '790759f055744e9071f4b7d1fb5771c395a5482d53cc3f8463dc3cf3d07fe03f',
      'label' => 'index-print.php',
    ),
    538 => 
    array (
      'sha256' => '9401a1779bcb262515797bf8b249025d399aa36ddc125056f7939b5723c3fe97',
      'label' => 'zzmexey.php',
    ),
    539 => 
    array (
      'sha256' => '35aaf0a6678f66bd000a9e5b58320f61dd72c779e9cc4d18170e0236c8ae5317',
      'label' => 'nsusz.php',
    ),
    540 => 
    array (
      'sha256' => '1b0fc68e2c8769f8347b0c5baf40c41c3bd9245b7c08cabe88980c9e1f07c526',
      'label' => 'ekvufx.php',
    ),
    541 => 
    array (
      'sha256' => '0328ac4d024ba52a12fe7c30e4b5b9eca7b6ab5d56f578a4cb189bae652acf90',
      'label' => 'rzprmgn.php',
    ),
    542 => 
    array (
      'sha256' => '9ea5cc60d0b640cd9a60ffefdaa70b1e4b270efaa5dcbf787339e31aa124f96f',
      'label' => 'dmnfgrx.php',
    ),
    543 => 
    array (
      'sha256' => '336e8d7479010b07bd6d745944bc33083d720a1f460cd0b337277b4de700352f',
      'label' => 'gnaqhrzcc.php',
    ),
    544 => 
    array (
      'sha256' => 'ebd98be71b5ec9489e80cfbddfb636a5269d8035b6bcf919d9682a6446c64ee7',
      'label' => 'vdaaexm.php',
    ),
    545 => 
    array (
      'sha256' => '58a9691e0a82e2bcf46da719f6057f59f52ad50dfb4487de56f552719881b78c',
      'label' => 'error_log.php',
    ),
    546 => 
    array (
      'sha256' => '6088f1178d6da34e2d5fdaf3c3863b1cda8257f3bfd36dc34a3e44f560090cfe',
      'label' => 'cmkpkxemp.php',
    ),
    547 => 
    array (
      'sha256' => 'd4cd0227b7d2eed2c82d53aaef3b5bf1626e24ee2586b48faf35582f198b3224',
      'label' => 'byfywnu.php',
    ),
    548 => 
    array (
      'sha256' => '12c74c3665a3d2eff2e0c7d2a22055c79c2c1247000243eaa36cf3a1c5288390',
      'label' => 'fphtmc.php',
    ),
    549 => 
    array (
      'sha256' => '74c3aefdc93e60d2f5ddd5d166a27be4572e8a3ef8f68466f1047c633d9155e1',
      'label' => 'zwmksxz.php',
    ),
    550 => 
    array (
      'sha256' => 'bb367aa57a677f392631a96d6fe5a13fdefe7ba369c7f3d148ee495b6985e063',
      'label' => 'kkqdkhq.php',
    ),
    551 => 
    array (
      'sha256' => 'f69a2715151d088c6e7044c275c580da1c3aef931c810590c42de754f614d51a',
      'label' => 'mxzgqreytx.php',
    ),
    552 => 
    array (
      'sha256' => 'a36369b0440f6711a2deb516dd4b4a20fd1710c346405768942996a83fd732c8',
      'label' => 'resend_login.php',
    ),
    553 => 
    array (
      'sha256' => 'b5c588d470eb6cdf62cf92f42b9255effe1e747b138622cbb7c926f8e1c30757',
      'label' => 'pgwcm.php',
    ),
    554 => 
    array (
      'sha256' => '39bfbfd785290d3841e1148703c9ab7517e66f0d879bf2aeaad6b2f4ab6f95b5',
      'label' => 'sptwbm.php',
    ),
    555 => 
    array (
      'sha256' => '94791f1942be1bfee6fb0d015a960a1b00de18e03d0f0ac5504a0d84c97285b6',
      'label' => 'cat_search.php',
    ),
    556 => 
    array (
      'sha256' => 'ece6910406175a6095a066910f2a8c0c75c82383394fd9eee261151becab5051',
      'label' => 'article_details.php',
    ),
    557 => 
    array (
      'sha256' => 'f3adc17d002e355d21b03fa4572a39beb9e87e7865bb06b345c1b0bf05bc46ab',
      'label' => 'fxstvddumw.php',
    ),
    558 => 
    array (
      'sha256' => 'b185d51b6cbb1f3fee9e4f1246170f6d69eea49126d908efbb38ffc42d0435f8',
      'label' => 'pqevdvp.php',
    ),
    559 => 
    array (
      'sha256' => '93617024b3e065eaf9ecb560d8ef907337d779c7df227ea6b8cb990136e8f58d',
      'label' => 'bmhea.php',
    ),
    560 => 
    array (
      'sha256' => 'b8e1e66063dce493d031e63165b04ef9e99a1489fad10a90c814a902bf403371',
      'label' => 'fcbfxe.php',
    ),
    561 => 
    array (
      'sha256' => 'f894600fa01457fc63a1116a18322adf0b191b07b852b9e3ea2a6d6bcec2ff6a',
      'label' => 'vwnucrv.php',
    ),
    562 => 
    array (
      'sha256' => '9642180fed7e72a5f51e78fcaab706fa2377fc06cd217ef5eadef0ca9da2ed01',
      'label' => 'cataloguesearch.php',
    ),
    563 => 
    array (
      'sha256' => '6f6d0b8be0214cf9f3d311f2386c546e674d85565cc0576a78ca62aca3218440',
      'label' => 'ucwyrsean.php',
    ),
    564 => 
    array (
      'sha256' => 'f346a4c79933ac3e8cdb9827d2a55d899abc2d736850f840934a8bf3c11d2522',
      'label' => 'rgwdzwq.php',
    ),
    565 => 
    array (
      'sha256' => '04bc7c27d27d98e3d2d4ccde9b325bfd5f887b4af3ff4285a85f6a6e65ee92eb',
      'label' => 'xfbqf.php',
    ),
    566 => 
    array (
      'sha256' => 'eb6279211b9b5f894cbf8a1a6ffc7a2ec57780ee928ded711eb7ea0f22f2b57f',
      'label' => 'swgzdblwls.php',
    ),
    567 => 
    array (
      'sha256' => 'd06928e70978be4a6d15de199ce088e946bf04d08edf2176cc487f8193f7a0b7',
      'label' => 'config.bak.php',
    ),
    568 => 
    array (
      'sha256' => '7b69f28e44cbd6c9d7daa4fe90193dd41989a33817fa0307f448ee2a02a6add4',
      'label' => 'tesTrei.php',
    ),
    569 => 
    array (
      'sha256' => '4696baca0ab7dc2179dcb062fa07ad3fd3432f781107412c43a6eb47c63277fe',
      'label' => 'index.php-4696baca0ab7',
    ),
    570 => 
    array (
      'sha256' => '9ff73f9d357ebd952f14e5d37d553ab1da6699b94faa292997e5b5174fa4fa9c',
      'label' => 'tbl_status.php',
    ),
    571 => 
    array (
      'sha256' => '0cc8dde487418ab54673c53083c65c2d1c011babaf1bed6cc017a518ef7cba09',
      'label' => 'widget.php',
    ),
    572 => 
    array (
      'sha256' => 'c01550acf43ae358ba5c4bec89d6c600d18e2b2eb2aed862856ca44a413b5458',
      'label' => 'UNZipeRkuh.php',
    ),
    573 => 
    array (
      'sha256' => 'fbcfc1c7c81c3b3c3293836d865ebf208f3f846824acccef4603b8b839f1b4d9',
      'label' => 'index.php-fbcfc1c7c81c',
    ),
    574 => 
    array (
      'sha256' => 'f965940f2a504bcf65376194476bc80cd181b22654faed86841f9566dd93b418',
      'label' => 'wwcgzjjpcl.php',
    ),
    575 => 
    array (
      'sha256' => 'f84ed8e49a1dfdf645fface0a4855bb68d90c174e40b22b88432f5fcce1f77b0',
      'label' => 'style.php',
    ),
    576 => 
    array (
      'sha256' => '9d7e7057fa69f7b1da9121539de5cf7fb81a54b7252452fc40412d8aefb8d9e8',
      'label' => 'index.php-9d7e7057fa69',
    ),
    577 => 
    array (
      'sha256' => 'f92fde4123a699ec857f19fa82988bbd5e2d58667a158e1b80aad6bc97845566',
      'label' => 'footer.php',
    ),
    578 => 
    array (
      'sha256' => '5854c6fb668c659187a25b3e2b230acd058eecb83f67d307ae7dca07a62bac9f',
      'label' => 'htaccess.php',
    ),
    579 => 
    array (
      'sha256' => 'dab9a24c29ce0cecefebd96615a1cd1a25685288fb7db5506b64f8435834f3e7',
      'label' => 'index.php-dab9a24c29ce',
    ),
    580 => 
    array (
      'sha256' => '396c9bb5b9cf790a2bbd723f70337517f4739d99551c9a776bfd18bb3fa16108',
      'label' => 'w21k73yk.php',
    ),
    581 => 
    array (
      'sha256' => 'dfb54d35f269c061929287899a19931975562767a6f96e8d896db0d035efc67a',
      'label' => 'dyf3f447.php',
    ),
    582 => 
    array (
      'sha256' => '717b0a9fc7096b95a028b58dfc677fb4e3afa5ff6b45eadad619a9300c946817',
      'label' => 'cn24xaiy.php',
    ),
    583 => 
    array (
      'sha256' => 'e3eb280f204a366d760e008c4f2812ea9d2034d12372a630a938a2fe21d55918',
      'label' => 'hx6bu4yh.php',
    ),
    584 => 
    array (
      'sha256' => 'edc70207b06703301ba05fc5b1442aca884ab83b5695340e8967b380c37f0439',
      'label' => 'three-column-screen-layout.php',
    ),
    585 => 
    array (
      'sha256' => '8b6a86e79085844269cb44b60847e12d1a1f5435a5b248f3fad28269f162f5f6',
      'label' => 'config.php',
    ),
    586 => 
    array (
      'sha256' => '9fbc1bdacc22a7ca0f01dc1ad3783c9effb73b99d71d9349250da611574120a5',
      'label' => 'index.php-9fbc1bdacc22',
    ),
    587 => 
    array (
      'sha256' => '59d9797b05cc14f34b825263084b1e9ebd50b174debbea511d6c3ecc9f92fa8f',
      'label' => 'wp-config.php-59d9797b05cc',
    ),
    588 => 
    array (
      'sha256' => '67575b32da6fcfb08ab11ad7b4b013ca5d36e4ddaab0a008278d16d980311a7c',
      'label' => 'paedtipz.php',
    ),
    589 => 
    array (
      'sha256' => '253a5648b970273e1f5fd132b872ac0290bf32fbcc237b61e5db68afc7109552',
      'label' => 'jzkucsymgf.php',
    ),
    590 => 
    array (
      'sha256' => 'db7ab532f6d5d894b23d1e866f9fc60ced74a7b666c412516aa0b8710e4dbaf8',
      'label' => 'iozhdxdasi.php',
    ),
    591 => 
    array (
      'sha256' => '3e4fb7e2f48d7bc337102c46c0894e4c1ec111bd68a99d2378ca836d2e610256',
      'label' => 'feal.php',
    ),
    592 => 
    array (
      'sha256' => 'd5cd56715c0d9d573410683e04c7c22546f930b311061616770c47ccf5930e60',
      'label' => 'to.php',
    ),
    593 => 
    array (
      'sha256' => '87df99d0b16e503892bee9e662053c419214c9ce595043e78b8cdee2e007c5ca',
      'label' => 'index.php-87df99d0b16e',
    ),
    594 => 
    array (
      'sha256' => 'f6d4934bf4133fbb0b763fc3c8e67554409219e36216a347742ef730b4caace8',
      'label' => 'index.php-f6d4934bf413',
    ),
    595 => 
    array (
      'sha256' => '2fe93674de745336bbeaa3c633e0a0108371781785b805f0e6589e89d525a505',
      'label' => 'wp-engine.php-2fe93674de74',
    ),
    596 => 
    array (
      'sha256' => '02eed2215152f8204d23be46176e779e712e15df6950be430b7329c1756146db',
      'label' => 'class.plugin-modules.php',
    ),
    597 => 
    array (
      'sha256' => '6c26dc8c5cee27b702544e7904fea710697bf8e6ce76b9a5758a9eda3e9056c0',
      'label' => 'style.php-6c26dc8c5cee',
    ),
    598 => 
    array (
      'sha256' => 'f04662d60fd8759ba46f77e5eb6d9a22f341616a40b397ea9f119853786ac4ba',
      'label' => 'dd.php',
    ),
    599 => 
    array (
      'sha256' => 'a2f54fb79105518766f9e60f1d08cba1a03a6d498719dbe699519bf6c47a2005',
      'label' => 'rptegmfmcq.php',
    ),
    600 => 
    array (
      'sha256' => 'e6880647ac06f3894676cef5af0ba3e9edb2f3c6b90431ea8325d172aa8b4c38',
      'label' => 'index.php-e6880647ac06',
    ),
    601 => 
    array (
      'sha256' => '7dd68c027c0aae85141639aec8f1ab35d3d1296f29d17fe6cbe0738845626f81',
      'label' => 'lock360.php',
    ),
    602 => 
    array (
      'sha256' => 'f524dac194f4a0fb5150232de0ad9ec5d9ff957a7ef90977217678878683526a',
      'label' => 'wp-install.php',
    ),
    603 => 
    array (
      'sha256' => '5c0dd9374e931d4c33e9842678735fae658cce0473587fb926baa5d14d7e9159',
      'label' => 'wikindex.php',
    ),
    604 => 
    array (
      'sha256' => 'fb51a30a4edb29824282cf62d9a414954988f2f985622991b90b3f563ed26b88',
      'label' => 'index.php-fb51a30a4edb',
    ),
    605 => 
    array (
      'sha256' => '7becc1408d5e89f642919eb3ce406818fd0ca9c153e6e84f0df1c8559f1f9ff6',
      'label' => 'content.php',
    ),
    606 => 
    array (
      'sha256' => '34ef6f72215173aca9bd3eae132e44170d5fce302464edf7c60891b84beece72',
      'label' => 'pnnfxpueiq.php',
    ),
    607 => 
    array (
      'sha256' => '34d7bb1c347e36f3a53d863cfbef0cd636a5f9fe2712147027b5ecf3654fc009',
      'label' => '.php',
    ),
    608 => 
    array (
      'sha256' => '41f600e6500903ccf58e0e46442bfc6f48029cee14033b970aa6aaa3e65c13c2',
      'label' => 'unsl2.php',
    ),
    609 => 
    array (
      'sha256' => 'ed707b3839e798b2aebf368750eaefe322421e22a41a9df1f87831dc4e5b7227',
      'label' => 'index.php-ed707b3839e7',
    ),
    610 => 
    array (
      'sha256' => '2e59610d00a9e012bcf0a6190a4f0e34841b59a57b09cd75ae2a34c590873478',
      'label' => '3drb4.php',
    ),
    611 => 
    array (
      'sha256' => '22739f0da730f0231a84303ce9fab64b65cb5834907a82bb42db9a8ed952e4b5',
      'label' => 'j1zrb.php',
    ),
    612 => 
    array (
      'sha256' => '023171b12d0f0634d10c4bfe179505164a02e8a20fa50401c24f5f796484a4c2',
      'label' => 'index.php-023171b12d0f',
    ),
    613 => 
    array (
      'sha256' => 'b0fef52d57455926e405b6d39dfad57ba8aa96241181580c8b74394d8831f201',
      'label' => 'index.php-b0fef52d5745',
    ),
    614 => 
    array (
      'sha256' => '79ac4877f4c7b246359f4354583a52e1a8846a640aac69e96ae5b1aeacaf603a',
      'label' => 'load.php',
    ),
    615 => 
    array (
      'sha256' => '3e30ee9eb14bfc29420cf58175f5b47febb52ef6d5332eaed2d47c119f0a83a0',
      'label' => 'index.php-3e30ee9eb14b',
    ),
    616 => 
    array (
      'sha256' => 'c2a277cf1b4a40aed5587c3e3b746c8a2ada5f1af5ada6e1e88a32c278849f69',
      'label' => 'index.php-c2a277cf1b4a',
    ),
    617 => 
    array (
      'sha256' => '3c0abc4fb94f3b4913851ec427a57bb874497ad4b90b3408f2e475bf7e5073d5',
      'label' => 'IpAdress.php',
    ),
    618 => 
    array (
      'sha256' => 'aea7b5701bcef6f68ef7f8416129989d4e7ad32f6f46a4299fd62c65fbd39a0a',
      'label' => 'defense.php',
    ),
    619 => 
    array (
      'sha256' => '3efc4666766ed829b78637702f6827e5e112e1e88fa5e4d672cd33a97d309672',
      'label' => 'class.php',
    ),
    620 => 
    array (
      'sha256' => 'b160b1c33d9ee387686733103d7b3b0c0622ac383f3977fae6feb68353a4b586',
      'label' => 'bepas.php',
    ),
    621 => 
    array (
      'sha256' => 'dc919f94e93aee92c4cfe2b2c6fefc56c6ba70fa9d3e19a8e6b17cc6d9b4901f',
      'label' => 'windex.php',
    ),
    622 => 
    array (
      'sha256' => 'dd8d87e6a8c9818e8b49a12a0329c9d6cb53d8ba2565afcc80a069e7cf37a86f',
      'label' => 'gdform.php',
    ),
    623 => 
    array (
      'sha256' => '43489de6f4667b460d5baa0529794692809aa2bc80721572665d053ae0f977c6',
      'label' => 'kindex.php',
    ),
    624 => 
    array (
      'sha256' => '862e72e43ba8e96ab6b28c2fdc7913a23bf818a6ae279dec5bf505da5d7558c3',
      'label' => 'baindes.php',
    ),
    625 => 
    array (
      'sha256' => '19ec7515dfbf02333c760a0fbb3c13493977221515dcd0c71d82bf1eabe43464',
      'label' => 'Coli.Php',
    ),
    626 => 
    array (
      'sha256' => '7d232f31c931c7f7b41339775539dc4014f2a81770c9d0c3a0a144b2c094940f',
      'label' => 'qtcshbkcgn.php',
    ),
    627 => 
    array (
      'sha256' => '9e5269dcc83ed427a5d4c7e26a5648b8a40db51f0edd96d2824057085766eaca',
      'label' => 'tmp.php',
    ),
    628 => 
    array (
      'sha256' => '4397576dd51d11fbb8be6248f40df77960eabca4db33fad3b7fbd10c0729d406',
      'label' => 'setting.php',
    ),
    629 => 
    array (
      'sha256' => 'b5a7e30118f6f676c5db54c31e998346d9c1d4670cdb23fda8b5b529f68646a4',
      'label' => 'vjpvgzdhka.php',
    ),
    630 => 
    array (
      'sha256' => 'a23c10e4c6ce3330ef350bac51b96d64480e0db66076f32a94bc6819c3f0a02a',
      'label' => 'kztaooepbp.php',
    ),
    631 => 
    array (
      'sha256' => '6546aa5dee5a942c282c82b4b2f43dd22db5e40e24171db5c54510a1dd073a66',
      'label' => 'ini.php',
    ),
    632 => 
    array (
      'sha256' => '6819180b6095b34b79f4caa829a88e688acc6969db98033bbbd3eb32699ae0d0',
      'label' => 'index.php-6819180b6095',
    ),
    633 => 
    array (
      'sha256' => 'a22027c335c76f1fbc8946d482ccec1959ec3a66d467fdf5e3fdde78c1ecb89a',
      'label' => 's_e.php',
    ),
    634 => 
    array (
      'sha256' => '29fefbb549688add54fb51cfad0024add89c69ea8c39bd667b275100484bbd1c',
      'label' => 'indexs.php',
    ),
    635 => 
    array (
      'sha256' => '849e3804238301a1b2315842441c8a4ef7b74c3471e910e42e5121c22c8de2b5',
      'label' => 'csv.php',
    ),
    636 => 
    array (
      'sha256' => 'b09f6a64b427875c4f4723738bd49817e60c6a7f5c534678b431592b1b9b43fe',
      'label' => 'email.php-b09f6a64b427',
    ),
    637 => 
    array (
      'sha256' => 'e8e169c3dbdc33be91bf31df596b155a0588e95cc97dc47a4b7efe2cb6b0bcdc',
      'label' => 'index.php-e8e169c3dbdc',
    ),
    638 => 
    array (
      'sha256' => '98450cd036afd27f6b2feab3a4e8ccbcaa4da0651de68abe7f0d491ff8aed865',
      'label' => 'index3.php',
    ),
    639 => 
    array (
      'sha256' => '8f1c4d4722d4a3cb9a8b25f04dc86a8b88e50b8f60eb941e3c7fc443b02f33e1',
      'label' => 'login.php',
    ),
    640 => 
    array (
      'sha256' => '6ffc79323418f862bdc1a0ca65a804cb2882822da652b78e5e28a8ee4c3d29f8',
      'label' => 'uploader.php',
    ),
    641 => 
    array (
      'sha256' => 'e7b6d2e10dd54b5e26dd1d4bfd6dc462a9f2fbae1012de7ee7b4ce846ec17523',
      'label' => 'zda.php',
    ),
    642 => 
    array (
      'sha256' => 'd8750585ff9f2ad0b100843ffcd0236b1ff1defc606653da4280bf1685a73db8',
      'label' => 'ff.php',
    ),
    643 => 
    array (
      'sha256' => 'bc798fa0a06b3edca30b8446e0cff5f39375cf86b9cfaeda722b5dc44ce93b88',
      'label' => 'wp-comments-post.php',
    ),
    644 => 
    array (
      'sha256' => 'de2e7e66e55678dab94eb9eeeb35afa13a64844da0b0877acf881451ff50c9aa',
      'label' => 'ND4H2OW8.php',
    ),
    645 => 
    array (
      'sha256' => '9a76d9c131894ab86278fb5b8f1f0934a84d8847753b2ec5968d17a4f481291f',
      'label' => 'optim_v40eut.php',
    ),
    646 => 
    array (
      'sha256' => '2d32a595eaf9aaf26bac6a6e03b69afbdd91b2bd20712a40aea17c500fe72014',
      'label' => '1gvyyld.php',
    ),
    647 => 
    array (
      'sha256' => '411ae2f78dbeaba0276dc97ed07e235ada45182586520521cb1a3bc3298a0e21',
      'label' => 'themes.php',
    ),
    648 => 
    array (
      'sha256' => 'aa6029d07a0dba326f97f300bc25f0b45b6bee06f2528ec126642fbb0243a28a',
      'label' => 'metabox.php',
    ),
    649 => 
    array (
      'sha256' => '7f2103984590122e780d9b0cf4aba5a1f31e52df2e57c5e4ae5a7695d44c2681',
      'label' => 'admin.php',
    ),
    650 => 
    array (
      'sha256' => 'a0ccacbc211f131b7c2189a147617e49beba42d0d1b96404018f767bc6ef0fc2',
      'label' => '1.php',
    ),
    651 => 
    array (
      'sha256' => '007944b9f2f2becbab407a58bc7e94903282e2b5fdabcb148a79ae2e3cef976f',
      'label' => 'wikindex.php-007944b9f2f2',
    ),
    652 => 
    array (
      'sha256' => '0e826b79b4a61d70b639f87844e5e11d5a131d3dc750c90df59a0de86c8d90ec',
      'label' => '3index.php',
    ),
    653 => 
    array (
      'sha256' => '8067522cf3721e474cc88a97fe0de9bf22b842828fdb3ed52a9122a062802bfc',
      'label' => 'wp-22.php',
    ),
    654 => 
    array (
      'sha256' => '821f7bf1d967ee3fbcdf29c146ab58f98e10b49b64012fa4966acaae02df7add',
      'label' => 'security.php-821f7bf1d967',
    ),
    655 => 
    array (
      'sha256' => '977303ecc509185f4c4dc3df89ae152234ef57e8fe17b532c25b3f6e8f8a0ee1',
      'label' => 'admin.php-977303ecc509',
    ),
    656 => 
    array (
      'sha256' => 'd2f3af4b352b3c7f42775305a6c5b4e6b1f25d89f9b0fedb2a862c90a371808a',
      'label' => 'blue.php',
    ),
    657 => 
    array (
      'sha256' => '4709270bf81dcf23123e0215e39c8b3a8e6f0531e38b4fdfe9934482dd50d1a4',
      'label' => 'auth-app.min.js',
    ),
    658 => 
    array (
      'sha256' => '106bfd9961ccf5b97b43586ae4f93cddcd7983822950b3dea06b25549f2cbccb',
      'label' => 'ProductList.php',
    ),
    659 => 
    array (
      'sha256' => 'bee863bd2ad94376d011d93c05e8a8a91e33e0c59bd164c24fcc41ef7549db8e',
      'label' => 'regexes.php',
    ),
    660 => 
    array (
      'sha256' => '3d3e567ea19a51f2f04b395ab979388b07a9ba0b45fd68b3c07a0db728a79159',
      'label' => 'seo.php',
    ),
    661 => 
    array (
      'sha256' => 'c4d2984ff0a65f02df9fdd78b116a014cdb6078931a04a2b9414b7e94d5b3403',
      'label' => 'fvk.php',
    ),
    662 => 
    array (
      'sha256' => '0bb3baa019280b344670629f54b3ecaa1cc0b2e1c990365c55b7af8dde3c3db2',
      'label' => 'old-index.php',
    ),
    663 => 
    array (
      'sha256' => '4ccd9e1f0131a802433c3e999006e989fa57be27c01c82e216117a35b948e716',
      'label' => 'wp-core.php',
    ),
    664 => 
    array (
      'sha256' => 'f803cc525f22216b20c1cab758ab6713c0ea4af05970236c7cb0f113e8a86be5',
      'label' => 'class-wp-image-selector.php',
    ),
    665 => 
    array (
      'sha256' => '67191685df6e8333f58bb1903674aedeadeacaa67441b35abc8b18cb1d307bf1',
      'label' => 'vars.php',
    ),
    666 => 
    array (
      'sha256' => '24fe95949b0e068293cc954ce32c91b35d4b3096f19d00c2d42ec49b154f4816',
      'label' => 'info.php',
    ),
    667 => 
    array (
      'sha256' => '68c4e2e0e27a842544cd5d65b447752ab9ac07d87a8e631dd4745096f59b9db5',
      'label' => 'uxrgdec.php',
    ),
    668 => 
    array (
      'sha256' => '57e722a646b8f08ec451d45d1adb214f9e9f629551631af91a97b452d3b86991',
      'label' => 'siteindex.php',
    ),
    669 => 
    array (
      'sha256' => '6be1cf44dc304dc40b4c68646dd944f9004a227266f546947436d15ad7e8743c',
      'label' => 'index.php-6be1cf44dc30',
    ),
    670 => 
    array (
      'sha256' => '8dcc5161ba9701193ef61c6a15ae3291e580f9a14cc078e96c1f8130e69b7b75',
      'label' => 'confirmation.php',
    ),
    671 => 
    array (
      'sha256' => 'e11819aed92c345e357371fa0cc0007c53e4fa031a6b2c054931c1f7f6fcf7fa',
      'label' => 'ms-edit.php',
    ),
    672 => 
    array (
      'sha256' => '0cfdf8fd85079ab69bb81781432ce8308473864f3b6a501d0f8e9d2658207c23',
      'label' => 'menu.php',
    ),
    673 => 
    array (
      'sha256' => '43c238b85ac77cf2e3c6c5e4a6b6b1c2a83f32a65aac3e971a2de307273cd551',
      'label' => 'wdgqgjvr.php',
    ),
    674 => 
    array (
      'sha256' => '6d5fb8ced8c9ec1fd863351bfc323e102b050e9c104eab013bcc20527bb00312',
      'label' => 'upload.php',
    ),
    675 => 
    array (
      'sha256' => 'aba6e110ddfdbb9b390fdb84ed7226ba42ce3f72bac6736935730dbee41c6cca',
      'label' => 'alfzwpxz.php',
    ),
    676 => 
    array (
      'sha256' => 'd066cc035194336be89d3eab1692b808a50723368efd773fcec626bbc7c2a600',
      'label' => 'lib.php',
    ),
    677 => 
    array (
      'sha256' => '294b363de0231de2529fb1b081e491a2477994d056f841536de06c383f71f80f',
      'label' => 'index.php-294b363de023',
    ),
    678 => 
    array (
      'sha256' => '08429473ce8335d937865daa9088414f9eb0641f98f6ae118b0dc718ed905cd0',
      'label' => 'rfboiwcj.php',
    ),
    679 => 
    array (
      'sha256' => '036dfddcf142e2f985f728c322dd544c06f4e4a8bc3ce6dafae2d27915d95c48',
      'label' => 'jlawhegu.php',
    ),
    680 => 
    array (
      'sha256' => 'fb68ad13139adb94ae8c206a87debfd4b600d908c00e24fe71ad11bfcee3881e',
      'label' => 'class-fl-builder-icons.php',
    ),
    681 => 
    array (
      'sha256' => '8d6d721de983b6d8a8cd908375cabdb06edd7e577d52f6001369b86f3964f423',
      'label' => 'class-fl-builder-service-mailchimp.php',
    ),
    682 => 
    array (
      'sha256' => '9dc69139bd1d591ce9f1c9232febfeeb9dd736df44a70f4b7fa4432c8be3cde1',
      'label' => 'rftpdsdv.php',
    ),
    683 => 
    array (
      'sha256' => '1cf4925e06c402cd0be92ac8cd2cb10415971da4df7e9e3490fda1207ac4e4ba',
      'label' => 'IOptimize.php',
    ),
    684 => 
    array (
      'sha256' => 'f6c04e5521d946345e12f11a9092ea080dbb27558acb308aa1684cc4df81dd4b',
      'label' => 'p6948105.php',
    ),
    685 => 
    array (
      'sha256' => 'd7fbc17153e82c1b3b26a03da6291d87974fe3e6681588ab4e9b3447c65dc13f',
      'label' => 'test.php-d7fbc17153e8',
    ),
    686 => 
    array (
      'sha256' => '5171f0acb0acb55d6b93a33059ab55ef8cf503ef046dc4b672848d38fbf34f1e',
      'label' => 'i5lzqchfxy_index.php',
    ),
    687 => 
    array (
      'sha256' => '9d0d1653b22cd0f1d8223165a73f292bb76e43ac0701e50aa23b7d5c0664389d',
      'label' => 'wp-signup.php-9d0d1653b22c',
    ),
    688 => 
    array (
      'sha256' => 'bc984e8d3dca5695f9cfe1534906c6820347bfe951d5802d205a736b4c1b4c65',
      'label' => 'update-config.php',
    ),
    689 => 
    array (
      'sha256' => '8ba5eee07651f40cff6590323875e17504215b18c512010edfe85d2c19ee1c68',
      'label' => 'services-update.php',
    ),
    690 => 
    array (
      'sha256' => 'fcf1d7de49a448b39a7480ac0a9d835a5f33784286e51319cd7e906305f0c433',
      'label' => 'index578b10.php',
    ),
    691 => 
    array (
      'sha256' => '6edc450ba5d2b23a7ae4578693f0d8386d7f93c8003768e4862bd0bc50eb18eb',
      'label' => 'mfi.php',
    ),
    692 => 
    array (
      'sha256' => 'c3d3c9f0a0fc80810f101a8fd784f077c6b41844741d64891faf3dd3558af089',
      'label' => 'index.php-c3d3c9f0a0fc',
    ),
    693 => 
    array (
      'sha256' => 'cce6078facd4237bb41ca09a3fdb7bb46a2d7017786a3ac92f4df8e9cfe01b8d',
      'label' => 'probable.php',
    ),
    694 => 
    array (
      'sha256' => '34146b7e9d80d311c730b7bd6b99d5f695ede4284cc925b07887087538025d90',
      'label' => 'admin.php-34146b7e9d80',
    ),
    695 => 
    array (
      'sha256' => '96b1861e55a24024800294761d5833d7212bac536bf50d46a81a3c7743f220a6',
      'label' => 'admin-ajax.php-96b1861e55a2',
    ),
    696 => 
    array (
      'sha256' => '1195a9b888961c89db97eb31cc33649cd74ae2acb0fce73779abd3851527b0ad',
      'label' => 'admin-post.php',
    ),
    697 => 
    array (
      'sha256' => '6a87c0684223c51d2f824dd669df537c6a43e88a8fbc6db6a44f24609bbde190',
      'label' => 'class.theme-modules.php',
    ),
    698 => 
    array (
      'sha256' => '95316622608e4da59f869dabfedc4d9ada64bee3ab0bc15c1822f73d5c1806b0',
      'label' => 'functions.php',
    ),
    699 => 
    array (
      'sha256' => '88896ee3309d208f4a3d7cad6766608b8e5b5923e3b4fac6713412cf9f8a338a',
      'label' => 'index.php-88896ee3309d',
    ),
    700 => 
    array (
      'sha256' => '2cd3b1a930406f0eb54759b2a2586743c3c4ded3dddc4d830d8d418e72b94946',
      'label' => 'IOptimize.php-2cd3b1a93040',
    ),
    701 => 
    array (
      'sha256' => 'ea6efba379be52ab23a361514b42535b185c06cf83e90fc2bd7a38ffb85b062d',
      'label' => 'connector.minimal.php',
    ),
    702 => 
    array (
      'sha256' => '67729a93700cfa9c340f3b5985ba75886915196bb73fe846b5fbecaa29aac023',
      'label' => 'cursed.php',
    ),
    703 => 
    array (
      'sha256' => 'e8ed18056ca7ff1d2455cec0db78e05f196f9908fd9e5460baf04b0acb978368',
      'label' => 'index.php-e8ed18056ca7',
    ),
    704 => 
    array (
      'sha256' => '84b216e73159abc9170c20d80f30572099db65fd10ad1681957aa94be456f58f',
      'label' => 'config.bak.php-84b216e73159',
    ),
    705 => 
    array (
      'sha256' => 'ea8e5aefb823d4e468446fae8c608f7c1d43ef73cd9febae01068d2687175600',
      'label' => 'dxnjdpzbrntxf.js',
    ),
    706 => 
    array (
      'sha256' => 'b39634edc679933a8a603612b89b930aed234e0b5ef78d97495728b14a82267b',
      'label' => 'monit.php',
    ),
    707 => 
    array (
      'sha256' => 'e512871cdb2720c315804a1211fedfe944886f670cbd15ea841f509453405577',
      'label' => 'index.php-e512871cdb27',
    ),
    708 => 
    array (
      'sha256' => '522b3f9fe81a2a526120285c20f50de64691fb14a4624d328e38e50d07a59ebf',
      'label' => 'index.php-522b3f9fe81a',
    ),
    709 => 
    array (
      'sha256' => '29fb32c6e21e6542432f995d8729e598b2690833f52375fbcf70dfed89ec54bf',
      'label' => 'wwdv.php',
    ),
    710 => 
    array (
      'sha256' => '98aace1b397973450ae7bb13d5505eee5568b7b9dfe0a2ca54df75a711ddf5ec',
      'label' => 'tax_class.php',
    ),
    711 => 
    array (
      'sha256' => 'f396f091b0c2e0802ecf34d5dc5862f8cd63f0ac9882b3a50285a0e2cd507dd3',
      'label' => 'index.php-f396f091b0c2',
    ),
    712 => 
    array (
      'sha256' => '7a1911107d3ba064a31cf71f44fed2cdd14e4c619431cd92f5fe23f6b4472b90',
      'label' => 'bs4p4.php',
    ),
    713 => 
    array (
      'sha256' => '05abf804111ca8c5b16ddc28f51111e55012a387e7366fd1e7ce23db94f85153',
      'label' => 'yvdrr4hj.php',
    ),
    714 => 
    array (
      'sha256' => '67c99d6ae044be373738285377481111863f4308053194edb42bf36e4181d35e',
      'label' => 'page.php',
    ),
    715 => 
    array (
      'sha256' => 'd083aec8710f34d5948cbf1a6b2610749f3e15fedc08ab82fa7ee1a538bc5ca5',
      'label' => 'iwcbtmor.php',
    ),
    716 => 
    array (
      'sha256' => 'b8fda6def3f8096c49c2b36360943131e1b59a7a103f052e89418a950c65da9d',
      'label' => 'bjltushm.php',
    ),
    717 => 
    array (
      'sha256' => 'c33eb53ee3c9046f470f53196aa2ee946bc473b665523d7b4f9ac0cffa1e88b4',
      'label' => 'index.php-c33eb53ee3c9',
    ),
    718 => 
    array (
      'sha256' => 'b46e52c18d47e2893fa368b138e85da899b811621ad2ee7c7ee739291aa88f95',
      'label' => 'FacebookSignedRequestFromInputHelper.php',
    ),
    719 => 
    array (
      'sha256' => '33958f8004a1b8ebdfa0873cf411b38d4ccbb4b7de8339be5db632c91e74767d',
      'label' => 'FacebookResponseException.php',
    ),
    720 => 
    array (
      'sha256' => '1061b0d6476089bb5669a056365fc42fdab0060dff0388815a59332890b71d22',
      'label' => 'index.php-1061b0d64760',
    ),
    721 => 
    array (
      'sha256' => 'a63e4c2845ac71d85d155a8d1719f8854e21476de8f5f141a3738064e6d56e5c',
      'label' => 'index.php-a63e4c2845ac',
    ),
    722 => 
    array (
      'sha256' => '98184f3cb57689422320cedce83325a6d7e71e49ce5ce6192d95e3b8c1315fa3',
      'label' => '8a8spqev.php',
    ),
    723 => 
    array (
      'sha256' => 'be09959e4b7d77e78646595e5b593938eefe0b3cf62d696562410ef08063ab10',
      'label' => 'qneyw2s.php',
    ),
    724 => 
    array (
      'sha256' => '06f08b14ac07aa85848b62970f00128695ba4c2b53bbde08c2d22af778cb54d1',
      'label' => 'qneyw1s.php',
    ),
    725 => 
    array (
      'sha256' => '442104ea840a334a70b4f3130d66a94ea000f27d09457c57e45e79cd4dee6608',
      'label' => 'hseo.php',
    ),
    726 => 
    array (
      'sha256' => '4dc53a892e247165eb4dfbfb20a78e70f13dfaa567fe703e05252b9a05fddb0c',
      'label' => 'class-custom-sitemap-provider.php',
    ),
    727 => 
    array (
      'sha256' => 'b67d393d32561a8ee7f1b80111e64bbdccbfe2ec615f9e09f855c1623f75e4c1',
      'label' => 'constants.php',
    ),
    728 => 
    array (
      'sha256' => '092aeca7edac6526f157f475c097f67475aaef953e1e707c4e3ed6818e86a72e',
      'label' => 'header.php',
    ),
    729 => 
    array (
      'sha256' => '50c8aa744554de7044419ad47ccbc46c665d9d45e1b6c158e956aaca60a83b96',
      'label' => 'admin.php-50c8aa744554',
    ),
    730 => 
    array (
      'sha256' => '2a24dd71c199d586231a20d2328b75272bf0dbccc059fa3ddc64261c5a71c873',
      'label' => 'wp-cron.php',
    ),
    731 => 
    array (
      'sha256' => 'be2c7b7e7910a5746b14a09818002ee4b589ab13e5561b036ef23e05bf075bc9',
      'label' => 'wordfence-waf.php',
    ),
    732 => 
    array (
      'sha256' => '47a1187e440bdb04b4538faf9bb9a7238ce31a28f67d807630576bf9ddc5d78a',
      'label' => 'tesTclc.php',
    ),
    733 => 
    array (
      'sha256' => 'e4254d7a9b654236a33da071ae450c74b416c3c2c44f3c50577f03e7bbb67582',
      'label' => 'tester.php',
    ),
    734 => 
    array (
      'sha256' => '250a0c4d7a08785b08600e44c0cdbfee2a47dd7f390a497fa8aa46d396d26708',
      'label' => 'UNZipeRexv.php',
    ),
    735 => 
    array (
      'sha256' => '5009d85c579aa1f8dfb01008ddcd7bb3e03718d2516729225825aef089518803',
      'label' => 'wp-comments-post.php-5009d85c579a',
    ),
    736 => 
    array (
      'sha256' => '0f64fc5fb41b5ef9b2f8af38f599301295a04b07b8f6bac71ba64d297f11bbda',
      'label' => 'xmlrpc.php-0f64fc5fb41b',
    ),
    737 => 
    array (
      'sha256' => '967beeb68e98dbf99a847ee191032dfa9f9a2eac31168d96dee977e3a46b0f50',
      'label' => 'wp-trackback.php-967beeb68e98',
    ),
    738 => 
    array (
      'sha256' => 'db8c6f48682c1edccfc5c7b985b57ca3f6511145d706252a2b2b5cc2b1f979a1',
      'label' => 'wp-activate.php',
    ),
    739 => 
    array (
      'sha256' => 'fad249beeed49dfe2e31f37f4bc47c85f2d5cec0494e0924a516d4de80aaf5fa',
      'label' => 'index.php-fad249beeed4',
    ),
    740 => 
    array (
      'sha256' => '005266b15082e4e156b73484d184e9be424123cbba08787e4d53cf12d79fc9a3',
      'label' => 'wp-signup.php-005266b15082',
    ),
    741 => 
    array (
      'sha256' => 'dbf512154dd375ce298dcc3569a0483112b6c7b60786afcda0ee1669ca263ab4',
      'label' => 'wp-blog-header.php',
    ),
    742 => 
    array (
      'sha256' => 'a090aa5826c35e5ab7cb998b8a0c54884b22ef6d9aa3257681af4d7b85451b7e',
      'label' => 'wp-links-opml.php',
    ),
    743 => 
    array (
      'sha256' => 'cb80f04869691d760a12bdd7ddc6dd57f4ac24371cd825985cc6c501530c29ac',
      'label' => 'wp-mail.php',
    ),
    744 => 
    array (
      'sha256' => 'b70dff107dab9406b56ea7730591e91ac886da8ee7a69a7f2c8a63230796b2ec',
      'label' => 'index.php-b70dff107dab',
    ),
    745 => 
    array (
      'sha256' => 'a47d1ce2b9829068584579c82fae4a279a274a4c031cb3ec3a4488843da9ccf5',
      'label' => 'exprt-personal-data.php',
    ),
    746 => 
    array (
      'sha256' => 'f37cc420165fb809eb34fbf9c8bf13236a0cc35dee210db5883107a08a70f66d',
      'label' => 'class-wp-page-V3pnwS.php',
    ),
    747 => 
    array (
      'sha256' => '7877e43973d1d831a48cdeb6701f49745101cfc2f9da0722b021bf873ff66e04',
      'label' => 'breeze-minification-fonts-V3pnwS.php',
    ),
    748 => 
    array (
      'sha256' => 'f9cba24a1729edbe0d3345168e91e87741a42b0487c75ac00bca982e8d4c298b',
      'label' => 'index.php-f9cba24a1729',
    ),
    749 => 
    array (
      'sha256' => '46cb57fdf65bbfe62698fa532ac02bdce9f9a12ebf5c025cafb31b116ea3fc17',
      'label' => 'Wait.php',
    ),
    750 => 
    array (
      'sha256' => '917a5033203b651f8247170aa0893c67d31ec09fdc5d63b7ddf57344330e47ff',
      'label' => 'index.php-917a5033203b',
    ),
    751 => 
    array (
      'sha256' => '9b86cea9f8e9014fdf7eafe6e3679babb0f53194fa1918bd4157ffe28cd67583',
      'label' => 'help.php',
    ),
    752 => 
    array (
      'sha256' => '7582d2e480747fdb7f12950f6f989830db4e67c4913685a384011ada15f197b4',
      'label' => 'style.php-7582d2e48074',
    ),
    753 => 
    array (
      'sha256' => 'bf2e6d571306a0e30242bac2fafe4fd53ceee9642e0e1848a7a560f812d8f95f',
      'label' => 'sec.php',
    ),
    754 => 
    array (
      'sha256' => '34736edbba99378cd9bc314d4a013c6bfc22b8749bf5c0566fc9f4bf042296be',
      'label' => 'idnsecmqvr19.php',
    ),
    755 => 
    array (
      'sha256' => 'afb515af57dba857f3e96858ff0ba05917eb32b85e112f4428467bef65a25a83',
      'label' => '__xmlrpc.php',
    ),
    756 => 
    array (
      'sha256' => '87542a7bd3b81abe08ea38f038baf0f0a9054bde2d0b739f0660543863edec7d',
      'label' => 'index.php-87542a7bd3b8',
    ),
    757 => 
    array (
      'sha256' => '7c1839cab3b5cf47dba5192883c347bbc69e9e70b16e706b20d11d3c78022c31',
      'label' => 'ltzsucuv.php',
    ),
    758 => 
    array (
      'sha256' => '9fb8712b765d7822e4a6aa1f677367ab60b76581f533df6ff0cfdfe47857763a',
      'label' => 't_file_wp.php',
    ),
    759 => 
    array (
      'sha256' => 'afe7569beeec110b771081710a91edc395c193a674fdac8abb5cd90480e14904',
      'label' => 'wp-core-module.php',
    ),
    760 => 
    array (
      'sha256' => '1069fef56ccb398f5fe0c830df7f574ef533ac3037fe8650bce62311a034b6da',
      'label' => 'tmmavqhr.php',
    ),
    761 => 
    array (
      'sha256' => '5c63c3694188f1f7b618a09c6fa6ff82227f72b624be2058e5022ab6d4228e69',
      'label' => 'index.php-5c63c3694188',
    ),
    762 => 
    array (
      'sha256' => '43861e735c67742d8b5991b0a612b76427893c06bfbf148242568cd7e2434f46',
      'label' => '5euqs1ia.php',
    ),
    763 => 
    array (
      'sha256' => 'fbaf444371f88d5a3d73f10a11d0eb68914bda421832939d4aa799dcee9e7727',
      'label' => 'index.php-fbaf444371f8',
    ),
    764 => 
    array (
      'sha256' => 'b46025244ba8de95793e73e64e1a0ccc38c89113a10bb4c2933ba2b4551f34ac',
      'label' => 'rlxdkieh.php',
    ),
    765 => 
    array (
      'sha256' => 'a3e6eac5089bfebd663faa2b3812807653562d6a0c0fff1268590f0057b1f0bd',
      'label' => 'wp-blockup.php',
    ),
    766 => 
    array (
      'sha256' => 'db0d4ec68f873e487acb663991b08a7e9c79d5826bd158eb2c8bd19d86dfa93d',
      'label' => 'index.php-db0d4ec68f87',
    ),
    767 => 
    array (
      'sha256' => '3ca0c55fe9acc08a15dc607959b10c70c6e6fde485dc6315829b9248256caab0',
      'label' => 'index.php-3ca0c55fe9ac',
    ),
    768 => 
    array (
      'sha256' => '68da34849479ecae684ac023ed5e9aefa5d34f6920686552c32e1c33fbb6314f',
      'label' => 'backup_pan.php',
    ),
    769 => 
    array (
      'sha256' => '0c8feebe4743eb44a427fb00ed7511f5b0de961c0ce9963ddfb67ff350eb8616',
      'label' => 'phpinfod.php',
    ),
    770 => 
    array (
      'sha256' => '0f9d1103f72f23d1729fe1c2f90682d28be36bee25f08f1e203c2f6827a1b9d5',
      'label' => 'informtv.php',
    ),
    771 => 
    array (
      'sha256' => '02c485ef77d85fd92fad116f9b81f0532a08e49418b57495f8130db0f091f2ce',
      'label' => 'index.php-02c485ef77d8',
    ),
    772 => 
    array (
      'sha256' => '615efa3c9b1edbe16c15b20559793e82def16d81f85f281aaa09a0ecfd71f368',
      'label' => 'index.php-615efa3c9b1e',
    ),
    773 => 
    array (
      'sha256' => 'bf589447e800f3571ba482286edef954101840256f8436da621a5b66d0b9b56a',
      'label' => 'k5kxoxi6.php',
    ),
    774 => 
    array (
      'sha256' => '9b3bb32ae44af35ee13bb47bfd6353a775f2f8f93b3b5c38633687562c17c90e',
      'label' => 'index.php-9b3bb32ae44a',
    ),
    775 => 
    array (
      'sha256' => '00242d402799f8e7f8cc6dfb19aa815d569a40c12a6becdcee1f18c06e7fde04',
      'label' => 'zend-fonts-wp.php',
    ),
    776 => 
    array (
      'sha256' => '5074ca026842658a5f2f0aaab52bc912e29c06659ee36e13f4af884c186b43e4',
      'label' => 'class-controller-link-resolver.php',
    ),
    777 => 
    array (
      'sha256' => 'e9d4ee9c43668dc574a51616ce23cf7053c33d65e05f2466764303585526a891',
      'label' => 'class-lazyloader-diff-kses.php',
    ),
    778 => 
    array (
      'sha256' => '117b81cc70d32dd8aa23a28edacd3705c8b339c6aea29fbc146367357170c1d3',
      'label' => 'wp-plugin-saver.php',
    ),
    779 => 
    array (
      'sha256' => '4e6f16a8f7663f4413157e937a6bce7f19d09442696ea1520e1f44afe22852a0',
      'label' => 'unzip.php',
    ),
    780 => 
    array (
      'sha256' => '9e662346168afc2448ce3fc7c7db1a825ee74cdc7c0136b3c8bdd2b9c27265c0',
      'label' => 'leafmailer.php',
    ),
    781 => 
    array (
      'sha256' => 'ee3b86daaa46733499bc014fee9c51b30863118dfab4535521f70e0e5c570027',
      'label' => 'orvxshell_v2.php',
    ),
    782 => 
    array (
      'sha256' => 'ad6ad4544ec69c8295337fdfebfaca65979596e2371b9158a26a7684485706c0',
      'label' => 'cp.php',
    ),
    783 => 
    array (
      'sha256' => '49c41fd8c0dbca9e56be2b5a2ad18fed7b624acfdb60f6b8d4439193e1afa356',
      'label' => 'mailer787655.php',
    ),
    784 => 
    array (
      'sha256' => '9fbb88a0a52ad3fb9d733b4fae6d32ac4bfb25549b3f8cdbbbb6fd1ca677ca9d',
      'label' => 'wp-config.php-9fbb88a0a52a',
    ),
    785 => 
    array (
      'sha256' => '56fe2502f2ed1c9c803300cdaa25377c4a151201c0ba07926382e84b76cabede',
      'label' => 'class-widgets-rss.php',
    ),
    786 => 
    array (
      'sha256' => '034abe058f39ce0b2aff1a5e07f2dc7d69b40be92c6c3fc89d327ed7d1835691',
      'label' => 'index.php-034abe058f39',
    ),
    787 => 
    array (
      'sha256' => 'c1a80b6b541dc95a194cb19c4858a3238551237f44d1d4a393864ebcc659395d',
      'label' => 'wp-add.php',
    ),
    788 => 
    array (
      'sha256' => 'c37c07ef19d5ee7e25f5aeedb852b31668ebf6e136798953072bcdbd574f2095',
      'label' => 'license.php',
    ),
    789 => 
    array (
      'sha256' => '24eeb4a0ec5b8a73aefcb8ec0d0fc4dac158ddfd26a9c1ecf73fca86adb2ef4f',
      'label' => 'app.php',
    ),
    790 => 
    array (
      'sha256' => '0295eb9720cfd412fabfceb99ba7a8527a327b530a912c2d8faa1bdab359b4f0',
      'label' => 'config-vars-rss.php',
    ),
    791 => 
    array (
      'sha256' => '0e9da8b87303ede5d6f1a9897cead59f1c43780e1b5de1b7798235e3ce18756a',
      'label' => 'index.php-0e9da8b87303',
    ),
    792 => 
    array (
      'sha256' => '06a0b64476c8cf6df23b5ac92a9a7c1b392c9835fae0b7409c8612219f1b9b29',
      'label' => 'class-site-style.php',
    ),
    793 => 
    array (
      'sha256' => '2170814f1b0ca1546f0f45ac87b7a139f489eefaf7593d412bcfeec4476b2e84',
      'label' => 'init-widgets-locale.php',
    ),
    794 => 
    array (
      'sha256' => '24d3b7ba41637ce6237d13923c7d5a69bfd532d331a20d53e8416dfaafa952b7',
      'label' => 'index.php-24d3b7ba4163',
    ),
    795 => 
    array (
      'sha256' => '15c1cd64cfc9b9fb95b60460d1eda50829b9bbc546dc4c681f227b0dcd1b781f',
      'label' => 'class-load-settings.php',
    ),
    796 => 
    array (
      'sha256' => '2707df93a5416e832679f8ca434952c082a4d4680c97c82f62aa98a0181f7507',
      'label' => 'wp-blog.php',
    ),
    797 => 
    array (
      'sha256' => 'b119446f55867066668bc402ae0f2648155bebc0a7cdd6e710ee018974e9a774',
      'label' => 'index.php-b119446f5586',
    ),
    798 => 
    array (
      'sha256' => 'b5a333308408bf5b247b75ce0139b00717198b31812595bdf7c30e1e12c3c289',
      'label' => 'style2.php',
    ),
    799 => 
    array (
      'sha256' => '50ef30f2305cf512651310a45cfa64475922da9dc9f02e43e940274e9fba58ed',
      'label' => 'xpxzko.php',
    ),
    800 => 
    array (
      'sha256' => 'ad54cc4bed81fe91d9b8b50a2161b7b56dbddd3faf8394ec6975dcd739ae9f03',
      'label' => 'lang-rest-nav.php',
    ),
    801 => 
    array (
      'sha256' => '272fae2667dd9ddffa75d4e2b1f1d3264b0580ed268073026aa53059e5a570ba',
      'label' => 'expect.php',
    ),
    802 => 
    array (
      'sha256' => '96b2fd797f953e9ce4010fbb6718498fb00dceec080351b4af96751cd4d33afa',
      'label' => 'api.library.php',
    ),
    803 => 
    array (
      'sha256' => 'a70650dc84074d149209e53d9fba768e17ecd4eda90c3d2216c7b605bb87bcd6',
      'label' => 'config.widgets-nva.php',
    ),
    804 => 
    array (
      'sha256' => 'c6bcd64ab0236bce546adf04b5c2a50d851a296ddd300bac92ec3a60d6cc83ad',
      'label' => 'index.php-c6bcd64ab023',
    ),
    805 => 
    array (
      'sha256' => '592338e4b5988924d5a2269b3ea18c03fed602c004c1d712b34b5d5b9694c44e',
      'label' => 'm.js',
    ),
    806 => 
    array (
      'sha256' => '0c51e99162f1073f2ca61949089d58275ff2c6f24d6aee87723a6ce607c89e2e',
      'label' => 'wp-links-opml.php-0c51e99162f1',
    ),
    807 => 
    array (
      'sha256' => 'a44f13e245eb8c4e102e3dda1c20c1208cfe53f17f575686ba7c862b21aab155',
      'label' => 'bs4p4.php-a44f13e245eb',
    ),
    808 => 
    array (
      'sha256' => 'fd3cf8a6fcc9a61313f950406344f5995f2523ce3ee9c499ecf844dd391111cd',
      'label' => 'zskdnqbg.php',
    ),
    809 => 
    array (
      'sha256' => '509b47c3ba97a8429269c63b2c43ef2c520194fb938d3d88b467dbdc4adff882',
      'label' => 'page.php-509b47c3ba97',
    ),
    810 => 
    array (
      'sha256' => '2be1d77a678940fb0a65f2aeb33ab37864156019126a4c4d275ffd0b905f7653',
      'label' => 'password.php',
    ),
    811 => 
    array (
      'sha256' => '08b65ed2e442b34c419150af1022910da53cbf9217d275c2f58b659e21e4d9d7',
      'label' => 'tjfljguv.php',
    ),
    812 => 
    array (
      'sha256' => '0cd1d9543f31193cedf133cd210c2be73275ffe486d221b41ecc7d23f478cc36',
      'label' => 'class-wp-page-1402421133.php',
    ),
    813 => 
    array (
      'sha256' => '6f6a1e6719dca5801ba898022c7a980709cc6f4db0305027723fd69e5335f872',
      'label' => 'assets.php',
    ),
    814 => 
    array (
      'sha256' => '1c7e412b74dbc2086bab35fd5feaf2d2d2923ff97942e77d96bb68c029fe148b',
      'label' => 'wp-active2.php',
    ),
    815 => 
    array (
      'sha256' => '393fc77a29485701d64d81bccc78842582a6f1935c75652b1654c8258f079204',
      'label' => 'wp-vcd.php',
    ),
    816 => 
    array (
      'sha256' => 'c11628a11b0253364ac086a26e6a3024d6ed85c9c4327a4f5938e662226e3dbd',
      'label' => 'wp-tmp.php',
    ),
    817 => 
    array (
      'sha256' => '7f60da2ec762677c4a7139494845252a30f2dfb2cacf6006444d94f7c7a9f798',
      'label' => 'wp-feed.php',
    ),
    818 => 
    array (
      'sha256' => 'eee648be6389b8897771baebafea52284f0e2afb522ea8a47ebf565095f69914',
      'label' => 'function.php',
    ),
    819 => 
    array (
      'sha256' => '22fcb2dd5802c7b28fe59a1bbfdef3cfa964555563b3e97a4ac35d02934926b8',
      'label' => 'index.php-22fcb2dd5802',
    ),
    820 => 
    array (
      'sha256' => '5f41092c08c6cfa182afceea7afc84ac4b53996d5328f18b4ee906bc574c4d38',
      'label' => 'mindex.php',
    ),
    821 => 
    array (
      'sha256' => 'bcea9ad0eda2cf075aa51b18c25f304886d38d80202c40854908c0e38147c2d1',
      'label' => 'indeex.php',
    ),
    822 => 
    array (
      'sha256' => 'a3de51b9239da6e2b4499917067d29b22af23a6f53a88749e8af05fced0bf656',
      'label' => 'liyava.php',
    ),
    823 => 
    array (
      'sha256' => 'fe375b386fa0be9d3f7568f3aa18c2d8cfe50289bed6e94e4cd6e7664701f415',
      'label' => 'index.php-fe375b386fa0',
    ),
    824 => 
    array (
      'sha256' => 'eee9487ba63e6f0d83073dd6e62ede22fa5b8d46044417ba49c7a42e9e7f50e1',
      'label' => 'wp-ngising.php',
    ),
    825 => 
    array (
      'sha256' => '789a03434716e9035efecbbf2f00f68a00bd7aa97339bec07bf1737543fa7aca',
      'label' => 'UNZipeRcba.php',
    ),
    826 => 
    array (
      'sha256' => '9ecfa5cfbbbc30dc2170761f7732ca2b2703669985ace2443fdc5a12c939350a',
      'label' => 'anti3.php',
    ),
    827 => 
    array (
      'sha256' => '18fc6ba2dfac1d050d74e99e32ae3605178197525be991e2a3096f57aa7bbea2',
      'label' => 'processing.php',
    ),
    828 => 
    array (
      'sha256' => '383d27761abc5bca411e3ed4e1428e540857bcdf48990bcc3ccc02c9a12f974c',
      'label' => 'secure.php',
    ),
    829 => 
    array (
      'sha256' => '6c7f21e2ac1f38c9d16ddd6bab72ebe08d16fa06140b1469ea982d2b791f3ab7',
      'label' => 'email.php-6c7f21e2ac1f',
    ),
    830 => 
    array (
      'sha256' => 'eb6c28e64fe93413c7937fb2aabfc876b370040195ffe8feae3ffdca2623aff3',
      'label' => 'card.php',
    ),
    831 => 
    array (
      'sha256' => '8dc8acfc528d92796e826d04b5561bccb8f38ab9c712ab7aa8b399798bf699fe',
      'label' => 'process.php',
    ),
    832 => 
    array (
      'sha256' => '6d8fd1dff29a21e0996fb51330422f12073b885a1cc798c3f40045177790e448',
      'label' => 'information.php',
    ),
    833 => 
    array (
      'sha256' => '1b2dd520c08fde8e1078898e85d979b61a9162443a6d3ecf3dae004564afe240',
      'label' => 'process3.php',
    ),
    834 => 
    array (
      'sha256' => '939bd444d5aa13f517924a22dab32692f4edba84105738943d9a3a12067582ed',
      'label' => 'anti.php',
    ),
    835 => 
    array (
      'sha256' => '18f83aa7b4767d5af3f9db320cdfc5bbc76139a5769e1b8237469bd46facf390',
      'label' => 'index.php-18f83aa7b476',
    ),
    836 => 
    array (
      'sha256' => '2675db3cb8e73d3b703d658965a949ff5391938b9f59fd2fec5461fef923a359',
      'label' => 'bt.php',
    ),
    837 => 
    array (
      'sha256' => '7c79e6ed121fd461386a6306e2ecf3775fdfa4b349f33e21fded26a75fad4636',
      'label' => 'redirect.php',
    ),
    838 => 
    array (
      'sha256' => '9659c1378ecf80c5c6d7b6cd37bea342fcc48eaa365e0e195b39e1c56f71fdd6',
      'label' => 'process2.php',
    ),
    839 => 
    array (
      'sha256' => '47a27ab5cb5a5cf7c3e61ce63477281bfed365537625f6b0b45e891ca016866c',
      'label' => 'tesTrwn.php',
    ),
    840 => 
    array (
      'sha256' => '30f9647f19911f33293cc7370e867cecec599d867cd43f73b2c76f9ab8b07e28',
      'label' => 'index.php-30f9647f1991',
    ),
    841 => 
    array (
      'sha256' => '9f0193a0e063ad15099f52a0d0281ff91daa19b46745826b7ea7192f4aaca024',
      'label' => 'up.php',
    ),
    842 => 
    array (
      'sha256' => 'aef6428f2545bd385d36290225b6616c50e7f8bf3bf0f6d61bc5cad28d1ea2f6',
      'label' => 'bmpjxdxukl.php',
    ),
    843 => 
    array (
      'sha256' => '368bf51be848a9625f92756d84f10afd6929ffe1122c47a62e43bfd1911030ae',
      'label' => '1zx.php',
    ),
    844 => 
    array (
      'sha256' => 'b2c090880c17b3feeb1c3eb31a5e370c716e3eb04c9e22b8ced6c2141ea77f9a',
      'label' => 'File.php',
    ),
    845 => 
    array (
      'sha256' => 'e87e66de3e23fe916721fff55f4b254c50f44d76910d447e82eb62c4a8a60a70',
      'label' => 'inbox.php',
    ),
    846 => 
    array (
      'sha256' => '202c5d56c3d2db767a511d5cf8b02f442eeeb8cc4d0dce46f91479f04dd2ab15',
      'label' => 'exhibitions.php',
    ),
    847 => 
    array (
      'sha256' => '88a7ea92c4581453b70eb45e9c2f444581a4bcd05f34a232a46894f70135e2a2',
      'label' => 'Util.php',
    ),
    848 => 
    array (
      'sha256' => 'e22d6d966b2d43a3bac221543d7ecf5537365d8aaabec528b1fd998a7c1e3917',
      'label' => 'rvsStaticWeb.php',
    ),
    849 => 
    array (
      'sha256' => '5e2e5c7ae41f045eba5721ca7f97b6bc0063fbda6ef42792a13402e8efe8c848',
      'label' => 'djlnlypiqz.php',
    ),
    850 => 
    array (
      'sha256' => 'a92756bc232b9a967cdb937178b4979abd6595d20cd4f62b025467f58c43812b',
      'label' => 'index.php-a92756bc232b',
    ),
    851 => 
    array (
      'sha256' => 'c16812297475887562b8e83ab2e0556779e189639062dd286afd9893ef6e10fc',
      'label' => 'admin.php-c16812297475',
    ),
    852 => 
    array (
      'sha256' => '0c53b6805130b800200cbb3b06ac00313404954b823bce018a5ed20fc82e7545',
      'label' => 'wp-info.php',
    ),
    853 => 
    array (
      'sha256' => 'd5d0d216c84324bad30b786799891c6389d5b87fa55a9c990173913a0de106e1',
      'label' => 'Apc-metaclass.php',
    ),
    854 => 
    array (
      'sha256' => 'dba4ab71bc2a4fe1a5276a53229332553b041c2d75c8b147ab18acafe3fe6e4b',
      'label' => 'ntlm_sasl_client-new.php',
    ),
    855 => 
    array (
      'sha256' => '14a6c4b6a93eddfc3f82892c39c04dfb8a758224f89a261b6efbc4faa0f406bb',
      'label' => 'new_random_bytes_mcrypt.php',
    ),
    856 => 
    array (
      'sha256' => 'b7945e2e3fc7392ed297f638733498ca24074598d4174845085128c3ac4dae16',
      'label' => 'cpl.php',
    ),
    857 => 
    array (
      'sha256' => '073419264ddd7ae14e94c86ba80376795f32a953e04a70d7b50b1927d94ab111',
      'label' => 'index.php-073419264ddd',
    ),
    858 => 
    array (
      'sha256' => 'd9951fb2c13e701a567c341fd68d4408f04b6df2fbb4d19da4440c8c71db0b5c',
      'label' => 'ysuqwwxvwr.php',
    ),
    859 => 
    array (
      'sha256' => '0daaf7d600a2c78db4c8c78f89a6e9b489a3429ec20b8a515dec8de16116cc60',
      'label' => 'frGpoHxuaA7.php',
    ),
    860 => 
    array (
      'sha256' => '73d3cc8297d507cd77e14b134cbff7dd4af7aae59e79e1ea17774a6a2bd728fd',
      'label' => 'cyuzfpxtha.php',
    ),
    861 => 
    array (
      'sha256' => '6c447338ba2ad7b0b465d0f1cdd51393b60b966a51c1f0883e2de7858858edca',
      'label' => 'jwqykjspax.php',
    ),
    862 => 
    array (
      'sha256' => '4656bc9b53ae3946e63e6d138c053f8301e2ab1fad7fd026c7b920f533a6ae09',
      'label' => 'aenvgpzkas.php',
    ),
    863 => 
    array (
      'sha256' => '13447ceff51bc16e5faa68d6e4e787d6c41a4f52667d702e27f8cf0226ae8030',
      'label' => 'C1iWuOpXDSZ.php',
    ),
    864 => 
    array (
      'sha256' => '230b59ca1403b68f8a2d2a2a4b5d97dee3b0a4ada6fe398a17877a84b697b41a',
      'label' => 'index.php-230b59ca1403',
    ),
    865 => 
    array (
      'sha256' => 'd56aaf12bf19a5abdcfe8ee181f8d552975da124562f6bd2741c512c36c8ac55',
      'label' => 'option.php',
    ),
    866 => 
    array (
      'sha256' => '61266f1f8d1ad404622e991f284c5683d9f8a5bb17926b1afffc86d394a13fc8',
      'label' => '4.php',
    ),
    867 => 
    array (
      'sha256' => '6d2e20cc2018d26f95ad54ca904782694b7c30c672d24f27dbd26a89c800e1b3',
      'label' => 'class.qle.php',
    ),
    868 => 
    array (
      'sha256' => '907ed3c7c802d0d7a352ded9ba71cacd9e2a310858436405db2e5fa2270c655f',
      'label' => 'skip-link-focus-fix.js',
    ),
    869 => 
    array (
      'sha256' => '8b4d1c18acf57131255afc903d4daa650bc55a8f31c1d5866690e3099817818e',
      'label' => 'export.min.js',
    ),
    870 => 
    array (
      'sha256' => '8533444fe951b0f0a5314df4f70a125d67c62aa1bc401d9df96e1fa50d65a3f9',
      'label' => 'updater.min.js',
    ),
    871 => 
    array (
      'sha256' => '51d669540b77a71b36527cd8f6ea9565448e9e966fb2174417c60dbd40c5a3a5',
      'label' => 'mk.js',
    ),
    872 => 
    array (
      'sha256' => '39b6dd791fa0a8991c64485f3a9c121e155113aa51092b2c8d0f2597eeb28025',
      'label' => 'file.js',
    ),
    873 => 
    array (
      'sha256' => '47ad58376b7991a2451a9824a5a57255419acd1ef51f4df789e43a68678b191c',
      'label' => 'datetimepicker.min.js',
    ),
    874 => 
    array (
      'sha256' => '4816069d193392ee356eec511849291fcd1166c1e177c149574094a66750f453',
      'label' => 'sortable.js',
    ),
    875 => 
    array (
      'sha256' => 'c80ef693761b1a45307747739cfa10849e3179c260572bbda62ebf4c6a04af38',
      'label' => 'fonts.js',
    ),
    876 => 
    array (
      'sha256' => '151a73d7f1fd97f36a2501f974b69687eecb3c9f444f430d0001e230582778b7',
      'label' => 'options.js',
    ),
    877 => 
    array (
      'sha256' => 'defa8ea491df9cc9132acc220b028c59a1f0ec556f633178564b9d12a564e898',
      'label' => 'jquery.cookie.js',
    ),
    878 => 
    array (
      'sha256' => '786946ec21cd359df83addeb05a071eda9715fed1e9524a8f8049923f48c1a5a',
      'label' => 'form-checkout.php',
    ),
    879 => 
    array (
      'sha256' => '84ab69fcbfd831b3b1ccdc72db31a7b4d1e18f8f54b34b66c1e0381bde469eda',
      'label' => 'admin.js',
    ),
    880 => 
    array (
      'sha256' => '498822ffa11554eaec44317c763607fce8020ca9a86f1fdf3905c075502b5579',
      'label' => 'index.js',
    ),
    881 => 
    array (
      'sha256' => '63db855715cfa2db6ebe5d8baaac317856fe815c3818458032fad8e0565e30ac',
      'label' => 'wp-blog-header.php-63db855715cf',
    ),
    882 => 
    array (
      'sha256' => '9c76e1a44f3a51bf368e4b0f5f8a7ae6ca81a2ff3d92a8ab7d142b832e7d4b10',
      'label' => 'vars.php-9c76e1a44f3a',
    ),
    883 => 
    array (
      'sha256' => 'fe6183d6a520b098e65c27f43cff0f1dede761e52b6e3b323ad4620c0cf32bf3',
      'label' => 'Chitoge.php',
    ),
    884 => 
    array (
      'sha256' => '6ee0f09face74c07764c95f66db526c363c7ded68412ed793cc1846bb34e090b',
      'label' => 'index.php-6ee0f09face7',
    ),
    885 => 
    array (
      'sha256' => '55725575cbdb72d2ceee778ef9770fd3bd74f31fddccdecfea6a65fe37b8ff8c',
      'label' => 'th3_alpha.php',
    ),
    886 => 
    array (
      'sha256' => '3dade2dc8eb17b8e59b91798311dad4009654e86d63d74b2224be360936dfb29',
      'label' => 'admin-post.php-3dade2dc8eb1',
    ),
    887 => 
    array (
      'sha256' => 'c9e8692892e4e009639a6a1115952371902496435b0785f4e4b0c13a61b4acc2',
      'label' => 'template-tags.php',
    ),
    888 => 
    array (
      'sha256' => '5d1252f9af1d5d70ab881c05e91ed92d707d2fa718ade3317c3df42b45694b88',
      'label' => 'index.php-5d1252f9af1d',
    ),
    889 => 
    array (
      'sha256' => '0cb6137947696084e471d083a44f7fb6753a7a38c627f43f786f386758790b98',
      'label' => 'index.php-0cb613794769',
    ),
    890 => 
    array (
      'sha256' => '75b9a9f6e6c17c422d8937024d33409fe3021b0160c5a31ee01c354bc60ff4a5',
      'label' => 'uwes.php',
    ),
    891 => 
    array (
      'sha256' => '7ba131ccb61ee936a1e7a6d4a5e9fc35f7f305513c69b3c3d4924430e28827c3',
      'label' => 'profile.php',
    ),
    892 => 
    array (
      'sha256' => 'b233bf689ce17776048e0f04d90b084eb3e7722a929ef129eeb5df1fa46e525f',
      'label' => 'index.php-b233bf689ce1',
    ),
    893 => 
    array (
      'sha256' => '8da06159f1cfaf6c5901b3babcf6f3de540c3600d4fa4dca043026f1f5ea9477',
      'label' => 'aovrk.php',
    ),
    894 => 
    array (
      'sha256' => '0b16e162ef0c17a46459d4c6f99ce794948091350a41eeef0a9465427a54685a',
      'label' => 'index.php-0b16e162ef0c',
    ),
    895 => 
    array (
      'sha256' => 'c35923cfa16ea6464350108e3ff96a43f644fb138c1709241deeb86fa6a0b329',
      'label' => '404.php',
    ),
    896 => 
    array (
      'sha256' => '2c80454bb47dd929d6260088a616779e183304cf2a6f1b61a2f78a9ae8fbb43d',
      'label' => 'trleasif.php',
    ),
    897 => 
    array (
      'sha256' => '3b7a70c5d6ec8bf614d3d7dcdc9addf5d69ee5e1cab1b1cac42701e71ebbf3ea',
      'label' => 'nrpjhuxjju.php',
    ),
    898 => 
    array (
      'sha256' => 'cc9b7542150296a3421a89002abb7d4d1ba18558c4b21886d85412b267629bbb',
      'label' => 'log.php',
    ),
    899 => 
    array (
      'sha256' => '08b85899e33bcbcd770aed84bed6782faf41aa971d8ad7c6ab3aa3739c50a236',
      'label' => 'delete.php',
    ),
    900 => 
    array (
      'sha256' => '5ca95be8f36d411448cfbae14a9e329073f5ae29c6ccd99840d5fd1c61c96d79',
      'label' => 'config.php-5ca95be8f36d',
    ),
    901 => 
    array (
      'sha256' => '573f9fdc9faf8f9611c57bf74eadcfb474831056d4147b73e5c1a9809c22ec38',
      'label' => 'surf4.php',
    ),
    902 => 
    array (
      'sha256' => '0ded5c0f5737b40f84b5b9cca3b7a1b8444ae50d1f491c49718f0b37afae77e0',
      'label' => 'surf5.php',
    ),
    903 => 
    array (
      'sha256' => '6b316aedc5deece1c2a921572343f298f65555e1a785c8650a783dad763c019b',
      'label' => 'need2.php',
    ),
    904 => 
    array (
      'sha256' => '7ab390f7717cfa3ce462625d7cefcb12ce1f40b778ccda2a540e953318cc50be',
      'label' => 'need4.php',
    ),
    905 => 
    array (
      'sha256' => '243dadf5e6a60546aeaf962a5bef3cb91d3ad163973c92406e4a3ae5a5319a51',
      'label' => 'mmsuauen.php',
    ),
    906 => 
    array (
      'sha256' => 'c10391b3463ed75ab25a899c9dda52bc77f1949cd4e8ccaf299e1c1162bd3d6e',
      'label' => 'email.php-c10391b3463e',
    ),
    907 => 
    array (
      'sha256' => '6d03c0d03f2bde7fa783ce05f70bef826ba30d8655ca8d1eb26aaa52fca7bab7',
      'label' => 'need1.php',
    ),
    908 => 
    array (
      'sha256' => 'eb186a983a02895e381ddc642e56b5f3dced196926502492aa0646099ba8768b',
      'label' => 'index.php-eb186a983a02',
    ),
    909 => 
    array (
      'sha256' => '8385342fd9d61b5ac86f5fce0a2f37cf8a13a2692a4cdddadf48250a97de15ce',
      'label' => 'need3.php',
    ),
    910 => 
    array (
      'sha256' => '4b3c479d160aa2732e6860c14231078556e3ad41f5e2d629ba40a3482b1ab748',
      'label' => 'index.php-4b3c479d160a',
    ),
    911 => 
    array (
      'sha256' => '342c72c8c0c61a31995a3397b68a43f02e27d939a91d65bab54e2ecf27c48797',
      'label' => 'surf2.php',
    ),
    912 => 
    array (
      'sha256' => '322ccfb94813e240dde73e3cdf3fe9afd2b7ce8cf85eb8a124309815ce33b685',
      'label' => 'admin.php-322ccfb94813',
    ),
    913 => 
    array (
      'sha256' => '4116d1ae354bee0d5b5c478e2792582b207d6a6bcc63d95f523fa612982a245d',
      'label' => 'old-index.php-4116d1ae354b',
    ),
    914 => 
    array (
      'sha256' => '6eea2fb01de38d36aa7c5fe55b914c3e505f51665dd21653b7f46265027f7157',
      'label' => '3index.php-6eea2fb01de3',
    ),
    915 => 
    array (
      'sha256' => '33497f11d9de9b5e943668bc10c384aaafde9a23279bf7da95406613babe2ae9',
      'label' => '2index.php',
    ),
    916 => 
    array (
      'sha256' => 'ccc3274276913c905aea2424ad15b35ce4212e5d8c294e649899460796f56473',
      'label' => '8bnw9w1.php',
    ),
    917 => 
    array (
      'sha256' => 'f4ca8b96b472702e8a9e425f77c60b5e0d511d4e45dffbffae2cd17617af8fa3',
      'label' => '8bnw9w.php',
    ),
    918 => 
    array (
      'sha256' => '0b3bba00db3ba526dd951d397d8a925e286e550ae6a08bbdb8f8065567246fd4',
      'label' => 'tzxqoy.php',
    ),
    919 => 
    array (
      'sha256' => '974aa21a15c8fb6e09155c14513226fee02366e88953adb0f0fabb677a86b0ed',
      'label' => 'wpload.php',
    ),
    920 => 
    array (
      'sha256' => '216b4e5531fcc87146d20080e77a75cbf6940f688e584dfde3fafad10c05f08b',
      'label' => 'api.neighbor.php',
    ),
    921 => 
    array (
      'sha256' => 'fb89fa089076aac3c44858debcfc27a4708d4ba88695f89475b0abda38954ab6',
      'label' => 'index.php-fb89fa089076',
    ),
    922 => 
    array (
      'sha256' => '387234eef39e3fa84188219dc3cccd2867669a1e664b078e81d775944643e879',
      'label' => 'kwtwhmv.php',
    ),
    923 => 
    array (
      'sha256' => '15ba955f4ffcbf37187ab485d30c5d5ef0fc77bf637292b52474593d8668c062',
      'label' => 'comment-abx.php',
    ),
    924 => 
    array (
      'sha256' => 'df996e087e68407526438b83fb6ddf13c5f58b1eb7058ba5624d40194fc38862',
      'label' => 'index.php-df996e087e68',
    ),
    925 => 
    array (
      'sha256' => 'f8efeabc625af31b2bf96741d86bfdb41b88a8cae41094527d89ea41e46e4de9',
      'label' => 'dg17bp02.php',
    ),
    926 => 
    array (
      'sha256' => '2aee6507936e3c8c918e99889fa5d1914a836ea9f7618d8702c57321c1b0172f',
      'label' => 'functions.php-2aee6507936e',
    ),
    927 => 
    array (
      'sha256' => '8f472d80203bf60170bf1d5760a04df3fe832978dec23b07c58fcc4cf7e50bd8',
      'label' => 'wp-xmlrpc.php',
    ),
    928 => 
    array (
      'sha256' => '920f23e74825ac48415a8c12c1c4dcdeb74518372006e692ad8fbe0ba7cbad77',
      'label' => 'index.php-920f23e74825',
    ),
    929 => 
    array (
      'sha256' => '5102fa569aa0d1c108060020bf835673553212b5ea806ad59b9853b50842cd8f',
      'label' => 'wp-security.php',
    ),
    930 => 
    array (
      'sha256' => '6329e62c5a9a7101d56aa5b5c150c48e592a7db370e10f14b9a10bb59c4f6e5e',
      'label' => 'dead.php',
    ),
    931 => 
    array (
      'sha256' => 'd4723733346f1731a85355aaec5cb72475f9cc6627f91462a13c9adda9ee365b',
      'label' => 'settings.php',
    ),
    932 => 
    array (
      'sha256' => '81d241b2d84c9b01acdedb1367afbe22707c55a2abf3023bdec12db60bf9571a',
      'label' => 'index.php-81d241b2d84c',
    ),
    933 => 
    array (
      'sha256' => '625d436d80e4f137987c3a87c05c391e20128d92f038dc60867f792699a9ee07',
      'label' => 'Virtualprivatenetwork.php',
    ),
    934 => 
    array (
      'sha256' => '5e1f068021e5215c0e10aa57633b1d1d4e606bd957756e9ee72199944dc677a5',
      'label' => 'servr.php',
    ),
    935 => 
    array (
      'sha256' => 'fda5f7fd110bae5d8de4869aa63895b73a51a4f49fe95900409aed81cea203b0',
      'label' => 'index.php-fda5f7fd110b',
    ),
    936 => 
    array (
      'sha256' => '7c24242ea881938319790a7b51d3084f2b409e4e7e3f20c1f87089e1c59fa67e',
      'label' => 'relogin.php',
    ),
    937 => 
    array (
      'sha256' => '21b0c00f679a0f28d0f6d0851756571b083acb2cb94f7dbbf63c7e1f7d679753',
      'label' => 'card.php-21b0c00f679a',
    ),
    938 => 
    array (
      'sha256' => '2e9cc1615cc108857a3444708002f370495db3dd137262c5c1309ce34bf7ad54',
      'label' => 'index.php-2e9cc1615cc1',
    ),
    939 => 
    array (
      'sha256' => 'dd349936893e64c2af5884138cadd121ab30eb2b5a43bebea003f52f33f50c4b',
      'label' => 'emma.php',
    ),
    940 => 
    array (
      'sha256' => '665fa48a61445a95d9e904bbce787f26f1be0b54b86cdf2d05b4731b288c18d6',
      'label' => 'personal.php',
    ),
    941 => 
    array (
      'sha256' => '7004d5e6d9accad280ace4e0ffe3da164732503d7a18ca84608af855690a73eb',
      'label' => 'question.php',
    ),
    942 => 
    array (
      'sha256' => '10354bb76f116cc1b5fab2a9968e261a95ce508a242ee6c657d8c8988e1acbf0',
      'label' => 'export.php',
    ),
    943 => 
    array (
      'sha256' => 'f4ffb12136e9a40e960acd871699bb0af0c6bafed7050174738162763e5da416',
      'label' => 'ReferralSpamDetect.php',
    ),
    944 => 
    array (
      'sha256' => '011c3c91489ed709f6cd640e823a2acf1171ae7314fdb3c735c7f8fb30ab18c9',
      'label' => 'Headers.php',
    ),
    945 => 
    array (
      'sha256' => 'dc7536e55184af5f1dec8e13b0f362cf04d1768dd5925e6a8cf4ed9d87eb9641',
      'label' => 'SpamReferrers.php',
    ),
    946 => 
    array (
      'sha256' => 'c17b453c2706e6cd58f691688603f7dedecf93924d3f193e1ac0ceba8bd2bc0b',
      'label' => 'Headerspam.php',
    ),
    947 => 
    array (
      'sha256' => 'f96b51f95ac3e51b3c48775cb4526cf2bb6bc2a8dc93fd9eae81a0fdf07f9647',
      'label' => 'AbstractProvider.php',
    ),
    948 => 
    array (
      'sha256' => '8c59be840e2a4f5fd6136810ce24dd08702ebc10bb9b4cbdf4ac1fc1de1a7f18',
      'label' => 'Crawlers.php',
    ),
    949 => 
    array (
      'sha256' => '1bc224f387ee592cf9f303b9c68cbd2abdd3d24b5d851546d795a2639a472f87',
      'label' => 'AbstractReff.php',
    ),
    950 => 
    array (
      'sha256' => '9f0716630313bf7bbb002d43f9c6ddfb89107940a37013e0f92cd73684189a54',
      'label' => 'Exclusions.php',
    ),
    951 => 
    array (
      'sha256' => 'a4bf86fb743d985f94ce468dcb51e9a28a2a21abf5acf38bd8d319f8a348bb17',
      'label' => 'CrawlerDetect.php',
    ),
    952 => 
    array (
      'sha256' => 'dec4fbd3ab0703d51badc623aa44474eb56293bb50cc56154e7140b8d11f5bab',
      'label' => 'index.php-dec4fbd3ab07',
    ),
    953 => 
    array (
      'sha256' => '17c8233d9dc08f89491dd8934b7307eb5138daaa66247e5a42938a45a424c3e4',
      'label' => 'ref.php',
    ),
    954 => 
    array (
      'sha256' => '3392bf45d8df8ce06156d4b1b896b47669f5ecdfe345e21a48ed4e95308ea490',
      'label' => 'bots.php',
    ),
    955 => 
    array (
      'sha256' => '316ee2a18ddf43d333b2f352c8c6794421a5df43dc6289ba25468c2418bfd0ce',
      'label' => 'anti.php-316ee2a18ddf',
    ),
    956 => 
    array (
      'sha256' => 'c6d7693a854cf94571e939e7e2d5e1e41ad6bf32acba1c854731dc28a169d274',
      'label' => 'bot-crawler.php',
    ),
    957 => 
    array (
      'sha256' => '10a5f675234230cf0acd9ad4eb9d2c548af8e9295d20f6484bd4ca3e5d6489c6',
      'label' => 'blacklist.php',
    ),
    958 => 
    array (
      'sha256' => '5eca57c58d6b5861afeee6e300a101b3bc0a1851f309af8667449f5a7d205e31',
      'label' => 'bot.php',
    ),
    959 => 
    array (
      'sha256' => 'ce28ae757d51c8d8bb7b8494a498879e1357a9fda8540149c42fc2690a0bf3f3',
      'label' => 'fucker.php',
    ),
    960 => 
    array (
      'sha256' => '53e62ba836d0681f166f5a98609867b362a6fd57ba57df430211270994b07127',
      'label' => 'ReferralSpamDetect.php-53e62ba836d0',
    ),
    961 => 
    array (
      'sha256' => '0f0c0c92be6a72af5e2b63a9c77e9a047f6b17dece94f1ee47ba4f60e58fd124',
      'label' => 'AbstractProvider.php-0f0c0c92be6a',
    ),
    962 => 
    array (
      'sha256' => 'a5546377dee0ea8f7a1fe4a322c8c40d5d12ab4efe87ddaaa2a57cb2624c3795',
      'label' => 'Crawlers.php-a5546377dee0',
    ),
    963 => 
    array (
      'sha256' => '656b094cd1f9079ae1dab1fd80a71b7feb6e6838978cbc371fce134b23ae9d63',
      'label' => 'Exclusions.php-656b094cd1f9',
    ),
    964 => 
    array (
      'sha256' => 'af0b717ae63ae401767553ffe322d09696adcc5523abb5c0df7fc842186ebf61',
      'label' => 'CrawlerDetect.php-af0b717ae63a',
    ),
    965 => 
    array (
      'sha256' => 'c642c0687019a7dcf5ff13ded7e5bc8329663686662709f5c6ee53fe52a718f0',
      'label' => 'crawlerdetect.php',
    ),
    966 => 
    array (
      'sha256' => '32c30284c0bf76d1372496f5ba28dd9663089f82875f775bff1227e08d619855',
      'label' => 'Antibotcrawlerdetect.php',
    ),
    967 => 
    array (
      'sha256' => '4b733688e8823ff7c83ce3d9983781b733088cb19ed3cd234945d04254d28c07',
      'label' => 'Antibotasn.php',
    ),
    968 => 
    array (
      'sha256' => '3b7fb0e7a32cf4fb9e25cfb1fd5dc746b4ae917e10306c6f96f6d4d7001161f8',
      'label' => 'country.php',
    ),
    969 => 
    array (
      'sha256' => '4ca969c7bd7122e829db6f343ce85f5dba2fd7a0f6166d8c54ad5028b1b14e60',
      'label' => 'blocker.php',
    ),
    970 => 
    array (
      'sha256' => '74d1694a2fd9dda3c59e6bb38e21c261731cb6f14584b66a92f2f6823f839cb2',
      'label' => 'proxy.php',
    ),
    971 => 
    array (
      'sha256' => 'bc1861bb2da730b11987e96985258539304601975312c32b6714e696acb0de2b',
      'label' => 'blacklister.php',
    ),
    972 => 
    array (
      'sha256' => '36be2fea9df6abe9bb0e362b43b637a2e916edd499baa638fffcc09728ee6fd5',
      'label' => 'index.php-36be2fea9df6',
    ),
    973 => 
    array (
      'sha256' => '10e16810dc59bd3049deeac2b3369fffad94e6013fcba9ca81a85495fc7e8fa3',
      'label' => 'lhwbomcdhm.php',
    ),
    974 => 
    array (
      'sha256' => 'ae8ac801ad8a367efb67e62d8f94fece8bf7d4cf502b0dfbdb6e03045f000b5e',
      'label' => 'options.php',
    ),
    975 => 
    array (
      'sha256' => '8f9600c39cffe84e936e3433b91c09d23a06e0cf1d902c0ec9c8c114ee6a1f41',
      'label' => 'gckrn.php',
    ),
    976 => 
    array (
      'sha256' => '94bcc841f8c8c9bbe9fa3db1c0a5436e46c9cabf84e07a3fe9c820da96f44369',
      'label' => 'groupon.php',
    ),
    977 => 
    array (
      'sha256' => '9fbca3e16fd0f83a0bc319f624a6054944bdc931e027fa4b34f7b350df0d81a8',
      'label' => 'index.php-9fbca3e16fd0',
    ),
    978 => 
    array (
      'sha256' => '753519b661cb2c8960c522a8836ba2c5400372cc7f0afff448b47aab3fbd2d2b',
      'label' => 'jebzniotxb.php',
    ),
    979 => 
    array (
      'sha256' => '0b3ba09321f3f5811a6633b90707df44c16888ed69f58d4e84b6507af88371b8',
      'label' => 'old-index.php-0b3ba09321f3',
    ),
    980 => 
    array (
      'sha256' => 'a848f6549693cf78b07c2d2ac0a408d4c9addd2b44f8abcea5f623b6aaa8ea30',
      'label' => 'index.php-a848f6549693',
    ),
    981 => 
    array (
      'sha256' => '9b881004938463d762080030caf49161087fded9f70a2a8cc96268d815fc20d2',
      'label' => 'template-loader.php',
    ),
    982 => 
    array (
      'sha256' => '56163d5aa4336cb70c3b0f8baf828ab6c53d499843638f1655deabc95cecc231',
      'label' => 'POPA.php',
    ),
    983 => 
    array (
      'sha256' => '840211d51393a03c3496524dae3f1e58975055bc477369cdfbda9d164194bed1',
      'label' => 'see.php',
    ),
    984 => 
    array (
      'sha256' => '7e02711ce4f5ed1ec9fe4cbd1d6147855025b37c8f917f784c20d1021312a60f',
      'label' => 'WSO.php',
    ),
    985 => 
    array (
      'sha256' => '7df7347460bf776e0b516914f3d7aab910afce14b080aebd7db9ab2334d264da',
      'label' => 'sdf00.php',
    ),
    986 => 
    array (
      'sha256' => '2def4fd8a8e1840f10ca074a1de6fb633f812f690719ae59a758541cc94a0099',
      'label' => 'system.php',
    ),
    987 => 
    array (
      'sha256' => 'd5a9dbf0c7fb2bffc87c13c9ed7b5a5e6a1ec80ecce9288f799dd2d89e9f8033',
      'label' => 'license.php-d5a9dbf0c7fb',
    ),
    988 => 
    array (
      'sha256' => 'f6b7166e50bc5bda9211cd30bb94f2bee604eecd8cfee15661e317f15e7eaad1',
      'label' => 'domain.net.php',
    ),
    989 => 
    array (
      'sha256' => 'a36c0877b1da282068191b4ca125814dcb24b642a4419d56cbc24d8b98b55170',
      'label' => 'sm.php',
    ),
    990 => 
    array (
      'sha256' => '4f3f91727489a54a36415af3bdfdd540affb3be461fa4ec424f95eb22e5ccc6c',
      'label' => 'melara666-FIRA.phP',
    ),
    991 => 
    array (
      'sha256' => 'ecad7d5b957f49192899780ce1b31a085dd7251e0c6492674e912a5da4e4c035',
      'label' => 'wp-config.php-ecad7d5b957f',
    ),
    992 => 
    array (
      'sha256' => '8aa07ba8efaf731d289abc7584c9555af7acb48954c0fb1c74989ea14acd80c4',
      'label' => '2index.php-8aa07ba8efaf',
    ),
    993 => 
    array (
      'sha256' => '92f5d59e8e976effca0ef9c11d36f5278dca95b97bdb375d96f5461e5c36edf5',
      'label' => 'cd0a0a2197.php',
    ),
    994 => 
    array (
      'sha256' => '7324d9836325383732a25a5b69d84c574ae42611f4ee5d899e86373a10547a61',
      'label' => '404.php-7324d9836325',
    ),
    995 => 
    array (
      'sha256' => '8405cecd0b32a97e444ab8977dc607760a1d8dc0cea30bef614697dd1defbe3a',
      'label' => 'syswow64.php',
    ),
    996 => 
    array (
      'sha256' => 'd854b338eed1ac6a9345a21614c5fcba4ce9c6ada776d265571758b463d22db4',
      'label' => 'wp-comments-post.php-d854b338eed1',
    ),
    997 => 
    array (
      'sha256' => 'f71fa0f905d48a1ccb41aaa1f8a320509ccce9b0deab44fc2322a772e8193a6b',
      'label' => 'wikindex.php-f71fa0f905d4',
    ),
    998 => 
    array (
      'sha256' => '6aa77f84f4aae9eb56d1f5cc0846e293e5e911ad0102320b9b3c962c8071da5b',
      'label' => 'index.php-6aa77f84f4aa',
    ),
    999 => 
    array (
      'sha256' => '70b59b37f942b469e7b2e4faa1e706a1c0839493b4535106fb693dd9afe90ae9',
      'label' => 'wp-load.php',
    ),
    1000 => 
    array (
      'sha256' => 'de68a9a30aa499bff310ff70cedc4da9139637c28cd5714123ff47f774f30357',
      'label' => 'index2.php-de68a9a30aa4',
    ),
    1001 => 
    array (
      'sha256' => '6b8b1078e4e37f68aafbf3c57890e8ba70baf1c190bf45cbc2693446f5017815',
      'label' => 'f0a7a8d82cfdc8fdce0593fc62b3e218.php',
    ),
    1002 => 
    array (
      'sha256' => 'b1b2f1e755053b9fdc063e26458abc2edd0eb577e6ff920e72ece80dac6e34e6',
      'label' => 'expecting2xx4.php',
    ),
    1003 => 
    array (
      'sha256' => '1290d25549a5b8bcd986a4452bf95e11925b8431cfee9d510a04bd49c5e81b29',
      'label' => 'wordsecurity_support.php',
    ),
    1004 => 
    array (
      'sha256' => 'e00e437f872e30aaf8f0d581101cbc351dbd17f9a9c039ec8e044f9512d3c9d5',
      'label' => 'index.php-e00e437f872e',
    ),
    1005 => 
    array (
      'sha256' => '6a7d63a610d250d8d4b8200c364db2f25369860789a5f81c1060ded510c1e4b7',
      'label' => 'wp-load.php-6a7d63a610d2',
    ),
    1006 => 
    array (
      'sha256' => '8ad36489b31e30fc17bef48b942f2df7cd63dc62c59809a5b7e13a12d9c87559',
      'label' => 'index.php-8ad36489b31e',
    ),
    1007 => 
    array (
      'sha256' => 'c4c120a8e0ef598e44a7a887edbcf55ddca2a72269ed6fe4e33a75467983c572',
      'label' => 'index.php-c4c120a8e0ef',
    ),
    1008 => 
    array (
      'sha256' => '3fb67961f84596714588074ebf7144d2ca3dbd66858478785d9d37aed85ba2f4',
      'label' => 'index.php-3fb67961f845',
    ),
    1009 => 
    array (
      'sha256' => '5adf7fe287715a4c44dab2c06a48493a66b6617ea83fb6d890fbcc025b2509f2',
      'label' => 'kindex.php-5adf7fe28771',
    ),
    1010 => 
    array (
      'sha256' => 'bf033007f79c94bca5fce605cfcaff0fc1fce3bc05af9be07b1b30943752755a',
      'label' => 'f0x.php-bf033007f79c',
    ),
    1011 => 
    array (
      'sha256' => 'e9d20a11b04f908735aef28652ae3c5146771aebc13ad8eb418ec26825ebd4ff',
      'label' => 'page.php-e9d20a11b04f',
    ),
    1012 => 
    array (
      'sha256' => '16b5854df1b1398f8b63d5f1bf9d28815279f490f7a72cbea63f44827de37e2f',
      'label' => 'u65m6b.php',
    ),
    1013 => 
    array (
      'sha256' => '0eee7739cf6d2075d827f6700f906d31db6c59678328569c3bc967ea3519f424',
      'label' => 'eokhggxdi.php',
    ),
    1014 => 
    array (
      'sha256' => '1eed8ac19b8d61ff0a9b40391e35826abb116d21ab80bfc95053df7a22007b85',
      'label' => 'wp-function.php',
    ),
    1015 => 
    array (
      'sha256' => 'd311156b73609c11fccc1acdcb7b03b6d774c9b6bac6f0fa77939ba5903df2dc',
      'label' => 'index.php-d311156b7360',
    ),
    1016 => 
    array (
      'sha256' => '5af7fbaa9d0757d48abde222fd8912df6bfa7778205a1d8a55aaca037c5e5b25',
      'label' => 'wp-demo.php',
    ),
    1017 => 
    array (
      'sha256' => 'ee7f9e9773f4927707f4eb72d2b4d3d973e4a6aa9338da4c205fff97cca6a001',
      'label' => 'old-index.php-ee7f9e9773f4',
    ),
    1018 => 
    array (
      'sha256' => 'b827cdd9d417abaf9050bc1377aa67127a12f0128f59391714239668c03a011d',
      'label' => 'wp-alfa.php',
    ),
    1019 => 
    array (
      'sha256' => '395c2c97519f5d6e042d0787fa88fcdf6e7bb7d2530da689c5ec5fcbf933eb5a',
      'label' => 'index.php-395c2c97519f',
    ),
    1020 => 
    array (
      'sha256' => '9b33e5758694999594062299225d3c1290db6201277a81cd03cbfc869a1c6ac5',
      'label' => 'protect-uploads.php',
    ),
    1021 => 
    array (
      'sha256' => '0014b5d98274d32800c2af54168f2eb305c24ba08af1ca5facee859596be148e',
      'label' => 'index.php-0014b5d98274',
    ),
    1022 => 
    array (
      'sha256' => '94923637faa69359601200ff91e536cc8210e78f58c5675787b82f921f319a58',
      'label' => 'frGpoHxuaA7.php-94923637faa6',
    ),
    1023 => 
    array (
      'sha256' => '035a9e2475d422c016a20329241218685fcce97c4be2cc788f9564f42c298127',
      'label' => 'index.php-035a9e2475d4',
    ),
    1024 => 
    array (
      'sha256' => '1ea2e97cf72fdbc5f627a6e356a13b43fed987db64f9cfbf5354d87f068c2bd4',
      'label' => 'C1iWuOpXDSZ.php-1ea2e97cf72f',
    ),
    1025 => 
    array (
      'sha256' => '479e743ea089f24aab4ed80ba2c99768941b15937873b424237d13469f964563',
      'label' => 'functions.php-479e743ea089',
    ),
    1026 => 
    array (
      'sha256' => '5c38fd05f864436c322466ffa12c97cc8e45614f92e1369cc6426e0d199c77d9',
      'label' => 'style.php-5c38fd05f864',
    ),
    1027 => 
    array (
      'sha256' => 'f8a77577ec7b8612f5270892ae48da3ae5b20bd16ff8a2244862d0bb5d613cf5',
      'label' => 'psm.php',
    ),
    1028 => 
    array (
      'sha256' => '1ee38c19d7da4f07d3bcb6af80362976a5fa294911043b677df286a9c192f56f',
      'label' => 'index.php-1ee38c19d7da',
    ),
    1029 => 
    array (
      'sha256' => 'f681d60e84781c96c9ab01b7c9592e291965998595d58ddd2669fc5289b1837d',
      'label' => 'n0vv13373erxx1331dope.php',
    ),
    1030 => 
    array (
      'sha256' => 'b4590f9adb1276d5d1a7700f209fb740c39d93aeb291ca3758c649579a4bb361',
      'label' => 'cache.php',
    ),
    1031 => 
    array (
      'sha256' => 'f1f790397d415aeaef754db7edd848433e8364d28d6ae24ea69b2fea5a7b132e',
      'label' => 'login.php-f1f790397d41',
    ),
    1032 => 
    array (
      'sha256' => '89a8c8a88f6a5326838d389a2c00ff9b447d5dd288b5307e79a0137a8538d122',
      'label' => 'post.php',
    ),
    1033 => 
    array (
      'sha256' => 'faf967a3fee47be7ded394766f98fe90894b3a28afa993bec2fbd9ffc8b4d7db',
      'label' => 'index.php-faf967a3fee4',
    ),
    1034 => 
    array (
      'sha256' => '2065c825b35e1f8b05b95552a6b5576ba2aa3661870160c5192a6e5d0a04e898',
      'label' => 'post.php-2065c825b35e',
    ),
    1035 => 
    array (
      'sha256' => '178876757c859b1894e726fdb0f195423c8ba96acd3b38b34dce496ab7937324',
      'label' => 'rx.php',
    ),
    1036 => 
    array (
      'sha256' => 'fe722a9100155da76a83d1894121b53f514fa358d2c3285c50ace36bae0d7e42',
      'label' => 'header.php-fe722a910015',
    ),
    1037 => 
    array (
      'sha256' => '3d49445d9067b5dfd10454eb94cfe2d194b73de47a96cacbb114059739b7a984',
      'label' => 'header.php-3d49445d9067',
    ),
    1038 => 
    array (
      'sha256' => '249404a40c71e99c630af367dd03ccf114bc9b7ce534d41cacba8e475cc34c9a',
      'label' => 'header.php-249404a40c71',
    ),
    1039 => 
    array (
      'sha256' => '545d332039f46bbf0b5d5a0f3a240c18c2c46102495046dbabcec5094c502e74',
      'label' => 'wp-update.php',
    ),
    1040 => 
    array (
      'sha256' => 'c354909a4b5735d8280bc9320f14f47ae2d4d541fc127f4d67a1d34a6f39fc3b',
      'label' => 'header.php-c354909a4b57',
    ),
    1041 => 
    array (
      'sha256' => 'cf5c61b269cb3ce9fdde03af076919783c7e79656f8b646ed4df513951a80c9c',
      'label' => 'r-all.php',
    ),
    1042 => 
    array (
      'sha256' => '11d8e39d0e7c7ca539cea4e91fd0c3e032d77e25631cffb1772c1d58d12c5159',
      'label' => 'world-map-pdf-high-resolution.php',
    ),
    1043 => 
    array (
      'sha256' => 'ca7aa6d55e2692575380f3ae297209320735960e4600dfbb22be97bc640017ae',
      'label' => 'wire-size-calculation-formula.php',
    ),
    1044 => 
    array (
      'sha256' => '733f2b281c9b6a9852add1d0ce06e1a47a56cfd74e14f960629019cab082136d',
      'label' => 'evp-app.php',
    ),
    1045 => 
    array (
      'sha256' => '37728baba5bfd243f6e62c399775590582aca81b588497715cd5e355ad416b79',
      'label' => 'ben-asamoah.php',
    ),
    1046 => 
    array (
      'sha256' => '38f86d787203672726c53fad0271550c6cdad067e0d90a18804873912b3c1985',
      'label' => 'hebrew-greek-interlinear-bible-pdf.php',
    ),
    1047 => 
    array (
      'sha256' => 'c689d3b9f75d003e373c1bc09df2d1fd5f3172706be1e8f903dda5cac8dd51e5',
      'label' => 'online-radionics.php',
    ),
    1048 => 
    array (
      'sha256' => 'aa1fa238cdc31c6041ba15de78e3a4b52d696e9561bec7c17158aa4a46ee8c2b',
      'label' => 'advantages-and-disadvantages-of-visual-communication.php',
    ),
    1049 => 
    array (
      'sha256' => 'e4cd72bda6cce9fc9caca94d7750b62340e86274448bb43821db524aca1662e0',
      'label' => 'conclusion-for-logistics-project.php',
    ),
    1050 => 
    array (
      'sha256' => '7db146973cb800161211f75f9552994604094b3aa23761f8249f2e700b7edb22',
      'label' => 'off-topic-synonym.php',
    ),
    1051 => 
    array (
      'sha256' => '06002eefeb0d580c899308918e6c376326a4a398d545ebc3ddd91b8f61bc0fac',
      'label' => 'tracepath-mac.php',
    ),
    1052 => 
    array (
      'sha256' => 'e59fa6a0e424287fbbcb9d5e53e14e84224bbd82996492273fd4a18765966691',
      'label' => 'traccar-web.php',
    ),
    1053 => 
    array (
      'sha256' => 'e4426de6479d54ddfc80ef0220c51a425cd146a4064ef67cc3a42b080bf5c972',
      'label' => 'hma-support.php',
    ),
    1054 => 
    array (
      'sha256' => '75ed1b8c249e155c96256c641959ca26fa9efedc03d4d893b873b9cd23a93c31',
      'label' => 'sherlock-fanfiction-sherlock-asthma.php',
    ),
    1055 => 
    array (
      'sha256' => 'bfe2266be01b3e98fae5964181f939220e103565e27ddb4b51805382f7c1f968',
      'label' => 'dsp-audio-effects.php',
    ),
    1056 => 
    array (
      'sha256' => '3ab67ae73e8047d794143fd5a3bca8d941cd413aa165bd1b1e6f651b1460f504',
      'label' => 'how-much-in-spanish.php',
    ),
    1057 => 
    array (
      'sha256' => 'fb8fee2cdaa47d8fe2e6558b99ae7c4756f61602f69be8b1fb67dec7b279c3c3',
      'label' => 'enrollment-letter-sample.php',
    ),
    1058 => 
    array (
      'sha256' => '85bcccb7eb6a9d7ab9526a6e3afa634c8c00b8089d2f7362f8678fd91eec3799',
      'label' => 'sfsfix.php',
    ),
    1059 => 
    array (
      'sha256' => 'b5ee4de6b42e8d11c47b150a7b309fd4f690a1323299e5de91d45ead663a6159',
      'label' => 'master.php',
    ),
    1060 => 
    array (
      'sha256' => '8740a570f6bf6ecd8dc064b3434bf9070095dc9e965f0b7af0265e62de20fd68',
      'label' => 'iced-2020.php',
    ),
    1061 => 
    array (
      'sha256' => '1eac762c473d45b27710ab1e880f02bf4a2673130c746fb53221172d185aba1e',
      'label' => 'channel-4-news-staff.php',
    ),
    1062 => 
    array (
      'sha256' => 'a4ae70408b8882662d5b225f1f0657b72b3160321b136553916b3b2f382100dd',
      'label' => 'destiny-2-hoodie.php',
    ),
    1063 => 
    array (
      'sha256' => '53c2ad43e5d403abb4fe55c1a3889428b5376e98cb0905c0bc94e2759ec04f73',
      'label' => 'alkaline-perm.php',
    ),
    1064 => 
    array (
      'sha256' => 'd788a55709c7737878bcedbd49918a95ae1765d3b7356447843be6c97eed48ec',
      'label' => 'easy-cat-paintings-on-canvas.php',
    ),
    1065 => 
    array (
      'sha256' => '3f1d6a03dba4b30bb1f67daf8a36f0e6e70e777da3ec3a84686dcdd23faccf65',
      'label' => 'wood-stove-pipe.php',
    ),
    1066 => 
    array (
      'sha256' => 'fdd35598255bf79b7b8c30da46406df1a03d3d7633917a1886ff12404500a78c',
      'label' => 'speeduino-mx5-pnp.php',
    ),
    1067 => 
    array (
      'sha256' => 'abd7b458f5d31aa9ce6ffcb18a1f610977ddb5c86ace046709ed321917598c1f',
      'label' => 'methods-of-conducting-research.php',
    ),
    1068 => 
    array (
      'sha256' => 'e8793f7182e300f3c7adc9e4a111536cdb780bb25996cd8b9203bbf3ff3ac923',
      'label' => 'gslx680.php',
    ),
    1069 => 
    array (
      'sha256' => 'f59a42efa0ce32be1be4f8a1272619dde4fab1d4557b0a3ad991b712b0aa68f9',
      'label' => 'decorative-screen-panels-indoor.php',
    ),
    1070 => 
    array (
      'sha256' => 'e5b0ba43c107e0b06741a0e320ede6ef688acb30858795ea5660c40c73a8aee3',
      'label' => 'galaxy-s8-sim-tray-replacement.php',
    ),
    1071 => 
    array (
      'sha256' => '818acea91250788774f630246c86b6f92df39207855d898f72933f7c0fc10ac7',
      'label' => 'rabbitmq-password-special-characters.php',
    ),
    1072 => 
    array (
      'sha256' => '23eee40e5683e80c723d99ac24801e7b00ea02486578d34572b1c51fd2828241',
      'label' => 'aeotec-multisensor-6-isy.php',
    ),
    1073 => 
    array (
      'sha256' => '09c7eafa9699f39b829e6bb41ca29508544802123d1d359e5a1bddb37cdeef81',
      'label' => '12-channel-car-amplifier.php',
    ),
    1074 => 
    array (
      'sha256' => 'c7b226dde5337461e05c78d79507285ed4022777bfaae5ebe04310accc79e4ae',
      'label' => 'cherokee-in-cherokee.php',
    ),
    1075 => 
    array (
      'sha256' => '60335a48de14cc177c032b1a14986da919c96a258fd90fe68c1084b8fab6ca25',
      'label' => 'zusette-deleon.php',
    ),
    1076 => 
    array (
      'sha256' => 'be8be987c0f4078c8584a4d2c21cf94c9971833aa5394dd6272fcc552419b4f7',
      'label' => 'military-paint.php',
    ),
    1077 => 
    array (
      'sha256' => 'ff70c628479501e2341e60fa666d01a955dba6740f87186d8ee972406ee5e308',
      'label' => 'bound-armor-eso.php',
    ),
    1078 => 
    array (
      'sha256' => 'be19119636a2c4eb7aa184bbf20a796e45c0dd8bce7f82b4cfa18cfe73af5cb5',
      'label' => 'clothes-rail.php',
    ),
    1079 => 
    array (
      'sha256' => '3e6d39b0b2e597bab34eb1ec864bb6466548520a4b1a0c47aac31262dc27418f',
      'label' => 'mp3-video-player.php',
    ),
    1080 => 
    array (
      'sha256' => '2f6a8653a7bf185c566ecf61b005a794fb80112b10fdf80a26f9cc7098c96040',
      'label' => 'ps4-media-player-controls.php',
    ),
    1081 => 
    array (
      'sha256' => '13d350a648cac5e09e5b070b4c0ea5daa47174d7ecbd5d43073bb0667b139198',
      'label' => 'military-gov.php',
    ),
    1082 => 
    array (
      'sha256' => 'c76f6f674b55a854f4ffbc23ca9e325d5fdf2f315e8e7e7d5b7c7330f6342fae',
      'label' => 'johns-hopkins-white-marsh-breast-center.php',
    ),
    1083 => 
    array (
      'sha256' => 'ddd2a7998adfb478dea75977436a14b76d4d1bc95672011586c7ae0f8f616757',
      'label' => 'kmseldi-reddit.php',
    ),
    1084 => 
    array (
      'sha256' => 'a42472fd2dfcef3779d991504649f6c2fc6b4efe7f38521511ca0ac79e3fd4ed',
      'label' => 'v8-detroit-diesel-sound.php',
    ),
    1085 => 
    array (
      'sha256' => '89a2cd69ea613bd11da1b82d2d6221d0727b7fff6a0c5f4a3c3ba56772a4ab32',
      'label' => 'tf2-x-reader-fluff.php',
    ),
    1086 => 
    array (
      'sha256' => '8cf8cccc57c036809b2e21911d8857e5e138149c6eee25b99ad5280b6bc0d815',
      'label' => 'fear-of-birds.php',
    ),
    1087 => 
    array (
      'sha256' => 'f60a7e2a715331d35435226f7ef3671812af7369c8b2ac009802b2ab77f615a9',
      'label' => 'checkmob.php',
    ),
    1088 => 
    array (
      'sha256' => '73b53009003dae1dcf67bf737c691422e97d443016c9f1ba2488e1f4b699addf',
      'label' => 'ginger-rogers-children.php',
    ),
    1089 => 
    array (
      'sha256' => '07f5e0d8424a05c32f31ab29f567d64158b0a69e7604045faa7b67a1a61850bc',
      'label' => 'pyinstaller-failed-to-load-dynlib-dll.php',
    ),
    1090 => 
    array (
      'sha256' => '8d0a5add0250121a3cef189827029c316ef0c1bb093d45243fa7f1793b16464d',
      'label' => 'reddit-chan.php',
    ),
    1091 => 
    array (
      'sha256' => '7fc39d618de009ce30a798931737bcce142cb6553c86e6468deaf0fb78347592',
      'label' => 'dr-mark-hyman-blog.php',
    ),
    1092 => 
    array (
      'sha256' => '470087ef957f8ae9eb6ed60a1a098ee05450a48b2d61313e40fb0515de2e44f8',
      'label' => 'land-cruiser-200-suspension.php',
    ),
    1093 => 
    array (
      'sha256' => 'ac115237051c3d281dd24a10ac8b5c79938d9e2e665c2af37e23f089d38e98eb',
      'label' => 'pvs-write-cache.php',
    ),
    1094 => 
    array (
      'sha256' => '6bd80bb4eb08b3673fe247b2e83f08a89cdb3158b9b4e656fd061334281c7d61',
      'label' => '50cc-scooter-smoking.php',
    ),
    1095 => 
    array (
      'sha256' => 'ed6a316e47e80a4af6f08e70642ff9782eb264c38665633f1a6eea83d317d1e7',
      'label' => 'installing-steps.php',
    ),
    1096 => 
    array (
      'sha256' => '754291264516ccf83a3550740e537ab0d0e88b2374760cfe9b0e3630981d3a92',
      'label' => 'pooja-kashipur.php',
    ),
    1097 => 
    array (
      'sha256' => '04e9ac139bc99bf0520db366f52f6b91708a8b967dbaf3441bbd6a15e52f784f',
      'label' => 'cpt-25575.php',
    ),
    1098 => 
    array (
      'sha256' => '24618fe5827c0db8f81c70b03c5ae3bc04be1a0866f5a317a3ed11c10cd6cc30',
      'label' => 'libxml2-xpath.php',
    ),
    1099 => 
    array (
      'sha256' => 'ab807f3238b92a03ba0287b3f49cd984d8043e976315349f942485b0e1eb7dd8',
      'label' => 'mygig-rhr.php',
    ),
    1100 => 
    array (
      'sha256' => 'bcb6f1479ba7dd15717f14a59713ad4568b22e2db148e33fb3070a2c808ab422',
      'label' => 'how-to-use-sde.php',
    ),
    1101 => 
    array (
      'sha256' => 'c83e0b62a10d12e31b7bb5ea5ebd8827681111ad80cd49d01c15e2b0e6168714',
      'label' => 'e-ralph-biggadike.php',
    ),
    1102 => 
    array (
      'sha256' => 'cd489640a55780f0fe9fce833c0eb57f14d8da6c568ed6c1d946a0ec76ba6656',
      'label' => 'architect-speech.php',
    ),
    1103 => 
    array (
      'sha256' => '954b9c72c6a377920b6a3ab9a066ec530bf35b1b3e39082000026441fce6d767',
      'label' => '2080-vs-2080-ti-reddit.php',
    ),
    1104 => 
    array (
      'sha256' => 'a98ae837faa6980f3495f0003fd29e874735dd2f6009d5dcec080f6d9054bcdd',
      'label' => 'add-money-to-riversweeps.php',
    ),
    1105 => 
    array (
      'sha256' => 'e165bbd4ec53f163813cb2508881e729ebf5932ac98bbb4a0dd4d24f88b67f39',
      'label' => 'vizio-tv-manual-32-inch.php',
    ),
    1106 => 
    array (
      'sha256' => '43904775d66cac32ca3140fd52579d5026461958502c285768b1406509a40f07',
      'label' => 'computer-audiophile-setup.php',
    ),
    1107 => 
    array (
      'sha256' => '6920f59e0998e24cd88ecc1a87be9bd92dcd055d9b5a1c5798c078a0b7ea9d02',
      'label' => 'wincdemu-scsi.php',
    ),
    1108 => 
    array (
      'sha256' => 'de80fdb7fec9afc2361eb4137ce5a6c6e9bedf9be7777d61a6dbf97032c41f63',
      'label' => 'permanent-residence-provincial-nominee-processing-time.php',
    ),
    1109 => 
    array (
      'sha256' => 'ffa7bf8cd2b7971245770a842ddfc6905a4fe5145fbb50676b2ac00ff7f54716',
      'label' => 'catia-practice-problems.php',
    ),
    1110 => 
    array (
      'sha256' => 'c2d82fc888d80d0dfa7382804e6d3c37b322da3fafa49ef7d1373bbf6701a6d2',
      'label' => 'gdpr-web-scraping.php',
    ),
    1111 => 
    array (
      'sha256' => '43291e158ff47d26236033eae453e8dd5852f05baea401b77f5a3de681572edf',
      'label' => 'pyside2-download-wheel.php',
    ),
    1112 => 
    array (
      'sha256' => 'c8ace57343b7d49fabcf82f2e8cc81ee6993f3ee52fe89fb7cc9d9543c3d5ec3',
      'label' => 'cinema-hd-for-iphone.php',
    ),
    1113 => 
    array (
      'sha256' => '7f113e4b876359ef1ee8592b68a02bfb7219fd3b3e208bed417ca2f14af4d9c2',
      'label' => 'scorm-tutorial.php',
    ),
    1114 => 
    array (
      'sha256' => '0da80bdbe304d312c8779759f48f6378352593a2d31df73321ec69393c3f563e',
      'label' => 'oil-ratio-for-yz250.php',
    ),
    1115 => 
    array (
      'sha256' => '6f32277ad066b69dcbb3e502a5cbb08356882a66c68f3710116fabcdfb3af317',
      'label' => 'mma-agent.php',
    ),
    1116 => 
    array (
      'sha256' => '4ce1123ca1acd52c2d7831e7e8c9004e1decba1cc6ffe8de0cb8365ff20e28da',
      'label' => 'exif-editor.php',
    ),
    1117 => 
    array (
      'sha256' => 'd9e3eb1c83470a3884ec247ceb829d008e49c834ed8c924e5c0e7a099c682a66',
      'label' => 'relay-wiring.php',
    ),
    1118 => 
    array (
      'sha256' => 'e6f56cd0051ea09764f61fad8eac2fa8aaae40565543a00002d33d36c245f0a8',
      'label' => 'auto-refresh-firefox-free-download.php',
    ),
    1119 => 
    array (
      'sha256' => '5dbbcc3edcdded50979d9cc5fa73b0eaaa4772ab0eafd641c425fef80f8f137b',
      'label' => 'time-dragon-5e.php',
    ),
    1120 => 
    array (
      'sha256' => 'a70a2a3310be5259e5a346d2507d52d0c11365f57381aeaa654f6e78d4ffaf78',
      'label' => 'cr10s-firmware.php',
    ),
    1121 => 
    array (
      'sha256' => 'e31473cd9ad633050e77ee3364a0e5ec85a0e155b432bcbc84418769ec00d242',
      'label' => 'avengers-x-reader-infinity-war.php',
    ),
    1122 => 
    array (
      'sha256' => '8cd841517e18ccb2571bb720c845b20f3b302a0416553c0ff0cb13eca7a8eaf4',
      'label' => 'odoo-runbot-setup.php',
    ),
    1123 => 
    array (
      'sha256' => '8d916e106e70adf1b0b99c3d52a7c6d288b86074778e62909bcf7a94bdc314c0',
      'label' => 'pueo-oc1.php',
    ),
    1124 => 
    array (
      'sha256' => '533033801720fdc8f28dfe2402d1d07c4faa50ef9eff938ea330e7734c29f350',
      'label' => 'cefsharp.php',
    ),
    1125 => 
    array (
      'sha256' => '42e66e168166f2060408e174247b34c2ba2df9c3a5c40f10d3f829c56766d4d5',
      'label' => 'osrs-hotkeys.php',
    ),
    1126 => 
    array (
      'sha256' => 'dad0ec0a04fd44d2e78fcc38c51b23aa9150eb10126625ec575d468145ac5da8',
      'label' => 'famous-romanichal-gypsy.php',
    ),
    1127 => 
    array (
      'sha256' => '8279037d4754523ebfe42d32d709eeddf84691096afca2034f9683bef223d2e6',
      'label' => 'javascript-socket.php',
    ),
    1128 => 
    array (
      'sha256' => '885e975b1bfc397a3c245a52555d462d0733b351a1dadeba4fc9c838ee7e21c2',
      'label' => 'adp-software.php',
    ),
    1129 => 
    array (
      'sha256' => '509eca446a2f828864a192e1a506c0cbf9bb867a1927cd3fdab3f9f60a66d87b',
      'label' => 'salvage-f250-craigslist.php',
    ),
    1130 => 
    array (
      'sha256' => '9af6e641450e9b310b0e9d7e130d88d3fb4200ff5149040f0bd34bb0ec706c6e',
      'label' => 'mobilogy-touch-2.php',
    ),
    1131 => 
    array (
      'sha256' => '22eb020f51ddef86bf7d5a757533bfff220d21be5330603f2f76e63a4097a448',
      'label' => 'reelsteady-discount.php',
    ),
    1132 => 
    array (
      'sha256' => '904f5d810f0bb70234035689fc2dead8ca4cafad3c58d4cb4327292167941f9b',
      'label' => 'github-kitty.php',
    ),
    1133 => 
    array (
      'sha256' => '7daeae497063b887f1baeaca605b64e5a19f85e11d509f49824adcbe4cc41988',
      'label' => 'divi-username-and-api-key-free.php',
    ),
    1134 => 
    array (
      'sha256' => 'a3e39f76c34cbd2205356eb81edba81f400e4713b8a4e30252d4e1bd98b36be5',
      'label' => 'cors-service.php',
    ),
    1135 => 
    array (
      'sha256' => '64634f8779a4a5f8d1db32554740327217c2753a2b5dabf36412d67eb04cff9f',
      'label' => 'google-pixel-keyboard-settings.php',
    ),
    1136 => 
    array (
      'sha256' => '4623a7b89454eb9c1a322a971bc6b2944a0072ee66c153e0ea5268a154794a42',
      'label' => 'petroktt.php',
    ),
    1137 => 
    array (
      'sha256' => 'dea758857dd8b42ef0ef9ac476a8e259d47a21d116cd86d829674191782707c7',
      'label' => 'adobe-rush-apk-for-android.php',
    ),
    1138 => 
    array (
      'sha256' => 'b70acd6bf8eea8073a0c28f475eb63b917546d3ef1da3994aecc6859ab77271a',
      'label' => 'ultrasurf-ios.php',
    ),
    1139 => 
    array (
      'sha256' => 'dc3bec544a04bb74a82290e9940132f6212fbacc3707d876e24d36da136d77ab',
      'label' => 'benefits-of-yoga-pdf.php',
    ),
    1140 => 
    array (
      'sha256' => '8a3fc521474d014efea9586c386cdc5bb52e2d6c05c95ff58c8c557a5a493d2d',
      'label' => 'nsuns-531-5-day.php',
    ),
    1141 => 
    array (
      'sha256' => 'e9c69cb1774409f0ba3fd2935e4ea37875977d1b35936a60126fcf8ab13c1e6a',
      'label' => 'gpd-win-3.php',
    ),
    1142 => 
    array (
      'sha256' => '4ae11c6ab4d9b8bddf6afc47267b32ad81e25ec0f917f533c799c24396e40f67',
      'label' => 'technology-guest-post-guidelines.php',
    ),
    1143 => 
    array (
      'sha256' => 'a9fa432cff8e110895bfd202826bb65ada355ccce4d0f291b0d6f9caf18def0b',
      'label' => 'philips-ip5-service-manual.php',
    ),
    1144 => 
    array (
      'sha256' => '8e7f3110599c6a79b08b0d47719e49ffac6701a80794ed6fd4f269070d5898ae',
      'label' => 'ableton-worship-patches.php',
    ),
    1145 => 
    array (
      'sha256' => 'b76d095350531315ff8e739236f9d434359214cb07d95ffa0e1c24027952b81e',
      'label' => 'seneca-aspen-25-cal.php',
    ),
    1146 => 
    array (
      'sha256' => '4d5d43e487fac71fb800bd0b4b41b05ca52e49c1e86027e98cc240dc237e4581',
      'label' => 'nava-maratha-newspaper-ahmednagar-today.php',
    ),
    1147 => 
    array (
      'sha256' => '8d39fd969dc51010e2d563ff377bf8ba085ccb521a45125476d3a22f036eec54',
      'label' => 'armalite-ar10a.php',
    ),
    1148 => 
    array (
      'sha256' => '5b16b312cfc0dc26f8a3c99db080692914606ccec413beeb80d2a19a2127b5e1',
      'label' => 'where-to-find-geodes-in-colorado.php',
    ),
    1149 => 
    array (
      'sha256' => 'e7af5c0b1039b7f463787030b1d7121fe1b504dc984678589a62197942a052d5',
      'label' => 'i2s-tutorial.php',
    ),
    1150 => 
    array (
      'sha256' => 'f24a45a0b52a994bc7b092de39624a347e22a402d34746040e1720afc9f7757c',
      'label' => 'mercedes-e400-tune.php',
    ),
    1151 => 
    array (
      'sha256' => 'd01dbdf1515aa169d2cdc8f511287c13aefce725d9d788ecea557f460905f070',
      'label' => 'cube-3d-cartridge-hack.php',
    ),
    1152 => 
    array (
      'sha256' => 'a5180bf345099f89899e84526697bf07ec7fe556b0c861a1892fc3194b61dc3e',
      'label' => 'index-of-the-mist.php',
    ),
    1153 => 
    array (
      'sha256' => '95823596942430c66d76a09513842de31ec2ba008afdbc23e865c23ee64345cc',
      'label' => 'bdo-fences.php',
    ),
    1154 => 
    array (
      'sha256' => '4673e790a5b2d63d55abe7275b6b11f080dc57008f33b61e7fcb0c32909d7afa',
      'label' => 'north-korea-server.php',
    ),
    1155 => 
    array (
      'sha256' => 'd28b36ffad042e223de279af71a5a0244ec6a6f33adfd2502c530d587b04177a',
      'label' => 'marshall-county-daily-obituaries.php',
    ),
    1156 => 
    array (
      'sha256' => 'cd8d7e67129faee5a260d11c12f969dee340bad1a12309b8e10bfd150a3f9fd1',
      'label' => 'emus4u-moviebox-ios-12.php',
    ),
    1157 => 
    array (
      'sha256' => 'fef9138c40f7a3b583e87f2eebe7f2cf3f74340e61349353ab4c7d2c93164998',
      'label' => 'curriculum-calendar-template.php',
    ),
    1158 => 
    array (
      'sha256' => '88ee96a32cfb4bf8d565a5c4f02da04933ca9d8d357d4139016a109280f1279c',
      'label' => 'trade-school-vs-college-reddit.php',
    ),
    1159 => 
    array (
      'sha256' => '5bbc71fe1f5215a62cf9f7ed73db0f1ce33ab6573b4e6e4ead2cd56388c22410',
      'label' => 'omid-royal-reporter.php',
    ),
    1160 => 
    array (
      'sha256' => 'd9e0483df950f6a6244c5721ab542e5cfffd275e6252f19106728de873fffd23',
      'label' => '3d-brooklyn-instagram.php',
    ),
    1161 => 
    array (
      'sha256' => '9ea47bd0c9645c836ded0e234b1821be36326482fe43de3691edf18a1941db7e',
      'label' => 'coyote-mix.php',
    ),
    1162 => 
    array (
      'sha256' => '833cd994507442dc8359b3c7acecb7b8a4009ffd1b863710d32095082c7f73bc',
      'label' => 'how-to-embed-subtitles-into-video-permanently-in-vlc-mac.php',
    ),
    1163 => 
    array (
      'sha256' => 'bcc304e0adbfd14911666d4bea58bfe36dab1e0e762ead0eb68e84800f620959',
      'label' => 'signal-season-2.php',
    ),
    1164 => 
    array (
      'sha256' => '2e2e29b1374aef9cb72c1efb4da8d2e13740ece3f3b30094f492f01197ec9fca',
      'label' => 'nunit-3-setup.php',
    ),
    1165 => 
    array (
      'sha256' => 'e9d6b6da560194e633bb653554358a13a010938e1cecb128239015ba8ff499f3',
      'label' => 'elasticsearch-empty-object.php',
    ),
    1166 => 
    array (
      'sha256' => '84810066eacd831126f16c4f218fe071516922a95aa3788b03d30c8b08c4494f',
      'label' => 'art-model-3d-pose-tool-and-morphing-tool-mod-apk.php',
    ),
    1167 => 
    array (
      'sha256' => '2eebed8e1032ef361f1e57b8a348bdf8c3f6ed080d0c9feffe442db0abec875c',
      'label' => 'craftsy-forum.php',
    ),
    1168 => 
    array (
      'sha256' => 'ce398b8816776c5c212e445b9eb4d3313f3d4d2aa999cc189870b010685f7d6d',
      'label' => 'textron-login.php',
    ),
    1169 => 
    array (
      'sha256' => '8ce61a5cdaaeab64e0068eb07f03322e467215959d2f595178d74b0b23cbd6cb',
      'label' => 'sngpl-test-questions.php',
    ),
    1170 => 
    array (
      'sha256' => 'ab003717b10060df3bf76425efccb1bf69bf90d28cba502f40e1565be334a9cd',
      'label' => 'what-is-smart-download-in-adm.php',
    ),
    1171 => 
    array (
      'sha256' => '7c0cd39aec2b0b8c56d7b431d03d7b1b1f58726b910c024bf7ae1f186dbccd28',
      'label' => 'best-bb-gun-for-10-year-old.php',
    ),
    1172 => 
    array (
      'sha256' => '0522eabc9514c847f829e616c1222f9df6b1e179fe8e4065ab1f5ad3b9b1dfe3',
      'label' => 'harvard-aba-509.php',
    ),
    1173 => 
    array (
      'sha256' => '10574130eed55b34d2d3b752d4313eb6925b8e62cf6fbf94aaf434af5799cd7a',
      'label' => 'z31-fsm.php',
    ),
    1174 => 
    array (
      'sha256' => '42169ecf4b5c9370d015be0a3197287f4464799c1d96e0d31cae67b4096aa3b6',
      'label' => 'occultic-recitation-to-get-money.php',
    ),
    1175 => 
    array (
      'sha256' => '6228c5c20f4db0b07aa8a97aa120c46f5cfddc18c4f044f57c9089f5b84d6b23',
      'label' => 'walmart-gun-sales-statistics.php',
    ),
    1176 => 
    array (
      'sha256' => '88d3afd411b28aa79b321c47df8570e6a158c8fd0ad5c3d4e5d39e4d81745523',
      'label' => 'ngrp-samp.php',
    ),
    1177 => 
    array (
      'sha256' => '320ee5c2a0bd2c26d91355117fe29af288d04079f1f7e98dce050d0bd5b34f66',
      'label' => 'yamaha-v-star-1300-fuel-filter-location.php',
    ),
    1178 => 
    array (
      'sha256' => 'd808253cdce9bf1c583f674b6fc02a53f104307b25fc88af9d8189ceba844e1e',
      'label' => 'tool-tour-history.php',
    ),
    1179 => 
    array (
      'sha256' => '15b9cacab85f78dd85e77792e5780240cfcec0f85107b92b168711b4b87fb55d',
      'label' => 'zzz.php',
    ),
    1180 => 
    array (
      'sha256' => '46c923c0ad054608fa68fb0ed762bdcaac8d1bf75578c7fbb85d032810536ba2',
      'label' => 'ici-castings.php',
    ),
    1181 => 
    array (
      'sha256' => 'b5ac6add78d892f489d5e2cdcd2eba2e05c98d0f547d2a09a20b25597cf6414c',
      'label' => 'pix4d.php',
    ),
    1182 => 
    array (
      'sha256' => '08a169fd8ea1ca046c8492fe875c0a108a3937261f0dcccaa6ea8b39fbfaa9bd',
      'label' => '2020-camaro.php',
    ),
    1183 => 
    array (
      'sha256' => '06a4d239beccca880fe2699a7a0fad0049fe561e43bd31d3043d55abacb243bc',
      'label' => 'waitress-musical-songs.php',
    ),
    1184 => 
    array (
      'sha256' => '5c0d715e5f758c06b758a7823ec8d2978dea6df46727d70d492eedb6f52573f6',
      'label' => 'rtings-hisense.php',
    ),
    1185 => 
    array (
      'sha256' => 'b29d54339d3f2557627e10fc21f109af4f389a5f5866bc832fb815cae81aa974',
      'label' => 'stm32wb55.php',
    ),
    1186 => 
    array (
      'sha256' => '685d79d9a8274a8b7785654ef68c8fa67da10282d101cb723810b4eac670241b',
      'label' => '936hz-benefits.php',
    ),
    1187 => 
    array (
      'sha256' => 'f7218ae6580c68973887440c7a2d30fa108657f6530a17b3e31f112496e2d852',
      'label' => 'stamp-and-coin-shops.php',
    ),
    1188 => 
    array (
      'sha256' => '84c7e186bc7b07d5987a7cb9ca50bd2d18a2ecf3c53b66ea3cc4602166491d93',
      'label' => 'macrame-wall-hanging-diy.php',
    ),
    1189 => 
    array (
      'sha256' => 'c870681f7601d31a632454f5390a55ded231f9e3fa519c8ea9e19172330cca97',
      'label' => 'pro-tools-vocal-presets.php',
    ),
    1190 => 
    array (
      'sha256' => '25149b6950002e947d2dd7cc87a24ae1ce803338ccac1b5d8fe46fdde701c752',
      'label' => 'cant-click-skyrim.php',
    ),
    1191 => 
    array (
      'sha256' => '4b7f7a638297eaf1900f918c9ad382e25bc8dc0fb0588f9200ad013444d39ce9',
      'label' => 'torch-set-num-threads.php',
    ),
    1192 => 
    array (
      'sha256' => 'ae28f0a7995eff913a8d1a4a237fee5bca41a9b4cf94c9df88c112e02eb55ef5',
      'label' => 'seeing-smoke-like-mist-after-suddenly-waking-up.php',
    ),
    1193 => 
    array (
      'sha256' => '966c602caad845562696a78f6bcf30b5685b295484740961bf7e43545a5c9e13',
      'label' => 'sweep-results.php',
    ),
    1194 => 
    array (
      'sha256' => 'd41874e2b097563b5b3f4b40d0450fa7df484a29791bb64f99396d603e226e17',
      'label' => 'boy-scouts-bayside.php',
    ),
    1195 => 
    array (
      'sha256' => '1a89fd552f6de4414a19072a1d52b981003505c42fa5b66455d98620255badef',
      'label' => 'lifan-motorcycle-150cc.php',
    ),
    1196 => 
    array (
      'sha256' => '7e4de2c0496604dd0a8bbfaed2d5a86a8732cc17a586b1dda928a15053659e8f',
      'label' => 'a7-card-size.php',
    ),
    1197 => 
    array (
      'sha256' => '5a4a6f6d4af2c2dfa73196f8207dc401087a7433069552ebaaa6a77c600c37d8',
      'label' => 'arjun-dixit-satta-king.php',
    ),
    1198 => 
    array (
      'sha256' => '830018f016ec6fd381e8fbaef601eaa00ad2ef3586c71da6ef324ee6255da952',
      'label' => 'ps3-jailbreak.php',
    ),
    1199 => 
    array (
      'sha256' => 'dd433831f8a7c011ac61410c2de16e2fb641ed6a5f6270f05b6b76191bec1b80',
      'label' => 'osisoft-forum.php',
    ),
    1200 => 
    array (
      'sha256' => 'a452432ce17c394cd1e946886001d431c6438fb79e7d48837dbfb46568bbcb76',
      'label' => 'mandelic-acid-the-ordinary.php',
    ),
    1201 => 
    array (
      'sha256' => 'f1c12817e723f28fe2e9b6da0cfcb455938a6894cbd041eac44075197a69635c',
      'label' => 'relion-alcohol-swabs.php',
    ),
    1202 => 
    array (
      'sha256' => '5db22d69823cd8ac1621651f658c2b89efbc8ac7cef08850ce2061b7d3ab09fd',
      'label' => 'eurolab-mumbai.php',
    ),
    1203 => 
    array (
      'sha256' => 'e5755e135f20bda082414d6343dbd6d8fd9c3d707ccd02ad016e8deb6ac2005f',
      'label' => 'shortwave-radio-online-tuner.php',
    ),
    1204 => 
    array (
      'sha256' => '28e641886deb178f02b269f3376823d178270f3f20c381f80125d56e32faaf5f',
      'label' => 'g2o-lambda.php',
    ),
    1205 => 
    array (
      'sha256' => '93bee4b0a0f7f195ea09c47c02c25bb84b9c1280c87764dec68f9410bacff3c3',
      'label' => 'ashoka-film.php',
    ),
    1206 => 
    array (
      'sha256' => 'd536aac0aa3e148212722e0ad644f82ce2e0ee6e59cf02d714db863ae7ed1e47',
      'label' => 'c4d-r20-signal.php',
    ),
    1207 => 
    array (
      'sha256' => '21a4fc968f3eefba5ddc3a88383bc978a249864a2a6336c7703b2a8d3b02ce08',
      'label' => 'vape-it-lisbon.php',
    ),
    1208 => 
    array (
      'sha256' => '93ede8b07019f8b4a185969e62a0828a8dfdceebd38b8b82060e10275e9df22e',
      'label' => 'cadoodle.php',
    ),
    1209 => 
    array (
      'sha256' => 'd898bfa8484a32eed8623fa01533aa6db7efea526a4c3dfa8d162a85f6566b9d',
      'label' => 'wifi-booter-free.php',
    ),
    1210 => 
    array (
      'sha256' => '0534620f231be314875d463edf30de0fd5bbde1ca4ddbb01b9468e4e7fd99503',
      'label' => '43-prayer-calc.php',
    ),
    1211 => 
    array (
      'sha256' => '764991f053390167855a7f0156190f420fdd0fa6c6cdef19bd81c715fb48c0b3',
      'label' => 'mapstate-nuxt.php',
    ),
    1212 => 
    array (
      'sha256' => 'fb6d9b9ce4d0820e3143b4703ee5421af43d30669597d3eaa4083b7d74393832',
      'label' => 'freertos-http-server.php',
    ),
    1213 => 
    array (
      'sha256' => '91bd04ad692c43ff385872e2a9f831627776b24b99ed8d269eb540a4ae80330e',
      'label' => 'rts-tv.php',
    ),
    1214 => 
    array (
      'sha256' => '47b908ef0f2badee3e74f59b51336f0c2ef6607832dc31c2a2b16fb386d7a607',
      'label' => 'how-to-adjust-pivot-in-zbrush.php',
    ),
    1215 => 
    array (
      'sha256' => '7b7cf0e4e35d57124e2157212bb41b41b844e5a77cdc8cc97e7b6b9b9c2d992a',
      'label' => 'marlocks-south-park.php',
    ),
    1216 => 
    array (
      'sha256' => 'c3216518264e1e5220ad95ae9d1f3c4390b749775680f10cdcc342483dbd2e47',
      'label' => 'betrayal-kjv.php',
    ),
    1217 => 
    array (
      'sha256' => '9dab6d11af15aa85482c8569ccdaaaa35914db387845942fc03fe3b946dc771b',
      'label' => 'qt5-resize-widget.php',
    ),
    1218 => 
    array (
      'sha256' => '34b411eb1864a6cb95eb8fa9374e60efb2c47544e62443c2c7ae553e917359d6',
      'label' => 'yugioh-archetype-generator.php',
    ),
    1219 => 
    array (
      'sha256' => '26ca3e0bbbbc49191ccdef3ebb000344aa017d1492446f887c0349c2dacb0e22',
      'label' => 'start-qiime2.php',
    ),
    1220 => 
    array (
      'sha256' => '35942eebad7803a8165b1690f39b23120328a651eae05505bf0e14f51f4fb007',
      'label' => 'rivatuner-amd.php',
    ),
    1221 => 
    array (
      'sha256' => 'fd764842788d0637b068c80bd7476d51557d495c9d178cfc4b608008d5a1d4c5',
      'label' => 'linx-phones.php',
    ),
    1222 => 
    array (
      'sha256' => '25b777df42643674e4dcd1ef5c9e79c01fa673a58f22d77856adf9dc2a94f549',
      'label' => 'dynamics-365-web-resources-javascript.php',
    ),
    1223 => 
    array (
      'sha256' => 'a83d5a9775372d71627c57c4d50acf550fad365c9bc4d91b20307d80ddb24205',
      'label' => 'jpop-m4a.php',
    ),
    1224 => 
    array (
      'sha256' => '373cc5eb8c95c0c443f280026aaeaa73e9791564881830ec14ec3336dc19a952',
      'label' => 'fz-movies-series.php',
    ),
    1225 => 
    array (
      'sha256' => '007a3b7926a25b0dd04ed2749a6600ff5089a67f2a666b909700e1c6107a5c7f',
      'label' => 'elementary-os-juno.php',
    ),
    1226 => 
    array (
      'sha256' => 'fc97e5849f6d70a51fa615ac6b82a12970e2a2b709cb00de20518a42c016c097',
      'label' => 'add-surface-information-arcgis.php',
    ),
    1227 => 
    array (
      'sha256' => '00d0795061682b2973c1b646739befe3f8461c53b92be1831729226f84525e19',
      'label' => 'mtv-india-app.php',
    ),
    1228 => 
    array (
      'sha256' => '41535890ccd897f68b33db0889f19e0625f0c989dfb640c2b8d5c330831f05bf',
      'label' => 'esp8266-fft.php',
    ),
    1229 => 
    array (
      'sha256' => 'ae067551d94c5a6e2bdb02285b2d70eaa2b38bfb04238803e2fed30c2ab3ee10',
      'label' => 'z125-subframe.php',
    ),
    1230 => 
    array (
      'sha256' => '27657354ac72c954c28d373c9f45bc8a75b9b5509d4e64194f3194f3c18cabd6',
      'label' => 'wii-usb-loader-2019.php',
    ),
    1231 => 
    array (
      'sha256' => '268297191230ec740c25de0cfa1be7ec4dbacaf19ce529c1b984e8e3013d062a',
      'label' => 'pycharm-no-tests-were-found.php',
    ),
    1232 => 
    array (
      'sha256' => '303c7bcc600e899ea267f9ead856c3ea8f6b52aaed3014a5542e5ec21737b544',
      'label' => 'dynaman-subbed.php',
    ),
    1233 => 
    array (
      'sha256' => '4c1b2ecd03703a94bbfc1b09d9d38a5c52167b19cd4a7e4035b4a84329670288',
      'label' => '2015-bassmaster-lake-guntersville.php',
    ),
    1234 => 
    array (
      'sha256' => 'd2920da309f8e6ff77a3aaf99d34ab72fcce738bf0b7f4c47ad3cf55553e7c4d',
      'label' => 'eagles-party-ideas.php',
    ),
    1235 => 
    array (
      'sha256' => 'edf82ce72216af160051756315e661c971990b53b2d6977021a71be3533b2575',
      'label' => 'tests.php',
    ),
    1236 => 
    array (
      'sha256' => '151b7c7bacf93dc11af638704910d97bc7b9f17d26ed72e6c5e9ed259b215832',
      'label' => 'lol-season-9.php',
    ),
    1237 => 
    array (
      'sha256' => 'b61bba310e401d2f5c74c474477ef8046dad58003f33313e1764b64c7a6b72e0',
      'label' => 'm4-vacuum-leak.php',
    ),
    1238 => 
    array (
      'sha256' => 'c6469fa3a7c908fa9d36dfcbeef022be375b021945560772cd3e25e28de4e3d5',
      'label' => 'ballet-class-music.php',
    ),
    1239 => 
    array (
      'sha256' => 'c02dfdb266ff2efecdbd441869d7b810b9b6352fb21d8fb82fad1039c175925a',
      'label' => 'knife-companies-list.php',
    ),
    1240 => 
    array (
      'sha256' => 'b7138a16e16451e1559a337153c643726dc53d1b3fb8636dc3784595f32d7e43',
      'label' => 'n920f-samsony.php',
    ),
    1241 => 
    array (
      'sha256' => '585e22f0c49c165ec03dcc5e3c65cf4faa7da7ae50596fe837f97aa168419287',
      'label' => 'used-20-hp-jet-outboard-for-sale.php',
    ),
    1242 => 
    array (
      'sha256' => 'a74930652a85cc3d0d12be449c8d029f3f500dac116622717ed0b157e2290168',
      'label' => 'android-instagram-story-cut-off.php',
    ),
    1243 => 
    array (
      'sha256' => 'a6cf1c440e57d5970e07d640beaf466b00ec3b16865b45c3ab510ce224fe755a',
      'label' => 'phone-ear-speaker-buzzing.php',
    ),
    1244 => 
    array (
      'sha256' => '8d015b660bef9b231880f5daddeb03b56f743efacf4f27313c126698aa5b5929',
      'label' => 'bats-in-attic-noise.php',
    ),
    1245 => 
    array (
      'sha256' => '6db74e672d12cd0e33dbd88824eb7cd9ed5312131382ce7976590178593c0b46',
      'label' => 'windows-10-update-assistant-1903.php',
    ),
    1246 => 
    array (
      'sha256' => 'cf76e249841c4fd01fc45ebe57c7ae4dad025b7289955d13159c3e4097123d7b',
      'label' => '2400mhz-vs-2666mhz.php',
    ),
    1247 => 
    array (
      'sha256' => 'fdb8517bfb526acd6320911da60e9378cc29aa43c56252156df451598a9f1f16',
      'label' => 'suntrust-login.php',
    ),
    1248 => 
    array (
      'sha256' => 'e82ad85c4aa40b6148724d642b4fab774c11d2cdd6f83a9ec980945c45535431',
      'label' => 'xc-plugin-epg.php',
    ),
    1249 => 
    array (
      'sha256' => 'e18372edfac4e79664cd4952fe0d25bb0a5487802bc3fe6b02142e8ee3f2f5dd',
      'label' => 'discourse-sso.php',
    ),
    1250 => 
    array (
      'sha256' => 'ca757ffde119ad0412152012f92a53be8176b33d31f05ca9d7a6f758c2c93152',
      'label' => 'sysprep-0x80070003.php',
    ),
    1251 => 
    array (
      'sha256' => '15f05f3549081e7e4fd3d0c5ec6a36db87541e5371087670400a236682ed0938',
      'label' => 'sea-group-garena.php',
    ),
    1252 => 
    array (
      'sha256' => '05a402155140ca2000540f56c1d17707c35ab54e88f8b87f117f44731a8995db',
      'label' => 'atoto-no-sound.php',
    ),
    1253 => 
    array (
      'sha256' => '67133b807f72e7d24a0e6cb12cb6c23e78b33bee1446076b8996b30b72d635d8',
      'label' => 'unscramble-motionr.php',
    ),
    1254 => 
    array (
      'sha256' => 'c9e4b1bc5945733d72c69f7a929d9cfc7cfb883abad3f9c67af4f11b84a1b6b8',
      'label' => 'hospital-design-pdf.php',
    ),
    1255 => 
    array (
      'sha256' => '99fc03c71dd86299f517769849108d5943f8410b357cca07f7aca8fda657ab1e',
      'label' => 'whatsminer-firmware-update.php',
    ),
    1256 => 
    array (
      'sha256' => 'a1e12a38f5264a8603029a8c5522dcba360288cec62fa70809b00760976f4b32',
      'label' => 'how-to-root-vivo-v5-plus.php',
    ),
    1257 => 
    array (
      'sha256' => 'f2a8cd0d026617f8c7cdc0892ce5fbed0c092992d451eddc3bf945d11497b9dc',
      'label' => 'laravel-500-error.php',
    ),
    1258 => 
    array (
      'sha256' => '26feb3cc7fc4a1466fe47ff2362c1e35efec7d0a019547329b0258a868b5bcd5',
      'label' => 'starlette-python-example.php',
    ),
    1259 => 
    array (
      'sha256' => 'a9050635fbd3406cfcc8149e4e42a050e48ff90cc7178557dbcf0b757fa21bad',
      'label' => 'format-dax.php',
    ),
    1260 => 
    array (
      'sha256' => '685099785ab4719e234c0979a6a403225ff917317d92d9e9aee8327cd9af6a57',
      'label' => 'jlink-clone.php',
    ),
    1261 => 
    array (
      'sha256' => 'c0e1c65522ff831a0ef566f58cc1bf7576cf9592572ab8eda124df0dc8178a03',
      'label' => 'catering-venues-of-birthdays-in-cape-town.php',
    ),
    1262 => 
    array (
      'sha256' => 'd52552e3737ec88a6dd23058d5336f44fec760cd47a30f199cd11f99c3c78f7a',
      'label' => 'infidel.php',
    ),
    1263 => 
    array (
      'sha256' => '7f52a4b2c039f2624e2df625729d4acd91bf74449a1f86b9a1b7805781f4373b',
      'label' => 'block-this-add.php',
    ),
    1264 => 
    array (
      'sha256' => 'a5b4bb6d302069e253268968f0d8c66452520fa93899ed71e065802cdc8a30f5',
      'label' => 'warez-bb-wiki.php',
    ),
    1265 => 
    array (
      'sha256' => '74e500cc06d2d96ebfeaa9705ce70737c25d418161b78958bd8eafb6ae50fd4f',
      'label' => 'mazda-rx-8-problems-solutions.php',
    ),
    1266 => 
    array (
      'sha256' => '60c19c41dbd7f852423b7e044799ad84d4f16bf4c2db55b0ffb89af7a73ef267',
      'label' => '3-ft-black-welded-wire-fence.php',
    ),
    1267 => 
    array (
      'sha256' => 'f1292179bed27d5fc9cfaac1e832af85f89143283dc31779a03490ec1d443bf8',
      'label' => 'uber-code.php',
    ),
    1268 => 
    array (
      'sha256' => '9eb6c77ffeede9d3ae09627ac11d12719abf0168eef2bc472ce7887ee553b723',
      'label' => 'free-drug-apps-for-android.php',
    ),
    1269 => 
    array (
      'sha256' => '6f389108e1a87a6d0a6d363a0d5331a772bd40d1f13e79a4b054fb3912eb52c2',
      'label' => 'geofabrik.php',
    ),
    1270 => 
    array (
      'sha256' => '30bfd01760f17cb497206772f289cc66ce58dd0961a41478e77fc61a590264d4',
      'label' => 'gilbarco-wow.php',
    ),
    1271 => 
    array (
      'sha256' => '3de3d353ffec1727805c4b4b051c7c2321f1296c7ba61ae3885694dbe38e5de6',
      'label' => 'german-pod-101.php',
    ),
    1272 => 
    array (
      'sha256' => 'd31a0518a571b02e96ba6da7ff9a903d55b2f46cfea01f868aa2d875a5c343ab',
      'label' => 'octagon-sx88.php',
    ),
    1273 => 
    array (
      'sha256' => '335a5e8af8b49e57dc20eea215b4e8605fc15808a5b04fed2581ba53aa927fb2',
      'label' => 'gmail-smtp-api.php',
    ),
    1274 => 
    array (
      'sha256' => 'b8b12310db945209f5066cfdb2b1fdc883f3ce801281f13ebd140cebcbd0bd56',
      'label' => 'fetty-wap-eye-makeup.php',
    ),
    1275 => 
    array (
      'sha256' => 'f8e99218d2e13018678cff166b4e1b1b097f00f675d2a61e0d7e61963e0fba71',
      'label' => 'fox-9-news-live.php',
    ),
    1276 => 
    array (
      'sha256' => '205040d45ab798d47afa9f4fbbde678bbb581e09c3169ec5b684a19cb7fca3d3',
      'label' => 'cinestyle-t3i.php',
    ),
    1277 => 
    array (
      'sha256' => 'e8be6d86356a36cf7fe5e1573d426887091623f6d3be8561ba39ceccaa08a46a',
      'label' => '2010-kawasaki-vulcan-2000.php',
    ),
    1278 => 
    array (
      'sha256' => '765c582814e324a615872bfed04e03499771ec2861c7d5680d35d8657dc14619',
      'label' => 'max9288.php',
    ),
    1279 => 
    array (
      'sha256' => 'ff96471424e8fe6e259a925a520ff437ed15444f05ac68ab73feb8dd7d2784e7',
      'label' => 'g3112-root.php',
    ),
    1280 => 
    array (
      'sha256' => 'd4009322dfe620e433861189a3548ee86bf025df99bbdb4a911a4ed1109601d4',
      'label' => 'dell-wyse-5030-manual.php',
    ),
    1281 => 
    array (
      'sha256' => 'f884930bf2bfefbc4b5edbc0753bd46a793e92f2f84aedef6f897f8ce61a4bf8',
      'label' => 'dnd-premade-shops.php',
    ),
    1282 => 
    array (
      'sha256' => '022a86e40b1ef4dbdd0470e1b67d8ff385bbd09ef98d6022f3d472bffc630dd4',
      'label' => 'xaml-to-html-converter-online.php',
    ),
    1283 => 
    array (
      'sha256' => 'd825ef4925e9dc16b4a11a3b7e5aeaa7cc0892efbdb7767b6f33da2d67229c89',
      'label' => 'anti-cheat-bypass-geometry-dash.php',
    ),
    1284 => 
    array (
      'sha256' => 'a972750dc0c79cf97ab3f4fe16414fade5c5f717c06ec37df13e681af0b5b0e9',
      'label' => 'google-dork.php',
    ),
    1285 => 
    array (
      'sha256' => 'e8c26f750abe869a7e9fcb85ebbd4323e689b99d42e2b1168cf1826e895008eb',
      'label' => 'proximate-analysis-of-biomass.php',
    ),
    1286 => 
    array (
      'sha256' => '9afcfe3061b9135cacbb0d853980c5ca1548a61f5b8646f33c2810c247609133',
      'label' => 'razer-pc.php',
    ),
    1287 => 
    array (
      'sha256' => 'fe1566011058a63e42a11cd34ececfbade77022204c66b7f7a158e2a5b6d0e82',
      'label' => 'opencart-mods.php',
    ),
    1288 => 
    array (
      'sha256' => '7cfa2facb87f53036115750f73a746e1556c1b7babd4645e2fb8bec48c20459b',
      'label' => 'kpk-physics-11-notes.php',
    ),
    1289 => 
    array (
      'sha256' => '8f95c293dab3fb2276188ad277c5023d4f562b0057888c6a556d66aa31fc7563',
      'label' => 'homemade-clue-game.php',
    ),
    1290 => 
    array (
      'sha256' => '495b794435eaa5a1f6c65076d279adcb0b28644029fbfa25787a707884e014b4',
      'label' => 'sky-iptv.php',
    ),
    1291 => 
    array (
      'sha256' => 'a512604e1e001ff09616cacdb5091b5950f5d24f23cda7ca6e59d71184d0886d',
      'label' => 'fiu-engineering-center-floor-map.php',
    ),
    1292 => 
    array (
      'sha256' => '5d206f8f2bc8b2c53793efbbd2358aa8f995759bff7f6c06548d8c9fe1d24108',
      'label' => 'urdu-sharah.php',
    ),
    1293 => 
    array (
      'sha256' => '5659790ca4c32e918f2f7a06c81d4fff566c1a6655a5a3252d3e1acc56a36d61',
      'label' => 'enumerator-jobs-in-ethiopia.php',
    ),
    1294 => 
    array (
      'sha256' => '6fefa5868e0a5fb0d037911ab07195bb5982755c627264a5866105c622d113ba',
      'label' => 'sulphuric-acid-oman.php',
    ),
    1295 => 
    array (
      'sha256' => '041b446fd001bfe37a21769afaf048f78545acc688817553d34e0cb24541bb12',
      'label' => 'wisconsin-paper-converters.php',
    ),
    1296 => 
    array (
      'sha256' => 'c2a2040f91507e0b8dd35bdff4a7c92fb93c3b80874132a8888c87d76f242dd3',
      'label' => 'smart-social-login-shopify.php',
    ),
    1297 => 
    array (
      'sha256' => '84e2bea6b5f6b44605dfb46be283798e9fda91dd7fc4050851729858ffafb6d0',
      'label' => 'arris-tm804-ds-light.php',
    ),
    1298 => 
    array (
      'sha256' => '6dfbef4a6328e630334434f5ad02d64aa944fd15de4cd2d98f8a8768ec1c5428',
      'label' => 'ymusic-ad-free.php',
    ),
    1299 => 
    array (
      'sha256' => '67d6714c6cb9adbb724aed17df8f797cb53540cccce1fe94d451db109265fd27',
      'label' => 'mobile-mohs-inc.php',
    ),
    1300 => 
    array (
      'sha256' => 'e09e2b2a438962f08f3a8d89ab9adb0ef9c33365af93ea247e42d26267cf740d',
      'label' => 'node-js-workflow-builder.php',
    ),
    1301 => 
    array (
      'sha256' => '62bc2e4886d961532ddb6286757ddf711ddc5c25074f801a0444a56ff7321a41',
      'label' => 'snacks-distribution-business.php',
    ),
    1302 => 
    array (
      'sha256' => 'a7f09b3e9772d5c47acb21830e53fbcf9bb48c89df2984bdd7bef8d927f59396',
      'label' => '3proxy-github.php',
    ),
    1303 => 
    array (
      'sha256' => '46cf76c9dc42f0f291ebff42dba3793a51998e443722a20fb528055d02884d84',
      'label' => 'fsx-aw189.php',
    ),
    1304 => 
    array (
      'sha256' => '41e39911a150fb0ec228cbda007c1ae0c613d47d83b6b9112d83178d084c76f7',
      'label' => 'local-7-union-denver.php',
    ),
    1305 => 
    array (
      'sha256' => 'ea5c49a35dcd473dbfde5225fd4dad3b93601ebffa9e3dc144fed32a4379134c',
      'label' => 'pet-friendly-hotels.php',
    ),
    1306 => 
    array (
      'sha256' => '9ac953dc70ca8d4d60b3c4fb607e023b26e78e275a6980b782354af3324a7e54',
      'label' => 'do-frogs-make-a-sound-like-a-cat.php',
    ),
    1307 => 
    array (
      'sha256' => '8507f227c8e2dfc1e65dc5735c782106421fbccae610579bed0d71b7c5303564',
      'label' => 'toluna.php',
    ),
    1308 => 
    array (
      'sha256' => '08073aaa83d3e5e457142c1e7745c19287aae073d812e6c43896fd07d575dc76',
      'label' => 'zbrush-logo.php',
    ),
    1309 => 
    array (
      'sha256' => 'dd68f7e2bb84b0f1fd0b4e33c20b3238f9151cf7d80438402a21b5f4cd3fdedc',
      'label' => 'fake-au-generator.php',
    ),
    1310 => 
    array (
      'sha256' => 'dede159a1b8c5658f6613dfbb81406e3f72aa65795e99c416b1905e3b4214596',
      'label' => 'meteor-garden-2018-ep-2-eng-sub-dramacool.php',
    ),
    1311 => 
    array (
      'sha256' => '6c54cf0f81237dbbe366e051f854e40324766dedaa5e29075da1a215787c4b75',
      'label' => 'css-gooey-effect.php',
    ),
    1312 => 
    array (
      'sha256' => 'ad4ed7247eaa4c1bd0e2fa9a89fd1d3b99c5af0e7881c8fb61027f83295442af',
      'label' => 'fortigate-external-ip-block-list.php',
    ),
    1313 => 
    array (
      'sha256' => 'a03b63830c7eb55d53459e50f112bde407e1f18cc4a5d7f6facda7de5c701fbb',
      'label' => '2019-dynamax-isata-4-25fw.php',
    ),
    1314 => 
    array (
      'sha256' => 'f6f37e391b205748ab371eca5ff4b754a0bf8e73e3fbdceb43c1e3c80a16d5b9',
      'label' => 'rar-to-iso.php',
    ),
    1315 => 
    array (
      'sha256' => '9cedf11bccb68c230e82b055ac312f33e26f739a7e158beec2f8e4e1649541ab',
      'label' => 'cozy-app.php',
    ),
    1316 => 
    array (
      'sha256' => '2eaac9b16e47dbd10af6fc6b5109203471055d434b22ff246a5594d6c0237622',
      'label' => 'africa-geojson.php',
    ),
    1317 => 
    array (
      'sha256' => '3e2af4b64a037361d2b5561de788ec41659e9e204a7ab941bca36b182c1f5c50',
      'label' => 'blue.php-3e2af4b64a03',
    ),
    1318 => 
    array (
      'sha256' => 'fcd62ed22f8734920fdf3204e10a33464ae2648233cc7e2e04b2fcbec5c9a05b',
      'label' => 'functions.php-fcd62ed22f87',
    ),
    1319 => 
    array (
      'sha256' => '5c16c723624a089147f7e2186dc16472af23c0a090a3efb8fb8272a79b7492e8',
      'label' => 'data.php',
    ),
    1320 => 
    array (
      'sha256' => '6ec3cfce68222310ea14f6c195fce64bf95da5421e50fd8746da147b91b750ac',
      'label' => 'src.php',
    ),
    1321 => 
    array (
      'sha256' => '84a9560379e61da79f1b9494cd9004ad5e02efde20ef2eb4915848a2e7f03a13',
      'label' => 'container.php',
    ),
    1322 => 
    array (
      'sha256' => 'd7527ec6785a87c04ab3d43037261392edb680750acc6bdf72cf1175116f74ca',
      'label' => 'header.php-d7527ec6785a',
    ),
    1323 => 
    array (
      'sha256' => '392735a9b5019aefa02c800a7b24873fc09ec02d26fe0091030e181f5e1cfae3',
      'label' => 'login.php-392735a9b501',
    ),
    1324 => 
    array (
      'sha256' => '40fa9efef031aa0f28e29485d028e71b8a8a233620a06e50d612c86c9313aad1',
      'label' => 'sy.php',
    ),
    1325 => 
    array (
      'sha256' => 'c38c38c5dd262f5e8015a3372e81f952e22da565bccf8825bfc99f4ad1059f45',
      'label' => 'insidePOSTcontent.php',
    ),
    1326 => 
    array (
      'sha256' => '16cc1627f5fe94abc57b677aa4f5293b7aa63d784a69ab5aae5f7491cc743a8c',
      'label' => 'autoload.php',
    ),
    1327 => 
    array (
      'sha256' => '3e86f0e5393a9e634b87ed7d342c8e8a4e61fb7bc7b63fc7f7939f1664f89d42',
      'label' => '48WJRPTlZBy.php',
    ),
    1328 => 
    array (
      'sha256' => 'e6d5891dcc5d443e81d5c755e9c7be20b33629b072288d5ec15fb6477cab1ab0',
      'label' => '1IXfrCTFSkN.php',
    ),
    1329 => 
    array (
      'sha256' => 'b26393285dbc1a77a36a33c9954a367c15a002088522c87c87a22dbccae4750b',
      'label' => 'vstasawqtt.php',
    ),
    1330 => 
    array (
      'sha256' => 'b9e7a913706c3be94af4b01284842affc93402280d50f8107cdf1e3203a434cc',
      'label' => 'u8T5sPY1zKV.php',
    ),
    1331 => 
    array (
      'sha256' => 'b76dd041f788efe1bd55535ac999f7b0b4778394cf8ba4839345c958ff0436a5',
      'label' => 'aqg7pYkHXR1.php',
    ),
    1332 => 
    array (
      'sha256' => '68e89d922b06a54973950e177741cb025cba52b80ddbbb90099aef597573f6d9',
      'label' => 'yos2zebCyw4.php',
    ),
    1333 => 
    array (
      'sha256' => '9c2e7f54c3a375b98154d6d00c329c836ef57a9fed402184f4e6ba3675256986',
      'label' => 'hnjsklepxv.php',
    ),
    1334 => 
    array (
      'sha256' => '79c7ae0b03e10474b8154ef7cab221f61bcc685f8ff44fbc03c562df530b0d1c',
      'label' => 'F1xurnS5IKJ.php',
    ),
    1335 => 
    array (
      'sha256' => 'ff69b486823b6f4544ebbb1f642af15a11d06055db9c7fc5bcd1851ebc2dad9a',
      'label' => 'vP365Y2LyKM.php',
    ),
    1336 => 
    array (
      'sha256' => 'b0b4bdef2c404312f8a3b70c2056d46645f595ba067679f725328118e5c8e551',
      'label' => '404.php-b0b4bdef2c40',
    ),
    1337 => 
    array (
      'sha256' => '69402f865bdb74e6dd8c80cc3869ed4723136b9e493645184322f3a8401b85f1',
      'label' => '4522171d318.php',
    ),
    1338 => 
    array (
      'sha256' => 'a605092cc1c1125a46a4d194a07c74d1b98f04749b126cbb2312b322b5ab5b29',
      'label' => 'index.php-a605092cc1c1',
    ),
    1339 => 
    array (
      'sha256' => '396c5f6dfcc15e2c736e845e57a00f34ed15a732c30c9dad0a3e11dea8ee390d',
      'label' => 'seassons.php',
    ),
    1340 => 
    array (
      'sha256' => '1e4ee97ec0e6732e0fb702231fe4d15de2e343f60ce94d263d89427af53b6b67',
      'label' => 'woocommerce-example.php',
    ),
    1341 => 
    array (
      'sha256' => '113e208f3384a94df152b2c510ef0a7b0a9f3122f5228336def17c0a05f1aa8b',
      'label' => 'index.php-113e208f3384',
    ),
    1342 => 
    array (
      'sha256' => '00528ff153cb5a300cd3a9d779ec66f39a2b59e197e683d7cfdb80384edac31b',
      'label' => 'bestside.php',
    ),
    1343 => 
    array (
      'sha256' => '4e6e34866e5fa25e52af1befa4264d6ec20362d162285efbfb0227ef765a74da',
      'label' => 'index3.php-4e6e34866e5f',
    ),
    1344 => 
    array (
      'sha256' => '3701d3f763e99a298f7839ff3d5aec8ea2683cbc9db6fda3232da9dc761138e1',
      'label' => '403.php',
    ),
    1345 => 
    array (
      'sha256' => '43450ac33388d15a54c8043487337dcce2c44bd6795fb0477809278a192136c1',
      'label' => 'antibot-config.php',
    ),
    1346 => 
    array (
      'sha256' => 'a5bd40e74e5d7cc211374fe8b48f119dc0c2ff6980a97ba6d264b472a91cb8ea',
      'label' => 'wp-load.php-a5bd40e74e5d',
    ),
    1347 => 
    array (
      'sha256' => '0758301cf241ba8189b77e22a2357dd9ad26a35719674960a49d9d19b4b46e6c',
      'label' => 'index2.php-0758301cf241',
    ),
    1348 => 
    array (
      'sha256' => '5e95e3405ac872687db2eb218ac5a8f0c8783cf1570f82dbea7dfd73b17bf2b9',
      'label' => 'antibot.php',
    ),
    1349 => 
    array (
      'sha256' => 'cf3d7f1906f9797b6ed2f0cd153d6bbbb2b57506863b62038e9f6ea492a0cef4',
      'label' => 'init.php',
    ),
    1350 => 
    array (
      'sha256' => '890b4f8d47f74ae15f4c6452dd43ae39813041e1ec2fae2b247b12b5213266d8',
      'label' => 'config.php-890b4f8d47f7',
    ),
    1351 => 
    array (
      'sha256' => '5988f56b113dd699c60f97842374978ffb2daad19e121e61a2bd2504e9d144bc',
      'label' => 'mplugin.php',
    ),
    1352 => 
    array (
      'sha256' => '0543b10bb644bf2bd31e490991e724fb8d5ba2859fcbeb10b5efb4ce5397a881',
      'label' => 'wp-settings.php-0543b10bb644',
    ),
    1353 => 
    array (
      'sha256' => 'c9ca6a3a7cbc440c64b81cfc1a900ee322f9e607df013e5078cfb852efeeaaf5',
      'label' => 'wikindex.php-c9ca6a3a7cbc',
    ),
    1354 => 
    array (
      'sha256' => '88a8e6278af2b797aef537c2fa732e3ae0c2210aa4e8e5ef890cc25a924370f4',
      'label' => 'wp-engine.php-88a8e6278af2',
    ),
    1355 => 
    array (
      'sha256' => 'e81dfc000974436e03f2b359e373b9fd6b8575d18d446450733eb122fd6b3ea0',
      'label' => 'index.php-e81dfc000974',
    ),
    1356 => 
    array (
      'sha256' => '26da8986e026deec9d11e6ad069c9e417c639d8250701732ef08ebb06da72a26',
      'label' => '0z.php',
    ),
    1357 => 
    array (
      'sha256' => '50ec7a0d0cf4b76c47358cf8c9a78f4434959240fe4d3db20ec6159992b47632',
      'label' => 'wp-logn.php',
    ),
    1358 => 
    array (
      'sha256' => 'fba2e786e20dd687de9db2c110085759c9a24553e4cade89acf840676d56b3dd',
      'label' => '9cb456bd866c8769e38da7b9d64415e4akc.php',
    ),
    1359 => 
    array (
      'sha256' => 'd5cd1086cff2514413e1506daf11228a2b50ec9d29040004892298c0ed3e8001',
      'label' => 'search.php',
    ),
    1360 => 
    array (
      'sha256' => '309aeaa09324c0ad2caf4eca2a136b4ed2ae717b6493ea3c900ed75d6ca4841a',
      'label' => 'index.php-309aeaa09324',
    ),
    1361 => 
    array (
      'sha256' => '094626499c4e878ffdddefd0bafc5cad60814cb9902eb91d9525555e78b085c9',
      'label' => 'linklove.php',
    ),
    1362 => 
    array (
      'sha256' => 'ab1b386d21102bf86f1606cef718c2656e4ab2a167a39f084c4e891c96b9f318',
      'label' => 'jquery.min.js',
    ),
    1363 => 
    array (
      'sha256' => 'a10a42f05f4a9f06d6577ce4d48652a70c0069d79e3270a691a2c51ada5741bd',
      'label' => 'index.min.js',
    ),
    1364 => 
    array (
      'sha256' => 'a50a1e3b15ceea4c2030e11457fcd326b2902627a7da03f11a2f5d810996e28d',
      'label' => 'field_import_export.js',
    ),
    1365 => 
    array (
      'sha256' => '4728e2fe2c6f4b4c201c6b217a229deb738bd805fd80c11ca72f7832a9ee451a',
      'label' => 'field_ace_editor.js',
    ),
    1366 => 
    array (
      'sha256' => '3b673f32babd9a3beed9cbb77227d88c945b7422dcc76be2fd9630f4917f93f9',
      'label' => 'deprecated.min.js',
    ),
    1367 => 
    array (
      'sha256' => '9aa4b225b9951e6d5fac7ae675a08fd8083b8acab9c38cae51a61afc858034c2',
      'label' => 'index.php-9aa4b225b995',
    ),
    1368 => 
    array (
      'sha256' => 'a44a446ebeee69409ffeadbd29c1c9d69fbc1f56abad67fc9604dbc6e516125c',
      'label' => 'windex.php-a44a446ebeee',
    ),
    1369 => 
    array (
      'sha256' => 'f6e6b312ece84b76d9cd7e31553ea905ca08e9d44ff57dddeba5a5bd592eb165',
      'label' => 'index.php-f6e6b312ece8',
    ),
    1370 => 
    array (
      'sha256' => '7317fa4103e2c4ceeec38d934161d46f73590a524fa304f7cf5094f541f0dbf7',
      'label' => 'kindex.php-7317fa4103e2',
    ),
    1371 => 
    array (
      'sha256' => 'd07e0c0e9ac5958e777867f760d2d451d57aee3f148b46a863763db20aea7141',
      'label' => 'wp-load.php-d07e0c0e9ac5',
    ),
    1372 => 
    array (
      'sha256' => '4953fe7328ff13c3f35c93b7d0b3e5acda1d01cbd402aae6ff709e93dea6e1e4',
      'label' => 'index.php-4953fe7328ff',
    ),
    1373 => 
    array (
      'sha256' => '8449d728211f70513dbf35afe8ccb2036e65e2ffefdc29aec8eefdd61b5bbf1e',
      'label' => 'WP-MU-Core.php',
    ),
    1374 => 
    array (
      'sha256' => '7a9d2eba765c7c0ea58caa4f6e5e14c3a63a7e51eca35fb133875edadc3d9843',
      'label' => 'cfkvgwvt.php',
    ),
    1375 => 
    array (
      'sha256' => '0b53a6154d5b73087568dc0996ab05fba476e013872a1c665ab4843bc0d812dc',
      'label' => 'index.php-0b53a6154d5b',
    ),
    1376 => 
    array (
      'sha256' => '77d6e7aa35a846e4594e9a225d5d21e87887631e9764310d047966777bf4825b',
      'label' => 'index.php-77d6e7aa35a8',
    ),
    1377 => 
    array (
      'sha256' => 'ca08a4a0f054b7322a271e215d73356cff65be7960fe616ce5b21a0332386093',
      'label' => 'inputs.php',
    ),
    1378 => 
    array (
      'sha256' => 'b2ce15c73093c242ce31a1081f373b832cf47f40cd63e804ad096a45fb309dec',
      'label' => 'license.php-b2ce15c73093',
    ),
    1379 => 
    array (
      'sha256' => '00df7c6dbbf2a5f351cfb15ad0b32ac59951a9a7cf3a2c048eab7d17c4a10671',
      'label' => 'cjh.php',
    ),
    1380 => 
    array (
      'sha256' => '475294eb1c78d4f3dd4058180de9a1d8641a0cd718b340b5caeabf7eae76c80f',
      'label' => 'f.php',
    ),
    1381 => 
    array (
      'sha256' => '8427273451b4d820c77c6cd4c88a433d7dfc27a58b078cbc0e361bb953dcd184',
      'label' => 'cxkvsexkyd.php',
    ),
    1382 => 
    array (
      'sha256' => 'c0705c5322a6aa3df0f0843d2156e5649844ea844bab1d65a5b970f425f8c4a7',
      'label' => '1jp.php',
    ),
    1383 => 
    array (
      'sha256' => '10a27df3ec7012e3ee1935830a5842b67b164103a9f4e6bedcef5d6a6e5ecb28',
      'label' => 'index.php-10a27df3ec70',
    ),
    1384 => 
    array (
      'sha256' => 'b09843b01478771fb9dae520273f663322627f9d5f7fc317f623401e33e2fdd6',
      'label' => 'file.php',
    ),
    1385 => 
    array (
      'sha256' => 'a7fd018dfd22b68a0d72a55572b3922ec271f7649f86f1745ed37e8c63a91928',
      'label' => 'byp.php',
    ),
  ),
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
