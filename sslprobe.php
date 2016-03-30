#!/usr/bin/php
<?php
	chdir( __DIR__ );
	
	$server = $argv[1];

	require_once( "termcolours.inc" );

	print( "Version:   " . bblue(SSLinfo::openssl_version()) . "\n" );
	print( "Server:    " . bblue($server) . "\n" );


	print( "Protocol support:" );

	$protos = array( "SSL3" => false, "TLS10" => false, "TLS11" => false, "TLS12" => false );
	$server_protocols = array();
	foreach ( $protos as $p => $k )
	{
		$pp = $protos;
		$pp[$p] = true;

		$cc = SSLinfo::connect( $server, true, $pp );
		print( "  " );
		if ( $cc )
		{
			$server_protocols[] = $p;

			if ( substr($p,0,3) == "SSL" )  print( bred( $p ) );
			elseif ( $p === "TLS12" )       print( bgreen( $p ) );
			else print( green( $p ) );
		}
		else
			print( bblack( $p ) );
	}
	print( "\n\n" );


	print( "Browser ciphers:\n" );

	$browsers = SSLinfo::get_browsers();

	foreach ( $browsers as $name => $BI )
	{
		print( "   " . blue($name) );
		print( str_repeat(" ",20-mb_strlen($name)) . " :  " );

		$cc = SSLinfo::connect( $server, $BI["ciphers"], $BI["protocol-support"] );
		if ( !$cc )
			print( red( "Error" ) . "\n" );
		else
			print( SSLinfo::format_cipher($cc) . "\n" );
	}


	$dh = SSLinfo::dh_size( $server );
	$ecdh = SSLinfo::ecdh_size( $server );
	if ( $dh || $ecdh )
		print( "\n" );

	if ( $dh )
	{
		print( "Diffie-Helmann parameter size:           " );

		$fdh = sprintf( "%5d", $dh );

		if ( $dh < 1526 )
			print( red( $fdh . "   WEAK" ) );
		elseif ( $dh < 2048 )
			print( yellow( $fdh ) );
		else
			print( green( $fdh ) );

		print( "\n" );
	}
	if ( $ecdh )
	{
		print( "Elliptic curve:  " . purple($ecdh["name"]) . ";  " );

		$eqdh = SSLinfo::ecbits_to_ff( $ecdh["ecbits"] );

		$fecdh = sprintf( "%4d", $ecdh["ecbits"] );
		$feqdh = sprintf( "%5d", $eqdh );

		if ( $eqdh <= 1526 )
			print( red( $fecdh ) . " -> eq. " . red( $feqdh . "   WEAK" ) );
		elseif ( $eqdh <= 2048 )
			print( yellow( $fecdh ) . " -> eq. " . yellow( $feqdh ) );
		else
			print( green( $fecdh ) . " -> eq. " . green( $feqdh ) );

		print( "\n" );
	}


	print( "\n" );

	if ( !in_array( "--very-quick", $argv ) )
	{
		print( "Cipher suites, in server-preferred order:\n" );

		$server_protocols = array_reverse( $server_protocols );
		foreach ( $server_protocols as $p )
		{
			print( "{$p}\n" );

			$suites = SSLinfo::server_probe( $server, $p );
			foreach ( $suites as $cc )
			{
				print( "   " . SSLinfo::format_cipher($cc) . "\n" );
			}
			if ( !in_array( "--quick", $argv ) )
			{
				break;
			}
		}

		print( "\n" );
	}


	class SSLinfo
	{
		protected static $map;
		protected static $curve_map;
		protected static $openssl;

		public static function init_though()
		{
			self::$openssl = "openssl";

			if ( is_executable("bin/custom-openssl") )
			{
				self::$openssl = "bin/custom-openssl";
			}

			self::$map = array(

				// TLS v1.0 cipher suites.
				"TLS_RSA_WITH_NULL_MD5"                           => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "NULL-MD5", ),
				"TLS_RSA_WITH_NULL_SHA"                           => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "NULL-SHA", ),
				"TLS_RSA_EXPORT_WITH_RC4_40_MD5"                  => array( "cipher-strength" =>  400, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-RC4-MD5", ),
				"TLS_RSA_WITH_RC4_128_MD5"                        => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "RC4-MD5", ),
				"TLS_RSA_WITH_RC4_128_SHA"                        => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "RC4-SHA", ),
				"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"              => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-RC2-CBC-MD5", ),
				"TLS_RSA_WITH_IDEA_CBC_SHA"                       => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "IDEA-CBC-SHA", ),
				"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"               => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-DES-CBC-SHA", ),
				"TLS_RSA_WITH_DES_CBC_SHA"                        => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DES-CBC-SHA", ),
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA"                   => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DES-CBC3-SHA", ),
				"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"            => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"TLS_DH_DSS_WITH_DES_CBC_SHA"                     => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"                => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"            => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"TLS_DH_RSA_WITH_DES_CBC_SHA"                     => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"                => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"           => array( "cipher-strength" =>   40, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "EXP-DHE-DSS-DES-CBC-SHA", ),
				"TLS_DHE_DSS_WITH_DES_CBC_SHA"                    => array( "cipher-strength" =>   56, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-CBC-SHA", ),
				"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"               => array( "cipher-strength" =>  112, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-DES-CBC3-SHA", ),
				"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"           => array( "cipher-strength" =>   40, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "EXP-DHE-RSA-DES-CBC-SHA", ),
				"TLS_DHE_RSA_WITH_DES_CBC_SHA"                    => array( "cipher-strength" =>   56, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-DES-CBC-SHA", ),
				"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"               => array( "cipher-strength" =>  112, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-DES-CBC3-SHA", ),
				"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"              => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-ADH-RC4-MD5", ),
				"TLS_DH_anon_WITH_RC4_128_MD5"                    => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-RC4-MD5", ),
				"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"           => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-ADH-DES-CBC-SHA", ),
				"TLS_DH_anon_WITH_DES_CBC_SHA"                    => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-DES-CBC-SHA", ),
				"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"               => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-DES-CBC3-SHA", ),

				// AES ciphersuites from RFC3268, extending TLS v1.0
				"TLS_RSA_WITH_AES_128_CBC_SHA"                    => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AES128-SHA", ),
				"TLS_RSA_WITH_AES_256_CBC_SHA"                    => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AES256-SHA", ),
				"TLS_DH_DSS_WITH_AES_128_CBC_SHA"                 => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-AES128-SHA", ),
				"TLS_DH_DSS_WITH_AES_256_CBC_SHA"                 => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-AES256-SHA", ),
				"TLS_DH_RSA_WITH_AES_128_CBC_SHA"                 => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-AES128-SHA", ),
				"TLS_DH_RSA_WITH_AES_256_CBC_SHA"                 => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-AES256-SHA", ),
				"TLS_DHE_DSS_WITH_AES_128_CBC_SHA"                => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-AES128-SHA", ),
				"TLS_DHE_DSS_WITH_AES_256_CBC_SHA"                => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-AES256-SHA", ),
				"TLS_DHE_RSA_WITH_AES_128_CBC_SHA"                => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-AES128-SHA", ),
				"TLS_DHE_RSA_WITH_AES_256_CBC_SHA"                => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-AES256-SHA", ),
				"TLS_DH_anon_WITH_AES_128_CBC_SHA"                => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-AES128-SHA", ),
				"TLS_DH_anon_WITH_AES_256_CBC_SHA"                => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-AES256-SHA", ),

				// Camellia ciphersuites from RFC4132, extending TLS v1.0
				"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"               => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "CAMELLIA128-SHA", ),
				"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"               => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "CAMELLIA256-SHA", ),
				"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"            => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-CAMELLIA128-SHA", ),
				"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"            => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-CAMELLIA256-SHA", ),
				"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"            => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-CAMELLIA128-SHA", ),
				"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"            => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-CAMELLIA256-SHA", ),
				"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"           => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-CAMELLIA128-SHA", ),
				"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"           => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-CAMELLIA256-SHA", ),
				"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"           => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-CAMELLIA128-SHA", ),
				"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"           => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-CAMELLIA256-SHA", ),
				"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"           => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-CAMELLIA128-SHA", ),
				"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"           => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-CAMELLIA256-SHA", ),

				// SEED ciphersuites from RFC4162, extending TLS v1.0
				"TLS_RSA_WITH_SEED_CBC_SHA"                       => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SEED-SHA", ),
				"TLS_DH_DSS_WITH_SEED_CBC_SHA"                    => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-SEED-SHA", ),
				"TLS_DH_RSA_WITH_SEED_CBC_SHA"                    => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-SEED-SHA", ),
				"TLS_DHE_DSS_WITH_SEED_CBC_SHA"                   => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-SEED-SHA", ),
				"TLS_DHE_RSA_WITH_SEED_CBC_SHA"                   => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-SEED-SHA", ),
				"TLS_DH_anon_WITH_SEED_CBC_SHA"                   => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-SEED-SHA", ),

				// GOST ciphersuites from draft-chudov-cryptopro-cptls, extending TLS v1.0
				// Note: these ciphers require an engine which including GOST cryptographic algorithms, such as the ccgost engine, included in the OpenSSL distribution.
				"TLS_GOSTR341094_WITH_28147_CNT_IMIT"             => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "GOST94-GOST89-GOST89", ),
				"TLS_GOSTR341001_WITH_28147_CNT_IMIT"             => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "GOST2001-GOST89-GOST89", ),
				"TLS_GOSTR341094_WITH_NULL_GOSTR3411"             => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "GOST94-NULL-GOST94", ),
				"TLS_GOSTR341001_WITH_NULL_GOSTR3411"             => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "GOST2001-NULL-GOST94", ),

				// Additional Export 1024 and other cipher suites

				// Note: these ciphers can also be used in SSL v3.
				"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"             => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP1024-DES-CBC-SHA", ),
				"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"              => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP1024-RC4-SHA", ),
				"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"         => array( "cipher-strength" =>   56, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "EXP1024-DHE-DSS-DES-CBC-SHA", ),
				"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"          => array( "cipher-strength" =>   56, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "EXP1024-DHE-DSS-RC4-SHA", ),
				"TLS_DHE_DSS_WITH_RC4_128_SHA"                    => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-RC4-SHA", ),

				// Elliptic curve cipher suites.
				"TLS_ECDH_RSA_WITH_NULL_SHA"                      => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-NULL-SHA", ),
				"TLS_ECDH_RSA_WITH_RC4_128_SHA"                   => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-RC4-SHA", ),
				"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"              => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-DES-CBC3-SHA", ),
				"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"               => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-AES128-SHA", ),
				"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"               => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-AES256-SHA", ),

				"TLS_ECDH_ECDSA_WITH_NULL_SHA"                    => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-NULL-SHA", ),
				"TLS_ECDH_ECDSA_WITH_RC4_128_SHA"                 => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-RC4-SHA", ),
				"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"            => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-DES-CBC3-SHA", ),
				"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"             => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-AES128-SHA", ),
				"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"             => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-AES256-SHA", ),

				"TLS_ECDHE_RSA_WITH_NULL_SHA"                     => array( "cipher-strength" =>    0, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-NULL-SHA", ),
				"TLS_ECDHE_RSA_WITH_RC4_128_SHA"                  => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-RC4-SHA", ),
				"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"             => array( "cipher-strength" =>  112, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-DES-CBC3-SHA", ),
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"              => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-AES128-SHA", ),
				"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"              => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-AES256-SHA", ),

				"TLS_ECDHE_ECDSA_WITH_NULL_SHA"                   => array( "cipher-strength" =>    0, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-NULL-SHA", ),
				"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"                => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-RC4-SHA", ),
				"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"           => array( "cipher-strength" =>  112, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-DES-CBC3-SHA", ),
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"            => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-AES128-SHA", ),
				"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"            => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-AES256-SHA", ),

				"TLS_ECDH_anon_WITH_NULL_SHA"                     => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AECDH-NULL-SHA", ),
				"TLS_ECDH_anon_WITH_RC4_128_SHA"                  => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AECDH-RC4-SHA", ),
				"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"             => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AECDH-DES-CBC3-SHA", ),
				"TLS_ECDH_anon_WITH_AES_128_CBC_SHA"              => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AECDH-AES128-SHA", ),
				"TLS_ECDH_anon_WITH_AES_256_CBC_SHA"              => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AECDH-AES256-SHA", ),

				// TLS v1.2 cipher suites
				"TLS_RSA_WITH_NULL_SHA256"                        => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "NULL-SHA256", ),
				"TLS_RSA_WITH_AES_128_CBC_SHA256"                 => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AES128-SHA256", ),
				"TLS_RSA_WITH_AES_256_CBC_SHA256"                 => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "AES256-SHA256", ),
				"TLS_RSA_WITH_AES_128_GCM_SHA256"                 => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "AES128-GCM-SHA256", ),
				"TLS_RSA_WITH_AES_256_GCM_SHA384"                 => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "AES256-GCM-SHA384", ),
				"TLS_DH_RSA_WITH_AES_128_CBC_SHA256"              => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-AES128-SHA256", ),
				"TLS_DH_RSA_WITH_AES_256_CBC_SHA256"              => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-AES256-SHA256", ),
				"TLS_DH_RSA_WITH_AES_128_GCM_SHA256"              => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "DH-RSA-AES128-GCM-SHA256", ),
				"TLS_DH_RSA_WITH_AES_256_GCM_SHA384"              => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "DH-RSA-AES256-GCM-SHA384", ),
				"TLS_DH_DSS_WITH_AES_128_CBC_SHA256"              => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-AES128-SHA256", ),
				"TLS_DH_DSS_WITH_AES_256_CBC_SHA256"              => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-AES256-SHA256", ),
				"TLS_DH_DSS_WITH_AES_128_GCM_SHA256"              => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "DH-DSS-AES128-GCM-SHA256", ),
				"TLS_DH_DSS_WITH_AES_256_GCM_SHA384"              => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "DH-DSS-AES256-GCM-SHA384", ),
				"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"             => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-AES128-SHA256", ),
				"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"             => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-AES256-SHA256", ),
				"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"             => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "DHE-RSA-AES128-GCM-SHA256", ),
				"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"             => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "DHE-RSA-AES256-GCM-SHA384", ),
				"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"             => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-AES128-SHA256", ),
				"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"             => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-AES256-SHA256", ),
				"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"             => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "DHE-DSS-AES128-GCM-SHA256", ),
				"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"             => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "DHE-DSS-AES256-GCM-SHA384", ),
				"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"            => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-AES128-SHA256", ),
				"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"            => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-AES256-SHA384", ),
				"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"            => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "ECDH-RSA-AES128-GCM-SHA256", ),
				"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"            => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "ECDH-RSA-AES256-GCM-SHA384", ),
				"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"          => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-AES128-SHA256", ),
				"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"          => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-AES256-SHA384", ),
				"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"          => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "ECDH-ECDSA-AES128-GCM-SHA256", ),
				"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"          => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "ECDH-ECDSA-AES256-GCM-SHA384", ),
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"           => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-AES128-SHA256", ),
				"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"           => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-AES256-SHA384", ),
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"           => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-RSA-AES128-GCM-SHA256", ),
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"           => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-RSA-AES256-GCM-SHA384", ),
				"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"         => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-AES128-SHA256", ),
				"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"         => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-AES256-SHA384", ),
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"         => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-ECDSA-AES128-GCM-SHA256", ),
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"         => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-ECDSA-AES256-GCM-SHA384", ),
				"TLS_DH_anon_WITH_AES_128_CBC_SHA256"             => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-AES128-SHA256", ),
				"TLS_DH_anon_WITH_AES_256_CBC_SHA256"             => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-AES256-SHA256", ),
				"TLS_DH_anon_WITH_AES_128_GCM_SHA256"             => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "ADH-AES128-GCM-SHA256", ),
				"TLS_DH_anon_WITH_AES_256_GCM_SHA384"             => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "ADH-AES256-GCM-SHA384", ),

				// Camellia HMAC-Based ciphersuites from RFC6367, extending TLS v1.2
				"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"    => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-CAMELLIA128-SHA256", ),
				"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"    => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-ECDSA-CAMELLIA256-SHA384", ),
				"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"     => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-CAMELLIA128-SHA256", ),
				"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"     => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-ECDSA-CAMELLIA256-SHA384", ),
				"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"      => array( "cipher-strength" =>  128, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-CAMELLIA128-SHA256", ),
				"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"      => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "ECDHE-RSA-CAMELLIA256-SHA384", ),
				"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"       => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-CAMELLIA128-SHA256", ),
				"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"       => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ECDH-RSA-CAMELLIA256-SHA384", ),

				// CHACHA20 ciphersuites from  draft-ietf-tls-chacha20-poly1305-04
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"   => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-ECDSA-CHACHA20-POLY1305", ),
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"     => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-RSA-CHACHA20-POLY1305", ),
				"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"       => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "RSA-PSK-CHACHA20-POLY1305", ),
				"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"       => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "DHE-PSK-CHACHA20-POLY1305", ),
				"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"     => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-PSK-CHACHA20-POLY1305", ),
				"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"       => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "DHE-RSA-CHACHA20-POLY1305", ),
				"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"           => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" =>  true, "openssl-name" => "PSK-CHACHA20-POLY1305", ),

				// Pre shared keying (PSK) cipheruites
				"TLS_PSK_WITH_RC4_128_SHA"                        => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "PSK-RC4-SHA", ),
				"TLS_PSK_WITH_3DES_EDE_CBC_SHA"                   => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "PSK-3DES-EDE-CBC-SHA", ),
				"TLS_PSK_WITH_AES_128_CBC_SHA"                    => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "PSK-AES128-CBC-SHA", ),
				"TLS_PSK_WITH_AES_256_CBC_SHA"                    => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "PSK-AES256-CBC-SHA", ),

				// Deprecated SSL v2.0 cipher suites.
				"SSL_CK_RC4_128_WITH_MD5"                         => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "RC4-MD5", ),
				"SSL_CK_RC4_128_EXPORT40_WITH_MD5"                => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-RC4-MD5", ),
				"SSL_CK_RC2_128_CBC_WITH_MD5"                     => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "RC2-MD5", ),
				"SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5"            => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-RC2-MD5", ),
				"SSL_CK_IDEA_128_CBC_WITH_MD5"                    => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "IDEA-CBC-MD5", ),
				"SSL_CK_DES_64_CBC_WITH_MD5"                      => array( "cipher-strength" =>   64, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DES-CBC-MD5", ),
				"SSL_CK_DES_192_EDE3_CBC_WITH_MD5"                => array( "cipher-strength" =>  192, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DES-CBC3-MD5", ),

				// SSL v3.0 cipher suites.
				"SSL_RSA_WITH_NULL_MD5"                           => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "NULL-MD5", ),
				"SSL_RSA_WITH_NULL_SHA"                           => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "NULL-SHA", ),
				"SSL_RSA_EXPORT_WITH_RC4_40_MD5"                  => array( "cipher-strength" =>  400, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-RC4-MD5", ),
				"SSL_RSA_WITH_RC4_128_MD5"                        => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "RC4-MD5", ),
				"SSL_RSA_WITH_RC4_128_SHA"                        => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "RC4-SHA", ),
				"SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5"              => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-RC2-CBC-MD5", ),
				"SSL_RSA_WITH_IDEA_CBC_SHA"                       => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "IDEA-CBC-SHA", ),
				"SSL_RSA_EXPORT_WITH_DES40_CBC_SHA"               => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-DES-CBC-SHA", ),
				"SSL_RSA_WITH_DES_CBC_SHA"                        => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DES-CBC-SHA", ),
				"SSL_RSA_WITH_3DES_EDE_CBC_SHA"                   => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DES-CBC3-SHA", ),
				"SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"            => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-DH-DSS-DES-CBC-SHA", ),
				"SSL_DH_DSS_WITH_DES_CBC_SHA"                     => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-DES-CBC-SHA", ),
				"SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA"                => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-DES-CBC3-SHA", ),
				"SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"            => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-DH-RSA-DES-CBC-SHA", ),
				"SSL_DH_RSA_WITH_DES_CBC_SHA"                     => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-DES-CBC-SHA", ),
				"SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA"                => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-DES-CBC3-SHA", ),
				"SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"           => array( "cipher-strength" =>   40, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "EXP-DHE-DSS-DES-CBC-SHA", ),
				"SSL_DHE_DSS_WITH_DES_CBC_SHA"                    => array( "cipher-strength" =>   56, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-CBC-SHA", ),
				"SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA"               => array( "cipher-strength" =>  112, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-DSS-DES-CBC3-SHA", ),
				"SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"           => array( "cipher-strength" =>   40, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "EXP-DHE-RSA-DES-CBC-SHA", ),
				"SSL_DHE_RSA_WITH_DES_CBC_SHA"                    => array( "cipher-strength" =>   56, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-DES-CBC-SHA", ),
				"SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"               => array( "cipher-strength" =>  112, "forward-secrecy" =>  true, "aead" => false, "openssl-name" => "DHE-RSA-DES-CBC3-SHA", ),
				"SSL_DH_anon_EXPORT_WITH_RC4_40_MD5"              => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-ADH-RC4-MD5", ),
				"SSL_DH_anon_WITH_RC4_128_MD5"                    => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-RC4-MD5", ),
				"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"           => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-ADH-DES-CBC-SHA", ),
				"SSL_DH_anon_WITH_DES_CBC_SHA"                    => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-DES-CBC-SHA", ),
				"SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"               => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "ADH-DES-CBC3-SHA", ),
				"SSL_FORTEZZA_KEA_WITH_NULL_SHA"                  => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"          => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)
				"SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"               => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => null, ),  //(Not implemented)

				// Ciphers not listed in the man page:
				"TLS_NULL_WITH_NULL_NULL"                         => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "NULL-MD5", ),
				"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"            => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-DH-DSS-DES-CBC-SHA", ),
				"TLS_DH_DSS_WITH_DES_CBC_SHA"                     => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-DES-CBC-SHA", ),
				"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"                => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-DSS-DES-CBC3-SHA", ),
				"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"            => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-DH-RSA-DES-CBC-SHA", ),
				"TLS_DH_RSA_WITH_DES_CBC_SHA"                     => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-DES-CBC-SHA", ),
				"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"                => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "DH-RSA-DES-CBC3-SHA", ),
				"TLS_KRB5_WITH_DES_CBC_SHA"                       => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-DES-CBC-SHA", ),
				"TLS_KRB5_WITH_3DES_EDE_CBC_SHA"                  => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-DES-CBC3-SHA", ),
				"TLS_KRB5_WITH_RC4_128_SHA"                       => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-RC4-SHA", ),
				"TLS_KRB5_WITH_IDEA_CBC_SHA"                      => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-IDEA-CBC-SHA", ),
				"TLS_KRB5_WITH_DES_CBC_MD5"                       => array( "cipher-strength" =>   56, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-DES-CBC-MD5", ),
				"TLS_KRB5_WITH_3DES_EDE_CBC_MD5"                  => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-DES-CBC3-MD5", ),
				"TLS_KRB5_WITH_RC4_128_MD5"                       => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-RC4-MD5", ),
				"TLS_KRB5_WITH_IDEA_CBC_MD5"                      => array( "cipher-strength" =>    0, "forward-secrecy" => false, "aead" => false, "openssl-name" => "KRB5-IDEA-CBC-MD5", ),
				"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"             => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-KRB5-DES-CBC-SHA", ),
				"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"             => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-KRB5-RC2-CBC-SHA", ),
				"TLS_KRB5_EXPORT_WITH_RC4_40_SHA"                 => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-KRB5-RC4-SHA", ),
				"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"             => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-KRB5-DES-CBC-MD5", ),
				"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"             => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-KRB5-RC2-CBC-MD5", ),
				"TLS_KRB5_EXPORT_WITH_RC4_40_MD5"                 => array( "cipher-strength" =>   40, "forward-secrecy" => false, "aead" => false, "openssl-name" => "EXP-KRB5-RC4-MD5", ),
				"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"               => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-3DES-EDE-CBC-SHA", ),
				"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"           => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-RSA-3DES-EDE-CBC-SHA", ),
				"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"           => array( "cipher-strength" =>  112, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-DSS-3DES-EDE-CBC-SHA", ),
				"TLS_SRP_SHA_WITH_AES_128_CBC_SHA"                => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-AES-128-CBC-SHA", ),
				"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"            => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-RSA-AES-128-CBC-SHA", ),
				"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"            => array( "cipher-strength" =>  128, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-DSS-AES-128-CBC-SHA", ),
				"TLS_SRP_SHA_WITH_AES_256_CBC_SHA"                => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-AES-256-CBC-SHA", ),
				"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"            => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-RSA-AES-256-CBC-SHA", ),
				"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"            => array( "cipher-strength" =>  256, "forward-secrecy" => false, "aead" => false, "openssl-name" => "SRP-DSS-AES-256-CBC-SHA", ),
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"     => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-RSA-CHACHA20-POLY1305", ),
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"   => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "ECDHE-ECDSA-CHACHA20-POLY1305", ),
				"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"       => array( "cipher-strength" =>  256, "forward-secrecy" =>  true, "aead" =>  true, "openssl-name" => "DHE-RSA-CHACHA20-POLY1305", ),
				"SSL_CK_RC4_64_WITH_MD5"                          => array( "cipher-strength" =>   64, "forward-secrecy" => false, "aead" => false, "openssl-name" => "RC4-64-MD5", ),

			);

			self::$curve_map = array(
				1  => array( "name" => "sect163k1", "ecbits" => 163 ),
				2  => array( "name" => "sect163r1", "ecbits" => 163 ),
				3  => array( "name" => "sect163r2", "ecbits" => 163 ),
				4  => array( "name" => "sect193r1", "ecbits" => 193 ),
				5  => array( "name" => "sect193r2", "ecbits" => 193 ),
				6  => array( "name" => "sect233k1", "ecbits" => 233 ),
				7  => array( "name" => "sect233r1", "ecbits" => 233 ),
				8  => array( "name" => "sect239k1", "ecbits" => 239 ),
				9  => array( "name" => "sect283k1", "ecbits" => 283 ),
				10 => array( "name" => "sect283r1", "ecbits" => 283 ),
				11 => array( "name" => "sect409k1", "ecbits" => 409 ),
				12 => array( "name" => "sect409r1", "ecbits" => 409 ),
				13 => array( "name" => "sect571k1", "ecbits" => 571 ),
				14 => array( "name" => "sect571r1", "ecbits" => 571 ),
				15 => array( "name" => "secp160k1", "ecbits" => 160 ),
				16 => array( "name" => "secp160r1", "ecbits" => 160 ),
				17 => array( "name" => "secp160r2", "ecbits" => 160 ),
				18 => array( "name" => "secp192k1", "ecbits" => 192 ),
				19 => array( "name" => "secp192r1", "ecbits" => 192 ),
				20 => array( "name" => "secp224k1", "ecbits" => 224 ),
				21 => array( "name" => "secp224r1", "ecbits" => 224 ),
				22 => array( "name" => "secp256k1", "ecbits" => 256 ),
				23 => array( "name" => "secp256r1", "ecbits" => 256 ),
				24 => array( "name" => "secp384r1", "ecbits" => 384 ),
				25 => array( "name" => "secp521r1", "ecbits" => 521 ),
			);
		}

		public static function get_browsers()
		{
			return array(
				/*"Firefox 32 / mac" => array(
					"ciphers" => array(
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_SEED_CBC_SHA",
						"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),*/
				"Firefox 37 / mac" => array(
					"ciphers" => array(
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => false, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				/*"Chrome 37 / mac" => array(
					"ciphers" => array(
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),*/
				"Chrome 42 / mac" => array(
					"ciphers" => array(
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => false, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				"Safari / Mac 10.10" => array(
					"ciphers" => array(
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				"Opera" => array(
					"ciphers" => array(
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => false, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				"Spartan / win10" => array(
					"ciphers" => array(
						"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => false, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				"IE11 / win 8.1" => array(
					"ciphers" => array(
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => false, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				"IE11 / win 7" => array(
					"ciphers" => array(
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => false, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				/*"IE Mobile 11 / WP8.1" => array(
					"ciphers" => array(
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),*/

				"IE8-10 / win 7" => array(
					"ciphers" => array(
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => false, "TLS12" => false ),
				),

				"IE8 / win XP" => array(
					"ciphers" => array(
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_DES_CBC_SHA",
						"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
						"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
						"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
						"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_DSS_WITH_DES_CBC_SHA",
						"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => false, "TLS12" => false ),
				),

				// "IE6 / win XP" => array(
				// 	"ciphers" => array(
				// 		"TLS_RSA_WITH_RC4_128_MD5",
				// 		"TLS_RSA_WITH_RC4_128_SHA",
				// 		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
				// 		"SSL_CK_RC4_128_WITH_MD5",
				// 		"SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
				// 		"SSL_CK_RC2_128_CBC_WITH_MD5",
				// 		"TLS_RSA_WITH_DES_CBC_SHA",
				// 		"SSL_CK_DES_64_CBC_WITH_MD5",
				// 		"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
				// 		"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
				// 		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
				// 		"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
				// 		"SSL_CK_RC4_128_EXPORT40_WITH_MD5",
				// 		"SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
				// 		"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
				// 		"TLS_DHE_DSS_WITH_DES_CBC_SHA",
				// 		"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
				// 	),
				// 	"protocol-support" => array( "SSL2" => true, "SSL3" => true, "TLS10" => false, "TLS11" => false, "TLS12" => false ),
				// ),

				"GoogleBot" => array(
					"ciphers" => array(
						"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				/*
				"iOS 6" => array(
					"ciphers" => array(
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
						"TLS_ECDHE_RSA_WITH_NULL_SHA",
						"TLS_ECDH_ECDSA_WITH_NULL_SHA",
						"TLS_ECDH_RSA_WITH_NULL_SHA",
						"TLS_RSA_WITH_NULL_SHA256",
						"TLS_RSA_WITH_NULL_SHA",
						"TLS_RSA_WITH_NULL_MD5",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),
				*/

				"iOS 7" => array(
					"ciphers" => array(
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				"iOS 8" => array(
					"ciphers" => array(
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				/*
				"Safari 6 / mac" => array(
					"ciphers" => array(
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => false, "TLS12" => false ),
				),
				*/

				"Safari 7 / mac" => array(
					"ciphers" => array(
						"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ),
				),

				"Safari 5.1 / 10.7" => array(
					"ciphers" => array(
						"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
						"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
						"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
						"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
						"TLS_ECDH_RSA_WITH_RC4_128_SHA",
						"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_AES_128_CBC_SHA",
						"TLS_RSA_WITH_RC4_128_SHA",
						"TLS_RSA_WITH_RC4_128_MD5",
						"TLS_RSA_WITH_AES_256_CBC_SHA",
						"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_RSA_WITH_DES_CBC_SHA",
						"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
						"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
						"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
						"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
						"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
						"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_RSA_WITH_DES_CBC_SHA",
						"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
						"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
						"TLS_DHE_DSS_WITH_DES_CBC_SHA",
						"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
					),
					"protocol-support" => array( "SSL2" => false, "SSL3" => true, "TLS10" => true, "TLS11" => false, "TLS12" => false ),
				),

			);
		}

		public static function openssl_version()
		{
			if ( !isset(self::$openssl) )  self::init_though();

			$openssl = self::$openssl;
			return trim( shell_exec( "{$openssl} version" ) );
		}

		protected static function s_client( $host, $ciphers, $protos = array( "SSL2" => true, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ) )
		{
			if ( !isset(self::$openssl) )  self::init_though();

			if ( is_string($ciphers) )
				$ciphers = [ $ciphers ];

			$cc = "";
			if ( is_array($ciphers) )
				$cc = "-cipher " . escapeshellarg(implode(":",array_map('SSLinfo::cipher_name',$ciphers)) . ":+HIGH:+MEDIUM:+LOW:+RC4:+MD5");

			list($servername) = explode( ":", $host );
			$servername = escapeshellarg( $servername );

			$host = escapeshellarg( $host );

			$prt = [];
			if ( !$protos["SSL3"]  ) $prt[] = "-no_ssl3";
			if ( !$protos["TLS10"] ) $prt[] = "-no_tls1";
			if ( !$protos["TLS11"] ) $prt[] = "-no_tls1_1";
			if ( !$protos["TLS12"] ) $prt[] = "-no_tls1_2";

			$prt = implode( " ", $prt );

			$openssl = self::$openssl;
			return shell_exec( "true | {$openssl} s_client -msg -prexit {$prt} {$cc} -connect {$host} -servername {$servername} 2>&1" );
		}

		public static function connect( $host, $ciphers, $protos = array( "SSL2" => true, "SSL3" => true, "TLS10" => true, "TLS11" => true, "TLS12" => true ) )
		{
			$op = self::s_client( $host, $ciphers, $protos );

			$a = strrpos( $op, "SSL-Session:" );
			if ( $a === false )  return null;

			$op = substr( $op, $a );

			if ( !preg_match( "/^\s+Protocol\s*:\s+([a-zA-Z0-9_.-]+)$/mus", $op, $A ) )
			{
				fwrite( STDERR, $op );
				return null;
			}

			$proto = substr($A[1],0,3);

			if ( preg_match( "/^\s+Cipher\s*:\s+([a-zA-Z0-9_.-]+)$/mus", $op, $A ) )
			{
				if ( $A[1] == "0000" )  return null;
				return self::cipher_lookup( $A[1], $proto );
			}

			fwrite( STDERR, $op );
			return null;
		}

		public static function dh_size( $server )
		{
			$op = self::s_client( $server, array( "*DH" ) );
			if ( !preg_match( "/ServerKeyExchange\\n\\s+0c .. .. .. ((..) (..))/muis", $op, $A ) )
				return null;

			return 8*hexdec("{$A[2]}{$A[3]}");
		}

		public static function ecdh_size( $server )
		{
			$op = self::s_client( $server, array( "*ECDH" ) );
			if ( preg_match( "/ServerKeyExchange\\n\\s+0c .. .. .. 03 ((..) (..))/muis", $op, $A ) )
			{
				$curve_id = hexdec("{$A[2]}{$A[3]}");
				if ( isset(self::$curve_map[$curve_id]) )
				{
					return self::$curve_map[$curve_id];
				}

				return array( "name" => sprintf("Unknown named curve %4x",$curve_id), "ecbits" => 1 );
			}

			// TODO: non-named curves

			return null;
		}

		public static function server_probe( $server, $protocol = "TLS10" )
		{
			if ( !isset(self::$map) )  self::init_though();
			$protos = array( "SSL2" => false, "SSL3" => false, "TLS10" => false, "TLS11" => false, "TLS12" => false );
			$protos[$protocol] = true;

			$ciphers = self::$map;

			foreach ( $ciphers as $key => $value )
				if ( substr($key,0,4) == "SSL_" )
					unset($ciphers[$key]);

			$cc = true;
			$rv = array();

			while ( count($ciphers) > 0 && $cc )
			{
				$cc = self::connect( $server, array_keys($ciphers), $protos );

				if ( !empty($cc) )
				{
					$rv[] = $cc;
					unset($ciphers[$cc]);
				}
			}

			return $rv;
		}

		public static function ecbits_to_ff( $b )
		{
			// Lagrange interpolation of the NIST recommendation table:
			//  160  →   1024
			//  224  →   2048
			//  256  →   3072
			//  384  →   7680
			//  521  →  15360

			return round( 2.2247113318292543e-06 * ($b*$b*$b*$b) - 0.002910544879983633 * ($b*$b*$b) + 1.4166053052358345 * ($b*$b) - 267.8476746244936 * $b + 18078.137135866877 );
		}

		public static function ecbits_to_symmetric( $b )
		{
			// Lagrange interpolation of the NIST recommendation table:
			//  160  →  80
			//  224  →  112
			//  256  →  128
			//  384  →  192
			//  521  →  256

			return round( 1.1838110189986005e-06 * ($b*$b*$b) - 0.0004391938880483129 * ($b*$b) + 0.5701573762299863 * $b - 4.073067544406371 );
		}

		public static function format_cipher( $s )
		{
			$ci = self::cipher_info( $s );
			$colour = null;

			if ( $ci["cipher-strength"] < 112 )
				$colour = "yellow";
			if ( strpos( $s, "_RC4_") !== false )
				$colour = "yellow";
			if ( substr($s,-4) == "_MD5" )
				$colour = "yellow";
			if ( strpos( $s, "_RC2_") !== false )
				$colour = "red";
			if ( substr($s,-9) == "_WITH_MD5" )
				$colour = "red";

			if ( $colour == "yellow" )
				$s .= "  WEAK";
			if ( $colour == "red" )
				$s .= "  INSECURE";

			$rv = $s;
			if ( $colour )  $rv = $colour($s);
			$rv .= str_repeat( " ", 46 - mb_strlen($s) );

			if ( $ci["forward-secrecy"] )
				$rv .= "   " . green("FS") . "   ";
			else
				$rv .= "  " . yellow("no FS") . " ";

			$cl = (int)$ci["cipher-strength"];
			$rv .= str_repeat( " ", 4 - strlen($cl) );
			if ( $colour )
				$rv .= $colour( $cl );
			elseif ( $ci["forward-secrecy"] && $ci["aead"] && $ci["cipher-strength"] > 128 )
				$rv .= green( $cl );
			else
				$rv .= $cl;

			if ( $ci["aead"] )
				$rv .= "  " . green("AEAD") . " ";

			return $rv;
		}

		public static function cipher_info( $s )
		{
			if ( !isset(self::$map) )  self::init_though();

			return @self::$map[$s];
		}
		public static function cipher_name( $s )
		{
			if ( !isset(self::$map) )  self::init_though();

			if ( substr($s,0,1) == "*" )
				return substr($s,1);

			return @self::$map[$s]["openssl-name"];
		}
		protected static function cipher_lookup( $s, $proto = null )
		{
			if ( !isset(self::$map) )
				self::init_though();

			if ( empty($s) )
				return null;
			if ( is_numeric($s) && $s == 0 )
				return null;

			foreach ( self::$map as $name => $info )
			{
				if ( $proto !== null && substr($name,0,4) != "{$proto}_" )  continue;

				if ( $info["openssl-name"] == $s )
					return $name;
			}

			// DHE/EDH wordt nog wel eens door elkaar gehaald
			if ( substr($s,0,4) === "EDH-" )
				return self::cipher_lookup( "DHE-" . substr($s,4), $proto );

			return "unknown-{$proto}-{$s}";
		}
	}

