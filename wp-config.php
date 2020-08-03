<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'gambus78_wp' );

/** MySQL database username */
define( 'DB_USER', 'gambus78_wp' );

/** MySQL database password */
define( 'DB_PASSWORD', 'gvsn3010ejsqRNXz' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',          'B0F~[j`?q*h}p+qB(<J]ve?^&)k@H&jsxyfmo#f3#GjThNMx,^]|0%AbVlX3pyQB' );
define( 'SECURE_AUTH_KEY',   'J:Lk_%#K:yfvo3$w>ih:I)`uPMSJoUqCyIccN:k1P<wC$wy4cYs0FkyDM?hPH/C&' );
define( 'LOGGED_IN_KEY',     '*>B, ,i<dh;>e>{MT0soKX5U.$7D?[?{uvSSZLCq{t6w.bX%VE5Yi*OsvFof)>M!' );
define( 'NONCE_KEY',         'u4+QTYoN^*oHrgdTPy1<>^>4i0VB3g<h2~PV`=Ej~N@K5_slDb?o~40 %s~c7d6@' );
define( 'AUTH_SALT',         '4Pv>m&jV$Rpk+w#}m=.|jE/2 P0(hwK%_G50oZLA%3vEMf;kp;W6$G:4piQbtYGt' );
define( 'SECURE_AUTH_SALT',  '0f/aKw<Pg3&pA,=nJw[Y I>1eG7;7^Jm_&cSlJsT%A-S~5{O|q6y`&[@]^WE7}0R' );
define( 'LOGGED_IN_SALT',    'KO[WCip;:~~LCiw;bw5Tr9E$w~KRR&X|p#_ZJ.(_3ZbN5];i&7D7oj810#11lW |' );
define( 'NONCE_SALT',        'I}d:26j~z)$SxkCQj[w_k=mcP} |QNOw$T7pCF#G7r)z1.]!Z|#^M+3f-=v=5 ^H' );
define( 'WP_CACHE_KEY_SALT', '6r0T/mII]<Qq?Ucn&FBz0jSpv{&f20=Yp#bQ+?ZrOFW!=rh)g_-kEFPL<#E73O9q' );

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';


define( 'WP_DEBUG', false );
define( 'WP_DEBUG_LOG', false );


/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) )
	define( 'ABSPATH', dirname( __FILE__ ) . '/' );

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
