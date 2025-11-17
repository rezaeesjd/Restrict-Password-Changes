<?php
/*
Plugin Name: Restrict Password Changes
Description: Prevents non-admin users from changing or resetting their passwords.
Version: 1.0.0
Author: Your Name
*/

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

/**
 * Helper: can this user bypass restrictions?
 *
 * - If $user is provided, check that user.
 * - Otherwise, check the current logged-in user.
 */
function rpc_can_bypass_password_restrictions( $user = null ) {

    // If a specific user was passed in
    if ( $user instanceof WP_User ) {
        return user_can( $user, 'manage_options' );
    }

    if ( is_numeric( $user ) ) {
        $user_obj = get_user_by( 'id', (int) $user );
        if ( $user_obj ) {
            return user_can( $user_obj, 'manage_options' );
        }
        return false;
    }

    // Fallback to current user
    if ( is_user_logged_in() ) {
        return current_user_can( 'manage_options' );
    }

    return false;
}

/**
 * 1) Hide password fields on profile screens for non-admins.
 */
function rpc_hide_profile_password_fields( $show ) {
    if ( ! rpc_can_bypass_password_restrictions() ) {
        return false;
    }
    return $show;
}
add_filter( 'show_password_fields', 'rpc_hide_profile_password_fields' );

/**
 * 2) Extra CSS hide on profile screens (backup).
 */
function rpc_profile_password_css() {

    // Only run on profile / user-edit screens
    $screen = get_current_screen();
    if ( ! $screen || ! in_array( $screen->id, array( 'profile', 'user-edit' ), true ) ) {
        return;
    }

    if ( rpc_can_bypass_password_restrictions() ) {
        return;
    }

    ?>
    <style>
        #password,
        #pass1,
        #pass2,
        .user-pass1-wrap,
        .user-pass2-wrap,
        .pw-weak,
        .wp-pwd {
            display: none !important;
        }
    </style>
    <?php
}
add_action( 'admin_head', 'rpc_profile_password_css' );

/**
 * 3) Disable password reset for non-admin accounts.
 *
 * This runs when WordPress decides if a user is allowed to reset their password.
 */
function rpc_allow_password_reset( $allow, $user_id ) {

    // If the target user is an admin, allow normal behaviour.
    if ( rpc_can_bypass_password_restrictions( $user_id ) ) {
        return $allow;
    }

    // For non-admin users, disallow password reset.
    return false;
}
add_filter( 'allow_password_reset', 'rpc_allow_password_reset', 10, 2 );

/**
 * 4) Prevent password reset email from being sent for non-admin accounts.
 */
function rpc_retrieve_password_message( $message, $key, $user ) {

    // Allow admins to get reset emails.
    if ( rpc_can_bypass_password_restrictions( $user ) ) {
        return $message;
    }

    // For non-admins: return empty message to prevent sending.
    return '';
}
add_filter( 'retrieve_password_message', 'rpc_retrieve_password_message', 10, 3 );
/**
 * 5) Hide "Lost your password?" link on the login screen.
 */
function rpc_hide_lost_password_link() {
    ?>
    <style>
        #nav .lostpassword-link {
            display: none !important;
        }
    </style>
    <?php
}
add_action( 'login_enqueue_scripts', 'rpc_hide_lost_password_link' );
