<?php

/**
 * @file
 *
 * ACL support module for the Aegir backend.
 *
 * This file contains common functions. It could be considered a draft
 * ACL API...
 */

/**
 * Set an ACL on the given files
 *
 * @param string $type
 *    type of ACL to set. Can be user, group, mask or other.
 * @param string $id
 *    the identifier to set the ACL for (usually a uid or gid,
 *    empty for mask and default)
 * @param string $mode
 *    the actual permissions to set
 * @param array $files
 *    the files to set the ACL on
 * @param string $flags
 *    extra flags to pass to setfacl(1)
 * @return if the setfacl operation succeeded
 *
 * All arguments are escaped with escapeshellarg().
 *
 * @see setfacl(1)
 * @see drush_shell_exec()
 * @see escapeshellarg()
 */
function provisionacl_set_acl($type, $id, $mode, $files, $flush = FALSE, $flags = array()) {
  // -b resets the ACLs present
  if ($flush) {
    $flags[] = '-b';
  }
  // we escape the files array ourselves above, so no placeholder
  $files = join(' ', array_map('escapeshellarg', $files));
  $flags = join(' ', array_map('escapeshellarg', $flags));
  return drush_shell_exec("setfacl " . $flags . " -m %s:%s:%s " . $files, $type, $id, $mode);
}

/**
 * Set ACLs for a site
 *
 * This sets ACLs on the settings and drushrc files and changes the
 * directories permissions.
 *
 * This will not set ACLs on non-existent groups
 *
 * @see provision_posix_groupname()
 * @see provisionacl_fix_settings()
 * @see provisionacl_fix_dirs()
 * @return bool if the ACL settings succeeded
 */
function provisionacl_site_acls() {
  $group = d()->client_name;
  if (!provision_posix_groupname($group)) {
    drush_log(dt('not setting ACLs for non-existent group @group', array('@group' => $group)), 'warning');
    return false;
  }
  return provisionacl_fix_settings($group, d()->name) && provisionacl_fix_dirs($group, d()->site_path);
}

/**
 * Configure ACLs on site's directories
 *
 * This gives additionnal privileges to the modules, themes,
 * libraries, files and private directories so that members of a group
 * can read and write them.
 *
 * @param $group string the group to give the rights to
 * @param $site_path string the base path of the site
 * (e.g. /var/www/drupal-6.20/sites/default/)
 * 
 * @return bool if the ACL was set properly
 * 
 * @see provisionacl_set_acl()
 */
function provisionacl_fix_dirs($group, $site_path) {
  $dirs = array('modules', 'themes', 'libraries', 'files', 'private');
  drush_log(dt('setting group ACL read/write access to @group on @dirs', array('@group' => $group, '@dirs' => join(',', $dirs))));
  return provisionacl_set_acl('group', $group, 'rw-', $dirs, TRUE);
}

/**
 * Configure the settings.php and drushrc.php files to have group read
 * access to the client.
 *
 * This operates on the current context, which should normally be a
 * site, and will fetch the client_name and file paths from the context.
 *
 * @param $group string the group to set the acl to
 * @param $context string the context name of this site. Results are
 * undefined if a non-site context is passed.
 * 
 * @return bool if the ACL was set properly
 *
 * @see d()
 * @see provision_set_acl()
 */
function provisionacl_fix_settings($group, $context) {
  drush_log(dt('setting group ACL read access to @group on drushrc.php and settings.php files', array('@group' => $group)));
  $drushrc = new provisionConfig_drushrc_site($context);
  $settings = new provisionConfig_drupal_settings($context);
  return provisionacl_set_acl('group', $group, 'r--', array($drushrc->filename(), $settings->filename()), TRUE);
}

/**
 * Implementation of hook_drush_exit()
 *
 * We need to run here as the drushrc is written during the exit hook.
 *
 * @deprecated ideally, this wouldn't be necessary, see https://drupal.org/node/1097854
 */
function provisionacl_drush_exit() {
  $command = drush_get_command();
  $command = explode(" ", $command['command']);

  if (preg_match("/^provision-(verify|install)$/", $command[0]) && drush_get_option('provision_save_config', TRUE)) {
    if (!provisionacl_site_acls()) {
      drush_set_error('PROVISION_ACL_FAILED', dt('could not set ACLs (error: %error)', array('%error' => drush_shell_exec_output())));
    }
  }
}
