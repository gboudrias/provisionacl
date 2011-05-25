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
 */
function provisionacl_site_acls() {
  $group = d()->client_name;
  if (!provision_posix_groupname($group)) {
    drush_log(dt('not setting ACLs for non-existent group @group', array('@group' => $group)), 'warning');
  } elseif (!(provisionacl_fix_settings($group, d()->name) && provisionacl_fix_dirs($group, d()->site_path) && provision_acl_fix_clientdir($group))) {
    drush_set_error('PROVISION_ACL_FAILED', dt('could not set ACLs (error: %error)', array('%error' => drush_shell_exec_output())));
  }
}

/**
 * Fix ACLs on client directories
 *
 * Starting with 1.0-rc4, Aegir creates symlinks in the "clients_path"
 * (usually ~/clients/<clientname>) directory. Since this is made to
 * be accessible by user, we also give our group read/execute access
 * to that directory so they can see their sites.
 *
 * @arg $group string
 *   the group name, also assumed to be the path to the subdirectory
 *   in the clients directory
 *
 * @return bool if the ACL was sucessful, or TRUE if the clients
 *   directory doesn't exist (for backward compatibility)
 */
function provision_acl_fix_clientdir($group) {
  $sites_dir = d()->server->clients_path . '/' . $group;
  if (file_exists($sites_dir)) {
    return provisionacl_set_acl('group', $group, 'r-x', array($sites_dir), TRUE);
  } else {
    drush_log(dt('not setting ACLs on non-existent client directory @path', array('@path' => $sites_dir)), 'warning');
    return TRUE;
  }
}

/**
 * Configure ACLs on site's directories
 *
 * This gives additionnal privileges to the modules, themes,
 * libraries, files and private directories so that members of a group
 * can read and write them.
 *
 * We create 3 ACLs here for all those directories:
 *
 * 1. a default ACL for the aegir user - to make sure that it has
 * access to files created by users under the directories
 *
 * 2. a default ACL for the client group - to make sure it has access
 * to files created under the directories
 *
 * 3. a regular ACL for the client group - to make sure it has access
 * to the directory itself
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
  foreach ($dirs as &$dir) {
    $dir = $site_path . '/' . $dir;
  }
  // a default ACL for the aegir user
  $result = provisionacl_set_acl('u', d()->server->script_user, 'rwx', $dirs, TRUE, array('-R'));
  $result = $result && provisionacl_set_acl('d:u', d()->server->script_user, 'rwx', $dirs, FALSE, array('-R'));
  // a default ACL for the client group
  $result = $result && provisionacl_set_acl('d:g', $group, 'rwx', $dirs, FALSE, array('-R'));
  // a regular ACL for the client group
  $result = $result && provisionacl_set_acl('g', $group, 'rwx', $dirs, FALSE, array('-R'));
  return $result;
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

  if (preg_match("/^provision-(verify|install)$/", $command[0])) {
    if (d()->context_type == 'site') {
      provisionacl_site_acls();
    }
  }
}
