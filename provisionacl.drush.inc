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
 * Fix ACLs on client directories
 *
 * Starting with 1.0-rc4, Aegir creates symlinks in the "clients_path"
 * (usually ~/clients/<clientname>) directory. Since this is made to
 * be accessible by user, we also give our group read/execute access
 * to that directory so they can see their sites.
 *
 * This function is not designed to be called by external modules.
 *
 * @arg $group string
 *   the group name, also assumed to be the path to the subdirectory
 *   in the clients directory
 *
 * @return bool if the ACL was sucessful, or TRUE if the clients
 *   directory doesn't exist (for backward compatibility)
 */
function _provisionacl_clientdir_acls($group = null) {
  if (is_null($group)) {
    $group = d()->client_name;
  }
  if (!provision_posix_groupname($group)) {
    drush_log(dt('not setting ACLs for non-existent group @group', array('@group' => $group)), 'warning');
    return FALSE;
  }
  $sites_dir = d()->server->clients_path . '/' . $group;
  if (file_exists($sites_dir)) {
    if (!provisionacl_set_acl('group', $group, 'r-x', array($sites_dir), TRUE)) {
      return drush_set_error('PROVISION_ACL_FAILED', dt('could not set ACLs (error: %error)', array('%error' => join("", drush_shell_exec_output()))));
    }
  } else {
    drush_log(dt('not setting ACLs on non-existent client directory @path', array('@path' => $sites_dir)), 'warning');
    return TRUE;
  }
}

/**
 * Configure ACLs on directories
 *
 * This gives additionnal privileges on directories so that members of
 * a group can read and write them.
 *
 * We create 3 ACLs here:
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
 * @param $dirs string an array of directories to recursively change
 * permissions on
 * 
 * @return bool if the ACL was set properly
 * 
 * @see provisionacl_set_acl()
 */
function provisionacl_dirs_acls($dirs, $group = null) {
  if (is_null($group)) {
    $group = d()->client_name;
  }
  if (!provision_posix_groupname($group)) {
    drush_log(dt('not setting ACLs for non-existent group @group', array('@group' => $group)), 'warning');
    return FALSE;
  }
  drush_log(dt('setting group ACL read/write access to @group on @dirs', array('@group' => $group, '@dirs' => join(',', $dirs))));
  // a default ACL for the aegir user
  $result = provisionacl_set_acl('u', d()->server->script_user, 'rwx', $dirs, TRUE, array('-R'));
  $result = $result && provisionacl_set_acl('d:u', d()->server->script_user, 'rwx', $dirs, FALSE, array('-R'));
  // a default ACL for the client group
  $result = $result && provisionacl_set_acl('d:g', $group, 'rwx', $dirs, FALSE, array('-R'));
  // a regular ACL for the client group
  $result = $result && provisionacl_set_acl('g', $group, 'rwx', $dirs, FALSE, array('-R'));

  // crude and ugly hack to remove g+s flags to files that was keeping
  // file truncates from working.
  $safe_dirs = join(' ', array_map('escapeshellarg', $dirs));
  system("chmod -R g-s " . $safe_dirs);

  if (!$result) {
    drush_set_error('PROVISION_ACL_FAILED', dt('could not set ACLs (error: %error)', array('%error' => join("", drush_shell_exec_output()))));
  }
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
function provisionacl_files_acls($files, $group = null) {
  if (is_null($group)) {
    $group = d()->client_name;
  }
  if (!provision_posix_groupname($group)) {
    drush_log(dt('not setting ACLs for non-existent group @group', array('@group' => $group)), 'warning');
    return FALSE;
  }
  drush_log(dt('setting group ACL group @group read access to files @files', array('@group' => $group, '@files' => join(", ", @files))));
  if (!provisionacl_set_acl('group', $group, 'r--', $files), TRUE)) {
    return drush_set_error('PROVISION_ACL_FAILED', dt('could not set ACLs (error: %error)', array('%error' => join("", drush_shell_exec_output()))));
  }
  return TRUE;
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
      $dirs = array();
      foreach (array('modules', 'themes', 'libraries', 'files', 'private') as &$dir) {
        $dirs[]= d()->site_path . '/' . $dir;
      }
      provisionacl_dirs_acls($dirs);
      $drushrc = new provisionConfig_drushrc_site(d()->name);
      $settings = new provisionConfig_drupal_settings(d()->name);
      provisionacl_files_acls(array($drushrc->filename(), $settings->filename()));
      _provisionacl_clientdir_acls();
    }
  }
}

/**
 * Implementation of hook_drush_pm_post_download().
 *
 * This runs after the user downloads a new module, and makes sure the ACLs are
 * set properly, as tar and cp do not respect ACLs and will set an erroneous
 * mask that will override the ACLs.
 *
 * This function resets that mask to rwx.
 */
function provisionacl_drush_pm_post_download($request, $release) {
  drush_log(dt("reseting ACL mask after expansion"));
  return provisionacl_set_acl('mask', '', 'rwx', array($request['project_install_location']), FALSE, array('-R'));
}
