<?php

/**
 * @file
 *
 * ACL support module for the Aegir backend.
 *
 * This file contains common functions. It could be considered a draft
 * ACL API for Aegir core 2.x. See http://drupal.org/node/1097886 for
 * followup.
 */

/**
 * Implementation of hook_drush_command().
 */
function provisionacl_drush_command() {
  $items['provisionacl'] = array(
    'description' => "Hooks into aegir-provision to setup ACL on client sites.\n\nNot intented to be used on the command line.",
  );
  return $items;
}

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
 * @param bool $flush
 *    if we need to flush (-b) the current ACLs
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
 * @param $dirs string an array of directories to recursively change
 * permissions on
 * @param $options array extra parameters to pass to setfacl
 * Valid values are:
 *  * recurse: whether to recurse in subdirectories (-R, default)
 *  * follow: whether to follow symlinks given on the commandline
 *    (default not to follow, -P)
 *  * group: group to change the ownership to (default to the client_name)
 * 
 * @return bool if the ACL was set properly. This will also raise a
 * drush_set_error() on failure.
 * 
 * @see provisionacl_set_acl()
 */
function provisionacl_dirs_acls($dirs, $options = array('recurse' => true, 'follow' => 'false')) {
  if (!isset($options['group'])) {
    $options['group'] = d()->client_name;
  }
  $flags = array();
  if ($options['recurse']) {
    $flags[] = '-R';
  }
  if (!$options['follow']) {
    $flags[] = '-P';
  }
  if (!provision_posix_groupname($options['group'])) {
    drush_log(dt('not setting ACLs for non-existent group @group', array('@group' => $options['group'])), 'warning');
    return FALSE;
  }
  drush_log(dt('setting group ACL read/write access to @group on @dirs', array('@group' => $options['group'], '@dirs' => join(',', $dirs))));
  // a default ACL for the aegir user
  $result = provisionacl_set_acl('u', d()->server->script_user, 'rwx', $dirs, TRUE, $flags);
  $result = provisionacl_set_acl('d:u', d()->server->script_user, 'rwx', $dirs, FALSE, $flags) && $result;
  // a default ACL for the client group
  $result = provisionacl_set_acl('d:g', $options['group'], 'rwx', $dirs, FALSE, $flags) && $result;
  // a regular ACL for the client group
  $result = provisionacl_set_acl('g', $options['group'], 'rwx', $dirs, FALSE, $flags) && $result;

  // crude and ugly hack to remove g+s flags to files that was keeping
  // file truncates from working. fixes bug 1195598
  $safe_dirs = join(' ', array_map('escapeshellarg', $dirs));
  // reset the flags for chmod since they are not the same as setfacl
  $flags = '';
  if ($options['recurse']) {
    $flags = '-R';
  }
  // should be safe on symlinks, even though they will be followed,
  // removing +s is harmless
  system("chmod $flags g-s " . $safe_dirs);

  if (!$result) {
    drush_log(dt('could not set ACLs (error: %error)', array('%error' => substr(join("", drush_shell_exec_output()), 0, 256))), 'warning');
;
  }
  return $result;
}

/**
 * Configure files to have group read access to the client.
 *
 * This operates on the current context, which should normally be a
 * site, and will fetch the client_name and file paths from the context.
 *
 * @param $files array list of files to change the owner.
 * @param $options array set of options, currently only checking the
 * 'group' to set the files to.
 * 
 * @return bool if the ACL was set properly. This will also raise a
 * drush_set_error() on failure.
 *
 * @see d()
 * @see provision_set_acl()
 */
function provisionacl_files_acls($files, $options = array('follow' => FALSE)) {
  if (!isset($options['group'])) {
    $options['group'] = d()->client_name;
  }
  $flags = array();
  if (!$options['follow']) {
    $flags[] = '-P';
  }
  
  if (!provision_posix_groupname($options['group'])) {
    drush_log(dt('not setting ACLs for non-existent group @group', array('@group' => $options['group'])), 'warning');
    return FALSE;
  }
  drush_log(dt('setting group ACL group @group read access to files @files', array('@group' => $options['group'], '@files' => join(", ", $files))));
  // a default ACL for the aegir user
  $result = provisionacl_set_acl('u', d()->server->script_user, 'rwx', $files, TRUE, $flags);
  // a regular ACL for the client group
  $result = $result && provisionacl_set_acl('group', $options['group'], 'r--', $files, FALSE, $flags);
  if (!$result) {
    drush_set_error('PROVISION_ACL_FAILED', dt('could not set ACLs (error: %error)', array('%error' => join("", drush_shell_exec_output()))));
  }
  // see 1195598
  $safe_files = join(' ', array_map('escapeshellarg', $files));
  system("chmod g-s " . $safe_files);
  return $result;
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
      provisionacl_dirs_acls(array(d()->site_path)); // recursive
      provisionacl_set_acl('group', d()->server->web_group, 'rwx', array(d()->site_path . "/files", d()->site_path . "/private"), FALSE, array("-P"));
      provisionacl_set_acl('default:group', d()->server->web_group, 'rwx', array(d()->site_path . "/files", d()->site_path . "/private"), FALSE, array("-P"));
      // restore the read-only ACLs on those files
      // XXX: there is a window of time during which those files are writable
      // there is also the possibility of users to root the
      // install thru local.settings.php since that one is writable
      // finally, one could just rewrite settings.php altogether since
      // he owns the directory
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
