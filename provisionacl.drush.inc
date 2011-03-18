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
 * @return if the setfacl operation succeeded
 *
 * @see setfacl(1)
 */
function provisionacl_set_acl($type, $id, $mode, $files, $flush = FALSE) {
  drush_log(dt("setting ACL"));

  // -b resets the ACLs present
  $flags = $flush ? '-b' : '';

  // we escape the files array ourselves above, so no placeholder
  $files = join(', ', array_map('escapeshellarg', $files));
  if (!drush_shell_exec("setfacl %s -m %s:%s:%s" . $files, $flags, $type, $id, $mode)) {
    return drush_set_error('PROVISION_ACL_FAILED', dt('could not set %type ACL (%mode) to %id on files %files... (error: %error)', array('%type' => $type, '%id' => $id, '%mode' => $mode, '%files' => substr($files, 0, 50), '%error' => drush_shell_exec_output())));
  }
  return true;
}
