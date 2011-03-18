<?php

/**
 * Implementation of drush_hook_provision_post_verify()
 */
function drush_provisionacl_post_provision_verify($url = null) {
  if (d()->type == 'site') {
    $group = d()->client_name;
    $drushrc = new provisionConfig_drushrc_site(d()->name);
    $settings = new provisionConfig_drupal_settings(d()->name);
    drush_log(dt("setting ACL for access to settings and drushrc files to group %group", array('%group' => $group)));
    if (!drush_shell_exec("setfacl -b -m g:%s:r-- %s %s", $group, $drushrc->filename(), $settings->filename())) {
      return drush_set_error('PROVISION_ACL_FAILED', dt('could not change ACL to group %group on files %settings and %drushrc (error: %msg)', array('%group' => $group, '%settings' => $settings->filename(), '%drushrc' => $drushrc->filename(), '%error' => drush_shell_exec_output())));
    }
  }
}
