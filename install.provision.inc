<?php

/**
 * Implementation of drush_hook_provision_post_install()
 *
 * Copy-paste of the verify hook.
 *
 * @see drush_provisionacl_post_provision_verify()
 */
function drush_provisionacl_post_provision_install($url = null) {
  if (d()->type == 'site') {
    $drushrc = new provisionConfig_drushrc_site(d()->name);
    $settings = new provisionConfig_drupal_settings(d()->name);
    provisionacl_set_acl('group', d()->client_name, 'r--', array($drushrc->filename(), $settings->filename()), TRUE);
  }
}