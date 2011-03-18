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
    provisionacl_fix_settings();
  }
}