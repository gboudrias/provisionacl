<?php

/**
 * Implementation of drush_hook_provision_post_verify()
 */
function drush_provisionacl_post_provision_verify($url = null) {
  if (d()->type == 'site') {
    provisionacl_fix_settings();
  }
}
