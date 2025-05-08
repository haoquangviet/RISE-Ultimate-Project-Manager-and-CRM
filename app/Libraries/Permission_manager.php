<?php

namespace App\Libraries;

class Permission_manager {

    private $ci = null;
    private $permissions = array();

    public function __construct($security_controller_instance) {
        $this->ci = $security_controller_instance;
        if (!$this->ci || !$this->ci->login_user->id) {
            redirect("forbidden");
        }

        $this->permissions = $this->ci->login_user->permissions || array();
    }

    private function _is_admin() {
        return $this->ci->login_user->is_admin;
    }

    private function _is_team_member() {
        return $this->ci->login_user->user_type == "staff";
    }

    private function _is_client() {
        return $this->ci->login_user->user_type == "client";
    }

    private function _is_active_module($module_name) {
        return get_setting($module_name) == "1";
    }

    function can_manage_invoices() {

        if (!$this->_is_active_module("module_invoice")) {
            return false;
        }

        if ($this->_is_admin()) {
            return true;
        }

        if ($this->_is_team_member()) {
            $invoice_permission = get_array_value($this->permissions, "invoice");

            return in_array($invoice_permission, [
                "all",
                "manage_own_client_invoices",
                "manage_own_client_invoices_except_delete",
                "manage_only_own_created_invoices",
                "manage_only_own_created_invoices_except_delete"
            ]);
        }
    }

    function can_manage_estimates() {
        if (!$this->_is_active_module("module_estimate")) {
            return false;
        }

        if ($this->_is_admin()) {
            return true;
        }

        if ($this->_is_team_member()) {
            $estimate_permission = get_array_value($this->permissions, "estimate");

            return in_array($estimate_permission, [
                "all",
                "own"
            ]);
        }
    }

    function can_manage_items() {
        return $this->can_manage_invoices() || $this->can_manage_estimates();
    }
}
