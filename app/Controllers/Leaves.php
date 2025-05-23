<?php

namespace App\Controllers;

use App\Libraries\Excel_import;

class Leaves extends Security_Controller {

    private $users_id_by_name = array();
    private $leave_types_id_by_title = array();

    use Excel_import;

    function __construct() {
        parent::__construct();
        $this->access_only_team_members();

        $this->init_permission_checker("leave");
    }

    //only admin or assigend members can access/manage other member's leave
    //none admin users who has limited permission to manage other members leaves, can't manage his/her own leaves
    protected function access_only_allowed_members($user_id = 0) {
        if ($this->access_type !== "all") {
            if ($user_id === $this->login_user->id || !array_search($user_id, $this->allowed_members)) {
                app_redirect("forbidden");
            }
        }
    }

    protected function can_delete_leave_application() {
        if ($this->login_user->is_admin || get_array_value($this->login_user->permissions, "can_delete_leave_application") == "1") {
            return true;
        }
    }

    function index($tab = "") {
        $this->check_module_availability("module_leave");

        $view_data["can_manage_all_leaves"] = $this->login_user->is_admin || $this->access_type === "all";
        $view_data['tab'] = clean_data($tab);

        return $this->template->rander("leaves/index", $view_data);
    }

    //load assign leave modal 

    function assign_leave_modal_form($applicant_id = 0) {
        validate_numeric_value($applicant_id);

        if ($applicant_id) {
            $view_data['team_members_info'] = $this->Users_model->get_one($applicant_id);
        } else {

            //show all members list to only admin and other members who has permission to manage all member's leave
            //show only specific members list who has limited access
            if ($this->access_type === "all") {
                $where = array("user_type" => "staff");
            } else {
                $where = array("user_type" => "staff", "id !=" => $this->login_user->id, "where_in" => array("id" => $this->allowed_members));
            }
            $view_data['team_members_dropdown'] = array("" => "-") + $this->Users_model->get_dropdown_list(array("first_name", "last_name"), "id", $where);
        }

        $view_data['leave_types_dropdown'] = array("" => "-") + $this->Leave_types_model->get_dropdown_list(array("title"), "id", array("status" => "active"));
        $view_data['form_type'] = "assign_leave";
        return $this->template->view('leaves/modal_form', $view_data);
    }

    //all team members can apply for leave
    function apply_leave_modal_form() {
        $view_data['leave_types_dropdown'] = array("" => "-") + $this->Leave_types_model->get_dropdown_list(array("title"), "id", array("status" => "active"));
        $view_data['form_type'] = "apply_leave";
        return $this->template->view('leaves/modal_form', $view_data);
    }

    // save: assign leave 
    function assign_leave() {
        $leave_data = $this->_prepare_leave_form_data();
        $applicant_id = $this->request->getPost('applicant_id');
        validate_numeric_value($applicant_id);

        $leave_data['applicant_id'] = $applicant_id;
        $leave_data['created_by'] = $this->login_user->id;
        $leave_data['checked_by'] = $this->login_user->id;
        $leave_data['checked_at'] = $leave_data['created_at'];
        $leave_data['status'] = "approved";

        //hasn't full access? allow to update only specific member's record, excluding loged in user's own record
        $this->access_only_allowed_members($leave_data['applicant_id']);

        $save_id = $this->Leave_applications_model->ci_save($leave_data);
        if ($save_id) {
            log_notification("leave_assigned", array("leave_id" => $save_id, "to_user_id" => $applicant_id));
            echo json_encode(array("success" => true, "data" => $this->_row_data($save_id), 'id' => $save_id, 'message' => app_lang('record_saved')));
        } else {
            echo json_encode(array("success" => false, 'message' => app_lang('error_occurred')));
        }
    }

    /* save: apply leave */

    function apply_leave() {
        $leave_data = $this->_prepare_leave_form_data();
        $leave_data['applicant_id'] = $this->login_user->id;
        $leave_data['created_by'] = 0;
        $leave_data['checked_at'] = "0000:00:00";
        $leave_data['status'] = "pending";

        $leave_data = clean_data($leave_data);

        $save_id = $this->Leave_applications_model->ci_save($leave_data);
        if ($save_id) {
            log_notification("leave_application_submitted", array("leave_id" => $save_id));
            echo json_encode(array("success" => true, "data" => $this->_row_data($save_id), 'id' => $save_id, 'message' => app_lang('record_saved')));
        } else {
            echo json_encode(array("success" => false, 'message' => app_lang('error_occurred')));
        }
    }

    /* prepare common data for a leave application both for apply a leave or assign a leave */

    private function _prepare_leave_form_data() {

        $this->validate_submitted_data(array(
            "leave_type_id" => "required|numeric",
            "reason" => "required"
        ));

        $duration = $this->request->getPost('duration');
        $hours_per_day = 8;
        $hours = 0;
        $days = 0;

        $target_path = get_setting("timeline_file_path");
        $files_data = move_files_from_temp_dir_to_permanent_dir($target_path, "leave");
        $new_files = unserialize($files_data);

        if ($duration === "multiple_days") {

            $this->validate_submitted_data(array(
                "start_date" => "required",
                "end_date" => "required"
            ));

            $start_date = $this->request->getPost('start_date');
            $end_date = $this->request->getPost('end_date');

            //calculate total days
            $d_start = new \DateTime($start_date);
            $d_end = new \DateTime($end_date);
            $d_diff = $d_start->diff($d_end);

            $days = $d_diff->days + 1;
            $hours = $days * $hours_per_day;
        } else if ($duration === "hours") {

            $this->validate_submitted_data(array(
                "hour_date" => "required"
            ));

            $start_date = $this->request->getPost('hour_date');
            $end_date = $start_date;
            $hours = $this->request->getPost('hours');
            $days = $hours / $hours_per_day;
        } else {

            $this->validate_submitted_data(array(
                "single_date" => "required"
            ));

            $start_date = $this->request->getPost('single_date');
            $end_date = $start_date;
            $hours = $hours_per_day;
            $days = 1;
        }

        $now = get_current_utc_time();
        $leave_data = array(
            "leave_type_id" => $this->request->getPost('leave_type_id'),
            "start_date" => $start_date,
            "end_date" => $end_date,
            "reason" => $this->request->getPost('reason'),
            "created_by" => $this->login_user->id,
            "created_at" => $now,
            "total_hours" => $hours,
            "total_days" => $days,
            "files" => serialize($new_files)
        );

        return $leave_data;
    }

    // load pending approval tab
    function pending_approval() {
        return $this->template->view("leaves/pending_approval");
    }

    // load all applications tab 
    function all_applications() {
        return $this->template->view("leaves/all_applications");
    }

    // load leave summary tab
    function summary() {
        $view_data['team_members_dropdown'] = json_encode($this->_get_members_dropdown_list_for_filter());
        $view_data['leave_types_dropdown'] = json_encode($this->_get_leave_types_dropdown_list_for_filter());
        return $this->template->view("leaves/summary", $view_data);
    }

    // list of pending leave application. prepared for datatable
    function pending_approval_list_data() {
        $options = array("status" => "pending", "access_type" => $this->access_type, "allowed_members" => $this->allowed_members);
        $list_data = $this->Leave_applications_model->get_list($options)->getResult();

        $result = array();
        foreach ($list_data as $data) {
            $result[] = $this->_make_row($data);
        }
        echo json_encode(array("data" => $result));
    }

    // list of all leave application. prepared for datatable 
    function all_application_list_data() {

        $this->validate_submitted_data(array(
            "applicant_id" => "numeric"
        ));

        $start_date = $this->request->getPost('start_date');
        $end_date = $this->request->getPost('end_date');
        $applicant_id = $this->request->getPost('applicant_id');

        $options = array("start_date" => $start_date, "end_date" => $end_date, "applicant_id" => $applicant_id, "login_user_id" => $this->login_user->id, "access_type" => $this->access_type, "allowed_members" => $this->allowed_members);
        $list_data = $this->Leave_applications_model->get_list($options)->getResult();
        $result = array();
        foreach ($list_data as $data) {
            $result[] = $this->_make_row($data);
        }
        echo json_encode(array("data" => $result));
    }

    // list of leave summary. prepared for datatable
    function summary_list_data() {
        $start_date = $this->request->getPost('start_date');
        $end_date = $this->request->getPost('end_date');
        $applicant_id = $this->request->getPost('applicant_id');
        $leave_type_id = $this->request->getPost('leave_type_id');

        $options = array("start_date" => $start_date, "end_date" => $end_date, "access_type" => $this->access_type, "allowed_members" => $this->allowed_members, "applicant_id" => $applicant_id, "leave_type_id" => $leave_type_id);
        $list_data = $this->Leave_applications_model->get_summary($options)->getResult();

        $result = array();
        foreach ($list_data as $data) {
            $result[] = $this->_make_row_for_summary($data);
        }
        echo json_encode(array("data" => $result));
    }

    // reaturn a row of leave application list table
    private function _row_data($id) {
        $options = array("id" => $id);
        $data = $this->Leave_applications_model->get_list($options)->getRow();
        return $this->_make_row($data);
    }

    // prepare a row of leave application list table
    private function _make_row($data) {
        $meta_info = $this->_prepare_leave_info($data);
        $option_icon = "info";
        if ($data->status === "pending") {
            $option_icon = "cloud-lightning";
        }

        $actions = modal_anchor(get_uri("leaves/application_details"), "<i data-feather='$option_icon' class='icon-16'></i>", array("class" => "edit", "title" => app_lang('application_details'), "data-post-id" => $data->id));

        //checking the user permissiton to show/hide reject and approve button
        $can_manage_application = false;
        if ($this->access_type === "all") {
            $can_manage_application = true;
        } else if (array_search($data->applicant_id, $this->allowed_members) && $data->applicant_id !== $this->login_user->id) {
            $can_manage_application = true;
        }

        if ($this->can_delete_leave_application() && $can_manage_application) {
            $actions .= js_anchor("<i data-feather='x' class='icon-16'></i>", array('title' => app_lang('delete'), "class" => "delete", "data-id" => $data->id, "data-action-url" => get_uri("leaves/delete"), "data-action" => "delete-confirmation"));
        }

        return array(
            get_team_member_profile_link($data->applicant_id, $meta_info->applicant_meta),
            $meta_info->leave_type_meta,
            $meta_info->date_meta,
            $meta_info->duration_meta,
            $meta_info->status_meta,
            $actions
        );
    }

    // prepare a row of leave application list table
    private function _make_row_for_summary($data) {
        $meta_info = $this->_prepare_leave_info($data);

        return array(
            get_team_member_profile_link($data->applicant_id, $meta_info->applicant_meta),
            $meta_info->leave_type_meta,
            $meta_info->duration_meta
        );
    }

    //return required style/format for a application
    private function _prepare_leave_info($data) {
        $image_url = get_avatar($data->applicant_avatar);
        $data->applicant_meta = "<span class='avatar avatar-xs mr10'><img src='$image_url' alt=''></span>" . $data->applicant_name;

        if (isset($data->status)) {
            if ($data->status === "pending") {
                $status_class = "bg-warning";
            } else if ($data->status === "approved") {
                $status_class = "bg-success";
            } else if ($data->status === "rejected") {
                $status_class = "bg-danger";
            } else {
                $status_class = "bg-dark";
            }
            $data->status_meta = "<span class='badge $status_class'>" . app_lang($data->status) . "</span>";
        }

        if (isset($data->start_date)) {
            $date = format_to_date($data->start_date, FALSE);
            if ($data->start_date != $data->end_date) {
                $date = sprintf(app_lang('start_date_to_end_date_format'), format_to_date($data->start_date, FALSE), format_to_date($data->end_date, FALSE));
            }
            $data->date_meta = $date;
        }
        if ($data->total_days > 1) {
            $duration = $data->total_days . " " . app_lang("days");
        } else {
            $duration = $data->total_days . " " . app_lang("day");
        }

        if ($data->total_hours > 1) {
            $duration = $duration . " (" . $data->total_hours . " " . app_lang("hours") . ")";
        } else {
            $duration = $duration . " (" . $data->total_hours . " " . app_lang("hour") . ")";
        }
        $data->duration_meta = $duration;
        $data->leave_type_meta = "<span style='background-color:" . $data->leave_type_color . "' class='color-tag float-start'></span>" . $data->leave_type_title;
        return $data;
    }

    // reaturn a row of leave application list table
    function application_details() {
        $this->validate_submitted_data(array(
            "id" => "required|numeric"
        ));

        $applicaiton_id = $this->request->getPost('id');
        $info = $this->Leave_applications_model->get_details_info($applicaiton_id);
        if (!$info) {
            show_404();
        }


        //checking the user permissiton to show/hide reject and approve button
        $can_manage_application = false;
        if ($this->access_type === "all") {
            $can_manage_application = true;
        } else if (array_search($info->applicant_id, $this->allowed_members) && $info->applicant_id !== $this->login_user->id) {
            $can_manage_application = true;
        }
        $view_data['show_approve_reject'] = $can_manage_application;

        //has permission to manage the appliation? or is it own application?
        if (!$can_manage_application && $info->applicant_id !== $this->login_user->id) {
            app_redirect("forbidden");
        }

        $view_data['leave_info'] = $this->_prepare_leave_info($info);
        return $this->template->view("leaves/application_details", $view_data);
    }

    //update leave status
    function update_status() {

        $this->validate_submitted_data(array(
            "id" => "required|numeric",
            "status" => "required"
        ));

        $applicaiton_id = $this->request->getPost('id');
        $status = $this->request->getPost('status');
        $now = get_current_utc_time();

        $leave_data = array(
            "checked_by" => $this->login_user->id,
            "checked_at" => $now,
            "status" => $status
        );

        //only allow to updte the status = accept or reject for admin or specefic user
        //otherwise user can cancel only his/her own application
        $applicatoin_info = $this->Leave_applications_model->get_one($applicaiton_id);

        if ($status === "approved" || $status === "rejected") {
            $this->access_only_allowed_members($applicatoin_info->applicant_id);
        } else if ($status === "canceled" && $applicatoin_info->applicant_id != $this->login_user->id) {
            //any user can't cancel other user's leave application
            app_redirect("forbidden");
        }

        //user can update only the applications where status = pending
        if ($applicatoin_info->status != "pending" || !($status === "approved" || $status === "rejected" || $status === "canceled")) {
            app_redirect("forbidden");
        }

        $save_id = $this->Leave_applications_model->ci_save($leave_data, $applicaiton_id);
        if ($save_id) {

            $notification_options = array("leave_id" => $applicaiton_id, "to_user_id" => $applicatoin_info->applicant_id);

            if ($status == "approved") {
                log_notification("leave_approved", $notification_options);
            } else if ($status == "rejected") {
                log_notification("leave_rejected", $notification_options);
            } else if ($status == "canceled") {
                log_notification("leave_canceled", $notification_options);
            }

            echo json_encode(array("success" => true, "data" => $this->_row_data($save_id), 'id' => $save_id, 'message' => app_lang('record_saved')));
        } else {
            echo json_encode(array("success" => false, 'message' => app_lang('error_occurred')));
        }
    }

    //    delete a leave application

    function delete() {

        $id = $this->request->getPost('id');

        $this->validate_submitted_data(array(
            "id" => "required|numeric"
        ));

        if (!$this->can_delete_leave_application()) {
            app_redirect("forbidden");
        }

        $applicatoin_info = $this->Leave_applications_model->get_one($id);
        $this->access_only_allowed_members($applicatoin_info->applicant_id);

        if ($this->Leave_applications_model->delete($id)) {
            echo json_encode(array("success" => true, 'message' => app_lang('record_deleted')));
        } else {
            echo json_encode(array("success" => false, 'message' => app_lang('record_cannot_be_deleted')));
        }
    }

    //view leave list of login user
    function leave_info() {
        $this->check_module_availability("module_leave");

        $view_data['applicant_id'] = $this->login_user->id;
        if ($this->request->isAJAX()) {
            return $this->template->view("team_members/leave_info", $view_data);
        } else {
            $view_data['page_type'] = "full";
            return $this->template->rander("team_members/leave_info", $view_data);
        }
    }

    //summary dropdown list of team members

    private function _get_members_dropdown_list_for_filter() {

        if ($this->access_type === "all") {
            $where = array("user_type" => "staff");
        } else {
            if (!count($this->allowed_members)) {
                $where = array("user_type" => "nothing");
            } else {
                $allowed_members = $this->allowed_members;
                $allowed_members[] = $this->login_user->id;

                $where = array("user_type" => "staff", "where_in" => array("id" => $allowed_members));
            }
        }

        return $this->Users_model->get_id_and_text_dropdown(
            array("first_name", "last_name"),
            $where,
            "- " . app_lang("team_member") . " -"
        );
    }

    //summary dropdown list of leave type 

    private function _get_leave_types_dropdown_list_for_filter() {

        $leave_type = $this->Leave_types_model->get_dropdown_list(array("title"), "id", array("status" => "active"));

        $leave_type_dropdown = array(array("id" => "", "text" => "- " . app_lang("leave_type") . " -"));
        foreach ($leave_type as $id => $name) {
            $leave_type_dropdown[] = array("id" => $id, "text" => $name);
        }
        return $leave_type_dropdown;
    }

    function file_preview($id = "", $key = "") {
        if ($id) {
            validate_numeric_value($id);
            $leave_info = $this->Leave_applications_model->get_one($id);
            $files = unserialize($leave_info->files);
            $file = get_array_value($files, $key);

            $file_name = get_array_value($file, "file_name");
            $file_id = get_array_value($file, "file_id");
            $service_type = get_array_value($file, "service_type");

            $view_data["file_url"] = get_source_url_of_file($file, get_setting("timeline_file_path"));
            $view_data["is_image_file"] = is_image_file($file_name);
            $view_data["is_iframe_preview_available"] = is_iframe_preview_available($file_name);
            $view_data["is_google_preview_available"] = is_google_preview_available($file_name);
            $view_data["is_viewable_video_file"] = is_viewable_video_file($file_name);
            $view_data["is_google_drive_file"] = ($file_id && $service_type == "google") ? true : false;
            $view_data["is_iframe_preview_available"] = is_iframe_preview_available($file_name);

            return $this->template->view("leaves/file_preview", $view_data);
        } else {
            show_404();
        }
    }

    private function _validate_excel_import_access() {
        return ($this->access_only_allowed_members());
    }

    private function _get_controller_slag() {
        return "leaves";
    }

    private function _get_custom_field_context() {
        return "leaves";
    }

    private function _get_headers_for_import() {
        $this->_init_required_data_before_starting_import();

        return array(
            array("name" => "applicant", "custom_validation" => function ($applicant) {
                //check the user is exist or not
                if ($applicant) {
                    $user_id = get_array_value($this->users_id_by_name, trim($applicant));
                    if (!$user_id) {
                        return array("error" => sprintf(app_lang("import_not_exists_error_message"), app_lang("user")));
                    }
                } else {
                    return array("error" => sprintf(app_lang("import_error_field_required"), app_lang("applicant")));
                }
            }),
            array("name" => "leave_type", "required" => true, "required_message" => sprintf(app_lang("import_error_field_required"), app_lang("leave_type"))),
            array("name" => "start_date", "required" => true, "required_message" => app_lang("import_date_error_message"), "custom_validation" => function ($start_date) {
                if (!$this->_check_valid_date($start_date)) {
                    return array("error" => app_lang("import_date_error_message"));
                }
            }),
            array("name" => "end_date", "required" => true, "required_message" => app_lang("import_date_error_message"), "custom_validation" => function ($start_date) {
                if (!$this->_check_valid_date($start_date)) {
                    return array("error" => app_lang("import_date_error_message"));
                }
            }),
            array("name" => "total_hours", "required" => true, "required_message" => sprintf(app_lang("import_error_field_required"), app_lang("total_hours"))),
            array("name" => "total_days", "required" => true, "required_message" => sprintf(app_lang("import_error_field_required"), app_lang("total_days"))),
            array("name" => "reason", "required" => true, "required_message" => sprintf(app_lang("import_error_field_required"), app_lang("reason"))),
            array("name" => "status", "required" => true, "required_message" => sprintf(app_lang("import_error_field_required"), app_lang("status")), "custom_validation" => function ($status) {
                if ($status && !in_array(strtolower($status), array("pending", "approved", "rejected", "canceled"))) {
                    return array("error" => sprintf(app_lang("import_leave_status_error_message"), $status) . ".");
                }
            })
        );
    }

    function download_sample_excel_file() {
        $this->access_only_allowed_members();
        return $this->download_app_files(get_setting("system_file_path"), serialize(array(array("file_name" => "import-leaves-sample.xlsx"))));
    }

    private function _init_required_data_before_starting_import() {
        $users = $this->Users_model->get_team_members_id_and_name()->getResult();
        $users_id_by_name = array();
        foreach ($users as $user) {
            $users_id_by_name[$user->user_name] = $user->id;
        }

        $leave_types = $this->Leave_types_model->get_details()->getResult();
        $leave_types_id_by_title = array();
        foreach ($leave_types as $leave_type) {
            $leave_types_id_by_title[$leave_type->title] = $leave_type->id;
        }

        $this->users_id_by_name = $users_id_by_name;
        $this->leave_types_id_by_title = $leave_types_id_by_title;
    }

    private function _save_a_row_of_excel_data($row_data) {
        $now = get_current_utc_time();

        $leave_data_array = $this->_prepare_leave_data($row_data);
        $leave_data = get_array_value($leave_data_array, "leave_data");

        //couldn't prepare valid data
        if (!($leave_data && count($leave_data) > 1)) {
            return false;
        }

        //found information about leave, add some additional info
        $leave_data["created_at"] = $now;
        $leave_data["created_by"] = $this->login_user->id;

        //save leave data
        $leave_save_id = $this->Leave_applications_model->ci_save($leave_data);
        if (!$leave_save_id) {
            return false;
        }
    }

    private function _prepare_leave_data($row_data) {

        $leave_data = array();

        foreach ($row_data as $column_index => $value) {
            if (!$value) {
                continue;
            }

            $column_name = $this->_get_column_name($column_index);
            if ($column_name == "applicant") {
                $leave_data["applicant_id"] = get_array_value($this->users_id_by_name, trim($value));
            } else if ($column_name == "leave_type") {
                $leave_type_id = get_array_value($this->leave_types_id_by_title, $value);
                if ($leave_type_id) {
                    $leave_data["leave_type_id"] = $leave_type_id;
                } else {
                    $leave_type_data = array("title" => $value, "color" => "#83c340");
                    $saved_leave_type_id = $this->Leave_types_model->ci_save($leave_type_data);
                    $leave_data["leave_type_id"] = $saved_leave_type_id;
                    $this->leave_types_id_by_title[$value] = $saved_leave_type_id;
                }
            } else if ($column_name == "start_date") {
                $leave_data["start_date"] = $this->_check_valid_date($value);
            } else if ($column_name == "end_date") {
                $leave_data["end_date"] = $this->_check_valid_date($value);
            } else if ($column_name == "status") {
                $leave_data["status"] = strtolower($value);
            } else {
                $leave_data[$column_name] = $value;
            }
        }

        return array(
            "leave_data" => $leave_data
        );
    }
}

/* End of file leaves.php */
/* Location: ./app/controllers/leaves.php */