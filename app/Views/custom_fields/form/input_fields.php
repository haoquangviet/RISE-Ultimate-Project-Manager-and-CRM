<input type="hidden" name="id" value="<?php echo $model_info->id; ?>" />

<div class="form-group">
    <div class="row">
        <label for="title" class=" col-md-3"><?php echo app_lang('title'); ?></label>
        <div class=" col-md-9">
            <?php
            echo form_input(array(
                "id" => "title",
                "name" => "title",
                "value" => $model_info->title,
                "class" => "form-control",
                "placeholder" => app_lang('title'),
                "autofocus" => true,
                "data-rule-required" => true,
                "data-msg-required" => app_lang("field_required"),
            ));
            ?>
        </div>
    </div>
</div>

<div class="form-group">
    <div class="row">
        <label for="title_language_key" class=" col-md-3"><?php echo app_lang('title_language_key'); ?>
            <span class="help" data-container="body" data-bs-toggle="tooltip" title="<?php echo app_lang('language_key_recommendation_help_text') ?>"><i data-feather="help-circle" class="icon-16"></i></span>
        </label>
        <div class=" col-md-9">
            <?php
            echo form_input(array(
                "id" => "title_language_key",
                "name" => "title_language_key",
                "value" => $model_info->title_language_key,
                "class" => "form-control",
                "placeholder" => app_lang('keep_it_blank_if_you_do_not_use_translation')
            ));
            ?>
        </div>
    </div>
</div>

<div class="form-group">
    <div class="row">
        <label for="placeholder" class=" col-md-3"><?php echo app_lang('placeholder'); ?></label>
        <div class=" col-md-9">
            <?php
            echo form_input(array(
                "id" => "placeholder",
                "name" => "placeholder",
                "value" => $model_info->placeholder,
                "class" => "form-control",
                "placeholder" => app_lang('placeholder')
            ));
            ?>
        </div>
    </div>
</div>

<div class="form-group">
    <div class="row">
        <label for="placeholder_language_key" class=" col-md-3"><?php echo app_lang('placeholder_language_key'); ?>
            <span class="help" data-container="body" data-bs-toggle="tooltip" title="<?php echo app_lang('language_key_recommendation_help_text') ?>"><i data-feather="help-circle" class="icon-16"></i></span>
        </label>
        <div class=" col-md-9">
            <?php
            echo form_input(array(
                "id" => "placeholder_language_key",
                "name" => "placeholder_language_key",
                "value" => $model_info->placeholder_language_key,
                "class" => "form-control",
                "placeholder" => app_lang('keep_it_blank_if_you_do_not_use_translation')
            ));
            ?>
        </div>
    </div>
</div>

<div class="form-group">
    <div class="row">
        <label for="template_variable_name" class=" col-md-3"><?php echo app_lang('template_variable_name'); ?></label>
        <div class=" col-md-9">
            <?php
            echo form_input(array(
                "id" => "template_variable_name",
                "name" => "template_variable_name",
                "value" => $model_info->template_variable_name,
                "class" => "form-control text-uppercase",
                "placeholder" => "VARIABLE_NAME",
                "autocomplete" => "off"
            ));
            ?>
        </div>
    </div>
</div>

<div class="form-group">
    <div class="row">
        <label for="field_type" class=" col-md-3"><?php echo app_lang('field_type'); ?></label>
        <div class="col-md-9">
            <?php
            $disabled = "";
            if ($model_info->id) {
                $disabled = " disabled='disabled'";
            }

            $field_type_dropdown = array(
                "text" => app_lang("field_type_text"),
                "textarea" => app_lang("field_type_textarea"),
                "select" => app_lang("field_type_select"),
                "multi_select" => app_lang("field_type_multi_select"),
                "email" => app_lang("email"),
                "date" => app_lang("date"),
                "time" => app_lang("field_type_time"),
                "number" => app_lang("field_type_number"),
                "external_link" => app_lang("field_type_external_link"),
                "multiple_choice" => app_lang("field_type_multiple_choice"),
                "checkboxes" => app_lang("field_type_checkboxes")
            );
            echo form_dropdown("field_type", $field_type_dropdown, $model_info->field_type, "class='select2' id='field_type' $disabled");
            ?>
        </div>
    </div>
</div>

<div id="options_container" class="form-group">
    <div class="row">
        <label for="options" class=" col-md-3"><?php echo app_lang('options'); ?></label>
        <div class=" col-md-9">
            <?php
            $labels = explode(",", $model_info->options);
            $opton_suggestions = array();
            foreach ($labels as $label) {
                if ($label && !in_array($label, $opton_suggestions)) {
                    $opton_suggestions[] = $label;
                }
            }
            if (!count($opton_suggestions)) {
                $opton_suggestions = array("0" => "");
            }


            echo form_input(array(
                "id" => "options",
                "name" => "options",
                "value" => $model_info->options,
                "class" => "form-control",
                "placeholder" => app_lang('select_placeholder_type_and_press_enter')
            ));
            ?>
        </div>
    </div>
</div>

<div class="form-group">
    <div class="row">
        <label for="required" class=" col-md-3"><?php echo app_lang('required'); ?></label>
        <div class="col-md-9">
            <?php
            echo form_checkbox(
                "required",
                "1",
                $model_info->required,
                "id='required' class='form-check-input'"
            );
            ?>
        </div>
    </div>
</div>

<?php if (isset($related_to) && $related_to != "events") { ?>
    <div id="add_filter_container" class="form-group">
        <div class="row">
            <label for="add_filter" class=" col-md-3"><?php echo app_lang('add_filter'); ?></label>
            <div class="col-md-9">
                <?php
                echo form_checkbox(
                    "add_filter",
                    "1",
                    $model_info->add_filter,
                    "id='add_filter' class='form-check-input'"
                );
                ?>
            </div>
        </div>
    </div>
<?php } ?>

<script type="text/javascript">
    $(document).ready(function() {

        $("#field_type").select2().change(function() {
            showHideFieldOptions($(this).val());
        });

        showHideFieldOptions("<?php echo $model_info->field_type; ?>");

        $("#options").select2({
            tags: <?php echo json_encode($opton_suggestions); ?>
        });

        $('[data-bs-toggle="tooltip"]').tooltip();

    });

    //show the options field only for slect/multi_select type fields
    function showHideFieldOptions(fieldType) {
        if (fieldType === "select" || fieldType === "multi_select" || fieldType === "multiple_choice" || fieldType === "checkboxes") {
            $("#options_container").show();
            $("#add_filter_container").show();
        } else {
            $("#options_container").hide();
            $("#add_filter_container").hide();
        }
    }
</script>