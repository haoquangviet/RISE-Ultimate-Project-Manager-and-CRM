<div class="card">
    <div class="card-header">
        <h4><?php echo app_lang('template') . ": " . $model_info->title; ?></h4>
    </div>
    <?php echo form_open(get_uri("contract_templates/save_template"), array("id" => "contract-template-form", "class" => "general-form email-template-form", "role" => "form")); ?>
    <div class="modal-body clearfix">
        <input type="hidden" name="id" value="<?php echo $model_info->id; ?>" />
        <div class='row'>
            <div class="form-group">
                <div class=" col-md-12">
                    <?php
                    echo form_textarea(array(
                        "id" => "template",
                        "name" => "template",
                        "value" => process_images_from_content($model_info->template, false),
                        "class" => "form-control",
                        "data-toolbar" => "pdf_friendly_toolbar",
                        "data-height" => 480,
                        "data-encode_ajax_post_data" => "1"
                    ));
                    ?>
                </div>
            </div>
        </div>
        <div><strong><?php echo app_lang("avilable_variables"); ?></strong>: <?php
            $avilable_variables = get_available_contract_variables();
            foreach ($avilable_variables as $variable) {
                echo "<span class='js-variable-tag clickable' data-bs-toggle='tooltip' data-bs-placement='bottom' data-title='" . app_lang('copy') . "' data-after-click-title='" . app_lang('copied') . "' title='" . app_lang('copy') . "'>{" . $variable . "}</span>, ";
            }
            ?></div>
        <hr />
        <div class="form-group m0">
            <button type="submit" class="btn btn-primary mr15"><span data-feather="check-circle" class="icon-16"></span> <?php echo app_lang('save'); ?></button>
        </div>

    </div>
    <?php echo form_close(); ?>
</div>

<script type="text/javascript">
    $(document).ready(function() {
        $("#contract-template-form").appForm({
            isModal: false,

            onSuccess: function(result) {
                if (result.success) {
                    appAlert.success(result.message, {
                        duration: 10000
                    });
                } else {
                    appAlert.error(result.message);
                }
            }
        });

        initWYSIWYGEditor("#template");

        $('[data-bs-toggle="tooltip"]').tooltip();
    });
</script> 