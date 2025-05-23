<div id="page-content" class="page-wrapper clearfix">
    <div class="row">
        <div class="col-sm-3 col-lg-2">
            <?php
            $tab_view['active_tab'] = "all_plugins";
            echo view("settings/tabs", $tab_view);
            ?>
        </div>

        <div class="col-sm-9 col-lg-10">
            <div class="card">
                <div class="page-title clearfix">
                    <h4> <?php echo app_lang('plugins'); ?></h4>
                    <div class="title-button-group">
                        <?php echo modal_anchor(get_uri("rise_plugins/modal_form"), "<i data-feather='download' class='icon-16'></i> " . app_lang('install_plugin'), array("class" => "btn btn-default", "title" => app_lang('install_plugin'))); ?>
                    </div>
                </div>
                <div class="table-responsive">
                    <table id="plugin-table" class="display" cellspacing="0" width="100%">            
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script type="text/javascript">
    $(document).ready(function () {
        $("#plugin-table").appTable({
            source: '<?php echo_uri("rise_plugins/list_data") ?>',
            columns: [
                {title: '<?php echo app_lang("title") ?>'},
                {title: '<?php echo app_lang("description") ?>'},
                {title: '<?php echo app_lang("status") ?>'},
                {title: '<i data-feather="menu" class="icon-16"></i>', "class": "text-center dropdown-option w100"}
            ]
        });

        $("#confirmationModalContent .container-fluid").html($("#confirmationModalContent .container-fluid").text() + "<br /> <?php echo app_lang("plugin_deletion_alert_message"); ?>");
    });
</script>