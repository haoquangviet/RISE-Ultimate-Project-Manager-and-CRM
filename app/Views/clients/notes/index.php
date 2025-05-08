<div class="card client-notes-container">
    <div class="card-header fw-bold">
        <i data-feather="check-circle" class="icon-16"></i> &nbsp;<?php echo app_lang("notes"); ?>
    </div>
    <div class="card-body">
        <?php echo modal_anchor(get_uri("notes/modal_form"), "<i data-feather='plus' class='icon-16'></i> " . app_lang('add_note'), array("title" => app_lang('add_note'), "data-post-client_id" => $client_id)); ?>
    </div>

    <div class="table-responsive">
        <table id="client-details-page-note-table" class="display no-thead b-t b-b-only no-hover hide-dtr-control hide-status-checkbox" width="100%">
        </table>
    </div>
</div>
<script type="text/javascript">
    $(document).ready(function () {
        $("#client-details-page-note-table").appTable({
            source: '<?php echo_uri("notes/list_data/client/" . $client_id) ?>' + '/1',
            order: [[0, "desc"]],
            hideTools: true,
            displayLength: 100,
            stateSave: false,
            responsive: true,
            mobileMirror: true,
            reloadHooks: [{
                    type: "app_form",
                    id: "note-form",
                    filter: {client_id: "<?php echo $client_info->id ?>"},
                },
                {
                    type: "app_table_row_update",
                    tableId: "client-details-page-note-table"
                }
            ],
            columns: [
                {targets: [1], visible: false},
                {visible: false, searchable: false},
                {title: '<?php echo app_lang("title"); ?>', "class": "all"},
                {visible: false, searchable: false},
                {title: '<?php echo app_lang("files") ?>'},
                {title: '<i data-feather="menu" class="icon-16"></i>', "class": "text-center option w100"}
            ]
        });
    });
</script>