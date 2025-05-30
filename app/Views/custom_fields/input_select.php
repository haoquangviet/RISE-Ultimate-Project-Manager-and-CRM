<?php $uid = "_" . uniqid(rand()); ?>
<select class="validate-hidden w100p" id="custom_field_<?php echo $field_info->id . $uid; ?>" name="custom_field_<?php echo $field_info->id; ?>" placeholder="<?php echo $placeholder; ?>" data-rule-required='<?php echo $field_info->required ? true : "false"; ?>'
    data-msg-required="<?php echo app_lang('field_required'); ?>">
    <option value=""></option>
    <?php
    $options = $field_info->options;
    $field_value = isset($field_info->value) ? $field_info->value : "";
    $options_array = explode(",", $options);
    if ($options && count($options_array)) {
        foreach ($options_array as $value) {
            $value = trim($value);

            if ($field_value === $value) {
                echo '<option selected="selected" value="' . $value . '" >' . $value . '</option>';
            } else {
                echo '<option value="' . $value . '" >' . $value . '</option>';
            }
        }
    }
    ?>
</select>
<?php
$return_only_field = isset($return_only_field) && $return_only_field == "1" ? true : false;

if (!$return_only_field) { ?>
    <script type="text/javascript">
        $(document).ready(function() {
            $("select#custom_field_<?php echo $field_info->id . $uid; ?>").appDropdown();
        });
    </script>

<?php } ?>