<div id="page-content" class="page-wrapper clearfix help-page-container <?php echo "main_" . $type ?>">

    <?php if (isset($can_manage_help_and_kb) && $can_manage_help_and_kb) { ?>
        <div class="view-container-large">
            <?php echo anchor("help/{$type}_articles", "<i data-feather='book-open' class='icon-16 mr5'></i> " . app_lang("articles"), array("class" => "btn btn-default round mr5")) ?>
            <?php echo anchor("help/{$type}_categories", "<i data-feather='codepen' class='icon-16 mr5'></i> " . app_lang("categories"), array("class" => "btn btn-default round")) ?>
        </div>
    <?php } ?>

    <div id="search-box-wrapper">
        <div class="help-search-box-container">
            <h2><?php
                if ($type === "knowledge_base") {
                    echo app_lang("how_can_we_help");
                } else {
                    echo app_lang("help_page_title");
                }
                ?></h2>
            <?php echo view("help_and_knowledge_base/search_box", array("type" => $type)); ?>
        </div>
    </div>

    <div class="help-page view-container-large" style="min-height: 300px;">

        <?php
        $count = 0;

        foreach ($categories as $category) {
            if ($count % 3 === 0) {
                echo "<div class='row'>";
            }
            $count++;
        ?>
            <div class="col-md-4 col-sm-12">
                <a href="<?php echo get_uri($type . "/category/" . $category->id); ?>">
                    <div class="card">
                        <div class="page-body p15 help-category-box">
                            <h4><?php echo $category->title; ?></h4>
                            <p class="text-off"><?php echo custom_nl2br($category->description ? process_images_from_content($category->description) : ""); ?></p>
                            <span class="anchor"><?php echo $category->total_articles . " " . app_lang("articles"); ?></span>
                        </div>
                    </div>
                </a>
            </div>
        <?php
            if (($count % 3 === 0) || ($count === count($categories))) {
                echo "</div>";
            }
        }
        ?>
    </div>
</div>