$('.collapsibleInput').keyup(function () {
    var value = $(this).val().toUpperCase();
    var $allListElements = $('.content ul > li');
    var $matchingListElements = $allListElements.filter(function(i, li){
        var listItemText = $(li).text().toUpperCase();
        return ~listItemText.indexOf(value);
    });

    var $content = $(".content");
    $content.each(function () {
        var $this = $(this);
        if ($("#liContent", this).text().toUpperCase().indexOf(value) !== -1 && value.length > 0) {
            $this.show();
            $allListElements.hide();
            $matchingListElements.show();
        } else {
            $this.hide();
        }
    });
});
