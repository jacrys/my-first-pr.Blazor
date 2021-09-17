// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.
$(function() {
    var issueTextElements = document.getElementsByClassName('card-text')
    for (issueTextElement of issueTextElements) {
        issueTextElement.innerHTML = marked(issueTextElement.innerHTML);
    }

    $(".search-link").click(() => {
        $("main").html(
            `<div class="spinner-container">
                <div class="spinner">
                   <i class="fas fa-jack-o-lantern fa-spin"></i>
                   <span>Loading...</span>
                </div>
            </div>`);
    })
})