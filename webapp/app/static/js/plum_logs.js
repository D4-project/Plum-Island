"use strict";

document.getElementById("plum-log-file")?.addEventListener("change", (event) => {
    event.currentTarget.form.requestSubmit();
});

const plumLogTail = document.querySelector("[data-log-tail]");
if (plumLogTail) plumLogTail.scrollTop = plumLogTail.scrollHeight;
