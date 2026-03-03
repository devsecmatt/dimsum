// dimsum — main application JavaScript
"use strict";

// Auto-dismiss flash messages after 5 seconds
document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".flash").forEach((el) => {
        setTimeout(() => {
            el.style.opacity = "0";
            setTimeout(() => el.remove(), 300);
        }, 5000);
    });
});
