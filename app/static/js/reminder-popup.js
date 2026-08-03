(() => {
    if (window.top !== window.self || !document.body) return;
    const sessionKey = "messis.reminderPopup.shown";
    if (sessionStorage.getItem(sessionKey) === "1") return;

    let overlay = null;
    let closeTimer = null;
    const close = () => {
        if (closeTimer) window.clearTimeout(closeTimer);
        if (overlay) overlay.remove();
        overlay = null;
    };

    window.addEventListener("message", event => {
        if (event.origin !== window.location.origin || !event.data) return;
        if (event.data.type === "messis-reminder-close") close();
        if (event.data.type === "messis-reminder-ready") {
            sessionStorage.setItem(sessionKey, "1");
            if (!event.data.count) { close(); return; }
            overlay.classList.add("messis-reminder-visible");
            closeTimer = window.setTimeout(close, 15000);
        }
    });

    window.setTimeout(() => {
        overlay = document.createElement("div");
        overlay.className = "messis-reminder-overlay";
        overlay.setAttribute("role", "dialog");
        overlay.setAttribute("aria-label", "Daily farm reminders");
        const frame = document.createElement("iframe");
        frame.src = "/reminders/popup";
        frame.title = "Daily farm reminders";
        frame.className = "messis-reminder-frame";
        overlay.appendChild(frame);
        document.body.appendChild(overlay);
    }, 5000);

    const style = document.createElement("style");
    style.textContent = `.messis-reminder-overlay{position:fixed;inset:0;z-index:100000;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(4,32,20,.62);backdrop-filter:blur(4px)}.messis-reminder-overlay.messis-reminder-visible{display:flex}.messis-reminder-frame{width:min(680px,100%);height:min(680px,88vh);border:0;border-radius:20px;background:#f5fff8;box-shadow:0 28px 80px rgba(0,0,0,.3)}@media(max-width:600px){.messis-reminder-overlay{padding:10px}.messis-reminder-frame{height:86vh;border-radius:16px}}`;
    document.head.appendChild(style);
})();
