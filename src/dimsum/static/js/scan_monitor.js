// dimsum — Scan progress monitor
"use strict";

class ScanMonitor {
    constructor(projectId, scanId) {
        this.projectId = projectId;
        this.scanId = scanId;
        this.pollInterval = 2000;
        this.timer = null;
    }

    start() {
        this.poll();
        this.timer = setInterval(() => this.poll(), this.pollInterval);
    }

    stop() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
        }
    }

    async poll() {
        try {
            const resp = await fetch(
                `/api/projects/${this.projectId}/scans/${this.scanId}/progress`
            );
            if (!resp.ok) return;
            const data = await resp.json();
            this.updateUI(data);

            if (["completed", "failed", "cancelled"].includes(data.status)) {
                this.stop();
                this.onComplete(data);
            }
        } catch (err) {
            console.error("Poll error:", err);
        }
    }

    updateUI(data) {
        const bar = document.getElementById("progress-bar");
        const text = document.getElementById("progress-text");
        const status = document.getElementById("scan-status");

        if (bar) bar.style.width = `${data.progress_percent}%`;
        if (text) text.textContent = data.progress_message || "";
        if (status) status.textContent = data.status;
    }

    onComplete(data) {
        const text = document.getElementById("progress-text");
        if (text) {
            text.textContent =
                data.status === "completed"
                    ? "Scan complete."
                    : `Scan ${data.status}.`;
        }
    }
}
