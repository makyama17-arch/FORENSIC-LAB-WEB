// ============================================
// FORENSIC LAB - MAIN JAVASCRIPT
// FULL FORENSIC REPORT VERSION
// ============================================

import {
    auth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged,
    updateProfile
} from "./firebase-config.js";


// ============================================
// GLOBAL HELPERS
// ============================================

const $ = (id) => document.getElementById(id);

const ADMIN_UID = "sNQN4CLKeIhdHUeXbMqfW0gOpg62";

function showMessage(message, type = "info") {

    const box = $("message-box");

    if (box) {

        box.textContent = message;
        box.className = `message-box ${type}`;
        box.style.display = "block";

    } else {

        alert(message);

    }
}

function hideMessage() {

    const box = $("message-box");

    if (box) {
        box.style.display = "none";
    }
}

function createElement(tag, className, text) {

    const element = document.createElement(tag);

    if (className) {
        element.className = className;
    }

    if (text !== undefined) {
        element.textContent = text;
    }

    return element;
}

function formatDate(timestamp) {

    if (!timestamp) return "N/A";

    return new Date(timestamp).toLocaleString();
}

function formatBytes(bytes) {

    if (!Number.isFinite(Number(bytes))) {
        return "N/A";
    }

    const units = ["Bytes", "KB", "MB", "GB"];

    let size = Number(bytes);
    let index = 0;

    while (size >= 1024 && index < units.length - 1) {

        size /= 1024;
        index++;

    }

    return `${size.toFixed(2)} ${units[index]}`;
}


// ============================================
// API REQUEST
// ============================================

async function apiRequest(url, options = {}) {

    const user = auth.currentUser;

    if (!user) {
        throw new Error("Please login first.");
    }

    const token = await user.getIdToken();

    const headers = {
        ...(options.headers || {}),
        Authorization: `Bearer ${token}`
    };

    if (
        options.body &&
        !(options.body instanceof FormData)
    ) {

        headers["Content-Type"] = "application/json";

    }

    const response = await fetch(url, {
        ...options,
        headers
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {

        throw new Error(
            data.error || `Request failed (${response.status}).`
        );

    }

    return data;
}


// ============================================
// AUTHENTICATED PDF DOWNLOAD
// ============================================

async function downloadForensicReport(reportUrl, button) {

    const user = auth.currentUser;

    if (!user) {
        throw new Error("Please login first.");
    }

    const originalText = button.textContent;

    button.disabled = true;
    button.textContent = "Preparing PDF...";

    try {

        const token = await user.getIdToken();

        const response = await fetch(reportUrl, {

            method: "GET",

            headers: {
                Authorization: `Bearer ${token}`
            }

        });

        if (!response.ok) {

            const errorData = await response.json().catch(() => ({}));

            throw new Error(
                errorData.error || "PDF download failed."
            );

        }

        const blob = await response.blob();

        const downloadUrl = URL.createObjectURL(blob);

        const link = document.createElement("a");

        link.href = downloadUrl;

        link.download = "FORENSIC_LAB_REPORT.pdf";

        document.body.appendChild(link);

        link.click();

        link.remove();

        setTimeout(() => {
            URL.revokeObjectURL(downloadUrl);
        }, 1000);

    } finally {

        button.disabled = false;
        button.textContent = originalText;

    }

}


// ============================================
// PAGE RELOAD DETECTION
// ============================================

const navigationEntry =
    performance.getEntriesByType("navigation")[0];

const isPageReload =
    navigationEntry?.type === "reload";


// ============================================
// AUTHENTICATION
// ============================================

const loginForm = $("login-form");

const registerForm = $("register-form");


// LOGIN

if (loginForm) {

    loginForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        hideMessage();

        const email = $("login-email")?.value.trim();

        const password = $("login-password")?.value;

        if (!email || !password) {

            showMessage(
                "Enter your email and password.",
                "error"
            );

            return;
        }

        try {

            await signInWithEmailAndPassword(
                auth,
                email,
                password
            );

            window.location.href = "/dashboard";

        } catch (error) {

            showMessage(error.message, "error");

        }

    });

}


// REGISTER

if (registerForm) {

    registerForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        hideMessage();

        const name = $("register-name")?.value.trim();

        const email = $("register-email")?.value.trim();

        const password = $("register-password")?.value;

        if (!name || name.length < 2) {

            showMessage("Enter a valid name.", "error");

            return;
        }

        if (!email) {

            showMessage("Enter your email.", "error");

            return;
        }

        if (!password || password.length < 6) {

            showMessage(
                "Password must contain at least 6 characters.",
                "error"
            );

            return;
        }

        try {

            const result = await createUserWithEmailAndPassword(
                auth,
                email,
                password
            );

            await updateProfile(result.user, {
                displayName: name
            });

            const token = await result.user.getIdToken(true);

            const response = await fetch("/api/sync-user", {

                method: "POST",

                headers: {

                    "Content-Type": "application/json",

                    Authorization: `Bearer ${token}`

                },

                body: JSON.stringify({ name })

            });

            if (!response.ok) {

                throw new Error(
                    "Account created, but profile synchronization failed."
                );

            }

            window.location.href = "/dashboard";

        } catch (error) {

            showMessage(error.message, "error");

        }

    });

}


// ============================================
// LOGIN / REGISTER SWITCHING
// ============================================

const showRegister = $("show-register");

const showLogin = $("show-login");

if (showRegister) {

    showRegister.addEventListener("click", (event) => {

        event.preventDefault();

        if (loginForm) {
            loginForm.style.display = "none";
        }

        if (registerForm) {
            registerForm.style.display = "block";
        }

        hideMessage();

    });

}

if (showLogin) {

    showLogin.addEventListener("click", (event) => {

        event.preventDefault();

        if (registerForm) {
            registerForm.style.display = "none";
        }

        if (loginForm) {
            loginForm.style.display = "block";
        }

        hideMessage();

    });

}


// ============================================
// LOGOUT
// ============================================

document.addEventListener("click", async (event) => {

    const target = event.target;

    if (!(target instanceof Element)) return;

    const button = target.closest("#logout-button");

    if (!button) return;

    event.preventDefault();

    button.disabled = true;

    try {

        await signOut(auth);

        window.location.replace("/auth");

    } catch (error) {

        alert("Logout failed: " + error.message);

        button.disabled = false;

    }

});


// ============================================
// AUTH STATE
// ============================================

onAuthStateChanged(auth, async (user) => {

    const currentPath = window.location.pathname;

    const protectedPages = [
        "/dashboard",
        "/analyze",
        "/admin"
    ];

    if (
        user &&
        user.uid === ADMIN_UID &&
        isPageReload &&
        currentPath === "/admin"
    ) {

        try {

            await signOut(auth);

        } catch (error) {

            console.error(error);

        }

        window.location.replace("/auth");

        return;
    }

    if (!user) {

        if (protectedPages.includes(currentPath)) {

            window.location.replace("/auth");

        }

        return;
    }

    try {

        await apiRequest("/api/sync-user", {

            method: "POST",

            body: JSON.stringify({})

        });

        if (currentPath === "/auth") {

            window.location.replace("/dashboard");

            return;
        }

        if (currentPath === "/dashboard") {

            loadDashboard();

        }

        if (currentPath === "/admin") {

            loadAdminPanel();

        }

    } catch (error) {

        console.error(error);

        if (
            error.message.toLowerCase().includes("suspended")
        ) {

            await signOut(auth);

            alert("Your account has been suspended.");

            window.location.replace("/auth");

        }

    }

});


// ============================================
// DASHBOARD
// ============================================

async function loadDashboard() {

    const userName = $("user-name");

    if (userName && auth.currentUser) {

        userName.textContent =
            auth.currentUser.displayName ||
            auth.currentUser.email;

    }

    await loadAds();

    await loadHistory();

}


// ============================================
// LOAD ADVERTISEMENTS
// ============================================

async function loadAds() {

    const container = $("ads-container");

    if (!container) return;

    container.replaceChildren();

    try {

        const data = await apiRequest("/api/ads");

        if (!data.ads || data.ads.length === 0) {

            container.textContent =
                "No announcements available.";

            return;
        }

        data.ads.forEach((ad) => {

            const card = createElement("div", "ad-card");

            const title = createElement("h3", "", ad.title);

            const text = createElement("p", "", ad.text);

            card.append(title, text);

            if (ad.url) {

                const link = createElement(
                    "a",
                    "",
                    "Learn more"
                );

                link.href = ad.url;

                link.target = "_blank";

                link.rel = "noopener noreferrer";

                card.appendChild(link);

            }

            container.appendChild(card);

        });

    } catch (error) {

        container.textContent = error.message;

    }

}


// ============================================
// ANALYSIS HISTORY
// ============================================

async function loadHistory() {

    const container = $("history-list");

    if (!container) return;

    container.replaceChildren();

    try {

        const data = await apiRequest("/api/history");

        if (!data.history || data.history.length === 0) {

            container.textContent =
                "No analysis history yet.";

            return;
        }

        data.history.forEach((item) => {

            const row = createElement(
                "div",
                "history-item"
            );

            row.append(

                createElement(
                    "strong",
                    "",
                    item.filename || "Unknown file"
                ),

                createElement(
                    "p",
                    "",
                    `Analysis: ${item.analysis_type || "File Analysis"}`
                ),

                createElement(
                    "p",
                    "",
                    `Case ID: ${item.case_id || "N/A"}`
                ),

                createElement(
                    "small",
                    "",
                    formatDate(item.created_at)
                )

            );

            container.appendChild(row);

        });

    } catch (error) {

        container.textContent = error.message;

    }

}


// ============================================
// FORENSIC RESULT DISPLAY HELPERS
// ============================================

function addReportHeading(container, title) {

    container.appendChild(
        createElement("h3", "forensic-section-title", title)
    );

}

function addReportField(container, label, value) {

    const row = createElement("div", "forensic-report-row");

    row.appendChild(
        createElement("strong", "", `${label}: `)
    );

    row.appendChild(
        createElement(
            "span",
            "",
            value === null || value === undefined || value === ""
                ? "Not Available"
                : String(value)
        )
    );

    container.appendChild(row);

}

function displayForensicReport(data, container) {

    container.replaceChildren();

    addReportHeading(
        container,
        "FORENSIC EXAMINATION COMPLETED"
    );

    // CASE INFORMATION

    addReportHeading(
        container,
        "1. CASE INFORMATION"
    );

    addReportField(container, "Case ID", data.case_id);

    addReportField(container, "Evidence ID", data.evidence_id);

    addReportField(
        container,
        "Analysis Type",
        data.analysis_type
    );

    // FILE INFORMATION

    addReportHeading(
        container,
        "2. FILE IDENTIFICATION"
    );

    addReportField(
        container,
        "Filename",
        data.filename
    );

    addReportField(
        container,
        "File Size",
        formatBytes(data.size)
    );

    addReportField(
        container,
        "SHA-256",
        data.sha256
    );

    addReportField(
        container,
        "SHA-1",
        data.sha1
    );

    addReportField(
        container,
        "MD5",
        data.md5
    );

    // IMAGE ANALYSIS

    if (data.is_image && data.image_analysis) {

        addReportHeading(
            container,
            "3. IMAGE TECHNICAL ANALYSIS"
        );

        const image = data.image_analysis;

        addReportField(container, "Format", image.format);

        addReportField(container, "Width", image.width);

        addReportField(container, "Height", image.height);

        addReportField(container, "Resolution", image.resolution);

        addReportField(container, "Color Mode", image.color_mode);

        addReportField(
            container,
            "Compression",
            image.compression
        );

        addReportField(
            container,
            "EXIF Present",
            image.exif_present ? "Yes" : "No"
        );

        addReportField(
            container,
            "Metadata Fields",
            image.metadata_fields
        );

        // EXIF METADATA

        addReportHeading(
            container,
            "4. EXIF METADATA"
        );

        const exif = data.exif_metadata || {};

        if (Object.keys(exif).length > 0) {

            Object.entries(exif).forEach(([key, value]) => {

                addReportField(
                    container,
                    key,
                    typeof value === "object"
                        ? JSON.stringify(value)
                        : value
                );

            });

        } else {

            addReportField(
                container,
                "EXIF",
                "No standard EXIF metadata detected."
            );

        }

        // GPS

        addReportHeading(
            container,
            "5. GPS INFORMATION"
        );

        const gps = data.gps_metadata;

        if (
            gps &&
            gps.available &&
            gps.latitude !== undefined
        ) {

            addReportField(
                container,
                "Latitude",
                gps.latitude
            );

            addReportField(
                container,
                "Longitude",
                gps.longitude
            );

        } else {

            addReportField(
                container,
                "GPS",
                "No interpretable GPS coordinates detected."
            );

        }

    }

    // FINDINGS

    addReportHeading(
        container,
        "6. FORENSIC FINDINGS"
    );

    if (data.findings && data.findings.length > 0) {

        data.findings.forEach((finding) => {

            const card = createElement(
                "div",
                "forensic-finding"
            );

            card.appendChild(
                createElement(
                    "strong",
                    "",
                    finding.title || "Finding"
                )
            );

            card.appendChild(
                createElement(
                    "p",
                    "",
                    finding.description || ""
                )
            );

            card.appendChild(
                createElement(
                    "small",
                    "",
                    `Severity: ${finding.severity || "Information"}`
                )
            );

            container.appendChild(card);

        });

    } else {

        addReportField(
            container,
            "Findings",
            "No additional findings recorded."
        );

    }

    // WARNINGS

    addReportHeading(
        container,
        "7. EXAMINATION WARNINGS"
    );

    if (data.warnings && data.warnings.length > 0) {

        data.warnings.forEach((warning) => {

            container.appendChild(
                createElement("p", "forensic-warning", warning)
            );

        });

    }

    // CONCLUSION

    addReportHeading(
        container,
        "8. EXAMINER'S CONCLUSION"
    );

    container.appendChild(
        createElement(
            "p",
            "forensic-conclusion",
            data.conclusion || "No conclusion available."
        )
    );

    // PDF DOWNLOAD

    const reportButton = createElement(
        "button",
        "btn btn-primary",
        "Download Full PDF Report"
    );

    reportButton.type = "button";

    reportButton.addEventListener("click", async () => {

        try {

            await downloadForensicReport(
                data.report_url,
                reportButton
            );

        } catch (error) {

            alert(error.message);

        }

    });

    container.appendChild(reportButton);

    // FINAL NOTICE

    container.appendChild(
        createElement(
            "p",
            "forensic-notice",
            "This automated examination does not independently prove file authenticity."
        )
    );

}


// ============================================
// FILE ANALYSIS
// ============================================

const analysisForm = $("analysis-form");

if (analysisForm) {

    analysisForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        const fileInput = $("analysis-file");

        const resultBox = $("analysis-result");

        const submitButton = analysisForm.querySelector(
            'button[type="submit"]'
        );

        if (!fileInput || !fileInput.files.length) {

            alert("Please select a file first.");

            return;
        }

        const file = fileInput.files[0];

        const maxSize = 100 * 1024 * 1024;

        if (file.size > maxSize) {

            resultBox.style.display = "block";

            resultBox.textContent =
                "File exceeds the 100 MB limit.";

            return;
        }

        const formData = new FormData();

        formData.append("file", file);

        resultBox.style.display = "block";

        resultBox.replaceChildren();

        resultBox.appendChild(
            createElement(
                "h3",
                "",
                "FORENSIC ANALYSIS IN PROGRESS"
            )
        );

        resultBox.appendChild(
            createElement(
                "p",
                "",
                "Examining evidence and generating forensic findings..."
            )
        );

        submitButton.disabled = true;

        submitButton.textContent = "Analyzing...";

        try {

            const data = await apiRequest(
                "/api/analyze",
                {
                    method: "POST",
                    body: formData
                }
            );

            displayForensicReport(
                data,
                resultBox
            );

            await loadHistory();

        } catch (error) {

            resultBox.replaceChildren();

            resultBox.appendChild(
                createElement(
                    "h3",
                    "",
                    "ANALYSIS FAILED"
                )
            );

            resultBox.appendChild(
                createElement(
                    "p",
                    "",
                    error.message
                )
            );

        } finally {

            submitButton.disabled = false;

            submitButton.textContent = "Start Analysis";

        }

    });

}


// ============================================
// ADMIN PANEL
// ============================================

async function loadAdminPanel() {

    try {

        await loadAdminStats();

        await loadAdminUsers();

        await loadAdminAds();

    } catch (error) {

        console.error(error);

        if (
            error.message.includes("Admin") ||
            error.message.includes("administrator")
        ) {

            alert("Administrator access required.");

            window.location.replace("/dashboard");

        }

    }

}


// ============================================
// ADMIN STATISTICS
// ============================================

async function loadAdminStats() {

    const data = await apiRequest(
        "/api/admin/stats"
    );

    if ($("total-users")) {

        $("total-users").textContent =
            data.total_users;

    }

    if ($("online-users")) {

        $("online-users").textContent =
            data.online_users;

    }

    if ($("weekly-users")) {

        $("weekly-users").textContent =
            data.weekly_users;

    }

    if ($("active-ads")) {

        $("active-ads").textContent =
            data.active_ads;

    }

}


// ============================================
// ADMIN USERS
// ============================================

async function loadAdminUsers() {

    const container = $("admin-users");

    if (!container) return;

    container.replaceChildren();

    const data = await apiRequest(
        "/api/admin/users"
    );

    data.users.forEach((user) => {

        const card = createElement(
            "div",
            "admin-user-card"
        );

        const name = createElement(
            "h4",
            "",
            user.name || user.email || user.uid
        );

        const email = createElement(
            "p",
            "",
            user.email || ""
        );

        const status = createElement(
            "p",
            "",
            user.suspended ? "Suspended" : "Active"
        );

        const button = createElement(
            "button",
            "action-button",
            user.suspended ? "Activate" : "Suspend"
        );

        button.addEventListener("click", async () => {

            const action = user.suspended
                ? "activate"
                : "suspend";

            if (
                !confirm(
                    `Are you sure you want to ${action} this user?`
                )
            ) {
                return;
            }

            try {

                await apiRequest(
                    `/api/admin/user/${encodeURIComponent(user.uid)}/${action}`,
                    {
                        method: "POST"
                    }
                );

                await loadAdminUsers();

                await loadAdminStats();

            } catch (error) {

                alert(error.message);

            }

        });

        card.append(
            name,
            email,
            status,
            button
        );

        container.appendChild(card);

    });

}


// ============================================
// CREATE ADVERTISEMENT
// ============================================

const adForm = $("ad-form");

if (adForm) {

    adForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        const title = $("ad-title")?.value.trim();

        const text = $("ad-text")?.value.trim();

        const url = $("ad-url")?.value.trim();

        try {

            await apiRequest(
                "/api/admin/ads",
                {
                    method: "POST",

                    body: JSON.stringify({
                        title,
                        text,
                        url
                    })

                }
            );

            adForm.reset();

            showMessage(
                "Announcement created successfully.",
                "success"
            );

            await loadAdminAds();

            await loadAdminStats();

        } catch (error) {

            showMessage(
                error.message,
                "error"
            );

        }

    });

}


// ============================================
// LOAD ADMIN ADVERTISEMENTS
// ============================================

async function loadAdminAds() {

    const container = $("admin-ads");

    if (!container) return;

    container.replaceChildren();

    const data = await apiRequest(
        "/api/admin/ads"
    );

    data.ads.forEach((ad) => {

        const card = createElement(
            "div",
            "admin-ad-card"
        );

        const title = createElement(
            "h4",
            "",
            ad.title
        );

        const text = createElement(
            "p",
            "",
            ad.text
        );

        const status = createElement(
            "p",
            "",
            ad.active ? "Active" : "Inactive"
        );

        const toggle = createElement(
            "button",
            "action-button",
            ad.active ? "Deactivate" : "Activate"
        );

        toggle.addEventListener("click", async () => {

            try {

                await apiRequest(
                    `/api/admin/ads/${encodeURIComponent(ad.id)}/toggle`,
                    {
                        method: "POST"
                    }
                );

                await loadAdminAds();

                await loadAdminStats();

            } catch (error) {

                alert(error.message);

            }

        });

        const deleteButton = createElement(
            "button",
            "delete-button",
            "Delete"
        );

        deleteButton.addEventListener("click", async () => {

            if (!confirm("Delete this announcement?")) {
                return;
            }

            try {

                await apiRequest(
                    `/api/admin/ads/${encodeURIComponent(ad.id)}/delete`,
                    {
                        method: "DELETE"
                    }
                );

                await loadAdminAds();

                await loadAdminStats();

            } catch (error) {

                alert(error.message);

            }

        });

        card.append(
            title,
            text,
            status,
            toggle,
            deleteButton
        );

        container.appendChild(card);

    });

}


// ============================================
// END OF FORENSIC LAB JAVASCRIPT
// ============================================
