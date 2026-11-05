// ============================================
// FORENSIC LAB - MAIN JAVASCRIPT
// ============================================

import {
    auth,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signOut,
    onAuthStateChanged,
    updateProfile
} from "./firebase-config.js";

// --------------------------------------------
// GLOBAL HELPERS
// --------------------------------------------

const $ = (id) => document.getElementById(id);

// ADMIN UID
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
        throw new Error(data.error || "Request failed.");
    }

    return data;
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

// --------------------------------------------
// PAGE RELOAD DETECTION
// --------------------------------------------

const navigationEntry =
    performance.getEntriesByType("navigation")[0];

const isPageReload =
    navigationEntry?.type === "reload";

// --------------------------------------------
// AUTHENTICATION
// --------------------------------------------

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

// --------------------------------------------
// LOGIN / REGISTER SWITCHING
// --------------------------------------------

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

// --------------------------------------------
// LOGOUT SYSTEM
// --------------------------------------------

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

// --------------------------------------------
// AUTH STATE AND PAGE PROTECTION
// --------------------------------------------

onAuthStateChanged(auth, async (user) => {

    const currentPath = window.location.pathname;

    const protectedPages = [
        "/dashboard",
        "/analyze",
        "/admin"
    ];

    // ----------------------------------------
    // ADMIN REFRESH LOGOUT
    // ----------------------------------------

    // Admin pekee anatolewa akifanya Refresh.
    // Users wengine hawataguswa.

    if (
        user &&
        user.uid === ADMIN_UID &&
        isPageReload
    ) {

        try {
            await signOut(auth);

        } catch (error) {
            console.error(
                "Admin refresh logout error:",
                error
            );
        }

        window.location.replace("/auth");

        return;
    }

    // ----------------------------------------
    // USER NOT LOGGED IN
    // ----------------------------------------

    if (!user) {

        if (protectedPages.includes(currentPath)) {
            window.location.replace("/auth");
        }

        return;
    }

    // ----------------------------------------
    // USER LOGGED IN
    // ----------------------------------------

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

// --------------------------------------------
// DASHBOARD
// --------------------------------------------

async function loadDashboard() {

    const userName = $("user-name");

    if (userName && auth.currentUser) {

        userName.textContent =
            auth.currentUser.displayName ||
            auth.currentUser.email;
    }

    loadAds();

    loadHistory();
}

// --------------------------------------------
// LOAD ADVERTISEMENTS
// --------------------------------------------

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

            const card = createElement(
                "div",
                "ad-card"
            );

            const title = createElement(
                "h3",
                "",
                ad.title
            );

            const text = createElement(
                "p",
                "",
                ad.text
            );

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

// --------------------------------------------
// ANALYSIS HISTORY
// --------------------------------------------

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
                    item.filename
                ),

                createElement(
                    "p",
                    "",
                    `SHA-256: ${item.sha256}`
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

// --------------------------------------------
// FILE ANALYSIS
// --------------------------------------------

const analysisForm = $("analysis-form");

if (analysisForm) {

    analysisForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        const fileInput = $("analysis-file");

        const resultBox = $("analysis-result");

        if (!fileInput || !fileInput.files.length) {

            showMessage(
                "Select a file first.",
                "error"
            );

            return;
        }

        const file = fileInput.files[0];

        const formData = new FormData();

        formData.append("file", file);

        resultBox.textContent = "Analyzing file...";

        try {

            const data = await apiRequest(
                "/api/analyze",
                {
                    method: "POST",
                    body: formData
                }
            );

            resultBox.replaceChildren();

            const heading = createElement(
                "h3",
                "",
                "Analysis completed"
            );

            const details = [
                `Filename: ${data.filename}`,
                `File size: ${data.size} bytes`,
                `SHA-256: ${data.sha256}`,
                `Analysis: ${data.message}`
            ];

            resultBox.appendChild(heading);

            details.forEach((detail) => {

                resultBox.appendChild(
                    createElement("p", "", detail)
                );
            });

            resultBox.appendChild(
                createElement(
                    "small",
                    "",
                    "A matching SHA-256 hash indicates matching file contents. It does not prove authenticity."
                )
            );

            loadHistory();

        } catch (error) {

            resultBox.textContent = error.message;
        }
    });
}

// --------------------------------------------
// ADMIN PANEL
// --------------------------------------------

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

// --------------------------------------------
// ADMIN STATISTICS
// --------------------------------------------

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

// --------------------------------------------
// ADMIN USERS
// --------------------------------------------

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

// --------------------------------------------
// CREATE ADVERTISEMENT
// --------------------------------------------

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

            loadAdminAds();

            loadAdminStats();

        } catch (error) {

            showMessage(
                error.message,
                "error"
            );
        }
    });
}

// --------------------------------------------
// LOAD ADMIN ADVERTISEMENTS
// --------------------------------------------

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

        // ACTIVATE / DEACTIVATE

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

        // DELETE ADVERTISEMENT

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
