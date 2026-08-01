(() => {
    const body = document.body;

    const navigation =
        document.getElementById(
            "messis-mobile-navigation"
        );

    const moreButton =
        document.getElementById(
            "messis-mobile-more-button"
        );

    const moreSheet =
        document.getElementById(
            "messis-mobile-more-sheet"
        );

    const backdrop =
        document.getElementById(
            "messis-mobile-sheet-backdrop"
        );

    const closeButton =
        document.getElementById(
            "messis-mobile-sheet-close"
        );

    const badge =
        document.getElementById(
            "messis-mobile-notification-badge"
        );

    if (!navigation) {
        return;
    }

    body.classList.add(
        "messis-mobile-shell-enabled"
    );

    const currentPath =
        window.location.pathname;

    const routeGroups = [
        {
            key: "dashboard",
            paths: [
                "/dashboard",
                "/business-dashboard"
            ]
        },
        {
            key: "farms",
            paths: [
                "/farms"
            ]
        },
        {
            key: "harvest",
            paths: [
                "/harvests",
                "/harvest-records"
            ]
        },
        {
            key: "expenses",
            paths: [
                "/expenses"
            ]
        },
        {
            key: "sales",
            paths: [
                "/sales"
            ]
        }
    ];

    function pathMatches(
        routePath,
        candidate
    ) {
        return (
            routePath === candidate
            || routePath.startsWith(
                candidate + "/"
            )
        );
    }

    let activeKey = "";

    for (const group of routeGroups) {
        if (
            group.paths.some(
                candidate =>
                    pathMatches(
                        currentPath,
                        candidate
                    )
            )
        ) {
            activeKey = group.key;
            break;
        }
    }

    navigation
        .querySelectorAll(
            "[data-mobile-route]"
        )
        .forEach(item => {
            const key =
                item.dataset.mobileRoute;

            item.classList.toggle(
                "active",
                key === activeKey
            );
        });

    document
        .querySelectorAll(
            ".messis-mobile-more-link"
        )
        .forEach(link => {
            const routePrefix =
                link.dataset.routePrefix;

            if (!routePrefix) {
                return;
            }

            link.classList.toggle(
                "active",
                pathMatches(
                    currentPath,
                    routePrefix
                )
            );
        });

    if (
        !activeKey
        && moreButton
        && currentPath !== "/"
    ) {
        moreButton.classList.add(
            "active"
        );
    }

    function setSheetOpen(open) {
        if (
            !moreSheet
            || !backdrop
            || !moreButton
        ) {
            return;
        }

        moreSheet.classList.toggle(
            "visible",
            open
        );

        backdrop.classList.toggle(
            "visible",
            open
        );

        moreSheet.setAttribute(
            "aria-hidden",
            open ? "false" : "true"
        );

        moreButton.setAttribute(
            "aria-expanded",
            open ? "true" : "false"
        );

        body.style.overflow =
            open ? "hidden" : "";
    }

    moreButton?.addEventListener(
        "click",
        () => {
            const isOpen =
                moreSheet?.classList.contains(
                    "visible"
                );

            setSheetOpen(!isOpen);
        }
    );

    closeButton?.addEventListener(
        "click",
        () => setSheetOpen(false)
    );

    backdrop?.addEventListener(
        "click",
        () => setSheetOpen(false)
    );

    document.addEventListener(
        "keydown",
        event => {
            if (event.key === "Escape") {
                setSheetOpen(false);
            }
        }
    );

    moreSheet
        ?.querySelectorAll("a")
        .forEach(link => {
            link.addEventListener(
                "click",
                () => setSheetOpen(false)
            );
        });

    async function refreshBadge() {
        if (!badge) {
            return;
        }

        try {
            const response = await fetch(
                "/notifications/summary",
                {
                    credentials: "same-origin",
                    headers: {
                        Accept: "application/json"
                    }
                }
            );

            if (!response.ok) {
                return;
            }

            const data =
                await response.json();

            const unread = Number(
                data.unread_count || 0
            );

            badge.textContent =
                unread > 99
                    ? "99+"
                    : String(unread);

            badge.classList.toggle(
                "visible",
                unread > 0
            );
        } catch (error) {
            console.warn(
                "Messis mobile notification badge:",
                error
            );
        }
    }

    refreshBadge();

    window.addEventListener(
        "messis:notifications-refreshed",
        refreshBadge
    );

    window.setInterval(
        refreshBadge,
        60000
    );
})();

/* PATCH-AUTH-003A.3-MOBILE-PWA-LOGOUT */

(() => {
    "use strict";

    const AUTH_EVENT_KEY =
        "messis-auth-event";

    const LOGOUT_FORM_ID =
        "messis-mobile-logout-form";

    const MOBILE_LINK_CLASS =
        "messis-mobile-more-link";

    function logoutEvent() {
        return JSON.stringify({
            type: "logout",
            timestamp: Date.now()
        });
    }

    function publishLogoutEvent() {
        try {
            localStorage.setItem(
                AUTH_EVENT_KEY,
                logoutEvent()
            );
        } catch (error) {
            console.debug(
                "Messis logout synchronization "
                + "storage unavailable.",
                error
            );
        }
    }

    function redirectAfterRemoteLogout() {
        window.location.replace(
            "/?error="
            + encodeURIComponent(
                "Your Messis AI session "
                + "was closed in another tab."
            )
        );
    }

    function createLogoutForm() {
        const form =
            document.createElement("form");

        form.id = LOGOUT_FORM_ID;
        form.method = "post";
        form.action = "/logout";
        form.className =
            "messis-mobile-logout-form";

        const button =
            document.createElement("button");

        button.type = "submit";

        button.className =
            MOBILE_LINK_CLASS
            + " messis-mobile-logout-link";

        button.innerHTML = `
            <span
                class="messis-mobile-more-icon"
                aria-hidden="true"
            >
                🚪
            </span>

            <span>Logout</span>
        `;

        form.appendChild(button);

        form.addEventListener(
            "submit",
            event => {
                const confirmed =
                    window.confirm(
                        "Logout from Messis AI?\n\n"
                        + "Your secure session "
                        + "will be closed."
                    );

                if (!confirmed) {
                    event.preventDefault();
                    return;
                }

                button.disabled = true;

                button.innerHTML = `
                    <span
                        class="messis-mobile-more-icon"
                        aria-hidden="true"
                    >
                        ⏳
                    </span>

                    <span>Logging out…</span>
                `;

                publishLogoutEvent();
            }
        );

        return form;
    }

    function findMobileMoreContainer() {
        const selectors = [
            ".messis-mobile-more-links",
            ".messis-mobile-more-menu",
            ".messis-mobile-more-panel",
            ".messis-mobile-more-sheet",
            "[data-messis-mobile-more]",
            "#messis-mobile-more"
        ];

        for (const selector of selectors) {
            const element =
                document.querySelector(selector);

            if (element) {
                return element;
            }
        }

        const existingLink =
            document.querySelector(
                "." + MOBILE_LINK_CLASS
            );

        if (existingLink?.parentElement) {
            return existingLink.parentElement;
        }

        return null;
    }

    function installMobileLogout() {
        if (
            document.getElementById(
                LOGOUT_FORM_ID
            )
        ) {
            return;
        }

        const container =
            findMobileMoreContainer();

        if (!container) {
            return;
        }

        const divider =
            document.createElement("div");

        divider.className =
            "messis-mobile-logout-divider";

        container.appendChild(divider);

        container.appendChild(
            createLogoutForm()
        );
    }

    function installLogoutStyles() {
        if (
            document.getElementById(
                "messis-mobile-logout-styles"
            )
        ) {
            return;
        }

        const style =
            document.createElement("style");

        style.id =
            "messis-mobile-logout-styles";

        style.textContent = `
            .messis-mobile-logout-divider {
                height: 1px;
                margin: 8px 10px;
                background: #e2e8f0;
            }

            .messis-mobile-logout-form {
                margin: 0;
                padding: 0;
            }

            .messis-mobile-logout-link {
                width: 100%;
                color: #b91c1c !important;
                background: transparent;
                border: 0;
                cursor: pointer;
                text-align: left;
            }

            .messis-mobile-logout-link:hover,
            .messis-mobile-logout-link:focus {
                color: #991b1b !important;
                background: #fef2f2 !important;
            }

            .messis-mobile-logout-link
            .messis-mobile-more-icon {
                background: #fee2e2 !important;
            }

            .messis-mobile-logout-link:disabled {
                opacity: 0.65;
                cursor: wait;
            }
        `;

        document.head.appendChild(style);
    }

    window.addEventListener(
        "storage",
        event => {
            if (
                event.key !== AUTH_EVENT_KEY
                || !event.newValue
            ) {
                return;
            }

            try {
                const payload =
                    JSON.parse(event.newValue);

                if (
                    payload.type === "logout"
                ) {
                    redirectAfterRemoteLogout();
                }
            } catch (error) {
                console.debug(
                    "Invalid Messis auth event.",
                    error
                );
            }
        }
    );

    window.addEventListener(
        "pageshow",
        event => {
            if (event.persisted) {
                window.location.reload();
            }
        }
    );

    window.addEventListener(
        "messis:mobile-more-open",
        installMobileLogout
    );

    document.addEventListener(
        "DOMContentLoaded",
        () => {
            installLogoutStyles();
            installMobileLogout();

            window.setTimeout(
                installMobileLogout,
                500
            );

            window.setTimeout(
                installMobileLogout,
                1500
            );
        }
    );

    installLogoutStyles();

    if (
        document.readyState !== "loading"
    ) {
        installMobileLogout();
    }
})();
