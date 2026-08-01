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
