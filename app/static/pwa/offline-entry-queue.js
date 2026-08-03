(() => {
    "use strict";

    const DATABASE_NAME =
        "messis-offline-entry";

    const DATABASE_VERSION = 1;

    const STORE_NAME =
        "mobile-captures";

    const MAX_FILE_BYTES =
        5 * 1024 * 1024;

    let synchronizationRunning = false;

    const form = document.querySelector(
        'form[action="/mobile/captures"]'
    );

    const fileInput =
        document.getElementById(
            "capture_file"
        );

    const expenseInput =
        document.getElementById(
            "expense_id"
        );

    const noteInput =
        document.getElementById(
            "note"
        );

    const queuePanel =
        document.getElementById(
            "offline-queue-panel"
        );

    const queueCount =
        document.getElementById(
            "offline-queue-count"
        );

    const queueStatus =
        document.getElementById(
            "offline-queue-status"
        );

    const syncButton =
        document.getElementById(
            "offline-queue-sync"
        );

    const connectionBadge =
        document.getElementById(
            "offline-connection-badge"
        );

    if (
        !form
        || !fileInput
        || !queuePanel
    ) {
        return;
    }

    function openDatabase() {
        return new Promise(
            (resolve, reject) => {
                const request =
                    indexedDB.open(
                        DATABASE_NAME,
                        DATABASE_VERSION
                    );

                request.onupgradeneeded =
                    event => {
                        const database =
                            event.target.result;

                        if (
                            !database.objectStoreNames
                                .contains(STORE_NAME)
                        ) {
                            const store =
                                database
                                    .createObjectStore(
                                        STORE_NAME,
                                        {
                                            keyPath: "id",
                                            autoIncrement: true
                                        }
                                    );

                            store.createIndex(
                                "createdAt",
                                "createdAt",
                                {
                                    unique: false
                                }
                            );
                        }
                    };

                request.onsuccess =
                    () => resolve(
                        request.result
                    );

                request.onerror =
                    () => reject(
                        request.error
                    );
            }
        );
    }

    async function databaseOperation(
        mode,
        operation
    ) {
        const database =
            await openDatabase();

        try {
            return await new Promise(
                (resolve, reject) => {
                    const transaction =
                        database.transaction(
                            STORE_NAME,
                            mode
                        );

                    const store =
                        transaction.objectStore(
                            STORE_NAME
                        );

                    const result =
                        operation(store);

                    transaction.oncomplete =
                        () => resolve(result);

                    transaction.onerror =
                        () => reject(
                            transaction.error
                        );

                    transaction.onabort =
                        () => reject(
                            transaction.error
                        );
                }
            );
        } finally {
            database.close();
        }
    }

    async function addQueueItem(item) {
        await databaseOperation(
            "readwrite",
            store => {
                store.add(item);
            }
        );
    }

    async function deleteQueueItem(id) {
        await databaseOperation(
            "readwrite",
            store => {
                store.delete(id);
            }
        );
    }

    async function getQueueItems() {
        const database =
            await openDatabase();

        try {
            return await new Promise(
                (resolve, reject) => {
                    const transaction =
                        database.transaction(
                            STORE_NAME,
                            "readonly"
                        );

                    const store =
                        transaction.objectStore(
                            STORE_NAME
                        );

                    const request =
                        store.getAll();

                    request.onsuccess =
                        () => resolve(
                            request.result || []
                        );

                    request.onerror =
                        () => reject(
                            request.error
                        );
                }
            );
        } finally {
            database.close();
        }
    }

    function setStatus(
        message,
        type = "normal"
    ) {
        queueStatus.textContent = message;

        queueStatus.dataset.statusType =
            type;
    }

    function updateConnectionStatus() {
        if (navigator.onLine) {
            connectionBadge.textContent =
                "Online";

            connectionBadge.classList.remove(
                "offline"
            );

            connectionBadge.classList.add(
                "online"
            );
        } else {
            connectionBadge.textContent =
                "Offline";

            connectionBadge.classList.remove(
                "online"
            );

            connectionBadge.classList.add(
                "offline"
            );
        }
    }

    async function refreshQueueDisplay() {
        try {
            const items =
                await getQueueItems();

            queueCount.textContent =
                String(items.length);

            queuePanel.classList.toggle(
                "has-items",
                items.length > 0
            );

            syncButton.disabled =
                items.length === 0
                || !navigator.onLine
                || synchronizationRunning;

            if (items.length === 0) {
                setStatus(
                    "No offline entries waiting."
                );
            } else if (!navigator.onLine) {
                setStatus(
                    `${items.length} receipt${
                        items.length === 1
                            ? ""
                            : "s"
                    } waiting for internet.`
                );
            } else {
                setStatus(
                    `${items.length} receipt${
                        items.length === 1
                            ? ""
                            : "s"
                    } ready to sync.`
                );
            }
        } catch (error) {
            console.error(
                "Messis queue display:",
                error
            );

            setStatus(
                "Unable to read offline queue.",
                "error"
            );
        }
    }

    function clearCaptureForm() {
        fileInput.value = "";

        if (expenseInput) {
            expenseInput.value = "";
        }

        if (noteInput) {
            noteInput.value = "";
        }

        const preview =
            document.getElementById(
                "capture-preview"
            );

        const previewImage =
            document.getElementById(
                "capture-preview-image"
            );

        preview?.classList.remove(
            "visible"
        );

        previewImage?.removeAttribute(
            "src"
        );
    }

    async function queueCurrentForm() {
        const file =
            fileInput.files?.[0];

        if (!file) {
            throw new Error(
                "Select a receipt image."
            );
        }

        if (
            ![
                "image/jpeg",
                "image/png",
                "image/webp"
            ].includes(file.type)
        ) {
            throw new Error(
                "Unsupported image format."
            );
        }

        if (file.size > MAX_FILE_BYTES) {
            throw new Error(
                "Image exceeds 5 MB."
            );
        }

        await addQueueItem({
            expenseId:
                expenseInput?.value || "",
            note:
                noteInput?.value || "",
            filename:
                file.name
                || `receipt-${Date.now()}.jpg`,
            contentType:
                file.type,
            file,
            createdAt:
                new Date().toISOString(),
            attemptCount: 0
        });

        clearCaptureForm();

        await refreshQueueDisplay();

        setStatus(
            "Receipt saved safely on this device."
        );
    }

    async function uploadQueueItem(item) {
        const formData =
            new FormData();

        formData.append(
            "expense_id",
            item.expenseId || ""
        );

        formData.append(
            "note",
            item.note || ""
        );

        formData.append(
            "capture_file",
            item.file,
            item.filename
        );

        const response = await fetch(
            "/mobile/captures",
            {
                method: "POST",
                credentials: "same-origin",
                body: formData,
                redirect: "follow"
            }
        );

        if (!response.ok) {
            throw new Error(
                `Upload failed with HTTP ${
                    response.status
                }.`
            );
        }
    }

    async function synchronizeQueue() {
        if (
            synchronizationRunning
            || !navigator.onLine
        ) {
            return;
        }

        synchronizationRunning = true;

        syncButton.disabled = true;
        syncButton.textContent =
            "Syncing…";

        try {
            const items =
                await getQueueItems();

            if (!items.length) {
                setStatus(
                    "No offline entries waiting."
                );
                return;
            }

            let completed = 0;
            let failed = 0;

            for (const item of items) {
                try {
                    await uploadQueueItem(
                        item
                    );

                    await deleteQueueItem(
                        item.id
                    );

                    completed += 1;
                } catch (error) {
                    failed += 1;

                    console.error(
                        "Messis offline upload:",
                        item.id,
                        error
                    );

                    if (!navigator.onLine) {
                        break;
                    }
                }
            }

            await refreshQueueDisplay();

            if (
                completed > 0
                && failed === 0
            ) {
                setStatus(
                    `${completed} offline receipt${
                        completed === 1
                            ? ""
                            : "s"
                    } uploaded successfully.`
                );

                window.dispatchEvent(
                    new CustomEvent(
                        "messis:offline-queue-synced",
                        {
                            detail: {
                                completed
                            }
                        }
                    )
                );
            } else if (failed > 0) {
                setStatus(
                    `${completed} uploaded; ${failed} will retry later.`,
                    "warning"
                );
            }
        } finally {
            synchronizationRunning = false;

            syncButton.textContent =
                "↻ Sync Now";

            await refreshQueueDisplay();
        }
    }

    form.addEventListener(
        "submit",
        async event => {
            if (navigator.onLine) {
                return;
            }

            event.preventDefault();

            const submitButton =
                form.querySelector(
                    'button[type="submit"]'
                );

            submitButton.disabled = true;
            submitButton.textContent =
                "Saving Offline…";

            try {
                await queueCurrentForm();

                alert(
                    "Receipt saved offline. "
                    + "It will upload automatically "
                    + "when internet returns."
                );
            } catch (error) {
                alert(
                    error.message
                    || "Unable to save offline receipt."
                );
            } finally {
                submitButton.disabled = false;
                submitButton.textContent =
                    "📤 Save Receipt";
            }
        }
    );

    syncButton.addEventListener(
        "click",
        synchronizeQueue
    );

    window.addEventListener(
        "online",
        async () => {
            updateConnectionStatus();
            await refreshQueueDisplay();
            await synchronizeQueue();
        }
    );

    window.addEventListener(
        "offline",
        async () => {
            updateConnectionStatus();
            await refreshQueueDisplay();
        }
    );

    document.addEventListener(
        "visibilitychange",
        async () => {
            if (
                !document.hidden
                && navigator.onLine
            ) {
                await synchronizeQueue();
            }
        }
    );

    updateConnectionStatus();
    refreshQueueDisplay();

    if (navigator.onLine) {
        window.setTimeout(
            synchronizeQueue,
            1500
        );
    }
})();
