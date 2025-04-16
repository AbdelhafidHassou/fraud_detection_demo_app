document.addEventListener('DOMContentLoaded', function () {
    // Initialize theme
    const themeToggle = document.getElementById('theme-toggle');
    const body = document.body;
    const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (prefersDarkMode) {
        body.classList.add('dark-mode');
        themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
    }

    themeToggle.addEventListener('click', function () {
        body.classList.toggle('dark-mode');
        if (body.classList.contains('dark-mode')) {
            themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        }
    });

    // Initialize tabs
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function () {
            // Remove active class from all tabs and content
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            // Add active class to clicked tab and corresponding content
            tab.classList.add('active');
            const tabId = tab.getAttribute('data-tab');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });

    // Initialize user info tabs
    const userInfoTabs = document.querySelectorAll('.tab-header');
    userInfoTabs.forEach(tab => {
        tab.addEventListener('click', function () {
            // Remove active class from all tabs and content
            document.querySelectorAll('.tab-header').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            // Add active class to clicked tab and corresponding content
            tab.classList.add('active');
            const tabId = tab.getAttribute('data-tab');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });

    // Initialize collapsible sections
    const collapseParams = document.getElementById('collapse-params');
    const paramsBody = document.getElementById('params-body');

    collapseParams.addEventListener('click', function () {
        paramsBody.classList.toggle('expanded');
        this.innerHTML = paramsBody.classList.contains('expanded')
            ? '<i class="fas fa-chevron-up"></i>'
            : '<i class="fas fa-chevron-down"></i>';
    });

    const collapseResults = document.getElementById('collapse-results');
    const resultsBody = document.getElementById('results-body');

    collapseResults.addEventListener('click', function () {
        resultsBody.classList.toggle('expanded');
        this.innerHTML = resultsBody.classList.contains('expanded')
            ? '<i class="fas fa-chevron-up"></i>'
            : '<i class="fas fa-chevron-down"></i>';
    });

    const collapseDatabase = document.getElementById('collapse-database');
    const databaseBody = document.getElementById('database-body');

    collapseDatabase.addEventListener('click', function () {
        databaseBody.classList.toggle('expanded');
        this.innerHTML = databaseBody.classList.contains('expanded')
            ? '<i class="fas fa-chevron-up"></i>'
            : '<i class="fas fa-chevron-down"></i>';
    });

    // Device fingerprinting
    document.getElementById('collect-fingerprint').addEventListener('click', collectFingerprint);

    // Clear results
    document.getElementById('clear-results').addEventListener('click', function () {
        document.getElementById('results-container').style.display = 'none';
        document.getElementById('initial-message').style.display = 'block';
    });

    // Session events
    const addEventButton = document.getElementById('add-event');
    const eventList = document.getElementById('event-list');
    const eventType = document.getElementById('event-type');
    const eventTimestamp = document.getElementById('event-timestamp');
    const clearEventsButton = document.getElementById('clear-events');

    let events = [];

    addEventButton.addEventListener('click', function () {
        const type = eventType.value;
        let timestamp = eventTimestamp.value;

        if (!timestamp) {
            timestamp = Math.floor(Date.now() / 1000);
        } else {
            timestamp = parseInt(timestamp);
        }

        events.push({
            type,
            timestamp
        });

        updateEventList();
        eventTimestamp.value = '';
    });

    clearEventsButton.addEventListener('click', function () {
        events = [];
        updateEventList();
    });

    function updateEventList() {
        eventList.innerHTML = '';

        events.forEach((event, index) => {
            const date = new Date(event.timestamp * 1000);
            const formattedDate = date.toLocaleString();

            const eventItem = document.createElement('div');
            eventItem.className = 'event-item';
            eventItem.innerHTML = `
                <div>${event.type} - ${formattedDate}</div>
                <div class="event-item-actions">
                    <button class="btn-icon btn-delete" data-index="${index}" title="Remove event">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `;
            eventList.appendChild(eventItem);
        });

        // Add event listeners to delete buttons
        document.querySelectorAll('.btn-delete').forEach(button => {
            button.addEventListener('click', function () {
                const index = parseInt(this.getAttribute('data-index'));
                events.splice(index, 1);
                updateEventList();
            });
        });
    }

    // Test buttons
    document.getElementById('test-all').addEventListener('click', testAllPredictors);
    document.getElementById('test-selected-user').addEventListener('click', testSelectedUser);

    // Database functions
    const refreshStatsButton = document.getElementById('refresh-stats');
    const generateDatabaseButton = document.getElementById('generate-database');
    const userSelect = document.getElementById('user-select');
    const useDbEventsButton = document.getElementById('use-db-events');
    const useDbFingerprintButton = document.getElementById('use-db-fingerprint');

    // Initialize database stats
    refreshDatabaseStats();

    refreshStatsButton.addEventListener('click', refreshDatabaseStats);
    generateDatabaseButton.addEventListener('click', generateDatabase);
    userSelect.addEventListener('change', loadUserData);
    useDbEventsButton.addEventListener('click', useSessionFromDatabase);
    useDbFingerprintButton.addEventListener('click', useDeviceFromDatabase);

    // Update refreshDatabaseStats function
    function refreshDatabaseStats() {
        const loadingOverlay = document.getElementById('loading-overlay');
        loadingOverlay.classList.add('active');

        fetch('/api/database-stats')
            .then(response => {
                if (!response.ok) {
                    // Check the content type to provide better error messages
                    const contentType = response.headers.get('content-type');
                    if (contentType && contentType.includes('text/html')) {
                        return response.text().then(html => {
                            console.error('Server returned HTML instead of JSON:', html.substring(0, 100) + '...');
                            throw new Error('Server error: The API returned HTML instead of JSON. The server might be unreachable or the route might not exist.');
                        });
                    }
                    throw new Error(`HTTP error: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.stats) {
                    document.getElementById('stat-users').textContent = data.stats.users;
                    document.getElementById('stat-devices').textContent = data.stats.devices;
                    document.getElementById('stat-logins').textContent = data.stats.logins;
                    document.getElementById('stat-failed-logins').textContent = data.stats.failed_logins;
                    document.getElementById('stat-ip-data').textContent = data.stats.ip_data;
                    document.getElementById('stat-sessions').textContent = data.stats.sessions;
                }

                // Populate user dropdown
                populateUserDropdown();
            })
            .catch(error => {
                console.error('Error fetching database stats:', error);
                alert('Error fetching database stats: ' + error.message);
            })
            .finally(() => {
                loadingOverlay.classList.remove('active');
            });
    }

    // Similarly update generateDatabase function
    function generateDatabase() {
        const loadingOverlay = document.getElementById('loading-overlay');
        loadingOverlay.classList.add('active');

        fetch('/api/generate-database', {
            method: 'POST'
        })
            .then(response => {
                if (!response.ok) {
                    // Check the content type to provide better error messages
                    const contentType = response.headers.get('content-type');
                    if (contentType && contentType.includes('text/html')) {
                        return response.text().then(html => {
                            console.error('Server returned HTML instead of JSON:', html.substring(0, 100) + '...');
                            throw new Error('Server error: The API returned HTML instead of JSON. The server might be unreachable or the route might not exist.');
                        });
                    }
                    throw new Error(`HTTP error: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                alert('Database generated successfully!');
                refreshDatabaseStats();
            })
            .catch(error => {
                console.error('Error generating database:', error);
                alert('Error generating database: ' + error.message);
            })
            .finally(() => {
                loadingOverlay.classList.remove('active');
            });
    }

    function populateUserDropdown() {
        // In a real implementation, you would fetch users from the database
        // For this example, we'll generate user IDs based on the stats
        const userCount = parseInt(document.getElementById('stat-users').textContent) || 0;

        // Clear dropdown except for the placeholder
        userSelect.innerHTML = '<option value="">-- Select a user --</option>';

        // Add users to dropdown
        for (let i = 1; i <= userCount; i++) {
            const userId = `user${String(i).padStart(3, '0')}`;
            const option = document.createElement('option');
            option.value = userId;
            option.textContent = userId;
            userSelect.appendChild(option);
        }
    }

    function loadUserData() {
        const userId = userSelect.value;

        if (!userId) {
            document.getElementById('user-info').style.display = 'none';
            return;
        }

        const loadingOverlay = document.getElementById('loading-overlay');
        loadingOverlay.classList.add('active');

        fetch(`/api/user/${userId}`)
            .then(response => response.json())
            .then(data => {
                // Populate user fields
                document.getElementById('user-id').value = userId;
                document.getElementById('email').value = data.user.email || '';

                // Update user info section
                document.getElementById('info-user-id').textContent = userId;
                document.getElementById('info-email').textContent = data.user.email || 'N/A';
                document.getElementById('info-created').textContent = new Date(data.user.created_at * 1000).toLocaleString();
                document.getElementById('info-devices').textContent = data.devices.length;

                // Last login info
                if (data.user.last_login) {
                    const lastLogin = data.user.last_login;
                    document.getElementById('info-last-login').textContent =
                        new Date(lastLogin.timestamp * 1000).toLocaleString();
                    document.getElementById('info-last-ip').textContent = lastLogin.ip || 'N/A';

                    const location = lastLogin.location || {};
                    document.getElementById('info-last-location').textContent =
                        `${location.city || ''}, ${location.country || 'Unknown'}`;

                    // Set the IP address field
                    document.getElementById('ip-address').value = lastLogin.ip || '';
                } else {
                    document.getElementById('info-last-login').textContent = 'Never';
                    document.getElementById('info-last-ip').textContent = 'N/A';
                    document.getElementById('info-last-location').textContent = 'N/A';
                }

                // Populate login history
                const loginHistoryContainer = document.getElementById('login-history');
                loginHistoryContainer.innerHTML = '';

                if (data.logins && data.logins.length > 0) {
                    data.logins.forEach(login => {
                        const loginItem = document.createElement('div');
                        loginItem.className = 'login-item';

                        const date = new Date(login.timestamp * 1000);
                        const location = login.location || {};

                        loginItem.innerHTML = `
                            <div><strong>${date.toLocaleString()}</strong></div>
                            <div>IP: ${login.ip || 'Unknown'}</div>
                            <div>Location: ${location.city || ''}, ${location.country || 'Unknown'}</div>
                        `;

                        loginHistoryContainer.appendChild(loginItem);
                    });
                } else {
                    loginHistoryContainer.innerHTML = '<p>No login history available</p>';
                }

                // Populate devices
                const devicesContainer = document.getElementById('user-devices-list');
                devicesContainer.innerHTML = '';

                if (data.devices && data.devices.length > 0) {
                    data.devices.forEach(device => {
                        const deviceItem = document.createElement('div');
                        deviceItem.className = 'login-item';

                        const firstSeen = new Date(device.first_seen * 1000);
                        const lastSeen = new Date(device.last_seen * 1000);

                        deviceItem.innerHTML = `
                            <div><strong>Device ID:</strong> ${device.device_id}</div>
                            <div><strong>First seen:</strong> ${firstSeen.toLocaleString()}</div>
                            <div><strong>Last seen:</strong> ${lastSeen.toLocaleString()}</div>
                            <div><strong>Visit count:</strong> ${device.visit_count || 0}</div>
                            <div class="mt-2">
                                <button class="btn btn-sm btn-outline use-device" data-device-id="${device.device_id}">
                                    Use This Device
                                </button>
                            </div>
                        `;

                        devicesContainer.appendChild(deviceItem);
                    });
                } else {
                    devicesContainer.innerHTML = '<p>No devices available</p>';
                }

                // Populate sessions
                const sessionsContainer = document.getElementById('session-events');
                sessionsContainer.innerHTML = '';

                if (data.sessions && data.sessions.length > 0) {
                    data.sessions.forEach((session, index) => {
                        const sessionDiv = document.createElement('div');
                        sessionDiv.className = 'login-item';

                        // Sort events by timestamp
                        session.sort((a, b) => a.timestamp - b.timestamp);

                        const startTime = new Date(session[0].timestamp * 1000);
                        const endTime = new Date(session[session.length - 1].timestamp * 1000);

                        let eventsHtml = '';
                        session.forEach(event => {
                            const eventTime = new Date(event.timestamp * 1000);
                            eventsHtml += `<div>${event.type} - ${eventTime.toLocaleTimeString()}</div>`;
                        });

                        sessionDiv.innerHTML = `
                            <div><strong>Session ${index + 1}</strong> - ${startTime.toLocaleString()} to ${endTime.toLocaleString()}</div>
                            <div><strong>Events:</strong> ${session.length}</div>
                            <div>${eventsHtml}</div>
                            <div class="mt-2">
                                <button class="btn btn-sm btn-outline use-session" data-session-id="${index}">
                                    Use This Session
                                </button>
                            </div>
                        `;

                        sessionsContainer.appendChild(sessionDiv);
                    });
                } else {
                    sessionsContainer.innerHTML = '<p>No session data available</p>';
                }

                // Store data for later use
                window.userData = data;

                // Show user info section
                document.getElementById('user-info').style.display = 'block';

                // Add event listeners to device and session buttons
                document.querySelectorAll('.use-device').forEach(button => {
                    button.addEventListener('click', function () {
                        const deviceId = this.getAttribute('data-device-id');
                        useDeviceById(deviceId);
                    });
                });

                document.querySelectorAll('.use-session').forEach(button => {
                    button.addEventListener('click', function () {
                        const sessionIndex = this.getAttribute('data-session-id');
                        useSessionByIndex(parseInt(sessionIndex));
                    });
                });
            })
            .catch(error => {
                console.error('Error loading user data:', error);
                alert('Error loading user data: ' + error.message);
            })
            .finally(() => {
                loadingOverlay.classList.remove('active');
            });
    }

    function useDeviceById(deviceId) {
        if (!window.userData || !window.userData.devices) {
            alert('No user data loaded');
            return;
        }

        const device = window.userData.devices.find(d => d.device_id === deviceId);
        if (!device || !device.fingerprints || device.fingerprints.length === 0) {
            alert('No fingerprint data available for this device');
            return;
        }

        // Use the most recent fingerprint
        const fingerprint = device.fingerprints[device.fingerprints.length - 1];
        document.getElementById('fingerprint-data').value = JSON.stringify(fingerprint, null, 2);

        alert('Device fingerprint loaded!');
    }

    function useSessionByIndex(sessionIndex) {
        if (!window.userData || !window.userData.sessions || sessionIndex >= window.userData.sessions.length) {
            alert('Invalid session data');
            return;
        }

        // Get the session events and format them for our system
        const sessionEvents = window.userData.sessions[sessionIndex];
        events = sessionEvents.map(event => ({
            type: event.type,
            timestamp: event.timestamp
        }));

        // Update the UI
        updateEventList();

        alert('Session events loaded!');
    }

    function useDeviceFromDatabase() {
        const userId = document.getElementById('user-id').value;

        if (!userId) {
            alert('Please enter or select a User ID first');
            return;
        }

        if (!window.userData) {
            alert('Please load user data first by selecting a user from the dropdown');
            return;
        }

        if (!window.userData.devices || window.userData.devices.length === 0) {
            alert('No devices available for this user');
            return;
        }

        // Use the first device's most recent fingerprint
        const device = window.userData.devices[0];
        if (!device.fingerprints || device.fingerprints.length === 0) {
            alert('No fingerprint data available for this device');
            return;
        }

        const fingerprint = device.fingerprints[device.fingerprints.length - 1];
        document.getElementById('fingerprint-data').value = JSON.stringify(fingerprint, null, 2);

        alert('Device fingerprint loaded!');
    }

    function useSessionFromDatabase() {
        const userId = document.getElementById('user-id').value;

        if (!userId) {
            alert('Please enter or select a User ID first');
            return;
        }

        if (!window.userData) {
            alert('Please load user data first by selecting a user from the dropdown');
            return;
        }

        if (!window.userData.sessions || window.userData.sessions.length === 0) {
            alert('No sessions available for this user');
            return;
        }

        // Use the first session's events
        const sessionEvents = window.userData.sessions[0];
        events = sessionEvents.map(event => ({
            type: event.type,
            timestamp: event.timestamp
        }));

        // Update the UI
        updateEventList();

        alert('Session events loaded!');
    }

    async function collectFingerprint() {
        // Clear manual input
        document.getElementById('manual-fingerprint-data').value = '';

        // Hide import section
        document.getElementById('import-fingerprint-section').style.display = 'none';

        // Collect browser fingerprint
        const fingerprinter = new DeviceFingerprinter();
        const fingerprintData = await fingerprinter.collectAll();

        document.getElementById('fingerprint-data').value = JSON.stringify(fingerprintData, null, 2);
    }

    async function testAllPredictors() {
        // Show loading overlay
        const loadingOverlay = document.getElementById('loading-overlay');
        loadingOverlay.classList.add('active');

        try {
            const userId = document.getElementById('user-id').value;
            const ipAddress = document.getElementById('ip-address').value;
            const email = document.getElementById('email').value;
            const userAgent = document.getElementById('user-agent').value || navigator.userAgent;
            const fingerprintData = document.getElementById('fingerprint-data').value;
            const timestampInput = document.getElementById('timestamp').value;

            // Validate inputs
            if (!userId) {
                alert('Please enter a User ID');
                return;
            }

            if (!ipAddress) {
                alert('Please enter an IP address');
                return;
            }

            // Build request data
            const requestData = {
                user_id: userId,
                ip_address: ipAddress,
                email: email,
                user_agent: userAgent,
                timestamp: timestampInput ? parseInt(timestampInput) : Math.floor(Date.now() / 1000),
                session_events: events
            };

            // Add device fingerprint if available
            if (fingerprintData.trim()) {
                try {
                    requestData.device_fingerprint = JSON.parse(fingerprintData);
                } catch (e) {
                    alert('Error parsing fingerprint data: ' + e.message);
                    return;
                }
            }

            // Send request
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData)
            });

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

            const result = await response.json();
            displayResults(result);
        } catch (e) {
            alert('Error testing predictors: ' + e.message);
        } finally {
            // Hide loading overlay
            loadingOverlay.classList.remove('active');
        }
    }

    async function testSelectedUser() {
        const userId = document.getElementById('user-id').value;

        if (!userId) {
            alert('Please enter or select a User ID');
            return;
        }

        // Show loading overlay
        const loadingOverlay = document.getElementById('loading-overlay');
        loadingOverlay.classList.add('active');

        try {
            // Send request to analyze the selected user
            const ipAddress = document.getElementById('ip-address').value;

            const requestData = {
                ip_address: ipAddress || ''
            };

            const response = await fetch(`/api/analyze/${userId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData)
            });

            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }

            const result = await response.json();
            displayResults(result);
        } catch (e) {
            alert('Error analyzing user: ' + e.message);
        } finally {
            // Hide loading overlay
            loadingOverlay.classList.remove('active');
        }
    }

    function displayResults(result) {
        // Hide initial message and show results
        document.getElementById('initial-message').style.display = 'none';
        document.getElementById('results-container').style.display = 'block';

        // Update overall score and risk level
        const overallScore = document.getElementById('overall-score');
        const riskLevel = document.getElementById('risk-level');
        const recommendation = document.getElementById('recommendation');
        const riskScoreContainer = document.getElementById('risk-score-container');

        overallScore.textContent = result.overall_risk;
        riskLevel.textContent = result.risk_level.toUpperCase();
        recommendation.textContent = result.recommendation.toUpperCase();

        // Update container class based on risk level
        riskScoreContainer.className = 'risk-score-container';
        riskScoreContainer.classList.add(`risk-${result.risk_level}`);

        // Build predictor cards
        const predictorGrid = document.getElementById('predictor-grid');
        predictorGrid.innerHTML = '';

        for (const [predictorName, predictorResult] of Object.entries(result.predictors)) {
            // Format display name
            const displayName = predictorName.replace(/_/g, ' ')
                .split(' ')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');

            // Determine risk class
            const riskScore = predictorResult.risk_score || 0;
            let scoreClass = 'score-low';
            if (riskScore >= 75) scoreClass = 'score-critical';
            else if (riskScore >= 50) scoreClass = 'score-high';
            else if (riskScore >= 25) scoreClass = 'score-medium';

            // Create predictor card
            const card = document.createElement('div');
            card.className = 'predictor-card';
            card.dataset.predictor = predictorName;

            card.innerHTML = `
                <div class="predictor-card-header">${displayName}</div>
                <div class="predictor-card-body">
                    <div class="predictor-score ${scoreClass}">${riskScore}</div>
                    <div class="predictor-status">${predictorResult.status || 'N/A'}</div>
                </div>
            `;

            predictorGrid.appendChild(card);

            // Add click handler to show details
            card.addEventListener('click', function () {
                // Switch to details tab
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

                document.querySelector('.tab[data-tab="details"]').classList.add('active');
                document.getElementById('details-tab').classList.add('active');

                // Scroll to the specific predictor's details
                const detailSection = document.getElementById(`${predictorName}-details`);
                if (detailSection) {
                    detailSection.scrollIntoView({ behavior: 'smooth' });
                }
            });
        }

        // Build detailed results
        const detailedResults = document.getElementById('detailed-results');
        detailedResults.innerHTML = '';

        for (const [predictorName, predictorResult] of Object.entries(result.predictors)) {
            const section = document.createElement('div');
            section.className = 'details-section';
            section.id = `${predictorName}-details`;

            const displayName = predictorName.replace(/_/g, ' ')
                .split(' ')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');

            let detailsHTML = '';

            // Handle different details formats based on predictor type
            if (predictorName === 'user_agent') {
                detailsHTML = buildUserAgentDetails(predictorResult);
            } else if (predictorName === 'geo_velocity') {
                detailsHTML = buildGeoVelocityDetails(predictorResult);
            } else if (predictorName === 'ip_reputation') {
                detailsHTML = buildIpReputationDetails(predictorResult);
            } else if (predictorName === 'device') {
                detailsHTML = buildDeviceDetails(predictorResult);
            } else if (predictorName === 'session') {
                detailsHTML = buildSessionDetails(predictorResult);
            } else {
                // Generic detail builder
                detailsHTML = '<ul class="details-list">';
                for (const [key, value] of Object.entries(predictorResult)) {
                    if (key !== 'risk_score' && key !== 'status' && typeof value !== 'object') {
                        detailsHTML += `<li><strong>${formatKey(key)}:</strong> ${value}</li>`;
                    }
                }
                detailsHTML += '</ul>';
            }

            section.innerHTML = `
                <h3>${displayName}</h3>
                <div class="details-info">
                    <p><strong>Risk Score:</strong> ${predictorResult.risk_score || 0}</p>
                    <p><strong>Status:</strong> ${predictorResult.status || 'N/A'}</p>
                    ${predictorResult.message ? `<p><strong>Message:</strong> ${predictorResult.message}</p>` : ''}
                </div>
                <div class="details-content">
                    ${detailsHTML}
                </div>
            `;

            detailedResults.appendChild(section);
        }

        // Update raw response
        document.getElementById('raw-results').textContent = JSON.stringify(result, null, 2);
    }

    function formatKey(key) {
        return key.replace(/_/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    function buildUserAgentDetails(result) {
        const browser = result.browser || {};
        const os = result.os || {};

        return `
            <div class="details-content">
                <h4>Browser Information</h4>
                <ul class="details-list">
                    <li><strong>Family:</strong> ${browser.family || 'Unknown'}</li>
                    <li><strong>Version:</strong> ${browser.version || 'Unknown'}</li>
                </ul>
                
                <h4>Operating System</h4>
                <ul class="details-list">
                    <li><strong>Family:</strong> ${os.family || 'Unknown'}</li>
                    <li><strong>Version:</strong> ${os.version || 'Unknown'}</li>
                </ul>
                
                <h4>Device Information</h4>
                <ul class="details-list">
                    <li><strong>Device:</strong> ${result.device || 'Unknown'}</li>
                    <li><strong>Is Mobile:</strong> ${result.is_mobile ? 'Yes' : 'No'}</li>
                    <li><strong>Is Tablet:</strong> ${result.is_tablet ? 'Yes' : 'No'}</li>
                    <li><strong>Is PC:</strong> ${result.is_pc ? 'Yes' : 'No'}</li>
                    <li><strong>Is Bot:</strong> ${result.is_bot ? 'Yes' : 'No'}</li>
                </ul>
                
                <h4>Detected Issues</h4>
                ${result.issues && result.issues.length > 0
                ? `<ul class="details-list">${result.issues.map(issue => `<li>${formatKey(issue)}</li>`).join('')}</ul>`
                : '<p>No issues detected</p>'
            }
            </div>
        `;
    }

    function buildGeoVelocityDetails(result) {
        const prevLogin = result.previous_login || {};
        const currLogin = result.current_login || {};

        return `
            <div class="details-content">
                <h4>Travel Information</h4>
                <ul class="details-list">
                    <li><strong>Travel Speed:</strong> ${result.travel_speed_kmh || 0} km/h</li>
                    <li><strong>Distance:</strong> ${result.distance_km || 0} km</li>
                    <li><strong>Time Difference:</strong> ${result.time_difference_hours || 0} hours</li>
                </ul>
                
                ${prevLogin.location ? `
                <h4>Previous Login</h4>
                <ul class="details-list">
                    <li><strong>IP Address:</strong> ${prevLogin.ip || 'Unknown'}</li>
                    <li><strong>Timestamp:</strong> ${prevLogin.timestamp || 'Unknown'}</li>
                    <li><strong>Location:</strong> ${prevLogin.location ? `${prevLogin.location.city || 'Unknown'}, ${prevLogin.location.country || 'Unknown'}` : 'Unknown'}</li>
                    <li><strong>Coordinates:</strong> ${prevLogin.location ? `${prevLogin.location.latitude || 0}, ${prevLogin.location.longitude || 0}` : 'Unknown'}</li>
                </ul>
                ` : ''}
                
                ${currLogin.location ? `
                <h4>Current Login</h4>
                <ul class="details-list">
                    <li><strong>IP Address:</strong> ${currLogin.ip || 'Unknown'}</li>
                    <li><strong>Timestamp:</strong> ${currLogin.timestamp || 'Unknown'}</li>
                    <li><strong>Location:</strong> ${currLogin.location ? `${currLogin.location.city || 'Unknown'}, ${currLogin.location.country || 'Unknown'}` : 'Unknown'}</li>
                    <li><strong>Coordinates:</strong> ${currLogin.location ? `${currLogin.location.latitude || 0}, ${currLogin.location.longitude || 0}` : 'Unknown'}</li>
                </ul>
                ` : ''}
            </div>
        `;
    }

    function buildIpReputationDetails(result) {
        return `
            <div class="details-content">
                <h4>IP Reputation Flags</h4>
                <ul class="details-list">
                    <li><strong>Is Proxy:</strong> ${result.is_proxy ? 'Yes' : 'No'}</li>
                    <li><strong>Is Tor:</strong> ${result.is_tor ? 'Yes' : 'No'}</li>
                    <li><strong>Is Datacenter:</strong> ${result.is_datacenter ? 'Yes' : 'No'}</li>
                    <li><strong>Is VPN:</strong> ${result.is_vpn ? 'Yes' : 'No'}</li>
                    <li><strong>Is Known Abuser:</strong> ${result.is_known_abuser ? 'Yes' : 'No'}</li>
                </ul>
                
                <h4>Statistics</h4>
                <ul class="details-list">
                    <li><strong>Failed Logins:</strong> ${result.failed_logins || 0}</li>
                    <li><strong>Countries Count:</strong> ${result.countries_count || 0}</li>
                    <li><strong>Raw Score:</strong> ${result.raw_score || 0}</li>
                </ul>
                
                ${result.location ? `
                <h4>Location Information</h4>
                <ul class="details-list">
                    <li><strong>Country:</strong> ${result.location.country || 'Unknown'}</li>
                    <li><strong>City:</strong> ${result.location.city || 'Unknown'}</li>
                    <li><strong>Coordinates:</strong> ${result.location.latitude || 0}, ${result.location.longitude || 0}</li>
                </ul>
                ` : ''}
            </div>
        `;
    }

    function buildDeviceDetails(result) {
        return `
            <div class="details-content">
                <h4>Device Information</h4>
                <ul class="details-list">
                    <li><strong>Device ID:</strong> ${result.device_id || 'Unknown'}</li>
                    <li><strong>Is Known Device:</strong> ${result.is_known_device ? 'Yes' : 'No'}</li>
                    <li><strong>Confidence Score:</strong> ${result.confidence_score || 0}</li>
                </ul>
                
                <h4>Detected Issues</h4>
                ${result.issues && result.issues.length > 0
                ? `<ul class="details-list">${result.issues.map(issue => `<li>${formatKey(issue)}</li>`).join('')}</ul>`
                : '<p>No issues detected</p>'
            }
                
                ${result.device_history ? `
                <h4>Device History</h4>
                <ul class="details-list">
                    <li><strong>First Seen:</strong> ${formatTimestamp(result.device_history.first_seen)}</li>
                    <li><strong>Last Seen:</strong> ${formatTimestamp(result.device_history.last_seen)}</li>
                    <li><strong>Visit Count:</strong> ${result.device_history.visit_count || 0}</li>
                </ul>
                ` : ''}
            </div>
        `;
    }

    function buildSessionDetails(result) {
        const anomalies = result.anomalies || {};

        return `
            <div class="details-content">
                <h4>Session Information</h4>
                <ul class="details-list">
                    <li><strong>Anomaly Score:</strong> ${result.anomaly_score || 0}</li>
                    <li><strong>Events Analyzed:</strong> ${result.events_analyzed || 0}</li>
                </ul>
                
                ${anomalies.timing ? `
                <h4>Timing Anomalies</h4>
                <ul class="details-list">
                    ${anomalies.timing.details.map(detail => `
                        <li><strong>${formatKey(detail.type)}:</strong> 
                            ${detail.type === 'too_fast' ? `Time between events: ${detail.time_diff}s (threshold: ${detail.threshold}s)` :
                detail.type === 'long_gap' ? `Gap between events: ${detail.time_diff}s (threshold: ${detail.threshold}s)` :
                    detail.type === 'long_session' ? `Session length: ${detail.session_length}s (threshold: ${detail.threshold}s)` :
                        JSON.stringify(detail)}
                        </li>
                    `).join('')}
                </ul>
                ` : ''}
                
                ${anomalies.sequence ? `
                <h4>Sequence Anomalies</h4>
                <ul class="details-list">
                    ${anomalies.sequence.details.map(detail => `
                        <li><strong>${formatKey(detail.type)}:</strong> 
                            ${detail.type === 'unlikely_transition' ? `From "${detail.from}" to "${detail.to}" (probability: ${detail.probability})` :
                                detail.type === 'unknown_transition' ? `From "${detail.from}" to "${detail.to}" (not in model)` :
                                    detail.type === 'repeated_action' ? `Action "${detail.action}" repeated ${detail.count} times` :
                                        detail.type === 'cyclic_pattern' ? `Cyclic pattern detected: ${detail.actions.join(' → ')}` :
                                            detail.type === 'rapid_navigation' ? `Rapid navigation through ${detail.unique_actions} unique actions` :
                                                JSON.stringify(detail)}
                        </li>
                    `).join('')}
                </ul>
                ` : ''}
                
                ${anomalies.activities ? `
                <h4>Activity Anomalies</h4>
                <ul class="details-list">
                    ${anomalies.activities.details.map(detail => `
                        <li><strong>${formatKey(detail.type)}:</strong> 
                            ${detail.type === 'suspicious_activity' ? `Suspicious activity "${detail.activity}" (risk level: ${detail.risk_level})` :
                                                        detail.type === 'multiple_suspicious' ? `Multiple suspicious activities (${detail.count} activities, total risk: ${detail.total_risk})` :
                                                            JSON.stringify(detail)}
                        </li>
                    `).join('')}
                </ul>
                ` : ''}
            </div>
        `;
    }

    function formatTimestamp(timestamp) {
        if (!timestamp) return 'Unknown';

        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    }

    // Fingerprint import toggle
    const importFingerprintBtn = document.getElementById('import-fingerprint');
    const importFingerprintSection = document.getElementById('import-fingerprint-section');
    const manualFingerprintInput = document.getElementById('manual-fingerprint-data');
    const fingerprintDataDisplay = document.getElementById('fingerprint-data');

    importFingerprintBtn.addEventListener('click', function () {
        importFingerprintSection.style.display =
            importFingerprintSection.style.display === 'none' ? 'block' : 'none';
    });

    manualFingerprintInput.addEventListener('input', function () {
        try {
            // Validate JSON
            const parsedFingerprint = JSON.parse(this.value);

            // Optional: Add some basic validation
            if (!parsedFingerprint || typeof parsedFingerprint !== 'object') {
                throw new Error('Invalid fingerprint format');
            }

            // Display and set the fingerprint
            fingerprintDataDisplay.value = JSON.stringify(parsedFingerprint, null, 2);
        } catch (error) {
            // Handle invalid JSON
            fingerprintDataDisplay.value = 'Invalid JSON: ' + error.message;
        }
    });
});