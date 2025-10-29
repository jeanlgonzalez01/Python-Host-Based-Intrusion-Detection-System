document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const tabs = document.querySelectorAll('nav ul li a');
    const tabContents = document.querySelectorAll('.tab-content');
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');
    const logoutButton = document.getElementById('logout');

    // State variables
    let isLoggedIn = false;
    let refreshIntervals = {
        systemStats: null,
        networkInfo: null,
        filesInfo: null,
        processInfo: null,
        loginsInfo: null
    };

    // Tab click handler
    function handleTabClick(e) {
        e.preventDefault();
        const targetId = this.id.replace('-tab', '');

        // Authentication check
        if (targetId !== 'login' && !isLoggedIn) {
            alert('Please log in to access this feature.');
            return;
        }

        // Hide all tab contents
        tabContents.forEach(content => {
            content.style.display = 'none';
        });

        // Show selected tab content
        document.getElementById(targetId).style.display = 'block';

        // Clear existing intervals
        Object.values(refreshIntervals).forEach(interval => {
            if (interval) clearInterval(interval);
        });

        // Set up data refresh based on active tab
        switch(targetId) {
            case 'resources':
                updateSystemStats();
                refreshIntervals.systemStats = setInterval(updateSystemStats, 5000);
                break;
            case 'network':
                updateNetworkInfo();
                refreshIntervals.networkInfo = setInterval(updateNetworkInfo, 5000);
                break;
            case 'files':
                updateFilesView();
                refreshIntervals.filesInfo = setInterval(updateFilesView, 5000);
                break;
            case 'processes':
                updateProcessesView();
                refreshIntervals.processInfo = setInterval(updateProcessesView, 5000);
                break;
            case 'logins':
                updateLoginsView();
                refreshIntervals.loginsInfo = setInterval(updateLoginsView, 5000);
                break;
        }

        // Update active tab styling
        tabs.forEach(t => t.classList.remove('active'));
        this.classList.add('active');
    }

    // Initialize tab event listeners
    tabs.forEach(tab => tab.addEventListener('click', handleTabClick));

    // System Resources Data Fetch - Non-scrollable version
    async function updateSystemStats() {
        try {
            const [memoryRes, cpuRes, networkRes] = await Promise.all([
                fetch('http://127.0.0.1:5000/memory_stats'),
                fetch('http://127.0.0.1:5000/cpu_stats'),
                fetch('http://127.0.0.1:5000/network_information')
            ]);

            if (!memoryRes.ok || !cpuRes.ok || !networkRes.ok) {
                throw new Error('Failed to fetch system stats');
            }

            const [memoryData, cpuData, networkData] = await Promise.all([
                memoryRes.json(),
                cpuRes.json(),
                networkRes.json()
            ]);

            const resourcesContent = document.getElementById('resources');
            resourcesContent.innerHTML = `
                <h2>System Resources</h2>
                <div class="resource-grid">
                    <div class="resource-card">
                        <h3>Memory Usage</h3>
                        <p>Total: ${memoryData.total.toFixed(3)} GB</p>
                        <p>Used: ${memoryData.used.toFixed(3)} GB</p>
                        <p>Available: ${memoryData.available.toFixed(3)} GB</p>
                        <p>Percentage: ${memoryData.percentage}%</p>
                    </div>
                    <div class="resource-card">
                        <h3>CPU Usage</h3>
                        <p>CPU Usage: ${cpuData.cpu_usage}%</p>
                        <p>Thread Count: ${cpuData.thread_count}</p>
                    </div>
                    <div class="resource-card">
                        <h3>Network Information</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>Interface</th>
                                    <th>Status</th>
                                    <th>Speed</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${networkData.map(net => `
                                    <tr>
                                        <td>${net.Network}</td>
                                        <td>${net.Status}</td>
                                        <td>${net.Speed || 'N/A'}${net.Speed ? ' Mbps' : ''}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } catch (error) {
            document.getElementById('resources').innerHTML = `
                <h2>System Resources</h2>
                <p class="error">Error: ${error.message}</p>
            `;
        }
    }

    // Network Traffic Data Fetch - Scrollable version
    async function updateNetworkInfo() {
        try {
            const response = await fetch('http://127.0.0.1:5000/network_traffic');
            if (!response.ok) throw new Error('Network response failed');
            
            const networkTrafficData = await response.json();
            const tbody = document.querySelector('#network tbody');
            
            tbody.innerHTML = networkTrafficData.map(net => `
                <tr>
                    <td>${net.source_ip}</td>
                    <td>${net.destination_ip}</td>
                    <td>${net.source_port}</td>
                    <td>${net.destination_port}</td>
                    <td>${net.protocol}</td>
                    <td>${net.packet_size}</td>
                    <td>${net.timestamp}</td>
                </tr>
            `).join('') || '<tr><td colspan="7">No network traffic data available</td></tr>';
        } catch (error) {
            document.querySelector('#network tbody').innerHTML = `
                <tr>
                    <td colspan="7">Error: ${error.message}</td>
                </tr>
            `;
        }
    }

    // File Integrity Data Fetch - Scrollable version
    async function updateFilesView() {
        try {
            const response = await fetch('http://127.0.0.1:5000/file_monitor');
            if (!response.ok) throw new Error('File monitor response failed');
            
            const filesData = await response.json();
            const tbody = document.querySelector('#files tbody');
            
            tbody.innerHTML = filesData.map(file => `
                <tr>
                    <td>${file.filename || 'N/A'}</td>
                    <td>${file.file_path || 'N/A'}</td>
                    <td>${file.creation_time || 'N/A'}</td>
                    <td>${file.modification_time || 'N/A'}</td>
                    <td>${file.deletion_time || 'N/A'}</td>
                    <td>${file.hash_value ? file.hash_value.substring(0, 10) + '...' : 'N/A'}</td>
                    <td>${file.event_type || 'N/A'}</td>
                    <td>${file.event_time || 'N/A'}</td>
                    <td>${file.user || 'N/A'}</td>
                    <td>${file.role || 'N/A'}</td>
                </tr>
            `).join('') || '<tr><td colspan="10">No file integrity data available</td></tr>';
        } catch (error) {
            document.querySelector('#files tbody').innerHTML = `
                <tr>
                    <td colspan="10">Error: ${error.message}</td>
                </tr>
            `;
        }
    }

    // Process Monitoring Data Fetch - Scrollable version
    async function updateProcessesView() {
        try {
            const response = await fetch('http://127.0.0.1:5000/process_monitor');
            if (!response.ok) throw new Error('Process monitor response failed');
            
            const processesData = await response.json();
            const tbody = document.querySelector('#processes tbody');
            
            tbody.innerHTML = processesData.map(process => `
                <tr>
                    <td>${process.start_time || 'N/A'}</td>
                    <td>${process.end_time || 'N/A'}</td>
                    <td>${process.status || 'N/A'}</td>
                    <td>${process.user || 'N/A'}</td>
                    <td>${process.role || 'N/A'}</td>
                    <td>${process.executable_name || 'N/A'}</td>
                    <td>${process.executable_path || 'N/A'}</td>
                    <td>${process.cpu_usage || '0'}%</td>
                    <td>${process.ram_usage || '0'} MB</td>
                    <td>${process.thread_count || '0'}</td>
                    <td>${process.usage_level || 'Normal'}</td>
                </tr>
            `).join('') || '<tr><td colspan="11">No process data available</td></tr>';
        } catch (error) {
            document.querySelector('#processes tbody').innerHTML = `
                <tr>
                    <td colspan="11">Error: ${error.message}</td>
                </tr>
            `;
        }
    }

    // Login Monitoring Data Fetch - Scrollable version
    async function updateLoginsView() {
        try {
            const response = await fetch('http://127.0.0.1:5000/login_monitor');
            if (!response.ok) throw new Error('Login monitor response failed');
            
            const loginsData = await response.json();
            const tbody = document.querySelector('#logins tbody');
            
            tbody.innerHTML = loginsData.map(login => `
                <tr>
                    <td>${login.username || 'N/A'}</td>
                    <td>${login.login_time || 'N/A'}</td>
                    <td>${login.logout_time || 'Still active'}</td>
                    <td>${login.ip_address || 'N/A'}</td>
                    <td>${login.status || 'N/A'}</td>
                </tr>
            `).join('') || '<tr><td colspan="5">No login data available</td></tr>';
        } catch (error) {
            document.querySelector('#logins tbody').innerHTML = `
                <tr>
                    <td colspan="5">Error: ${error.message}</td>
                </tr>
            `;
        }
    }

    // Login Form Handler
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                isLoggedIn = true;
                loginError.textContent = '';
                document.getElementById('login-tab').style.display = 'none';
                logoutButton.style.display = 'inline';

                // Show network tab by default after login
                tabContents.forEach(content => content.style.display = 'none');
                document.getElementById('network').style.display = 'block';
                document.getElementById('network-tab').click();
            } else {
                throw new Error('Invalid credentials');
            }
        } catch (error) {
            loginError.textContent = error.message;
        }
    });

    // Logout Handler
    logoutButton.addEventListener('click', function(e) {
        e.preventDefault();
        isLoggedIn = false;
        
        // Reset UI to login state
        document.getElementById('login-tab').style.display = 'inline';
        logoutButton.style.display = 'none';
        tabContents.forEach(content => content.style.display = 'none');
        document.getElementById('login').style.display = 'block';
        document.getElementById('login-tab').click();
        
        // Clear all intervals
        Object.keys(refreshIntervals).forEach(key => {
            clearInterval(refreshIntervals[key]);
            refreshIntervals[key] = null;
        });
    });

    // Initialize login tab on page load
    document.getElementById('login-tab').click();
});
