// Helpers
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatSpeed(bytesPerSec) {
    return formatBytes(bytesPerSec) + '/s';
}

function formatTime(isoString) {
    if (!isoString || isoString.startsWith('0001')) return '-';
    return new Date(isoString).toLocaleTimeString();
}

function formatDuration(seconds) {
    if (!seconds) return '0s';
    if (seconds < 60) return seconds + 's';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (mins < 60) return `${mins}m ${secs}s`;
    const hrs = Math.floor(mins / 60);
    const m = mins % 60;
    return `${hrs}h ${m}m`;
}

function formatDurationSince(isoString) {
    if (!isoString || isoString.startsWith('0001')) return '-';
    const start = new Date(isoString).getTime();
    const now = new Date().getTime();
    const seconds = Math.floor((now - start) / 1000);
    return formatDuration(seconds);
}

async function copyText(text) {
    try {
        if (navigator.clipboard) {
            await navigator.clipboard.writeText(text);
        } else {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
        showToast(`Copied: ${text}`);
    } catch (e) {
        console.error('Copy failed', e);
    }
}

function showToast(msg) {
    let el = document.getElementById('toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'toast';
        el.style.cssText = 'position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:var(--pico-primary-inverse); color:var(--pico-primary); padding:8px 16px; border-radius:4px; font-size:14px; z-index:9999; transition: opacity 0.3s; pointer-events:none;';
        document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.opacity = '1';
    setTimeout(() => { el.style.opacity = '0'; }, 2000);
}



// Theme Helper
function getInitialTheme() {
    const persisted = localStorage.getItem('catchmole_theme');
    if (persisted) return persisted;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('catchmole_theme', theme);
}

// Alpine Initialization
document.addEventListener('alpine:init', () => {
    
    // === Clients List App ===
    // === Clients List App ===
    Alpine.data('clientsApp', () => ({
        clients: [],
        global: {},
        search: '',
        sortBy: localStorage.getItem('catchmole_sortBy') || 'total_download',
        sortDesc: localStorage.getItem('catchmole_sortDesc') === 'true',
        startTime: '',
        autoRefresh: true,
        theme: getInitialTheme(),

        init() {
            // Restore defaults if logic failed
            if (!this.sortBy) { this.sortBy = 'total_download'; this.sortDesc = true; }
            
            // Apply Initial Theme
            applyTheme(this.theme);

            this.fetchData();
            setInterval(() => {
                if (this.autoRefresh) this.fetchData();
            }, 1000);
        },

        async fetchData() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                this.clients = data.clients || [];
                this.global = data.global || {};
                this.startTime = data.start_time;
            } catch (e) {
                console.error(e);
            }
        },

        get sortedClients() {
            if (!this.clients) return [];
            
            let list = this.clients.filter(c => {
                const q = this.search.toLowerCase();
                return !q || 
                    (c.name || '').toLowerCase().includes(q) || 
                    c.mac.toLowerCase().includes(q) || 
                    (c.ips && c.ips.some(ip => ip.includes(q)));
            });

            return list.sort((a, b) => {
                let va = this.getValue(a, this.sortBy);
                let vb = this.getValue(b, this.sortBy);
                
                let res = 0;
                if (va < vb) res = this.sortDesc ? 1 : -1;
                else if (va > vb) res = this.sortDesc ? -1 : 1;

                if (res === 0) {
                    // Secondary Name Sort
                    if ((a.name||'') < (b.name||'')) return -1;
                    if ((a.name||'') > (b.name||'')) return 1;
                }
                return res;
            });
        },

        getValue(obj, key) {
            if (key === 'started') return obj.start_time;
            return obj[key] || 0;
        },

        setSort(col) {
            if (this.sortBy === col) {
                this.sortDesc = !this.sortDesc;
            } else {
                this.sortBy = col;
                this.sortDesc = true;
            }
            localStorage.setItem('catchmole_sortBy', this.sortBy);
            localStorage.setItem('catchmole_sortDesc', this.sortDesc);
        },

        setMobileSort(val) {
            const [col, dir] = val.split(':');
            this.sortBy = col;
            this.sortDesc = dir === 'desc';
            localStorage.setItem('catchmole_sortBy', this.sortBy);
            localStorage.setItem('catchmole_sortDesc', this.sortDesc);
        },

        async resetAll() {
            if (!confirm('Clear ALL statistics?')) return;
            await fetch('/api/reset', { method: 'POST' });
            this.fetchData();
        },

        toggleTheme() {
            this.theme = this.theme === 'dark' ? 'light' : 'dark';
            applyTheme(this.theme);
        }
    }));


    // === Detail App ===
    // === Detail App ===
    Alpine.data('detailApp', () => ({
        mac: new URLSearchParams(window.location.search).get('mac'),
        client: {},
        flows: [],
        localIPs: [], // Store local IPs from API
        filterProtocol: '',
        filterRemoteIP: '',
        filterRemotePort: '',
        ipProvider: localStorage.getItem('catchmole_ipProvider') || 'https://ipinfo.io/',
        autoRefresh: true,
        theme: getInitialTheme(),
        
        // Flow Sorting
        sortBy: localStorage.getItem('catchmole_detail_sortBy') || 'session_download',
        sortDesc: (localStorage.getItem('catchmole_detail_sortDesc') ?? 'true') === 'true',

        init() {
            if (!this.mac) {
                window.location.href = '/clients';
                return;
            }
            
            // Restore defaults if logic failed
            if (!this.sortBy) this.sortBy = 'session_download';
            if (this.sortDesc === undefined) this.sortDesc = true;
            
            // Apply Initial Theme
            applyTheme(this.theme);

            this.fetchData();
            setInterval(() => {
                if (this.autoRefresh) this.fetchData();
            }, 1000);
        },

        async fetchData() {
            try {
                const res = await fetch(`/api/client?mac=${this.mac}`);
                const data = await res.json();
                this.client = data.client || {};
                
                let flows = data.flows || [];
                // Pre-calculate keys to avoid side-effects in computed property
                flows.forEach(f => {
                    f.key = (f.protocol||'') + ':' + (f.remote_ip||'') + ':' + (f.remote_port||'');
                });
                this.flows = flows;

                this.localIPs = data.local_ips || []; // Receive local IPs from API
            } catch (e) { console.error(e); }
        },

        get uniqueIPs() {
            // Directly return localIPs from API instead of extracting from flows
            // Sort IPs: IPv4 first, then IPv6
             let ips = [...this.localIPs];
             
             ips.sort((a, b) => {
                 // Simple IP sort helper
                 // Check if IPv4
                 const isIPv4 = ip => ip.includes('.') && !ip.includes(':');
                 const aIs4 = isIPv4(a);
                 const bIs4 = isIPv4(b);
                 
                 if (aIs4 && !bIs4) return -1;
                 if (!aIs4 && bIs4) return 1;
                 
                 // Lexicographical sort (simple enough only for same version grouping)
                 // For better IP sort we'd need a robust parser, but this is usually sufficient for UI
                 // To sort numerically, we'd need to split segments.
                 
                 return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
             });
             
            return ips;
        },

        get filteredFlows() {
            if (!this.flows) return [];

            let list = this.flows.filter(f => {
                if (this.filterProtocol && !f.protocol.toLowerCase().includes(this.filterProtocol.toLowerCase())) {
                    return false;
                };
                if (this.filterRemoteIP && !f.remote_ip.includes(this.filterRemoteIP)) {
                    return false;
                }
                if (this.filterRemotePort && !(f.remote_port + '').includes(this.filterRemotePort)) {
                    return false;
                }

                return true;
            });

            return list.sort((a, b) => {
                let va = a[this.sortBy] || 0;
                let vb = b[this.sortBy] || 0;
                
                let res = 0;
                if (va < vb) res = this.sortDesc ? 1 : -1;
                else if (va > vb) res = this.sortDesc ? -1 : 1;
                
                if (res === 0) {
                     const aIp = a.remote_ip || '';
                     const bIp = b.remote_ip || '';
                     if (aIp < bIp) return -1;
                     if (aIp > bIp) return 1;
                }
                return res;
            });
        }, 
        // ... (keeping methods)

        setSort(col) {
            if (this.sortBy === col) {
                this.sortDesc = !this.sortDesc;
            } else {
                this.sortBy = col;
                this.sortDesc = true;
            }
            localStorage.setItem('catchmole_detail_sortBy', this.sortBy);
            localStorage.setItem('catchmole_detail_sortDesc', this.sortDesc);
        },

        setMobileSort(val) {
            const [col, dir] = val.split(':');
            this.sortBy = col;
            this.sortDesc = dir === 'desc';
            localStorage.setItem('catchmole_detail_sortBy', this.sortBy);
            localStorage.setItem('catchmole_detail_sortDesc', this.sortDesc);
        },

        setProvider(val) {
            this.ipProvider = val;
            localStorage.setItem('catchmole_ipProvider', val);
        },

        clearFilters() {
            this.filterProtocol = '';
            this.filterRemoteIP = '';
            this.filterRemotePort = '';
        },
        
        // IPv6 Helper Functions
        getIpView(ip) {
            if (!ip || !ip.includes(':')) return ip;

            const parts = ip.split(':');
            if (parts.length <= 4) return ip;
            
            const headParts = parts.slice(0, 2);
            let head = headParts.join(':');
            if (headParts[1] === '') head += ':';
            
            const tailParts = parts.slice(-2);
            let tail = tailParts.join(':');
            if (tailParts[0] === '') tail = ':' + tail;
            
            return head + ' ~ ' + tail;
        },

        copyText(text) {
            copyText(text);
        },
        
        async resetSession() {
            if (!confirm('Reset SESSION stats (duration, traffic) for this client?')) return;
            await fetch(`/api/client/reset_session?mac=${this.mac}`, { method: 'POST' });
            this.fetchData();
        },

        async resetGlobal() {
            if (!confirm(`Reset GLOBAL stats (history) for this client? This cannot be undone.`)) return;
            await fetch(`/api/client/reset?mac=${this.mac}`, { method: 'POST' });
            this.fetchData();
        },

        toggleTheme() {
            this.theme = this.theme === 'dark' ? 'light' : 'dark';
            applyTheme(this.theme);
        }
    }));
});
