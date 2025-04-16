/**
 * Device Fingerprinting Module
 * Collects browser and device characteristics to create a unique fingerprint
 */

class DeviceFingerprinter {
    constructor() {
        this.fingerprint = {};
    }

    /**
     * Collect all available fingerprinting data
     * @returns {Promise<Object>} The complete fingerprint object
     */
    async collectAll() {
        // Basic information
        this.collectBasicInfo();
        
        // Browser capabilities
        this.collectBrowserCapabilities();
        
        // Canvas fingerprint
        this.collectCanvasFingerprint();
        
        // WebGL information
        this.collectWebGLInfo();
        
        // Audio fingerprint
        await this.collectAudioFingerprint();
        
        // Advanced detection
        this.detectInconsistencies();
        
        // Generate the fingerprint hash
        this.fingerprint.hash = this.generateHash(this.fingerprint);
        
        return this.fingerprint;
    }

    /**
     * Collect basic device and browser information
     */
    collectBasicInfo() {
        const nav = window.navigator;
        const screen = window.screen;

        this.fingerprint.userAgent = nav.userAgent;
        this.fingerprint.language = nav.language;
        this.fingerprint.languages = Array.isArray(nav.languages) ? 
            [...nav.languages] : [nav.language];
        this.fingerprint.platform = nav.platform;
        this.fingerprint.doNotTrack = nav.doNotTrack;
        
        // Time and timezone information
        this.fingerprint.timezone = {
            offset: new Date().getTimezoneOffset(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };
        
        // Screen properties
        this.fingerprint.screen = {
            width: screen.width,
            height: screen.height,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,
            colorDepth: screen.colorDepth,
            pixelRatio: window.devicePixelRatio || 1
        };
        
        // Browser window
        this.fingerprint.window = {
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight
        };
    }

    /**
     * Collect browser capabilities and installed plugins
     */
    collectBrowserCapabilities() {
        const nav = window.navigator;
        
        // Browser features detection
        this.fingerprint.features = {
            cookiesEnabled: nav.cookieEnabled,
            localStorageAvailable: this.isLocalStorageAvailable(),
            sessionStorageAvailable: this.isSessionStorageAvailable(),
            indexedDBAvailable: !!window.indexedDB,
            addBehaviorAvailable: document.body && !!document.body.addBehavior,
            openDatabaseAvailable: !!window.openDatabase,
            cpuClass: nav.cpuClass,
            hardwareConcurrency: nav.hardwareConcurrency || 0,
            deviceMemory: nav.deviceMemory || 0,
            touchPoints: nav.maxTouchPoints || 0,
            touchSupport: ('ontouchstart' in window) || (navigator.maxTouchPoints > 0)
        };
        
        // Plugins (non-IE)
        this.fingerprint.plugins = [];
        if (nav.plugins && nav.plugins.length) {
            const pluginsArr = Array.from(nav.plugins || []);
            this.fingerprint.plugins = pluginsArr.map(p => ({
                name: p.name,
                description: p.description,
                filename: p.filename,
                version: p.version,
                length: p.length
            }));
        }
        
        // Mime types
        try {
            if (nav.mimeTypes && nav.mimeTypes.length) {
                const mimeTypesArr = Array.from(nav.mimeTypes || []);
                this.fingerprint.mimeTypes = mimeTypesArr.map(m => ({
                    type: m.type,
                    description: m.description,
                    suffixes: m.suffixes
                }));
            } else {
                this.fingerprint.mimeTypes = [];
            }
        } catch (e) {
            this.fingerprint.mimeTypes = [];
            console.error('Error collecting mime types:', e);
        }
    }

    /**
     * Collect canvas fingerprint
     */
    collectCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            if (!ctx) {
                this.fingerprint.canvasSupported = false;
                return;
            }
            
            this.fingerprint.canvasSupported = true;
            
            // Set canvas size
            canvas.width = 220;
            canvas.height = 30;
            
            // Fill background
            ctx.fillStyle = 'rgb(255, 255, 255)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            // Text content and styling
            ctx.fillStyle = 'rgb(0, 0, 255)';
            ctx.font = '14px Arial';
            ctx.textBaseline = 'alphabetic';
            ctx.fillText('Canvas Fingerprint 👋', 10, 20);
            
            // Additional element with different color
            ctx.fillStyle = 'rgb(255, 0, 0)';
            ctx.font = '16px Georgia';
            ctx.fillText('!', 204, 20);
            
            // Extract data URL and hash
            try {
                this.fingerprint.canvasHash = this.hashString(canvas.toDataURL());
            } catch (e) {
                this.fingerprint.canvasHash = null;
                this.fingerprint.canvasError = e.message;
            }
            
            // WebGL canvas fingerprint
            this.collectWebGLFingerprint();
            
        } catch (e) {
            this.fingerprint.canvasSupported = false;
            this.fingerprint.canvasError = e.message;
        }
    }

    /**
     * Collect WebGL fingerprint
     */
    collectWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || 
                      canvas.getContext('experimental-webgl');
            
            if (!gl) {
                this.fingerprint.webglSupported = false;
                return;
            }
            
            this.fingerprint.webglSupported = true;
            
            // Set canvas size
            canvas.width = 50;
            canvas.height = 50;
            
            // Clear canvas
            gl.clearColor(1, 0, 0, 1);
            gl.clear(gl.COLOR_BUFFER_BIT);
            
            // Extract data URL and hash
            try {
                this.fingerprint.webglHash = this.hashString(canvas.toDataURL());
            } catch (e) {
                this.fingerprint.webglHash = null;
                this.fingerprint.webglError = e.message;
            }
            
        } catch (e) {
            this.fingerprint.webglSupported = false;
            this.fingerprint.webglError = e.message;
        }
    }

    /**
     * Collect WebGL information
     */
    collectWebGLInfo() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || 
                      canvas.getContext('experimental-webgl');
            
            if (!gl) {
                this.fingerprint.webgl = { supported: false };
                return;
            }
            
            // Get WebGL vendor and renderer
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            const vendor = debugInfo ? 
                gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 
                gl.getParameter(gl.VENDOR);
            const renderer = debugInfo ? 
                gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 
                gl.getParameter(gl.RENDERER);
            
            this.fingerprint.webgl = {
                supported: true,
                vendor,
                renderer,
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                antialiasing: gl.getContextAttributes().antialias,
                extensions: gl.getSupportedExtensions()
            };
            
        } catch (e) {
            this.fingerprint.webgl = { 
                supported: false,
                error: e.message
            };
        }
    }

    /**
     * Collect audio fingerprint
     */
    async collectAudioFingerprint() {
        try {
            if (!window.AudioContext && !window.webkitAudioContext) {
                this.fingerprint.audio = { supported: false };
                return;
            }
            
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const analyser = audioContext.createAnalyser();
            const oscillator = audioContext.createOscillator();
            const dynamicsCompressor = audioContext.createDynamicsCompressor();
            
            // Set properties that will affect the audio output
            analyser.fftSize = 1024;
            
            // Set non-default compressor settings
            dynamicsCompressor.threshold.setValueAtTime(-50, audioContext.currentTime);
            dynamicsCompressor.knee.setValueAtTime(40, audioContext.currentTime);
            dynamicsCompressor.ratio.setValueAtTime(12, audioContext.currentTime);
            dynamicsCompressor.attack.setValueAtTime(0, audioContext.currentTime);
            dynamicsCompressor.release.setValueAtTime(0.25, audioContext.currentTime);
            
            // Connect nodes
            oscillator.connect(dynamicsCompressor);
            dynamicsCompressor.connect(analyser);
            analyser.connect(audioContext.destination);
            
            // Start generating sound
            oscillator.start(0);
            
            // Wait for compressor to do its work
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Get frequency data
            const frequencyData = new Uint8Array(analyser.frequencyBinCount);
            analyser.getByteFrequencyData(frequencyData);
            
            // Calculate a simple hash from frequency data
            let sum = 0;
            for (let i = 0; i < frequencyData.length; i++) {
                sum += frequencyData[i];
            }
            
            // Stop generating sound
            oscillator.stop();
            await audioContext.close();
            
            this.fingerprint.audio = {
                supported: true,
                hash: sum.toString(16)
            };
            
        } catch (e) {
            this.fingerprint.audio = {
                supported: false,
                error: e.message
            };
        }
    }

    /**
     * Detect inconsistencies in browser information
     */
    detectInconsistencies() {
        this.fingerprint.inconsistencies = [];
        
        // Check for inconsistencies in user agent vs platform
        this.checkUserAgentInconsistencies();
        
        // Check for inconsistencies in plugins vs claimed browser
        this.checkPluginInconsistencies();
        
        // Check for inconsistencies in hardware
        this.checkHardwareInconsistencies();
        
        // Check for automation signs
        this.checkForAutomation();
    }

    /**
     * Check for inconsistencies in the user agent
     */
    checkUserAgentInconsistencies() {
        const ua = this.fingerprint.userAgent.toLowerCase();
        const platform = this.fingerprint.platform.toLowerCase();
        
        // Check for platform/UA mismatch
        if (ua.includes('windows') && !platform.includes('win')) {
            this.fingerprint.inconsistencies.push('ua_platform_mismatch');
        }
        
        if (ua.includes('macintosh') && !platform.includes('mac')) {
            this.fingerprint.inconsistencies.push('ua_platform_mismatch');
        }
        
        if (ua.includes('linux') && !platform.includes('linux')) {
            this.fingerprint.inconsistencies.push('ua_platform_mismatch');
        }
        
        if (ua.includes('android') && !platform.includes('android')) {
            this.fingerprint.inconsistencies.push('ua_platform_mismatch');
        }
        
        // Check for mobile/desktop mismatch
        const isMobileUA = /mobile|android|iphone|ipod|ipad/i.test(ua);
        const isMobileScreen = window.screen.width < 800 || window.screen.height < 600;
        
        if (isMobileUA !== isMobileScreen) {
            this.fingerprint.inconsistencies.push('mobile_mismatch');
        }
    }

    /**
     * Check for inconsistencies in plugins
     */
    checkPluginInconsistencies() {
        const ua = this.fingerprint.userAgent.toLowerCase();
        const plugins = this.fingerprint.plugins || [];
        
        // Firefox-specific plugins in Chrome UA
        if (ua.includes('chrome') && !ua.includes('firefox')) {
            const hasFirefoxPlugins = plugins.some(p => 
                p.name.toLowerCase().includes('firefox') || 
                p.name.toLowerCase().includes('mozilla')
            );
            
            if (hasFirefoxPlugins) {
                this.fingerprint.inconsistencies.push('browser_plugin_mismatch');
            }
        }
        
        // Chrome-specific plugins in Firefox UA
        if (ua.includes('firefox') && !ua.includes('chrome')) {
            const hasChromePlugins = plugins.some(p => 
                p.name.toLowerCase().includes('chrome') || 
                p.name.toLowerCase().includes('google')
            );
            
            if (hasChromePlugins) {
                this.fingerprint.inconsistencies.push('browser_plugin_mismatch');
            }
        }
    }

    /**
     * Check for inconsistencies in hardware reporting
     */
    checkHardwareInconsistencies() {
        // Unrealistic hardware concurrency
        if (this.fingerprint.features.hardwareConcurrency > 32) {
            this.fingerprint.inconsistencies.push('unrealistic_hardware');
        }
        
        // Unrealistic memory
        if (this.fingerprint.features.deviceMemory > 32) {
            this.fingerprint.inconsistencies.push('unrealistic_hardware');
        }
    }

    /**
     * Check for signs of automation/headless browsers
     */
    checkForAutomation() {
        // Check for navigator properties often present in automation tools
        const nav = window.navigator;
        
        if (
            nav.webdriver === true || 
            nav.languages === undefined ||
            (nav.languages && nav.languages.length === 0)
        ) {
            this.fingerprint.inconsistencies.push('automation_detected');
        }
        
        // Check for missing image/canvas support (common in headless browsers)
        if (
            !this.fingerprint.canvasSupported && 
            !this.fingerprint.webglSupported
        ) {
            this.fingerprint.inconsistencies.push('missing_graphics_support');
        }
        
        // Check for missing audio support (common in headless browsers)
        if (!this.fingerprint.audio || !this.fingerprint.audio.supported) {
            this.fingerprint.inconsistencies.push('missing_audio_support');
        }
    }

    /**
     * Check if localStorage is available
     * @returns {boolean} True if localStorage is available
     */
    isLocalStorageAvailable() {
        try {
            const test = '__test__';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Check if sessionStorage is available
     * @returns {boolean} True if sessionStorage is available
     */
    isSessionStorageAvailable() {
        try {
            const test = '__test__';
            sessionStorage.setItem(test, test);
            sessionStorage.removeItem(test);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Generate a simple hash from a string
     * @param {string} str - String to hash
     * @returns {string} Hash value
     */
    hashString(str) {
        let hash = 0;
        if (str.length === 0) return hash.toString(16);
        
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        
        return hash.toString(16);
    }

    /**
     * Generate a hash from the fingerprint data
     * @param {Object} obj - Fingerprint data object
     * @returns {string} Hash value
     */
    generateHash(obj) {
        // Exclude the inconsistencies array and some volatile properties
        const copy = JSON.parse(JSON.stringify(obj));
        
        // Remove properties that change frequently
        delete copy.inconsistencies;
        delete copy.window;
        
        if (copy.timezone) {
            delete copy.timezone.currentTime;
        }
        
        // Convert to string and hash
        const str = JSON.stringify(copy);
        return this.hashString(str);
    }
}

// Usage example:
// const fingerprinter = new DeviceFingerprinter();
// fingerprinter.collectAll().then(fingerprint => {
//     console.log(fingerprint);
//     
//     // Send to server
//     fetch('/api/analyze', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json'
//         },
//         body: JSON.stringify({
//             device_fingerprint: fingerprint,
//             // other data...
//         })
//     });
// });
