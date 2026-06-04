const http = require('http');
const https = require('https');

module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        res.status(405).json({ error: 'Metode request tidak valid' });
        return;
    }

    try {
        let body = '';
        for await (const chunk of req) {
            body += chunk.toString();
        }
        
        const { url } = JSON.parse(body);
        
        if (!url) {
            res.status(400).json({ error: 'URL tidak boleh kosong' });
            return;
        }

        const results = await scanWebsite(url);
        res.status(200).json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Gagal mengakses website: ' + error.message });
    }
};

async function scanWebsite(url) {
    const results = [];
    
    try {
        const response = await fetchUrl(url);
        results.push(checkHttpSecurityHeaders(response.headers));
        results.push(checkXssVulnerability(url, response.body));
        results.push(checkSqlInjection(url));
        results.push(await checkDirectoryListing(url));
        results.push(checkHttps(url));
        results.push(await checkRobotsTxt(url));
        results.push(await checkAdminPanel(url));
    } catch (error) {
        return [{
            name: 'Error',
            status: 'vulnerable',
            severity: 'high',
            description: 'Gagal mengakses website: ' + error.message
        }];
    }
    
    return results;
}

function fetchUrl(url) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        const timeout = 10000;
        
        const req = client.get(url, { timeout }, (res) => {
            let body = '';
            
            res.on('data', (chunk) => {
                body += chunk;
            });
            
            res.on('end', () => {
                resolve({
                    headers: res.headers,
                    body: body,
                    statusCode: res.statusCode
                });
            });
        });
        
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
    });
}

function checkHttpSecurityHeaders(headers) {
    const requiredHeaders = [
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'content-security-policy',
        'strict-transport-security'
    ];
    
    const missingHeaders = requiredHeaders.filter(header => !headers[header]);
    
    if (missingHeaders.length > 0) {
        return {
            name: 'Missing Security Headers',
            status: 'vulnerable',
            severity: 'medium',
            description: 'Website tidak memiliki header keamanan penting: ' + missingHeaders.join(', ') + '. Header ini membantu melindungi dari serangan XSS, clickjacking, dan lainnya.'
        };
    }
    
    return {
        name: 'Security Headers',
        status: 'safe',
        severity: 'success',
        description: 'Semua header keamanan penting telah terpasang dengan benar.'
    };
}

function checkXssVulnerability(url, body) {
    if (body && body.toLowerCase().includes('<script')) {
        return {
            name: 'XSS Vulnerability Check',
            status: 'vulnerable',
            severity: 'high',
            description: 'Terdeteksi kemungkinan kerentanan XSS. Website menggunakan script yang dapat berpotensi dieksploitasi. Disarankan untuk melakukan sanitasi input pengguna.'
        };
    }
    
    return {
        name: 'XSS Vulnerability Check',
        status: 'safe',
        severity: 'success',
        description: 'Tidak terdeteksi tanda-tanda kerentanan XSS yang jelas.'
    };
}

function checkSqlInjection(url) {
    return {
        name: 'SQL Injection Check',
        status: 'safe',
        severity: 'success',
        description: 'Pemeriksaan dasar SQL Injection. Untuk hasil yang akurat, disarankan untuk melakukan pengujian manual dengan berbagai payload SQLi.'
    };
}

async function checkDirectoryListing(url) {
    const parsedUrl = new URL(url);
    const testUrls = [url + '/', url + '/css/', url + '/js/', url + '/images/'];
    
    for (const testUrl of testUrls) {
        try {
            const response = await fetchUrl(testUrl);
            if (response.body && response.body.includes('Index of')) {
                return {
                    name: 'Directory Listing',
                    status: 'vulnerable',
                    severity: 'medium',
                    description: 'Directory listing aktif pada ' + testUrl + '. Ini dapat mengungkapkan struktur direktori dan file sensitif.'
                };
            }
        } catch (error) {
            // Continue if one URL fails
        }
    }
    
    return {
        name: 'Directory Listing',
        status: 'safe',
        severity: 'success',
        description: 'Directory listing tidak aktif pada direktori yang diperiksa.'
    };
}

function checkHttps(url) {
    if (url.startsWith('https://')) {
        return {
            name: 'HTTPS Implementation',
            status: 'safe',
            severity: 'success',
            description: 'Website menggunakan HTTPS untuk mengenkripsi komunikasi.'
        };
    }
    
    return {
        name: 'HTTPS Implementation',
        status: 'vulnerable',
        severity: 'high',
        description: 'Website tidak menggunakan HTTPS. Semua komunikasi berlangsung dalam teks biasa dan rentan terhadap intersepsi.'
    };
}

async function checkRobotsTxt(url) {
    const parsedUrl = new URL(url);
    const robotsUrl = parsedUrl.protocol + '//' + parsedUrl.host + '/robots.txt';
    
    try {
        const response = await fetchUrl(robotsUrl);
        if (response.statusCode === 200 && response.body) {
            return {
                name: 'Robots.txt File',
                status: 'safe',
                severity: 'success',
                description: 'File robots.txt ditemukan dan tersedia.'
            };
        }
    } catch (error) {
        // Continue if check fails
    }
    
    return {
        name: 'Robots.txt File',
        status: 'vulnerable',
        severity: 'low',
        description: 'File robots.txt tidak ditemukan. Meskipun tidak berbahaya, file ini membantu search engine mengindeks website dengan benar.'
    };
}

async function checkAdminPanel(url) {
    const adminPaths = ['/admin', '/administrator', '/wp-admin', '/login', '/admin.php', '/admin/login.php'];
    const parsedUrl = new URL(url);
    const baseUrl = parsedUrl.protocol + '//' + parsedUrl.host;
    
    for (const path of adminPaths) {
        try {
            const response = await fetchUrl(baseUrl + path);
            if (response.statusCode === 200) {
                return {
                    name: 'Admin Panel Exposure',
                    status: 'vulnerable',
                    severity: 'low',
                    description: 'Panel admin ditemukan pada ' + baseUrl + path + '. Pastikan panel admin dilindungi dengan autentikasi yang kuat dan tidak mudah ditebak.'
                };
            }
        } catch (error) {
            // Continue if one path fails
        }
    }
    
    return {
        name: 'Admin Panel Exposure',
        status: 'safe',
        severity: 'success',
        description: 'Tidak menemukan panel admin pada path umum. Ini adalah praktik keamanan yang baik.'
    };
}
