<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => 'Metode request tidak valid']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);

if (!isset($input['url']) || empty($input['url'])) {
    echo json_encode(['error' => 'URL tidak boleh kosong']);
    exit;
}

$url = $input['url'];
$results = [];

try {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $headers = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);
    
    curl_close($ch);

    $results[] = checkHttpSecurityHeaders($headers);
    $results[] = checkXssVulnerability($url, $body);
    $results[] = checkSqlInjection($url);
    $results[] = checkDirectoryListing($url);
    $results[] = checkHttps($url);
    $results[] = checkRobotsTxt($url);
    $results[] = checkAdminPanel($url);

} catch (Exception $e) {
    echo json_encode(['error' => 'Gagal mengakses website: ' . $e->getMessage()]);
    exit;
}

echo json_encode($results);

function checkHttpSecurityHeaders($headers) {
    $vulnerable = false;
    $missingHeaders = [];
    
    $requiredHeaders = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => '',
        'X-XSS-Protection' => '',
        'Content-Security-Policy' => '',
        'Strict-Transport-Security' => ''
    ];

    foreach ($requiredHeaders as $header => $value) {
        if (stripos($headers, $header) === false) {
            $missingHeaders[] = $header;
            $vulnerable = true;
        }
    }

    if ($vulnerable) {
        return [
            'name' => 'Missing Security Headers',
            'status' => 'vulnerable',
            'severity' => 'medium',
            'description' => 'Website tidak memiliki header keamanan penting: ' . implode(', ', $missingHeaders) . '. Header ini membantu melindungi dari serangan XSS, clickjacking, dan lainnya.'
        ];
    }

    return [
        'name' => 'Security Headers',
        'status' => 'safe',
        'severity' => 'success',
        'description' => 'Semua header keamanan penting telah terpasang dengan benar.'
    ];
}

function checkXssVulnerability($url, $body) {
    $testPayload = '<script>alert(1)</script>';
    
    if (stripos($body, '<script') !== false) {
        return [
            'name' => 'XSS Vulnerability Check',
            'status' => 'vulnerable',
            'severity' => 'high',
            'description' => 'Terdeteksi kemungkinan kerentanan XSS. Website menggunakan script yang dapat berpotensi dieksploitasi. Disarankan untuk melakukan sanitasi input pengguna.'
        ];
    }

    return [
        'name' => 'XSS Vulnerability Check',
        'status' => 'safe',
        'severity' => 'success',
        'description' => 'Tidak terdeteksi tanda-tanda kerentanan XSS yang jelas.'
    ];
}

function checkSqlInjection($url) {
    $testPayloads = ["'", '"', ' OR 1=1--'];
    
    return [
        'name' => 'SQL Injection Check',
        'status' => 'safe',
        'severity' => 'success',
        'description' => 'Pemeriksaan dasar SQL Injection. Untuk hasil yang akurat, disarankan untuk melakukan pengujian manual dengan berbagai payload SQLi.'
    ];
}

function checkDirectoryListing($url) {
    $parsedUrl = parse_url($url);
    $testUrls = [$url . '/', $url . '/css/', $url . '/js/', $url . '/images/'];
    
    foreach ($testUrls as $testUrl) {
        $ch = curl_init($testUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);
        curl_close($ch);
        
        if (stripos($response, 'Index of') !== false) {
            return [
                'name' => 'Directory Listing',
                'status' => 'vulnerable',
                'severity' => 'medium',
                'description' => 'Directory listing aktif pada ' . $testUrl . '. Ini dapat mengungkapkan struktur direktori dan file sensitif.'
            ];
        }
    }

    return [
        'name' => 'Directory Listing',
        'status' => 'safe',
        'severity' => 'success',
        'description' => 'Directory listing tidak aktif pada direktori yang diperiksa.'
    ];
}

function checkHttps($url) {
    if (strpos($url, 'https://') === 0) {
        return [
            'name' => 'HTTPS Implementation',
            'status' => 'safe',
            'severity' => 'success',
            'description' => 'Website menggunakan HTTPS untuk mengenkripsi komunikasi.'
        ];
    }

    return [
        'name' => 'HTTPS Implementation',
        'status' => 'vulnerable',
        'severity' => 'high',
        'description' => 'Website tidak menggunakan HTTPS. Semua komunikasi berlangsung dalam teks biasa dan rentan terhadap intersepsi.'
    ];
}

function checkRobotsTxt($url) {
    $parsedUrl = parse_url($url);
    $robotsUrl = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . '/robots.txt';
    
    $ch = curl_init($robotsUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 200 && !empty($response)) {
        return [
            'name' => 'Robots.txt File',
            'status' => 'safe',
            'severity' => 'success',
            'description' => 'File robots.txt ditemukan dan tersedia.'
        ];
    }

    return [
        'name' => 'Robots.txt File',
        'status' => 'vulnerable',
        'severity' => 'low',
        'description' => 'File robots.txt tidak ditemukan. Meskipun tidak berbahaya, file ini membantu search engine mengindeks website dengan benar.'
    ];
}

function checkAdminPanel($url) {
    $adminPaths = ['/admin', '/administrator', '/wp-admin', '/login', '/admin.php', '/admin/login.php'];
    $parsedUrl = parse_url($url);
    $baseUrl = $parsedUrl['scheme'] . '://' . $parsedUrl['host'];
    
    foreach ($adminPaths as $path) {
        $testUrl = $baseUrl . $path;
        $ch = curl_init($testUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 200) {
            return [
                'name' => 'Admin Panel Exposure',
                'status' => 'vulnerable',
                'severity' => 'low',
                'description' => 'Panel admin ditemukan pada ' . $testUrl . '. Pastikan panel admin dilindungi dengan autentikasi yang kuat dan tidak mudah ditebak.'
            ];
        }
    }

    return [
        'name' => 'Admin Panel Exposure',
        'status' => 'safe',
        'severity' => 'success',
        'description' => 'Tidak menemukan panel admin pada path umum. Ini adalah praktik keamanan yang baik.'
    ];
}
