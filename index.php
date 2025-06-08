<?php

// 🌐 Rate limiting por IP al inicio del script
$ip = $_SERVER['REMOTE_ADDR'];
$max_requests = 5;       // Máximo 100 requests...
$window = 10;              // ...por cada 60 segundos
$file = sys_get_temp_dir() . '/ratelimit_' . md5($ip);

$data = ['start' => time(), 'count' => 1];

if (file_exists($file)) {
    $data = json_decode(file_get_contents($file), true);
    if (time() - $data['start'] < $window) {
        $data['count']++;
        if ($data['count'] > $max_requests) {
            http_response_code(429); // Too Many Requests
            echo json_encode(['error' => 'Too many requests']);
            exit;
        }
    } else {
        // Ventana nueva, reiniciar contador
        $data = ['start' => time(), 'count' => 1];
    }
}
file_put_contents($file, json_encode($data), LOCK_EX);



define('DIRECT_ACCESS', true);


session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '', // o tu dominio
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();


// 🔐 Seguridad: Tiempo máximo de inactividad
$timeout = 900; // 15 minutos
if (isset($_SESSION['ultimo_acceso']) && time() - $_SESSION['ultimo_acceso'] > $timeout) {
    destroySession();
    session_start();
    session_regenerate_id(true); // Cambiar el ID de sesión tras reinicio
}
$_SESSION['ultimo_acceso'] = time();



if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!isset($_COOKIE['__secure_fp'])) {
    $fpCookie = bin2hex(random_bytes(16));
    setcookie('__secure_fp', $fpCookie, [
        'expires' => time() + 3600 * 24 * 30, // 30 días
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    $_COOKIE['__secure_fp'] = $fpCookie;
}



if (isset($_SESSION['user_agent'])) {
    if ($_SESSION['user_agent'] !== getSessionFingerprint()) {
        destroySessionAndForbidden();
    }
} else {
    $_SESSION['user_agent'] = getSessionFingerprint();
}



// 👤 Guest automático
if (!isset($_SESSION['usuario'])) {
    session_regenerate_id(true); // Cambiar el ID de sesión tras reinicio
    $_SESSION['usuario'] = 'guest_' . substr(md5(uniqid()), 0, 5);
    $_SESSION['es_guest'] = true;
}



if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');

    $data = json_decode(file_get_contents("php://input"), true);

    // Validar que no hubo error en la decodificación
    if (json_last_error() !== JSON_ERROR_NONE) {
        // JSON inválido: manejar el error o responder con un mensaje

        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'invalid JSON']);
        exit;
    }

    $csrf_token = $data['csrf_token'] ?? '';
    if (!$csrf_token ||  $csrf_token !== $_SESSION['csrf_token']) {
        destroySessionAndForbidden();
    }

    require_once __DIR__ . '/service/service.php';

    exit;
}


// 3. Validar método para GET o invalidar otros métodos
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); // Método no permitido
    header('Allow: GET, POST, OPTIONS');
    exit;
}

$oage = (isset($_GET['page']) && preg_match('/^[a-zA-Z0-9_\-\/]+\.html?$/', $_GET['page'])) 
    ? htmlspecialchars($_GET['page'], ENT_QUOTES, 'UTF-8') 
    : 'index.html';

$carpeta = "templated-hielo";
$archivo = __DIR__ . '/' . $carpeta . '/' . $oage;


$jsnonce = base64_encode(random_bytes(16));
$jssri = "sha384-" . base64_encode(hash('sha384', file_get_contents(__DIR__ . '/js/virtualized-list.min.js'), true));


$html = renderHtmlTemplate($archivo);
//$html = str_replace("<head>", "<head><base href=\"./$carpeta/\" />", $html);



if (!ob_start("ob_gzhandler")) {
    ob_start(); // fallback si no se puede usar gzip
}
//header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$jsnonce' data:; style-src 'self' 'unsafe-inline' data: https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';");
header('Content-Type: text/html; charset=utf-8');
//header('Content-Length: ' . strlen($html));
header('Cache-Control: no-cache, no-store, must-revalidate'); // evita cacheo
header('Pragma: no-cache'); // para compatibilidad HTTP/1.0
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("X-XSS-Protection: 1; mode=block"); // Opcional, algunos navegadores lo ignoran ya
header("X-Server: https://www.youtube.com/@xanderdice");
header('Referrer-Policy: no-referrer');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
header("Permissions-Policy: accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()");
// Ocultar X-Powered-By real y poner uno falso si querés
header_remove("X-Powered-By");
header("X-Powered-By: PsytranceEngine/9.9");
// Falso header para confundir escáneres
header("X-Server: PsytranceServer/9.9");
echo $html;
exit;




function getSessionFingerprint()
{
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    $encoding = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
    $language = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    $cookieHash = $_COOKIE['__secure_fp'] ?? '';
    $salt = 'TU_SAL_SECRETA';
    $ipPart = substr($_SERVER['REMOTE_ADDR'] ?? '', 0, 6); // opcional, corta para evitar falsos positivos

    $rawFingerprint = $ipPart . '|' . $userAgent . '|' . $accept . '|' . $encoding . '|' . $language . '|' . $cookieHash . '|' . $salt;

    return hash('sha256', $rawFingerprint);
}

function destroySession()
{
    session_unset();
    session_destroy();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }
}

function destroySessionAndForbidden()
{
    destroySession();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'forbidden']);
    } else {
        echo 'forbidden';
    }
    exit;
}


function renderHtmlTemplate($path)
{
    if (!file_exists($path)) {
        http_response_code(404);
        exit("404 Not found");
    }

    $html = file_get_contents($path);

    // Buscar todas las variables [[NOMBRE]]
    preg_match_all('/\[\[([a-zA-Z0-9_]+)\]\]/', $html, $matches);

    foreach ($matches[1] as $varName) {
        $value = null;

        if (isset($_SESSION[$varName])) {
            $value = $_SESSION[$varName];
        } elseif (isset($GLOBALS[$varName])) {
            $value = $GLOBALS[$varName];
        }

        if ($value !== null) {
            // Reemplazar todas las ocurrencias de [[NOMBRE]] por su valor
            $html = str_replace("[[$varName]]", htmlspecialchars((string)$value), $html);
        }
    }

    // 🔁 Reemplazar solo <a href="*.html|htm|php"> ignorando http, mailto, etc. Soporta saltos de línea.
    $html = preg_replace_callback(
        '/<a\b([^>]*?)\bhref\s*=\s*"((?!https?:\/\/|mailto:)[^"]+\.(?:html?|php))"([^>]*)>/is',
        function ($matches) {
            $antes = $matches[1];
            $href = $matches[2];
            $despues = $matches[3];

            // Ignorar si ya es ./?page= o es ruta absoluta o relativa tipo /, ./, ../
            if (
                preg_match('/^(\.\/|\.\.\/|\/|\.?\?page=)/', $href)
            ) {
                return "<a{$antes}href=\"$href\"{$despues}>";
            }

            $nuevoHref = './?page=' . htmlspecialchars($href, ENT_QUOTES);
            return "<a{$antes}href=\"$nuevoHref\"{$despues}>";
        },
        $html
    );

    $html = preg_replace_callback(
        '/<link\b([^>]*?\brel\s*=\s*["\']\s*stylesheet\s*["\'][^>]*?\bhref\s*=\s*["\'])([^"\']+)(["\'][^>]*?)>/is',
        function ($matches) use ($path) {
            $antesHref = $matches[1];
            $rutaHref = trim($matches[2]);
            $despuesHref = $matches[3];

            $baseDir = dirname($path);
            $cssPath = realpath($baseDir . DIRECTORY_SEPARATOR . $rutaHref);

            if ($cssPath && file_exists($cssPath)) {
                $contenido = file_get_contents($cssPath);

                // Reemplazar todas las url(...) por data:image/...
                $contenido = preg_replace_callback(
                    '/url\(\s*([\'"]?)([^\'")]+)\1\s*\)/i',
                    function ($match) use ($cssPath) {
                        $urlRelativa = $match[2];
                        $dirCss = dirname($cssPath);
                        $imgPath = realpath($dirCss . DIRECTORY_SEPARATOR . $urlRelativa);

                        if ($imgPath && file_exists($imgPath)) {
                            $mime = mime_content_type($imgPath);
                            $data = base64_encode(file_get_contents($imgPath));
                            return 'url("data:' . $mime . ';base64,' . $data . '")';
                        } else {
                            return $match[0]; // no se modifica si no existe
                        }
                    },
                    $contenido
                );

                $base64 = base64_encode($contenido);
                $nuevoHref = 'data:text/css;base64,' . $base64;

                return '<link' . $antesHref . $nuevoHref . $despuesHref . ' />';
            } else {
                return $matches[0];
            }
        },
        $html
    );


    //JAVASCRIPT:
    $html = preg_replace_callback(
        '/<script\b([^>]*?\bsrc\s*=\s*["\'])(?!https?:\/\/|\/\/|data:|mailto:)([^"\']+)(["\'][^>]*?)><\/script>/is',
        function ($matches) use ($path) {
            $antesSrc = $matches[1];       // antes del valor de src
            $scriptSrc = trim($matches[2]);
            $despuesSrc = $matches[3];     // después del valor de src

            // Resolver ruta absoluta del archivo JavaScript
            $baseDir = dirname($path);
            $fullPath = realpath($baseDir . DIRECTORY_SEPARATOR . $scriptSrc);

            if ($fullPath && file_exists($fullPath)) {
                $jsContent = file_get_contents($fullPath);
                $base64 = base64_encode($jsContent);
                $nuevoSrc = 'data:application/javascript;base64,' . $base64;

                // reconstruir el tag <script> con los mismos atributos
                return '<script' . $antesSrc . $nuevoSrc . $despuesSrc . '></script>';
            } else {
                return $matches[0]; // si no existe, no se toca
            }
        },
        $html
    );

    //IMAGE:
    $html = preg_replace_callback(
        '/<img\b([^>]*?\bsrc\s*=\s*["\'])(?!https?:\/\/|\/\/|data:|mailto:)([^"\']+)(["\'][^>]*?)>/is',
        function ($matches) use ($path) {
            $antesSrc = $matches[1];
            $imgSrc = trim($matches[2]);
            $despuesSrc = $matches[3];

            // Ruta absoluta del archivo de imagen
            $baseDir = dirname($path);
            $fullPath = realpath($baseDir . DIRECTORY_SEPARATOR . $imgSrc);

            if ($fullPath && file_exists($fullPath)) {
                $contenido = file_get_contents($fullPath);
                $mimeType = mime_content_type($fullPath);
                $base64 = base64_encode($contenido);
                $dataUri = 'data:' . $mimeType . ';base64,' . $base64;

                return '<img ' . $antesSrc . $dataUri . $despuesSrc . ' />';
            } else {
                return $matches[0]; // No se modifica si no existe
            }
        },
        $html
    );


    return $html;
}

//google:
//clientid=382946950229-tombg84idimlf58i215aeichljss2qa1.apps.googleusercontent.com
//secret=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