<?php
session_start();
require_once '../config/conexion.php';
require_once '../includes/seguridad.php';

set_time_limit(35);

if (!isset($_POST['id_historial'])) {
    die("Error: No se recibió el ID por POST.");
}

$id = (int)$_POST['id_historial'];

if (!usuarioPuedeAccederAnalisis($conn, $id)) {
    die("Error: Acceso no autorizado.");
}

registrarAnalisisPermitido($id);

function h(string $texto): string
{
    return htmlspecialchars($texto, ENT_QUOTES, 'UTF-8');
}

function normalizarDominioSsl(string $entrada)
{
    $dominio = trim($entrada);
    if ($dominio === '') {
        return false;
    }

    $dominio = preg_replace('~^https?://~i', '', $dominio);
    $dominio = preg_replace('~[/?#].*$~', '', $dominio);
    $dominio = preg_replace('~:\d+$~', '', $dominio);
    $dominio = strtolower(trim($dominio));
    $dominio = rtrim($dominio, '.');

    if ($dominio === '' || !filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return false;
    }

    return $dominio;
}

function candidatosHttps(string $dominio): array
{
    $candidatos = [$dominio];

    // Muchos sitios pequeños solo tienen certificado en www.dominio.com.
    if (stripos($dominio, 'www.') !== 0) {
        $candidatos[] = 'www.' . $dominio;
    }

    return array_values(array_unique($candidatos));
}

function valorCampoCertificado(array $datos, string $clave): string
{
    if (!isset($datos[$clave])) {
        return 'N/D';
    }

    if (is_array($datos[$clave])) {
        $partes = [];
        foreach ($datos[$clave] as $k => $v) {
            if (is_array($v)) {
                $v = implode(', ', array_map('strval', $v));
            }
            $partes[] = $k . '=' . (string)$v;
        }
        return implode(', ', $partes);
    }

    return (string)$datos[$clave];
}

function normalizarNombreCert(string $nombre): string
{
    $nombre = strtolower(trim($nombre));
    $nombre = preg_replace('/^dns:/i', '', $nombre);
    return rtrim($nombre, '.');
}

function dominioCoincideConPatron(string $dominio, string $patron): bool
{
    $dominio = normalizarNombreCert($dominio);
    $patron = normalizarNombreCert($patron);

    if ($dominio === $patron) {
        return true;
    }

    // Un comodín *.ejemplo.com cubre blog.ejemplo.com, pero no ejemplo.com ni a.b.ejemplo.com.
    if (strpos($patron, '*.') === 0) {
        $base = substr($patron, 2);
        if ($base === '' || $dominio === $base) {
            return false;
        }

        if (substr($dominio, -strlen('.' . $base)) !== '.' . $base) {
            return false;
        }

        $parteIzquierda = substr($dominio, 0, -strlen('.' . $base));
        return $parteIzquierda !== '' && strpos($parteIzquierda, '.') === false;
    }

    return false;
}

function extraerSAN(array $certInfo): array
{
    $sans = [];
    $texto = $certInfo['extensions']['subjectAltName'] ?? '';

    if (!is_string($texto) || trim($texto) === '') {
        return [];
    }

    foreach (explode(',', $texto) as $parte) {
        $parte = trim($parte);
        if (stripos($parte, 'DNS:') === 0) {
            $nombre = normalizarNombreCert(substr($parte, 4));
            if ($nombre !== '') {
                $sans[] = $nombre;
            }
        }
    }

    $sans = array_values(array_unique($sans));
    sort($sans, SORT_NATURAL | SORT_FLAG_CASE);
    return $sans;
}

function certificadoCubreDominio(string $dominio, array $certInfo, array $sans): bool
{
    if (!empty($sans)) {
        foreach ($sans as $san) {
            if (dominioCoincideConPatron($dominio, $san)) {
                return true;
            }
        }
        return false;
    }

    $cn = $certInfo['subject']['CN'] ?? '';
    if (is_array($cn)) {
        foreach ($cn as $cnItem) {
            if (dominioCoincideConPatron($dominio, (string)$cnItem)) {
                return true;
            }
        }
        return false;
    }

    return is_string($cn) && dominioCoincideConPatron($dominio, $cn);
}

function formatoFechaCert($timestamp): string
{
    if (!is_numeric($timestamp)) {
        return 'N/D';
    }

    return date('d/m/Y H:i:s', (int)$timestamp);
}

function conectarCertificado(string $host, bool $verificar, int $timeout = 6): array
{
    $contexto = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
            'verify_peer' => $verificar,
            'verify_peer_name' => $verificar,
            'allow_self_signed' => false,
            'peer_name' => $host,
            'SNI_enabled' => true,
            'SNI_server_name' => $host,
        ]
    ]);

    $errno = 0;
    $errstr = '';
    $socket = @stream_socket_client(
        'ssl://' . $host . ':443',
        $errno,
        $errstr,
        $timeout,
        STREAM_CLIENT_CONNECT,
        $contexto
    );

    if (!$socket) {
        return [
            'ok' => false,
            'error' => trim($errstr) !== '' ? $errstr : 'No se pudo conectar por TLS.',
            'errno' => $errno,
            'cert' => null,
            'chain' => [],
            'crypto' => []
        ];
    }

    $params = stream_context_get_params($socket);
    $meta = stream_get_meta_data($socket);
    fclose($socket);

    $sslOptions = $params['options']['ssl'] ?? [];

    return [
        'ok' => true,
        'error' => '',
        'errno' => 0,
        'cert' => $sslOptions['peer_certificate'] ?? null,
        'chain' => $sslOptions['peer_certificate_chain'] ?? [],
        'crypto' => $meta['crypto'] ?? []
    ];
}

function obtenerCertificadoDeCandidatos(array $hosts): array
{
    $intentos = [];

    foreach ($hosts as $host) {
        $verificada = conectarCertificado($host, true, 6);
        $intentos[] = [
            'host' => $host,
            'modo' => 'validación estricta PHP/OpenSSL',
            'ok' => $verificada['ok'],
            'error' => $verificada['error']
        ];

        if ($verificada['ok'] && $verificada['cert']) {
            return [
                'ok' => true,
                'host' => $host,
                'cert' => $verificada['cert'],
                'cadena_valida_local' => true,
                'conexion_verificada' => $verificada,
                'conexion_lectura' => $verificada,
                'intentos' => $intentos
            ];
        }

        $lectura = conectarCertificado($host, false, 6);
        $intentos[] = [
            'host' => $host,
            'modo' => 'lectura sin validación local',
            'ok' => $lectura['ok'],
            'error' => $lectura['error']
        ];

        if ($lectura['ok'] && $lectura['cert']) {
            return [
                'ok' => true,
                'host' => $host,
                'cert' => $lectura['cert'],
                'cadena_valida_local' => false,
                'conexion_verificada' => $verificada,
                'conexion_lectura' => $lectura,
                'intentos' => $intentos
            ];
        }
    }

    return [
        'ok' => false,
        'host' => '',
        'cert' => null,
        'cadena_valida_local' => false,
        'conexion_verificada' => ['ok' => false, 'error' => 'No ejecutada', 'chain' => [], 'crypto' => []],
        'conexion_lectura' => ['ok' => false, 'error' => 'No ejecutada', 'chain' => [], 'crypto' => []],
        'intentos' => $intentos
    ];
}

function tipoClavePublica(array $detalles): string
{
    $tipo = $detalles['type'] ?? null;
    $bits = isset($detalles['bits']) ? (int)$detalles['bits'] : 0;

    switch ($tipo) {
        case OPENSSL_KEYTYPE_RSA:
            return 'RSA ' . ($bits > 0 ? $bits . ' bits' : '');
        case OPENSSL_KEYTYPE_DSA:
            return 'DSA ' . ($bits > 0 ? $bits . ' bits' : '');
        case OPENSSL_KEYTYPE_DH:
            return 'DH ' . ($bits > 0 ? $bits . ' bits' : '');
        case OPENSSL_KEYTYPE_EC:
            return 'EC/ECDSA ' . ($bits > 0 ? $bits . ' bits' : '');
        default:
            return $bits > 0 ? 'Tipo no identificado, ' . $bits . ' bits' : 'N/D';
    }
}

function emisorCAComun(string $issuerTexto): bool
{
    $issuer = strtolower($issuerTexto);
    $casComunes = [
        "let's encrypt",
        'digicert',
        'globalsign',
        'sectigo',
        'google trust services',
        'cloudflare',
        'amazon',
        'microsoft',
        'entrust',
        'go daddy',
        'godaddy',
        'zerossl',
        'buypass',
        'ssl.com',
        'identrust',
        'usertrust',
        'comodoca',
        'comodorsa',
        'comodo',
        'trustasia',
        'quovadis',
        'geotrust',
        'thawte',
        'rapidssl',
        'certum',
        'harica',
        'd-trust',
        'r3',
        'e1',
        'e5'
    ];

    foreach ($casComunes as $ca) {
        if (strpos($issuer, $ca) !== false) {
            return true;
        }
    }

    return false;
}

function protocoloObsoleto(string $protocolo): bool
{
    $p = strtoupper($protocolo);
    return strpos($p, 'SSL') !== false || strpos($p, 'TLSV1.0') !== false || strpos($p, 'TLSV1.1') !== false || $p === 'TLSV1';
}

function prepararIntentosParaJson(array $intentos): array
{
    $salida = [];
    foreach ($intentos as $intento) {
        $salida[] = [
            'host' => (string)($intento['host'] ?? ''),
            'modo' => (string)($intento['modo'] ?? ''),
            'ok' => !empty($intento['ok']),
            'error' => (string)($intento['error'] ?? '')
        ];
    }
    return $salida;
}

$stmt = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($stmt, "i", $id);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$fila = mysqli_fetch_assoc($res);
mysqli_stmt_close($stmt);

if (!$fila) {
    die("Dominio no encontrado.");
}

$dominio = normalizarDominioSsl($fila['dominio']);
if ($dominio === false) {
    die("El dominio guardado no es válido.");
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-info border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 6 de 7</h4>
            <h2 class="text-info mb-4"><i class="bi bi-patch-check"></i> Candado HTTPS</h2>
            <p class="lead">Comprobando si la web usa un certificado HTTPS correcto: <strong><?= h($dominio) ?></strong></p>

            <div id="terminal" class="mt-4 mb-4" style="background:#0f172a;color:#dbeafe;padding:20px;font-family:'Consolas',monospace;border-radius:8px;height:380px;overflow-y:auto;box-shadow:inset 0 0 15px #000;font-size:0.9rem;border:1px solid #0dcaf0;scroll-behavior:smooth;">
                <?php
                while (ob_get_level() > 0) {
                    ob_end_flush();
                }
                ob_implicit_flush(true);

                $fecha = date("d/m/Y H:i:s");
                $problemasCriticos = [];
                $avisos = [];
                $notas = [];
                $certInfo = null;
                $hostComprobado = '';
                $certificadoEncontrado = false;
                $jsonResultado = [
                    'modulo' => 'certificado_ssl_tls',
                    'version' => 3,
                    'dominio_solicitado' => $dominio,
                    'host_comprobado' => '',
                    'puerto' => '443/HTTPS',
                    'fecha' => $fecha,
                    'certificado_encontrado' => false,
                    'cubre_host' => null,
                    'vigente' => null,
                    'autofirmado' => null,
                    'dias_restantes' => null,
                    'validacion_local_php_openssl' => 'No evaluada',
                    'ca_comun_reconocida_por_app' => null,
                    'riesgo_tecnico' => 'NO CONCLUYENTE',
                    'dictamen' => 'NO CONCLUYENTE',
                    'modifica_dictamen_global' => false,
                    'certificado' => [],
                    'conexion_https' => [],
                    'cobertura_dominio' => [],
                    'revision' => [
                        'problemas' => [],
                        'avisos' => [],
                        'notas' => []
                    ],
                    'intentos_conexion' => []
                ];

                echo "<span style='color:#ffffff;'>[INFO] Revisando el candado HTTPS de:</span> " . h($dominio) . "<br>";
                echo "[+] Comprobando si el certificado existe, pertenece a la web y no está caducado...<br>";
                flush();

                if (!extension_loaded('openssl')) {
                    echo "<span style='color:#ffc107;'>[AVISO] La extensión OpenSSL de PHP no está habilitada.</span><br>";
                    $avisos[] = "La extensión OpenSSL de PHP no está habilitada; no se pudo revisar el certificado.";
                } else {
                    $hosts = candidatosHttps($dominio);
                    $resultado = obtenerCertificadoDeCandidatos($hosts);
                    $jsonResultado['intentos_conexion'] = prepararIntentosParaJson($resultado['intentos']);

                    if (!$resultado['ok']) {
                        echo "<span style='color:#ffc107;'>[AVISO] No se pudo obtener certificado HTTPS.</span><br>";
                        $avisos[] = "No se pudo obtener un certificado HTTPS en el puerto 443 para el dominio ni para su variante www. Puede que el sitio no use HTTPS, bloquee la conexión o no sea accesible desde el entorno local.";
                    } else {
                        $hostComprobado = $resultado['host'];
                        $cert = $resultado['cert'];
                        $certInfo = openssl_x509_parse($cert);
                        $certificadoEncontrado = true;
                        $jsonResultado['certificado_encontrado'] = true;
                        $jsonResultado['host_comprobado'] = $hostComprobado;

                        if ($hostComprobado !== $dominio) {
                            $notas[] = "El dominio guardado era " . $dominio . ", pero se pudo comprobar correctamente " . $hostComprobado . ". Esto es habitual en webs pequeñas que solo tienen certificado configurado en www.";
                        }

                        if (!is_array($certInfo)) {
                            echo "<span style='color:#ffc107;'>[AVISO] El certificado se recibió, pero OpenSSL no pudo interpretarlo.</span><br>";
                            $avisos[] = "El certificado se recibió, pero OpenSSL no pudo interpretarlo.";
                        } else {
                            $sans = extraerSAN($certInfo);
                            $cubreHost = certificadoCubreDominio($hostComprobado, $certInfo, $sans);
                            $validFrom = $certInfo['validFrom_time_t'] ?? null;
                            $validTo = $certInfo['validTo_time_t'] ?? null;
                            $ahora = time();
                            $tieneFechas = is_numeric($validFrom) && is_numeric($validTo);
                            $vigente = $tieneFechas && (int)$validFrom <= $ahora && (int)$validTo >= $ahora;
                            $diasRestantes = is_numeric($validTo) ? (int)floor(((int)$validTo - $ahora) / 86400) : null;
                            $subjectTexto = valorCampoCertificado($certInfo, 'subject');
                            $issuerTexto = valorCampoCertificado($certInfo, 'issuer');
                            $autofirmado = ($subjectTexto !== 'N/D' && $issuerTexto !== 'N/D' && hash_equals($subjectTexto, $issuerTexto));
                            $cadenaValidaLocal = (bool)$resultado['cadena_valida_local'];
                            $conexionUsada = $resultado['conexion_lectura'];
                            $cadena = $conexionUsada['chain'] ?? [];
                            $crypto = $conexionUsada['crypto'] ?? [];
                            $fingerprint = function_exists('openssl_x509_fingerprint') ? openssl_x509_fingerprint($cert, 'sha256') : '';
                            $algoritmoFirma = (string)($certInfo['signatureTypeSN'] ?? ($certInfo['signatureTypeLN'] ?? 'N/D'));
                            $pkey = openssl_pkey_get_public($cert);
                            $detallesClave = $pkey ? openssl_pkey_get_details($pkey) : false;
                            $claveTexto = is_array($detallesClave) ? tipoClavePublica($detallesClave) : 'N/D';
                            $caComun = emisorCAComun($issuerTexto);
                            $protocoloNegociado = (string)($crypto['protocol'] ?? 'N/D');
                            $cnPrincipal = $certInfo['subject']['CN'] ?? 'N/D';
                            if (is_array($cnPrincipal)) {
                                $cnPrincipal = implode(', ', array_map('strval', $cnPrincipal));
                            }

                            $sanCoincidentes = [];
                            foreach ($sans as $san) {
                                if (dominioCoincideConPatron($hostComprobado, $san)) {
                                    $sanCoincidentes[] = $san;
                                }
                            }

                            if (!$cadenaValidaLocal) {
                                $notas[] = "Validación local PHP/OpenSSL no concluyente. No se considera riesgo por sí solo porque puede depender del almacén de certificados del equipo.";
                            }
                            if (!$caComun) {
                                $notas[] = "Emisor no incluido en la lista corta interna de CA comunes. Dato informativo; no implica certificado malo.";
                            }
                            if (!$cubreHost) {
                                $problemasCriticos[] = "El certificado obtenido no cubre el host comprobado (" . $hostComprobado . ").";
                            }
                            if (!$tieneFechas) {
                                $avisos[] = "No se pudieron leer correctamente las fechas de validez del certificado.";
                            } elseif (!$vigente) {
                                if ((int)$validTo < $ahora) {
                                    $problemasCriticos[] = "El certificado está caducado.";
                                } elseif ((int)$validFrom > $ahora) {
                                    $problemasCriticos[] = "El certificado todavía no es válido porque su fecha de inicio es futura.";
                                }
                            }
                            if ($autofirmado && !$cadenaValidaLocal) {
                                $problemasCriticos[] = "El certificado parece autofirmado y no fue validado como confiable por PHP/OpenSSL.";
                            } elseif ($autofirmado) {
                                $avisos[] = "El sujeto y el emisor coinciden. Conviene revisarlo, aunque no se marca como crítico porque la cadena local fue aceptada.";
                            }
                            if (is_int($diasRestantes) && $diasRestantes >= 0 && $diasRestantes <= 14) {
                                $avisos[] = "El certificado caduca pronto: quedan " . $diasRestantes . " días.";
                            }
                            if (stripos($algoritmoFirma, 'sha1') !== false || stripos($algoritmoFirma, 'md5') !== false) {
                                $problemasCriticos[] = "El certificado usa un algoritmo de firma débil o antiguo: " . $algoritmoFirma . ".";
                            }
                            if (is_array($detallesClave) && ($detallesClave['type'] ?? null) === OPENSSL_KEYTYPE_RSA && isset($detallesClave['bits']) && (int)$detallesClave['bits'] < 2048) {
                                $problemasCriticos[] = "La clave RSA es menor de 2048 bits.";
                            }
                            if (protocoloObsoleto($protocoloNegociado)) {
                                $problemasCriticos[] = "La conexión negoció un protocolo obsoleto: " . $protocoloNegociado . ".";
                            }

                            $jsonResultado['cubre_host'] = $cubreHost;
                            $jsonResultado['vigente'] = $vigente;
                            $jsonResultado['autofirmado'] = $autofirmado;
                            $jsonResultado['dias_restantes'] = $diasRestantes;
                            $jsonResultado['validacion_local_php_openssl'] = $cadenaValidaLocal ? 'Correcta' : 'No concluyente';
                            $jsonResultado['ca_comun_reconocida_por_app'] = $caComun;
                            $jsonResultado['certificado'] = [
                                'cn' => (string)$cnPrincipal,
                                'sujeto_completo' => $subjectTexto,
                                'emisor' => $issuerTexto,
                                'valido_desde' => formatoFechaCert($validFrom),
                                'valido_hasta' => formatoFechaCert($validTo),
                                'algoritmo_firma' => $algoritmoFirma,
                                'clave_publica' => $claveTexto,
                                'huella_sha256' => $fingerprint ?: 'N/D',
                                'numero_serie' => (string)($certInfo['serialNumberHex'] ?? ($certInfo['serialNumber'] ?? 'N/D')),
                                'openssl_parseado' => $certInfo
                            ];
                            $jsonResultado['conexion_https'] = [
                                'protocolo_tls_negociado' => $protocoloNegociado,
                                'cifrado_negociado' => (string)($crypto['cipher_name'] ?? 'N/D'),
                                'certificados_cadena_recibida' => is_array($cadena) ? count($cadena) : 0
                            ];
                            $jsonResultado['cobertura_dominio'] = [
                                'cn_evaluado' => (string)$cnPrincipal,
                                'san_dns_encontrados' => count($sans),
                                'san_dns_coincidentes' => $sanCoincidentes,
                                'san_dns' => $sans
                            ];

                            echo "<br><span style='color:#ffffff;'>[RESUMEN]</span><br>";
                            echo "- Certificado encontrado: <strong>Sí</strong><br>";
                            echo "- Pertenece a la web: <strong>" . ($cubreHost ? "Sí" : "No") . "</strong><br>";
                            echo "- No está caducado: <strong>" . ($vigente ? "Sí" : "No") . "</strong><br>";
                            if (is_int($diasRestantes)) {
                                echo "- Caducidad: <strong>" . ($diasRestantes >= 0 ? "caduca en " . $diasRestantes . " días" : "caducado") . "</strong><br>";
                            }
                            flush();
                        }
                    }
                }

                if ($certInfo === null && empty($avisos) && empty($problemasCriticos)) {
                    $avisos[] = "No se pudo obtener información útil del certificado.";
                }

                if ($certInfo === null) {
                    $nivelRiesgoFinal = 'NO CONCLUYENTE';
                    $dictamenModulo = 'NO CONCLUYENTE';
                } elseif (!empty($problemasCriticos)) {
                    $nivelRiesgoFinal = 'ALTO';
                    $dictamenModulo = 'REVISAR CONFIGURACIÓN SSL/TLS';
                } elseif (!empty($avisos)) {
                    $nivelRiesgoFinal = 'MEDIO';
                    $dictamenModulo = 'CERTIFICADO ACEPTABLE, CON AVISOS';
                } else {
                    $nivelRiesgoFinal = 'BAJO';
                    $dictamenModulo = 'CERTIFICADO TÉCNICAMENTE CORRECTO';
                }

                $jsonResultado['riesgo_tecnico'] = $nivelRiesgoFinal;
                $jsonResultado['dictamen'] = $dictamenModulo;
                $jsonResultado['revision'] = [
                    'problemas' => array_values($problemasCriticos),
                    'avisos' => array_values($avisos),
                    'notas' => array_values($notas)
                ];

                if ($nivelRiesgoFinal === 'BAJO') {
                    echo "<br><span style='color:#00ff00;'>[OK] El candado HTTPS no muestra problemas importantes.</span>";
                } elseif ($nivelRiesgoFinal === 'NO CONCLUYENTE') {
                    echo "<br><span style='color:#ffc107;'>[INFO] No se pudo comprobar bien el candado HTTPS.</span>";
                } else {
                    echo "<br><span style='color:#ffc107;'>[AVISO] El candado HTTPS tiene avisos. Se mostrarán de forma sencilla en el informe.</span>";
                }

                $resultadoGuardar = json_encode($jsonResultado, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
                if ($resultadoGuardar === false) {
                    $resultadoGuardar = json_encode([
                        'modulo' => 'certificado_ssl_tls',
                        'version' => 3,
                        'dominio_solicitado' => $dominio,
                        'fecha' => $fecha,
                        'riesgo_tecnico' => 'NO CONCLUYENTE',
                        'dictamen' => 'Error al serializar el resultado del certificado',
                        'modifica_dictamen_global' => false
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                }

                $stmtDelete = mysqli_prepare($conn, "DELETE FROM osint_resultados WHERE id_historial = ? AND herramienta = 'Certificado'");
                mysqli_stmt_bind_param($stmtDelete, "i", $id);
                mysqli_stmt_execute($stmtDelete);
                mysqli_stmt_close($stmtDelete);

                $stmtInsert = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Certificado', ?)");
                mysqli_stmt_bind_param($stmtInsert, "is", $id, $resultadoGuardar);
                mysqli_stmt_execute($stmtInsert);
                mysqli_stmt_close($stmtInsert);

                echo "<br><br><span style='color:#00ff00;'>[OK] Comprobación del candado HTTPS finalizada. Continuando con puertos...</span>";
                ?>
            </div>

            <div class="progress" style="height: 12px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-info w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="nextStepCertificate" action="puertos.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= (int)$id ?>">
</form>

<script>
    const terminal = document.getElementById('terminal');
    terminal.scrollTop = terminal.scrollHeight;

    setTimeout(function () {
        document.getElementById('nextStepCertificate').submit();
    }, 1400);
</script>

<?php require_once '../includes/footer.php'; ?>
