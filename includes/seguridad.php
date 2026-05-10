<?php

function generarTokenCsrf(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function campoCsrf(): string
{
    return '<input type="hidden" name="csrf_token" value="' .
        htmlspecialchars(generarTokenCsrf(), ENT_QUOTES, 'UTF-8') .
        '">';
}

function validarCsrf(): bool
{
    return isset($_POST['csrf_token'], $_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function esAdmin(): bool
{
    return isset($_SESSION['rol']) && $_SESSION['rol'] === 'admin';
}

function registrarAnalisisPermitido(int $id_historial): void
{
    if ($id_historial <= 0) {
        return;
    }

    if (!isset($_SESSION['analisis_permitidos']) || !is_array($_SESSION['analisis_permitidos'])) {
        $_SESSION['analisis_permitidos'] = [];
    }

    if (!in_array($id_historial, $_SESSION['analisis_permitidos'], true)) {
        $_SESSION['analisis_permitidos'][] = $id_historial;
    }
}




function consultaSeguraAnalisis(mysqli $conn, string $sql): bool
{
    if (function_exists('pavonSqlSeguro')) {
        return pavonSqlSeguro($conn, $sql);
    }

    try {
        return (bool)mysqli_query($conn, $sql);
    } catch (mysqli_sql_exception $e) {
        return false;
    }
}

function columnaHistorialExiste(mysqli $conn, string $columna): bool
{
    if (function_exists('pavonColumnaExiste')) {
        return pavonColumnaExiste($conn, 'historial_dominios', $columna);
    }

    try {
        $sql = "SELECT COUNT(*) AS total
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'historial_dominios'
                  AND COLUMN_NAME = ?";
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            return false;
        }

        mysqli_stmt_bind_param($stmt, "s", $columna);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        $fila = mysqli_fetch_assoc($res);
        mysqli_stmt_close($stmt);

        return isset($fila['total']) && (int)$fila['total'] > 0;
    } catch (mysqli_sql_exception $e) {
        return false;
    }
}

function asegurarColumnaAnalisisCompleto(mysqli $conn): void
{
    static $hecho = false;

    if ($hecho) {
        return;
    }

    // Marca interna para diferenciar análisis terminados de análisis cortados a medias.
    // Se comprueba antes de alterar la tabla para evitar el error de "Duplicate column name".
    if (!columnaHistorialExiste($conn, 'analisis_completo')) {
        consultaSeguraAnalisis($conn, "ALTER TABLE historial_dominios ADD COLUMN analisis_completo TINYINT(1) NOT NULL DEFAULT 0 AFTER token_publico");
    }

    if (columnaHistorialExiste($conn, 'analisis_completo')) {
        // Al actualizar una instalación antigua, no ocultamos informes que ya llegaron al último paso.
        consultaSeguraAnalisis($conn, "
            UPDATE historial_dominios h
            SET h.analisis_completo = 1
            WHERE h.analisis_completo = 0
              AND EXISTS (
                  SELECT 1
                  FROM osint_resultados r
                  WHERE r.id_historial = h.id
                    AND r.herramienta = 'Puertos'
              )
        ");
    }

    $hecho = true;
}

function limpiarAnalisisIncompletosAntiguos(mysqli $conn, int $minutos = 60): void
{
    asegurarColumnaAnalisisCompleto($conn);

    if (!columnaHistorialExiste($conn, 'analisis_completo')) {
        return;
    }

    $minutos = max(10, min(1440, $minutos));

    // Primero borramos resultados parciales y después la cabecera del historial.
    consultaSeguraAnalisis($conn, "
        DELETE r
        FROM osint_resultados r
        INNER JOIN historial_dominios h ON h.id = r.id_historial
        WHERE h.analisis_completo = 0
          AND h.fecha_escaneo < (NOW() - INTERVAL {$minutos} MINUTE)
    ");

    consultaSeguraAnalisis($conn, "
        DELETE FROM historial_dominios
        WHERE analisis_completo = 0
          AND fecha_escaneo < (NOW() - INTERVAL {$minutos} MINUTE)
    ");
}

function marcarAnalisisCompleto(mysqli $conn, int $id_historial): void
{
    if ($id_historial <= 0) {
        return;
    }

    asegurarColumnaAnalisisCompleto($conn);

    try {
        $stmt = mysqli_prepare($conn, "UPDATE historial_dominios SET analisis_completo = 1 WHERE id = ?");
        if (!$stmt) {
            return;
        }

        mysqli_stmt_bind_param($stmt, "i", $id_historial);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
    } catch (mysqli_sql_exception $e) {
        return;
    }
}

function analisisEstaCompleto(mysqli $conn, int $id_historial): bool
{
    if ($id_historial <= 0) {
        return false;
    }

    asegurarColumnaAnalisisCompleto($conn);

    try {
        $stmt = mysqli_prepare($conn, "SELECT analisis_completo FROM historial_dominios WHERE id = ? LIMIT 1");
        if (!$stmt) {
            return false;
        }

        mysqli_stmt_bind_param($stmt, "i", $id_historial);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        $fila = mysqli_fetch_assoc($res);
        mysqli_stmt_close($stmt);

        return $fila && (int)$fila['analisis_completo'] === 1;
    } catch (mysqli_sql_exception $e) {
        return false;
    }
}

function generarTokenPublicoAnalisis(): string
{
    return bin2hex(random_bytes(32));
}

function tokenReporteValido(string $token): bool
{
    return (bool)preg_match('/^[a-f0-9]{64}$/', $token);
}

function obtenerIdAnalisisPorToken(mysqli $conn, string $token): int
{
    $token = strtolower(trim($token));

    if (!tokenReporteValido($token)) {
        return 0;
    }

    $stmt = mysqli_prepare($conn, "SELECT id FROM historial_dominios WHERE token_publico = ? LIMIT 1");
    if (!$stmt) {
        return 0;
    }

    mysqli_stmt_bind_param($stmt, "s", $token);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $fila = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);

    return $fila ? (int)$fila['id'] : 0;
}

function asegurarTokenAnalisis(mysqli $conn, int $id_historial): string
{
    if ($id_historial <= 0) {
        return '';
    }

    $stmt = mysqli_prepare($conn, "SELECT token_publico FROM historial_dominios WHERE id = ? LIMIT 1");
    if (!$stmt) {
        return '';
    }

    mysqli_stmt_bind_param($stmt, "i", $id_historial);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $fila = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);

    if (!$fila) {
        return '';
    }

    $tokenActual = strtolower(trim((string)($fila['token_publico'] ?? '')));
    if (tokenReporteValido($tokenActual)) {
        return $tokenActual;
    }

    for ($i = 0; $i < 5; $i++) {
        $nuevoToken = generarTokenPublicoAnalisis();
        $stmtUpd = mysqli_prepare($conn, "UPDATE historial_dominios SET token_publico = ? WHERE id = ? AND (token_publico IS NULL OR token_publico = '')");
        if (!$stmtUpd) {
            return '';
        }

        mysqli_stmt_bind_param($stmtUpd, "si", $nuevoToken, $id_historial);
        $ok = mysqli_stmt_execute($stmtUpd);
        mysqli_stmt_close($stmtUpd);

        if ($ok) {
            return $nuevoToken;
        }
    }

    return '';
}

function urlInformeAnalisis(mysqli $conn, int $id_historial, string $extra = ''): string
{
    $token = asegurarTokenAnalisis($conn, $id_historial);

    if ($token === '') {
        return '#';
    }

    $url = 'ver_resultado.php?r=' . urlencode($token);
    if ($extra !== '') {
        $url .= $extra;
    }

    return $url;
}

function usuarioPuedeAccederAnalisis(mysqli $conn, int $id_historial): bool
{
    if ($id_historial <= 0) {
        return false;
    }

    $stmt = mysqli_prepare($conn, "SELECT id_usuario FROM historial_dominios WHERE id = ? LIMIT 1");
    if (!$stmt) {
        return false;
    }

    mysqli_stmt_bind_param($stmt, "i", $id_historial);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $fila = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);

    if (!$fila) {
        return false;
    }

    if (esAdmin()) {
        return true;
    }

    if ($fila['id_usuario'] !== null && isset($_SESSION['id_usuario'])) {
        return (int)$fila['id_usuario'] === (int)$_SESSION['id_usuario'];
    }

    $permitidos = $_SESSION['analisis_permitidos'] ?? [];

    return $fila['id_usuario'] === null
        && is_array($permitidos)
        && in_array($id_historial, $permitidos, true);
}
?>
