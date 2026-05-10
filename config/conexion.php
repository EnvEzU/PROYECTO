<?php
// Archivo: config/conexion.php

$servidor   = "localhost";
$usuario    = "root";         // Usuario de XAMPP por defecto
$password   = "";             // Contraseña vacía por defecto
$base_datos = "virustotal_osint";

$conn = mysqli_connect($servidor, $usuario, $password, $base_datos);

// Verificar conexión
if (!$conn) {
    // En producción no se debe mostrar el error exacto, pero para desarrollo (TFG) está bien.
    die("Error crítico de conexión: " . mysqli_connect_error());
}

// Forzar UTF-8 para evitar problemas con tildes y ñ
mysqli_set_charset($conn, "utf8mb4");

function pavonSqlSeguro(mysqli $conn, string $sql): bool
{
    try {
        return (bool)mysqli_query($conn, $sql);
    } catch (mysqli_sql_exception $e) {
        return false;
    }
}

/**
 * Pequeñas migraciones defensivas para que el proyecto funcione aunque la base de datos
 * ya existiera antes de añadir tokens de informe, estado no concluyente o el módulo SSL/TLS.
 * No crean datos nuevos: solo aseguran columnas/tipos compatibles.
 */
function pavonColumnaExiste(mysqli $conn, string $tabla, string $columna): bool
{
    try {
        $sql = "SELECT COUNT(*) AS total
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = ?
                  AND COLUMN_NAME = ?";
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            return false;
        }

        mysqli_stmt_bind_param($stmt, "ss", $tabla, $columna);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        $fila = mysqli_fetch_assoc($res);
        mysqli_stmt_close($stmt);

        return isset($fila['total']) && (int)$fila['total'] > 0;
    } catch (mysqli_sql_exception $e) {
        return false;
    }
}

function pavonIndiceExiste(mysqli $conn, string $tabla, string $indice): bool
{
    try {
        $sql = "SELECT COUNT(*) AS total
                FROM INFORMATION_SCHEMA.STATISTICS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = ?
                  AND INDEX_NAME = ?";
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            return false;
        }

        mysqli_stmt_bind_param($stmt, "ss", $tabla, $indice);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        $fila = mysqli_fetch_assoc($res);
        mysqli_stmt_close($stmt);

        return isset($fila['total']) && (int)$fila['total'] > 0;
    } catch (mysqli_sql_exception $e) {
        return false;
    }
}

function pavonTipoColumna(mysqli $conn, string $tabla, string $columna): string
{
    try {
        $sql = "SELECT COLUMN_TYPE
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = ?
                  AND COLUMN_NAME = ?
                LIMIT 1";
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            return '';
        }

        mysqli_stmt_bind_param($stmt, "ss", $tabla, $columna);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        $fila = mysqli_fetch_assoc($res);
        mysqli_stmt_close($stmt);

        return (string)($fila['COLUMN_TYPE'] ?? '');
    } catch (mysqli_sql_exception $e) {
        return '';
    }
}

function pavonInicializarEsquema(mysqli $conn): void
{
    // Estado adicional para diferenciar una API caída de una detección sospechosa real.
    $tipoEstado = pavonTipoColumna($conn, 'historial_dominios', 'estado');
    if ($tipoEstado !== '' && strpos($tipoEstado, 'no_concluyente') === false) {
        pavonSqlSeguro($conn, "ALTER TABLE historial_dominios MODIFY estado ENUM('segura','maliciosa','sospechosa','no_concluyente') DEFAULT 'no_concluyente'");
    }

    // Token público para evitar enumeración directa de informes por ID.
    if (!pavonColumnaExiste($conn, 'historial_dominios', 'token_publico')) {
        pavonSqlSeguro($conn, "ALTER TABLE historial_dominios ADD COLUMN token_publico VARCHAR(64) DEFAULT NULL AFTER fecha_escaneo");
    }

    if (pavonColumnaExiste($conn, 'historial_dominios', 'token_publico') && !pavonIndiceExiste($conn, 'historial_dominios', 'idx_historial_token_publico')) {
        pavonSqlSeguro($conn, "ALTER TABLE historial_dominios ADD UNIQUE KEY idx_historial_token_publico (token_publico)");
    }

    // Control interno: un análisis solo aparece en historial cuando llega al último paso.
    if (!pavonColumnaExiste($conn, 'historial_dominios', 'analisis_completo')) {
        pavonSqlSeguro($conn, "ALTER TABLE historial_dominios ADD COLUMN analisis_completo TINYINT(1) NOT NULL DEFAULT 0 AFTER token_publico");
    }

    if (pavonColumnaExiste($conn, 'historial_dominios', 'analisis_completo') && !pavonIndiceExiste($conn, 'historial_dominios', 'idx_historial_completo')) {
        pavonSqlSeguro($conn, "ALTER TABLE historial_dominios ADD KEY idx_historial_completo (analisis_completo)");
    }

    if (pavonColumnaExiste($conn, 'historial_dominios', 'analisis_completo')) {
        pavonSqlSeguro($conn, "
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

    // El resultado del certificado se guarda en JSON dentro del longtext existente.
    if (pavonColumnaExiste($conn, 'osint_resultados', 'resultado_completo')) {
        pavonSqlSeguro($conn, "ALTER TABLE osint_resultados MODIFY resultado_completo LONGTEXT DEFAULT NULL");
    }

    if (pavonColumnaExiste($conn, 'osint_resultados', 'herramienta')) {
        pavonSqlSeguro($conn, "ALTER TABLE osint_resultados MODIFY herramienta VARCHAR(50) DEFAULT NULL");
    }
}

pavonInicializarEsquema($conn);
?>
