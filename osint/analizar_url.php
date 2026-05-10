<?php
session_start();
require_once '../config/conexion.php';
require_once '../includes/seguridad.php';

$error = "";
$id_analisis = null;

// Estado adicional para evitar falsos positivos cuando una API no devuelve datos.
if (function_exists('pavonSqlSeguro')) {
    pavonSqlSeguro($conn, "ALTER TABLE historial_dominios MODIFY estado ENUM('segura','maliciosa','sospechosa','no_concluyente') DEFAULT 'no_concluyente'");
}
asegurarColumnaAnalisisCompleto($conn);
limpiarAnalisisIncompletosAntiguos($conn, 60);

/**
 * Limpia y normaliza un dominio.
 * Ejemplos:
 *  - https://Google.com/login -> google.com
 *  - http://paypal.com/ -> paypal.com
 *  - google.com -> google.com
 */
function normalizarDominio(string $entrada)
{
    $dominio = trim($entrada);

    if ($dominio === '') {
        return false;
    }

    // Quitar protocolo
    $dominio = preg_replace('~^https?://~i', '', $dominio);

    // Quitar www.
    $dominio = preg_replace('~^www\.~i', '', $dominio);

    // Quitar ruta, query o fragmento
    $dominio = preg_replace('~[/?#].*$~', '', $dominio);

    // Quitar espacios laterales y pasar a minúsculas
    $dominio = strtolower(trim($dominio));

    // Quitar punto final si existe
    $dominio = rtrim($dominio, '.');

    if ($dominio === '') {
        return false;
    }

    // Validar como hostname/dominio
    if (!filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return false;
    }

    return $dominio;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $entradaDominio = $_POST['dominio'] ?? '';
    $dominio = normalizarDominio($entradaDominio);

    if ($dominio === false) {
        $error = "Introduce un dominio válido. Ejemplo: google.com";
    } else {
        $token_publico = generarTokenPublicoAnalisis();

        if (isset($_SESSION['id_usuario'])) {
            $id_usuario = (int)$_SESSION['id_usuario'];

            $sql = "INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles, token_publico, analisis_completo) 
                    VALUES (?, ?, 'no_concluyente', 'Análisis manual', ?, 0)";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "iss", $id_usuario, $dominio, $token_publico);
        } else {
            $sql = "INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles, token_publico, analisis_completo) 
                    VALUES (NULL, ?, 'no_concluyente', 'Análisis anónimo', ?, 0)";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "ss", $dominio, $token_publico);
        }

        if ($stmt && mysqli_stmt_execute($stmt)) {
            $id_analisis = mysqli_insert_id($conn);
            registrarAnalisisPermitido((int)$id_analisis);
            mysqli_stmt_close($stmt);
            ?>
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Iniciando análisis...</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-dark text-light d-flex align-items-center justify-content-center min-vh-100">
                <div class="text-center">
                    <div class="spinner-border text-primary mb-3" role="status"></div>
                    <h4>Iniciando análisis de <?= htmlspecialchars($dominio) ?></h4>
                    <p class="text-secondary mb-0">Redirigiendo al escaneo de VirusTotal...</p>
                </div>

                <form id="startPost" action="virus_total.php" method="POST">
                    <input type="hidden" name="id_historial" value="<?= (int)$id_analisis ?>">
                </form>

                <script>
                    setTimeout(function () {
                        document.getElementById('startPost').submit();
                    }, 700);
                </script>
            </body>
            </html>
            <?php
            exit;
        } else {
            $error = "Error al guardar el análisis.";
        }
    }
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-md-8 col-lg-6">
        <div class="card shadow mt-4 border-0">
            <div class="card-header bg-primary text-white text-center py-4">
                <h3 class="mb-0">Nuevo Análisis OSINT</h3>
                <?php if (!isset($_SESSION['id_usuario'])): ?>
                    <small class="text-white-50">(Modo Invitado)</small>
                <?php endif; ?>
            </div>

            <div class="card-body p-4">
                <?php if ($error): ?>
                    <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>

                <form method="POST" autocomplete="off">
                    <div class="mb-4">
                        <label class="form-label fw-bold">Dominio</label>
                        <div class="input-group input-group-lg">
                            <span class="input-group-text"><i class="bi bi-globe"></i></span>
                            <input
                                type="text"
                                class="form-control"
                                name="dominio"
                                placeholder="google.com"
                                required
                                autofocus
                            >
                        </div>
                        <div class="form-text">
                            Puedes introducir un dominio normal o una URL. El informe solo se guardará si el análisis termina completo.
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary btn-lg w-100">
                        Escanear
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>
