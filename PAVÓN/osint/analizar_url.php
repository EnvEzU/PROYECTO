<?php
// Archivo: osint/analizar_url.php
session_start();
require_once '../config/conexion.php';

// NOTA: Hemos quitado el bloqueo de seguridad para permitir acceso público.

$error = "";
$id_analisis = null;

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $entrada = trim($_POST['dominio']);

    if (empty($entrada)) {
        $error = "Introduce un dominio o URL válida.";
    } else {
        // Normalizar entrada: aceptar dominio o URL completa
        $dominio = $entrada;

        // Si no lleva esquema, añadimos uno temporal para parsear bien el host
        $url_para_parsear = $entrada;
        if (!preg_match('#^https?://#i', $entrada)) {
            $url_para_parsear = 'https://' . $entrada;
        }

        $host = parse_url($url_para_parsear, PHP_URL_HOST);

        // Si viene una URL, nos quedamos con el host
        if (!empty($host)) {
            $dominio = $host;
        }

        // Normalización básica
        $dominio = strtolower(trim($dominio));
        $dominio = preg_replace('/^www\./i', '', $dominio);
        $dominio = preg_replace('/:\d+$/', '', $dominio); // quitar puerto

        // Validación final
        if (!filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            $error = "Introduce un dominio o URL válida.";
        } else {
            // Lógica Híbrida: ¿Es usuario o invitado?
            if (isset($_SESSION['id_usuario'])) {
                $id_usuario = $_SESSION['id_usuario'];
                $sql = "INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles) VALUES (?, ?, 'sospechosa', 'Análisis manual')";
                $stmt = mysqli_prepare($conn, $sql);
                mysqli_stmt_bind_param($stmt, "is", $id_usuario, $dominio);
            } else {
                $sql = "INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles) VALUES (NULL, ?, 'sospechosa', 'Análisis anónimo')";
                $stmt = mysqli_prepare($conn, $sql);
                mysqli_stmt_bind_param($stmt, "s", $dominio);
            }

            if (mysqli_stmt_execute($stmt)) {
                $id_analisis = mysqli_insert_id($conn);
            } else {
                $error = "Error al guardar: " . mysqli_error($conn);
            }
        }
    }
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="row justify-content-center">
    <div class="col-md-8 col-lg-6">
        <div class="card shadow mt-4">
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

                <?php if ($id_analisis): ?>
                    <div class="alert alert-success">
                        Dominio preparado correctamente. Iniciando análisis...
                    </div>

                    <form id="autoPostVirusTotal" action="virus_total.php" method="POST">
                        <input type="hidden" name="id_historial" value="<?= (int)$id_analisis ?>">
                    </form>

                    <script>
                        document.getElementById('autoPostVirusTotal').submit();
                    </script>
                <?php else: ?>
                    <form method="POST">
                        <div class="mb-4">
                            <label class="form-label fw-bold">Dominio o URL</label>
                            <div class="input-group input-group-lg">
                                <span class="input-group-text"><i class="bi bi-globe"></i></span>
                                <input
                                    type="text"
                                    class="form-control"
                                    name="dominio"
                                    placeholder="google.com o https://google.com"
                                    required
                                    autofocus
                                >
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary btn-lg w-100">Escanear</button>
                    </form>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>
