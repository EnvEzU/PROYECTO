<?php
// Archivo: osint/analizar_url.php
session_start();
require_once '../config/conexion.php';

// NOTA: Hemos quitado el bloqueo de seguridad para permitir acceso público.

$error = "";
$id_analisis = null;

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $dominio = trim($_POST['dominio']);
    
    if (empty($dominio)) {
        $error = "Introduce un dominio válido.";
    } else {
        // Lógica Híbrida: ¿Es usuario o invitado?
        if (isset($_SESSION['id_usuario'])) {
            $id_usuario = $_SESSION['id_usuario'];
            // SQL para Usuario Registrado
            $sql = "INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles) VALUES (?, ?, 'sospechosa', 'Análisis manual')";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "is", $id_usuario, $dominio);
        } else {
            // SQL para Invitado (id_usuario es NULL)
            $sql = "INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles) VALUES (NULL, ?, 'sospechosa', 'Análisis anónimo')";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "s", $dominio);
        }
        
        if (mysqli_stmt_execute($stmt)) {
            $id_analisis = mysqli_insert_id($conn);
            
            // REEMPLAZO DEL HEADER POR AUTO-POST
            // Imprimimos el formulario y el script de envío inmediato
            ?>
            <!DOCTYPE html>
            <html lang="es">
            <body>
                <form id="startPost" action="virus_total.php" method="POST">
                    <input type="hidden" name="id_historial" value="<?= $id_analisis ?>">
                </form>
                <script>
                    document.getElementById('startPost').submit();
                </script>
            </body>
            </html>
            <?php
            exit;
            
        } else {
            $error = "Error al guardar: " . mysqli_error($conn);
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
                <?php if(!isset($_SESSION['id_usuario'])): ?>
                    <small class="text-white-50">(Modo Invitado)</small>
                <?php endif; ?>
            </div>
            <div class="card-body p-4">
                <?php if($error): ?><div class="alert alert-danger"><?= $error ?></div><?php endif; ?>
                
                <form method="POST">
                    <div class="mb-4">
                        <label class="form-label fw-bold">Dominio</label>
                        <div class="input-group input-group-lg">
                            <span class="input-group-text"><i class="bi bi-globe"></i></span>
                            <input type="text" class="form-control" name="dominio" placeholder="google.com" required autofocus>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary btn-lg w-100">Escanear</button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>