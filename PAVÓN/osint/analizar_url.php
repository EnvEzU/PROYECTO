<?php
session_start();
require_once '../config/conexion.php';

// Seguridad: Verificar si el usuario está logueado
if (!isset($_SESSION['id_usuario'])) {
    header("Location: ../auth/login.php");
    exit;
}

$mensaje = "";
$error = "";

// Procesar el formulario cuando se envía
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Limpiar el dato de entrada
    $dominio = trim($_POST['dominio']);
    
    // Validación básica
    if (empty($dominio)) {
        $error = "Por favor, introduce un dominio o IP válida.";
    } else {
        // 1. Insertamos en el historial como 'pendiente' o 'sospechosa'
        // Nota: Usamos 'sospechosa' como estado inicial por defecto según tu SQL, 
        // pero idealmente podrías añadir un estado 'analizando'.
        $id_usuario = $_SESSION['id_usuario'];
        $estado_inicial = 'sospechosa'; 
        $detalles = 'Análisis iniciado manualmente.';

        $sql = "INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles) VALUES (?, ?, ?, ?)";
        
        if ($stmt = mysqli_prepare($conn, $sql)) {
            mysqli_stmt_bind_param($stmt, "isss", $id_usuario, $dominio, $estado_inicial, $detalles);
            
            if (mysqli_stmt_execute($stmt)) {
                // Obtenemos el ID del análisis recién creado
                $id_analisis = mysqli_insert_id($conn);
                
                // 2. Aquí es donde llamaríamos a las herramientas (VirusTotal, Whois, etc.)
                // Por ahora, redirigimos al script de procesamiento de VirusTotal pasando el ID
                // para que haga el trabajo sucio y actualice la DB.
                header("Location: virus_total.php?id_historial=" . $id_analisis);
                exit;
            } else {
                $error = "Error al guardar en base de datos: " . mysqli_error($conn);
            }
            mysqli_stmt_close($stmt);
        }
    }
}

// Configuración de ruta para el header (estamos en subcarpeta /osint/)
$ruta_base = "../";
?>

<?php require_once '../includes/header.php'; ?>

<div class="row justify-content-center">
    <div class="col-md-8 col-lg-6">
        
        <div class="card shadow-lg border-0 mt-4">
            <div class="card-header bg-primary text-white text-center py-4">
                <h3 class="mb-0"><i class="bi bi-search"></i> Nuevo Análisis OSINT</h3>
                <p class="mb-0 opacity-75">Introduce un dominio para escanear</p>
            </div>
            
            <div class="card-body p-4">
                
                <?php if(!empty($error)): ?>
                    <div class="alert alert-danger d-flex align-items-center" role="alert">
                        <i class="bi bi-exclamation-triangle-fill me-2"></i>
                        <div><?= $error ?></div>
                    </div>
                <?php endif; ?>

                <form method="POST" action="">
                    <div class="mb-4">
                        <label for="dominio" class="form-label fw-bold">Dominio o Dirección IP</label>
                        <div class="input-group input-group-lg">
                            <span class="input-group-text bg-light"><i class="bi bi-globe"></i></span>
                            <input type="text" 
                                   class="form-control" 
                                   id="dominio" 
                                   name="dominio" 
                                   placeholder="ejemplo: google.com" 
                                   required 
                                   autofocus>
                        </div>
                        <div class="form-text text-muted">
                            Se ejecutarán automáticamente: VirusTotal, Whois y Reputación.
                        </div>
                    </div>

                    <div class="d-grid gap-2">
                        <button type="submit" class="btn btn-primary btn-lg">
                            <i class="bi bi-radar"></i> Iniciar Escaneo
                        </button>
                        <a href="../index.php" class="btn btn-outline-secondary">Cancelar</a>
                    </div>
                </form>

            </div>
            <div class="card-footer text-center text-muted bg-light py-3">
                <small><i class="bi bi-shield-lock"></i> Sistema Seguro de Vigilancia de Dominios</small>
            </div>
        </div>

    </div>
</div>

<?php require_once '../includes/footer.php'; ?>