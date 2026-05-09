<?php
session_start();
$ruta_base = "./";
require_once 'includes/header.php';
?>

<div class="px-4 py-5 my-5 text-center">
    <h1 class="display-5 fw-bold text-body-emphasis">Sistema de Vigilancia de Dominios</h1>
    <div class="col-lg-6 mx-auto">
        <p class="lead mb-4">Herramienta OSINT para el análisis de seguridad y detección de amenazas en dominios.</p>
        
        <div class="d-grid gap-2 d-sm-flex justify-content-sm-center">
            
            <a href="osint/analizar_url.php" class="btn btn-primary btn-lg px-4 gap-3">
                <i class="bi bi-search"></i> Analizar Dominio
            </a>

            <?php if(isset($_SESSION['id_usuario'])): ?>
                <a href="resultados/historial.php" class="btn btn-outline-secondary btn-lg px-4">
                    <i class="bi bi-clock-history"></i> Mi Historial
                </a>
            <?php else: ?>
                <a href="auth/login.php" class="btn btn-outline-dark btn-lg px-4">
                    <i class="bi bi-person"></i> Iniciar Sesión
                </a>
            <?php endif; ?>

        </div>
    </div>
</div>

<div class="row g-4 py-5 row-cols-1 row-cols-lg-3">
    <div class="col text-center">
        <h3><i class="bi bi-virus text-danger"></i> VirusTotal</h3>
        <p>Escaneo de malware y reputación.</p>
    </div>
    <div class="col text-center">
        <h3><i class="bi bi-globe text-primary"></i> WHOIS</h3>
        <p>Información del registro del dominio.</p>
    </div>
    <div class="col text-center">
        <h3><i class="bi bi-file-earmark-pdf text-success"></i> Reportes</h3>
        <p>Descarga de informes (Solo registrados).</p>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>