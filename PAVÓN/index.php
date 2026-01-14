<?php
// Archivo: index.php (En la raíz)
session_start();

// 1. Seguridad: Si no está logueado, lo mandamos al login
if (!isset($_SESSION['id_usuario'])) {
    header("Location: auth/login.php");
    exit;
}

// 2. Configuración de rutas
// Como index.php está en la raíz, la ruta base es "./"
$ruta_base = "./";

// 3. Incluimos la cabecera
require_once 'includes/header.php';
?>

<div class="row text-center">
    <div class="col-12 mb-4">
        <h1 class="display-4">Bienvenido al Panel OSINT</h1>
        <p class="lead">Herramientas de ciberseguridad para análisis de dominios.</p>
    </div>
</div>

<div class="row g-4">
    <div class="col-md-6">
        <div class="card h-100 shadow-sm border-primary">
            <div class="card-body text-center">
                <h1 class="display-1 text-primary"><i class="bi bi-search"></i></h1>
                <h3 class="card-title">Analizar URL</h3>
                <p class="card-text">Escanea un dominio usando la API de VirusTotal, Whois y Reputation.</p>
                <a href="osint/analizar_url.php" class="btn btn-primary btn-lg">Nuevo Análisis</a>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="card h-100 shadow-sm border-secondary">
            <div class="card-body text-center">
                <h1 class="display-1 text-secondary"><i class="bi bi-clock-history"></i></h1>
                <h3 class="card-title">Mi Historial</h3>
                <p class="card-text">Revisa tus escaneos anteriores y exporta los reportes.</p>
                <a href="resultados/historial.php" class="btn btn-outline-secondary btn-lg">Ver Historial</a>
            </div>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>