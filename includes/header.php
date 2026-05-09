<?php
if (!isset($ruta_base)) {
    $ruta_base = './';
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Panel OSINT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .content-wrapper {
            flex: 1;
        }

        .navbar-brand {
            font-weight: 700;
            letter-spacing: 0.3px;
        }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4 shadow-sm">
    <div class="container">
        <a class="navbar-brand" href="<?= $ruta_base ?>index.php">
            <i class="bi bi-shield-lock me-2"></i>OSINT TFG
        </a>

        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarPrincipal" aria-controls="navbarPrincipal" aria-expanded="false" aria-label="Mostrar navegación">
            <span class="navbar-toggler-icon"></span>
        </button>

        <div class="collapse navbar-collapse" id="navbarPrincipal">
            <ul class="navbar-nav me-auto">
                <li class="nav-item">
                    <a class="nav-link" href="<?= $ruta_base ?>index.php">
                        <i class="bi bi-house-door me-1"></i>Inicio
                    </a>
                </li>

                <li class="nav-item">
                    <a class="nav-link" href="<?= $ruta_base ?>osint/analizar_url.php">
                        <i class="bi bi-search me-1"></i>Analizar
                    </a>
                </li>

                <?php if (isset($_SESSION['id_usuario'])): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="<?= $ruta_base ?>resultados/historial.php">
                            <i class="bi bi-clock-history me-1"></i>Historial
                        </a>
                    </li>
                <?php endif; ?>

            </ul>

            <ul class="navbar-nav">
                <?php if (isset($_SESSION['usuario'])): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="bi bi-person-circle me-1"></i><?= htmlspecialchars($_SESSION['usuario']) ?>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end shadow-sm">
                            <?php if (isset($_SESSION['rol']) && $_SESSION['rol'] === 'admin'): ?>
                                <li>
                                    <a class="dropdown-item" href="<?= $ruta_base ?>admin/panel_admin.php">
                                        <i class="bi bi-speedometer2 me-2"></i>Panel admin
                                    </a>
                                </li>
                                <li><hr class="dropdown-divider"></li>
                            <?php endif; ?>

                            <li>
                                <a class="dropdown-item text-danger" href="<?= $ruta_base ?>auth/logout.php">
                                    <i class="bi bi-box-arrow-right me-2"></i>Salir
                                </a>
                            </li>
                        </ul>
                    </li>
                <?php else: ?>
                    <li class="nav-item">
                        <a class="nav-link" href="<?= $ruta_base ?>auth/login.php">
                            <i class="bi bi-box-arrow-in-right me-1"></i>Entrar
                        </a>
                    </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<div class="container content-wrapper">