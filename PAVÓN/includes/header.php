<?php
// Si no definimos la ruta base en el archivo principal, asumimos raíz "./"
if (!isset($ruta_base)) { $ruta_base = './'; }
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
        body { background-color: #f8f9fa; min-height: 100vh; display: flex; flex-direction: column; }
        .content-wrapper { flex: 1; }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container">
    <a class="navbar-brand" href="<?= $ruta_base ?>index.php">OSINT TFG</a>
    
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav me-auto">
        <li class="nav-item">
            <a class="nav-link" href="<?= $ruta_base ?>index.php">Inicio</a>
        </li>
        <?php if(isset($_SESSION['rol'])): ?>
            <li class="nav-item">
                <a class="nav-link" href="<?= $ruta_base ?>osint/analizar_url.php">Analizar</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="<?= $ruta_base ?>resultados/historial.php">Historial</a>
            </li>
        <?php endif; ?>
      </ul>
      
      <ul class="navbar-nav">
        <?php if(isset($_SESSION['usuario'])): ?>
            <li class="nav-item dropdown">
                <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                    <?= htmlspecialchars($_SESSION['usuario']) ?>
                </a>
                <ul class="dropdown-menu dropdown-menu-end">
                    <?php if($_SESSION['rol'] == 'admin'): ?>
                        <li><a class="dropdown-item" href="<?= $ruta_base ?>admin/panel_admin.php">Admin</a></li>
                    <?php endif; ?>
                    <li><a class="dropdown-item text-danger" href="<?= $ruta_base ?>auth/logout.php">Salir</a></li>
                </ul>
            </li>
        <?php else: ?>
            <li class="nav-item"><a class="nav-link" href="<?= $ruta_base ?>auth/login.php">Entrar</a></li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</nav>

<div class="container content-wrapper">