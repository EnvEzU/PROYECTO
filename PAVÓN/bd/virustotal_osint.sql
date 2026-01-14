-- 1. LIMPIEZA E INICIO
DROP DATABASE IF EXISTS virustotal_osint;
CREATE DATABASE virustotal_osint CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE virustotal_osint;

-- 2. CREACIÓN DE TABLAS

-- Tabla Usuarios
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- Aquí guardaremos el MD5
    rol ENUM('admin','usuario') DEFAULT 'usuario',
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Tabla Historial de Dominios
CREATE TABLE historial_dominios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario INT,
    dominio VARCHAR(255) NOT NULL,
    estado ENUM('segura','maliciosa','sospechosa') DEFAULT 'sospechosa',
    detalles TEXT,
    fecha_escaneo TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_historial_usuario FOREIGN KEY (id_usuario) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Tabla Resultados OSINT
CREATE TABLE osint_resultados (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_historial INT NOT NULL,
    herramienta VARCHAR(50),
    resultado_completo LONGTEXT,
    fecha_ejecucion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_osint_historial FOREIGN KEY (id_historial) REFERENCES historial_dominios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Tabla Historial de Accesos
CREATE TABLE historial_accesos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_usuario INT NOT NULL,
    ip_acceso VARCHAR(45),
    fecha_acceso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exito BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (id_usuario) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Tabla Errores
CREATE TABLE errores_sistema (
    id INT AUTO_INCREMENT PRIMARY KEY,
    archivo VARCHAR(100),
    mensaje TEXT,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 3. INSERCIÓN DE DATOS (SOLO ADMIN CON MD5)

-- Usuario: admin / Pass: 1234
INSERT INTO usuarios (usuario, email, password, rol) VALUES 
('Admin Supremo', 'admin@test.com', MD5('1234'), 'admin');

-- Insertamos datos de prueba vinculados al admin (ID 1)
INSERT INTO historial_dominios (id_usuario, dominio, estado, detalles) VALUES
(1, 'google.com', 'segura', 'Limpio según VirusTotal'),
(1, 'web-peligrosa.net', 'maliciosa', 'Detectado malware');

INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES
(1, 'VirusTotal', '{"scan_id": "12345", "positives": 0}'),
(2, 'VirusTotal', '{"scan_id": "67890", "positives": 15}');