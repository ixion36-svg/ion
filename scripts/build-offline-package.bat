@echo off
REM =============================================================================
REM DocForge - Build Offline Deployment Package (Windows)
REM =============================================================================
REM Run this script on a machine WITH internet access to create an air-gapped
REM deployment package that can be transferred to the secure environment.
REM
REM Usage: build-offline-package.bat [version]
REM Example: build-offline-package.bat 1.0.0
REM =============================================================================

setlocal enabledelayedexpansion

set VERSION=%1
if "%VERSION%"=="" set VERSION=latest

set PACKAGE_NAME=docforge-offline-%VERSION%
set OUTPUT_DIR=dist\%PACKAGE_NAME%

echo ==============================================
echo Building DocForge Offline Package v%VERSION%
echo ==============================================

REM Create output directory
if exist "%OUTPUT_DIR%" rmdir /s /q "%OUTPUT_DIR%"
mkdir "%OUTPUT_DIR%"

REM Step 1: Build Docker image
echo.
echo [1/4] Building Docker image...
docker build -t docforge:%VERSION% -t docforge:latest .
if errorlevel 1 (
    echo ERROR: Docker build failed!
    exit /b 1
)

REM Step 2: Save Docker image as tar
echo.
echo [2/4] Exporting Docker image...
echo       This may take a few minutes...
docker save docforge:%VERSION% -o "%OUTPUT_DIR%\docforge-image-%VERSION%.tar"
if errorlevel 1 (
    echo ERROR: Docker save failed!
    exit /b 1
)

REM Compress the image
echo       Compressing image...
powershell -Command "Compress-Archive -Path '%OUTPUT_DIR%\docforge-image-%VERSION%.tar' -DestinationPath '%OUTPUT_DIR%\docforge-image-%VERSION%.zip' -Force"
del "%OUTPUT_DIR%\docforge-image-%VERSION%.tar"

REM Step 3: Copy deployment files
echo.
echo [3/4] Copying deployment files...
copy docker-compose.yml "%OUTPUT_DIR%\"
copy SETUP.md "%OUTPUT_DIR%\" 2>nul

REM Copy HTTPS deployment files
mkdir "%OUTPUT_DIR%\nginx" 2>nul
mkdir "%OUTPUT_DIR%\ssl" 2>nul
copy deploy\docker-compose.https.yml "%OUTPUT_DIR%\" 2>nul
copy deploy\nginx\nginx.conf "%OUTPUT_DIR%\nginx\" 2>nul
copy deploy\generate-certs.sh "%OUTPUT_DIR%\" 2>nul
copy deploy\DEPLOYMENT_GUIDE.md "%OUTPUT_DIR%\" 2>nul

REM Create deployment script for Linux target
(
echo #!/bin/bash
echo # DocForge Offline Deployment Script
echo # Run this on the air-gapped target machine
echo.
echo set -e
echo.
echo SCRIPT_DIR="$^(cd "$^(dirname "${BASH_SOURCE[0]}"^)" ^&^& pwd^)"
echo.
echo echo "=============================================="
echo echo "DocForge Offline Deployment"
echo echo "=============================================="
echo.
echo # Check for zip or tar.gz
echo if [ -f "${SCRIPT_DIR}/docforge-image-*.zip" ]; then
echo     echo "[1/3] Extracting and loading Docker image..."
echo     unzip -p "${SCRIPT_DIR}"/docforge-image-*.zip ^| docker load
echo elif [ -f "${SCRIPT_DIR}/docforge-image-*.tar.gz" ]; then
echo     echo "[1/3] Loading Docker image..."
echo     gunzip -c "${SCRIPT_DIR}"/docforge-image-*.tar.gz ^| docker load
echo elif [ -f "${SCRIPT_DIR}/docforge-image-*.tar" ]; then
echo     echo "[1/3] Loading Docker image..."
echo     docker load -i "${SCRIPT_DIR}"/docforge-image-*.tar
echo else
echo     echo "ERROR: No Docker image file found!"
echo     exit 1
echo fi
echo.
echo echo "[2/3] Initializing database..."
echo docker run --rm -v docforge-data:/data docforge:latest python -c "
echo from pathlib import Path
echo from docforge.storage.database import init_db
echo from docforge.core.config import Config
echo data_dir = Path('/data/.docforge')
echo data_dir.mkdir(parents=True, exist_ok=True)
echo db_path = data_dir / 'docforge.db'
echo if not db_path.exists():
echo     init_db(db_path)
echo     Config(db_path=db_path).to_file(data_dir / 'config.json')
echo     print('Database created')
echo "
echo.
echo echo "[3/3] Setting up authentication..."
echo docker run --rm -v docforge-data:/data docforge:latest python -c "
echo from pathlib import Path
echo from docforge.storage.database import get_engine, get_session_factory
echo from docforge.auth.service import AuthService
echo db_path = Path('/data/.docforge/docforge.db')
echo engine = get_engine(db_path)
echo session = get_session_factory(engine)()
echo auth = AuthService(session)
echo auth.seed_permissions()
echo auth.seed_roles()
echo auth.seed_admin_user(password='changeme')
echo session.commit()
echo print('Auth configured: admin / changeme')
echo "
echo.
echo echo "Deployment complete! Run: docker-compose up -d"
echo echo "Access: http://localhost:8000"
echo echo "Credentials: admin / changeme"
) > "%OUTPUT_DIR%\deploy.sh"

REM Create README
(
echo ================================================================================
echo DocForge Offline Deployment Package
echo ================================================================================
echo.
echo CONTENTS:
echo   - docforge-image-*.zip     : Docker image ^(compressed^)
echo   - docker-compose.yml       : Docker Compose configuration
echo   - deploy.sh               : Deployment script ^(Linux/Mac^)
echo.
echo QUICK START:
echo   1. Transfer this folder to the target machine
echo   2. Run: chmod +x deploy.sh ^&^& ./deploy.sh
echo   3. Run: docker-compose up -d
echo   4. Access: http://localhost:8000
echo.
echo DEFAULT CREDENTIALS:
echo   Username: admin
echo   Password: changeme
echo.
echo   *** CHANGE THIS PASSWORD IMMEDIATELY ***
echo.
echo ================================================================================
) > "%OUTPUT_DIR%\README.txt"

echo.
echo [4/4] Package created successfully!
echo.
echo Package location: %OUTPUT_DIR%
echo.
echo Contents:
dir "%OUTPUT_DIR%"
echo.
echo To deploy:
echo   1. Copy '%OUTPUT_DIR%' to the air-gapped machine
echo   2. Run: ./deploy.sh
echo   3. Run: docker-compose up -d
echo.

endlocal
