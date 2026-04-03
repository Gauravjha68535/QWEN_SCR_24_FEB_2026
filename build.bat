@echo off
echo 🚀 Starting SentryQ Windows Build Process...

:: 1. Build the Frontend
echo 📦 Building React Frontend...
cd web
if not exist "node_modules" (
    echo 📥 Installing frontend dependencies...
    call npm install
)
call npm run build
if errorlevel 1 (
    echo ❌ Frontend build failed. Aborting.
    cd ..
    exit /b 1
)
cd ..

:: 2. Synchronize assets to internal\ui\dist
echo 🔄 Synchronizing assets to internal\ui\dist...
if not exist "internal\ui\dist" mkdir "internal\ui\dist"

:: Clean destination to avoid stale assets
echo 🗑️ Cleaning old assets...
if exist "internal\ui\dist" rmdir /s /q "internal\ui\dist"
mkdir "internal\ui\dist"

if exist "web\dist" (
    echo 📂 Copying build assets...
    xcopy /e /i /y "web\dist\*" "internal\ui\dist\"
    
    if exist "internal\ui\dist\index.html" (
        echo ✅ Assets synchronized successfully
    ) else (
        echo ❌ Error: No assets were copied to internal\ui\dist
        exit /b 1
    )
) else (
    echo ⚠️ Warning: web\dist is missing. Creating placeholder.
    echo. > internal\ui\dist\.gitkeep
)

:: 3. Build the Go Application
echo 🐹 Building Go application (sentryq.exe)...
set CGO_ENABLED=1
go build -o sentryq.exe ./cmd/scanner
if errorlevel 1 (
    echo ❌ Go build failed. Aborting.
    exit /b 1
)

echo ✅ Build Complete! You can now run the scanner with: sentryq.exe
