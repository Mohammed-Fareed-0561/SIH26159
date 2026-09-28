@echo off
setlocal enabledelayedexpansion
title SecureMailScope - Unified Startup Manager

echo =======================================================================
echo                 SecureMailScope System Startup Script                  
echo =======================================================================
echo.
echo Launching full stack: Docker Containers, PostgreSQL Database, 
echo Spring Boot Backend REST API, and React Frontend Dashboard.
echo.
echo   [1] Full Docker Stack (PostgreSQL + Backend + Frontend on http://localhost:8080)
echo   [2] Local Development Mode (Docker Database + Frontend Dev Server)
echo   [3] Database Only via Docker (PostgreSQL on port 5432)
echo.
choice /c 123 /n /m "Select option [1, 2, 3] (Auto-selecting 1 in 5 seconds): " /t 5 /d 1

if errorlevel 3 goto db_only
if errorlevel 2 goto dev_mode
if errorlevel 1 goto docker_stack

:docker_stack
echo.
echo =======================================================================
echo Starting Docker Compose Stack...
echo - Database: PostgreSQL 16 (Port 5432)
echo - Application (Backend API + Frontend Dashboard): http://localhost:8080
echo =======================================================================
echo.
docker compose up --build
goto end

:dev_mode
echo.
echo =======================================================================
echo Starting PostgreSQL Container via Docker...
echo =======================================================================
docker compose up -d postgres

echo.
echo Starting Frontend Dev Server (Vite) on http://localhost:5173...
start "SecureMailScope - Frontend Dev" cmd /k "cd /d %~dp0frontend && npm install && npm run dev"

echo.
echo =======================================================================
echo Database and Frontend Started!
echo To run Backend locally, ensure Java 17 / Maven is installed and run:
echo   cd backend ^&^& mvn spring-boot:run -Dspring-boot.run.profiles=postgres
echo Or run Option 1 to use Docker for all components.
echo =======================================================================
goto end

:db_only
echo.
echo =======================================================================
echo Starting PostgreSQL Database Container on Port 5432...
echo =======================================================================
docker compose up -d postgres
echo Database container 'sms-postgres' is active.
goto end

:end
pause
