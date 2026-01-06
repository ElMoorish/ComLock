$ErrorActionPreference = "Stop"

Write-Host "Starting ComLock Security Audit..." -ForegroundColor Cyan

# 1. Dependency Vulnerability Check
Write-Host "`nChecking for vulnerable dependencies..."
try {
    cargo audit
    if ($LASTEXITCODE -eq 0) {
        Write-Host "No vulnerabilities found." -ForegroundColor Green
    }
}
catch {
    Write-Host "Vulnerabilities detected!" -ForegroundColor Yellow
}

# 2. Unsafe Code Analysis
Write-Host "`nAnalyzing unsafe usage..."
try {
    # Analyze main crates
    cargo geiger
}
catch {
    Write-Host "Geiger analysis failed to run." -ForegroundColor Red
}

# 3. Linter Checks
Write-Host "`nRunning Clippy linting..."
try {
    cargo clippy --all-targets --all-features -- -D warnings
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Clippy clean." -ForegroundColor Green
    }
}
catch {
    Write-Host "Clippy found potential issues." -ForegroundColor Yellow
}

Write-Host "`nAudit simulation complete."
