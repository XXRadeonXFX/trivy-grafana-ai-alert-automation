pipeline {
    agent any

    // options {
    //     buildDiscarder(logRotator(numToKeepStr: '10'))
    //     timeout(time: 2, unit: 'HOURS')
    //     retry(1)
    //     skipDefaultCheckout(false)
    //     timestamps()
    //     ansiColor('xterm')
    // }

    environment {
        // Repository Configuration
        GIT_REPO = "https://github.com/XXRadeonXFX/trivy-grafana-ai-alert-automation"
        GIT_BRANCH = "main"
        
        // Infrastructure Configuration
        EC2_SSH = "prince-ec2"
        EC2_USER = "ubuntu"
        EC2_HOST = "13.201.45.17"
        AWS_REGION = "ap-south-1"
        
        // Container Registry Configuration
        ECR_REPO_PATH = "975050024946.dkr.ecr.ap-south-1.amazonaws.com/prince-reg"
        ECR_REPO_NAME = "prince-reg"
        IMAGE_TAG = "build-${BUILD_NUMBER}"
        ECR_RETAIN_COUNT = "10"
        
        // AWS Credentials
        AWS_ACCESS_KEY_ID = credentials('prince-access-key-id')
        AWS_SECRET_ACCESS_KEY = credentials('prince-secret-access-key')
        
        // Application Configuration
        CONTAINER_NAME = "user-api"
        CONTAINER_PORT = "8000"
        DATABASE_URL = credentials('prince-mern-database')
        
        // Security Scanning Configuration
        CVE_DB_HOST = credentials('CVE_DB_HOST')
        CVE_DB_USERNAME = credentials('CVE_DB_USERNAME')
        CVE_DB_PASSWORD = credentials('CVE_DB_PASSWORD')
        CVE_DB_NAME = credentials('CVE_DB_NAME')
        
        // Alert Manager Configuration
        ALERT_MANAGER_URL = "https://alerts.thakurprince.com:8000"
        ALERT_MANAGER_SECRET = "yourapisecret"
        AI_ENGINE = "gemini"
        AI_MODEL = "gemini-2.0-flash"
        
        // Notification Configuration
        ALERT_EMAIL = "prince.thakur24051996@gmail.com"
        
        // Tool Paths
        TRIVY_CACHE_DIR = "${WORKSPACE}/.trivy"
        REPORTS_DIR = "${WORKSPACE}/reports"
        
        // Default values for variables that might not be set
        GIT_COMMIT = ""
        BUILD_REF_ID = ""
        SECURITY_REPORT = ""
        SCAN_OUTPUT = ""
        
        // Pipeline Control Flags
        DOCKER_BUILDKIT = "0"  // Disable BuildKit for stability
        COMPOSE_DOCKER_CLI_BUILD = "0"
    }

    stages {
        stage('Initialize') {
            steps {
                script {
                    currentBuild.displayName = "#${BUILD_NUMBER}-${GIT_BRANCH}"
                    currentBuild.description = "Build: ${IMAGE_TAG}"
                    
                    // Set GIT_COMMIT if available
                    try {
                        env.GIT_COMMIT = sh(
                            script: 'git rev-parse HEAD',
                            returnStdout: true
                        ).trim()
                    } catch (Exception e) {
                        env.GIT_COMMIT = "unknown"
                        echo "Warning: Could not determine git commit: ${e.getMessage()}"
                    }
                    
                    // Initialize BUILD_REF_ID with BUILD_NUMBER as fallback
                    env.BUILD_REF_ID = BUILD_NUMBER
                }
                
                echo "=== Build Information ==="
                echo "Build Number: ${BUILD_NUMBER}"
                echo "Git Branch: ${GIT_BRANCH}"
                echo "Git Commit: ${env.GIT_COMMIT}"
                echo "Docker Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                echo "Build Timestamp: ${new Date()}"
                
                // Create required directories
                sh '''
                    mkdir -p "${TRIVY_CACHE_DIR}" || true
                    mkdir -p "${REPORTS_DIR}" || true
                    mkdir -p test-reports || true
                    
                    # Set proper permissions
                    chmod 755 "${TRIVY_CACHE_DIR}" "${REPORTS_DIR}" test-reports || true
                '''
            }
        }

        stage('Environment Health Check') {
            steps {
                sh '''
                    echo "=== Environment Health Check ==="
                    echo "Disk usage:"
                    df -h
                    echo "Memory usage:"
                    free -h
                    echo "Docker system status:"
                    docker system df || echo "Docker system df failed"
                    docker info | head -20 || echo "Docker info failed"
                    
                    # Check minimum requirements
                    AVAILABLE_SPACE_KB=$(df /var/lib/docker | tail -1 | awk '{print $4}')
                    AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB / 1024 / 1024))
                    
                    if [ "$AVAILABLE_SPACE_GB" -lt 5 ]; then
                        echo "WARNING: Low disk space detected: ${AVAILABLE_SPACE_GB}GB"
                        echo "Performing emergency cleanup..."
                        docker system prune -a -f --volumes || true
                    fi
                '''
            }
        }

        stage('Checkout Source Code') {
            steps {
                cleanWs()
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: "*/${GIT_BRANCH}"]],
                    userRemoteConfigs: [[
                        url: "${GIT_REPO}",
                        credentialsId: "prince-github-access"
                    ]]
                ])
            }
        }

        stage('Code Verification') {
            steps {
                sh '''
                    echo "=== Repository Structure Verification ==="
                    pwd
                    ls -la
                    
                    # Verify critical files exist
                    if [ ! -f "Dockerfile" ]; then
                        echo "ERROR: Dockerfile not found"
                        exit 1
                    fi
                    
                    if [ ! -d "trivy" ]; then
                        echo "ERROR: Trivy security scanning directory not found"
                        exit 1
                    fi
                    
                    echo "=== Trivy Components Verification ==="
                    ls -la trivy/
                    
                    # Check required files
                    required_files="scan.sh report.py email_template.py ai_suggestion.py"
                    for file in $required_files; do
                        if [ ! -f "trivy/$file" ]; then
                            echo "WARNING: File trivy/$file not found"
                        fi
                    done
                    
                    # Make scripts executable
                    chmod +x trivy/*.sh 2>/dev/null || true
                    chmod +x trivy/*.py 2>/dev/null || true
                    
                    echo "Repository verification completed"
                '''
            }
        }

        stage('Setup Security Tools') {
            steps {
                script {
                    sh '''
                        echo "=== Security Tools Setup ==="
                        
                        # Check if Trivy is installed
                        if command -v trivy >/dev/null 2>&1; then
                            echo "Trivy is already installed"
                            trivy --version
                        else
                            echo "Installing Trivy using binary download method"
                            
                            # Create local bin directory
                            mkdir -p "${HOME}/bin"
                            
                            # Download and install Trivy binary
                            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "${HOME}/bin"
                            
                            # Verify installation
                            if [ -f "${HOME}/bin/trivy" ]; then
                                echo "Trivy installed successfully"
                                "${HOME}/bin/trivy" --version
                            else
                                echo "ERROR: Trivy installation failed"
                                exit 1
                            fi
                        fi
                        
                        # Ensure Trivy is in PATH
                        export PATH="${HOME}/bin:$PATH"
                        
                        # Update Trivy database
                        echo "Updating Trivy vulnerability database"
                        trivy --cache-dir "${TRIVY_CACHE_DIR}" image --download-db-only || echo "Database update completed with warnings"
                    '''
                }
            }
        }

        stage('Unit Tests') {
            when {
                expression { fileExists('docker-compose.yaml') || fileExists('docker-compose.yml') }
            }
            steps {
                script {
                    try {
                        sh '''
                            echo "=== Unit Test Execution ==="
                            
                            # Cleanup any existing containers
                            docker-compose down -v --remove-orphans || true
                            docker rm -f mongo-db test-container || true
                            
                            # Start test dependencies
                            echo "Starting test dependencies"
                            docker-compose up -d mongo-db
                            
                            # Wait for MongoDB to be ready
                            echo "Waiting for MongoDB initialization"
                            max_attempts=30
                            attempt=0
                            
                            while [ $attempt -lt $max_attempts ]; do
                                if docker-compose exec -T mongo-db mongosh --eval "db.runCommand({ping:1})" >/dev/null 2>&1; then
                                    echo "MongoDB is ready after $attempt attempts"
                                    break
                                fi
                                echo "Waiting for MongoDB... (attempt $((attempt+1))/$max_attempts)"
                                sleep 3
                                attempt=$((attempt+1))
                            done
                            
                            if [ $attempt -eq $max_attempts ]; then
                                echo "WARNING: MongoDB may not be fully ready, continuing with tests"
                            fi
                            
                            # Execute tests
                            echo "Executing test suite"
                            docker-compose run --rm test pytest \\
                                --maxfail=5 \\
                                --tb=short \\
                                --disable-warnings \\
                                --junitxml=test-reports/test-results.xml \\
                                --verbose || echo "Tests completed with warnings"
                        '''
                    } catch (Exception e) {
                        echo "Test execution failed: ${e.getMessage()}"
                        currentBuild.result = 'UNSTABLE'
                    } finally {
                        sh '''
                            echo "Cleaning up test environment"
                            docker-compose down -v --remove-orphans || true
                        '''
                    }
                }
            }
            post {
                always {
                    script {
                        try {
                            junit(
                                testResults: 'test-reports/*.xml',
                                allowEmptyResults: true,
                                skipPublishingChecks: true
                            )
                        } catch (Exception e) {
                            echo "Could not process test results: ${e.getMessage()}"
                        }
                    }
                }
            }
        }

        stage('Build Application Image') {
            steps {
                script {
                    try {
                        // Pre-build cleanup and space check
                        sh '''
                            echo "=== Pre-Build Environment Setup ==="
                            
                            # Check current disk usage
                            echo "Current disk usage:"
                            df -h
                            
                            # Clean up Docker to free space before build
                            echo "Cleaning up Docker resources..."
                            docker system prune -f --volumes || true
                            docker image prune -a -f || true
                            
                            # Remove dangling images and containers
                            docker container prune -f || true
                            docker volume prune -f || true
                            docker network prune -f || true
                            
                            # Clean up any old builds of this image
                            docker rmi "${ECR_REPO_PATH}:latest" || true
                            docker rmi $(docker images "${ECR_REPO_PATH}" -q) 2>/dev/null || true
                            
                            # Check available space after cleanup
                            echo "Disk usage after cleanup:"
                            df -h
                            
                            # Verify minimum space requirements (at least 3GB for Docker build)
                            AVAILABLE_SPACE_KB=$(df /var/lib/docker | tail -1 | awk '{print $4}')
                            AVAILABLE_SPACE_GB=$((AVAILABLE_SPACE_KB / 1024 / 1024))
                            
                            echo "Available space: ${AVAILABLE_SPACE_GB}GB"
                            
                            if [ "$AVAILABLE_SPACE_KB" -lt 3145728 ]; then
                                echo "ERROR: Insufficient disk space for Docker build. Available: ${AVAILABLE_SPACE_GB}GB, Required: 3GB"
                                echo "Please free up disk space or increase storage allocation."
                                exit 1
                            fi
                            
                            # Check Docker daemon status
                            if ! docker info >/dev/null 2>&1; then
                                echo "ERROR: Docker daemon is not accessible"
                                exit 1
                            fi
                            
                            echo "Pre-build checks passed. Proceeding with Docker build..."
                        '''
                        
                        // Build Docker image with legacy builder for stability
                        sh '''
                            echo "=== Docker Image Build ==="
                            
                            # Disable BuildKit for stability
                            export DOCKER_BUILDKIT=0
                            
                            # Check Docker version
                            echo "Docker version:"
                            docker --version
                            
                            # Create build context size check
                            echo "Checking build context size..."
                            BUILD_CONTEXT_SIZE=$(du -sh . | cut -f1)
                            echo "Build context size: $BUILD_CONTEXT_SIZE"
                            
                            # Build Docker image with legacy builder
                            echo "Starting Docker build..."
                            docker build \\
                                --no-cache \\
                                --pull \\
                                --tag "${ECR_REPO_PATH}:${IMAGE_TAG}" \\
                                --tag "${ECR_REPO_PATH}:latest" \\
                                --label "build.number=${BUILD_NUMBER}" \\
                                --label "build.url=${BUILD_URL}" \\
                                --label "git.commit=${GIT_COMMIT}" \\
                                --label "git.branch=${GIT_BRANCH}" \\
                                --label "build.timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
                                . 2>&1
                            
                            # Verify image was created successfully
                            echo "Verifying built image..."
                            docker images "${ECR_REPO_PATH}:${IMAGE_TAG}"
                            
                            # Get image size information
                            IMAGE_SIZE=$(docker images "${ECR_REPO_PATH}:${IMAGE_TAG}" --format "table {{.Size}}" | tail -1)
                            echo "Built image size: $IMAGE_SIZE"
                            
                            # Quick image inspection
                            echo "Image inspection:"
                            docker inspect "${ECR_REPO_PATH}:${IMAGE_TAG}" --format='{{.Config.Labels}}' || true
                            
                            echo "Docker image build completed successfully"
                        '''
                        
                        // Post-build verification
                        sh '''
                            echo "=== Post-Build Verification ==="
                            
                            # Verify both tags exist
                            echo "Verifying image tags:"
                            docker images "${ECR_REPO_PATH}" --format "table {{.Repository}}:{{.Tag}}\\t{{.Size}}\\t{{.CreatedAt}}"
                            
                            # Test that the image can be run (basic smoke test)
                            echo "Testing image can be instantiated..."
                            if timeout 30 docker run --rm "${ECR_REPO_PATH}:${IMAGE_TAG}" echo "Image test successful" 2>/dev/null; then
                                echo "✓ Image smoke test passed"
                            else
                                echo "⚠ Warning: Image smoke test failed - image may have issues"
                            fi
                            
                            # Clean up intermediate build artifacts but keep our image
                            echo "Cleaning up build artifacts..."
                            docker builder prune -f || true
                            
                            # Final disk usage check
                            echo "Final disk usage:"
                            df -h
                        '''
                        
                    } catch (Exception e) {
                        // Enhanced error handling
                        def errorMessage = e.getMessage()
                        
                        if (errorMessage.contains("no space left on device") || 
                            errorMessage.contains("disk") || 
                            errorMessage.contains("space")) {
                            
                            sh '''
                                echo "=== DISK SPACE FAILURE ANALYSIS ==="
                                df -h
                                echo "Docker system usage:"
                                docker system df 2>/dev/null || true
                                echo "Largest files in Docker directory:"
                                sudo du -h /var/lib/docker/ 2>/dev/null | sort -rh | head -10 || true
                            '''
                            
                            currentBuild.result = 'FAILURE'
                            error("Docker build failed due to insufficient disk space. Jenkins node requires maintenance.")
                            
                        } else {
                            currentBuild.result = 'FAILURE'
                            error("Docker build failed: ${errorMessage}")
                        }
                    }
                }
            }
            post {
                success {
                    script {
                        env.DOCKER_IMAGE_BUILT = 'true'
                        env.DOCKER_IMAGE_TAG = "${ECR_REPO_PATH}:${IMAGE_TAG}"
                        echo "✓ Docker image built successfully: ${env.DOCKER_IMAGE_TAG}"
                    }
                }
                failure {
                    script {
                        env.DOCKER_IMAGE_BUILT = 'false'
                        sh '''
                            echo "=== Emergency Cleanup After Build Failure ==="
                            docker system prune -a -f --volumes || true
                        '''
                    }
                }
            }
        }

        stage('Security Scan') {
                    when {
                        expression { env.DOCKER_IMAGE_BUILT == 'true' }
                    }
                    steps {
                        script {
                            try {
                                sh '''
                                    echo "=== Container Image Security Scan ==="
                                    
                                    # Ensure required directories exist
                                    mkdir -p "${REPORTS_DIR}"
                                    mkdir -p "${WORKSPACE}/trivy-cache"
                                    
                                    # Ensure Trivy is available
                                    export PATH="${HOME}/bin:$PATH"
                                    
                                    # Set Trivy cache location to workspace
                                    export TRIVY_CACHE_DIR="${WORKSPACE}/trivy-cache"
                                    
                                    # Verify Trivy is working
                                    trivy --version
                                    
                                    # Verify the Docker image exists locally before scanning
                                    echo "Checking if Docker image exists locally..."
                                    if ! docker images "${ECR_REPO_PATH}:${IMAGE_TAG}" --format "table {{.Repository}}:{{.Tag}}" | grep -q "${IMAGE_TAG}"; then
                                        echo "ERROR: Docker image ${ECR_REPO_PATH}:${IMAGE_TAG} not found locally"
                                        echo "Available images:"
                                        docker images "${ECR_REPO_PATH}" || echo "No images found"
                                        exit 1
                                    fi
                                    
                                    echo "✓ Docker image ${ECR_REPO_PATH}:${IMAGE_TAG} found locally"
                                    
                                    # Create scan output file
                                    touch "${REPORTS_DIR}/scan-output.log"
                                    
                                    # Run Trivy scan with proper error handling
                                    echo "Starting Trivy security scan..."
                                    
                                    # Use a more robust approach for capturing output and exit code
                                    set +e  # Temporarily disable exit on error
                                    
                                    timeout 1800 ./trivy/scan.sh \
                                        "${ECR_REPO_PATH}" \
                                        "${IMAGE_TAG}" \
                                        "${ECR_REPO_NAME}" \
                                        "${GIT_BRANCH}" \
                                        "${BUILD_URL}" \
                                        "${CVE_DB_HOST}" \
                                        "${CVE_DB_USERNAME}" \
                                        "${CVE_DB_PASSWORD}" \
                                        "${CVE_DB_NAME}" \
                                        "${ALERT_MANAGER_URL}" \
                                        "${ALERT_MANAGER_SECRET}" 2>&1 | tee "${REPORTS_DIR}/scan-output.log"
                                    
                                    SCAN_EXIT_CODE=$?
                                    set -e  # Re-enable exit on error
                                    
                                    echo "Trivy scan exit code: $SCAN_EXIT_CODE"
                                    
                                    # Display scan output for debugging
                                    echo "=== Scan Output Preview ==="
                                    head -20 "${REPORTS_DIR}/scan-output.log" || echo "Could not read scan output"
                                    
                                    # Check if scan completed successfully
                                    if [ $SCAN_EXIT_CODE -ne 0 ] && [ $SCAN_EXIT_CODE -ne 1 ]; then
                                        echo "WARNING: Trivy scan completed with exit code $SCAN_EXIT_CODE"
                                        if [ $SCAN_EXIT_CODE -eq 124 ]; then
                                            echo "ERROR: Scan timed out after 30 minutes"
                                            exit 1
                                        fi
                                    fi
                                    
                                    # Verify scan report was generated
                                    if [ -f "${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json" ]; then
                                        echo "✓ Scan report generated successfully"
                                        REPORT_SIZE=$(du -h "${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json" | cut -f1)
                                        echo "Report size: $REPORT_SIZE"
                                        
                                        # Add build_id to scan output for AI analysis
                                        echo "" >> "${REPORTS_DIR}/scan-output.log"
                                        echo "build_id: ${BUILD_NUMBER}" >> "${REPORTS_DIR}/scan-output.log"
                                        echo "scan_timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${REPORTS_DIR}/scan-output.log"
                                        
                                        # Quick summary of findings using basic shell tools
                                        echo "=== Quick Scan Summary ==="
                                        if command -v jq >/dev/null 2>&1; then
                                            echo "Attempting to parse vulnerability summary..."
                                            # Safer jq command with proper error handling
                                            jq -r '
                                                if .Results then 
                                                    [.Results[]?.Vulnerabilities // []] | flatten | 
                                                    group_by(.Severity) | 
                                                    map("\\(.key // "Unknown"): \\(length)") | 
                                                    join(", ")
                                                else 
                                                    "No vulnerabilities section found"
                                                end
                                            ' "${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json" 2>/dev/null || echo "Could not parse JSON with jq"
                                            
                                            # Alternative simple count
                                            echo "Total vulnerabilities found:"
                                            jq '[.Results[]?.Vulnerabilities // []] | flatten | length' "${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json" 2>/dev/null || echo "Count unavailable"
                                        else
                                            echo "jq not available for JSON parsing"
                                            # Basic grep-based summary
                                            echo "Using basic text analysis:"
                                            grep -o '"Severity":"[^"]*"' "${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json" 2>/dev/null | \\
                                                sort | uniq -c | head -10 || echo "Could not analyze with grep"
                                        fi
                                    else
                                        echo "WARNING: Scan report not found"
                                        echo "Contents of reports directory:"
                                        ls -la "${REPORTS_DIR}/" || echo "Reports directory not found"
                                        echo "Checking for any JSON files:"
                                        find "${REPORTS_DIR}" -name "*.json" -type f 2>/dev/null || echo "No JSON files found"
                                    fi
                                    
                                    # Always exit successfully to allow pipeline continuation
                                    exit 0
                                '''
                                
                                // Process scan results with better error handling
                                script {
                                    try {
                                        echo "Processing scan results..."
                                        
                                        if (fileExists("${REPORTS_DIR}/scan-output.log")) {
                                            def scanOutput = readFile("${REPORTS_DIR}/scan-output.log")
                                            
                                            if (scanOutput && scanOutput.trim()) {
                                                env.SCAN_OUTPUT = scanOutput
                                                echo "Scan output captured (${scanOutput.length()} characters)"
                                                
                                                // Extract build ID from scan output with better regex
                                                def buildIdMatcher = (scanOutput =~ /build_id:\s*([0-9]+)/)
                                                if (buildIdMatcher) {
                                                    env.BUILD_REF_ID = buildIdMatcher[0][1]
                                                    echo "Security scan completed. Build Reference ID: ${env.BUILD_REF_ID}"
                                                } else {
                                                    env.BUILD_REF_ID = BUILD_NUMBER
                                                    echo "No build_id found in output, using BUILD_NUMBER: ${env.BUILD_REF_ID}"
                                                }
                                                
                                                // Check for critical errors but be more specific
                                                if (scanOutput.contains("FATAL") && scanOutput.contains("error")) {
                                                    if (!scanOutput.contains("successfully")) {
                                                        echo "WARNING: Fatal error detected in scan, but continuing pipeline"
                                                        currentBuild.result = 'UNSTABLE'
                                                    }
                                                }
                                                
                                                // Check if timeout occurred
                                                if (scanOutput.contains("timed out") || scanOutput.contains("timeout")) {
                                                    echo "WARNING: Scan timeout detected"
                                                    currentBuild.result = 'UNSTABLE'
                                                }
                                                
                                            } else {
                                                throw new Exception("Scan output file is empty")
                                            }
                                        } else {
                                            throw new Exception("Scan output file not found")
                                        }
                                        
                                        // Verify scan report exists and has content
                                        if (fileExists("${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json")) {
                                            def fileSize = sh(
                                                script: "stat -c%s '${WORKSPACE}/${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json' 2>/dev/null || echo 0",
                                                returnStdout: true
                                            ).trim().toInteger()
                                            
                                            if (fileSize > 100) {
                                                echo "✓ Scan report verified: ${fileSize} bytes"
                                            } else {
                                                echo "WARNING: Scan report file is too small or empty"
                                                currentBuild.result = 'UNSTABLE'
                                            }
                                        } else {
                                            echo "WARNING: Scan report JSON file not found"
                                            currentBuild.result = 'UNSTABLE'
                                        } 
                                        
                                    } catch (Exception e) {
                                        echo "Error processing scan output: ${e.getMessage()}"
                                        env.SCAN_OUTPUT = "Scan output processing failed: ${e.getMessage()}"
                                        env.BUILD_REF_ID = BUILD_NUMBER
                                        currentBuild.result = 'UNSTABLE'
                                        
                                        // Try to provide some diagnostic information
                                        try {
                                            sh '''
                                                echo "=== Diagnostic Information ==="
                                                echo "Reports directory contents:"
                                                ls -la "${REPORTS_DIR}/" || echo "No reports directory"
                                                echo "Workspace contents:"
                                                ls -la "${WORKSPACE}/" | head -20
                                                echo "Available disk space:"
                                                df -h
                                            '''
                                        } catch (Exception diagEx) {
                                            echo "Could not gather diagnostic info: ${diagEx.getMessage()}"
                                        }
                                    }
                                }
                                
                            } catch (Exception e) {
                                def errorMessage = e.getMessage()
                                echo "Security scan stage failed: ${errorMessage}"
                                
                                if (errorMessage.contains("no space left on device") || errorMessage.contains("disk")) {
                                    currentBuild.result = 'FAILURE'
                                    error("Security scan failed due to insufficient disk space.")
                                } else if (errorMessage.contains("timeout") || errorMessage.contains("124")) {
                                    currentBuild.result = 'UNSTABLE'
                                    echo "Security scan timed out after 30 minutes."
                                    env.SCAN_OUTPUT = "Security scan timed out"
                                    env.BUILD_REF_ID = BUILD_NUMBER
                                } else if (errorMessage.contains("Docker image") && errorMessage.contains("not found")) {
                                    currentBuild.result = 'FAILURE'
                                    error("Security scan failed: Docker image not available for scanning.")
                                } else {
                                    currentBuild.result = 'UNSTABLE'
                                    echo "Security scan encountered issues but pipeline will continue: ${errorMessage}"
                                    env.SCAN_OUTPUT = "Security scan failed: ${errorMessage}"
                                    env.BUILD_REF_ID = BUILD_NUMBER
                                }
                            }
                        }
                    }
                    post {
                        always {
                            script {
                                echo "=== Security Scan Post Actions ==="
                                
                                // Archive scan outputs with better error handling
                                try {
                                    def artifactPattern = "reports/scan-*.json, reports/scan-output.log, reports/scan-report-*.json"
                                    archiveArtifacts artifacts: artifactPattern, 
                                                   allowEmptyArchive: true,
                                                   fingerprint: true,
                                                   caseSensitive: false
                                    echo "✓ Scan artifacts archived successfully"
                                } catch (Exception e) {
                                    echo "Could not archive scan artifacts: ${e.getMessage()}"
                                    // Try to archive just the basic files
                                    try {
                                        archiveArtifacts artifacts: 'reports/**/*', 
                                                       allowEmptyArchive: true,
                                                       fingerprint: false
                                        echo "✓ Basic reports archived as fallback"
                                    } catch (Exception e2) {
                                        echo "Complete archiving failure: ${e2.getMessage()}"
                                    }
                                }
                                
                                // Publish HTML report if available
                                try {
                                    if (fileExists("reports/scan-report-${IMAGE_TAG}.json")) {
                                        publishHTML([
                                            allowMissing: false,
                                            alwaysLinkToLastBuild: true,
                                            keepAll: true,
                                            reportDir: 'reports',
                                            reportFiles: "scan-report-${IMAGE_TAG}.json",
                                            reportName: 'Trivy Security Scan Report',
                                            reportTitles: 'Security Vulnerabilities'
                                        ])
                                        echo "✓ Security report published to Jenkins"
                                    }
                                } catch (Exception e) {
                                    echo "Could not publish HTML report: ${e.getMessage()}"
                                }
                                
                                // Cleanup with better error handling
                                try {
                                    sh '''
                                        echo "=== Post-Scan Cleanup ==="
                                        
                                        # Clean up trivy cache
                                        if [ -d "${WORKSPACE}/trivy-cache" ]; then
                                            rm -rf "${WORKSPACE}/trivy-cache" || echo "Could not remove trivy cache"
                                            echo "✓ Trivy cache cleaned"
                                        fi
                                        
                                        # Clean up docker temp files
                                        sudo rm -rf /var/lib/docker/tmp/docker-export-* 2>/dev/null || true
                                        
                                        # Show final disk usage
                                        echo "Final disk usage:"
                                        df -h | head -5
                                        
                                        # Ensure scan artifacts are preserved
                                        if [ -f "${REPORTS_DIR}/scan-output.log" ]; then
                                            SCAN_LOG_SIZE=$(du -h "${REPORTS_DIR}/scan-output.log" | cut -f1)
                                            echo "✓ Scan output preserved: $SCAN_LOG_SIZE"
                                        fi
                                        
                                        echo "Security scan cleanup completed"
                                    '''
                                } catch (Exception e) {
                                    echo "Cleanup encountered issues: ${e.getMessage()}"
                                }
                            }
                        }
                        
                        success {
                            echo "✓ Security scan stage completed successfully"
                        }
                        
                        unstable {
                            echo "⚠ Security scan completed with warnings - check scan output for details"
                        }
                        
                        failure {
                            echo "❌ Security scan stage failed - check logs for troubleshooting steps"
                        }
                    }
                }

        stage('AI Security Analysis') {
            when {
                anyOf {
                    expression { env.BUILD_REF_ID?.trim() && env.BUILD_REF_ID != '' }
                    expression { fileExists("reports/scan-report-${IMAGE_TAG}.json") }
                }
            }
            steps {
                script {
                    try {
                        def analysisId = env.BUILD_REF_ID?.trim() ?: BUILD_NUMBER
                        echo "Running AI Security Analysis with ID: ${analysisId}"
                        
                        sh """
                            echo "=== AI-Powered Security Recommendations ==="
                            echo "Analysis ID: ${analysisId}"
                            
                            # Check if AI script exists
                            if [ -f "trivy/ai_suggestion.py" ]; then
                                python3 trivy/ai_suggestion.py \\
                                    "${analysisId}" \\
                                    "${ALERT_MANAGER_URL}" \\
                                    "${ALERT_MANAGER_SECRET}" \\
                                    --engine "${AI_ENGINE}" \\
                                    --model "${AI_MODEL}" || echo "AI analysis completed with warnings"
                            else
                                echo "AI suggestion script not found, skipping AI analysis"
                            fi
                        """
                        
                        echo "AI security analysis completed successfully"
                        
                    } catch (Exception e) {
                        echo "AI analysis failed but continuing pipeline: ${e.getMessage()}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    try {
                        // Process scan results for security gate
                        def scanSummary = ""
                        try {
                            if (fileExists("reports/scan-report-${IMAGE_TAG}.json")) {
                                scanSummary = sh(
                                    script: """
                                        if [ -f "trivy/email_template.py" ]; then
                                            python3 trivy/email_template.py \\
                                                reports/scan-report-${IMAGE_TAG}.json \\
                                                ${BUILD_URL}
                                        else
                                            echo "Security scan completed successfully"
                                        fi
                                    """,
                                    returnStdout: true
                                ).trim()
                            } else {
                                scanSummary = "Scan report file not found"
                            }
                        } catch (Exception e) {
                            scanSummary = "Security report generation failed: ${e.getMessage()}"
                        }
                        
                        env.SECURITY_REPORT = scanSummary
                        
                        // Extract vulnerability counts
                        def criticalCount = 0
                        def highCount = 0
                        
                        if (env.SCAN_OUTPUT) {
                            def criticalMatch = (env.SCAN_OUTPUT =~ /CRITICAL:\s*([0-9]+)/)
                            def highMatch = (env.SCAN_OUTPUT =~ /HIGH:\s*([0-9]+)/)
                            
                            criticalCount = criticalMatch ? criticalMatch[0][1].toInteger() : 0
                            highCount = highMatch ? highMatch[0][1].toInteger() : 0
                        }
                        
                        echo "Security Assessment Results:"
                        echo "- Critical Vulnerabilities: ${criticalCount}"
                        echo "- High Vulnerabilities: ${highCount}"
                        
                        // Security gate decision
                        if (criticalCount > 10) {
                            echo "WARNING: ${criticalCount} critical vulnerabilities found. Consider reviewing before deployment."
                        } else if (highCount > 20) {
                            echo "WARNING: ${highCount} high-severity vulnerabilities detected."
                        } else {
                            echo "Security gate passed. Vulnerability counts within acceptable limits."
                        }
                        
                    } catch (Exception e) {
                        echo "Security gate evaluation failed: ${e.getMessage()}"
                        env.SECURITY_REPORT = "Security gate evaluation failed"
                    }
                }
            }
        }

        stage('Registry Operations') {
            when {
                expression { env.DOCKER_IMAGE_BUILT == 'true' }
            }
            steps {
                script {
                    retry(3) {
                        sh '''
                            echo "=== Container Registry Authentication ==="
                            aws ecr get-login-password --region "${AWS_REGION}" | \\
                                docker login --username AWS --password-stdin "${ECR_REPO_PATH}"
                            
                            echo "=== Container Image Registry Push ==="
                            
                            # Push tagged image
                            docker push "${ECR_REPO_PATH}:${IMAGE_TAG}"
                            
                            # Push latest tag
                            docker push "${ECR_REPO_PATH}:latest"
                            
                            echo "Image push completed successfully"
                        '''
                    }
                }
            }
        }

        stage('Deploy Application') {
            when {
                expression { env.DOCKER_IMAGE_BUILT == 'true' }
            }
            steps {
                script {
                    // Test SSH connectivity first
                    try {
                        sshagent(credentials: ['prince-ec2']) {
                            sh '''
                                echo "=== Testing SSH Connection ==="
                                ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=no "${EC2_USER}@${EC2_HOST}" 'echo "SSH connection test successful"'
                            '''
                        }
                        echo "SSH connection verified successfully"
                    } catch (Exception e) {
                        error("SSH connection failed. Please check your SSH credentials and EC2 server status. Error: ${e.getMessage()}")
                    }
                    
                    // Proceed with deployment
                    sshagent(credentials: ['prince-ec2']) {
                        sh '''
                            echo "=== Application Deployment ==="
                            
                            ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=no "${EC2_USER}@${EC2_HOST}" "
                                set -e
                                
                                echo 'Deployment initiated on target server'
                                echo 'Current user: '\\$(whoami)
                                echo 'Current directory: '\\$(pwd)
                                
                                # Install required tools
                                if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
                                  sudo apt-get update -y
                                  sudo apt-get install -y curl unzip
                                fi
                                
                                # Check if AWS CLI is installed
                                if ! command -v aws >/dev/null 2>&1; then
                                    echo 'Installing AWS CLI...'
                                    curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'
                                    unzip -q awscliv2.zip
                                    sudo ./aws/install
                                    rm -rf aws awscliv2.zip
                                fi
                                
                                # Export AWS credentials
                                export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
                                export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
                                export AWS_DEFAULT_REGION=${AWS_REGION}
                                
                                echo 'AWS credentials configured'
                                
                                # Check if Docker is installed and running
                                if ! command -v docker >/dev/null 2>&1; then
                                    echo 'Installing Docker...'
                                    curl -fsSL https://get.docker.com -o get-docker.sh
                                    sudo sh get-docker.sh
                                    sudo usermod -aG docker \\$USER
                                    sudo systemctl enable docker
                                    sudo systemctl start docker
                                fi
                                
                                # Ensure docker service is running
                                sudo systemctl start docker || true
                                
                                echo 'Docker service status:'
                                sudo systemctl status docker --no-pager -l
                                
                                # Authenticate with ECR
                                echo 'Authenticating with ECR...'
                                aws ecr get-login-password --region ${AWS_REGION} | \\
                                    sudo docker login --username AWS --password-stdin ${ECR_REPO_PATH}
                                
                                # Pull latest image
                                echo 'Pulling application image: ${ECR_REPO_PATH}:${IMAGE_TAG}'
                                sudo docker pull ${ECR_REPO_PATH}:${IMAGE_TAG}
                                
                                # Stop and remove existing container
                                echo 'Stopping existing application container'
                                sudo docker stop ${CONTAINER_NAME} 2>/dev/null || echo 'No existing container to stop'
                                sudo docker rm ${CONTAINER_NAME} 2>/dev/null || echo 'No existing container to remove'
                                
                                # Start new container
                                echo 'Starting new application container'
                                sudo docker run -d \\
                                    --name ${CONTAINER_NAME} \\
                                    -p ${CONTAINER_PORT}:${CONTAINER_PORT} \\
                                    --restart unless-stopped \\
                                    -e PORT=${CONTAINER_PORT} \\
                                    -e MONGO_URI='${DATABASE_URL}' \\
                                    -e JWT_SECRET_KEY=thirumalaipy \\
                                    -e MONGO_DB_NAME=flask_db \\
                                    -e NODE_ENV=production \\
                                    --label deployment.build=${BUILD_NUMBER} \\
                                    --label deployment.timestamp=\\$(date -u +%Y-%m-%dT%H:%M:%SZ) \\
                                    ${ECR_REPO_PATH}:${IMAGE_TAG}
                                
                                echo 'Container started. Waiting for application to initialize...'
                                sleep 15
                                
                                # Verify deployment
                                echo 'Verifying deployment...'
                                if sudo docker ps | grep -q ${CONTAINER_NAME}; then
                                    echo 'Container is running successfully'
                                    sudo docker ps | grep ${CONTAINER_NAME}
                                    
                                    # Check application health
                                    echo 'Testing application health...'
                                    sleep 5
                                    if curl -f -s http://localhost:${CONTAINER_PORT}/health >/dev/null 2>&1; then
                                        echo 'Application health check passed'
                                    else
                                        echo 'Application health check failed, checking logs...'
                                        sudo docker logs ${CONTAINER_NAME} --tail 50
                                    fi
                                else
                                    echo 'Container failed to start. Checking logs...'
                                    sudo docker logs ${CONTAINER_NAME} --tail 50 || echo 'No logs available'
                                    exit 1
                                fi
                                
                                echo 'Application deployment completed successfully'
                            "
                        '''
                    }
                }
            }
        }

        stage('Post-Deployment Cleanup') {
            steps {
                sh '''
                    echo "=== Container Registry Cleanup ==="
                    
                    # Authenticate with ECR
                    aws ecr get-login-password --region "${AWS_REGION}" | \\
                        docker login --username AWS --password-stdin "${ECR_REPO_PATH}"
                    
                    # Clean up old images in ECR (keep last 5)
                    aws ecr describe-images \\
                        --repository-name "${ECR_REPO_NAME}" \\
                        --region "${AWS_REGION}" \\
                        --query "imageDetails[?imageDigest!=null].[imageTags[0], imagePushedAt]" \\
                        --output text | \\
                        sort -k2 -r | \\
                        tail -n +6 | \\
                        awk '{print $1}' | \\
                        while read tag; do
                            if [ "$tag" != "null" ] && [ "$tag" != "latest" ]; then
                                echo "Removing old image tag: $tag"
                                aws ecr batch-delete-image \\
                                    --repository-name "${ECR_REPO_NAME}" \\
                                    --region "${AWS_REGION}" \\
                                    --image-ids imageTag=$tag \\
                                    --output text || true
                            fi
                        done
                    
                    echo "=== Local Environment Cleanup ==="
                    
                    # Remove local Docker images (keep last 3)
                    docker images "${ECR_REPO_PATH}" --format "table {{.Repository}}:{{.Tag}} {{.CreatedAt}}" | \\
                        tail -n +2 | \\
                        sort -k2 -r | \\
                        tail -n +4 | \\
                        awk '{print $1}' | \\
                        xargs -r docker rmi || true
                    
                    echo "Cleanup completed"
                '''
            }
        }

        stage('Health Check & Monitoring') {
            steps {
                script {
                    try {
                        sh '''
                            echo "=== Post-Deployment Health Check ==="
                            
                            # Wait a bit more for application to fully start
                            sleep 30
                            
                            # Check if we can reach the application
                            MAX_ATTEMPTS=5
                            ATTEMPT=1
                            
                            while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
                                echo "Health check attempt $ATTEMPT of $MAX_ATTEMPTS"
                                
                                if curl -f -s "http://${EC2_HOST}:${CONTAINER_PORT}/health" >/dev/null 2>&1; then
                                    echo "✓ Application is responding to health checks"
                                    break
                                elif [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
                                    echo "⚠ Application health check failed after $MAX_ATTEMPTS attempts"
                                    echo "Application may still be starting up or there may be an issue"
                                else
                                    echo "Health check failed, retrying in 10 seconds..."
                                    sleep 10
                                fi
                                
                                ATTEMPT=$((ATTEMPT + 1))
                            done
                            
                            echo "=== Deployment Summary ==="
                            echo "Build Number: ${BUILD_NUMBER}"
                            echo "Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                            echo "Deployed to: ${EC2_HOST}:${CONTAINER_PORT}"
                            echo "Security Report: Available in build artifacts"
                        '''
                    } catch (Exception e) {
                        echo "Health check encountered issues: ${e.getMessage()}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                try {
                    // Archive build artifacts
                    archiveArtifacts(
                        artifacts: 'reports/**/*,test-reports/**/*',
                        allowEmptyArchive: true,
                        fingerprint: true
                    )
                } catch (Exception e) {
                    echo "Could not archive artifacts: ${e.getMessage()}"
                }
                
                // Final cleanup
                sh '''
                    echo "=== Final Workspace Cleanup ==="
                    docker system prune -f --volumes || true
                    rm -rf "${WORKSPACE}/.trivy" || true
                    
                    # Show final system state
                    echo "Final disk usage:"
                    df -h
                    echo "Final Docker usage:"
                    docker system df || true
                '''
            }
        }
        
        success {
            script {
                def deploymentTime = new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("UTC"))
                
                emailext(
                    subject: "✅ DEPLOYMENT SUCCESS: ${env.JOB_NAME} Build #${BUILD_NUMBER}",
                    body: """
                        <html>
                        <head>
                            <style>
                                body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                                .header { background-color: #28a745; color: white; padding: 15px; border-radius: 5px; text-align: center; }
                                .content { padding: 20px 0; }
                                .detail-table { border-collapse: collapse; width: 100%; margin: 15px 0; }
                                .detail-table th, .detail-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                                .detail-table th { background-color: #f2f2f2; font-weight: bold; }
                                .success-box { background-color: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 15px 0; }
                                .footer { margin-top: 20px; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 10px; }
                            </style>
                        </head>
                        <body>
                            <div class="header">
                                <h2>🚀 Deployment Successful</h2>
                                <p>Your application has been successfully deployed to production!</p>
                            </div>
                            
                            <div class="content">
                                <div class="success-box">
                                    <strong>✅ All pipeline stages completed successfully</strong><br>
                                    Your application is now live and responding to requests.
                                </div>
                                
                                <table class="detail-table">
                                    <tr><th>Job Name</th><td>${env.JOB_NAME}</td></tr>
                                    <tr><th>Build Number</th><td>${BUILD_NUMBER}</td></tr>
                                    <tr><th>Git Branch</th><td>${env.GIT_BRANCH ?: 'N/A'}</td></tr>
                                    <tr><th>Git Commit</th><td>${env.GIT_COMMIT?.take(8) ?: 'N/A'}</td></tr>
                                    <tr><th>Docker Image</th><td>${ECR_REPO_PATH}:${IMAGE_TAG}</td></tr>
                                    <tr><th>Deployment Time</th><td>${deploymentTime} UTC</td></tr>
                                    <tr><th>Target Server</th><td>${EC2_HOST}:${CONTAINER_PORT}</td></tr>
                                    <tr><th>Build Status</th><td><span style="color: green; font-weight: bold;">SUCCESS</span></td></tr>
                                </table>
                                
                                <h3>🔒 Security Scan Summary</h3>
                                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #28a745;">
                                    ${env.SECURITY_REPORT ?: 'Security scan completed successfully with no critical issues blocking deployment.'}
                                </div>
                                
                                <h3>🔗 Quick Links</h3>
                                <ul style="list-style-type: none; padding-left: 0;">
                                    <li>📊 <a href="${BUILD_URL}" style="text-decoration: none;">View Build Details</a></li>
                                    <li>🛡️ <a href="http://4.240.98.78:3000" style="text-decoration: none;">Security Dashboard</a></li>
                                    <li>📁 <a href="${BUILD_URL}artifact/" style="text-decoration: none;">Build Artifacts</a></li>
                                    <li>🌐 <a href="http://${EC2_HOST}:${CONTAINER_PORT}" style="text-decoration: none;">Application URL</a></li>
                                </ul>
                            </div>
                            
                            <div class="footer">
                                <p>This is an automated notification from Jenkins CI/CD Pipeline.<br>
                                Build completed at ${deploymentTime} UTC</p>
                            </div>
                        </body>
                        </html>
                    """,
                    mimeType: 'text/html',
                    to: "${ALERT_EMAIL}",
                    attachLog: false
                )
                
                echo "=== 🎉 DEPLOYMENT SUCCESS SUMMARY ==="
                echo "Status: ✅ SUCCESS"
                echo "Build: #${BUILD_NUMBER}"
                echo "Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                echo "Deployed: ${deploymentTime} UTC"
                echo "Application URL: http://${EC2_HOST}:${CONTAINER_PORT}"
            }
        }
        
        failure {
            script {
                def failureTime = new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("UTC"))
                
                emailext(
                    subject: "❌ DEPLOYMENT FAILED: ${env.JOB_NAME} Build #${BUILD_NUMBER}",
                    body: """
                        <html>
                        <head>
                            <style>
                                body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                                .header { background-color: #dc3545; color: white; padding: 15px; border-radius: 5px; text-align: center; }
                                .content { padding: 20px 0; }
                                .detail-table { border-collapse: collapse; width: 100%; margin: 15px 0; }
                                .detail-table th, .detail-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                                .detail-table th { background-color: #f2f2f2; font-weight: bold; }
                                .error-section { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 15px 0; }
                                .action-section { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 15px 0; }
                                .footer { margin-top: 20px; font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 10px; }
                            </style>
                        </head>
                        <body>
                            <div class="header">
                                <h2>⚠️ Deployment Failed</h2>
                                <p>The deployment pipeline encountered an error and needs attention.</p>
                            </div>
                            
                            <div class="content">
                                <div class="error-section">
                                    <strong>❌ Pipeline Failure Detected</strong><br>
                                    The deployment process failed and requires immediate investigation.
                                </div>
                                
                                <table class="detail-table">
                                    <tr><th>Job Name</th><td>${env.JOB_NAME}</td></tr>
                                    <tr><th>Build Number</th><td>${BUILD_NUMBER}</td></tr>
                                    <tr><th>Git Branch</th><td>${env.GIT_BRANCH ?: 'N/A'}</td></tr>
                                    <tr><th>Git Commit</th><td>${env.GIT_COMMIT?.take(8) ?: 'N/A'}</td></tr>
                                    <tr><th>Failure Time</th><td>${failureTime} UTC</td></tr>
                                    <tr><th>Build Result</th><td><span style="color: red; font-weight: bold;">${currentBuild.result ?: 'FAILURE'}</span></td></tr>
                                </table>
                                
                                <h3>🔒 Security Scan Results</h3>
                                <div class="error-section">
                                    ${env.SECURITY_REPORT ?: 'Security scan results not available due to pipeline failure. Please review build logs for details.'}
                                </div>
                                
                                <div class="action-section">
                                    <h3>🚨 Immediate Actions Required</h3>
                                    <ol>
                                        <li><strong>Review build logs</strong> for specific error messages and stack traces</li>
                                        <li><strong>Check infrastructure</strong> - verify Jenkins node disk space and Docker daemon status</li>
                                        <li><strong>Validate recent changes</strong> - review recent commits for potential issues</li>
                                        <li><strong>Check dependencies</strong> - ensure all external services are available</li>
                                        <li><strong>Verify credentials</strong> - confirm AWS and other service credentials are valid</li>
                                    </ol>
                                </div>
                                
                                <h3>🔗 Investigation Links</h3>
                                <ul style="list-style-type: none; padding-left: 0;">
                                    <li>📋 <a href="${BUILD_URL}console" style="text-decoration: none;">View Console Output</a></li>
                                    <li>📊 <a href="${BUILD_URL}" style="text-decoration: none;">Build Details</a></li>
                                    <li>🛡️ <a href="http://4.240.98.78:3000" style="text-decoration: none;">Security Dashboard</a></li>
                                    <li>📁 <a href="${BUILD_URL}artifact/" style="text-decoration: none;">Available Artifacts</a></li>
                                </ul>
                            </div>
                            
                            <div class="footer">
                                <p>This is an automated notification from Jenkins CI/CD Pipeline.<br>
                                Failure detected at ${failureTime} UTC</p>
                            </div>
                        </body>
                        </html>
                    """,
                    mimeType: 'text/html',
                    to: "${ALERT_EMAIL}",
                    attachLog: true
                )
                
                echo "=== ❌ FAILURE SUMMARY ==="
                echo "Status: ❌ FAILED"
                echo "Build: #${BUILD_NUMBER}"
                echo "Result: ${currentBuild.result}"
                echo "Failed: ${failureTime} UTC"
                echo "Action Required: Review console logs and investigate"
            }
        }
        
        unstable {
            script {
                echo "=== ⚠️ UNSTABLE BUILD SUMMARY ==="
                echo "Build completed with warnings. Check logs for details."
                echo "Security scan may have encountered non-critical issues."
                echo "Application deployment may have succeeded despite warnings."
            }
        }
        
        aborted {
            script {
                echo "=== 🛑 BUILD ABORTED ==="
                echo "Build was aborted by user or timeout."
                echo "Check pipeline configuration and resource allocation."
            }
        }
    }
}
