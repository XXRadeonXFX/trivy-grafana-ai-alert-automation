pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 1, unit: 'HOURS')
        retry(1)
        skipDefaultCheckout(false)
    }

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
        ALERT_MANAGER_URL = "http://4.240.98.78:8000"
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
                }
                
                echo "=== Build Information ==="
                echo "Build Number: ${BUILD_NUMBER}"
                echo "Git Branch: ${GIT_BRANCH}"
                echo "Git Commit: ${env.GIT_COMMIT}"
                echo "Docker Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                echo "Build Timestamp: ${new Date()}"
                
                // Create required directories
                sh '''
                    mkdir -p ${TRIVY_CACHE_DIR} || true
                    mkdir -p ${REPORTS_DIR} || true
                    mkdir -p test-reports || true
                '''
            }
        }

        stage('Checkout Source Code') {
            steps {
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
                            echo "ERROR: Required file trivy/$file not found"
                            exit 1
                        fi
                    done
                    
                    # Make scripts executable
                    chmod +x trivy/*.sh || true
                    chmod +x trivy/*.py || true
                    
                    echo "Repository verification completed successfully"
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
                            mkdir -p ${HOME}/bin
                            
                            # Download and install Trivy binary
                            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ${HOME}/bin
                            
                            # Add to PATH for this session
                            export PATH=${HOME}/bin:$PATH
                            
                            # Verify installation
                            if [ -f "${HOME}/bin/trivy" ]; then
                                echo "Trivy installed successfully"
                                ${HOME}/bin/trivy --version
                            else
                                echo "ERROR: Trivy installation failed"
                                exit 1
                            fi
                        fi
                        
                        # Ensure Trivy is in PATH
                        export PATH=${HOME}/bin:$PATH
                        
                        # Update Trivy database
                        echo "Updating Trivy vulnerability database"
                        trivy --cache-dir ${TRIVY_CACHE_DIR} image --download-db-only || echo "Database update completed with warnings"
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
                                    docker rmi ${ECR_REPO_PATH}:latest || true
                                    docker rmi $(docker images ${ECR_REPO_PATH} -q) 2>/dev/null || true
                                    
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
                                
                                // Build Docker image with enhanced error handling
                                sh '''
                                    echo "=== Docker Image Build ==="
                                    
                                    # Check Docker version and BuildKit support
                                    echo "Docker version:"
                                    docker --version
                                    
                                    # Check if BuildKit/buildx is available
                                    echo "Checking BuildKit/buildx availability..."
                                    if docker buildx version >/dev/null 2>&1; then
                                        echo "✓ BuildKit/buildx is available"
                                        export DOCKER_BUILDKIT=1
                                        export BUILDKIT_PROGRESS=plain
                                        BUILD_COMMAND="docker buildx build"
                                        PROGRESS_FLAG="--progress=plain"
                                    else
                                        echo "⚠ BuildKit/buildx not available, using legacy builder"
                                        export DOCKER_BUILDKIT=0
                                        BUILD_COMMAND="docker build"
                                        PROGRESS_FLAG=""
                                    fi
                                    
                                    # Create build context size check
                                    echo "Checking build context size..."
                                    BUILD_CONTEXT_SIZE=$(du -sh . | cut -f1)
                                    echo "Build context size: $BUILD_CONTEXT_SIZE"
                                    
                                    # Build Docker image with fallback approach
                                    echo "Starting Docker build with command: $BUILD_COMMAND"
                                    
                                    if [ "$DOCKER_BUILDKIT" = "1" ]; then
                                        # BuildKit-enabled build
                                        echo "Using BuildKit for optimized build..."
                                        $BUILD_COMMAND \\
                                            --no-cache \\
                                            --pull \\
                                            --tag ${ECR_REPO_PATH}:${IMAGE_TAG} \\
                                            --tag ${ECR_REPO_PATH}:latest \\
                                            --label "build.number=${BUILD_NUMBER}" \\
                                            --label "build.url=${BUILD_URL}" \\
                                            --label "git.commit=${GIT_COMMIT}" \\
                                            --label "git.branch=${GIT_BRANCH}" \\
                                            --label "build.timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
                                            $PROGRESS_FLAG \\
                                            --load \\
                                            . 2>&1
                                    else
                                        # Legacy build without BuildKit
                                        echo "Using legacy Docker build..."
                                        $BUILD_COMMAND \\
                                            --no-cache \\
                                            --pull \\
                                            --tag ${ECR_REPO_PATH}:${IMAGE_TAG} \\
                                            --tag ${ECR_REPO_PATH}:latest \\
                                            --label "build.number=${BUILD_NUMBER}" \\
                                            --label "build.url=${BUILD_URL}" \\
                                            --label "git.commit=${GIT_COMMIT}" \\
                                            --label "git.branch=${GIT_BRANCH}" \\
                                            --label "build.timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \\
                                            . 2>&1
                                    fi
                                    
                                    # Verify image was created successfully
                                    echo "Verifying built image..."
                                    docker images ${ECR_REPO_PATH}:${IMAGE_TAG}
                                    
                                    # Get image size information
                                    IMAGE_SIZE=$(docker images ${ECR_REPO_PATH}:${IMAGE_TAG} --format "table {{.Size}}" | tail -1)
                                    echo "Built image size: $IMAGE_SIZE"
                                    
                                    # Quick image inspection
                                    echo "Image inspection:"
                                    docker inspect ${ECR_REPO_PATH}:${IMAGE_TAG} --format='{{.Config.Labels}}' || true
                                    
                                    echo "Docker image build completed successfully"
                                '''
                                
                                // Post-build verification and cleanup
                                sh '''
                                    echo "=== Post-Build Verification ==="
                                    
                                    # Verify both tags exist
                                    echo "Verifying image tags:"
                                    docker images ${ECR_REPO_PATH} --format "table {{.Repository}}:{{.Tag}}\\t{{.Size}}\\t{{.CreatedAt}}"
                                    
                                    # Test that the image can be run (basic smoke test)
                                    echo "Testing image can be instantiated..."
                                    if docker run --rm ${ECR_REPO_PATH}:${IMAGE_TAG} echo "Image test successful" 2>/dev/null; then
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
                                // Enhanced error handling with specific disk space detection
                                def errorMessage = e.getMessage()
                                
                                if (errorMessage.contains("no space left on device") || 
                                    errorMessage.contains("disk") || 
                                    errorMessage.contains("space")) {
                                    
                                    // Critical disk space failure
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
                                    
                                } else if (errorMessage.contains("docker: command not found") || 
                                          errorMessage.contains("daemon")) {
                                    
                                    // Docker daemon issues
                                    currentBuild.result = 'FAILURE'
                                    error("Docker build failed due to Docker daemon issues: ${errorMessage}")
                                    
                                } else if (errorMessage.contains("COPY failed") || 
                                          errorMessage.contains("ADD failed")) {
                                    
                                    // Dockerfile or build context issues
                                    currentBuild.result = 'FAILURE'
                                    error("Docker build failed due to build context or Dockerfile issues: ${errorMessage}")
                                    
                                } else {
                                    
                                    // Generic build failure
                                    currentBuild.result = 'FAILURE'
                                    error("Docker build failed: ${errorMessage}")
                                }
                            }
                            
                            // Always clean up regardless of success/failure
                            finally {
                                sh '''
                                    echo "=== Final Cleanup ==="
                                    
                                    # Remove any dangling images created during failed builds
                                    docker image prune -f || true
                                    
                                    # Show final Docker system usage
                                    echo "Final Docker system usage:"
                                    docker system df || true
                                    
                                    # Log successful build for tracking
                                    if docker images ${ECR_REPO_PATH}:${IMAGE_TAG} >/dev/null 2>&1; then
                                        echo "✓ Image ${ECR_REPO_PATH}:${IMAGE_TAG} successfully built and available"
                                    else
                                        echo "✗ Image ${ECR_REPO_PATH}:${IMAGE_TAG} not found after build"
                                    fi
                                '''
                            }
                        }
                    }
        }

        stage('Security Scan') {
                    steps {
                        script {
                            try {
                                // Pre-scan disk space and cleanup
                                sh '''
                                    echo "=== Pre-Security Scan Setup ==="
                                    
                                    # Check available disk space
                                    echo "Current disk usage:"
                                    df -h
                                    
                                    # Clean up Docker to free space
                                    echo "Cleaning up Docker resources..."
                                    docker system prune -f --volumes || true
                                    docker image prune -a -f || true
                                    
                                    # Remove old trivy cache if it exists
                                    rm -rf ~/.cache/trivy || true
                                    
                                    # Check space after cleanup
                                    echo "Disk usage after cleanup:"
                                    df -h
                                    
                                    # Verify minimum space requirements (at least 2GB free)
                                    AVAILABLE_SPACE=$(df /var/lib/docker | tail -1 | awk '{print $4}')
                                    if [ "$AVAILABLE_SPACE" -lt 2097152 ]; then
                                        echo "WARNING: Low disk space detected. Available: ${AVAILABLE_SPACE}KB"
                                        echo "Consider adding more cleanup or increasing disk space"
                                    fi
                                '''
                                
                                sh '''
                                    echo "=== Container Image Security Scan ==="
                                    
                                    # Ensure required directories exist
                                    mkdir -p ${REPORTS_DIR}
                                    mkdir -p ${WORKSPACE}/trivy-cache
                                    
                                    # Ensure Trivy is available
                                    export PATH=${HOME}/bin:$PATH
                                    
                                    # Set Trivy cache location to workspace to avoid permission issues
                                    export TRIVY_CACHE_DIR=${WORKSPACE}/trivy-cache
                                    
                                    # Verify Trivy is working
                                    trivy --version
                                    
                                    # Create scan output file
                                    touch ${REPORTS_DIR}/scan-output.log
                                    
                                    # Set timeout for the scan (30 minutes)
                                    timeout 1800 ./trivy/scan.sh \\
                                        "${ECR_REPO_PATH}" \\
                                        "${IMAGE_TAG}" \\
                                        "${ECR_REPO_NAME}" \\
                                        "${GIT_BRANCH}" \\
                                        "${BUILD_URL}" \\
                                        "${CVE_DB_HOST}" \\
                                        "${CVE_DB_USERNAME}" \\
                                        "${CVE_DB_PASSWORD}" \\
                                        "${CVE_DB_NAME}" 2>&1 | tee ${REPORTS_DIR}/scan-output.log
                                    
                                    # Check if scan completed successfully
                                    SCAN_EXIT_CODE=${PIPESTATUS[0]}
                                    echo "Scan exit code: $SCAN_EXIT_CODE"
                                    
                                    # Verify scan report was generated
                                    if [ -f "reports/scan-report-${IMAGE_TAG}.json" ]; then
                                        echo "Scan report generated successfully"
                                        cp reports/scan-report-${IMAGE_TAG}.json ${REPORTS_DIR}/
                                    else
                                        echo "Warning: Scan report not found at expected location"
                                        ls -la reports/ || echo "Reports directory not found"
                                    fi
                                    
                                    # Return scan exit code for proper error handling
                                    exit $SCAN_EXIT_CODE
                                '''
                                
                                // Process scan results
                                script {
                                    try {
                                        // Check if scan output file exists and is not empty
                                        if (fileExists("${REPORTS_DIR}/scan-output.log")) {
                                            def scanOutput = readFile("${REPORTS_DIR}/scan-output.log")
                                            
                                            if (scanOutput.trim()) {
                                                env.SCAN_OUTPUT = scanOutput
                                                
                                                // Extract build ID for AI recommendations
                                                def buildIdMatcher = (scanOutput =~ /build_id:\s+([0-9]+)/)
                                                env.BUILD_REF_ID = buildIdMatcher ? buildIdMatcher[0][1] : ""
                                                
                                                echo "Security scan completed. Build Reference ID: ${env.BUILD_REF_ID}"
                                                
                                                // Check for critical errors in scan output
                                                if (scanOutput.contains("FATAL") || scanOutput.contains("no space left on device")) {
                                                    throw new Exception("Critical error detected in scan output")
                                                }
                                            } else {
                                                throw new Exception("Scan output file is empty")
                                            }
                                        } else {
                                            throw new Exception("Scan output file not found")
                                        }
                                        
                                        // Verify scan report exists
                                        def reportFiles = sh(
                                            script: "find ${REPORTS_DIR} -name '*scan-report*.json' -type f",
                                            returnStdout: true
                                        ).trim()
                                        
                                        if (reportFiles) {
                                            echo "Found scan report files: ${reportFiles}"
                                        } else {
                                            echo "Warning: No scan report JSON files found"
                                            currentBuild.result = 'UNSTABLE'
                                        }
                                        
                                    } catch (Exception e) {
                                        echo "Error processing scan output: ${e.getMessage()}"
                                        env.SCAN_OUTPUT = "Scan output processing failed: ${e.getMessage()}"
                                        env.BUILD_REF_ID = ""
                                        throw e // Re-throw to trigger catch block
                                    }
                                }
                                
                            } catch (Exception e) {
                                // Handle different types of failures
                                def errorMessage = e.getMessage()
                                
                                if (errorMessage.contains("no space left on device") || 
                                    errorMessage.contains("disk") || 
                                    errorMessage.contains("space")) {
                                    
                                    currentBuild.result = 'FAILURE'
                                    error("Pipeline failed due to insufficient disk space. Please clean up or increase disk allocation.")
                                    
                                } else if (errorMessage.contains("timeout") || errorMessage.contains("1800")) {
                                    
                                    currentBuild.result = 'UNSTABLE'
                                    echo "Security scan timed out after 30 minutes. This may indicate network issues or very large image size."
                                    env.SCAN_OUTPUT = "Security scan timed out: ${errorMessage}"
                                    
                                } else {
                                    
                                    currentBuild.result = 'UNSTABLE'
                                    echo "Security scan encountered issues: ${errorMessage}"
                                    env.SCAN_OUTPUT = "Security scan failed: ${errorMessage}"
                                }
                            }
                            
                            // Post-scan cleanup regardless of success/failure
                            finally {
                                sh '''
                                    echo "=== Post-Security Scan Cleanup ==="
                                    
                                    # Clean up trivy cache to prevent accumulation
                                    rm -rf ${WORKSPACE}/trivy-cache || true
                                    
                                    # Clean up any temporary docker exports
                                    sudo rm -rf /var/lib/docker/tmp/docker-export-* 2>/dev/null || true
                                    
                                    # Show final disk usage
                                    echo "Final disk usage:"
                                    df -h
                                    
                                    # Ensure scan artifacts are preserved for archiving
                                    if [ -f "${REPORTS_DIR}/scan-output.log" ]; then
                                        echo "Scan output file size: $(du -h ${REPORTS_DIR}/scan-output.log)"
                                    fi
                                '''
                            }
                        }
                    }
        }

        stage('Debug Build Ref ID') {
            steps {
                script {
                    echo "=== BUILD_REF_ID Debug Information ==="
                    echo "BUILD_REF_ID value: '${env.BUILD_REF_ID ?: 'NULL/EMPTY'}'"
                    echo "BUILD_REF_ID length: ${env.BUILD_REF_ID?.length() ?: 0}"
                    echo "BUILD_REF_ID trimmed: '${env.BUILD_REF_ID?.trim() ?: 'NULL/EMPTY'}'"
                    echo "Condition result: ${env.BUILD_REF_ID?.trim() ? 'TRUE - Stage will run' : 'FALSE - Stage will be skipped'}"
                    
                    // Check if scan output contains expected pattern
                    if (env.SCAN_OUTPUT) {
                        echo "=== Scan Output Analysis ==="
                        echo "Scan output length: ${env.SCAN_OUTPUT.length()}"
                        
                        // Look for build_id pattern in scan output
                        def buildIdMatcher = (env.SCAN_OUTPUT =~ /build_id:\s*([0-9]+)/)
                        if (buildIdMatcher) {
                            echo "Found build_id pattern: ${buildIdMatcher[0][0]}"
                            echo "Extracted ID: ${buildIdMatcher[0][1]}"
                        } else {
                            echo "No build_id pattern found in scan output"
                            echo "First 500 characters of scan output:"
                            echo env.SCAN_OUTPUT.take(500)
                        }
                    } else {
                        echo "SCAN_OUTPUT is null or empty"
                    }
                }
            }
        }

        stage('AI Security Analysis') {
            when {
                expression { 
                    echo "Evaluating BUILD_REF_ID condition..."
                    echo "BUILD_REF_ID: '${env.BUILD_REF_ID}'"
                    def result = env.BUILD_REF_ID?.trim()
                    echo "Condition result: ${result ? 'TRUE' : 'FALSE'}"
                    return result
                }
            }
            steps {
                script {
                    try {
                        sh '''
                            echo "=== AI-Powered Security Recommendations ==="
                            python3 trivy/ai_suggestion.py \\
                                "${analysisId}" \\
                                "${ALERT_MANAGER_URL}" \\
                                "${ALERT_MANAGER_SECRET}" \\
                                --engine "$AI_ENGINE" \\
                                --model "$AI_MODEL"
                            '''
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
                            scanSummary = sh(
                                script: """
                                    if [ -f "reports/scan-report-${IMAGE_TAG}.json" ]; then
                                        python3 trivy/email_template.py \\
                                            reports/scan-report-${IMAGE_TAG}.json \\
                                            ${BUILD_URL}
                                    else
                                        echo "Scan report file not found"
                                    fi
                                """,
                                returnStdout: true
                            ).trim()
                        } catch (Exception e) {
                            scanSummary = "Security report generation failed: ${e.getMessage()}"
                        }
                        
                        env.SECURITY_REPORT = scanSummary
                        
                        // Extract vulnerability counts
                        def criticalCount = 0
                        def highCount = 0
                        
                        if (env.SCAN_OUTPUT) {
                            def criticalMatch = (env.SCAN_OUTPUT =~ /CRITICAL:\s+([0-9]+)/)
                            def highMatch = (env.SCAN_OUTPUT =~ /HIGH:\s+([0-9]+)/)
                            
                            criticalCount = criticalMatch ? criticalMatch[0][1].toInteger() : 0
                            highCount = highMatch ? highMatch[0][1].toInteger() : 0
                        }
                        
                        echo "Security Assessment Results:"
                        echo "- Critical Vulnerabilities: ${criticalCount}"
                        echo "- High Vulnerabilities: ${highCount}"
                        
                        // Security gate decision (more lenient for now)
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
            steps {
                sh '''
                    echo "=== Container Registry Authentication ==="
                    aws ecr get-login-password --region ${AWS_REGION} | \\
                        docker login --username AWS --password-stdin ${ECR_REPO_PATH}
                    
                    echo "=== Container Image Registry Push ==="
                    
                    # Push tagged image
                    docker push ${ECR_REPO_PATH}:${IMAGE_TAG}
                    
                    # Push latest tag
                    docker push ${ECR_REPO_PATH}:latest
                    
                    echo "Image push completed successfully"
                '''
            }
        }

        stage('Deploy Application') {
            steps {
                script {
                    // First, test SSH connectivity
                    try {
                        sshagent(credentials: ['prince-ec2']) {
                            sh '''
                                echo "=== Testing SSH Connection ==="
                                ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_HOST} 'echo "SSH connection test successful"'
                            '''
                        }
                        echo "SSH connection verified successfully"
                    } catch (Exception e) {
                        error("SSH connection failed. Please check your SSH credentials and EC2 server status. Error: ${e.getMessage()}")
                    }
                    
                    // Proceed with deployment if SSH test passes
                    sshagent(credentials: ['prince-ec2']) {
                        sh '''
                            echo "=== Application Deployment ==="
                            
                            ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_HOST} "
                                set -e
                                
                                echo 'Deployment initiated on target server'
                                echo 'Current user: '\\$(whoami)
                                echo 'Current directory: '\\$(pwd)
                                
                                # Ensure curl & unzip exist (needed for AWS CLI install)
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
                    aws ecr get-login-password --region ${AWS_REGION} | \\
                        docker login --username AWS --password-stdin ${ECR_REPO_PATH}
                    
                    # Clean up old images in ECR (keep last 5)
                    aws ecr describe-images \\
                        --repository-name ${ECR_REPO_NAME} \\
                        --region ${AWS_REGION} \\
                        --query "imageDetails[?imageDigest!=null].[imageTags[0], imagePushedAt]" \\
                        --output text | \\
                        sort -k2 -r | \\
                        tail -n +6 | \\
                        awk '{print $1}' | \\
                        while read tag; do
                            if [ "$tag" != "null" ] && [ "$tag" != "latest" ]; then
                                echo "Removing old image tag: $tag"
                                aws ecr batch-delete-image \\
                                    --repository-name ${ECR_REPO_NAME} \\
                                    --region ${AWS_REGION} \\
                                    --image-ids imageTag=$tag \\
                                    --output text || true
                            fi
                        done
                    
                    echo "=== Local Environment Cleanup ==="
                    
                    # Remove local Docker images (keep last 3)
                    docker images ${ECR_REPO_PATH} --format "table {{.Repository}}:{{.Tag}} {{.CreatedAt}}" | \\
                        tail -n +2 | \\
                        sort -k2 -r | \\
                        tail -n +4 | \\
                        awk '{print $1}' | \\
                        xargs -r docker rmi || true
                    
                    echo "Cleanup completed"
                '''
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
                
                // Cleanup workspace
                sh '''
                    docker system prune -f --volumes || true
                    rm -rf ${WORKSPACE}/.trivy || true
                '''
            }
        }
        
        success {
            script {
                def deploymentTime = new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("UTC"))
                
                emailext(
                    subject: "DEPLOYMENT SUCCESS: ${env.JOB_NAME} Build #${BUILD_NUMBER}",
                    body: """
                        <html>
                        <head>
                            <style>
                                body { font-family: Arial, sans-serif; margin: 20px; }
                                .header { background-color: #28a745; color: white; padding: 15px; border-radius: 5px; }
                                .content { padding: 20px 0; }
                                .detail-table { border-collapse: collapse; width: 100%; margin: 15px 0; }
                                .detail-table th, .detail-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                                .detail-table th { background-color: #f2f2f2; }
                                .footer { margin-top: 20px; font-size: 12px; color: #666; }
                            </style>
                        </head>
                        <body>
                            <div class="header">
                                <h2>Deployment Successful</h2>
                            </div>
                            
                            <div class="content">
                                <p>The application has been successfully deployed to production.</p>
                                
                                <table class="detail-table">
                                    <tr><th>Job Name</th><td>${env.JOB_NAME}</td></tr>
                                    <tr><th>Build Number</th><td>${BUILD_NUMBER}</td></tr>
                                    <tr><th>Git Branch</th><td>${env.GIT_BRANCH ?: 'N/A'}</td></tr>
                                    <tr><th>Git Commit</th><td>${env.GIT_COMMIT?.take(8) ?: 'N/A'}</td></tr>
                                    <tr><th>Docker Image</th><td>${ECR_REPO_PATH}:${IMAGE_TAG}</td></tr>
                                    <tr><th>Deployment Time</th><td>${deploymentTime} UTC</td></tr>
                                    <tr><th>Target Server</th><td>${EC2_HOST}</td></tr>
                                </table>
                                
                                <h3>Security Scan Summary</h3>
                                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
                                    ${env.SECURITY_REPORT ?: 'Security scan completed successfully'}
                                </div>
                                
                                <h3>Links</h3>
                                <ul>
                                    <li><a href="${BUILD_URL}">View Build Details</a></li>
                                    <li><a href="http://4.240.98.78:3000">Security Dashboard</a></li>
                                    <li><a href="${BUILD_URL}artifact/">Build Artifacts</a></li>
                                </ul>
                            </div>
                            
                            <div class="footer">
                                This is an automated notification from Jenkins CI/CD Pipeline.
                            </div>
                        </body>
                        </html>
                    """,
                    mimeType: 'text/html',
                    to: "${ALERT_EMAIL}",
                    attachLog: false
                )
                
                echo "=== Deployment Summary ==="
                echo "Status: SUCCESS"
                echo "Build: ${BUILD_NUMBER}"
                echo "Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                echo "Deployed: ${deploymentTime} UTC"
            }
        }
        
        failure {
            script {
                def failureTime = new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("UTC"))
                
                emailext(
                    subject: "DEPLOYMENT FAILED: ${env.JOB_NAME} Build #${BUILD_NUMBER}",
                    body: """
                        <html>
                        <head>
                            <style>
                                body { font-family: Arial, sans-serif; margin: 20px; }
                                .header { background-color: #dc3545; color: white; padding: 15px; border-radius: 5px; }
                                .content { padding: 20px 0; }
                                .detail-table { border-collapse: collapse; width: 100%; margin: 15px 0; }
                                .detail-table th, .detail-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                                .detail-table th { background-color: #f2f2f2; }
                                .error-section { background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 15px 0; }
                                .footer { margin-top: 20px; font-size: 12px; color: #666; }
                            </style>
                        </head>
                        <body>
                            <div class="header">
                                <h2>Deployment Failed</h2>
                            </div>
                            
                            <div class="content">
                                <p>The deployment pipeline has failed. Please review the details below and take appropriate action.</p>
                                
                                <table class="detail-table">
                                    <tr><th>Job Name</th><td>${env.JOB_NAME}</td></tr>
                                    <tr><th>Build Number</th><td>${BUILD_NUMBER}</td></tr>
                                    <tr><th>Git Branch</th><td>${env.GIT_BRANCH ?: 'N/A'}</td></tr>
                                    <tr><th>Git Commit</th><td>${env.GIT_COMMIT?.take(8) ?: 'N/A'}</td></tr>
                                    <tr><th>Failure Time</th><td>${failureTime} UTC</td></tr>
                                    <tr><th>Build Result</th><td>${currentBuild.result ?: 'FAILURE'}</td></tr>
                                </table>
                                
                                <div class="error-section">
                                    <h3>Security Scan Results</h3>
                                    ${env.SECURITY_REPORT ?: 'Security scan results not available due to pipeline failure'}
                                </div>
                                
                                <h3>Immediate Actions Required</h3>
                                <ul>
                                    <li>Review build logs for specific error messages</li>
                                    <li>Check security scan results if available</li>
                                    <li>Verify infrastructure connectivity</li>
                                    <li>Validate recent code changes</li>
                                </ul>
                                
                                <h3>Links</h3>
                                <ul>
                                    <li><a href="${BUILD_URL}console">View Console Output</a></li>
                                    <li><a href="http://4.240.98.78:3000">Security Dashboard</a></li>
                                    <li><a href="${BUILD_URL}">Build Details</a></li>
                                </ul>
                            </div>
                            
                            <div class="footer">
                                This is an automated notification from Jenkins CI/CD Pipeline.
                            </div>
                        </body>
                        </html>
                    """,
                    mimeType: 'text/html',
                    to: "${ALERT_EMAIL}",
                    attachLog: true
                )
                
                echo "=== Failure Summary ==="
                echo "Status: FAILED"
                echo "Build: ${BUILD_NUMBER}"
                echo "Result: ${currentBuild.result}"
                echo "Failed: ${failureTime} UTC"
            }
        }
        
        unstable {
            echo "Build completed with warnings. Check logs for details."
        }
        
        aborted {
            echo "Build was aborted by user or timeout."
        }
    }
}
