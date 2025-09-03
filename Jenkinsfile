pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 1, unit: 'HOURS')
        retry(1)
        skipDefaultCheckout()
    }

    environment {
        // Repository Configuration
        GIT_REPO = "https://github.com/XXRadeonXFX/trivy-grafana-ai-alert-automation"
        GIT_BRANCH = "main"
        
        // Infrastructure Configuration
        EC2_SSH = "prince-ec2"
        EC2_USER = "ubuntu"
        EC2_HOST = "15.206.75.104"
        AWS_REGION = "ap-south-1"
        
        // Container Registry Configuration
        ECR_REPO_PATH = "975050024946.dkr.ecr.ap-south-1.amazonaws.com/prince-reg"
        ECR_REPO_NAME = "prince-reg"
        IMAGE_TAG = "build-${BUILD_NUMBER}-${GIT_COMMIT.take(7)}"
        ECR_RETAIN_COUNT = "10"
        
        // AWS Credentials
        AWS_ACCESS_KEY_ID = credentials('prince-access-key-id')
        AWS_SECRET_ACCESS_KEY = credentials('prince-secret-access-key')
        
        // Application Configuration
        CONTAINER_NAME = "user-api"
        CONTAINER_PORT = "8000"
        DATABASE_URL = credentials('prince-mern-database')
        JWT_SECRET_KEY = credentials('JWT_SECRET_KEY')
        
        // Security Scanning Configuration
        CVE_DB_HOST = credentials('CVE_DB_HOST')
        CVE_DB_USERNAME = credentials('CVE_DB_USERNAME')
        CVE_DB_PASSWORD = credentials('CVE_DB_PASSWORD')
        CVE_DB_NAME = credentials('CVE_DB_NAME')
        
        // Alert Manager Configuration
        ALERT_MANAGER_URL = "http://4.240.98.78:8000"
        ALERT_MANAGER_SECRET = credentials('ALERT_MANAGER_SECRET')
        
        // Notification Configuration
        ALERT_EMAIL = "prince.thakur24051996@gmail.com"
        
        // Tool Paths
        TRIVY_CACHE_DIR = "${WORKSPACE}/.trivy"
        REPORTS_DIR = "${WORKSPACE}/reports"
    }

    stages {
        stage('Initialize') {
            steps {
                script {
                    currentBuild.displayName = "#${BUILD_NUMBER}-${GIT_BRANCH}"
                    currentBuild.description = "Build: ${IMAGE_TAG}"
                }
                
                echo "=== Build Information ==="
                echo "Build Number: ${BUILD_NUMBER}"
                echo "Git Branch: ${GIT_BRANCH}"
                echo "Docker Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                echo "Build Timestamp: ${new Date()}"
                
                // Create required directories
                sh '''
                    mkdir -p ${TRIVY_CACHE_DIR}
                    mkdir -p ${REPORTS_DIR}
                    mkdir -p test-reports
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
                
                script {
                    env.GIT_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                }
            }
        }

        stage('Code Verification') {
            parallel {
                stage('Verify Repository Structure') {
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
                            
                            if [ ! -f "docker-compose.yaml" ] && [ ! -f "docker-compose.yml" ]; then
                                echo "WARNING: docker-compose file not found"
                            fi
                            
                            if [ ! -d "trivy" ]; then
                                echo "ERROR: Trivy security scanning directory not found"
                                exit 1
                            fi
                            
                            echo "Repository structure verification completed"
                        '''
                    }
                }
                
                stage('Verify Trivy Components') {
                    steps {
                        sh '''
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
                            chmod +x trivy/*.sh
                            chmod +x trivy/*.py
                            
                            echo "Trivy components verification completed"
                        '''
                    }
                }
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
                                # Create symlink for global access
                                ln -sf ${HOME}/bin/trivy /usr/local/bin/trivy 2>/dev/null || echo "Could not create global symlink, using local installation"
                            else
                                echo "ERROR: Trivy installation failed"
                                exit 1
                            fi
                        fi
                        
                        # Update Trivy database
                        echo "Updating Trivy vulnerability database"
                        trivy --cache-dir ${TRIVY_CACHE_DIR} image --download-db-only
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
                            max_attempts=60
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
                                echo "ERROR: MongoDB failed to start within timeout period"
                                docker-compose logs mongo-db
                                exit 1
                            fi
                            
                            # Execute tests
                            echo "Executing test suite"
                            docker-compose run --rm test pytest \\
                                --maxfail=5 \\
                                --tb=short \\
                                --disable-warnings \\
                                --junitxml=test-reports/test-results.xml \\
                                --cov=. \\
                                --cov-report=xml:test-reports/coverage.xml \\
                                --cov-report=html:test-reports/htmlcov \\
                                --verbose
                        '''
                    } catch (Exception e) {
                        echo "Test execution failed: ${e.getMessage()}"
                        currentBuild.result = 'UNSTABLE'
                        sh 'docker-compose logs || true'
                        throw e
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
                    junit(
                        testResults: 'test-reports/*.xml',
                        allowEmptyResults: true,
                        skipPublishingChecks: true
                    )
                    publishHTML([
                        allowMissing: true,
                        alwaysLinkToLastBuild: false,
                        keepAll: true,
                        reportDir: 'test-reports/htmlcov',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
                failure {
                    echo "Unit tests failed. Check test reports for details."
                }
            }
        }

        stage('Build Application Image') {
            steps {
                script {
                    sh '''
                        echo "=== Docker Image Build ==="
                        
                        # Build Docker image with build args
                        docker build \\
                            --tag ${ECR_REPO_PATH}:${IMAGE_TAG} \\
                            --tag ${ECR_REPO_PATH}:latest \\
                            --label "build.number=${BUILD_NUMBER}" \\
                            --label "build.url=${BUILD_URL}" \\
                            --label "git.commit=${GIT_COMMIT}" \\
                            --label "git.branch=${GIT_BRANCH}" \\
                            --no-cache \\
                            .
                        
                        # Verify image was created
                        docker images ${ECR_REPO_PATH}:${IMAGE_TAG}
                        
                        echo "Docker image build completed successfully"
                    '''
                }
            }
        }

        stage('Security Scan') {
            parallel {
                stage('Vulnerability Scan') {
                    steps {
                        script {
                            try {
                                sh '''
                                    echo "=== Container Image Security Scan ==="
                                    
                                    # Ensure Trivy is available
                                    if ! command -v trivy >/dev/null 2>&1; then
                                        export PATH=${HOME}/bin:$PATH
                                    fi
                                    
                                    # Verify Trivy is working
                                    trivy --version
                                    
                                    # Execute security scan
                                    ./trivy/scan.sh \\
                                        "${ECR_REPO_PATH}" \\
                                        "${IMAGE_TAG}" \\
                                        "${ECR_REPO_NAME}" \\
                                        "${GIT_BRANCH}" \\
                                        "${BUILD_URL}" \\
                                        "${CVE_DB_HOST}" \\
                                        "${CVE_DB_USERNAME}" \\
                                        "${CVE_DB_PASSWORD}" \\
                                        "${CVE_DB_NAME}"
                                '''
                                
                                // Process scan results
                                def scanOutput = readFile("${REPORTS_DIR}/scan-output.log")
                                env.SCAN_OUTPUT = scanOutput
                                
                                // Extract build ID for AI recommendations
                                def buildIdMatcher = (scanOutput =~ /build_id:\s+([0-9]+)/)
                                env.BUILD_REF_ID = buildIdMatcher ? buildIdMatcher[0][1] : ""
                                
                                echo "Security scan completed. Build Reference ID: ${env.BUILD_REF_ID}"
                                
                            } catch (Exception e) {
                                currentBuild.result = 'UNSTABLE'
                                echo "Security scan encountered issues: ${e.getMessage()}"
                                throw e
                            }
                        }
                    }
                }
                
                stage('Image Quality Check') {
                    steps {
                        sh '''
                            echo "=== Docker Image Quality Assessment ==="
                            
                            # Check image size
                            image_size=$(docker images ${ECR_REPO_PATH}:${IMAGE_TAG} --format "table {{.Size}}" | tail -n 1)
                            echo "Image size: $image_size"
                            
                            # Check image layers
                            layer_count=$(docker history ${ECR_REPO_PATH}:${IMAGE_TAG} | wc -l)
                            echo "Layer count: $layer_count"
                            
                            # Basic image inspection
                            docker inspect ${ECR_REPO_PATH}:${IMAGE_TAG} > ${REPORTS_DIR}/image-inspection.json
                            
                            echo "Image quality assessment completed"
                        '''
                    }
                }
            }
        }

        stage('AI Security Analysis') {
            when {
                expression { env.BUILD_REF_ID?.trim() }
            }
            steps {
                script {
                    try {
                        sh '''
                            echo "=== AI-Powered Security Recommendations ==="
                            python3 trivy/ai_suggestion.py \\
                                "${BUILD_REF_ID}" \\
                                "${ALERT_MANAGER_URL}" \\
                                "${ALERT_MANAGER_SECRET}"
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
                        def scanSummary = sh(
                            script: """
                                python3 trivy/email_template.py \\
                                    ${REPORTS_DIR}/scan-report-${IMAGE_TAG}.json \\
                                    ${BUILD_URL}
                            """,
                            returnStdout: true
                        ).trim()
                        
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
                        
                        // Security gate decision
                        if (criticalCount > 0) {
                            error("SECURITY GATE FAILED: ${criticalCount} critical vulnerabilities found. Deployment blocked.")
                        } else if (highCount > 5) {
                            echo "WARNING: ${highCount} high-severity vulnerabilities detected."
                            echo "Consider addressing these vulnerabilities in the next release."
                        } else {
                            echo "Security gate passed. No critical vulnerabilities detected."
                        }
                        
                    } catch (Exception e) {
                        currentBuild.result = 'FAILURE'
                        echo "Security gate evaluation failed: ${e.getMessage()}"
                        throw e
                    }
                }
            }
        }

        stage('Registry Operations') {
            parallel {
                stage('Authenticate Registry') {
                    steps {
                        sh '''
                            echo "=== Container Registry Authentication ==="
                            aws ecr get-login-password --region ${AWS_REGION} | \\
                                docker login --username AWS --password-stdin ${ECR_REPO_PATH}
                        '''
                    }
                }
                
                stage('Push Image') {
                    steps {
                        sh '''
                            echo "=== Container Image Registry Push ==="
                            
                            # Push tagged image
                            docker push ${ECR_REPO_PATH}:${IMAGE_TAG}
                            
                            # Push latest tag
                            docker push ${ECR_REPO_PATH}:latest
                            
                            echo "Image push completed successfully"
                        '''
                    }
                }
            }
        }

        stage('Deploy Application') {
            steps {
                sshagent(credentials: [env.EC2_SSH]) {
                    sh '''
                        echo "=== Application Deployment ==="
                        
                        ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_HOST} "
                            set -e
                            
                            # Export AWS credentials
                            export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
                            export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
                            export AWS_DEFAULT_REGION=${AWS_REGION}
                            
                            echo 'Deployment initiated on target server'
                            
                            # Authenticate with ECR
                            aws ecr get-login-password --region ${AWS_REGION} | \\
                                docker login --username AWS --password-stdin ${ECR_REPO_PATH}
                            
                            # Pull latest image
                            echo 'Pulling application image'
                            docker pull ${ECR_REPO_PATH}:${IMAGE_TAG}
                            
                            # Stop existing container
                            echo 'Stopping existing application container'
                            docker stop ${CONTAINER_NAME} 2>/dev/null || true
                            docker rm ${CONTAINER_NAME} 2>/dev/null || true
                            
                            # Start new container
                            echo 'Starting new application container'
                            docker run -d \\
                                --name ${CONTAINER_NAME} \\
                                --port ${CONTAINER_PORT}:${CONTAINER_PORT} \\
                                --restart unless-stopped \\
                                --env PORT=${CONTAINER_PORT} \\
                                --env MONGO_URI=${DATABASE_URL} \\
                                --env JWT_SECRET_KEY=${JWT_SECRET_KEY} \\
                                --env MONGO_DB_NAME=flask_db \\
                                --env NODE_ENV=production \\
                                --label deployment.build=${BUILD_NUMBER} \\
                                --label deployment.timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) \\
                                ${ECR_REPO_PATH}:${IMAGE_TAG}
                            
                            # Verify deployment
                            echo 'Verifying deployment'
                            sleep 10
                            
                            if docker ps | grep -q ${CONTAINER_NAME}; then
                                echo 'Deployment verification successful'
                            else
                                echo 'Deployment verification failed'
                                docker logs ${CONTAINER_NAME}
                                exit 1
                            fi
                            
                            echo 'Application deployment completed successfully'
                        "
                    '''
                }
            }
        }

        stage('Post-Deployment Cleanup') {
            parallel {
                stage('Registry Cleanup') {
                    steps {
                        sh '''
                            echo "=== Container Registry Cleanup ==="
                            
                            # Authenticate with ECR
                            aws ecr get-login-password --region ${AWS_REGION} | \\
                                docker login --username AWS --password-stdin ${ECR_REPO_PATH}
                            
                            # Clean up old images in ECR
                            aws ecr describe-images \\
                                --repository-name ${ECR_REPO_NAME} \\
                                --region ${AWS_REGION} \\
                                --query "imageDetails[?imageDigest!=null].[imageTags[0], imagePushedAt]" \\
                                --output text | \\
                                sort -k2 -r | \\
                                tail -n +${ECR_RETAIN_COUNT} | \\
                                awk '{print $1}' | \\
                                while read tag; do
                                    if [ "$tag" != "null" ] && [ "$tag" != "latest" ]; then
                                        echo "Removing old image tag: $tag"
                                        aws ecr batch-delete-image \\
                                            --repository-name ${ECR_REPO_NAME} \\
                                            --region ${AWS_REGION} \\
                                            --image-ids imageTag=$tag \\
                                            --output text
                                    fi
                                done
                        '''
                    }
                }
                
                stage('Local Cleanup') {
                    steps {
                        sh '''
                            echo "=== Local Environment Cleanup ==="
                            
                            # Remove local Docker images (keep last 3)
                            docker images ${ECR_REPO_PATH} --format "table {{.Repository}}:{{.Tag}} {{.CreatedAt}}" | \\
                                tail -n +2 | \\
                                sort -k2 -r | \\
                                tail -n +4 | \\
                                awk '{print $1}' | \\
                                xargs -r docker rmi || true
                            
                            # Clean up build artifacts
                            rm -rf ${TRIVY_CACHE_DIR}/* || true
                            
                            echo "Local cleanup completed"
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                // Archive build artifacts
                archiveArtifacts(
                    artifacts: 'reports/**/*,test-reports/**/*',
                    allowEmptyArchive: true,
                    fingerprint: true
                )
                
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
                                    <tr><th>Git Branch</th><td>${GIT_BRANCH}</td></tr>
                                    <tr><th>Git Commit</th><td>${env.GIT_COMMIT?.take(8) ?: 'N/A'}</td></tr>
                                    <tr><th>Docker Image</th><td>${ECR_REPO_PATH}:${IMAGE_TAG}</td></tr>
                                    <tr><th>Deployment Time</th><td>${deploymentTime} UTC</td></tr>
                                    <tr><th>Target Server</th><td>${EC2_HOST}</td></tr>
                                </table>
                                
                                <h3>Security Scan Summary</h3>
                                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
                                    ${env.SECURITY_REPORT ?: 'Security scan results not available'}
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
                                    <tr><th>Git Branch</th><td>${GIT_BRANCH}</td></tr>
                                    <tr><th>Git Commit</th><td>${env.GIT_COMMIT?.take(8) ?: 'N/A'}</td></tr>
                                    <tr><th>Failure Time</th><td>${failureTime} UTC</td></tr>
                                    <tr><th>Build Result</th><td>${currentBuild.result ?: 'FAILURE'}</td></tr>
                                </table>
                                
                                <div class="error-section">
                                    <h3>Security Scan Results</h3>
                                    ${env.SECURITY_REPORT ?: 'Security scan results not available due to early pipeline failure'}
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
