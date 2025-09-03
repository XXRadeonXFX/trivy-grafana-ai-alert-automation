pipeline {
    agent any

    environment {
        GIT_REPO = "https://github.com/XXRadeonXFX/trivy-grafana-ai-alert-automation"
        GIT_BRANCH = "main"
        EC2_SSH = "thiru-ec2"
        EC2_USER = "ubuntu"
        EC2_HOST = "13.201.59.34"
        AWS_REGION = "ap-south-1"
        ECR_REPO_PATH = "975050024946.dkr.ecr.ap-south-1.amazonaws.com/prince-reg"
        ECR_REPO_NAME = "prince-reg"
        IMAGE_TAG = "dev-${BUILD_NUMBER}"
        AWS_ACCESS_KEY_ID = credentials('prince-access-key-id')
        AWS_SECRET_ACCESS_KEY = credentials('prince-secret-access-key')
        DOCKER_NETWORK = "app-network"
        ALERT_EMAIL = "prince.thakur24051996@gmail.com"
        CONTAINER_NAME= "user-api"
        DATABASE_URL = credentials('prince-mern-database')
        CVE_DB_HOST = credentials('CVE_DB_HOST')
        CVE_DB_USERNAME = credentials('CVE_DB_USERNAME')
        CVE_DB_PASSWORD = credentials('CVE_DB_PASSWORD')
        CVE_DB_NAME = credentials('CVE_DB_NAME')
        ECR_RETAIN_COUNT = 6
        CONTAINER_PORT= 8000
        
        // Updated AlertManager URL to your Azure VM
        ALERT_MANAGER_URL= "http://4.240.98.78:8000"
        ALERT_MANAGER_SECRET= "yourapisecret"
    }

    stages {

        stage('Get Build Number') { 
            steps {
                echo "Build Number: ${BUILD_NUMBER}"
            }
        }

        stage("Checkout Git Repo "){
            steps{
                git(
                    url: "${GIT_REPO}",
                    branch: "${GIT_BRANCH}",
                    credentialsId: "prince-github-access"
                )
            }
        }

        stage("Verify the code") {
            steps {
                sh'''
                    pwd
                    ls -la
                '''
            }
        }
        
        stage('Run Tests') {
            steps {
                script {
                    try {
                        sh '''
                            echo "Removing existing MongoDB container if it exists..."
                            docker rm -f mongo-db || true

                            echo "Starting MongoDB with seed data..."
                            docker-compose up -d mongo-db

                            echo "Waiting for MongoDB to be ready..."
                            max_attempts=30
                            attempt=0
                            while [ $attempt -lt $max_attempts ]; do
                                docker-compose exec -T mongo-db mongosh --eval "db.runCommand({ping:1})" && break
                                echo "Waiting for MongoDB to be ready... (attempt $attempt)"
                                sleep 2
                                attempt=$((attempt+1))
                            done

                            if [ $attempt -eq $max_attempts ]; then
                                echo "MongoDB did not become ready in time"
                                exit 1
                            fi

                            echo "MongoDB is ready. Running tests..."
                            mkdir -p test-reports
                            docker-compose run --rm test pytest --maxfail=1 --disable-warnings --junitxml=test-reports/test-results.xml
                        '''
                    } catch (Exception e) {
                        echo "Test stage failed: ${e.getMessage()}"
                        throw e
                    } finally {
                        sh 'docker-compose down -v || true'
                    }
                }
            }
            post {
                always {
                    junit 'test-reports/*.xml'
                }
                failure {
                    echo "Tests failed. Check the test reports for details."
                }
            }
        }

        stage("Login to AWS ECR") {
            steps {
                sh """
                    aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REPO_PATH}
                """
            }
        }

        stage("Build and Push Image to ECR") {
            steps {
                sh """
                    echo "Docker Build Image.."
                    docker build -t ${ECR_REPO_PATH}:${IMAGE_TAG} .

                """
            }
        }

        stage("Scan the Image") {
            steps {
                script {
                    sh "chmod +x ./trivy/scan.sh"

                    // Capture scan output
                    def fullOutput = sh(
                        script: """
                            ./trivy/scan.sh \
                                "${ECR_REPO_PATH}" \
                                "${IMAGE_TAG}" \
                                "${ECR_REPO_NAME}" \
                                "${GIT_BRANCH}" \
                                "${env.BUILD_URL}" \
                                "${CVE_DB_HOST}" \
                                "${CVE_DB_USERNAME}" \
                                "${CVE_DB_PASSWORD}" \
                                "${CVE_DB_NAME}" || true
                        """,
                        returnStdout: true
                    ).trim()

                    env.FULL_RESULT = fullOutput

                    echo "Full Scan Output:\n${FULL_RESULT}"

                    // Extract build_id as String
                    def refBuildId = (fullOutput =~ /build_id:\s+([0-9]+)/)
                    env.REF_BUILD_ID = (refBuildId ? refBuildId[0][1] : "").toString()

                    echo "Reference Build ID: ${env.REF_BUILD_ID}"

                    
                }
            }
        }

        stage("Smart AI Recommendation Generate") {
            when {
                expression { return env.REF_BUILD_ID?.trim() }
            }
            steps {
                sh """
                    echo "Initiate AI recommendation API Call..."
                    python3 trivy/ai_suggestion.py ${env.REF_BUILD_ID} ${ALERT_MANAGER_URL} ${ALERT_MANAGER_SECRET}
                """
            }
        }

        stage("Validate Vulnerability Outcome") {
            steps {
                script {
                    // Keep only the last 3 lines (your summary)
                    def result = env.FULL_RESULT.readLines().findAll {
                        it.startsWith("Project:") || it.startsWith("Image:") || it.startsWith("CRITICAL:") || it.startsWith("HIGH:")
                    }.join("\n")

                    env.SCAN_RESULT = sh(
                        script: "python3 trivy/email_template.py reports/scan-report-${IMAGE_TAG}.json ${env.BUILD_URL}",
                        returnStdout: true
                    )
                    
                    // Fail build if CRITICAL or HIGH issues found
                    def criticalMatch = (result =~ /CRITICAL:\s+([0-9]+)/)
                    def highMatch     = (result =~ /HIGH:\s+([0-9]+)/)
                    
                    def criticalCount = criticalMatch ? criticalMatch[0][1].toInteger() : 0
                    def highCount     = highMatch ? highMatch[0][1].toInteger() : 0

                    if (criticalCount > 0 || highCount > 0) {
                        error("❌ Found vulnerabilities (CRITICAL: ${criticalCount}, HIGH: ${highCount}) – failing build!")
                    }
                }
            }
        }

        stage("Push Image to ECR") {
            steps {
                sh """
                    echo "Docker Push Image to ECR.."
                    docker push ${ECR_REPO_PATH}:${IMAGE_TAG}
                """
            }
        }

        stage("Deploy code to EC2"){
            steps{
                sshagent(credentials: [env.EC2_SSH]){
                    sh """
                        echo "login to EC2"
                        ssh -o StrictHostKeyChecking=no ${EC2_USER}@${EC2_HOST} '
                            export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
                            export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
                            export AWS_DEFAULT_REGION=${AWS_REGION}

                            echo "Login success.."

                            ls

                            sudo usermod -aG docker ${EC2_USER}

                            aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REPO_PATH} 

                            echo "Pull ECR Images.."
                            docker pull ${ECR_REPO_PATH}:${IMAGE_TAG}

                            echo "Remove Running containers"
                            docker stop ${CONTAINER_NAME} || true
                            docker rm ${CONTAINER_NAME} || true

                            echo "Start the new containers.."
                            docker run -d -p ${CONTAINER_PORT}:${CONTAINER_PORT} \
                            --name ${CONTAINER_NAME} \
                            -e PORT=${CONTAINER_PORT} \
                            -e MONGO_URI="${DATABASE_URL}" \
                            -e JWT_SECRET_KEY=thirumalaipy \
                            -e MONGO_DB_NAME=flask_db \
                            --restart unless-stopped \
                            ${ECR_REPO_PATH}:${IMAGE_TAG}

                            echo "Deployment done.."

                        '
                    """
                }
            }
        }

        stage("Clean up old ECR Images"){
            steps {
                sh """
                    aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REPO_PATH}

                    echo "Clear ECR Images"

                    aws ecr describe-images \
                    --repository-name ${ECR_REPO_NAME} \
                    --region ${AWS_REGION} \
                    --query "imageDetails[*].[imageTags[0], imagePushedAt]" \
                    --output text | \
                    sort -k2 -r | \
                    tail -n +${ECR_RETAIN_COUNT} | \
                    awk '{print \$1}' | \
                    while read item; do
                        echo "Deleted tag : \$item"

                        aws ecr batch-delete-image \
                        --repository-name ${ECR_REPO_NAME} \
                        --region ${AWS_REGION} \
                        --image-ids imageTag=\$item
                    done

                """
            }
        }

        
    }

    post {
        failure {
            echo 'Build or test failed. Sending notifications...'
            emailext(
    subject: "❌ Deployment Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
    body: """\
<html>
<body>
<h3>${env.JOB_NAME} Deployment FAILED ❌</h3>
<p style="font-size:16px; line-height:21px;"><strong>Job:</strong> ${env.JOB_NAME}</p>
<p style="font-size:16px; line-height:21px;"><strong>Build Number:</strong> ${env.BUILD_NUMBER}</p>
<p style="font-size:16px; line-height:21px;"><strong>Branch:</strong> ${env.GIT_BRANCH}</p>
<p style="font-size:16px; line-height:21px;"><strong>Git Repo:</strong> ${env.GIT_REPO}</p>
<p style="font-size:16px; line-height:21px;"><strong>Docker Image:</strong> ${ECR_REPO_PATH}:${IMAGE_TAG}</p>
<p style="font-size:16px; line-height:21px;"><strong>Failure Time:</strong> ${new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("Asia/Kolkata"))}</p>
<p style="font-size:18px; line-height:25px;"><strong>🔎 Trivy Scan Report:</strong></p>
${env.SCAN_RESULT}
<p style="font-size:16px; line-height:21px;"><a href="${env.BUILD_URL}">Click here to view full build logs</a></p>
</body>
</html>
""",
    mimeType: 'text/html',
    to: "${ALERT_EMAIL}"
)
            script {
                sh '''
                    echo "===== Deployment Success Summary ====="
                    echo "Build Number: ${BUILD_NUMBER}"
                    echo "Docker Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                    echo "Deployment Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

                    echo "===== Remove Old Images except last 2 ====="
                    docker images \
                    ${ECR_REPO_PATH} \
                    --format "{{.Repository}}:{{.Tag}} {{.CreatedAt}}" | \
                    sort -k2 | \
                    head -n -2 2>/dev/null | \
                    cut -d' ' -f1 | \
                    xargs -r docker rmi
                '''
            }

        }
        success {
            echo 'Build and deployment passed successfully!'
            emailext(
    subject: "✅ Build Success: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
    body: """\
<html>
<body>
<h3>${env.JOB_NAME} Build & Deployment SUCCEEDED ✅</h3>
<p style="font-size:16px; line-height:21px;"><strong>Job:</strong> ${env.JOB_NAME}</p>
<p style="font-size:16px; line-height:21px;"><strong>Build Number:</strong> ${env.BUILD_NUMBER}</p>
<p style="font-size:16px; line-height:21px;"><strong>Branch:</strong> ${env.GIT_BRANCH}</p>
<p style="font-size:16px; line-height:21px;"><strong>Git Repo:</strong> ${env.GIT_REPO}</p>
<p style="font-size:16px; line-height:21px;"><strong>Docker Image:</strong> ${ECR_REPO_PATH}:${IMAGE_TAG}</p>
<p style="font-size:16px; line-height:21px;"><strong>Failure Time:</strong> ${new Date().format("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("Asia/Kolkata"))}</p>
<p style="font-size:18px; line-height:25px;"><strong>🔎 Trivy Scan Report:</strong></p>
${env.SCAN_RESULT}
<p style="font-size:16px; line-height:21px;"><a href="${env.BUILD_URL}">Click here to view full build logs</a></p>
</body>
</html>
""",
    mimeType: 'text/html',
    to: "${ALERT_EMAIL}"
)

            script {
                sh '''
                    echo "===== Deployment Success Summary ====="
                    echo "Build Number: ${BUILD_NUMBER}"
                    echo "Docker Image: ${ECR_REPO_PATH}:${IMAGE_TAG}"
                    echo "Deployment Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"

                    echo "===== Remove Old Images except last 2 ====="
                    docker images \
                    ${ECR_REPO_PATH} \
                    --format "{{.Repository}}:{{.Tag}} {{.CreatedAt}}" | \
                    sort -k2 | \
                    head -n -2 | \
                    cut -d' ' -f1 | \
                    xargs -r docker rmi
                '''
            }
        }
    }
}
