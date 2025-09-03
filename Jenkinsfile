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
        EC2_HOST = "15.206.75.104"
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
    
    stage('Debug SSH to EC2') {
      steps {
        sshagent(credentials: [env.EC2_SSH]) {
          sh '''
            set -x
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 ${EC2_USER}@${EC2_HOST} "echo SSH OK && uname -a && whoami"
          '''
        }
      }
}
}
