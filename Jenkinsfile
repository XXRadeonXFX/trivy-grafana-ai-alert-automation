// Jenkinsfile (AI stage test only)
pipeline {
  agent any
  options {
    timeout(time: 15, unit: 'MINUTES')
    skipDefaultCheckout(true)
  }

  parameters {
    string(name: 'BUILD_REF_ID', defaultValue: '3', description: 'build_id to send')
    choice(name: 'AI_ENGINE', choices: ['openai', 'gemini'], description: 'AI provider')
    string(name: 'AI_MODEL', defaultValue: '', description: 'Optional model override')
    string(name: 'ALERT_MANAGER_URL', defaultValue: 'https://alerts.thakurprince.com', description: 'Service base URL')
    password(name: 'ALERT_MANAGER_SECRET', defaultValue: '', description: 'Value for api-secret header')
    string(name: 'GIT_BRANCH', defaultValue: 'main', description: 'Branch to checkout')
  }

  environment {
    GIT_REPO = 'https://github.com/XXRadeonXFX/trivy-grafana-ai-alert-automation'
  }

  stages {
    stage('Checkout for script') {
      steps {
        checkout([
          $class: 'GitSCM',
          branches: [[name: "*/${params.GIT_BRANCH}"]],
          userRemoteConfigs: [[
            url: "${GIT_REPO}",
            credentialsId: "prince-github-access"
          ]]
        ])
      }
    }

    stage('AI Security Analysis (TEST)') {
      steps {
        script {
          // Build optional --model arg in Groovy to avoid shell quoting mess
          def modelOpt = params.AI_MODEL?.trim() ? "--model ${params.AI_MODEL.trim()}" : ""

          sh """
            set -euo pipefail
            mkdir -p reports

            echo "=== AI-Powered Security Recommendations (TEST) ==="
            python3 trivy/ai_suggestion.py \\
              '${params.BUILD_REF_ID}' \\
              '${params.ALERT_MANAGER_URL}' \\
              '${params.ALERT_MANAGER_SECRET}' \\
              --engine ${params.AI_ENGINE} ${modelOpt} \\
              --timeout 60 --retries 3 --log-level INFO --json-only \\
              | tee "reports/ai-suggestion-${BUILD_NUMBER}.json"
          """

          // keep JSON handy for emails / later stages
          env.AI_SUGGESTION = readFile("reports/ai-suggestion-${env.BUILD_NUMBER}.json")
          echo "AI Suggestion JSON saved to reports/ai-suggestion-${env.BUILD_NUMBER}.json"
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/ai-suggestion-*.json',
                       allowEmptyArchive: true, fingerprint: true
    }
  }
}
