pipeline {
  agent any

  options {
    timeout(time: 15, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '10'))
  }

  parameters {
    string(name: 'BUILD_REF_ID', defaultValue: '26', description: 'build_id sent to /generate-ai-suggestion')
    choice(name: 'AI_ENGINE', choices: ['openai', 'gemini'], description: 'AI provider to use')
    string(name: 'AI_MODEL', defaultValue: '', description: 'Optional: override model (leave empty for default per engine)')
    string(name: 'ALERT_MANAGER_URL', defaultValue: 'https://alerts.thakurprince.com', description: 'Base URL of the AI Suggestion service')
  }

  environment {
    // your repo that contains trivy/ai_suggestion.py
    GIT_REPO   = 'https://github.com/XXRadeonXFX/trivy-grafana-ai-alert-automation'
    GIT_BRANCH = 'main'
  }

  stages {
    stage('Checkout for script') {
      steps {
        checkout([
          $class: 'GitSCM',
          branches: [[name: "*/${GIT_BRANCH}"]],
          userRemoteConfigs: [[url: "${GIT_REPO}", credentialsId: 'prince-github-access']]
        ])
        sh 'test -f trivy/ai_suggestion.py && echo "ai_suggestion.py present" || (echo "Missing trivy/ai_suggestion.py" && exit 1)'
      }
    }

    stage('AI Security Analysis (TEST)') {
      steps {
        withCredentials([string(credentialsId: 'alert-manager-secret', variable: 'ALERT_SECRET')]) {
          sh """#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports

# ensure Python + requests
python3 --version
python3 -m pip install --user -q --upgrade pip requests || true
export PATH="\$HOME/.local/bin:\$PATH"

# optional model flag
MODEL_OPT=""
if [ -n "${params.AI_MODEL}" ]; then
  MODEL_OPT="--model ${params.AI_MODEL}"
fi

echo "=== AI-Powered Security Recommendations (TEST) ==="
python3 trivy/ai_suggestion.py \\
  '${params.BUILD_REF_ID}' \\
  '${params.ALERT_MANAGER_URL}' \\
  "\$ALERT_SECRET" \\
  --engine ${params.AI_ENGINE} \${MODEL_OPT} \\
  --timeout 60 --retries 3 --log-level INFO --json-only \\
| tee "reports/ai-suggestion-${BUILD_NUMBER}.json"

echo "Saved: reports/ai-suggestion-${BUILD_NUMBER}.json"
"""
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/ai-suggestion-*.json', fingerprint: true, allowEmptyArchive: true
    }
  }
}
