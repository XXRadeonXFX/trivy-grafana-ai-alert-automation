pipeline {
  agent any

  options {
    timeout(time: 15, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '10'))
  }

  environment {
    // Repo that contains trivy/ai_suggestion.py
    GIT_REPO   = 'https://github.com/XXRadeonXFX/trivy-grafana-ai-alert-automation'
    GIT_BRANCH = 'main'

    // ---- TEST SETTINGS (edit as you like) ----
    BUILD_REF_ID       = '26'
    AI_ENGINE          = 'openai'      // or 'gemini'
    AI_MODEL           = ''            // optional; leave empty to use engine default
    ALERT_MANAGER_URL  = 'https://alerts.thakurprince.com'
    ALERT_SECRET       = 'yourapisecret' // <-- hardcoded per your request
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
        sh """#!/usr/bin/env bash
set -e
mkdir -p reports

# ensure Python + requests
python3 --version || true
python3 -m pip install --user -q --upgrade pip requests || true
export PATH="\$HOME/.local/bin:\$PATH"

# optional model flag
MODEL_OPT=""
if [ -n "${AI_MODEL}" ]; then
  MODEL_OPT="--model ${AI_MODEL}"
fi

echo "=== AI-Powered Security Recommendations (TEST) ==="
python3 trivy/ai_suggestion.py \\
  "${BUILD_REF_ID}" \\
  "${ALERT_MANAGER_URL}" \\
  "${ALERT_SECRET}" \\
  --engine "${AI_ENGINE}" \${MODEL_OPT} \\
  --timeout 60 --retries 3 --log-level INFO --json-only \\
| tee "reports/ai-suggestion-${BUILD_NUMBER}.json"

echo "Saved: reports/ai-suggestion-${BUILD_NUMBER}.json"
"""
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/ai-suggestion-*.json', fingerprint: true, allowEmptyArchive: true
    }
  }
}
