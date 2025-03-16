pipeline {
    agent any

    environment {
        // Set AWS credentials
        AWS_ACCESS_KEY_ID = credentials('AWS_ACCESS_KEY_ID') // Jenkins credentials ID
        AWS_SECRET_ACCESS_KEY = credentials('AWS_SECRET_ACCESS_KEY') // Jenkins credentials ID
    }

    stages {

        stage('Pre-Stage') {
            steps {
                script {
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan-Infra && terraform destroy --auto-approve || true'
                }
            }
        }

        stage('Build') {
            steps {
                script {
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && git pull origin main || true'
                    echo 'Snyk SAST'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && snyk code test || true'
                    echo 'Snyk SCA'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && snyk test --skip-unresolved || true'
                    echo 'Scanning for Secrets'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && gitleaks detect -v || true'
                    echo 'Building Docker Image'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && docker build -t my-secure-file-scan:latest . || true'
                    echo 'Running Trivy Container Security Scan...'
                    //sh 'trivy image my-secure-file-scan || true'  // Runs Trivy container scan
                    echo 'Running Docker Container...'
                    sh 'docker run -d -p 443:443 --name secure-file-scan my-secure-file-scan:latest || true'
                    
                }
            }
        }

        stage('Test') {
            steps {
                script {
                    echo 'Running Test...'
                    sh 'sleep 30 || true'
                    sh 'curl --insecure https://localhost || true'
                }
            }
        }

        stage('Deploy') {
            steps {
                script {
                    echo 'Snyk Infrastructure as Code Testing'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan-Infra && snyk iac test || true'
                    echo 'Applying Terraform Configuration...'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan-Infra && terraform apply --auto-approve || true'
                }
            }
        }

    }

    post {
        always {
            echo 'Cleaning up resources...'
            script {
                // Stop and remove the container after testing
                sh 'docker stop secure-file-scan || true'
                sh 'docker rm secure-file-scan || true'
                sh 'docker rmi my-secure-file-scan || true'
            }
        }
    }
}
