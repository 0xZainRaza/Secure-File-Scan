pipeline {
    agent any
    environment {
        AWS_ACCESS_KEY_ID = credentials('AWS_ACCESS_KEY_ID')
        AWS_SECRET_ACCESS_KEY = credentials('AWS_SECRET_ACCESS_KEY')
    }
    stages {
        stage('Pre-Stage') {
            steps {
                script {
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan-Infra && terraform destroy --auto-approve'
                }
            }
        }
        stage('Build') {
            steps {
                script {
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && git pull origin main'
                    echo 'Snyk SAST'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && snyk code test'
                    echo 'Snyk SCA'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && snyk test --skip-unresolved'
                    echo 'Scanning for Secrets'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && gitleaks detect -v'
                    echo 'Building Docker Image'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && docker build -t secure-file-scan:latest .'
                    echo 'Running Trivy Container Security Scan...'
                    sh 'trivy image secure-file-scan:latest'
                    echo 'Running Docker Container...'
                    sh 'docker run -d -p 443:443 --name secure-file-scan secure-file-scan:latest'
                }
            }
        }
        stage('Test') {
            steps {
                script {
                    echo 'Running Test...'
                    sh 'sleep 30'
                    sh 'curl --insecure https://localhost'
                }
            }
        }
        stage('Deploy') {
            steps {
                script {
                    echo 'Snyk Infrastructure as Code Testing'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan-Infra && snyk iac test'
                    echo 'Applying Terraform Configuration...'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan-Infra && terraform apply --auto-approve'
                }
            }
        }
        stage('K8s Deploy') {
            steps {
                script {
                    echo 'Deploying to Kubernetes...'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && kubectl apply -f kubernetes/deployment.yml'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && kubectl apply -f kubernetes/service.yml'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && kubectl apply -f kubernetes/configmap.yml'
                    sh 'cd /var/lib/jenkins/workspace/Secure-File-Scan/Secure-File-Scan && kubectl apply -f kubernetes/secrets.yml'
                    sh 'kubectl rollout status deployment/secure-file-scan'
                }
            }
        }
    }
    post {
        always {
            echo 'Cleaning up resources...'
            script {
                sh 'docker stop secure-file-scan'
                sh 'docker rm secure-file-scan'
                sh 'docker rmi secure-file-scan:latest'
            }
        }
    }
}
