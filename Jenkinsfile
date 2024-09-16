pipeline {
    agent any
    environment {
        CI = 'true'
    }
    stages {
        stage('Build') {
            steps {
                sh 'echo "building"'
            }
        }
        stage('Test') {
            steps {
                sh 'echo "testing"'
            }
        }
    }
}
