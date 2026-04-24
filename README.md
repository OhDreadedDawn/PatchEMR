# PatchEMR: Automated Vulnerability & Deployment Orchestrator

**Authors:** Christopher Ghanma, Brandon Heiney, Megan Hoxha, Gabriel Brinza, Bishesh Joshi, Sai Gudapati

## System Description & Architecture
PatchEMR is an external, automated deployment constraint system designed to safely orchestrate updates for OpenEMR environments. Upgrading healthcare infrastructure introduces significant socio-technical risks, including potential downtime and the introduction of new vulnerabilities. 

This system works strictly outside the OpenEMR boundary. It integrates an AI Threat Broker and a Kubernetes Deployment Enforcer. 
* **Pre-Flight Analysis:** The system uses an ephemeral Kubernetes pod to execute a Trivy container scan, and compares the live production OpenEMR image against the proposed version. 
* **Decision Support:** It forces deployment only to proceed if the total number of Critical/High CVEs is reduced.
* **Governance:** The Gemini AI API parses the specific CVEs to generate an Executive Summary which bridges the gap between technical flaws and human decision-makers and possibly less technical clinicians in smaller practices.
* **Execution:** After authorization, the system interfaces with the Kubernetes API to execute a zero-downtime rolling update which ensures continuous availability for hospital staff.

## Installation & Environment Requirements
This Proof of Concept (PoC) is designed to run in a Linux environment with a local Kubernetes cluster.

**Prerequisites:**
* Ubuntu Linux (or WSL2)
* Docker & Minikube (Install instructions for Minikube here: https://minikube.sigs.k8s.io/docs/start/?arch=%2Flinux%2Fx86-64%2Fstable%2Fbinary+download)
* `kubectl` CLI (Install instructions for kubectl cli here: https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)
* Python 3.8+ 

**Environment Setup:**
1. Clone this repository to your local machine.
2. Install the required Python dependencies:
   `pip install -r requirements.txt`
3. Start your local Kubernetes cluster:
   `minikube start --driver=docker`
4. Deploy the Baseline OpenEMR Environment:
   `minikube kubectl create deployment openemr-staging --image=openemr/openemr:7.0.2`

## Execution & Demo Instructions
1. Get a Gemini API Key from Google AI Studio.
2. Export the key into your active terminal environment:
   `export GEMINI_API_KEY="AIzaSy_YOUR_KEY_HERE"`
3. Launch the orchestration dashboard:
   `streamlit run app.py`
4. Use the web interface (defaulting to `http://localhost:8501`) to select production and staging versions, run the analysis, and review the AI Threat Broker's output before authorizing deployment. Also prompt the LLM for any additional 

## Example Inputs and Expected Outputs
* **Input Scenario (Blocked):** Production is set to `openemr/openemr:8.0.0` and Staging is set to `openemr/openemr:7.0.0`.
* **Expected Output:** The Trivy scanner will detect an increase in vulnerabilities. The Math Check will register a "FAIL". The AI Threat Broker will generate a "NO-GO DECISION", and the physical deployment button will be restricted from the UI.
* **Input Scenario (Approved):** Production is set to `openemr/openemr:7.0.2` and Staging is set to `openemr/openemr:8.0.0`.
* **Expected Output:** The scanner confirms a reduction in the attack surface. The AI generates a "GO DECISION" detailing the mitigated risks. The "AUTHORIZE & DEPLOY" button appears, which dynamically updates the Kubernetes deployment when clicked.
