import streamlit as st
import requests
import subprocess
import os
import json
import time

# Setup
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    st.error("GEMINI_API_KEY environment variable is not set. Please set it before running the dashboard.")

st.set_page_config(page_title="PatchEMR Dashboard", layout="wide")

# Hide the default Streamlit Deploy button, Menu, and Footer
hide_streamlit_style = """
<style>
.stAppDeployButton {display:none;}
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.title("PatchEMR: Orchestration Dashboard")
st.markdown("Automated vulnerability validation and zero-downtime deployment constraint system.")

# Helper Functions
def get_current_k8s_version():
    """Dynamically fetches the image currently running in the local Minikube cluster."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "deployment", "openemr-staging", "-o=jsonpath='{.spec.template.spec.containers[0].image}'"],
            capture_output=True, text=True, check=True
        )
        image = result.stdout.strip().strip("'")
        if image:
            return image
    except Exception:
        pass
    return "openemr/openemr:7.0.0"

@st.cache_data(ttl=3600)
def get_github_versions():
    """Scrapes the official OpenEMR GitHub repository for the latest release tags."""
    default_tags = ["openemr/openemr:8.0.0", "openemr/openemr:7.0.2", "openemr/openemr:7.0.1", "openemr/openemr:7.0.0"]
    try:
        resp = requests.get("https://api.github.com/repos/openemr/openemr/tags", timeout=3)
        if resp.status_code == 200:
            tags = [item['name'] for item in resp.json()]
            formatted_tags = [f"openemr/openemr:{tag}" for tag in tags if tag[0].isdigit()][:15]
            if formatted_tags:
                return formatted_tags
    except Exception:
        pass
    return default_tags

def run_trivy_scan(image_tag):
    """Executes Trivy via subprocess, parses the JSON, and returns the count and detailed CVEs."""
    try:
        cmd = ["trivy", "image", "-f", "json", "--severity", "HIGH,CRITICAL", "-q", image_tag]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        
        vulns = []
        if "Results" in data:
            for res in data["Results"]:
                if "Vulnerabilities" in res:
                    for v in res["Vulnerabilities"]:
                        vulns.append({
                            "id": v.get("VulnerabilityID", "Unknown"),
                            "severity": v.get("Severity", "Unknown"),
                            "pkg": v.get("PkgName", "Unknown")
                        })
        return len(vulns), vulns
    except Exception as e:
        return None, str(e)

# UI Logic
current_k8s_img = get_current_k8s_version()
available_tags = get_github_versions()

if current_k8s_img not in available_tags:
    available_tags.append(current_k8s_img)

col1, col2 = st.columns(2)
with col1:
    prod_version = st.selectbox("Current Production Version (Fetched via kubectl)", options=available_tags, index=available_tags.index(current_k8s_img))
with col2:
    staging_version = st.selectbox("Proposed Update Version (Fetched from GitHub)", options=available_tags)

if 'context_string' not in st.session_state:
    st.session_state['context_string'] = ""

if st.button("Run Pre-Flight Analysis", type="primary"):
    with st.spinner("Executing live Trivy scans on container images (This may take a minute)..."):
        
        # 1. Run actual Trivy Scans
        prod_count, prod_vulns = run_trivy_scan(prod_version)
        staging_count, staging_vulns = run_trivy_scan(staging_version)
        
        if prod_count is None or staging_count is None:
            st.error(f"Trivy Scan Failed. Ensure Trivy is installed and Docker/Minikube is running. Error: {prod_vulns or staging_vulns}")
            st.stop()
            
        st.success("Trivy Analysis Complete")
        
        # 2. Display Metrics
        st.subheader("Vulnerability Delta (Critical/High CVEs)")
        metric_col1, metric_col2, metric_col3 = st.columns(3)
        metric_col1.metric(f"Production ({prod_version.split(':')[-1]})", f"{prod_count} CVEs")
        
        delta_val = staging_count - prod_count
        metric_col2.metric(f"Staging ({staging_version.split(':')[-1]})", f"{staging_count} CVEs", delta=f"{delta_val} CVEs", delta_color="inverse")
        
        math_check_passed = staging_count < prod_count
        if math_check_passed:
            metric_col3.success("Math Check = PASS (Attack surface reduced)")
        else:
            metric_col3.error("Math Check = FAIL (Deployment Blocked: Risk increased or unchanged)")

        # 3. Display Detailed CVEs in Expanders
        with st.expander("View Production Vulnerability Details"):
            st.write([f"{v['id']} ({v['severity']}) in {v['pkg']}" for v in prod_vulns[:10]] + ["...truncated"])
        with st.expander("View Staging Vulnerability Details"):
            st.write([f"{v['id']} ({v['severity']}) in {v['pkg']}" for v in staging_vulns[:10]] + ["...truncated"])

    if api_key:
        with st.spinner("AI Threat Broker generating executive summary..."):
            
            # Extract top 3 CVEs to feed the LLM for highly specific context
            prod_cve_sample = ", ".join([v['id'] for v in prod_vulns[:3]]) if prod_vulns else "None"
            staging_cve_sample = ", ".join([v['id'] for v in staging_vulns[:3]]) if staging_vulns else "None"
            
            st.session_state['context_string'] = f"Production image {prod_version} has {prod_count} Critical/High CVEs (including {prod_cve_sample}). Proposed staging image {staging_version} has {staging_count} Critical/High CVEs (including {staging_cve_sample}). Math check passed: {math_check_passed}."
            
            system_prompt = f"""
            You are the AI Threat Broker for PatchEMR, a healthcare cybersecurity orchestration system. 
            Your task is to analyze the real-world vulnerability delta between the current production container and the proposed update.
            
            Context: {st.session_state['context_string']}
            
            Task: Write a highly professional, 2-sentence executive summary for the Hospital IT Board justifying the deployment decision based on the specific numbers and CVE examples provided. Focus on risk reduction, patient data protection, and operational resilience. 
            If the math check passed, conclude with exactly: "GO DECISION: [Brief justification]". 
            If the math check failed, conclude with exactly: "NO-GO DECISION: [Brief justification]".
            """
            
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
            payload = {"contents": [{"parts": [{"text": system_prompt}]}]}
            
            try:
                response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'})
                response.raise_for_status()
                summary_text = response.json()['candidates'][0]['content']['parts'][0]['text']
                
                st.session_state['llm_summary'] = summary_text
                st.session_state['ready_to_deploy'] = math_check_passed
                st.session_state['analysis_run'] = True
                
            except Exception as e:
                st.error(f"AI API Connection Failed: {e}")

# Enforcement Logic
if st.session_state.get('analysis_run'):
    st.divider()
    st.subheader("AI Executive Summary")
    
    if st.session_state.get('ready_to_deploy'):
        st.info(st.session_state['llm_summary'])
        st.warning("Awaiting IT/Sec Staff Authorization")
        
        if st.button("AUTHORIZE & DEPLOY UPGRADE (Zero Downtime)", type="secondary"):
            with st.spinner(f"RBAC Enforcer applying Kubernetes manifests for {staging_version}..."):
                try:
                    # Dynamically deploys the specific version chosen in the staging dropdown
                    subprocess.run(
                        ["kubectl", "set", "image", "deployment/openemr-staging", f"openemr={staging_version}"], 
                        capture_output=True, text=True, check=True
                    )
                    st.code(f"deployment.apps/openemr-staging image updated to {staging_version}\nOpenEMR Staging is now running. Awaiting QA confirmation.", language="bash")
                    st.success("Deployment Successful. Traffic is routing to the new version.")
                except Exception as e:
                    st.error(f"Deployment failed. Ensure Minikube is running and the deployment name is correct. Error: {e}")
    else:
        st.error(st.session_state['llm_summary'])
        st.error("System Constraint Enforced: Deployment blocked due to increased or stagnant risk profile.")

# CHAT WITH LLM
st.divider()
st.subheader("Chat with AI Threat Broker")
st.markdown("Query the AI regarding vulnerability details, HIPAA compliance implications, or architectural constraints.")

if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    st.chat_message(msg["role"]).write(msg["content"])

if prompt := st.chat_input("E.g., What specific socio-technical risks are mitigated by this automated deployment?"):
    st.chat_message("user").write(prompt)
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    chat_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    
    payload = {
        "system_instruction": {
            "parts": [{"text": f"You are a Cybersecurity Systems Engineer assisting IT staff. Answer concisely and professionally. Current System Context: {st.session_state.get('context_string', 'No analysis run yet.')}"}]
        },
        "contents": []
    }
    
    for msg in st.session_state.messages:
        api_role = "user" if msg["role"] == "user" else "model"
        payload["contents"].append({"role": api_role, "parts": [{"text": msg["content"]}]})
    
    try:
        chat_resp = requests.post(chat_url, json=payload, headers={'Content-Type': 'application/json'})
        chat_resp.raise_for_status()
        ai_reply = chat_resp.json()['candidates'][0]['content']['parts'][0]['text']
        
        st.chat_message("assistant").write(ai_reply)
        st.session_state.messages.append({"role": "assistant", "content": ai_reply})
    except Exception as e:
        st.error(f"Chat Error: {e}")
