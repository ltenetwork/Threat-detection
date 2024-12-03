import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

st.title("Cybersecurity Threat Detection Dashboard")
st.markdown("A demo showcasing real-time threat detection and incident response.")

# Load data
st.header("Threat Log Data")
uploaded_file = st.file_uploader("Upload a log file (CSV)", type="csv")
if uploaded_file:
    data = pd.read_csv(uploaded_file)
    st.dataframe(data)

    # Feature extraction
    st.subheader("Analyzing Threat Patterns")
    if "severity" in data.columns:
        severity_counts = data['severity'].value_counts()
        fig, ax = plt.subplots()
        severity_counts.plot(kind="bar", color=["green", "orange", "red"], ax=ax)
        plt.title("Threat Severity Distribution")
        plt.xlabel("Severity")
        plt.ylabel("Count")
        st.pyplot(fig)

    # Threat detection using ML
    st.subheader("Threat Anomaly Detection")
    if "source_ip" in data.columns and "destination_ip" in data.columns:
        # Convert IPs to numerical values
        data['source_ip_num'] = data['source_ip'].apply(lambda ip: sum([int(x) for x in ip.split('.')]))
        data['destination_ip_num'] = data['destination_ip'].apply(lambda ip: sum([int(x) for x in ip.split('.')]))
        features = data[['source_ip_num', 'destination_ip_num']]

        # Train an Isolation Forest for anomaly detection
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        predictions = model.fit_predict(features)

        data['anomaly'] = predictions
        st.write("Detected anomalies (marked as -1):")
        st.dataframe(data[data['anomaly'] == -1])

    # Response recommendations
    st.subheader("Incident Response")
    if len(data[data['anomaly'] == -1]) > 0:
        st.markdown("**Recommended Actions:**")
        st.write("- Block IPs marked as anomalies.")
        st.write("- Notify the security team.")
        st.write("- Increase monitoring for suspicious traffic.")