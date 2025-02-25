import streamlit as st
import time
import pandas as pd
import plotly.express as px
import socket
import logging
import threading
import queue
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StreamlitSecurityApp:
    def __init__(self):
        self.task_queue = queue.Queue()
        self.results_queue = queue.Queue()
        self.initialize_session_state()

    def initialize_session_state(self):
        if 'tasks' not in st.session_state:
            st.session_state.tasks = []
        if 'completed_tasks' not in st.session_state:
            st.session_state.completed_tasks = []
        if 'failed_tasks' not in st.session_state:
            st.session_state.failed_tasks = []
        if 'logs' not in st.session_state:
            st.session_state.logs = []
        if 'is_scanning' not in st.session_state:
            st.session_state.is_scanning = False

    def create_sidebar(self):
        with st.sidebar:
            st.header("Scan Configuration")
            
            target = st.text_input("Target IP / Host", placeholder="192.168.1.1 or example.com")
            scan_type = st.selectbox("Scan Type", ["Quick Scan", "Aggressive Scan"])
            
            if st.button("Start Scan", type="primary"):
                self.start_scan(target, scan_type)

    def create_main_content(self):
        st.title("Security Scan Dashboard")
        tab1, tab2, tab3 = st.tabs(["Active Scans", "Results", "Logs"])
        
        with tab1:
            self.show_active_scans()
        with tab2:
            self.show_results()
        with tab3:
            self.show_logs()

    def show_active_scans(self):
        st.subheader("Active Scans")
        if st.session_state.is_scanning:
            st.write("🔄 Scan in progress...")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Tasks", len(st.session_state.tasks))
        with col2:
            st.metric("Completed", len(st.session_state.completed_tasks))
        with col3:
            st.metric("Failed", len(st.session_state.failed_tasks))

    def show_results(self):
        st.subheader("Scan Results")
        if st.session_state.completed_tasks:
            df = pd.DataFrame(st.session_state.completed_tasks)
            fig = px.bar(df, x="Target", y="Ports Open", color="Status", title="Scan Results")
            st.plotly_chart(fig)
            with st.expander("Detailed Results"):
                st.dataframe(df)

    def show_logs(self):
        st.subheader("Logs")
        st.text_area("Log Output", "\n".join(st.session_state.logs), height=300)

    def start_scan(self, target, scan_type):
        if not target:
            st.error("Please enter a valid target.")
            return
        
        st.session_state.is_scanning = True
        st.session_state.logs.append(f"Starting scan on {target} ({scan_type})")
        thread = threading.Thread(target=self.run_scan, args=(target, scan_type))
        thread.start()
        st.success("Scan started successfully!")
    
    def run_scan(self, target, scan_type):
        try:
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]  # Common ports list
            
            for port in common_ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
            
            st.session_state.completed_tasks.append(
                {"Target": target, "Ports Open": len(open_ports), "Status": "Completed", "Timestamp": str(datetime.now())}
            )
            st.session_state.is_scanning = False
            st.session_state.logs.append(f"Scan completed for {target}")
        
        except Exception as e:
            st.session_state.failed_tasks.append({"Target": target, "Status": "Failed"})
            st.session_state.is_scanning = False
            st.session_state.logs.append(f"Scan failed: {str(e)}")
            logger.error(f"Scan execution error: {str(e)}")

    def run(self):
        self.create_sidebar()
        self.create_main_content()

if __name__ == "__main__":
    app = StreamlitSecurityApp()
    app.run()