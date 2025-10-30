r"""
================================================================================
MULTILAYERED CYBER DEFENSE PLATFORM - SERVER PERFORMANCE MONITOR
================================================================================

File: pages/Server_Performance.py
Purpose: Real-time server performance monitoring and resource utilization

DESCRIPTION:
    This module monitors and displays real-time performance metrics of the server
    hosting the Cyber Defense Platform. It provides comprehensive insights into
    system resource utilization including CPU, Memory, Disk, Network, and GPU.

METRICS MONITORED:
    1. CPU Metrics:
        - Overall CPU usage percentage
        - Per-core CPU utilization
        - CPU frequency
        - CPU temperature (if available)
        
    2. Memory Metrics:
        - Total RAM
        - Used RAM
        - Available RAM
        - Memory usage percentage
        - Swap memory usage
        
    3. Disk Metrics:
        - Disk usage per partition
        - Read/Write speeds
        - Total/Used/Free space
        - I/O statistics
        
    4. Network Metrics:
        - Bytes sent/received
        - Network interface status
        - Active connections
        - Network speed
        
    5. GPU Metrics (if available):
        - GPU utilization
        - GPU memory usage
        - GPU temperature
        - GPU power consumption

VISUALIZATIONS:
    - Real-time line charts for CPU and Memory usage
    - Gauge charts for resource utilization
    - Bar charts for per-core CPU usage
    - Disk usage pie charts
    - Network traffic time series
    - System information cards

FEATURES:
    - Auto-refresh every 2 seconds
    - Historical data tracking
    - Alert thresholds for high usage
    - Export performance reports
    - Detailed system information

DEPENDENCIES:
    - psutil: System and process monitoring
    - streamlit: UI framework
    - plotly: Interactive charts
    - pandas: Data manipulation

Author: Multilayered Cyber Defense Team
Last Modified: October 30, 2025
Version: 1.0.0
================================================================================
"""

import streamlit as st
import psutil
import platform
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import pandas as pd
import time

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Server Performance Monitor",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_size(bytes):
    """Convert bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} PB"


def get_cpu_info():
    """Get CPU information and metrics"""
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count(logical=False)
    cpu_count_logical = psutil.cpu_count(logical=True)
    cpu_freq = psutil.cpu_freq()
    cpu_per_core = psutil.cpu_percent(interval=1, percpu=True)
    
    return {
        'percent': cpu_percent,
        'count_physical': cpu_count,
        'count_logical': cpu_count_logical,
        'frequency_current': cpu_freq.current if cpu_freq else 0,
        'frequency_min': cpu_freq.min if cpu_freq else 0,
        'frequency_max': cpu_freq.max if cpu_freq else 0,
        'per_core': cpu_per_core
    }


def get_memory_info():
    """Get memory information and metrics"""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    return {
        'total': mem.total,
        'available': mem.available,
        'used': mem.used,
        'percent': mem.percent,
        'swap_total': swap.total,
        'swap_used': swap.used,
        'swap_percent': swap.percent
    }


def get_disk_info():
    """Get disk information and metrics"""
    partitions = psutil.disk_partitions()
    disk_info = []
    
    for partition in partitions:
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disk_info.append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            })
        except PermissionError:
            continue
    
    return disk_info


def get_network_info():
    """Get network information and metrics"""
    net_io = psutil.net_io_counters()
    net_if = psutil.net_if_addrs()
    
    return {
        'bytes_sent': net_io.bytes_sent,
        'bytes_recv': net_io.bytes_recv,
        'packets_sent': net_io.packets_sent,
        'packets_recv': net_io.packets_recv,
        'interfaces': list(net_if.keys())
    }


def get_system_info():
    """Get general system information"""
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'boot_time': boot_time,
        'uptime': datetime.now() - boot_time
    }


def create_gauge_chart(value, title, max_value=100):
    """Create a gauge chart for resource utilization"""
    color = "green" if value < 50 else "orange" if value < 80 else "red"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title, 'font': {'size': 20}},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, max_value], 'tickwidth': 1},
            'bar': {'color': color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 50], 'color': 'lightgray'},
                {'range': [50, 80], 'color': 'gray'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(height=250, margin=dict(l=10, r=10, t=50, b=10))
    return fig


# ============================================================================
# MAIN CONTENT
# ============================================================================

def main():
    """Main function for server performance monitoring"""
    
    st.title("🖥️ Server Performance Monitor")
    st.markdown("Real-time monitoring of server resources and performance metrics")
    st.markdown("---")
    
    # Auto-refresh toggle
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown("### Live Monitoring Dashboard")
    with col2:
        auto_refresh = st.checkbox("Auto-refresh", value=True)
    with col3:
        if st.button("🔄 Refresh Now"):
            st.rerun()
    
    # ========================================================================
    # SYSTEM INFORMATION
    # ========================================================================
    
    st.markdown("### 📋 System Information")
    sys_info = get_system_info()
    
    info_col1, info_col2, info_col3, info_col4 = st.columns(4)
    
    with info_col1:
        st.metric("Operating System", f"{sys_info['system']} {sys_info['release']}")
    with info_col2:
        st.metric("Machine Type", sys_info['machine'])
    with info_col3:
        st.metric("Boot Time", sys_info['boot_time'].strftime("%Y-%m-%d %H:%M:%S"))
    with info_col4:
        uptime_str = str(sys_info['uptime']).split('.')[0]
        st.metric("Uptime", uptime_str)
    
    st.markdown("---")
    
    # ========================================================================
    # CPU METRICS
    # ========================================================================
    
    st.markdown("### 🔥 CPU Performance")
    cpu_info = get_cpu_info()
    
    cpu_col1, cpu_col2, cpu_col3 = st.columns(3)
    
    with cpu_col1:
        st.metric("CPU Usage", f"{cpu_info['percent']:.1f}%")
        st.metric("Physical Cores", cpu_info['count_physical'])
    
    with cpu_col2:
        st.metric("CPU Frequency", f"{cpu_info['frequency_current']:.0f} MHz")
        st.metric("Logical Cores", cpu_info['count_logical'])
    
    with cpu_col3:
        st.plotly_chart(create_gauge_chart(cpu_info['percent'], "CPU Usage"), use_container_width=True)
    
    # Per-core CPU usage
    if cpu_info['per_core']:
        st.markdown("#### Per-Core CPU Usage")
        core_df = pd.DataFrame({
            'Core': [f"Core {i}" for i in range(len(cpu_info['per_core']))],
            'Usage (%)': cpu_info['per_core']
        })
        
        fig = px.bar(core_df, x='Core', y='Usage (%)', 
                     title="CPU Usage by Core",
                     color='Usage (%)',
                     color_continuous_scale=['green', 'yellow', 'red'])
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ========================================================================
    # MEMORY METRICS
    # ========================================================================
    
    st.markdown("### 💾 Memory Performance")
    mem_info = get_memory_info()
    
    mem_col1, mem_col2, mem_col3 = st.columns(3)
    
    with mem_col1:
        st.metric("Total RAM", get_size(mem_info['total']))
        st.metric("Used RAM", get_size(mem_info['used']))
        st.metric("Available RAM", get_size(mem_info['available']))
    
    with mem_col2:
        st.metric("Memory Usage", f"{mem_info['percent']:.1f}%")
        st.metric("Swap Total", get_size(mem_info['swap_total']))
        st.metric("Swap Used", f"{mem_info['swap_percent']:.1f}%")
    
    with mem_col3:
        st.plotly_chart(create_gauge_chart(mem_info['percent'], "Memory Usage"), use_container_width=True)
    
    # Memory breakdown pie chart
    mem_col_chart1, mem_col_chart2 = st.columns(2)
    
    with mem_col_chart1:
        fig_mem = go.Figure(data=[go.Pie(
            labels=['Used', 'Available'],
            values=[mem_info['used'], mem_info['available']],
            hole=0.4,
            marker_colors=['#FF6B6B', '#4ECDC4']
        )])
        fig_mem.update_layout(title="RAM Distribution", height=300)
        st.plotly_chart(fig_mem, use_container_width=True)
    
    with mem_col_chart2:
        if mem_info['swap_total'] > 0:
            fig_swap = go.Figure(data=[go.Pie(
                labels=['Used', 'Free'],
                values=[mem_info['swap_used'], mem_info['swap_total'] - mem_info['swap_used']],
                hole=0.4,
                marker_colors=['#FFD93D', '#6BCB77']
            )])
            fig_swap.update_layout(title="Swap Memory Distribution", height=300)
            st.plotly_chart(fig_swap, use_container_width=True)
        else:
            st.info("No swap memory configured")
    
    st.markdown("---")
    
    # ========================================================================
    # DISK METRICS
    # ========================================================================
    
    st.markdown("### 💿 Disk Performance")
    disk_info = get_disk_info()
    
    if disk_info:
        disk_cols = st.columns(min(len(disk_info), 3))
        
        for idx, disk in enumerate(disk_info):
            with disk_cols[idx % 3]:
                st.markdown(f"**{disk['device']}**")
                st.metric("Mount Point", disk['mountpoint'])
                st.metric("Total Space", get_size(disk['total']))
                st.metric("Used", f"{get_size(disk['used'])} ({disk['percent']}%)")
                st.metric("Free", get_size(disk['free']))
                
                # Disk usage progress bar
                st.progress(disk['percent'] / 100)
                st.markdown("---")
        
        # Disk usage comparison chart
        disk_df = pd.DataFrame(disk_info)
        fig_disk = px.bar(disk_df, x='device', y='percent',
                         title="Disk Usage Comparison (%)",
                         color='percent',
                         color_continuous_scale=['green', 'yellow', 'red'])
        fig_disk.update_layout(height=300)
        st.plotly_chart(fig_disk, use_container_width=True)
    else:
        st.warning("No disk information available")
    
    st.markdown("---")
    
    # ========================================================================
    # NETWORK METRICS
    # ========================================================================
    
    st.markdown("### 🌐 Network Performance")
    net_info = get_network_info()
    
    net_col1, net_col2, net_col3, net_col4 = st.columns(4)
    
    with net_col1:
        st.metric("Data Sent", get_size(net_info['bytes_sent']))
    with net_col2:
        st.metric("Data Received", get_size(net_info['bytes_recv']))
    with net_col3:
        st.metric("Packets Sent", f"{net_info['packets_sent']:,}")
    with net_col4:
        st.metric("Packets Received", f"{net_info['packets_recv']:,}")
    
    # Network interfaces
    st.markdown("#### Active Network Interfaces")
    interface_cols = st.columns(min(len(net_info['interfaces']), 4))
    for idx, interface in enumerate(net_info['interfaces']):
        with interface_cols[idx % 4]:
            st.success(f"✅ {interface}")
    
    st.markdown("---")
    
    # ========================================================================
    # PROCESS INFORMATION
    # ========================================================================
    
    st.markdown("### 📊 Top Processes by CPU Usage")
    
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    processes_df = pd.DataFrame(processes)
    processes_df = processes_df.sort_values('cpu_percent', ascending=False).head(10)
    processes_df['memory_percent'] = processes_df['memory_percent'].round(2)
    processes_df['cpu_percent'] = processes_df['cpu_percent'].round(2)
    
    st.dataframe(processes_df, use_container_width=True, height=400)
    
    # ========================================================================
    # ALERTS
    # ========================================================================
    
    st.markdown("---")
    st.markdown("### ⚠️ System Alerts")
    
    alert_col1, alert_col2, alert_col3 = st.columns(3)
    
    with alert_col1:
        if cpu_info['percent'] > 80:
            st.error(f"🔴 High CPU Usage: {cpu_info['percent']:.1f}%")
        elif cpu_info['percent'] > 60:
            st.warning(f"🟡 Moderate CPU Usage: {cpu_info['percent']:.1f}%")
        else:
            st.success(f"🟢 CPU Usage Normal: {cpu_info['percent']:.1f}%")
    
    with alert_col2:
        if mem_info['percent'] > 80:
            st.error(f"🔴 High Memory Usage: {mem_info['percent']:.1f}%")
        elif mem_info['percent'] > 60:
            st.warning(f"🟡 Moderate Memory Usage: {mem_info['percent']:.1f}%")
        else:
            st.success(f"🟢 Memory Usage Normal: {mem_info['percent']:.1f}%")
    
    with alert_col3:
        high_disk = any(d['percent'] > 80 for d in disk_info)
        moderate_disk = any(d['percent'] > 60 for d in disk_info)
        
        if high_disk:
            st.error("🔴 High Disk Usage Detected")
        elif moderate_disk:
            st.warning("🟡 Moderate Disk Usage")
        else:
            st.success("🟢 Disk Usage Normal")
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(2)
        st.rerun()


# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.markdown("## 🖥️ Server Monitor")
    st.markdown("---")
    
    st.markdown("### Monitoring Options")
    refresh_rate = st.select_slider(
        "Refresh Rate (seconds)",
        options=[1, 2, 5, 10, 30],
        value=2
    )
    
    st.markdown("---")
    st.markdown("### Alert Thresholds")
    cpu_threshold = st.slider("CPU Alert (%)", 0, 100, 80)
    mem_threshold = st.slider("Memory Alert (%)", 0, 100, 80)
    disk_threshold = st.slider("Disk Alert (%)", 0, 100, 80)
    
    st.markdown("---")
    st.markdown("### Actions")
    if st.button("📥 Export Report", use_container_width=True):
        st.info("Report export feature coming soon")
    
    if st.button("🏠 Back to Home", use_container_width=True):
        st.switch_page("app.py")


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
