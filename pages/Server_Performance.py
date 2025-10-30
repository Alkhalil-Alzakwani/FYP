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
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CUSTOM CSS FOR SCROLLING
# ============================================================================

st.markdown("""
<style>
    /* Ensure main container is scrollable */
    .main {
        overflow-y: auto !important;
        height: 100vh !important;
        max-height: 100vh !important;
    }
    
    /* Fix block container */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
        max-width: 100% !important;
        overflow-y: visible !important;
    }
    
    /* Sidebar scrolling */
    section[data-testid="stSidebar"] {
        height: 100vh !important;
        overflow-y: auto !important;
    }
    
    /* Force scrolling on app view container */
    .appview-container {
        overflow-y: auto !important;
    }
    
    /* Make sure content doesn't get cut off */
    div[data-testid="stVerticalBlock"] {
        overflow: visible !important;
    }
</style>
""", unsafe_allow_html=True)

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


def get_gpu_info():
    """Get GPU information and metrics (if available)"""
    try:
        import GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu = gpus[0]  # Get first GPU
            return {
                'available': True,
                'name': gpu.name,
                'load': gpu.load * 100,
                'memory_used': gpu.memoryUsed,
                'memory_total': gpu.memoryTotal,
                'memory_percent': (gpu.memoryUsed / gpu.memoryTotal) * 100 if gpu.memoryTotal > 0 else 0,
                'temperature': gpu.temperature
            }
        else:
            # GPUtil is installed but no GPU detected
            return {
                'available': False,
                'name': 'No GPU Detected',
                'load': 0,
                'memory_used': 0,
                'memory_total': 0,
                'memory_percent': 0,
                'temperature': 0,
                'error': 'no_gpu'
            }
    except ImportError:
        # GPUtil not installed
        return {
            'available': False,
            'name': 'N/A',
            'load': 0,
            'memory_used': 0,
            'memory_total': 0,
            'memory_percent': 0,
            'temperature': 0,
            'error': 'not_installed'
        }
    except Exception as e:
        # Other errors
        return {
            'available': False,
            'name': 'Error',
            'load': 0,
            'memory_used': 0,
            'memory_total': 0,
            'memory_percent': 0,
            'temperature': 0,
            'error': str(e)
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


def create_gauge_chart(value, title, max_value=100, height=400):
    """Create a large gauge chart for resource utilization"""
    # Determine color based on value
    if value < 50:
        color = "#4ECDC4"  # Teal/Cyan
    elif value < 80:
        color = "#FFD93D"  # Yellow
    else:
        color = "#FF6B6B"  # Red
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title, 'font': {'size': 28, 'color': '#333'}},
        number={'suffix': "%", 'font': {'size': 48}},
        gauge={
            'axis': {
                'range': [None, max_value],
                'tickwidth': 2,
                'tickcolor': "darkgray",
                'tickfont': {'size': 16}
            },
            'bar': {'color': color, 'thickness': 0.75},
            'bgcolor': "white",
            'borderwidth': 3,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 50], 'color': '#E8F8F5'},
                {'range': [50, 80], 'color': '#FEF9E7'},
                {'range': [80, 100], 'color': '#FADBD8'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 6},
                'thickness': 0.85,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        height=height,
        margin=dict(l=20, r=20, t=80, b=20),
        paper_bgcolor="white",
        font={'color': "#333", 'family': "Arial"}
    )
    return fig


def create_network_realtime_chart(history_data):
    """Create real-time network usage line chart"""
    fig = go.Figure()
    
    if len(history_data) > 0:
        df = pd.DataFrame(history_data)
        
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['sent_mbps'],
            mode='lines',
            name='Upload (Mbps)',
            line=dict(color='#FF6B6B', width=3),
            fill='tozeroy',
            fillcolor='rgba(255, 107, 107, 0.2)'
        ))
        
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['recv_mbps'],
            mode='lines',
            name='Download (Mbps)',
            line=dict(color='#4ECDC4', width=3),
            fill='tozeroy',
            fillcolor='rgba(78, 205, 196, 0.2)'
        ))
    
    fig.update_layout(
        title="Real-Time Network Traffic",
        xaxis_title="Time",
        yaxis_title="Speed (Mbps)",
        height=350,
        hovermode='x unified',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(l=50, r=20, t=80, b=50),
        plot_bgcolor='rgba(240, 240, 240, 0.5)',
        paper_bgcolor='white'
    )
    
    return fig


# ============================================================================
# MAIN CONTENT
# ============================================================================

def main():
    """Main function for server performance monitoring"""
    
    st.title("Server Performance Monitor")
    st.markdown("Real-time monitoring of server resources and performance metrics")
    st.markdown("---")
    
    # Initialize session state for network history
    if 'network_history' not in st.session_state:
        st.session_state.network_history = []
    if 'last_network_bytes' not in st.session_state:
        st.session_state.last_network_bytes = {'sent': 0, 'recv': 0, 'time': time.time()}
    
    # Auto-refresh toggle
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.markdown("### Live Monitoring Dashboard")
    with col2:
        auto_refresh = st.checkbox("Auto-refresh", value=True)
    with col3:
        if st.button("Refresh Now"):
            st.rerun()
    
    # ========================================================================
    # SYSTEM INFORMATION
    # ========================================================================
    
    st.markdown("### System Information")
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
    # CPU & GPU GAUGE CHARTS (GIANT)
    # ========================================================================
    
    st.markdown("### CPU & GPU Performance")
    cpu_info = get_cpu_info()
    gpu_info = get_gpu_info()
    
    gauge_col1, gauge_col2 = st.columns(2)
    
    with gauge_col1:
        st.plotly_chart(
            create_gauge_chart(cpu_info['percent'], "CPU Usage", height=450),
            use_container_width=True
        )
        st.markdown(f"**Physical Cores:** {cpu_info['count_physical']} | **Logical Cores:** {cpu_info['count_logical']}")
        st.markdown(f"**Frequency:** {cpu_info['frequency_current']:.0f} MHz")
    
    with gauge_col2:
        if gpu_info['available']:
            st.plotly_chart(
                create_gauge_chart(gpu_info['load'], "GPU Usage", height=450),
                use_container_width=True
            )
            st.markdown(f"**GPU:** {gpu_info['name']}")
            st.markdown(f"**Memory:** {gpu_info['memory_used']:.0f} MB / {gpu_info['memory_total']:.0f} MB ({gpu_info['memory_percent']:.1f}%)")
            if gpu_info['temperature'] > 0:
                st.markdown(f"**Temperature:** {gpu_info['temperature']:.1f} C")
        else:
            st.plotly_chart(
                create_gauge_chart(0, "GPU Usage (Not Available)", height=450),
                use_container_width=True
            )
            # Show appropriate message based on error type
            error_type = gpu_info.get('error', 'unknown')
            if error_type == 'not_installed':
                st.warning("GPUtil library not installed. Install with: pip install gputil")
            elif error_type == 'no_gpu':
                st.info("No GPU detected on this system")
            else:
                st.info("GPU monitoring unavailable")
    
    st.markdown("---")
    
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
    
    st.markdown("### Memory Performance")
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
    
    st.markdown("### Disk Performance")
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
    # NETWORK METRICS WITH REAL-TIME GRAPH
    # ========================================================================
    
    st.markdown("### Network Performance")
    net_info = get_network_info()
    
    # Calculate network speed in Mbps
    current_time = time.time()
    time_diff = current_time - st.session_state.last_network_bytes['time']
    
    if time_diff > 0:
        sent_speed = (net_info['bytes_sent'] - st.session_state.last_network_bytes['sent']) / time_diff / 1024 / 1024 * 8  # Mbps
        recv_speed = (net_info['bytes_recv'] - st.session_state.last_network_bytes['recv']) / time_diff / 1024 / 1024 * 8  # Mbps
        
        # Update network history
        st.session_state.network_history.append({
            'timestamp': datetime.now(),
            'sent_mbps': max(0, sent_speed),
            'recv_mbps': max(0, recv_speed)
        })
        
        # Keep only last 30 data points
        if len(st.session_state.network_history) > 30:
            st.session_state.network_history = st.session_state.network_history[-30:]
        
        # Update last values
        st.session_state.last_network_bytes = {
            'sent': net_info['bytes_sent'],
            'recv': net_info['bytes_recv'],
            'time': current_time
        }
    else:
        sent_speed = 0
        recv_speed = 0
    
    # Current network stats
    net_col1, net_col2, net_col3, net_col4 = st.columns(4)
    
    with net_col1:
        st.metric("Upload Speed", f"{sent_speed:.2f} Mbps")
    with net_col2:
        st.metric("Download Speed", f"{recv_speed:.2f} Mbps")
    with net_col3:
        st.metric("Total Sent", get_size(net_info['bytes_sent']))
    with net_col4:
        st.metric("Total Received", get_size(net_info['bytes_recv']))
    
    # Real-time network graph
    st.plotly_chart(
        create_network_realtime_chart(st.session_state.network_history),
        use_container_width=True
    )
    
    # Network interfaces
    st.markdown("#### Active Network Interfaces")
    interface_cols = st.columns(min(len(net_info['interfaces']), 4))
    for idx, interface in enumerate(net_info['interfaces']):
        with interface_cols[idx % 4]:
            st.success(f"{interface}")
    
    st.markdown("---")
    
    # ========================================================================
    # PROCESS INFORMATION
    # ========================================================================
    
    st.markdown("### Top Processes by CPU Usage")
    
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
    st.markdown("### System Alerts")
    
    alert_col1, alert_col2, alert_col3, alert_col4 = st.columns(4)
    
    with alert_col1:
        if cpu_info['percent'] > 80:
            st.error(f"HIGH CPU Usage: {cpu_info['percent']:.1f}%")
        elif cpu_info['percent'] > 60:
            st.warning(f"MODERATE CPU Usage: {cpu_info['percent']:.1f}%")
        else:
            st.success(f"CPU Usage Normal: {cpu_info['percent']:.1f}%")
    
    with alert_col2:
        if mem_info['percent'] > 80:
            st.error(f"HIGH Memory Usage: {mem_info['percent']:.1f}%")
        elif mem_info['percent'] > 60:
            st.warning(f"MODERATE Memory Usage: {mem_info['percent']:.1f}%")
        else:
            st.success(f"Memory Usage Normal: {mem_info['percent']:.1f}%")
    
    with alert_col3:
        high_disk = any(d['percent'] > 80 for d in disk_info)
        moderate_disk = any(d['percent'] > 60 for d in disk_info)
        
        if high_disk:
            st.error("HIGH Disk Usage Detected")
        elif moderate_disk:
            st.warning("MODERATE Disk Usage")
        else:
            st.success("Disk Usage Normal")
    
    with alert_col4:
        if gpu_info['available']:
            if gpu_info['load'] > 80:
                st.error(f"HIGH GPU Usage: {gpu_info['load']:.1f}%")
            elif gpu_info['load'] > 60:
                st.warning(f"MODERATE GPU Usage: {gpu_info['load']:.1f}%")
            else:
                st.success(f"GPU Usage Normal: {gpu_info['load']:.1f}%")
        else:
            st.info("GPU Not Available")
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(2)
        st.rerun()


# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.markdown("## Server Monitor")
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
    st.markdown("### Network History")
    if st.button("Clear History", use_container_width=True, key="clear_network_history"):
        st.session_state.network_history = []
        st.rerun()
    
    st.markdown("---")
    st.markdown("### Actions")
    if st.button("Export Report", use_container_width=True, key="export_report"):
        st.info("Report export feature coming soon")
    
    if st.button("Back to Dashboard", use_container_width=True, key="back_to_dashboard"):
        st.switch_page("pages/Dashboard_Overview.py")


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
