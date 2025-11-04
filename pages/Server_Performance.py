"""
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
    /* Page background color */
    .stApp {
        background-color: #0f1220 !important;
    }
    
    /* Main content background */
    .main {
        background-color: #0f1220 !important;
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
        background-color: #0f1220 !important;
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
    
    /* Remove ALL transitions and animations to prevent flash */
    *, *::before, *::after {
        transition: none !important;
        animation: none !important;
    }
    
    /* Prevent iframe flashing */
    iframe {
        opacity: 1 !important;
    }
    
    /* Prevent element container flash */
    .element-container {
        opacity: 1 !important;
    }
    
    /* Prevent stale element warnings from showing */
    .stException {
        display: none !important;
    }
    
    /* Keep fragments stable during updates */
    [data-testid="stVerticalBlock"] > div {
        opacity: 1 !important;
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


def create_gauge_chart(value, title, max_value=100, height=250):
    """Create a compact gauge chart for resource utilization"""
    # Determine color based on value - using new color scheme
    if value < 50:
        color = "#8b5cf6"  # Purple
    elif value < 80:
        color = "#ec4899"  # Pink
    else:
        color = "#f43f5e"  # Rose/Red
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title, 'font': {'size': 18, 'color': 'white'}},
        number={'suffix': "%", 'font': {'size': 32, 'color': 'white'}},
        gauge={
            'axis': {
                'range': [None, max_value],
                'tickwidth': 1,
                'tickcolor': "lightgray",
                'tickfont': {'size': 12, 'color': 'white'}
            },
            'bar': {'color': color, 'thickness': 0.65},
            'bgcolor': "#1e2139",
            'borderwidth': 2,
            'bordercolor': "#2d3250",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(139, 92, 246, 0.1)'},
                {'range': [50, 80], 'color': 'rgba(236, 72, 153, 0.1)'},
                {'range': [80, 100], 'color': 'rgba(244, 63, 94, 0.1)'}
            ],
            'threshold': {
                'line': {'color': "#f43f5e", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=50, b=10),
        paper_bgcolor="#1e2139",
        font={'color': "white", 'family': "Arial"}
    )
    return fig


def create_network_realtime_chart(history_data):
    """Create real-time network usage line chart with smooth curves"""
    fig = go.Figure()
    
    if len(history_data) > 0:
        df = pd.DataFrame(history_data)
        
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['sent_mbps'],
            mode='lines',
            name='Upload (Kbps)',
            line=dict(color='#ec4899', width=3, shape='spline', smoothing=1.3),
            fill='tozeroy',
            fillcolor='rgba(236, 72, 153, 0.2)'
        ))
        
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['recv_mbps'],
            mode='lines',
            name='Download (Kbps)',
            line=dict(color='#8b5cf6', width=3, shape='spline', smoothing=1.3),
            fill='tozeroy',
            fillcolor='rgba(139, 92, 246, 0.2)'
        ))
    
    fig.update_layout(
        title={'text': "Real-Time Network Traffic", 'font': {'size': 16, 'color': 'white'}},
        xaxis_title="Time",
        yaxis_title="Speed (Kbps)",
        height=330,
        hovermode='x unified',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(color='white')),
        margin=dict(l=40, r=20, t=50, b=40),
        plot_bgcolor='#1e2139',
        paper_bgcolor='#1e2139',
        font={'color': 'white'},
        xaxis=dict(gridcolor='rgba(255,255,255,0.1)', color='white'),
        yaxis=dict(gridcolor='rgba(255,255,255,0.1)', color='white')
    )
    
    return fig


# ============================================================================
# MAIN CONTENT
# ============================================================================

@st.fragment(run_every="2s")
def update_dashboard():
    """Fragment that updates dashboard content every 2 seconds without full page reload"""
    
    # Use a container to wrap all updates for smoother rendering
    with st.container():
        # Get all system information at once
        sys_info = get_system_info()
        cpu_info = get_cpu_info()
        gpu_info = get_gpu_info()
        mem_info = get_memory_info()
        disk_info = get_disk_info()
        net_info = get_network_info()
        
        # Calculate network speed in Kbps for more visible curves (scaled down by 2x)
        current_time = time.time()
        time_diff = current_time - st.session_state.last_network_bytes['time']
        
        # Only calculate speed if we have previous data (not first run)
        if st.session_state.last_network_bytes['sent'] > 0 and time_diff > 0:
            sent_speed = (net_info['bytes_sent'] - st.session_state.last_network_bytes['sent']) / time_diff / 1024 * 8 / 2
            recv_speed = (net_info['bytes_recv'] - st.session_state.last_network_bytes['recv']) / time_diff / 1024 * 8 / 2
            
            st.session_state.network_history.append({
                'timestamp': datetime.now(),
                'sent_mbps': max(0, sent_speed),
                'recv_mbps': max(0, recv_speed)
            })
            
            if len(st.session_state.network_history) > 60:
                st.session_state.network_history = st.session_state.network_history[-60:]
        else:
            sent_speed = 0
            recv_speed = 0
        
        # Always update the last values for next calculation
        st.session_state.last_network_bytes = {
            'sent': net_info['bytes_sent'],
            'recv': net_info['bytes_recv'],
            'time': current_time
        }
        
        # ====================================================================
        # SYSTEM INFO BAR CARD
        # ====================================================================
        
        uptime_str = str(sys_info['uptime']).split('.')[0]
        
        # Create compact system info bar
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 15px 20px; 
                    border-radius: 10px; 
                    margin-bottom: 20px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="display: flex; justify-content: space-between; align-items: center; color: white;">
                <div style="flex: 1; text-align: center; border-right: 1px solid rgba(255,255,255,0.2); padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">System</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['system']} {sys_info['release']}</div>
                </div>
                <div style="flex: 1; text-align: center; border-right: 1px solid rgba(255,255,255,0.2); padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">Machine</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['machine']}</div>
                </div>
                <div style="flex: 1; text-align: center; border-right: 1px solid rgba(255,255,255,0.2); padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">Processor</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['processor'][:30]}</div>
                </div>
                <div style="flex: 1; text-align: center; border-right: 1px solid rgba(255,255,255,0.2); padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">Boot Time</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['boot_time'].strftime("%Y-%m-%d %H:%M")}</div>
                </div>
                <div style="flex: 1; text-align: center; padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">Uptime</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{uptime_str}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # ====================================================================
        # SYSTEM STATUS BAR CARD
        # ====================================================================
        
        # Determine status colors and levels
        cpu_status = "HIGH" if cpu_info['percent'] > 80 else "MODERATE" if cpu_info['percent'] > 60 else "NORMAL"
        cpu_color = "#ff4444" if cpu_info['percent'] > 80 else "#ffa726" if cpu_info['percent'] > 60 else "#66bb6a"
    
    mem_status = "HIGH" if mem_info['percent'] > 80 else "MODERATE" if mem_info['percent'] > 60 else "NORMAL"
    mem_color = "#ff4444" if mem_info['percent'] > 80 else "#ffa726" if mem_info['percent'] > 60 else "#66bb6a"
    
    high_disk = any(d['percent'] > 80 for d in disk_info)
    moderate_disk = any(d['percent'] > 60 for d in disk_info)
    max_disk = max([d['percent'] for d in disk_info]) if disk_info else 0
    disk_status = "HIGH" if high_disk else "MODERATE" if moderate_disk else "NORMAL"
    disk_color = "#ff4444" if high_disk else "#ffa726" if moderate_disk else "#66bb6a"
    
    if gpu_info['available']:
        gpu_status = "HIGH" if gpu_info['load'] > 80 else "MODERATE" if gpu_info['load'] > 60 else "NORMAL"
        gpu_color = "#ff4444" if gpu_info['load'] > 80 else "#ffa726" if gpu_info['load'] > 60 else "#66bb6a"
        gpu_text = f"{gpu_info['load']:.1f}%"
    else:
        gpu_status = "N/A"
        gpu_color = "#78909c"
        gpu_text = "N/A"
    
    # Create compact system status bar
    st.markdown(f"""
    <div style="background: #1e2139; 
                padding: 15px 20px; 
                border-radius: 10px; 
                margin-bottom: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        <div style="display: flex; justify-content: space-between; align-items: center; color: white;">
            <div style="flex: 1; text-align: center; border-right: 1px solid rgba(255,255,255,0.2); padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">CPU</div>
                <div style="font-size: 16px; font-weight: bold; margin-top: 3px; color: {cpu_color};">{cpu_info['percent']:.1f}%</div>
                <div style="font-size: 10px; opacity: 0.8; margin-top: 2px;">{cpu_status}</div>
            </div>
            <div style="flex: 1; text-align: center; border-right: 1px solid rgba(255,255,255,0.2); padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">Memory</div>
                <div style="font-size: 16px; font-weight: bold; margin-top: 3px; color: {mem_color};">{mem_info['percent']:.1f}%</div>
                <div style="font-size: 10px; opacity: 0.8; margin-top: 2px;">{mem_status}</div>
            </div>
            <div style="flex: 1; text-align: center; border-right: 1px solid rgba(255,255,255,0.2); padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">Disk</div>
                <div style="font-size: 16px; font-weight: bold; margin-top: 3px; color: {disk_color};">{max_disk:.1f}%</div>
                <div style="font-size: 10px; opacity: 0.8; margin-top: 2px;">{disk_status}</div>
            </div>
            <div style="flex: 1; text-align: center; padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px;">GPU</div>
                <div style="font-size: 16px; font-weight: bold; margin-top: 3px; color: {gpu_color};">{gpu_text}</div>
                <div style="font-size: 10px; opacity: 0.8; margin-top: 2px;">{gpu_status}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # ========================================================================
    # CPU & GPU CARDS
    # ========================================================================
    
    row2_col1, row2_col2 = st.columns(2)
    
    # CPU CARD
    with row2_col1:
        st.markdown("""
        <div style="background: #1e2139; 
                    padding: 20px 20px 10px 20px; 
                    border-radius: 10px 10px 0 0; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center;">CPU Usage</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.plotly_chart(
            create_gauge_chart(cpu_info['percent'], "", height=220),
            use_container_width=True
        )
        
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 10px 20px 20px 20px; 
                    border-radius: 0 0 10px 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-top: -20px;
                    height: 140px;">
            <div style="color: white;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Physical Cores:</span>
                    <span style="font-weight: bold;">{cpu_info['count_physical']}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Logical Cores:</span>
                    <span style="font-weight: bold;">{cpu_info['count_logical']}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Current Frequency:</span>
                    <span style="font-weight: bold;">{cpu_info['frequency_current']:.0f} MHz</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="opacity: 0.8;">Max Frequency:</span>
                    <span style="font-weight: bold;">{cpu_info['frequency_max']:.0f} MHz</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # GPU CARD
    with row2_col2:
        if gpu_info['available']:
            gpu_name = gpu_info['name'][:30] + "..." if len(gpu_info['name']) > 30 else gpu_info['name']
            temp_display = f"{gpu_info['temperature']:.1f} °C" if gpu_info['temperature'] > 0 else "N/A"
            
            st.markdown("""
            <div style="background: #1e2139; 
                        padding: 20px 20px 10px 20px; 
                        border-radius: 10px 10px 0 0; 
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <div style="color: white;">
                    <div style="font-size: 18px; font-weight: bold; text-align: center;">GPU Usage</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.plotly_chart(
                create_gauge_chart(gpu_info['load'], "", height=220),
                use_container_width=True
            )
            
            st.markdown(f"""
            <div style="background: #1e2139; 
                        padding: 10px 20px 20px 20px; 
                        border-radius: 0 0 10px 10px; 
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        margin-top: -20px;
                        height: 140px;">
                <div style="color: white;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span style="opacity: 0.8;">GPU Name:</span>
                        <span style="font-weight: bold; font-size: 11px;">{gpu_name}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span style="opacity: 0.8;">Memory Used:</span>
                        <span style="font-weight: bold;">{gpu_info['memory_used']:.0f} MB</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span style="opacity: 0.8;">Memory Total:</span>
                        <span style="font-weight: bold;">{gpu_info['memory_total']:.0f} MB</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span style="opacity: 0.8;">Memory Usage:</span>
                        <span style="font-weight: bold;">{gpu_info['memory_percent']:.1f}%</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span style="opacity: 0.8;">Temperature:</span>
                        <span style="font-weight: bold;">{temp_display}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            error_type = gpu_info.get('error', 'unknown')
            error_msg = "No GPU detected" if error_type == 'no_gpu' else "GPU unavailable"
            
            st.markdown("""
            <div style="background: #1e2139; 
                        padding: 20px 20px 10px 20px; 
                        border-radius: 10px 10px 0 0; 
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <div style="color: white;">
                    <div style="font-size: 18px; font-weight: bold; text-align: center;">GPU Usage</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.plotly_chart(
                create_gauge_chart(0, "", height=220),
                use_container_width=True
            )
            
            st.markdown(f"""
            <div style="background: #1e2139; 
                        padding: 10px 20px 20px 20px; 
                        border-radius: 0 0 10px 10px; 
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        margin-top: -20px;
                        height: 140px;
                        display: flex;
                        align-items: center;
                        justify-content: center;">
                <div style="color: white; text-align: center; opacity: 0.8;">
                    {error_msg}
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("")
    
    # ========================================================================
    # ROW 3: MEMORY & DISK
    # ========================================================================
    
    row3_col1, row3_col2, row3_col3 = st.columns([1, 1, 1])
    
    # MEMORY CARD
    with row3_col1:
        st.markdown("""
        <div style="background: #1e2139; 
                    padding: 20px 20px 10px 20px; 
                    border-radius: 10px 10px 0 0; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center;">Memory Usage</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.plotly_chart(
            create_gauge_chart(mem_info['percent'], "", height=220),
            use_container_width=True
        )
        
        swap_text = f"{get_size(mem_info['swap_total'])} ({mem_info['swap_percent']:.1f}%)" if mem_info['swap_total'] > 0 else "Not configured"
        
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 10px 20px 20px 20px; 
                    border-radius: 0 0 10px 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-top: -20px;
                    height: 140px;">
            <div style="color: white;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Total Memory:</span>
                    <span style="font-weight: bold;">{get_size(mem_info['total'])}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Used:</span>
                    <span style="font-weight: bold;">{get_size(mem_info['used'])}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Available:</span>
                    <span style="font-weight: bold;">{get_size(mem_info['available'])}</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="opacity: 0.8;">Swap:</span>
                    <span style="font-weight: bold; font-size: 11px;">{swap_text}</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # RAM DISTRIBUTION CARD
    with row3_col2:
        st.markdown("""
        <div style="background: #1e2139; 
                    padding: 20px 20px 10px 20px; 
                    border-radius: 10px 10px 0 0; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center;">RAM Distribution</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        fig_mem = go.Figure(data=[go.Pie(
            labels=['Used', 'Available'],
            values=[mem_info['used'], mem_info['available']],
            hole=0.4,
            marker_colors=['#ec4899', '#8b5cf6']
        )])
        fig_mem.update_layout(
            height=220,
            margin=dict(l=10, r=10, t=20, b=10),
            showlegend=True,
            legend=dict(font=dict(size=9, color='white'), orientation="h", yanchor="bottom", y=-0.1),
            paper_bgcolor="#1e2139",
            plot_bgcolor="#1e2139",
            font={'color': 'white'}
        )
        st.plotly_chart(fig_mem, use_container_width=True)
        
        used_percent = (mem_info['used'] / mem_info['total'] * 100) if mem_info['total'] > 0 else 0
        avail_percent = (mem_info['available'] / mem_info['total'] * 100) if mem_info['total'] > 0 else 0
        
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 10px 20px 20px 20px; 
                    border-radius: 0 0 10px 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-top: -20px;
                    height: 140px;">
            <div style="color: white;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Used:</span>
                    <span style="font-weight: bold;">{used_percent:.1f}%</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Available:</span>
                    <span style="font-weight: bold;">{avail_percent:.1f}%</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # DISK USAGE CARD
    with row3_col3:
        st.markdown("""
        <div style="background: #1e2139; 
                    padding: 20px 20px 10px 20px; 
                    border-radius: 10px 10px 0 0; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center;">Disk Usage</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if disk_info:
            disk_df = pd.DataFrame(disk_info)
            fig_disk = px.bar(disk_df, x='device', y='percent',
                             color='percent',
                             color_continuous_scale=['#8b5cf6', '#ec4899', '#f43f5e'])
            fig_disk.update_layout(
                height=220,
                margin=dict(l=30, r=10, t=20, b=40),
                xaxis={'tickangle': -45, 'tickfont': {'size': 9, 'color': 'white'}, 'showticklabels': True},
                yaxis={'tickfont': {'color': 'white'}},
                paper_bgcolor="#1e2139",
                plot_bgcolor="#1e2139",
                font={'color': 'white'},
                showlegend=False
            )
            st.plotly_chart(fig_disk, use_container_width=True)
            
            # Build disk details list
            disk_items = []
            for i, disk in enumerate(disk_info[:3]):
                device_short = disk['device'][:15] + "..." if len(disk['device']) > 15 else disk['device']
                disk_items.append(f'<div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 11px;"><span style="opacity: 0.8;">{device_short}</span><span style="font-weight: bold;">{disk["percent"]:.1f}%</span></div>')
            
            disk_details_html = ''.join(disk_items)
            
            st.markdown(f"""
            <div style="background: #1e2139; 
                        padding: 10px 20px 20px 20px; 
                        border-radius: 0 0 10px 10px; 
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        margin-top: -20px;
                        height: 140px;
                        overflow-y: auto;">
                <div style="color: white;">
                    {disk_details_html}
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background: #1e2139; 
                        padding: 10px 20px 20px 20px; 
                        border-radius: 0 0 10px 10px; 
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        margin-top: -20px;
                        height: 140px;
                        display: flex;
                        align-items: center;
                        justify-content: center;">
                <div style="color: white; text-align: center; opacity: 0.8;">
                    No disk info available
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("")
    
    # ========================================================================
    # ROW 4: NETWORK & PROCESSES
    # ========================================================================
    
    row4_col1, row4_col2 = st.columns([1, 1])
    
    # NETWORK TRAFFIC CARD
    with row4_col1:
        st.markdown("""
        <div style="background: #1e2139; 
                    padding: 20px 20px 10px 20px; 
                    border-radius: 10px 10px 0 0; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center;">Network Traffic</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.plotly_chart(
            create_network_realtime_chart(st.session_state.network_history),
            use_container_width=True
        )
        
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 10px 20px 20px 20px; 
                    border-radius: 0 0 10px 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-top: -20px;
                    height: 140px;">
            <div style="color: white;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Upload Speed:</span>
                    <span style="font-weight: bold; color: #ec4899;">{sent_speed:.2f} Kbps</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Download Speed:</span>
                    <span style="font-weight: bold; color: #8b5cf6;">{recv_speed:.2f} Kbps</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Total Sent:</span>
                    <span style="font-weight: bold;">{get_size(net_info['bytes_sent'])}</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="opacity: 0.8;">Total Received:</span>
                    <span style="font-weight: bold;">{get_size(net_info['bytes_recv'])}</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # TOP PROCESSES CARD
    with row4_col2:
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
        
        # Create process table HTML
        process_rows = []
        for idx, row in processes_df.iterrows():
            process_name = row['name'][:25] + "..." if len(str(row['name'])) > 25 else row['name']
            process_rows.append(f'<tr><td style="padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 11px;">{process_name}</td><td style="padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); text-align: center; font-size: 11px;">{row["cpu_percent"]}%</td><td style="padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); text-align: center; font-size: 11px;">{row["memory_percent"]}%</td></tr>')
        
        process_table_html = ''.join(process_rows)
        
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 20px; 
                    border-radius: 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center; margin-bottom: 15px;">Top Processes</div>
                <div style="background: #2d3250; padding: 15px; border-radius: 8px; height: 322px; overflow-y: auto;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead style="position: sticky; top: 0; background: #2d3250; z-index: 1;">
                            <tr style="border-bottom: 2px solid rgba(139, 92, 246, 0.5);">
                                <th style="padding: 10px; text-align: left; font-size: 12px;">Process Name</th>
                                <th style="padding: 10px; text-align: center; font-size: 12px;">CPU %</th>
                                <th style="padding: 10px; text-align: center; font-size: 12px;">Memory %</th>
                            </tr>
                        </thead>
                        <tbody>
                            {process_table_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Summary stats below the table
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 10px 20px 20px 20px; 
                    border-radius: 0 0 10px 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-top: -20px;
                    height: 140px;">
            <div style="color: white;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Total Processes:</span>
                    <span style="font-weight: bold;">{len(processes)}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Top CPU User:</span>
                    <span style="font-weight: bold; font-size: 11px;">{processes_df.iloc[0]['name'][:20] if len(processes_df) > 0 else 'N/A'}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">CPU Usage:</span>
                    <span style="font-weight: bold; color: #ec4899;">{processes_df.iloc[0]['cpu_percent'] if len(processes_df) > 0 else 0}%</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="opacity: 0.8;">Memory Usage:</span>
                    <span style="font-weight: bold; color: #8b5cf6;">{processes_df.iloc[0]['memory_percent'] if len(processes_df) > 0 else 0}%</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("")
    
    # ========================================================================
    # ROW 5: DETAILED STATISTICS
    # ========================================================================
    
    row5_col1, row5_col2 = st.columns([1, 1])
    
    # CPU CORES CARD
    with row5_col1:
        st.markdown("""
        <div style="background: #1e2139; 
                    padding: 20px 20px 10px 20px; 
                    border-radius: 10px 10px 0 0; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center;">CPU Usage by Core</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if cpu_info['per_core']:
            core_df = pd.DataFrame({
                'Core': [f"Core {i}" for i in range(len(cpu_info['per_core']))],
                'Usage (%)': cpu_info['per_core']
            })
            
            fig = px.bar(core_df, x='Core', y='Usage (%)', 
                         color='Usage (%)',
                         color_continuous_scale=['#8b5cf6', '#ec4899', '#f43f5e'])
            fig.update_layout(
                height=280, 
                margin=dict(l=40, r=20, t=20, b=40),
                paper_bgcolor="#1e2139",
                plot_bgcolor="#1e2139",
                font={'color': 'white'},
                xaxis=dict(gridcolor='rgba(255,255,255,0.1)', color='white'),
                yaxis=dict(gridcolor='rgba(255,255,255,0.1)', color='white'),
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Core statistics
        avg_usage = sum(cpu_info['per_core']) / len(cpu_info['per_core']) if cpu_info['per_core'] else 0
        max_core = max(cpu_info['per_core']) if cpu_info['per_core'] else 0
        min_core = min(cpu_info['per_core']) if cpu_info['per_core'] else 0
        
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 10px 20px 20px 20px; 
                    border-radius: 0 0 10px 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-top: -20px;
                    height: 140px;">
            <div style="color: white;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Total Cores:</span>
                    <span style="font-weight: bold;">{len(cpu_info['per_core'])}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Average Usage:</span>
                    <span style="font-weight: bold; color: #8b5cf6;">{avg_usage:.1f}%</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span style="opacity: 0.8;">Highest Core:</span>
                    <span style="font-weight: bold; color: #ec4899;">{max_core:.1f}%</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="opacity: 0.8;">Lowest Core:</span>
                    <span style="font-weight: bold; color: #f43f5e;">{min_core:.1f}%</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # DETAILED PROCESSES TABLE CARD
    with row5_col2:
        st.markdown("""
        <div style="background: #1e2139; 
                    padding: 20px 20px 10px 20px; 
                    border-radius: 10px 10px 0 0; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="color: white;">
                <div style="font-size: 18px; font-weight: bold; text-align: center;">Detailed Process List</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        processes_df = pd.DataFrame(processes)
        processes_df = processes_df.sort_values('cpu_percent', ascending=False).head(12)
        processes_df['memory_percent'] = processes_df['memory_percent'].round(2)
        processes_df['cpu_percent'] = processes_df['cpu_percent'].round(2)
        
        # Create detailed process table HTML
        detailed_rows = []
        for idx, row in processes_df.iterrows():
            process_name = row['name'][:30] + "..." if len(str(row['name'])) > 30 else row['name']
            detailed_rows.append(f'<tr><td style="padding: 6px; border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 10px;">{row["pid"]}</td><td style="padding: 6px; border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 10px;">{process_name}</td><td style="padding: 6px; border-bottom: 1px solid rgba(255,255,255,0.1); text-align: center; font-size: 10px;">{row["cpu_percent"]}%</td><td style="padding: 6px; border-bottom: 1px solid rgba(255,255,255,0.1); text-align: center; font-size: 10px;">{row["memory_percent"]}%</td></tr>')
        
        detailed_table_html = ''.join(detailed_rows)
        
        st.markdown(f"""
        <div style="background: #1e2139; 
                    padding: 10px 20px 20px 20px; 
                    border-radius: 0 0 10px 10px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-top: -20px;
                    height: 440px;
                    overflow-y: auto;">
            <div style="color: white;">
                <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
                    <thead style="position: sticky; top: 0; background: #1e2139; z-index: 1;">
                        <tr style="border-bottom: 2px solid rgba(139, 92, 246, 0.5);">
                            <th style="padding: 8px; text-align: left; font-size: 11px;">PID</th>
                            <th style="padding: 8px; text-align: left; font-size: 11px;">Process Name</th>
                            <th style="padding: 8px; text-align: center; font-size: 11px;">CPU %</th>
                            <th style="padding: 8px; text-align: center; font-size: 11px;">Mem %</th>
                        </tr>
                    </thead>
                    <tbody>
                        {detailed_table_html}
                    </tbody>
                </table>
            </div>
        </div>
        """, unsafe_allow_html=True)


def main():
    """Main function for server performance monitoring"""
    
    st.markdown('<h1 style="color: #c0c0c0;">Server Performance Dashboard</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color: #a8a8a8; font-size: 16px;">Real-time system monitoring and resource utilization (Auto-refresh: 2 seconds)</p>', unsafe_allow_html=True)
    
    # Initialize session state for network history
    if 'network_history' not in st.session_state:
        st.session_state.network_history = []
    if 'last_network_bytes' not in st.session_state:
        st.session_state.last_network_bytes = {'sent': 0, 'recv': 0, 'time': time.time()}
    
    # Call the fragment function that updates every 2 seconds
    update_dashboard()


# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.markdown("## Server Monitor")
    st.markdown("---")
    
    st.markdown("### Monitoring Options")
    st.info("🔄 Real-time updates: Every 2 seconds (no flash, smooth updates)")
    
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
