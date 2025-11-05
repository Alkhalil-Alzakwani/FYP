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
    /* Main content background */
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
    # Determine color based on value - simple color scheme
    if value < 50:
        color = "#28a745"  # Green
    elif value < 80:
        color = "#ffc107"  # Yellow
    else:
        color = "#dc3545"  # Red
    
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
            'bgcolor': "#1f1f28",
            'borderwidth': 2,
            'bordercolor': "#3a4150",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(40, 167, 69, 0.1)'},
                {'range': [50, 80], 'color': 'rgba(255, 193, 7, 0.1)'},
                {'range': [80, 100], 'color': 'rgba(220, 53, 69, 0.1)'}
            ],
            'threshold': {
                'line': {'color': "#dc3545", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=50, b=10),
        paper_bgcolor="#1f1f28",
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
            line=dict(color='#dc3545', width=3, shape='spline', smoothing=1.3),
            fill='tozeroy',
            fillcolor='rgba(220, 53, 69, 0.2)'
        ))
        
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['recv_mbps'],
            mode='lines',
            name='Download (Kbps)',
            line=dict(color='#007bff', width=3, shape='spline', smoothing=1.3),
            fill='tozeroy',
            fillcolor='rgba(0, 123, 255, 0.2)'
        ))
    
    fig.update_layout(
        title={'text': "Real-Time Network Traffic", 'font': {'size': 16, 'color': 'white'}},
        xaxis_title="Time",
        yaxis_title="Speed (Kbps)",
        height=330,
        hovermode='x unified',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(color='white')),
        margin=dict(l=40, r=20, t=50, b=40),
        plot_bgcolor='#1f1f28',
        paper_bgcolor='#1f1f28',
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
        <div style="background: #1f1f28; 
                    padding: 10px 20px; 
                    border-radius: 10px; 
                    margin-bottom: 20px;
                    border: 1px solid #3a4150;
                    box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
            <div style="display: flex; justify-content: space-between; align-items: center; color: white;">
                <div style="flex: 1; text-align: center; border-right: 1px solid #3a4150; padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">System</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['system']} {sys_info['release']}</div>
                </div>
                <div style="flex: 1; text-align: center; border-right: 1px solid #3a4150; padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">Machine</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['machine']}</div>
                </div>
                <div style="flex: 1; text-align: center; border-right: 1px solid #3a4150; padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">Processor</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['processor'][:30]}</div>
                </div>
                <div style="flex: 1; text-align: center; border-right: 1px solid #3a4150; padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">Boot Time</div>
                    <div style="font-size: 14px; font-weight: bold; margin-top: 3px;">{sys_info['boot_time'].strftime("%Y-%m-%d %H:%M")}</div>
                </div>
                <div style="flex: 1; text-align: center; padding: 0 15px;">
                    <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">Uptime</div>
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
    <div style="background: #1f1f28; 
                padding: 10px 20px; 
                border-radius: 10px; 
                margin-bottom: 20px;
                border: 1px solid #3a4150;
                box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
        <div style="display: flex; justify-content: space-between; align-items: center; color: white;">
            <div style="flex: 1; text-align: center; border-right: 1px solid #3a4150; padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">CPU</div>
                <div style="font-size: 14px; font-weight: bold; margin-top: 3px; color: {cpu_color};">{cpu_info['percent']:.1f}%</div>
            </div>
            <div style="flex: 1; text-align: center; border-right: 1px solid #3a4150; padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">Memory</div>
                <div style="font-size: 14px; font-weight: bold; margin-top: 3px; color: {mem_color};">{mem_info['percent']:.1f}%</div>
            </div>
            <div style="flex: 1; text-align: center; border-right: 1px solid #3a4150; padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">Disk</div>
                <div style="font-size: 14px; font-weight: bold; margin-top: 3px; color: {disk_color};">{max_disk:.1f}%</div>
            </div>
            <div style="flex: 1; text-align: center; padding: 0 15px;">
                <div style="font-size: 11px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px;">GPU</div>
                <div style="font-size: 14px; font-weight: bold; margin-top: 3px; color: {gpu_color};">{gpu_text}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # ========================================================================
    # ROW 2: CPU, GPU & MEMORY (LEFT) + SYSTEM RESOURCES (RIGHT)
    # ========================================================================
    
    # Create main layout with left column for gauges and right column for System Resources
    main_left_col, main_right_col = st.columns([2, 1])
    
    with main_left_col:
        # Inner layout for CPU, GPU, Memory gauges
        row2_col1, row2_col2, row2_col3 = st.columns([1, 1, 1])
        
        # CPU CARD
        with row2_col1:
            st.markdown("""
            <div style="background: #1f1f28; 
                        padding: 10px 20px 5px 20px; 
                        border-radius: 10px 10px 0 0; 
                        border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
                <div style="color: white;">
                    <div style="font-size: 16px; font-weight: bold; text-align: center;">CPU Usage</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.plotly_chart(
                create_gauge_chart(cpu_info['percent'], "", height=160),
                use_container_width=True
            )
            
            st.markdown(f"""
            <div style="background: #1f1f28; 
                        padding: 5px 15px 10px 15px; 
                        border-radius: 0 0 10px 10px; 
                        border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);
                        margin-top: -20px;
                        height: 100px;">
                <div style="color: white;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 11px;">
                        <span style="opacity: 0.7;">Physical Cores:</span>
                        <span style="font-weight: bold;">{cpu_info['count_physical']}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 11px;">
                        <span style="opacity: 0.7;">Logical Cores:</span>
                        <span style="font-weight: bold;">{cpu_info['count_logical']}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 11px;">
                        <span style="opacity: 0.7;">Current Freq:</span>
                        <span style="font-weight: bold;">{cpu_info['frequency_current']:.0f} MHz</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 11px;">
                        <span style="opacity: 0.7;">Max Freq:</span>
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
                <div style="background: #1f1f28; 
                            padding: 10px 20px 5px 20px; 
                            border-radius: 10px 10px 0 0; 
                            border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
                    <div style="color: white;">
                        <div style="font-size: 16px; font-weight: bold; text-align: center;">GPU Usage</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.plotly_chart(
                    create_gauge_chart(gpu_info['load'], "", height=160),
                    use_container_width=True
                )
                
                st.markdown(f"""
                <div style="background: #1f1f28; 
                            padding: 5px 15px 10px 15px; 
                            border-radius: 0 0 10px 10px; 
                            border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);
                            margin-top: -20px;
                            height: 100px;">
                    <div style="color: white;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 10px;">
                            <span style="opacity: 0.7;">GPU Name:</span>
                            <span style="font-weight: bold;">{gpu_name}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 10px;">
                            <span style="opacity: 0.7;">Memory Used:</span>
                            <span style="font-weight: bold;">{gpu_info['memory_used']:.0f} MB</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 10px;">
                            <span style="opacity: 0.7;">Memory Total:</span>
                            <span style="font-weight: bold;">{gpu_info['memory_total']:.0f} MB</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 10px;">
                            <span style="opacity: 0.7;">Memory Usage:</span>
                            <span style="font-weight: bold;">{gpu_info['memory_percent']:.1f}%</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; font-size: 10px;">
                            <span style="opacity: 0.7;">Temperature:</span>
                            <span style="font-weight: bold;">{temp_display}</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                error_type = gpu_info.get('error', 'unknown')
                error_msg = "No GPU detected" if error_type == 'no_gpu' else "GPU unavailable"
                
                st.markdown("""
                <div style="background: #1f1f28; 
                            padding: 10px 20px 5px 20px; 
                            border-radius: 10px 10px 0 0; 
                            border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
                    <div style="color: white;">
                        <div style="font-size: 16px; font-weight: bold; text-align: center;">GPU Usage</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.plotly_chart(
                    create_gauge_chart(0, "", height=160),
                    use_container_width=True
                )
                
                st.markdown(f"""
                <div style="background: #1f1f28; 
                            padding: 5px 15px 10px 15px; 
                            border-radius: 0 0 10px 10px; 
                            border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);
                            margin-top: -20px;
                            height: 100px;
                            display: flex;
                            align-items: center;
                            justify-content: center;">
                    <div style="color: white; text-align: center; opacity: 0.7;">
                        {error_msg}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        # MEMORY CARD
        with row2_col3:
            st.markdown("""
            <div style="background: #1f1f28; 
                        padding: 10px 20px 5px 20px; 
                        border-radius: 10px 10px 0 0; 
                        border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
                <div style="color: white;">
                    <div style="font-size: 16px; font-weight: bold; text-align: center;">Memory Usage</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.plotly_chart(
                create_gauge_chart(mem_info['percent'], "", height=160),
                use_container_width=True
            )
            
            swap_text = f"{get_size(mem_info['swap_total'])} ({mem_info['swap_percent']:.1f}%)" if mem_info['swap_total'] > 0 else "Not configured"
            
            st.markdown(f"""
            <div style="background: #1f1f28; 
                        padding: 5px 15px 10px 15px; 
                        border-radius: 0 0 10px 10px; 
                        border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);
                        margin-top: -20px;
                        height: 100px;">
                <div style="color: white;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 11px;">
                        <span style="opacity: 0.7;">Total Memory:</span>
                        <span style="font-weight: bold;">{get_size(mem_info['total'])}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 11px;">
                        <span style="opacity: 0.7;">Used:</span>
                        <span style="font-weight: bold;">{get_size(mem_info['used'])}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 11px;">
                        <span style="opacity: 0.7;">Available:</span>
                        <span style="font-weight: bold;">{get_size(mem_info['available'])}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 11px;">
                        <span style="opacity: 0.7;">Swap:</span>
                        <span style="font-weight: bold; font-size: 10px;">{swap_text}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Add Network Traffic card under the three gauge cards (within main_left_col)
        st.markdown("")
        
        # NETWORK TRAFFIC CARD
        st.markdown("""
        <div style="background: #1f1f28; 
                    padding: 10px 20px 5px 20px; 
                    border-radius: 10px 10px 0 0; 
                    border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
            <div style="color: white;">
                <div style="font-size: 16px; font-weight: bold; text-align: center;">Network Traffic</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.plotly_chart(
            create_network_realtime_chart(st.session_state.network_history),
            use_container_width=True
        )
        
        st.markdown(f"""
        <div style="background: #1f1f28; 
                    padding: 5px 15px 10px 15px; 
                    border-radius: 0 0 10px 10px; 
                    border: 1px solid #3a4150; box-shadow: 0 2px 4px rgba(255,255,255,0.1);
                    margin-top: -20px;
                    height: 70px;">
            <div style="color: white;">
                <div style="display: flex; justify-content: space-around; margin-bottom: 5px;">
                    <div style="text-align: center;">
                        <span style="opacity: 0.7; display: block; font-size: 10px;">Upload</span>
                        <span style="font-weight: bold; color: #dc3545; font-size: 12px;">{sent_speed:.2f} Kbps</span>
                    </div>
                    <div style="text-align: center;">
                        <span style="opacity: 0.7; display: block; font-size: 10px;">Download</span>
                        <span style="font-weight: bold; color: #007bff; font-size: 12px;">{recv_speed:.2f} Kbps</span>
                    </div>
                    <div style="text-align: center;">
                        <span style="opacity: 0.7; display: block; font-size: 10px;">Total Sent</span>
                        <span style="font-weight: bold; font-size: 12px;">{get_size(net_info['bytes_sent'])}</span>
                    </div>
                    <div style="text-align: center;">
                        <span style="opacity: 0.7; display: block; font-size: 10px;">Total Received</span>
                        <span style="font-weight: bold; font-size: 12px;">{get_size(net_info['bytes_recv'])}</span>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Now add the System Resources card in the right column
    with main_right_col:
        # UNIFIED SYSTEM RESOURCES CARD (VERTICAL) - Single container with one background
        with st.container():
            st.markdown("""
            <div style="background: #1f1f28; 
                        padding: 10px 20px 5px 20px; 
                        border-radius: 10px 10px 0 0; 
                        border: 1px solid #3a4150; 
                        box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
                <div style="color: white;">
                    <div style="font-size: 16px; font-weight: bold; text-align: center;">System Resources</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # RAM section
            st.markdown("""
            <div style="background: #1f1f28; 
                        padding: 0 20px; 
                        margin-top: -20px;
                        border-left: 1px solid #3a4150;
                        border-right: 1px solid #3a4150;">
            </div>
            """, unsafe_allow_html=True)
            
            # Create vertical RAM bar chart
            used_percent = (mem_info['used'] / mem_info['total'] * 100) if mem_info['total'] > 0 else 0
            
            fig_ram_vert = go.Figure()
            
            # Add background bar (100% capacity)
            fig_ram_vert.add_trace(go.Bar(
                y=['RAM'],
                x=[100],
                orientation='h',
                name='Capacity',
                marker=dict(
                    color='rgba(0, 0, 0, 0.5)',
                    line=dict(color='#000000', width=2),
                    cornerradius="30%"
                ),
                width=0.3,
                showlegend=False
            ))
            
            # Add available bar
            fig_ram_vert.add_trace(go.Bar(
                y=['RAM'],
                x=[100],
                orientation='h',
                name='Available',
                marker=dict(
                    color='#007bff',
                    line=dict(color='#000000', width=1),
                    cornerradius="30%"
                ),
                width=0.3,
                showlegend=False
            ))
            
            # Add used bar
            fig_ram_vert.add_trace(go.Bar(
                y=['RAM'],
                x=[used_percent],
                orientation='h',
                name='Used',
                marker=dict(
                    color='#dc3545',
                    line=dict(color='#000000', width=1),
                    cornerradius="30%"
                ),
                width=0.3,
                showlegend=False
            ))
            
            fig_ram_vert.update_layout(
                height=100,
                margin=dict(l=60, r=20, t=5, b=5),
                xaxis={'tickfont': {'size': 10, 'color': 'white'}, 'range': [0, 100], 'title': '%'},
                yaxis={'tickfont': {'color': 'white', 'size': 12}},
                paper_bgcolor="#1f1f28",
                plot_bgcolor="#1f1f28",
                font={'color': 'white'},
                barmode='overlay',
                showlegend=False
            )
            
            st.markdown("""
            <div style="background: #1f1f28; 
                        padding: 0 20px; 
                        margin-top: -20px;
                        border-left: 1px solid #3a4150;
                        border-right: 1px solid #3a4150;">
            """, unsafe_allow_html=True)
            st.plotly_chart(fig_ram_vert, use_container_width=True, key="ram_vertical")
            st.markdown("</div>", unsafe_allow_html=True)
            
            st.markdown(f"""
            <div style="background: #1f1f28; 
                        padding: 0 20px; 
                        margin-top: -40px;
                        border-left: 1px solid #3a4150;
                        border-right: 1px solid #3a4150;">
                <div style="color: white; font-size: 11px; text-align: center; margin-bottom: 0px;">
                    <span style="opacity: 0.7;">Used: </span><span style="font-weight: bold; color: #dc3545;">{get_size(mem_info['used'])}</span>
                    <span style="opacity: 0.7;"> / </span>
                    <span style="font-weight: bold;">{get_size(mem_info['total'])}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Disk Usage section
            if disk_info:
                disk_df = pd.DataFrame(disk_info)
                
                # Create vertical disk bar chart
                fig_disk_vert = go.Figure()
                
                # Add background bars (100% capacity)
                fig_disk_vert.add_trace(go.Bar(
                    y=disk_df['device'],
                    x=[100] * len(disk_df),
                    orientation='h',
                    name='Capacity',
                    marker=dict(
                        color='rgba(0, 0, 0, 0.5)',
                        line=dict(color='#000000', width=2),
                        cornerradius="30%"
                    ),
                    width=0.3,
                    showlegend=False
                ))
                
                # Add usage bars with color based on percentage
                colors = ['#007bff' if percent < 80 else '#dc3545' for percent in disk_df['percent']]
                fig_disk_vert.add_trace(go.Bar(
                    y=disk_df['device'],
                    x=disk_df['percent'],
                    orientation='h',
                    name='Usage',
                    marker=dict(
                        color=colors,
                        line=dict(color='#000000', width=1),
                        cornerradius="30%"
                    ),
                    width=0.3,
                    showlegend=False
                ))
                
                fig_disk_vert.update_layout(
                    height=max(100, len(disk_df) * 50),
                    margin=dict(l=60, r=20, t=5, b=5),
                    xaxis={'tickfont': {'size': 10, 'color': 'white'}, 'range': [0, 100], 'title': '%'},
                    yaxis={'tickfont': {'color': 'white', 'size': 10}},
                    paper_bgcolor="#1f1f28",
                    plot_bgcolor="#1f1f28",
                    font={'color': 'white'},
                    barmode='overlay',
                    showlegend=False
                )
                
                st.markdown("""
                <div style="background: #1f1f28; 
                            padding: 0 20px; 
                            margin-top: -20px;
                            border-left: 1px solid #3a4150;
                            border-right: 1px solid #3a4150;">
                """, unsafe_allow_html=True)
                st.plotly_chart(fig_disk_vert, use_container_width=True, key="disk_vertical")
                st.markdown("</div>", unsafe_allow_html=True)
                
                # Disk details
                disk_items = []
                for disk in disk_info[:5]:
                    device_short = disk['device'][:15] + "..." if len(disk['device']) > 15 else disk['device']
                    disk_items.append(f'<div style="margin-bottom: 6px; font-size: 10px;"><span style="opacity: 0.7;">{device_short}</span><br/><span style="font-weight: bold;">{disk["percent"]:.1f}%</span> <span style="opacity: 0.7;">({get_size(disk["used"])} / {get_size(disk["total"])})</span></div>')
                
                disk_details_html = ''.join(disk_items)
                
                st.markdown(f"""
                <div style="background: #1f1f28; 
                            padding: 0 20px; 
                            margin-top: -40px;
                            border-left: 1px solid #3a4150;
                            border-right: 1px solid #3a4150;">
                    <div style="color: white; padding: 0 0; max-height: 180px; overflow-y: auto;">
                        {disk_details_html}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div style="background: #1f1f28; 
                            padding: 20px; 
                            margin-top: -20px;
                            border-left: 1px solid #3a4150;
                            border-right: 1px solid #3a4150;">
                    <div style="color: white; text-align: center; opacity: 0.7; font-size: 12px;">
                        No disk info available
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            # CPU Usage by Core vertical section
            if cpu_info['per_core']:
                fig_cpu_vert = go.Figure()
                
                # Reverse the order so Core 0 is at the top
                core_labels = [f"Core {i}" for i in range(len(cpu_info['per_core']))]
                core_values = cpu_info['per_core']
                
                # Add background bars (100% capacity)
                fig_cpu_vert.add_trace(go.Bar(
                    y=core_labels,
                    x=[100] * len(core_values),
                    orientation='h',
                    name='Max',
                    marker=dict(
                        color='rgba(0, 0, 0, 0.5)',
                        line=dict(color='#000000', width=2),
                        cornerradius="30%"
                    ),
                    width=0.5,
                    showlegend=False
                ))
                
                # Add usage bars with color based on usage level
                colors = ['#dc3545' if usage > 80 else '#007bff' for usage in core_values]
                
                fig_cpu_vert.add_trace(go.Bar(
                    y=core_labels,
                    x=core_values,
                    orientation='h',
                    name='Usage',
                    marker=dict(
                        color=colors,
                        opacity=0.9,
                        line=dict(color='#000000', width=1),
                        cornerradius="30%"
                    ),
                    width=0.5,
                    showlegend=False
                ))
                
                fig_cpu_vert.update_layout(
                    height=max(250, len(core_values) * 30),
                    margin=dict(l=60, r=20, t=5, b=5),
                    xaxis={'tickfont': {'size': 10, 'color': 'white'}, 'range': [0, 100], 'title': '%'},
                    yaxis={'tickfont': {'color': 'white', 'size': 10}},
                    paper_bgcolor="#1f1f28",
                    plot_bgcolor="#1f1f28",
                    font={'color': 'white'},
                    barmode='overlay',
                    showlegend=False
                )
                
                st.markdown("""
                <div style="background: #1f1f28; 
                            padding: 0 20px; 
                            margin-top: -20px;
                            border-left: 1px solid #3a4150;
                            border-right: 1px solid #3a4150;">
                """, unsafe_allow_html=True)
                st.plotly_chart(fig_cpu_vert, use_container_width=True, key="cpu_cores_vertical")
                st.markdown("</div>", unsafe_allow_html=True)
                
                # CPU Core statistics
                avg_usage = sum(cpu_info['per_core']) / len(cpu_info['per_core']) if cpu_info['per_core'] else 0
                max_core = max(cpu_info['per_core']) if cpu_info['per_core'] else 0
                min_core = min(cpu_info['per_core']) if cpu_info['per_core'] else 0
                
                st.markdown(f"""
                <div style="background: #1f1f28; 
                            padding: 0 20px 10px 20px; 
                            margin-top: -40px;
                            border-radius: 0 0 10px 10px;
                            border-left: 1px solid #3a4150;
                            border-right: 1px solid #3a4150;
                            border-bottom: 1px solid #3a4150;
                            box-shadow: 0 2px 4px rgba(255,255,255,0.1);">
                    <div style="color: white; padding: 0;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 3px; font-size: 10px;">
                            <span style="opacity: 0.7;">Cores:</span>
                            <span style="font-weight: bold;">{len(cpu_info['per_core'])}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 3px; font-size: 10px;">
                            <span style="opacity: 0.7;">Avg:</span>
                            <span style="font-weight: bold; color: #007bff;">{avg_usage:.1f}%</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 3px; font-size: 10px;">
                            <span style="opacity: 0.7;">Max:</span>
                            <span style="font-weight: bold; color: #dc3545;">{max_core:.1f}%</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; font-size: 10px;">
                            <span style="opacity: 0.7;">Min:</span>
                            <span style="font-weight: bold; color: #28a745;">{min_core:.1f}%</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
    st.markdown("")


def main():
    """Main function for server performance monitoring"""
    
    st.markdown('<h1>Server Performance Dashboard</h1>', unsafe_allow_html=True)
    st.markdown('<p style="font-size: 16px;">Real-time system monitoring and resource utilization (Auto-refresh: 2 seconds)</p>', unsafe_allow_html=True)
    
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
    st.info("ًں”„ Real-time updates: Every 2 seconds (no flash, smooth updates)")
    
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








