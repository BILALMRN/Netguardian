"""
Traffic Monitoring Module for NetGuardian

This module provides functionality for monitoring network traffic and
collecting statistics.
"""

import psutil
import time
import logging
import threading
from typing import List, Dict, Optional, Tuple, Deque
from collections import deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TrafficMonitor:
    """
    Monitors network traffic.
    """
    
    def __init__(self, update_interval: float = 1.0, history_size: int = 60):
        """
        Initialize the traffic monitor.
        
        Args:
            update_interval: Interval in seconds between updates.
            history_size: Number of historical data points to keep.
        """
        self.update_interval = update_interval
        self.history_size = history_size
        self.running = False
        self.monitor_thread = None
        self._lock = threading.Lock()
        
        # Traffic history (bytes per second)
        self.send_history = deque(maxlen=history_size)
        self.recv_history = deque(maxlen=history_size)
        
        # Timestamps for history
        self.timestamps = deque(maxlen=history_size)
        
        # Last counters
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0
        self.last_time = 0
        
        # Initialize with zeros
        for _ in range(history_size):
            self.send_history.append(0)
            self.recv_history.append(0)
            self.timestamps.append(time.time())
    
    def start(self) -> None:
        """Start monitoring traffic."""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("Traffic monitoring started")
    
    def stop(self) -> None:
        """Stop monitoring traffic."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
            self.monitor_thread = None
        logger.info("Traffic monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        # Initialize counters
        net_io = psutil.net_io_counters()
        self.last_bytes_sent = net_io.bytes_sent
        self.last_bytes_recv = net_io.bytes_recv
        self.last_time = time.time()
        
        while self.running:
            try:
                self._update_traffic()
                time.sleep(self.update_interval)
            except Exception as e:
                logger.error(f"Error in traffic monitoring: {e}")
                time.sleep(1.0)  # Sleep a bit to avoid tight loop on error
    
    def _update_traffic(self) -> None:
        """Update traffic statistics."""
        try:
            # Get current counters
            net_io = psutil.net_io_counters()
            current_time = time.time()
            
            # Calculate rates
            time_diff = current_time - self.last_time
            if time_diff > 0:
                bytes_sent_diff = net_io.bytes_sent - self.last_bytes_sent
                bytes_recv_diff = net_io.bytes_recv - self.last_bytes_recv
                
                send_rate = bytes_sent_diff / time_diff
                recv_rate = bytes_recv_diff / time_diff
                
                with self._lock:
                    self.send_history.append(send_rate)
                    self.recv_history.append(recv_rate)
                    self.timestamps.append(current_time)
            
            # Update last values
            self.last_bytes_sent = net_io.bytes_sent
            self.last_bytes_recv = net_io.bytes_recv
            self.last_time = current_time
            
        except Exception as e:
            logger.error(f"Error updating traffic: {e}")
    
    def get_current_rates(self) -> Dict[str, float]:
        """
        Get current traffic rates.
        
        Returns:
            Dictionary with current send and receive rates.
        """
        with self._lock:
            if len(self.send_history) > 0:
                send_rate = self.send_history[-1]
                recv_rate = self.recv_history[-1]
            else:
                send_rate = 0
                recv_rate = 0
            
            return {
                "send_rate": send_rate,
                "recv_rate": recv_rate
            }
    
    def get_history(self, duration: Optional[int] = None) -> Dict:
        """
        Get traffic history.
        
        Args:
            duration: Optional duration in seconds to limit history.
            
        Returns:
            Dictionary with traffic history.
        """
        with self._lock:
            if duration is None or duration >= self.history_size:
                # Return all history
                return {
                    "timestamps": list(self.timestamps),
                    "send_rates": list(self.send_history),
                    "recv_rates": list(self.recv_history)
                }
            else:
                # Return limited history
                limit = min(duration, len(self.timestamps))
                return {
                    "timestamps": list(self.timestamps)[-limit:],
                    "send_rates": list(self.send_history)[-limit:],
                    "recv_rates": list(self.recv_history)[-limit:]
                }
    
    def get_average_rates(self, duration: Optional[int] = None) -> Dict[str, float]:
        """
        Get average traffic rates over a duration.
        
        Args:
            duration: Optional duration in seconds to calculate average.
            
        Returns:
            Dictionary with average send and receive rates.
        """
        with self._lock:
            if duration is None or duration >= self.history_size:
                # Average over all history
                send_avg = sum(self.send_history) / max(1, len(self.send_history))
                recv_avg = sum(self.recv_history) / max(1, len(self.recv_history))
            else:
                # Average over limited history
                limit = min(duration, len(self.send_history))
                send_avg = sum(list(self.send_history)[-limit:]) / max(1, limit)
                recv_avg = sum(list(self.recv_history)[-limit:]) / max(1, limit)
            
            return {
                "send_rate_avg": send_avg,
                "recv_rate_avg": recv_avg
            }
    
    def get_peak_rates(self, duration: Optional[int] = None) -> Dict[str, float]:
        """
        Get peak traffic rates over a duration.
        
        Args:
            duration: Optional duration in seconds to find peak.
            
        Returns:
            Dictionary with peak send and receive rates.
        """
        with self._lock:
            if duration is None or duration >= self.history_size:
                # Peak over all history
                send_peak = max(self.send_history) if self.send_history else 0
                recv_peak = max(self.recv_history) if self.recv_history else 0
            else:
                # Peak over limited history
                limit = min(duration, len(self.send_history))
                send_peak = max(list(self.send_history)[-limit:]) if self.send_history else 0
                recv_peak = max(list(self.recv_history)[-limit:]) if self.recv_history else 0
            
            return {
                "send_rate_peak": send_peak,
                "recv_rate_peak": recv_peak
            }
