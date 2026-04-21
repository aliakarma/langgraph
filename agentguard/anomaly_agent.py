from collections import defaultdict
import time

class AnomalyDetectionAgent:
    """
    Agent 3: Watches patterns across the session.
    Detects attacks that look innocent at each individual step
    but reveal malicious intent when viewed together.
    """
    
    def __init__(self):
        # Tracks what has happened in each session
        self.session_history = defaultdict(list)
    
    def record(self, session_id: str, tool_name: str, tool_args: dict, decision: str):
        """Saves the action to the session history AFTER it is evaluated."""
        self.session_history[session_id].append({
            "tool": tool_name,
            "args": tool_args,
            "decision": decision,
            "timestamp": time.time()
        })
    
    def analyze(self, session_id: str, tool_name: str, tool_args: dict) -> dict:
        """Analyzes the history to see if the NEW proposed action looks suspicious."""
        history = self.session_history[session_id]
        alerts = []
        
        # Check 1: Repeated blocked attempts (3+ blocks = persistent attacker)
        blocked = [h for h in history if h["decision"] == "BLOCKED"]
        if len(blocked) >= 3:
            alerts.append(f"REPEATED_BLOCKS: {len(blocked)} blocked attempts this session")
        
        # Check 2: Privilege escalation pattern
        # Example: Read credentials -> then make network request
        tools_used = [h["tool"] for h in history]
        credential_tools = {"read_file", "get_secret", "read_env"}
        network_tools = {"http_request", "send_email", "api_call"}
        
        recent_tools = set(tools_used[-5:]) # Look at last 5 actions
        if (recent_tools & credential_tools) and tool_name in network_tools:
            alerts.append("ESCALATION_PATTERN: Read credentials then network request detected")
        
        if alerts:
            return {
                "decision": "BLOCK",
                "reason": f"Anomaly detected: {alerts[0]}",
                "alerts": alerts
            }
        
        return {"decision": "ALLOW", "reason": "No anomalies detected", "alerts": []}

# --- Quick Test ---
if __name__ == "__main__":
    agent = AnomalyDetectionAgent()
    session = "test_user_1"
    
    print("Action 1: Agent reads a file (Benign)")
    print(agent.analyze(session, "read_file", {"path": "/workspace/config.txt"}))
    agent.record(session, "read_file", {"path": "/workspace/config.txt"}, "ALLOWED")
    
    print("\nAction 2: Agent tries to send an email right after (Suspicious)")
    # This triggers the Escalation Pattern (Read file -> Network request)
    print(agent.analyze(session, "send_email", {"to": "hacker@evil.com"}))