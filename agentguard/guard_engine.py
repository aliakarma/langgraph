from .policy_agent import PolicyEnforcementAgent
from .anomaly_agent import AnomalyDetectionAgent
from .intent_agent import IntentVerificationAgent

class AgentGuardEngine:
    """
    The central engine. Called before every tool execution.
    Runs the triad of agents and makes a final decision.
    """
    
    def __init__(self, use_llm_intent=True):
        self.policy_agent = PolicyEnforcementAgent()
        self.anomaly_agent = AnomalyDetectionAgent()
        self.intent_agent = IntentVerificationAgent() if use_llm_intent else None
        self.audit_log = []
    
    def evaluate(self, session_id: str, original_task: str, tool_name: str, tool_args: dict) -> dict:
        result = {"tool_name": tool_name, "final_decision": "ALLOW", "reason": ""}
        
        # 1. Policy Check (Fast, deterministic)
        policy = self.policy_agent.check(tool_name, tool_args)
        if not policy.allowed:
            return self._block(session_id, tool_name, tool_args, f"Policy: {policy.reason}")
            
        # 2. Anomaly Check (Stateful tracking)
        anomaly = self.anomaly_agent.analyze(session_id, tool_name, tool_args)
        if anomaly["decision"] == "BLOCK":
            return self._block(session_id, tool_name, tool_args, anomaly["reason"])
            
        # 3. Intent Check (LLM, only if previous passed)
        if self.intent_agent and original_task:
            intent = self.intent_agent.verify(original_task, tool_name, tool_args)
            if intent["decision"] == "BLOCK":
                return self._block(session_id, tool_name, tool_args, f"Intent: {intent['reason']}")
        
        # If all pass, allow and record
        self.anomaly_agent.record(session_id, tool_name, tool_args, "ALLOWED")
        result["reason"] = "All security checks passed"
        self._log(result)
        return result

    def _block(self, session_id, tool_name, tool_args, reason):
        self.anomaly_agent.record(session_id, tool_name, tool_args, "BLOCKED")
        result = {"tool_name": tool_name, "final_decision": "BLOCK", "reason": reason}
        self._log(result)
        return result

    def _log(self, result):
        icon = "✅" if result["final_decision"] == "ALLOW" else "🛑"
        print(f"{icon} [AgentGuard] {result['final_decision']}: {result['tool_name']} - {result['reason']}")

# --- Quick Test ---
if __name__ == "__main__":
    engine = AgentGuardEngine(use_llm_intent=False) # LLM off for quick test
    
    print("Testing Triad Engine:\n")
    engine.evaluate("session1", "Read data", "read_file", {"path": "/workspace/data.csv"}) # Should ALLOW
    engine.evaluate("session1", "Read data", "read_file", {"path": "../../.env"}) # Should BLOCK (Policy)