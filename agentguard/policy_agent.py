from dataclasses import dataclass

@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    rule_matched: str

class PolicyEnforcementAgent:
    """
    Agent 2: Checks tool calls against a security policy.
    Fast, reliable, auditable. No LLM involved.
    """
    
    def __init__(self, policy_dict: dict = None):
        if policy_dict:
            self.policy = policy_dict
        else:
            # The default strict policy
            self.policy = {
                "denied_tools": ["delete_file", "drop_table", "send_email"],
                "dangerous_patterns": ["rm -rf", "DROP TABLE", "../", ".env"],
                "allowed_file_paths": ["/workspace/"]
            }
    
    def check(self, tool_name: str, tool_args: dict) -> PolicyDecision:
        # Rule 1: Explicitly denied tools
        if tool_name in self.policy.get("denied_tools", []):
            return PolicyDecision(False, f"Tool '{tool_name}' is explicitly denied", "denied_tools")
        
        # Rule 2: Dangerous patterns in arguments
        args_str = str(tool_args).lower()
        for pattern in self.policy.get("dangerous_patterns", []):
            if pattern.lower() in args_str:
                return PolicyDecision(False, f"Dangerous pattern detected: '{pattern}'", "dangerous_patterns")
        
        # Rule 3: File path restrictions
        if "path" in tool_args:
            path = tool_args["path"]
            allowed_paths = self.policy.get("allowed_file_paths", [])
            if allowed_paths and not any(path.startswith(p) for p in allowed_paths):
                return PolicyDecision(False, f"File path '{path}' is outside allowed directories", "allowed_file_paths")
        
        return PolicyDecision(True, "All policy checks passed", "none")

# --- Quick Test ---
if __name__ == "__main__":
    agent = PolicyEnforcementAgent()
    
    print("Testing benign action...")
    result1 = agent.check("read_file", {"path": "/workspace/data.csv"})
    print(f"Allowed: {result1.allowed} | Reason: {result1.reason}")
    
    print("\nTesting malicious action (path traversal)...")
    result2 = agent.check("read_file", {"path": "../../.env"})
    print(f"Allowed: {result2.allowed} | Reason: {result2.reason}")