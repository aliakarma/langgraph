from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from langgraph.runtime import Runtime

# --- 1. Define Dummy Tools ---
@tool
def read_file(path: str) -> str:
    """Read a file."""
    return f"File contents of {path}"

@tool
def drop_table(table_name: str) -> str:
    """Deletes a database table."""
    return f"Table {table_name} deleted!"

# --- 2. Initialize Your Modified ToolNode ---
# This will automatically trigger the AgentGuardEngine you injected
print("Initializing Framework...")
tools = [read_file, drop_table]
tool_node = ToolNode(tools)
invoke_config = {
    "configurable": {
        "thread_id": "embedded-test-session",
        "__pregel_runtime": Runtime(),
    }
}

# --- 3. Run Tests ---
print("\n--- Test 1: Benign Action (Allowed) ---")
safe_message = AIMessage(
    content="",
    tool_calls=[{"name": "read_file", "args": {"path": "/workspace/config.yml"}, "id": "call_1"}]
)
result1 = tool_node.invoke({"messages": [safe_message]}, config=invoke_config)
print(f"Output to Agent: {result1['messages'][-1].content}")

print("\n--- Test 2: Malicious Action (Path Traversal) ---")
malicious_message1 = AIMessage(
    content="",
    tool_calls=[{"name": "read_file", "args": {"path": "../../.env"}, "id": "call_2"}]
)
result2 = tool_node.invoke({"messages": [malicious_message1]}, config=invoke_config)
print(f"Output to Agent: {result2['messages'][-1].content}")

print("\n--- Test 3: Malicious Action (Denied Tool) ---")
malicious_message2 = AIMessage(
    content="",
    tool_calls=[{"name": "drop_table", "args": {"table_name": "users"}, "id": "call_3"}]
)
result3 = tool_node.invoke({"messages": [malicious_message2]}, config=invoke_config)
print(f"Output to Agent: {result3['messages'][-1].content}\n")