import json
import os
import glob

brain_dir = r"C:\Users\raksh\.gemini\antigravity\brain"
target_dir = r"C:\Users\raksh\OneDrive\Desktop\CyberAIProject\agentic-cyber-security"

files_to_recover = [
    "app.py",
    "src/database.py",
    "src/agent_pipeline.py",
    "src/telegram_bot.py",
    "src/twilio_server.py",
    "src/agents/scam_agent.py"
]

file_contents = {}

log_files = glob.glob(os.path.join(brain_dir, "*", ".system_generated", "logs", "overview.txt"))
log_files.sort(key=os.path.getmtime)

for log_file in log_files:
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                if "tool_calls" in data:
                    for tool in data["tool_calls"]:
                        if tool["name"] == "write_to_file":
                            args = tool["args"]
                            target = args.get("TargetFile", "")
                            content = args.get("CodeContent", "")
                            if isinstance(target, str):
                                target = target.strip('"')
                            for f_name in files_to_recover:
                                if target.replace("\\", "/").endswith(f_name):
                                    if isinstance(content, str) and content.startswith('"'):
                                        content = json.loads(content)
                                    file_contents[f_name] = content
            except Exception as e:
                print(f"Error parsing line: {e}")
                pass

print("Files found in logs:", file_contents.keys())

for f_name, content in file_contents.items():

    if not content: continue
    full_path = os.path.join(target_dir, f_name)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Recovered {f_name}")
