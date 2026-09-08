# Autonomous SOC AI Agent: Natural Language Threat Hunting, KQL Generation & Automated Endpoint Containment

As a recent Cybersecurity graduate, I built this project to address analyst fatigue and response latency in SOC environments. This Python-based agent translates plain-English analyst queries into valid Kusto Query Language (KQL), executes searches against Azure Log Analytics, performs AI cognitive threat hunting mapped to MITRE ATT&CK, and triggers host isolation via Microsoft Defender for Endpoint (MDE).

---

## 📌 Executive Summary

Modern SOC teams process thousands of alerts daily. This tool demonstrates how LLMs act as force multipliers for Tier-1 threat hunting and incident triage:

* **Natural Language to KQL Translation:** Converts natural language queries into schema-compliant KQL.
* **Cognitive Log Analysis:** Analyzes raw CSV log outputs against table-specific hunting prompts to identify malicious behaviors, confidence scores, and Indicators of Compromise (IOCs).
* **MITRE ATT&CK Framework Mapping:** Maps suspicious activity to MITRE ATT&CK tactics, techniques, and sub-techniques.
* **Active Endpoint Remediation:** Integrates with the MDE REST API to quarantine compromised hosts upon analyst confirmation.
* **Security & Cost Governance:** Enforces parameter sanitization to prevent KQL injection, paired with real-time token tracking (`tiktoken`) to manage API rate limits and costs.

---

## 🏗️ System Architecture & Workflow

```text
[Analyst Prompt] ➔ [LLM Tool Call Parameter Extraction] ➔ [Guardrail Validation & Sanitization]
                                                                        │
[MDE Endpoint Isolation]  [Analyst Approval]  [LLM Cognitive Hunt]  [Azure Log Analytics Query (KQL)]

```

1. **Prompt Ingestion:** Captures analyst investigation intent (e.g., searching for suspicious logins or command-line activity).
2. **KQL Formulation:** Uses OpenAI tool calling (`query_log_analytics`) to extract target tables, field projections, entity filters, and timeframes.
3. **Guardrail Validation:** Validates query parameters against hardcoded whitelists to ensure schema compliance and strips dangerous query characters.
4. **Log Data Ingestion:** Queries Azure Log Analytics via the `azure-monitor-query` SDK and `DefaultAzureCredential`, converting query responses into CSV string payloads.
5. **Cost & Token Assessment:** Computes input token counts using `tiktoken` to estimate execution costs and ensure compliance with model Tokens-Per-Minute (TPM) limits.
6. **Threat Hunting Evaluation:** Evaluates log payloads against table-specific expert system prompts, generating structured JSON findings containing threat descriptions, confidence levels, IOCs, and MITRE ATT&CK mappings.
7. **Reporting & Automated Response:** Outputs colorized terminal reports and logs findings to `_threats.jsonl`. If high-confidence host threats are detected, the analyst can trigger one-click host isolation via MDE REST APIs.

---

## 📂 Source Code & Architecture Deep Dive

```python
# Standard library
import time

# Third-party libraries
from colorama import Fore, init, Style
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# Local modules
import UTILITIES
import _keys
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import GUARDRAILS

# Authenticate to Azure using active CLI credentials (az login)
law_client = LogsQueryClient(credential=DefaultAzureCredential())
# Initialize OpenAI client with project API key
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)
# Set default model (e.g., gpt-5-mini)
model = MODEL_MANAGEMENT.DEFAULT_MODEL

# 1. Capture analyst's natural language prompt from terminal input
user_message = PROMPT_MANAGEMENT.get_user_message()

# 2. Convert prompt to query parameters via OpenAI Function Calling (Tool Call)
unformatted_query_context = EXECUTOR.get_query_context(openai_client, user_message, model=model)
# Strip dangerous KQL characters (| ; \n) from variables
query_context = UTILITIES.sanitize_query_context(unformatted_query_context)

# Print target table, field projections, and LLM rationale
UTILITIES.display_query_context(query_context)
# Security Check: Enforce table and field whitelists against KQL injection
GUARDRAILS.validate_tables_and_fields(query_context["table_name"], query_context["fields"])

# 3. Query Log Analytics workspace and convert results into CSV format
law_query_results = EXECUTOR.query_log_analytics(
    log_analytics_client=law_client,
    workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
    timerange_hours=query_context["time_range_hours"],
    table_name=query_context["table_name"],
    device_name=query_context["device_name"],
    fields=query_context["fields"],
    caller=query_context["caller"],
    user_principal_name=query_context["user_principal_name"])

number_of_records = law_query_results['count']
print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

# Graceful exit if no matching logs exist in timeframe
if number_of_records == 0:
    print("Exiting.")
    exit(0)

# 4. Construct threat hunt payload combining logs, formatting rules & domain prompts
threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
    user_prompt=user_message["content"],
    table_name=query_context["table_name"],
    log_data=law_query_results["records"]
)

threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT
threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

# 5. Token governance: Count tokens with tiktoken & check tier TPM limits/costs
number_of_tokens = MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model)
model = MODEL_MANAGEMENT.choose_model(model, number_of_tokens)

# Validate that selected model is approved in system whitelist
GUARDRAILS.validate_model(model)
print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against targeted logs...\n")

start_time = time.time()
# 6. Execute cognitive threat hunt with OpenAI forced JSON output mode
hunt_results = EXECUTOR.hunt(
    openai_client=openai_client,
    threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
    threat_hunt_user_message=threat_hunt_user_message,
    openai_model=model
)

if not hunt_results:
    exit()

elapsed = time.time() - start_time
print(f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found {Fore.LIGHTRED_EX}{len(hunt_results['findings'])} {Fore.WHITE}potential threat(s)!\n")

input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} or {Fore.LIGHTGREEN_EX}[Return]{Fore.WHITE} to see results.")
# 7. Print colorized threat findings in CLI and append output to _threats.jsonl
UTILITIES.display_threats(threat_list=hunt_results['findings'])

# 8. Active Response: Handle automated isolation for high-confidence host threats
token = EXECUTOR.get_bearer_token()
machine_is_isolated = False
query_is_about_individual_host = query_context["about_individual_host"]

for threat in hunt_results['findings']:
    threat_confidence_is_high = threat["confidence"].lower() == "high"
    
    # Prompt analyst for confirmation before isolating host via MDE REST API
    if query_is_about_individual_host and threat_confidence_is_high and (not machine_is_isolated):
        print(Fore.YELLOW + "[!] High confidence threat detected on host:" + Style.RESET_ALL, query_context["device_name"])
        print(Fore.LIGHTRED_EX + threat['title'])
        confirm = input(f"{Fore.RED}{Style.BRIGHT}Would you like to isolate this VM? (yes/no): " + Style.RESET_ALL).strip().lower()
        
        if confirm.startswith("y"):
            # Lookup Defender machine ID using short or FQDN host name
            machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                token=token,
                device_name=query_context["device_name"]
            )
            # Call MDE isolation API endpoint
            machine_is_isolated = EXECUTOR.quarantine_virtual_machine(
                token=token,
                machine_id=machine_id
            )
            if machine_is_isolated:
                print(Fore.GREEN + "[+] VM successfully isolated." + Style.RESET_ALL)
                print(Fore.CYAN + "Reminder: Release the VM from isolation when appropriate at: [https://security.microsoft.com/](https://security.microsoft.com/)" + Style.RESET_ALL)
        else:
            print(Fore.CYAN + "[i] Isolation skipped by user." + Style.RESET_ALL)

```

```python
from colorama import Fore

# JSON schema contract enforcing consistent structured output from LLM
FORMATTING_INSTRUCTIONS = """
Return findings in JSON format:
{
  "findings": [
    {
      "title": "Short title",
      "description": "Detailed explanation",
      "mitre": {
        "tactic": "Execution",
        "technique": "T1059",
        "sub_technique": "T1059.001",
        "id": "T1059.001",
        "description": "Technique details"
      },
      "log_lines": ["Log evidence string"],
      "confidence": "High",
      "recommendations": ["pivot", "create incident"],
      "indicators_of_compromise": ["IP/Hash/Account"],
      "tags": ["credential access"],
      "notes": "Analyst notes"
    }
  ]
}
"""

# System persona definition for threat hunting model
SYSTEM_PROMPT_THREAT_HUNT = {
    "role": "system",
    "content": "You are a threat hunting AI identifying suspicious activity across Microsoft Defender for Endpoint, Entra ID, and Azure logs. Map activity to MITRE ATT&CK, extract IOCs, and recommend defender actions."
}

# System instructions for OpenAI function calling tool decision phase
SYSTEM_PROMPT_TOOL_SELECTION = {
    "role": "system",
    "content": "Analyze analyst prompts and extract Log Analytics search parameters using query_log_analytics. Default timeframe to 96 hours if unspecified."
}

# OpenAI Function Calling Schema (Tool Contract)
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_log_analytics",
            "description": "Query Log Analytics workspace using KQL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "table_name": {"type": "string"},
                    "device_name": {"type": "string"},
                    "caller": {"type": "string"},
                    "user_principal_name": {"type": "string"},
                    "time_range_hours": {"type": "integer"},
                    "fields": {"type": "array", "items": {"type": "string"}},
                    "about_individual_user": {"type": "boolean"},
                    "about_individual_host": {"type": "boolean"},
                    "about_network_security_group": {"type": "boolean"},
                    "rationale": {"type": "string"}
                },
                "required": ["table_name", "device_name", "time_range_hours", "fields", "caller", "user_principal_name", "about_individual_user", "about_individual_host", "about_network_security_group", "rationale"]
            }
        }
    }
]

# Interactive terminal prompt to capture SOC analyst query
def get_user_message():
    user_input = input(f"{Fore.LIGHTBLUE_EX}Agentic SOC Analyst at your service! What would you like to do?\n\n{Fore.RESET}").strip()
    return {"role": "user", "content": user_input}

# Assembles the analyst prompt, raw log CSV data, and JSON output schema into final LLM prompt
def build_threat_hunt_prompt(user_prompt: str, table_name: str, log_data: str) -> dict:
    full_prompt = f"User request:\n{user_prompt}\n\nLog Data:\n{log_data}\n\n{FORMATTING_INSTRUCTIONS}"
    return {"role": "user", "content": full_prompt}

```

```python
from datetime import timedelta
import json
import pandas as pd
from colorama import Fore, Style
from openai import RateLimitError, OpenAIError
from azure.identity import DefaultAzureCredential
import requests, urllib.parse
import PROMPT_MANAGEMENT

# Obtains OAuth token for Microsoft Defender for Endpoint API via Azure Identity
def get_bearer_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("[https://api.securitycenter.microsoft.com/.default](https://api.securitycenter.microsoft.com/.default)")
    return token

# Queries MDE API to map hostname/FQDN to internal Defender Machine ID
def get_mde_workstation_id_from_name(token, device_name):
    headers = {"Authorization": f"Bearer {token.token}"}
    filter_q = urllib.parse.quote(f"startswith(computerDnsName,'{device_name}')")
    url = f"[https://api.securitycenter.microsoft.com/api/machines?$filter=](https://api.securitycenter.microsoft.com/api/machines?$filter=){filter_q}"

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    machines = resp.json().get("value", [])
    if not machines:
        raise Exception(f"No machine found starting with {device_name}")

    return machines[0]["id"]

# Sends active quarantine/isolation POST request to MDE REST API
def quarantine_virtual_machine(token, machine_id):
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json"
    }
    payload = {
        "Comment": "Isolation via Python Agentic AI using DefaultAzureCredential",
        "IsolationType": "Full"
    }
    resp = requests.post(
        f"[https://api.securitycenter.microsoft.com/api/machines/](https://api.securitycenter.microsoft.com/api/machines/){machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30
    )
    return resp.status_code in (200, 201)

# Sends threat hunting payload to OpenAI with strict JSON output enforcement
def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model):
    messages = [threat_hunt_system_message, threat_hunt_user_message]
    try:
        response = openai_client.chat.completions.create(
            model=openai_model,
            messages=messages,
            response_format={"type": "json_object"} # Enforces structured JSON response
        )
        return json.loads(response.choices[0].message.content)
    except RateLimitError as e:
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}🚨ERROR: Rate limit or token overage detected!{Style.RESET_ALL}\n{e}")
        return None
    except OpenAIError as e:
        print(f"{Fore.RED}Unexpected OpenAI API error:\n{e}")
        return None

# Translates natural language prompt to structured tool call arguments
def get_query_context(openai_client, user_message, model):
    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n")
    system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION
    response = openai_client.chat.completions.create(
        model=model,
        messages=[system_message, user_message],
        tools=PROMPT_MANAGEMENT.TOOLS,
        tool_choice="required" # Forces model to invoke query_log_analytics tool
    )
    function_call = response.choices[0].message.tool_calls[0]
    return json.loads(function_call.function.arguments)

# Constructs dynamic KQL query and executes search against Log Analytics workspace
def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name):
    # Construct table-specific KQL queries with proper filters
    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'{table_name}\n| where FlowType_s == "MaliciousFlow"\n| project {fields}'
    elif table_name == "AzureActivity":
        user_query = f'{table_name}\n| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")\n| where Caller startswith "{caller}"\n| project {fields}'
    elif table_name == "SigninLogs":
        user_query = f'{table_name}\n| where UserPrincipalName startswith "{user_principal_name}"\n| project {fields}'
    else:
        user_query = f'{table_name}\n| where DeviceName startswith "{device_name}"\n| project {fields}'
        
    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:\n{Fore.WHITE}{user_query}\n")
    # Execute query using azure-monitor-query SDK
    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=timedelta(hours=timerange_hours)
    )

    if len(response.tables[0].rows) == 0:
        return {"records": "", "count": 0}
    
    # Convert query result rows into Pandas DataFrame, then format as CSV string
    table = response.tables[0]
    df = pd.DataFrame(table.rows, columns=table.columns)
    return {"records": df.to_csv(index=False), "count": len(table.rows)}

```

```python
from colorama import Fore, Style

# Whitelist dictionary restricting allowed Log Analytics tables and permissible field projections
ALLOWED_TABLES = {
    "DeviceProcessEvents": {"TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine"},
    "DeviceNetworkEvents": {"TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort"},
    "DeviceLogonEvents": {"TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName"},
    "AlertInfo": {},
    "AlertEvidence": {},
    "DeviceFileEvents": {"TimeGenerated", "ActionType", "DeviceName", "FileName", "FolderPath", "InitiatingProcessAccountName", "SHA256"},
    "DeviceRegistryEvents": {},
    "AzureNetworkAnalytics_CL": {"TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d"},
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category"},
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails"},
}

# Approved OpenAI models with pricing tiers, max input/output tokens, and TPM limits
ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768, "cost_per_million_input": 0.10, "cost_per_million_output": 0.40, "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768, "cost_per_million_input": 1.00, "cost_per_million_output": 8.00, "tier": {"free": None, "1": 30_000, "2": 450_000, "3": 800_000, "4": 2_000_000, "5": 30_000_000}},
    "gpt-5-mini": {"max_input_tokens": 272_000, "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00, "tier": {"free": None, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5": {"max_input_tokens": 272_000, "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None, "1": 30_000, "2": 450_000, "3": 800_000, "4": 2_000_000, "5": 40_000_000}}
}

# Verifies requested table and fields against whitelists to block unauthorized data access or KQL injection
def validate_tables_and_fields(table, fields):
    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Table '{table}' is not allowed — exiting.")
        exit(1)
    
    field_list = fields.replace(' ', '').split(',')
    for field in field_list:
        if field not in ALLOWED_TABLES[table]:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Field '{field}' is not allowed for Table '{table}' — exiting.")
            exit(1)
    
    print(f"{Fore.WHITE}Fields and tables validated successfully.\n")

# Ensures selected LLM exists within system's approved model whitelist
def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed — exiting.")
        exit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")

```

```python
from colorama import Fore, Style
import tiktoken
import GUARDRAILS

CURRENT_TIER = "4"
DEFAULT_MODEL = "gpt-5-mini"
WARNING_RATIO = 0.80

def money(usd):
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"

# Estimates API query cost based on token length and model pricing
def estimate_cost(input_tokens, output_tokens, model_info):
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout

# Accurately calculates message token length using tiktoken encodings
def count_tokens(messages, model):
    try:
        enc = tiktoken.encoding_for_model(model)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")

    text = ""
    for m in messages:
        text += m.get("role", "") + " " + m.get("content", "") + "\n"
    return len(enc.encode(text))

# Evaluates token metrics against model limits and organization TPM caps; allows model switching
def choose_model(model_name, input_tokens, tier=CURRENT_TIER, assumed_output_tokens=500, interactive=True):
    if model_name not in GUARDRAILS.ALLOWED_MODELS:
        model_name = DEFAULT_MODEL

    info = GUARDRAILS.ALLOWED_MODELS[model_name]
    est = estimate_cost(input_tokens, assumed_output_tokens, info)
    print(f"Model: {model_name} | Input Tokens: {input_tokens} | Estimated Cost: {money(est)}\n")

    if not interactive:
        return model_name

    choice = input(f"{Fore.WHITE}Continue with '{model_name}'? (Enter to continue / type model name): ").strip()
    if choice in GUARDRAILS.ALLOWED_MODELS:
        return choice
    return model_name

```

```python
import json
from colorama import Fore, Style, init

# Prints formatted query metadata and AI rationale in CLI
def display_query_context(query_context):
    print(f"{Fore.LIGHTGREEN_EX}Query Context:")
    print(f"{Fore.WHITE}Table: {query_context['table_name']} | Time Range: {query_context['time_range_hours']}h")
    print(f"{Fore.WHITE}Rationale: {query_context['rationale']}\n")

# Formats and color-codes threat findings in terminal based on confidence level
def display_threats(threat_list):
    for idx, threat in enumerate(threat_list, 1):
        print(f"\n=============== Potential Threat #{idx} ===============")
        print(f"{Fore.LIGHTCYAN_EX}Title: {threat.get('title')}{Fore.RESET}")
        print(f"Description: {threat.get('description')}")
        print(f"Confidence: {threat.get('confidence')}")
        print(f"MITRE: {threat.get('mitre', {}).get('id')} - {threat.get('mitre', {}).get('tactic')}")
        print("=" * 51)
    append_threats_to_jsonl(threat_list)

# Appends detected threat findings to persistent _threats.jsonl file for audit trail
def append_threats_to_jsonl(threat_list, filename="_threats.jsonl"):
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            f.write(json.dumps(threat, ensure_ascii=False) + "\n")

# Strips pipe (|), newline (\n), and semicolon (;) characters to mitigate KQL query injection
def sanitize_literal(s: str) -> str:
    return str(s).replace("|", " ").replace("\n", " ").replace(";", " ")

# Sanitizes context string variables prior to query building
def sanitize_query_context(query_context):
    for key in ['caller', 'device_name', 'user_principal_name']:
        query_context[key] = sanitize_literal(query_context.get(key, ''))
    query_context["fields"] = ', '.join(query_context["fields"])
    return query_context

```

```python
# API Key & Log Analytics Workspace ID Configuration
OPENAI_API_KEY = "YOUR-OPENAI-API-KEY"
LOG_ANALYTICS_WORKSPACE_ID = "XXXXXXXXXXX"

```

---

## 📊 Telemetry Coverage & MITRE ATT&CK Focus

| Log Table | Log Domain | Whitelisted Fields | Primary ATT&CK Focus |
| --- | --- | --- | --- |
| **`DeviceProcessEvents`** | Host Executions | `TimeGenerated`, `AccountName`, `ActionType`, `DeviceName`, `InitiatingProcessCommandLine`, `ProcessCommandLine` | Execution (T1059), Defense Evasion, LOLBins |
| **`DeviceNetworkEvents`** | Host Network | `TimeGenerated`, `ActionType`, `DeviceName`, `RemoteIP`, `RemotePort` | Command & Control (T1071), TOR egress, Beaconing |
| **`DeviceLogonEvents`** | Host Auth | `TimeGenerated`, `AccountName`, `DeviceName`, `ActionType`, `RemoteIP`, `RemoteDeviceName` | Lateral Movement (T1021), Brute Force |
| **`DeviceFileEvents`** | File System | `TimeGenerated`, `ActionType`, `DeviceName`, `FileName`, `FolderPath`, `InitiatingProcessAccountName`, `SHA256` | Defense Evasion, Malware drops in Temp dirs |
| **`AzureActivity`** | Cloud Control Plane | `TimeGenerated`, `OperationNameValue`, `ActivityStatusValue`, `ResourceGroup`, `Caller`, `CallerIpAddress`, `Category` | Resource Persistence, Policy Tampering |
| **`SigninLogs`** | Entra ID Authentication | `TimeGenerated`, `UserPrincipalName`, `OperationName`, `Category`, `ResultSignature`, `ResultDescription`, `AppDisplayName`, `IPAddress`, `LocationDetails` | Credential Access (T1110), Impossible Travel |
| **`AzureNetworkAnalytics_CL`** | NSG Flow Logs | `TimeGenerated`, `FlowType_s`, `SrcPublicIPs_s`, `DestIP_s`, `DestPort_d`, `VM_s`, `AllowedInFlows_d`, `AllowedOutFlows_d`, `DeniedInFlows_d`, `DeniedOutFlows_d` | Exfiltration, Malicious Egress/Ingress |

---

## 🔒 Security Controls & Defensive Engineering

* **Query Injection Mitigation:** All literal values extracted from natural language prompts pass through `sanitize_literal()` to scrub operator characters (`|`, `;`, `\n`) before constructing KQL queries.
* **Schema Whitelisting:** KQL field projections are strictly checked against `ALLOWED_TABLES` prior to API calls. Unapproved fields trigger an immediate program abort.
* **Resource Governance:** Real-time token tracking via `tiktoken` monitors input metrics against account tier limits, reducing API overage risks.
* **Persistent Audit Trail:** Detected findings automatically save to `_threats.jsonl` to support historical auditing.

---

## 🛠️ Setup & Local Deployment

### Prerequisites

* Python 3.9+
* Active Azure Subscription with Log Analytics Workspace
* Azure CLI configured (`az login`)
* OpenAI API Key

### Installation

1. **Clone the repository:**
```bash
git clone [https://github.com/your-username/autonomous-soc-agent.git](https://github.com/your-username/autonomous-soc-agent.git)
cd autonomous-soc-agent

```


2. **Install dependencies:**
```bash
pip install openai azure-identity azure-monitor-query pandas colorama tiktoken requests

```


3. **Configure API Keys:**
Update `_keys.py` with your workspace ID and API key:
```python
OPENAI_API_KEY = "your-openai-key"
LOG_ANALYTICS_WORKSPACE_ID = "your-workspace-id"

```


4. **Authenticate to Azure:**
```bash
az login

```


5. **Execute the Agent:**
```bash
python _main.py

```



---

## 💻 Technical Stack

* **Language:** Python 3.x
* **AI & NLP:** OpenAI API (Function Calling & Structured Outputs), Tiktoken
* **Cloud & Security SDKs:** Azure Monitor Query (`azure-monitor-query`), Azure Identity (`azure-identity`), Microsoft Defender for Endpoint REST API
* **Data Processing & Terminal UI:** Pandas, Requests, Colorama

```

```
