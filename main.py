from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PromptInput(BaseModel):
    prompt: str

@app.post("/scan")
def scan_prompt(input_data: PromptInput):
    prompt = input_data.prompt.lower()
    issues = []
    score = "Low"

    # Check for common prompt injection patterns
    if re.search(r"ignore (all )?previous instructions", prompt):
        issues.append("Possible prompt injection: 'ignore previous instructions'")
    if re.search(r"disregard", prompt):
        issues.append("Potential override instruction: 'disregard'")
    if re.search(r"forget.*you were told", prompt):
        issues.append("Prompt manipulation: 'forget previous context'")

    # Check for sensitive data patterns
    if re.search(r"(api[_-]?key|token|password|secret|access[_-]?token|bearer|sk_live|sk_test|pk_live|pk_test)", prompt):
        issues.append("Sensitive keyword detected (e.g., token, API key, secret)")
    if re.search(r"[a-zA-Z0-9_]{20,}[_-]?(key|token|secret)", prompt):
        issues.append("Long string resembling a secret or token")
    if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", prompt):
        issues.append("Email address detected — could be a data leak")

        # Determine risk score (severity-based)
    high_risk = any(kw in issue.lower() for issue in issues for kw in ["api key", "token", "password", "secret", "injection", "override"])
    
    if high_risk:
        score = "High"
    elif len(issues) >= 2:
        score = "Medium"
    elif len(issues) == 1:
        score = "Low"
    else:
        score = "Low"

        ]
    }
