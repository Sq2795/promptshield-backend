from fastapi import FastAPI, Request
from pydantic import BaseModel
import re

app = FastAPI()

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
    if re.search(r"(api[_-]?key|token|password|secret)", prompt):
        issues.append("Sensitive info found: possible API key or password")
    if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", prompt):
        issues.append("Email address detected — could be a data leak")

    # Determine risk score
    if len(issues) >= 3:
        score = "High"
    elif len(issues) == 2:
        score = "Medium"

    return {
        "risk_score": score,
        "issues_found": issues,
        "recommendations": [
            "Avoid using open-ended instructions like 'ignore previous instructions'",
            "Never include secrets (tokens, passwords, emails) in prompts",
            "Use strict role-based prompts and validate all user inputs"
        ]
    }