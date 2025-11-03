import json
from google import genai
from google.genai import types

def Results_with_gemini(email):
    results = {
        "score": 0,
        "findings": []
    }
    
    gemini_results = AI_Analyser(email)
    results["score"] = gemini_results["score"]
    results["findings"] = gemini_results["findings"]
    
    return results


def AI_Analyser(email):
    results = {'score': 0, 'findings': []}
    
    # CHANGED: Old method was genai.configure() and GenerativeModel
    # New method uses genai.Client() for API initialization
    client = genai.Client(api_key="YOUR_GEMINI_API_KEY")
    
    # Get prompt
    formatted_prompt = create_prompt(email)
    
    # CHANGED: Old method was model.generate_content() with generation_config parameter
    # New method uses client.models.generate_content() with config parameter using types.GenerateContentConfig
    # FIXED: Model name should NOT include 'models/' prefix, use just the model name
    # CHANGED: Updated to gemini-2.0-flash-exp (newer model) or use gemini-1.5-flash for stable version
    response = client.models.generate_content(
        model='gemini-2.5-flash', 
        contents=formatted_prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
            top_p=0.95,
            top_k=40,
            max_output_tokens=1024
        )
    )
    
    # CHANGED: Old method accessed response directly
    # New method uses response.text to get the text output
    response_analysis = parse_gemini_response(response.text)
    
    if response_analysis['is_phishing'] == True:
        results['score'] += response_analysis['confidence_score']
        
        for indicator in response_analysis['phishing_indicators']:
            severity = map_indicator_to_severity(indicator['type'])
            results['findings'].append({
                'severity': severity,
                'message': 'AI Detection: ' + indicator['description'],
                'confidence': indicator['confidence']
            })
    
    if response_analysis['overall_risk_level'] == "HIGH":
        results['findings'].append({
            'severity': 'HIGH',
            'message': 'Gemini AI assessment: High phishing probability - ' + response_analysis['reasoning']
        })
    elif response_analysis['overall_risk_level'] == "MEDIUM":
        results['findings'].append({
            'severity': 'MEDIUM',
            'message': 'Gemini AI assessment: Possible phishing indicators detected'
        })
    
    return results


def create_prompt(email):
    prompt_template = """You are a cybersecurity expert analyzing an email for phishing indicators.

**EMAIL METADATA:**
- From: {from_address}
- Subject: {subject}
- Date: {date}

**EMAIL CONTENT:**
{content}

**ANALYSIS TASK:**
Analyze this email for phishing indicators and return your assessment in JSON format.

Look for these specific indicators:
1. **Deceptive language**: False urgency, threats, or pressure tactics
2. **Credential harvesting**: Requests for passwords, account verification, or personal info
3. **Impersonation**: Pretending to be a legitimate organization
4. **Generic greetings**: "Dear Customer" instead of personalized names
5. **Grammar/spelling**: Unusual errors or awkward phrasing
6. **Suspicious requests**: Unexpected money transfers, gift card purchases
7. **Emotional manipulation**: Fear, urgency, or too-good-to-be-true offers

**REQUIRED JSON OUTPUT FORMAT:**
{{
    "is_phishing": true/false,
    "confidence_score": 0-50 (points to add to risk score),
    "overall_risk_level": "LOW/MEDIUM/HIGH",
    "phishing_indicators": [
        {{
            "type": "urgency/credentials/impersonation/grammar/etc",
            "description": "Brief description of what you found",
            "confidence": "low/medium/high"
        }}
    ],
    "reasoning": "Brief explanation of your overall assessment",
    "legitimate_explanation": "If not phishing, why this might be legitimate"
}}

Be thorough but concise. Focus on concrete indicators, not speculation."""
    
    formatted_prompt = prompt_template.format(
        from_address=email['from_address'],
        subject=email['subject'],
        date=email['date'],
        content=email['content']
    )
    return formatted_prompt


def parse_gemini_response(response_text):
    cleaned_text = response_text.strip()
    
    # Remove markdown code blocks if present
    if cleaned_text.startswith("```json"):
        cleaned_text = cleaned_text.replace("```json", "").replace("```", "")
    elif cleaned_text.startswith("```"):
        cleaned_text = cleaned_text.replace("```", "")
    
    cleaned_text = cleaned_text.strip()
    
    try:
        analysis = json.loads(cleaned_text)
        
        # Validate required fields
        required_fields = ['is_phishing', 'confidence_score', 'overall_risk_level', 'phishing_indicators', 'reasoning']
        if not all(field in analysis for field in required_fields):
            raise ValueError("Missing required fields in Gemini response")
        
        return analysis
        
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Failed to parse Gemini JSON response: {e}")
        
        # Fallback: Extract basic assessment from text
        return {
            'is_phishing': any(keyword in response_text.lower() for keyword in ["phishing", "suspicious", "malicious"]),
            'confidence_score': 20,
            'overall_risk_level': 'MEDIUM',
            'phishing_indicators': [],
            'reasoning': response_text.split('.')[0] if '.' in response_text else response_text[:100]
        }


def map_indicator_to_severity(indicator_type):
    severity_map = {
        'credentials': 'CRITICAL',
        'impersonation': 'HIGH',
        'urgency': 'MEDIUM',
        'suspicious_links': 'HIGH',
        'grammar': 'LOW',
        'generic_greeting': 'LOW',
        'emotional_manipulation': 'MEDIUM',
        'financial_request': 'CRITICAL'
    }
    
    return severity_map.get(indicator_type, 'MEDIUM')


# Example usage with manual email data
if __name__ == "__main__":
    # You can manually create email data from any email you want to analyze
    email_data = {
        'from_address': 'support@paypa1.com',  # Example - manually copy from email
        'subject': 'Urgent: Verify your account now!',
        'date': '2025-11-01',
        'content': '''Dear Customer,
        
        Your account has been suspended due to unusual activity.
        Click here to verify your identity immediately: http://paypa1-verify.com
        
        If you don't verify within 24 hours, your account will be permanently closed.
        
        Thank you,
        PayPal Security Team'''
    }
    
    # Analyze the email
    results = Results_with_gemini(email_data)
    
    print("Analysis Results:")
    print(f"Risk Score: {results['score']}")
    print("\nFindings:")
    for finding in results['findings']:
        print(f"- [{finding['severity']}] {finding['message']}")
