import os
import time
import google.generativeai as genai
from datetime import datetime
import json
from typing import Dict, Any
from dotenv import load_dotenv

# Global rate limiting variables
LAST_API_CALL_TIME = 0
MIN_CALL_INTERVAL = 10  # seconds between API calls

def configure_gemini():
    """Configure Gemini API using environment variable"""
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in .env file")
    genai.configure(api_key=api_key)

def generate_risk_summary(domain: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate security risk summary using Gemini AI with rate limiting"""
    global LAST_API_CALL_TIME
    
    try:
        configure_gemini()
        
        # Enforce rate limiting
        current_time = time.time()
        time_since_last_call = current_time - LAST_API_CALL_TIME
        
        if time_since_last_call < MIN_CALL_INTERVAL:
            wait_time = MIN_CALL_INTERVAL - time_since_last_call
            print(f"⏳ Rate limiting: Waiting {wait_time:.1f} seconds before next API call...")
            time.sleep(wait_time)
        
        # Initialize the model with lightweight options
        model = genai.GenerativeModel('gemini-1.5-flash')  # Using lighter model
        
        # Create a condensed version of scan data to reduce token usage
        condensed_data = {
            "domain": domain,
            "live_subdomains": len(scan_data.get("live", {}).get("live", [])),
            "vulnerabilities": scan_data.get("ssl", {}).get("vulnerabilities", []),
            "header_issues": scan_data.get("headers", {}).get("issues", []),
            "sensitive_paths": len(scan_data.get("paths", {}))
        }
        
        prompt = f"""
        As a cybersecurity expert, analyze this condensed security scan data for {domain}:
        {json.dumps(condensed_data, indent=2)}
        
        Provide a concise JSON response with:
        - summary: 1-2 sentence risk overview
        - severity: Critical/High/Medium/Low
        - top_recommendations: 2 most urgent actions
        
        Focus on the most critical findings only.
        """
        
        try:
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.2,
                    "max_output_tokens": 500  # Reduced token count
                }
            )
            
            LAST_API_CALL_TIME = time.time()  # Update last call time
            
            if not response.text:
                raise ValueError("Empty API response")
                
            # Extract JSON from response
            clean_text = response.text.strip()
            if '```json' in clean_text:
                clean_text = clean_text.split('```json')[1].split('```')[0].strip()
            elif '```' in clean_text:
                clean_text = clean_text.split('```')[1].strip()
                
            analysis = json.loads(clean_text)
            
            return {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "analysis": analysis,
                "scan_metadata": {
                    "ssl_analysis": bool(scan_data.get("ssl")),
                    "header_analysis": bool(scan_data.get("headers")),
                    "path_analysis": bool(scan_data.get("paths"))
                }
            }
            
        except Exception as api_error:
            print(f"⚠️ API Error: {str(api_error)}")
            return {
                "domain": domain,
                "error": str(api_error),
                "timestamp": datetime.now().isoformat(),
                "retry_after": 60  # Suggested retry time in seconds
            }
            
    except Exception as e:
        print(f"⚠️ System Error: {str(e)}")
        return {
            "domain": domain,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def save_ai_results(domain: str, data: Dict[str, Any]):
    """Save AI analysis results to JSON file with error handling"""
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{output_dir}/{domain}_ai_analysis.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"✅ Saved analysis for {domain}")
    except Exception as e:
        print(f"⚠️ Failed to save results for {domain}: {str(e)}")