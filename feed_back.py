import requests
import re

API_KEY = "AIzaSyDmPtIbJg2dJcwD2jcgjt4UsXZjl-H__IA"
api_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={API_KEY}"





def extract_score(feedback_text):
    match = re.search(r"(\d{1,2})\s*/\s*30", feedback_text)
    if match:
        return int(match.group(1))
    return None  # or 0, depending on your default behavior


def get_feedback(question, answer):
    prompt = (
        f"The following is a technical interview question and a user's answer. "
        f"Please evaluate the answer and provide constructive feedback  and assign the average score for the entire performance out of 10 and i need to give overall score for each techstack means for each technology i need to give the seperate score that is the average of the individual scores of the same cluster.\n\n"
        f"Question: {question}\nAnswer: {answer}\n\nFeedback:"
    )

    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ]
    }

    try:
        response = requests.post(api_url, json=payload)

        if response.status_code == 200:
            output = response.json()
            candidates = output.get("candidates", [])
            if candidates and "content" in candidates[0]:
                parts = candidates[0]["content"].get("parts", [])
                
                if parts:
                    feedback_text = parts[0]["text"].strip()
                    score = extract_score(feedback_text)
                    return feedback_text, score
                else:
                    return "⚠️ No feedback generated.", None
                
                
                # return parts[0]["text"].strip() if parts else "⚠️ No feedback generated."
            else:
                return "⚠️ Unexpected response format."

        else:
            return f"⚠️ Error {response.status_code}: {response.text}"

    except Exception as e:
        return f"❌ Exception: {e}"

