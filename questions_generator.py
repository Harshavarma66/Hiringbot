import requests
import re

API_KEY = "AIzaSyDmPtIbJg2dJcwD2jcgjt4UsXZjl-H__IA "
api_url = f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key={API_KEY}"

def clean_response(text):
    match = re.search(r"Question:\s*(.*)", text, re.IGNORECASE | re.DOTALL)
    question_body = match.group(1).strip() if match else text.strip()

    for stop_word in ["Answer:", "Explanation:", "answer:", "explanation:"]:
        if stop_word in question_body:
            question_body = question_body.split(stop_word)[0].strip()

    return question_body

def generate_questions(tech_list,role,years):
    questions = {}

    for tech in tech_list:
        tech_questions = []

        for i in range(1, 4):
            prompt = f"Generate technical interview codeing question #{i} about {tech} on {role} for the {years} of experience. Only give the one question, no explanation."

            payload = {
                "contents": [
                    {
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ]
            }

            try:
                response = requests.post(api_url, json=payload)
                if response.status_code == 200:
                    output = response.json()
                    candidates = output.get("candidates", [])
                    if candidates:
                        raw_text = candidates[0]["content"]["parts"][0]["text"]
                    else:
                        raw_text = "No candidates returned."

                    # cleaned = clean_response(raw_text)
                    formatted_question = f"Question {i}\n{raw_text}"
                    tech_questions.append(formatted_question)
                else:
                    tech_questions.append(f"Question {i}\nError: {response.status_code} - {response.text}")
            except Exception as e:
                tech_questions.append(f"Question {i}\nException occurred: {e}")

        questions[tech] = tech_questions

    return questions
