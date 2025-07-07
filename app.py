import streamlit as st
from prompt import intro_prompt
from questions_generator import generate_questions
from feed_back import get_feedback
from database import init_db, user_exists, save_user
from table_fields import create_leaderboard_table, insert_score, get_leaderboard
from datetime import datetime
from collections import defaultdict
timestamp = datetime.now()

# Initialize DB and leaderboard table
init_db()
create_leaderboard_table()
st.set_page_config(page_title="Welcome to AI Hiring Assistant", layout="centered")

# Initialize session state keys if not present
if 'stage' not in st.session_state:
    st.session_state.stage = 'intro'
if 'candidate_info' not in st.session_state:
    st.session_state.candidate_info = {}
if 'tech_stack' not in st.session_state:
    st.session_state.tech_stack = []
if 'questions' not in st.session_state:
    st.session_state.questions = {}
if 'answers' not in st.session_state:
    st.session_state.answers = {}
if 'feedback' not in st.session_state:
    st.session_state.feedback = {}
if 'role' not in st.session_state:
    st.session_state.role = ""
if 'years_experience' not in st.session_state:
    st.session_state.years_experience = 0  
if 'avg_score' not in st.session_state:
    st.session_state.avg_score = 0


# --------------- INTRODUCTION ----------------
if st.session_state.stage == 'intro':
    st.image(
        "https://cdn5.vectorstock.com/i/1000x1000/49/59/robot-or-chatbot-logo-template-chat-bot-icon-vector-35064959.jpg",
        width=70
    )
    st.info(intro_prompt())
    if st.button("Start"):
        st.session_state.stage = 'info'
        st.rerun()

# --------------- CANDIDATE INFO ----------------
elif st.session_state.stage == 'info':    
    st.header("Hiring Assistant chatbot")
    st.subheader("Please fill the following information")
    name = st.text_input("Name")
    email = st.text_input("Email")
    phone = st.text_input("Phone Number")
    # experience = st.text_input("Years of Experience")
    # position = st.text_input("Desired Position")
    location = st.text_input("Current Location")
    
    col1,space,col2=st.columns([1,8,1])
    with col1:
        if st.button("Prev",key="prev_button"):
            st.session_state.stage='intro'
            st.rerun()      
    with col2:
        if st.button("Next", key="next_button"):
            st.session_state.candidate_info = {
                "Name": name, "Email": email, "Phone": phone,
                "Location": location
            }
            if user_exists(email):
                st.warning("User already exists. Please continue or update your email.")
                st.session_state.stage='intro'
                st.rerun()
            else:
                # st.session_state.y=(user_exists(email))
                save_user(st.session_state.candidate_info)
                st.session_state.stage = 'tech_stack'
                st.rerun()
                
if st.session_state.stage == 'tech_stack':
    st.subheader("Skill Set & Role Information")
    # st.markdown(st.session_state.y)
    name = st.session_state.candidate_info.get("Name", "Candidate")
    st.write(f"Hi {name}, please provide your details.")
    # New: Role input
    st.session_state.role = st.text_input("Your Role:", value=st.session_state.role, key="role_input")

    # New: Years of Experience input
    st.session_state.years_experience = st.number_input(
        "Years of Experience:",
        min_value=0,
        max_value=50,
        value=st.session_state.years_experience,
        step=1,
        key="years_experience_input"
    )
    # Existing: Tech stack input
    tech_stack_str = st.text_input(
        f"List your skills (comma-separated, e.g., Python, Java, AWS):",
        value=",".join(st.session_state.tech_stack),
        key="tech_stack_input"
    )

    col1, _, col2 = st.columns([1, 5, 1])
    with col1:
        if st.button("Generate", key="generate_skills_button"):
            techs = [tech.strip() for tech in tech_stack_str.split(",") if tech.strip()]
            if not techs:
                st.error("⚠️ Please enter at least one skill.")
            elif not st.session_state.role.strip():
                st.error("⚠️ Please enter your role.")
            else:
                # Store the parsed skills
                st.session_state.tech_stack = list(set(techs)) # Use list(set()) to remove duplicates
                
                # Call generate_questions with the new parameters
                st.session_state.questions = generate_questions(
                    st.session_state.tech_stack,
                    st.session_state.role,
                    st.session_state.years_experience
                )
                st.session_state.stage = 'questions'
                st.rerun()           
    with col2:
        if st.button("Prev"):
            st.session_state.stage='info'
            st.rerun()

# --- Combined Questions and Answer Collection Stage ---
elif st.session_state.stage == 'questions':
    st.subheader("Technical Interview Questions")
    st.write(f"Based on your role as **{st.session_state.role}** with **{st.session_state.years_experience} years** of experience and skills: **{', '.join(st.session_state.tech_stack)}**, here are your questions:")
    if not st.session_state.questions:
        st.info("No questions were generated. Please go back and try again.")
    else:
        # Display questions and inputs for answers
        for tech, question_list in st.session_state.questions.items():
            st.markdown(f"### Questions on {tech}")
            for idx, question in enumerate(question_list, start=1):
                # Ensure the key is unique and consistent
                key = f"{tech}_q{idx}" 
                st.markdown(f"**Question {idx}:** {question}")
                
                # Fetch existing answer for persistence
                current_answer = st.session_state.answers.get(key, {}).get('answer', '')
                answer = st.text_area("Your Answer:", value=current_answer, key=key)
                
                # Store the answer in session state
                st.session_state.answers[key] = {
                    'question': question,
                    'tech': tech,
                    'answer': answer
                }

                # Display feedback if available
                if st.session_state.feedback.get(key):
                    st.info(f"**Feedback:** {st.session_state.feedback[key]}")
                st.markdown("---") # Separator

        # Submit answers button
        if st.button("Submit Answers", key="submit_answers"):
            st.session_state.feedback = {}  # reset feedback dict before recalculating
            total_score = 0
            count = 0
            for key, data in st.session_state.answers.items():
                question = data['question']
                answer = data['answer']
                if answer.strip():
                    fb_text, score = get_feedback(question, answer)
                else:
                    fb_text, score = "⚠️ No answer provided.", 0
                st.session_state.feedback[key] = fb_text
                if score is not None: # Ensure score is a number
                    total_score += score
                    count += 1  
            st.session_state.avg_score = round(total_score / count) if count else 0
            st.success(f"Answers submitted! Your average score: **{st.session_state.avg_score}**")
            st.rerun() # Rerun to display feedback next to answers immediately
            
    # Navigation buttons
    col_nav1, col_nav2 = st.columns(2)
    with col_nav2:
        if st.session_state.avg_score > 0: # Only show next stage button if feedback was generated
            st.button("View Overall Summary", key="view_summary") # Placeholder for next stage

    # Show feedback if available
    if st.session_state.feedback:
        st.subheader("Feedback for your Performance:")
        for key, fb in st.session_state.feedback.items():
            q_data = st.session_state.answers[key]
            st.markdown(f"**{q_data['tech']} - Question:** {q_data['question']}")
            st.markdown(f"**Your Answer:** {q_data['answer']}")
            st.markdown(f"**Feedback:** {fb}")
            st.markdown("====="*20)

    # End chat button: save score and show leaderboard
    if st.button("End Chat", key="end_chat"):
        total_questions = len(st.session_state.answers)
        if total_questions == 0:
            st.warning("Please answer the questions before ending the chat.")
        else:
            correct = sum("correct" in fb for fb in st.session_state.feedback.values())
            score = int((correct / total_questions) * 100)
            st.markdown(score)
            name = st.session_state.candidate_info.get("Name", "Unknown")
            email = st.session_state.candidate_info.get("Email", "")

# Group scores by tech
            tech_scores = defaultdict(list)
            for key, fb in st.session_state.feedback.items():
                tech = st.session_state.answers[key]['tech']
                score = 0
                if "correct" in fb:
                    score = 1  # assuming binary correct/incorrect scoring
                tech_scores[tech].append(score)
                
# Calculate and insert average score per tech
            for tech, scores in tech_scores.items():
                avg_score = round((sum(scores) / len(scores)) * 100)
                insert_score(name, email, avg_score, tech, timestamp)
            st.session_state.feedback = {}
            st.session_state.stage = 'leaderboard'
            st.rerun()

# --------------- LEADERBOARD ----------------
elif st.session_state.stage == 'leaderboard':
    st.subheader("🏆 Leaderboard")
    leaderboard = get_leaderboard()

    if leaderboard:
        for idx, (n, email, tech, sc, ts) in enumerate(leaderboard, start=1):
            st.write(f"{idx}. **{n}** ({email}) | {tech} | Score: {sc} | _{ts}_")
    else:
        st.write("No leaderboard data available.")

    if st.button("Back to Home", key="leaderboard_back"):
        st.session_state.stage = 'intro'
        st.rerun()










