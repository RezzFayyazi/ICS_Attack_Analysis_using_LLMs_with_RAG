import openai
import time
import pandas as pd
import random
import configparser
config = configparser.ConfigParser()
config.read('config.ini')

def get_completion(prompt, model="gpt-4-1106-preview"):
    api_key = config.get('API', 'OpenAI_Key')
    openai.api_key = api_key
    messages = [{"role": "system", 
                 "content":"You are a cybersecurity analyst with the expertise in analyzing cyberattack procedures."},
                {"role": "user", "content": prompt}]
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=0,
        seed=1106,
    )
    return response.choices[0].message["content"]

def load_questions_from_csv(csv_file):
    list_of_questions = []
    df = pd.read_csv(csv_file)
    for procedure in df['Description']:
        temp = f"Knowing this ICS attack procedure <<{procedure}>>, what MITRE ATT&CK ICS tactics will a cyber adversary achieve with this technique?"
        list_of_questions.append(temp)
    return list_of_questions


def prediction(list_of_questions):
    predictions = []
    counter = 0
    for question in list_of_questions:
        counter += 1
        print('Procedure:', counter)
        prompt = f"""{question}

        Please write the response in the following format: ICS tactic(s)
        """
        while True:
            try:

                print(question)
                result = get_completion(prompt)
                print(result,'\n')
                predictions.append(result)
                break
            except (openai.error.RateLimitError, openai.error.APIError, openai.error.Timeout,
                    openai.error.OpenAIError, openai.error.ServiceUnavailableError):
                delay = random.randint(2, 6)
                time.sleep(delay)
    return predictions

