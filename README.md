# ICS_Attack_Analysis_using_LLMs_with_RAG

The aim of this project is to use various Retrieval Augmented Generation (RAG) Techniques with Large Language Models to process the intent behind ICS attack procedure descriptions.

## Installation
Install the following packages:
```python
pip install -q openai==0.27.6
pip install -q langchain
pip install -q pydantic==1.10.12
pip install -q tiktoken
pip install -q lark
pip install -q faiss-cpu
```

## Usage

In the Data folder, there are three files. The "ICS_Procedures_main.csv" is the main dataset that is crawled from MITRE ATT&CK framework, the "ICS_Procedures_main_encoded.csv" is the encoded version of the dataset for evaluation, and the "procedures_similarity_main.csv" is the file containing the top-2 most similar procedures along with their tactics.


The "prompt_only.py" file is the process of directly accessing the OpenAI GPT models with prompt engineering. 

The "RAG.py" file contains three different RAG techniques:
1) all_urls: This is to load all the ICS URLs from MITRE ATT&CK for retrieval.
2) reference_url: This is to load the reference URL of each specific procedure description (the reference URL is in the ICS_Procedures_main.csv dataset).
3) similar_procedure_urls: This is to retrieve URLs that correspond to the top-2 'target' procedure descriptions, which are most similar to the 'source' procedure specified in the query.

## How to Run

1) Create a "config.ini" file and put your OpenAI API key in the following format:
```python
[API]
OpenAI_Key = <YOUR_API_KEY>
```
2) Run the "main.py" file with the following line:
```python
python main.py --mode [prompt_only, reference_url, similar_procedure_urls, all_urls] --llm [LLM]
```
Choose one of the four modes in --mode (e.g., --mode all_urls) and specify the desired Large Language Model in --llm (e.g., --llm gpt-3.5-turbo-1106). After running this file, the predictions are gonna be stored in the Results folder.


3) Run the "postprocess.py" file to extract the tactics' keywords from the LLM's response with the following line:
```python
python postprocess.py --file_path PATH
```
Specify the csv file path in --file_path created from the "main.py" file (e.g., --file_path ./Results/preds_gpt-3.5-turbo-1106_all_urls.csv). After running this file, the encoded predictions are gonna be stored in the Results folder.

4) For evalution, run "evaluation.py" file by specifying the encoded prediction file with the following line:
```python
python evaluation.py --encoded_file_path PATH
```
Specify the csv file path in --encoded_file_path created from the "postprocess.py" file (e.g., --encoded_file_path ./Results/preds_gpt-3.5-turbo-1106_all_urls_encoded.csv)


