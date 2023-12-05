#!pip install -q langchain
#!pip install -q Pydantic==1.10.12
#!pip install -q chromadb
#!pip install -q tiktoken
#!pip install -q lark
#!pip install faiss-cpu


import os
import sys
import openai
import time
import transformers
import pandas as pd
import nest_asyncio
from torch import cuda
from langchain.document_loaders.csv_loader import CSVLoader
from langchain.document_loaders import WebBaseLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter, CharacterTextSplitter, TokenTextSplitter, NLTKTextSplitter
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.vectorstores import Chroma, FAISS
from langchain.chains import RetrievalQA
from langchain.llms import HuggingFacePipeline
from langchain.prompts import PromptTemplate
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.chat_models import ChatOpenAI
from langchain.chains import RetrievalQA
import nest_asyncio
nest_asyncio.apply()
sys.path.append('../..')




class MITRE_ICS_Analysis:
    def __init__(self, api_key, data_source, mode='url'):
        openai.api_key = api_key
        if mode == 'all_urls':
            self.data = self.load_and_split_web_content()
        elif mode == 'exact_url':
            urls = data_source
            self.data = self.load_and_split_web_content(urls)
        elif mode == 'similar_procedure_urls':
            urls = data_source
            self.data = self.load_and_split_web_content(urls)
        else:
            raise ValueError("Invalid mode.")
        
        self.embeddings = OpenAIEmbeddings(openai_api_key=openai.api_key)
        self.vectordb = FAISS.from_documents(
            documents=self.data,
            embedding=self.embeddings,            
        )
        self.llm_name = "gpt-3.5-turbo-1106"
        self.llm = ChatOpenAI(model_name=self.llm_name, temperature=0, openai_api_key=openai.api_key, seed=1106)


        self.prompt_template = self.build_qa_chain_prompt()


    def perform_similarity_search(self, question, k=3):
        docs = self.vectordb.similarity_search(question, k=k)
        for doc in docs:
            print(doc.metadata)

    def build_qa_chain_prompt(self):
        template = """You are a cybersecurity analyst with the expertise in analyzing cyberattack procedures. Consider the relevant context provided below and answer the question.

Relevant Context: {context}

Question: {question}

Please write the response in the following format: ICS tactic(s)
        """
        return PromptTemplate.from_template(template)


    def perform_qa(self, question, prompt_template):
        qa_chain = RetrievalQA.from_chain_type(
            self.llm,
            retriever=self.vectordb.as_retriever(search_type="similarity", search_kwargs={"k":3}),
            return_source_documents=True,
            chain_type_kwargs={"prompt": prompt_template}
        )
        print(qa_chain)
        result = qa_chain({"query": question})
        print(result["result"],'\n')
        return result


    def load_questions_from_csv(self, csv_file):
        list_of_questions = []
        df = pd.read_csv(csv_file)
        for procedure in df['Description']:
            temp = f"Knowing this ICS attack procedure <<{procedure}>>, what MITRE ATT&CK ICS tactics will a cyber adversary achieve with this technique?"
            list_of_questions.append(temp)
        return list_of_questions


    def perform_qa_for_list(self, list_of_questions):
        predictions = []
        for question in list_of_questions:
            while True:
                try:
                    print(question)
                    result = self.perform_qa(question, self.prompt_template)
                    predictions.append(result)
                    break
                except (openai.error.RateLimitError, openai.error.APIError, openai.error.Timeout,
                        openai.error.OpenAIError, openai.error.ServiceUnavailableError):
                    time.sleep(5)
        return predictions

    def load_and_split_web_content_all(self):
        loader = WebBaseLoader(["https://attack.mitre.org/techniques/T0800",
                                "https://attack.mitre.org/techniques/T0830",
                                "https://attack.mitre.org/techniques/T0878",
                                "https://attack.mitre.org/techniques/T0802",
                                "https://attack.mitre.org/techniques/T0803",
                                "https://attack.mitre.org/techniques/T0804",
                                "https://attack.mitre.org/techniques/T0805",
                                "https://attack.mitre.org/techniques/T0806",
                                "https://attack.mitre.org/techniques/T0892",
                                "https://attack.mitre.org/techniques/T0858",
                                "https://attack.mitre.org/techniques/T0807",
                                "https://attack.mitre.org/techniques/T0885",
                                "https://attack.mitre.org/techniques/T0884",
                                "https://attack.mitre.org/techniques/T0879",
                                "https://attack.mitre.org/techniques/T0809",
                                "https://attack.mitre.org/techniques/T0811",
                                "https://attack.mitre.org/techniques/T0893",
                                "https://attack.mitre.org/techniques/T0812",
                                "https://attack.mitre.org/techniques/T0813",
                                "https://attack.mitre.org/techniques/T0814",
                                "https://attack.mitre.org/techniques/T0815",
                                "https://attack.mitre.org/techniques/T0868",
                                "https://attack.mitre.org/techniques/T0816",
                                "https://attack.mitre.org/techniques/T0817",
                                "https://attack.mitre.org/techniques/T0871",
                                "https://attack.mitre.org/techniques/T0819",
                                "https://attack.mitre.org/techniques/T0820",
                                "https://attack.mitre.org/techniques/T0890",
                                "https://attack.mitre.org/techniques/T0866",
                                "https://attack.mitre.org/techniques/T0822",
                                "https://attack.mitre.org/techniques/T0823",
                                "https://attack.mitre.org/techniques/T0891",
                                "https://attack.mitre.org/techniques/T0874",
                                "https://attack.mitre.org/techniques/T0877",
                                "https://attack.mitre.org/techniques/T0872",
                                "https://attack.mitre.org/techniques/T0883",
                                "https://attack.mitre.org/techniques/T0867",
                                "https://attack.mitre.org/techniques/T0826",
                                "https://attack.mitre.org/techniques/T0827",
                                "https://attack.mitre.org/techniques/T0828",
                                "https://attack.mitre.org/techniques/T0837",
                                "https://attack.mitre.org/techniques/T0880",
                                "https://attack.mitre.org/techniques/T0829",
                                "https://attack.mitre.org/techniques/T0835",
                                "https://attack.mitre.org/techniques/T0831",
                                "https://attack.mitre.org/techniques/T0832",
                                "https://attack.mitre.org/techniques/T0849",
                                "https://attack.mitre.org/techniques/T0838",
                                "https://attack.mitre.org/techniques/T0821",
                                "https://attack.mitre.org/techniques/T0836",
                                "https://attack.mitre.org/techniques/T0889",
                                "https://attack.mitre.org/techniques/T0839",
                                "https://attack.mitre.org/techniques/T0801",
                                "https://attack.mitre.org/techniques/T0834",
                                "https://attack.mitre.org/techniques/T0840",
                                "https://attack.mitre.org/techniques/T0842",
                                "https://attack.mitre.org/techniques/T0861",
                                "https://attack.mitre.org/techniques/T0843",
                                "https://attack.mitre.org/techniques/T0845",
                                "https://attack.mitre.org/techniques/T0873",
                                "https://attack.mitre.org/techniques/T0886",
                                "https://attack.mitre.org/techniques/T0846",
                                "https://attack.mitre.org/techniques/T0888",
                                "https://attack.mitre.org/techniques/T0847",
                                "https://attack.mitre.org/techniques/T0848",
                                "https://attack.mitre.org/techniques/T0851",
                                "https://attack.mitre.org/techniques/T0852",
                                "https://attack.mitre.org/techniques/T0853",
                                "https://attack.mitre.org/techniques/T0881",
                                "https://attack.mitre.org/techniques/T0865",
                                "https://attack.mitre.org/techniques/T0856",
                                "https://attack.mitre.org/techniques/T0869",
                                "https://attack.mitre.org/techniques/T0862",
                                "https://attack.mitre.org/techniques/T0857",
                                "https://attack.mitre.org/techniques/T0882",
                                "https://attack.mitre.org/techniques/T0864",
                                "https://attack.mitre.org/techniques/T0855",
                                "https://attack.mitre.org/techniques/T0863",
                                "https://attack.mitre.org/techniques/T0859",
                                "https://attack.mitre.org/techniques/T0860",
                                "https://attack.mitre.org/techniques/T0887",
                                ])
        loader.requests_per_second = 1
        docs = loader.aload()


        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size = 4000,
            separators=["\n\n", "\n", " ", ""]
        )
        splits = text_splitter.split_documents(docs)
        print(len(splits))
        return splits

if __name__ == "__main__":


    api_key  = "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"
    #x_dataset_file = "./Data/X-MITRE_Descriptions_only.csv"

    analysis = MITRE_ICS_Analysis(api_key, loader, mode='url')
   
    question = "Knowing that <<menuPass can use DLL search order hijacking>>, what MITRE ATT&CK tactics will a cyber adversary achieve with this technique?"
   
    analysis.perform_similarity_search(question, k=5)
    print('------------------')

    prompt_template = analysis.build_qa_chain_prompt()
    analysis.perform_qa(question, prompt_template)

    list_of_questions = analysis.load_questions_from_csv('./Data/Y-MITRE_Procedures.csv')
    predictions = analysis.perform_qa_for_list(list_of_questions)


    df = pd.DataFrame(predictions)    
    df.to_csv('./preds_gpt-3.5_with_all_urls_gpt-3.5-16k.csv', index=False)