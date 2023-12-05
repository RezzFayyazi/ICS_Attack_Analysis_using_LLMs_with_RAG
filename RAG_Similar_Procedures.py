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
from torch import cuda
from langchain.document_loaders.csv_loader import CSVLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter, CharacterTextSplitter, TokenTextSplitter
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.vectorstores import Chroma, FAISS
from langchain.chains import RetrievalQA
from langchain.llms import HuggingFacePipeline
from langchain.prompts import PromptTemplate
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.chat_models import ChatOpenAI
from langchain.chains import RetrievalQA
sys.path.append('../..')




class MITREAnalysis:
    def __init__(self, api_key, dataset_file):
        openai.api_key = api_key
        self.loader = CSVLoader(dataset_file,source_column='Procedures',metadata_columns=['URL'] , encoding="ISO-8859-1")
        self.data = self.loader.load()
        self.embeddings = OpenAIEmbeddings(openai_api_key=openai.api_key)
        self.vectordb = FAISS.from_documents(
            documents=self.data,
            embedding=self.embeddings
        )
        
    def perform_procedure_retrieval(self, procedure, url, tactics, k=3):
        docs = self.vectordb.similarity_search(procedure, k=k)
        retr_procecdures = []
        retr_urls = []
        for doc in docs[1:]:
            print(doc.metadata)
            retr_procecdures.append(doc.metadata.get('source'))
            retr_urls.append(doc.metadata.get('URL'))
    
        procedure_data = {
            "Procedure": procedure,
            "Procedure URL": url, 
            "Retrieved Procedures": retr_procecdures, 
            "Retrieved Procedure URLs": retr_urls,
            "Tactic(s)": tactics,
            
        }
        return procedure_data


if __name__ == "__main__":


    api_key  = "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"
    #x_dataset_file = "./Data/X-MITRE_Descriptions_only.csv"
    #x_dataset_file = './Data/enterprise-attack_relationships.csv'
    y_dataset_file = "./Data/Y-MITRE_Procedures.csv"
    analysis = MITREAnalysis(api_key, y_dataset_file)
    all_procedures_df = pd.DataFrame(columns=["Procedure", "Procedure URL", "Retrieved Procedures", "Retrieved Procedure URLs", "Tactic(s)"])

    df = pd.read_csv('./Data/Y-MITRE_Procedures.csv')
    for procedure, url, tactic1, tactic2, tactic3, tactic4 in zip(df['Procedures'], df['URL'], df['Tactic1'], df['Tactic2']):
        procedure_data = analysis.perform_procedure_retrieval(procedure, url, [tactic1, tactic2, tactic3, tactic4])

        procedure_data_df = pd.DataFrame([procedure_data])

    # Concatenate the new DataFrame with the existing one
        all_procedures_df = pd.concat([all_procedures_df, procedure_data_df], ignore_index=True)
        
   
    #print('------------------')
    #analysis.perform_marginal_relevance_search(question)
    #print('------------------')
    #prompt_template = analysis.build_qa_chain_prompt()
    #analysis.perform_qa(question, prompt_template)
    #list_of_questions = analysis.load_questions_from_csv('./Data/Y-MITRE_Procedures.csv')
    #predictions = analysis.perform_qa_for_list(list_of_questions)
    #df = pd.DataFrame(predictions)    
    all_procedures_df.to_csv('./retrieve_similar_procedures.csv', index=False)