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
import asyncio
import aiohttp
from tenacity import retry, wait_exponential
import nest_asyncio
nest_asyncio.apply()
sys.path.append('../..')



class MITREAnalysis:
    def __init__(self, api_key, data_source, mode='url'):
        openai.api_key = api_key
        if mode == 'csv':
            self.loader = CSVLoader(file_path=data_source)
            self.data = self.loader.load()

        elif mode == 'url':
            self.url = data_source
            self.data = self.load_and_split_web_content(self.url)
        else:
            raise ValueError("Invalid mode. Choose 'csv' or 'search'.")
        
        self.embeddings = OpenAIEmbeddings(openai_api_key=openai.api_key)
        self.vectordb = FAISS.from_documents(
            documents=self.data,
            embedding=self.embeddings,            
        )
        self.llm_name = "gpt-3.5-turbo"
        self.llm = ChatOpenAI(model_name=self.llm_name, temperature=0, openai_api_key=openai.api_key)


        self.prompt_template = self.build_qa_chain_prompt()


    def perform_similarity_search(self, question, k=3):
        docs = self.vectordb.similarity_search(question, k=k)
        for doc in docs:
            print(doc.metadata)


    def perform_marginal_relevance_search(self, question, k=3, fetch_k=5):
        docs = self.vectordb.max_marginal_relevance_search(question, k=k, fetch_k=fetch_k)
        for doc in docs:
            print(doc.metadata)


    def build_qa_chain_prompt(self):
        template = """You are a cybersecurity expert. Consider the relevant context provided below and answer the question.

Relevant Context: {context}

Question: {question}

Please only respond with the MITRE ATT&CK tactics you are certain about.
        """
        return PromptTemplate.from_template(template)


    def perform_qa(self, question, prompt_template):
        qa_chain = RetrievalQA.from_chain_type(
            self.llm,
            retriever=self.vectordb.as_retriever(search_type="similarity", search_kwargs={"k":3}),
            return_source_documents=True,
            chain_type_kwargs={"prompt": prompt_template}
        )
        result = qa_chain({"query": question})
        print(result["result"],'\n')
        return result

    def load_and_split_web_content(self, url):
        docs = WebBaseLoader(url).load()

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size = 5250,
            chunk_overlap = 250,
            separators=["\n\n", "\n", " ", ""]
        )
        splits = text_splitter.split_documents(docs)
        print(len(splits))
        return splits

if __name__ == "__main__":
    api_key  = "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"
    preds = []
    df = pd.read_csv('./Data/Y-MITRE_Procedures.csv')

    for procedure, url in zip(df['Procedures'], df['URL']):
        analysis = MITREAnalysis(api_key, url, mode='url')
        prompt_template = analysis.build_qa_chain_prompt()
        while True:
            try:
                question = f"Knowing that <<{procedure}>>, what MITRE ATT&CK tactics will a cyber adversary achieve with this technique?"
                print(question)
                result = analysis.perform_qa(question, prompt_template)
                print('------------------')
                preds.append(result)
                break
            except (openai.error.RateLimitError, openai.error.APIError, openai.error.Timeout,
                    openai.error.OpenAIError, openai.error.ServiceUnavailableError):
                time.sleep(8)


    df = pd.DataFrame(preds)    
    df.to_csv('./preds_gpt-3.5_with_exact_urls.csv', index=False)