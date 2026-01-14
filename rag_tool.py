import os
from dotenv import load_dotenv

# Modern Imports (LCEL)
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import CharacterTextSplitter
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.vectorstores import Chroma
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate

# Load API Key
load_dotenv()

def main():
    print("🔄 Loading Threat Intel Data...")
    
    # 1. INGEST
    loader = TextLoader("cve_data.txt")
    documents = loader.load()
    
    # 2. SPLIT
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    texts = text_splitter.split_documents(documents)
    
    # 3. EMBED
    print("🧠 Indexing data into Vector Store...")
    embeddings = OpenAIEmbeddings()
    db = Chroma.from_documents(texts, embeddings)
    retriever = db.as_retriever()
    
    # 4. PROMPT (The "Brain")
    # We tell the AI exactly how to behave
    prompt = ChatPromptTemplate.from_template("""
    You are a Cyber Threat Intelligence Analyst. 
    Answer the user's question based ONLY on the following context context.
    If the answer is not in the context, say "I don't have intel on that."
    
    <context>
    {context}
    </context>

    Question: {input}
    """)
    
    # 5. CHAIN (The Modern "LCEL" Way)
    llm = ChatOpenAI(model_name="gpt-3.5-turbo", temperature=0)
    
    # Create the "Document Chain" (Handles the text)
    document_chain = create_stuff_documents_chain(llm, prompt)
    
    # Create the "Retrieval Chain" (Connects DB -> Document Chain)
    retrieval_chain = create_retrieval_chain(retriever, document_chain)
    
    print("✅ System Ready! Ask about a CVE (or type 'exit').")
    
    # 6. INTERACT
    while True:
        query = input("\n🔎 Query: ")
        if query.lower() == 'exit':
            break
        
        try:
            response = retrieval_chain.invoke({"input": query})
            print(f"🤖 AI Response: {response['answer']}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()