# --- DATABASE FIX FOR RENDER (MUST BE AT THE VERY TOP) ---
__import__('pysqlite3')
import sys
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import streamlit as st
import os
import tempfile

# --- UPDATED IMPORTS ---
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import CharacterTextSplitter
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.vectorstores import Chroma
# CHANGE: Import RetrievalChain from the new location
from langchain.chains.retrieval import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate

# --- CONFIGURATION ---
st.set_page_config(page_title="CVE RAG Intelligence", page_icon="🧠", layout="wide")

# Custom CSS
st.markdown("""
    <style>
    .stApp { background-color: #0f172a; color: #e2e8f0; }
    .stChatMessage { background-color: #1e293b; border-radius: 10px; padding: 10px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🧠 CVE Intelligence Agent (RAG)")
st.markdown("Ask questions about specific CVEs, and the AI will answer based on the indexed threat intelligence.")

# --- SIDEBAR: API KEY ---
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    api_key = st.sidebar.text_input("Enter OpenAI API Key", type="password")

# --- INITIALIZATION (Cached to run once) ---
@st.cache_resource
def initialize_rag_system(key):
    if not key:
        return None
    
    os.environ["OPENAI_API_KEY"] = key
    
    # 1. CREATE DUMMY DATA IF FILE MISSING
    if not os.path.exists("cve_data.txt"):
        with open("cve_data.txt", "w") as f:
            f.write("""
            CVE-2024-3094: XZ Utils Backdoor. Severity: Critical (CVSS 10.0). 
            Description: Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. 
            Impact: Allows remote attackers to bypass SSH authentication.
            Mitigation: Downgrade to xz version 5.4.6 or earlier immediately.
            
            CVE-2023-4863: Heap buffer overflow in libwebp. Severity: High (CVSS 8.8).
            Description: A heap buffer overflow in WebP allows a remote attacker to perform an out of bounds write via a crafted HTML page.
            Impact: Remote Code Execution (RCE) in Chrome, Firefox, and other browsers.
            """)
    
    # 2. LOAD & PROCESS
    loader = TextLoader("cve_data.txt")
    documents = loader.load()
    
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    texts = text_splitter.split_documents(documents)
    
    # 3. EMBED & STORE
    embeddings = OpenAIEmbeddings()
    # Using a temporary directory for Chroma to avoid permission issues on Render
    db = Chroma.from_documents(texts, embeddings)
    retriever = db.as_retriever()
    
    # 4. SETUP LLM CHAIN
    llm = ChatOpenAI(model_name="gpt-3.5-turbo", temperature=0)
    
    prompt = ChatPromptTemplate.from_template("""
    You are a Cyber Threat Intelligence Analyst. 
    Answer the user's question based ONLY on the following context.
    If the answer is not in the context, say "I don't have intel on that."
    
    <context>
    {context}
    </context>

    Question: {input}
    """)
    
    document_chain = create_stuff_documents_chain(llm, prompt)
    retrieval_chain = create_retrieval_chain(retriever, document_chain)
    
    return retrieval_chain

# --- MAIN APP ---
if api_key:
    try:
        chain = initialize_rag_system(api_key)
        
        # Chat History
        if "messages" not in st.session_state:
            st.session_state.messages = []

        # Display Chat
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        # User Input
        if prompt := st.chat_input("Ask about a CVE (e.g., 'What is CVE-2024-3094?')"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                # Run the RAG chain
                response = chain.invoke({"input": prompt})
                st.markdown(response['answer'])
            
            st.session_state.messages.append({"role": "assistant", "content": response['answer']})
            
    except Exception as e:
        st.error(f"Error initializing RAG: {e}")
else:
    st.info("👈 Please enter your OpenAI API Key in the sidebar to activate the agent.")