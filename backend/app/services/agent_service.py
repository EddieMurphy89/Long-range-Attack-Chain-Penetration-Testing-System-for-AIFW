import os
from app.core.config import logger, VULHUB_ROOT, OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL_NAME
from openai import OpenAI, AsyncOpenAI
from typing import Optional, AsyncGenerator

from app.services.vector_db_service import vector_db
from app.services.web_search_service import web_search_service

def find_vulhub_readme(cve_or_app_name: str) -> Optional[str]:
    """
    Search for CVE/App context using Vector DB (Local Vulhub).
    If no good results are found, fallback to Web Search.
    """
    if not cve_or_app_name:
        return None

    cve_or_app_name = cve_or_app_name.lower().strip()
    
    try:
        # Ensure VectorDB is indexed
        vector_db.index_vulhub_if_empty()
        
        # 1. Try Vector DB Search
        results = vector_db.search(cve_or_app_name, n_results=3)
        if results:
            logger.info(f"Found {len(results)} chunks in Vector DB for {cve_or_app_name}")
            context = "【Local Vulhub Context (RAG)】\n"
            for r in results:
                context += f"--- Source: {r['metadata']['source']} ---\n{r['content']}\n\n"
            return context
            
    except Exception as e:
        logger.error(f"Vector DB Search failed: {e}")
        
    # 2. Fallback to Web Search
    logger.info(f"No local results for {cve_or_app_name}, falling back to Web Search.")
    try:
        web_query = f"{cve_or_app_name} exploit poc github python"
        web_results = web_search_service.search_cve_info(web_query)
        if web_results:
             return f"【Web Search Context (Fallback)】\n{web_results}"
    except Exception as e:
        logger.error(f"Web Search Fallback failed: {e}")
        
    return None


def generate_payload_from_readme(readme_content: str, target_url: str = "", api_key: str = "", base_url: str = "", model_name: str = "") -> str:
    """
    Pass the README content to the LLM to generate a Python exploit script.
    """
    key_to_use = api_key or OPENAI_API_KEY
    if not key_to_use:
        raise ValueError("OPENAI_API_KEY is not set. Please set it in the frontend configuration to use the AI Agent.")

    client = OpenAI(
        api_key=key_to_use,
        base_url=base_url or OPENAI_BASE_URL
    )
    
    effective_model_name = model_name or OPENAI_MODEL_NAME

    prompt = f"""
你是一个专业的红队武器开发专家。
以下是某个漏洞的 README 文档内容，请你根据其中的复现方法或攻击载荷（POC/EXP），编写一段基于 Python 的独立漏洞测试脚本，并对该脚本进行解释和给出执行建议。

【要求与严苛约束】：
1. 脚本必须使用 Python 3 编写。
2. 脚本需要使用 `sys.argv` 接收参数，例如 `sys.argv[1]` 作为目标URL，`sys.argv[2]` 作为执行命令 (如果需要RCE的话)。
3. 提供完整的可执行代码，不要缩减。
4. **务必** 使用 markdown 格式输出你的回复，不要将所有的回复整合在一个代码块中。
5. 请在你的回复中包含三部分：
    - **漏洞/攻击脚本解释**：简单解释这个漏洞的原理或脚本的攻击逻辑。
    - **执行建议**：给出执行此脚本的命令示例及注意事项。
    - **Python 脚本**：给出用于测试的 Python 脚本。
6. 对于 Python 脚本部分，**必须** 使用 ```python 和 ``` 包裹代码。
7. 如果是纯验证类漏洞而无法执行命令，请在脚本中实现验证并发起请求，打印验证成功或失败的结果。
8. 目标 URL 可能类似于: {target_url} 

【README内容】：
{readme_content}
"""

    try:
        response = client.chat.completions.create(
            model=effective_model_name,
            messages=[
                {"role": "system", "content": "You are a professional red team tool developer. Your output must be in markdown format containing the script explanation, execution suggestions, and the python script itself."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        
        result = response.choices[0].message.content.strip()
        return result
            
        return result
    except Exception as e:
        logger.error(f"Error generating payload from LLM: {e}")
        raise e

async def generate_payload_multi_agent(readme_content: str, target_url: str = "", aifw_status: str = "", api_key: str = "", base_url: str = "", model_name: str = "", attempt: int = 0) -> AsyncGenerator[str, None]:
    """
    Pass the README content and AI Firewall routing status to the LLM to generate a Python exploit script, yielding chunks.
    """
    key_to_use = api_key or OPENAI_API_KEY
    if not key_to_use:
        raise ValueError("API KEY is not set. Please set it in the frontend configuration to use the AI Agent.")

    client = AsyncOpenAI(
        api_key=key_to_use,
        base_url=base_url or OPENAI_BASE_URL
    )
    
    effective_model_name = model_name or OPENAI_MODEL_NAME

    mutation_instruction = ""
    if attempt > 0:
        mutation_instruction = f"\n这是第 {attempt + 1} 次尝试生成 payload。请务必使用与之前完全不同的、更高级的 AIFW 绕过或 payload 混淆技术（例如：不同的编码方式、分块传输、特殊 Header 伪造、参数污染或语法变异等），并在你的解释中明确说明这次使用的绕过思路是什么。\n"

    prompt = f"""
你是一个专业的红队武器开发专家和渗透测试专家。
以下是某个漏洞的 README 文档内容，请你根据其中的复现方法或攻击载荷（POC/EXP），编写一段基于 Python 的独立漏洞测试脚本，并对该脚本进行解释和给出执行建议。

【AIFW (AI Firewall) 状态】：
{aifw_status}
如果AIFW处于启用状态，你需要特别注意混淆或绕过技术，否则你的普通POC很可能被拦截。{mutation_instruction}

【要求与严苛约束】：
1. 脚本必须使用 Python 3 编写。
2. 脚本需要使用 `sys.argv` 接收参数，例如 `sys.argv[1]` 作为目标URL，`sys.argv[2]` 作为执行命令 (如果需要RCE的话)。
3. 提供完整的可执行代码，不要缩减。
4. **务必** 使用 markdown 格式输出你的回复，不要将所有的回复整合在一个代码块中。
5. 请在你的回复中包含三部分：
    - **漏洞/攻击脚本解释**：简单解释这个漏洞的原理或脚本的攻击逻辑。
    - **执行建议**：给出执行此脚本的命令示例及注意事项。
    - **Python 脚本**：给出用于测试的 Python 脚本。
6. 对于 Python 脚本部分，**必须** 使用 ```python 和 ``` 包裹代码。
7. 如果是纯验证类漏洞而无法执行命令，请在脚本中实现验证并发起请求，打印验证成功或失败的结果。
8. 目标 URL 可能类似于: {target_url}

【README内容】：
{readme_content}
"""

    try:
        response = await client.chat.completions.create(
            model=effective_model_name,
            messages=[
                {"role": "system", "content": "You are a professional red team tool developer. Your output must be in markdown format containing the script explanation, execution suggestions, and the python script itself."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            stream=True
        )
        
        async for chunk in response:
            content = chunk.choices[0].delta.content
            if content:
                yield content
                
    except Exception as e:
        logger.error(f"Error generating multi-agent payload from LLM: {e}")
        raise e
