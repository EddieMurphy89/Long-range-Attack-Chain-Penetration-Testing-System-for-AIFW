from ddgs import DDGS
from bs4 import BeautifulSoup
import httpx
from app.core.config import logger
from typing import Optional

class WebSearchService:
    def __init__(self):
        self.ddgs = DDGS()
        
    def search_cve_info(self, query: str, max_results: int = 3) -> str:
        """
        Search duckduckgo for the query and extract text from the top results.
        Returns a concatenated string of the extracted text.
        """
        logger.info(f"Initiating Web Search Fallback for query: {query}")
        try:
            results = list(self.ddgs.text(query, max_results=max_results))
            if not results:
                return ""
            
            combined_context = []
            for res in results:
                url = res.get('href')
                if not url:
                    continue
                
                # Try to fetch and parse the page text
                try:
                    # Timeout set to 5 seconds to prevent hanging
                    response = httpx.get(url, timeout=5.0, follow_redirects=True, verify=False)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        # Remove script and style elements
                        for script in soup(["script", "style", "header", "footer", "nav", "aside"]):
                            script.extract()
                        
                        text = soup.get_text(separator='\n')
                        # collapse whitespace
                        lines = (line.strip() for line in text.splitlines())
                        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                        text = '\n'.join(chunk for chunk in chunks if chunk)
                        
                        # We only take the first ~3000 chars of each page to avoid context overflow
                        truncated_text = text[:3000]
                        combined_context.append(f"--- Source: {url} ---\n{truncated_text}\n")
                    else:
                        # Fallback to duckduckgo snippet if page fetch fails
                        snippet = res.get('body', '')
                        combined_context.append(f"--- Source snippet: {url} ---\n{snippet}\n")
                except Exception as fetch_err:
                    logger.warning(f"Failed to fetch {url}: {fetch_err}")
                    snippet = res.get('body', '')
                    combined_context.append(f"--- Source snippet: {url} ---\n{snippet}\n")
                    
            return "\n\n".join(combined_context)
        except Exception as e:
            logger.error(f"Web search failed: {e}")
            return ""

web_search_service = WebSearchService()
