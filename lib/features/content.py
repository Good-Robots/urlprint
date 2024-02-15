
import re 
import logging
from pyquery import PyQuery
from pydantic import computed_field


from lib.features.base import (
    cached_property, UC, Optional, FeatureSet
)



class ContentFeatures(FeatureSet):
    components: UC 

    @cached_property
    def ct_response(self):
        return self.components.cp_response
    
    @cached_property
    def ct_has_headers(self) -> bool:
        if self.ct_response:
            return bool(self.ct_response.headers)
        return False

    @cached_property
    def ct_content(self) -> str:
        try:
            return self.ct_response.text
        except Exception as e:
            logging.error(e)
            return ""

    
    @cached_property
    def ct_pq(self) -> PyQuery:
        try:
            return PyQuery(self.ct_content)
        except Exception as e:
            logging.error(e)
            return PyQuery("<html></html>")


    
    @cached_property
    def ct_text(self) -> str:
        return self.ct_pq.text()

    
    @cached_property
    def ct_sentences(self) -> list[str]:
        if bool(self.ct_text):
            return re.split(r"\.|\?|\!", self.ct_text)
        return []

    
    @cached_property
    def ct_tokens(self) -> list[str]:
        if bool(self.ct_text):
            return self.ct_text.split()
        return []

    
    @cached_property
    def ct_scripts(self) -> list[PyQuery]:
        scripts = list(
            filter(
                lambda x: bool(x), self.ct_pq('script')
            )
        )
        return scripts

    
    @cached_property
    def ct_script_texts(self) -> list[str]:
        return [i.text() for i in self.ct_scripts]

    
    @computed_field
    @cached_property
    def ct_has_redirects(self) -> bool:
        """Check if URL has Redirects."""
        if self.ct_response and self.ct_response.history:
            return True
        return False
    
    @computed_field
    @cached_property
    def ct_status_code(self) -> Optional[int]:
        """Status Code of the URL."""
        return self.components.cp_status_code
    
    @computed_field
    @cached_property
    def ct_entropy(self) -> float:
        """Entropy of the URL."""
        return self.components.entropy(self.ct_text)

    
    @computed_field
    @cached_property
    def ct_num_redirects(self) -> Optional[int]:
        """Number of Redirects in the URL."""
        redirects = self.components.cp_redirects
        if bool(redirects):
            return len(redirects)
        return None
    
    
    @computed_field
    @cached_property
    def ct_content_type(self) -> str:
        """Content Type of the URL."""
        if self.ct_has_headers:
            return self.components.cp_headers.get("content-type", "")
        return ""

    
    @computed_field
    @cached_property
    def ct_connection(self) -> str:
        """Connection Type of the URL."""
        if self.ct_has_headers:
            return self.components.cp_headers.get("connection", "close")
        return ""
        
    
    @computed_field
    @cached_property
    def ct_server(self) -> str:
        """Server Type of the URL."""
        if self.ct_has_headers:
            return self.components.cp_headers.get("server", "unknown")
        return ""

    
    @computed_field
    @cached_property
    def ct_content_length(self) -> int:
        """Content of the URL."""
        return len(self.ct_text)

    
    @computed_field
    @cached_property
    def ct_content_to_text_ratio(self) -> Optional[float]:
        """Content to Text Ratio."""
        if bool(self.ct_text):
            return len(self.ct_content) / len(self.ct_text)
        return None


    @computed_field
    @cached_property
    def ct_num_words(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_tokens)

    @computed_field
    @cached_property
    def ct_num_sentences(self) -> list[str]:
        """List of Words in the Content."""
        return len(self.ct_sentences)
    
    @computed_field
    @cached_property
    def ct_num_paragraphs(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_text.split("\n"))
    
    @computed_field
    @cached_property
    def ct_token_to_text_ratio(self) -> Optional[float]:
        """Token to Text Ratio."""
        if bool(self.ct_text):
            return len(self.ct_tokens) / len(self.ct_text)
        return None 
        
    @computed_field
    @cached_property
    def ct_sentence_to_text_ratio(self) -> Optional[float]:
        """Sentence to Text Ratio."""
        if bool(self.ct_text):
            return len(self.ct_sentences) / len(self.ct_text)
        return None
    
    @computed_field
    @cached_property
    def ct_token_to_sententce_ratio(self) -> Optional[float]:
        """Token to Sentence Ratio."""
        if bool(self.ct_sentences):
            return len(self.ct_tokens) / len(self.ct_sentences)
        return None
    
    @computed_field
    @cached_property
    def ct_avg_token_length(self) -> Optional[float]:
        """Average Word Length."""
        if bool(self.ct_tokens):
            total = sum([len(i) for i in self.ct_tokens])
            return total / len(self.ct_tokens)
        return None
    
    @computed_field
    @cached_property
    def ct_avg_sentence_length(self) -> Optional[float]:
        """Average Sentence Length."""
        if bool(self.ct_sentences):
            total = sum([len(i) for i in self.ct_sentences])
            return total / len(self.ct_sentences)
        return None
    
    @computed_field
    @cached_property
    def ct_num_script_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_scripts)
    
    @computed_field
    @cached_property
    def ct_num_style_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("style"))
    
    @computed_field
    @cached_property
    def ct_num_image_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("img"))
    
    @computed_field
    @cached_property
    def ct_num_links(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("a"))
    
    @computed_field
    @cached_property
    def ct_num_h1_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("h1"))
    
    @computed_field
    @cached_property
    def ct_num_h2_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("h2"))
    
    @computed_field
    @cached_property
    def ct_num_h3_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("h3"))
    
    @computed_field
    @cached_property
    def ct_num_h4_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("h4"))
    
    @computed_field
    @cached_property
    def ct_num_h5_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("h5"))
    
    @computed_field
    @cached_property
    def ct_num_h6_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("h6"))
    
    @computed_field
    @cached_property
    def ct_num_table_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("table"))
    
    @computed_field
    @cached_property
    def ct_num_form_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("form"))
    
    @computed_field
    @cached_property
    def ct_num_input_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("input"))
    
    @computed_field
    @cached_property
    def ct_num_hidden_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("*[hidden]")) # FIX ME
    

    @computed_field
    @cached_property
    def ct_num_hidden_input(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("input[type=hidden]"))
    
    @computed_field
    @cached_property
    def ct_num_external_links(self) -> int:
        """Number of Characters in the Content."""
        if bool(self.ct_text):
            return len(self.ct_pq("a[href^=http]")) ### FIX ME
        return 0
    
    @computed_field
    @cached_property
    def ct_num_files(self) -> int:
        """Number of Characters in the Content."""
        files = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'mp3', 'mp4', 'php']
        has_files = [self.ct_pq(f"a[href$={file}]") for file in files]
        files = [file for files in has_files for file in files]
        return len(files)
    
    @computed_field
    @cached_property
    def ct_text_entropy(self) -> float:
        """Number of Characters in the Content."""
        return self.components.entropy(self.ct_text)
    
    @computed_field
    @cached_property
    def ct_num_html_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("*"))
    
    @computed_field
    @cached_property
    def ct_num_html_comments(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_text.split("<!--"))
    
    @computed_field
    @cached_property
    def ct_num_capitalizations(self) -> int:
        """Number of Characters in the Content."""
        return sum([i.isupper() for i in self.ct_text])
    
    @computed_field
    @cached_property
    def ct_num_embeds(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("embed"))
    
    @computed_field
    @cached_property
    def ct_num_objects(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("object"))
    
    @computed_field
    @cached_property
    def ct_num_iframes(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("iframe"))
    
    @computed_field
    @cached_property
    def ct_num_meta_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("meta"))
    
    @computed_field
    @cached_property
    def ct_num_title_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("title"))
    
    @computed_field
    @cached_property
    def ct_num_head_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("head"))
    
    @computed_field
    @cached_property
    def ct_num_body_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("body"))
    
    @computed_field
    @cached_property
    def ct_num_html_meta_tags(self) -> int:
        """Number of Characters in the Content."""
        return len(self.ct_pq("html"))

    
    @computed_field
    @cached_property
    def ct_script_entropy(self) -> float:
        """Number of Characters in the Content."""
        s_text = " ".join(self.ct_script_texts)
        return self.components.entropy(s_text)
    
    @computed_field
    @cached_property
    def ct_num_evals(self) -> int:
        """Number of Characters in the Content."""
        return sum(["eval" in i for i in self.ct_script_texts])
    
    @computed_field
    @cached_property
    def ct_avg_script_length(self) -> float:
        """Number of Characters in the Content."""
        
        if bool(self.ct_num_script_tags):
            total = sum([len(i) for i in self.ct_script_texts])
            return total / self.ct_num_script_tags
        return 0
    

    @computed_field
    @cached_property
    def ct_num_external_scripts(self) -> int:
        """Number of Characters in the Content."""
        if bool(self.ct_num_script_tags):
            return len(self.ct_pq("script[src^=http]"))
        return 0
    
    @computed_field
    @cached_property
    def ct_num_inline_scripts(self) -> int:
        """Number of Characters in the Content."""
        if bool(self.ct_num_script_tags):
            inline_scripts = [s for s in self.ct_script_texts if s != ""]
            return len(inline_scripts)
        return 0
    
    @computed_field
    @cached_property
    def ct_num_internal_scripts(self) -> Optional[int]:
        """Number of Characters in the Content."""
        if bool(self.ct_num_script_tags):
            return self.ct_num_script_tags - self.ct_num_external_scripts - self.ct_num_inline_scripts
        return 0
    
    @computed_field
    @cached_property
    def ct_script_to_text_ratio(self) -> Optional[float]:
        """Number of Characters in the Content."""
        if bool(self.ct_text):
            return len(" ".join(self.ct_script_texts)) / len(self.ct_text)
        return None
    
    @computed_field
    @cached_property
    def ct_script_to_sentence_ratio(self) -> Optional[float]:
        """Number of Characters in the Content."""
        if bool(self.ct_sentences):
            return self.ct_num_script_tags  / len(self.ct_sentences)
        return None
    
    @computed_field
    @cached_property
    def ct_script_to_tag_ratio(self) -> Optional[float]:
        """Number of Characters in the Content."""
        if bool(self.ct_num_html_tags):
            return self.ct_num_script_tags / self.ct_num_html_tags
        return None
    