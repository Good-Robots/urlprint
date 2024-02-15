import logging
from string import punctuation
from pydantic import computed_field

from lib.features.base import cached_property, UC, Optional, FeatureSet


class LexicalFeatures(FeatureSet):
    components: UC 

    @cached_property
    def vowels(self) -> str:
        vowels = "aeiou"
        return vowels + vowels.upper()
    
    @cached_property
    def consonants(self) -> str:
        consonants = "bcdfghjklmnpqrstvwxyz"
        return consonants + consonants.upper()
    
    @cached_property
    def punctuations(self) -> str:
        return punctuation
    
    @computed_field
    @cached_property
    def lx_url_raw(self) -> str:
        return self.components.url
    
    @computed_field
    @cached_property
    def lx_url_string(self) -> str:
        return self.components.cp_resolved
    
    @computed_field
    @cached_property
    def lx_label(self) -> str:
        return self.components.label.value
    
    @computed_field
    @cached_property
    def lx_path_extension(self) -> Optional[str]:
        """File Extension of the URL Path."""
        if "." in self.components.cp_path:
            return self.components.cp_path.split(".")[-1].strip("/")
        return None
    
    @computed_field
    @cached_property
    def lx_scheme(self) -> str:
        return self.components.cp_scheme

    @computed_field
    @cached_property
    def lx_url_length(self) -> int:
        """Number of Characters in the URL String."""
        return len(self.lx_url_string)
    
    @computed_field
    @cached_property
    def lx_length_of_host(self) -> int:
        """Number of Characters in URL's Hostname."""
        return len(self.components.cp_host)
    
    @computed_field
    @cached_property
    def lx_length_of_path(self) -> int:
        """Number of Characters in URL's Path."""
        return len(self.components.cp_path)
    
    @computed_field
    @cached_property
    def lx_num_paths(self) -> int:
        """Number of Paths in the URL."""
        return self.components.cp_path.count("/")
    
    @computed_field
    @cached_property
    def lx_has_tls(self) -> bool:
        """Check if URL uses HTTPS."""
        return self.lx_url_string.startswith("https")
    
    @computed_field
    @cached_property
    def lx_tld(self) -> str:
        """Top Level Domain of the URL."""
        return self.components.cp_domains[-1]
    
    @computed_field
    @cached_property
    def lx_len_tld(self) -> int:
        """Length of the TLD."""
        return len(self.lx_tld)
    
    @computed_field
    @cached_property
    def lx_has_subdomains(self) -> bool:
        """Check if URL has Subdomains."""
        return len(self.components.cp_domains) > 1
    
    @computed_field
    @cached_property
    def lx_num_subdomains(self) -> Optional[int]:
        """Number of Subdomains in the URL."""
        if self.lx_has_subdomains:
            return len(self.components.cp_domains)-1
        return None
    
    @computed_field
    @cached_property
    def lx_num_hyphens(self) -> int:
        """Number of Hyphens in the URL."""
        return self.lx_url_string.count("-")

    @computed_field
    @cached_property
    def lx_num_query_params(self) -> int:
        """Number of Parameters in the URL."""
        return len(self.components.cp_query_params)
    
    @computed_field
    @cached_property
    def lx_avg_len_query_params(self) -> Optional[float]:
        """Average Length of the Query Parameters."""
        if len(self.components.cp_query_params) == 0:
            return 0
        
        try:
            total = sum([
                len(param[1]) for param in self.components.cp_query_params
            ])
            return total / len(self.components.cp_query_params)
        except:
            return None


    @computed_field
    @cached_property
    def lx_num_int_query_params(self) -> Optional[int]:
        """Number of Integer Query Parameters."""
        if len(self.components.cp_query_params) == 0:
            return 0
        
        try:
            total = sum([
                all(c.isdigit() for c in param[1]) 
                    for param in self.components.cp_query_params
            ])
            return total
        except Exception as e:
            logging.error(e)
            return None
    
    @computed_field
    @cached_property
    def lx_num_underscore(self) -> int:
        """Number of Underscores in the URL."""
        return self.lx_url_string.count("_")
    
    @computed_field
    @cached_property
    def lx_num_fragment(self) -> int:
        """Number of Fragments in the URL."""
        return self.lx_url_string.count("#")
    
    @computed_field
    @cached_property
    def lx_has_username(self) -> bool:
        """Check if URL has a Username."""
        return bool(self.components.cp_username)
    
    @computed_field
    @cached_property
    def lx_has_password(self) -> bool:
        """Check if URL has a Password."""
        return bool(self.components.cp_password)
    
    @computed_field
    @cached_property
    def lx_has_port(self) -> bool:
        """Check if URL has a Port. E.g example.com:80"""
        return bool(self.components.cp_port)
    
    @computed_field
    @cached_property
    def lx_has_www(self) -> bool:
        """Check if URL has a www. prefix."""
        return "www." in self.lx_url_string
    
    @computed_field
    @cached_property
    def lx_entropy(self) -> float:
        """Shanon Entropy of the URL String."""
        return self.components.entropy(self.lx_url_string)
    
    @computed_field
    @cached_property
    def lx_num_vowels(self) -> int:
        """Number of Vowels in the URL String."""
        total = sum([self.lx_url_string.count(v) for v in self.vowels])
        return total
    
    @computed_field
    @cached_property
    def lx_num_consonants(self) -> int:
        """Number of Consonants in the URL String."""
        total = sum([
            self.lx_url_string.split("://")[-1].strip('www').count(c) 
                for c in self.consonants
        ])
        return total
    
    @computed_field
    @cached_property
    def lx_num_digits(self) -> int:
        """Number of Digits in the URL String."""
        total = sum(c.isdigit() for c in self.lx_url_string)
        return total
    
    @computed_field
    @cached_property
    def lx_num_puncs(self) -> int:
        """Number of Punctuations in the URL String."""
        total = sum([self.lx_url_string.count(c) for c in self.punctuations])
        return total
    
    @computed_field
    @cached_property
    def lx_num_subdirectories(self) -> int:
        """Number of Subdirectories in the URL Path."""
        return self.components.cp_path.count("/")
    
    @computed_field
    @cached_property
    def lx_num_uppercase(self) -> int:
        """Number of Uppercase Characters in the URL String."""
        return sum(c.isupper() for c in self.lx_url_string)
    
    @computed_field
    @cached_property
    def lx_vowel_density(self) -> Optional[float]:
        """Total number of Vowels divided by the URL Length."""
        try:
            return self.lx_num_vowels / self.lx_url_length
        except:
            return None
    
    @computed_field
    @cached_property
    def lx_consonant_density(self) -> float:
        """Total number of Consonants divided by the URL Length."""
        try:
            return self.lx_num_consonants / self.lx_url_length
        except:
            return 0
    
    @computed_field
    @cached_property
    def lx_digit_density(self) -> Optional[float]:
        """Total number of Digits divided by the URL Length."""
        try:
            return self.lx_num_digits / self.lx_url_length
        except:
            return None

    @computed_field
    @cached_property
    def lx_punctuation_density(self) -> Optional[float]:
        """Total number of Punctuations divided by the URL Length."""
        try:
            return self.lx_num_puncs / self.lx_url_length
        except:
            return None
    
    @computed_field
    @cached_property
    def lx_vowel_to_consonant_ratio(self) -> Optional[float]:
        """Total number of Vowels divided by the Total number of Consonants."""
        try:
            return self.lx_num_vowels / self.lx_num_consonants
        except:
            return None
    
    @computed_field
    @cached_property
    def lx_vowel_following_vowel(self) -> int:
        """Number of Vowels following another Vowel."""
        total = sum([
            (self.lx_url_string[i] in self.vowels and 
                self.lx_url_string[i+1] in self.vowels)
                    for i in range(len(self.lx_url_string)-1)
            ])
        return total 

    @computed_field
    @cached_property
    def lx_consonant_following_consonant(self) -> int:
        """Number of Consonants following another Consonant."""
        total = sum([
            (self.lx_url_string[i] in self.consonants and 
                self.lx_url_string[i+1] in self.consonants)
                    for i in range(len(self.lx_url_string)-1)
            ])
        return total

    @computed_field
    @cached_property
    def lx_digit_following_digit(self) -> int:
        """Number of Digits following another Digit."""
        total = sum([
            (self.lx_url_string[i].isdigit() and 
                self.lx_url_string[i+1].isdigit())
                    for i in range(len(self.lx_url_string)-1)
            ])
        return total

    @computed_field
    @cached_property
    def lx_vowel_following_consonant(self) -> int:
        """Number of Vowels following a Consonant."""
        total = sum([
            (self.lx_url_string[i] in self.consonants and
                self.lx_url_string[i+1] in self.vowels)
                    for i in range(len(self.lx_url_string)-1)
            ])
        return total

    @computed_field
    @cached_property
    def lx_consonant_following_vowel(self) -> int:
        """Number of Consonants following a Vowel."""
        total = sum([
            (self.lx_url_string[i] in self.vowels and 
                self.lx_url_string[i+1] in self.consonants)
                    for i in range(len(self.lx_url_string)-1)
            ])
        return total 