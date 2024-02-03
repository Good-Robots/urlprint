from math import log
from requests import head
from string import punctuation

from base import URL, computed_field, cached_property, Optional


class LexicalFeatures(URL):
    vowels: str = "aeiou"
    consonants: str = "bcdfghjklmnpqrstvwxyz"
    punctuations: str = punctuation

    @computed_field
    @cached_property
    def lx_url_string(self) -> str:
        """String representation of the URL."""
        _url = self.url
        if not self.cp_scheme:
            _url = f"http://{self.url}"

        try:
            return head(_url, allow_redirects=True, timeout=1).url
        except:
            return self.url
        
    @computed_field
    @cached_property
    def lx_label(self) -> str:
        return self.label.value

    @computed_field
    @cached_property
    def lx_host(self) -> str:
        """Hostname of the URL."""
        return self.cp_host
    
    @computed_field
    @cached_property
    def lx_path(self) -> Optional[str]:
        """Path of the URL."""
        return self.cp_path

    @computed_field
    @cached_property
    def lx_url_length(self) -> int:
        """Number of Characters in the URL String."""
        return len(self.lx_url_string)
    
    @computed_field
    @cached_property
    def lx_length_of_host(self) -> int:
        """Number of Characters in URL's Hostname."""
        return len(self.cp_host)
    
    @computed_field
    @cached_property
    def lx_length_of_path(self) -> int:
        """Number of Characters in URL's Path."""
        return len(self.cp_path)
    
    @computed_field
    @cached_property
    def lx_has_tls(self) -> bool:
        """Check if URL uses HTTPS."""
        return self.url.startswith("https")
    
    @computed_field
    @cached_property
    def lx_tld(self) -> str:
        """Top Level Domain of the URL."""
        return self.cp_host.split(".")[-1]
    
    @computed_field
    @cached_property
    def lx_number_tld(self) -> int:
        """Number of Subdomains in the URL."""
        return self.cp_host.count(".")
    
    @computed_field
    @cached_property
    def lx_number_of_hyphens(self) -> int:
        """Number of Hyphens in the URL."""
        return self.lx_url_string.count("-")

    @computed_field
    @cached_property
    def lx_number_of_parameters(self) -> int:
        """Number of Parameters in the URL."""
        return len(self.cp_query_params)
    
    @computed_field
    @cached_property
    def lx_number_of_underscore(self) -> int:
        """Number of Underscores in the URL."""
        return self.lx_url_string.count("_")
    
    @computed_field
    @cached_property
    def lx_number_of_fragment(self) -> int:
        """Number of Fragments in the URL."""
        return self.lx_url_string.count("#")
    
    @computed_field
    @cached_property
    def lx_has_username(self) -> bool:
        """Check if URL has a Username."""
        return bool(self.cp_username)
    
    @computed_field
    @cached_property
    def lx_has_password(self) -> bool:
        """Check if URL has a Password."""
        return bool(self.cp_password)
    
    @computed_field
    @cached_property
    def lx_has_port(self) -> bool:
        """Check if URL has a Port. E.g example.com:80"""
        return bool(self.cp_port)
    
    @computed_field
    @cached_property
    def lx_has_www(self) -> bool:
        """Check if URL has a www. prefix."""
        return "www." in self.cp_host
    
    @computed_field
    @cached_property
    def lx_entropy(self) -> float:
        """Shanon Entropy of the URL String."""
        prob = [self.lx_url_string.count(c) / len(self.lx_url_string) 
                for c in self.lx_url_string]
        entropy = - sum([
            p * log(p) / log(2.0) for p in prob
        ])
        return entropy
    
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
            self.lx_url_string.count(c) for c in self.consonants
        ])
        return total
    
    @computed_field
    @cached_property
    def lx_number_of_digits(self) -> int:
        """Number of Digits in the URL String."""
        total = sum(c.isdigit() for c in self.lx_url_string)
        return total
    
    @computed_field
    @cached_property
    def lx_number_of_punctutations(self) -> int:
        """Number of Punctuations in the URL String."""
        total = sum([self.lx_url_string.count(c) for c in self.punctuations])
        return total
    
    @computed_field
    @cached_property
    def lx_number_subdirectories(self) -> int:
        """Number of Subdirectories in the URL Path."""
        return self.cp_path.count("/")
    
    @computed_field
    @cached_property
    def lx_vowel_density(self) -> float:
        """Total number of Vowels divided by the URL Length."""
        return self.lx_num_vowels / self.lx_url_length
    
    @computed_field
    @cached_property
    def lx_consonant_density(self) -> float:
        """Total number of Consonants divided by the URL Length."""
        return self.lx_num_consonants / self.lx_url_length
    
    @computed_field
    @cached_property
    def lx_digit_density(self) -> float:
        """Total number of Digits divided by the URL Length."""
        return self.lx_number_of_digits / self.lx_url_length

    @computed_field
    @cached_property
    def lx_punctuation_density(self) -> float:
        """Total number of Punctuations divided by the URL Length."""
        return self.lx_number_of_punctutations / self.lx_url_length
    
    @computed_field
    @cached_property
    def lx_vowel_to_consonant_ratio(self) -> float:
        """Total number of Vowels divided by the Total number of Consonants."""
        return self.lx_num_vowels / self.lx_num_consonants
    
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