"""
GraphQL Security Scanner.
Checks for exposed endpoints and introspection.
"""
import logging
from typing import List
from models import Finding
from scanner.core.requester import Requester

logger = logging.getLogger(__name__)

class GraphQLScanner:
    """Scanner for GraphQL vulnerabilities."""

    def __init__(self):
        self.requester = Requester()
        self.endpoints = [
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/gql",
            "/query"
        ]

    def scan(self, base_url: str) -> List[Finding]:
        """
        Scan a URL for exposed GraphQL endpoints and introspection.
        """
        findings = []
        if not base_url.endswith('/'):
            base_url += '/'

        for endpoint in self.endpoints:
            target_url = base_url.rstrip('/') + endpoint
            try:
                # 1. Check if endpoint exists
                # GraphQL often accepts GET but recommends POST. 
                # A 400 Bad Request usually means "I'm a GraphQL server but you didn't send a query".
                # A 200 OK with specific error json is also a hit.
                response = self.requester.get(target_url, timeout=4)
                
                is_graphql = False
                
                if response.status_code == 400 and "query" in response.text.lower():
                     is_graphql = True
                elif "graphql" in response.text.lower() or "data" in response.text.lower():
                     if "errors" in response.text.lower():
                         is_graphql = True

                if is_graphql:
                    findings.append(Finding(
                        title="GraphQL Endpoint Discovered",
                        severity="LOW",
                        description="A GraphQL endpoint was detected. Access controls should be verified.",
                        location=f"URL: {target_url}",
                        recommendation="Ensure the endpoint is intended to be public and rate-limited.",
                        cwe_reference="CWE-284"
                    ))

                    # 2. Check Introspection
                    # Try to query the schema
                    introspection_query = {
                        "query": "{ __schema { types { name } } }"
                    }
                    post_response = self.requester.post(target_url, json=introspection_query, timeout=4)
                    
                    if post_response.status_code == 200 and "__schema" in post_response.text:
                        findings.append(Finding(
                            title="GraphQL Introspection Enabled",
                            severity="MEDIUM",
                            description="The GraphQL endpoint allows Introspection queries, enabling attackers to map the entire API schema, types, and fields.",
                            location=f"URL: {target_url}",
                            recommendation="Disable GraphQL Introspection in production environments.",
                            cwe_reference="CWE-200"
                        ))
                    
                    # Stop after finding one valid endpoint to avoid duplicates
                    break

            except Exception:
                pass

        return findings
