import logging

import requests

from vuln_checker.config import GithubConfig


def github_graphql_api_query(query: str):
    def decorator(func):
        def wrapper(*args, **kwargs):
            q = query[:]
            if kwargs:
                for key, value in kwargs.items():
                    q = q.replace(f"${key}", value)

            response = requests.post(
                GithubConfig.GITHUB_GRAPHQL_API,
                json={"query": q},
                headers={"Authorization": GithubConfig.GITHUB_AUTH_HEADER}
            )

            if response.status_code != 200:
                raise Exception("GitHub GraphQL API returned non-200 status code")

            if "errors" in response.json():
                logging.error("GitHub GraphQL API returned errors")
                logging.error("Query: " + q)
                for error in response.json()["errors"]:
                    logging.error(error)
                raise Exception("Failed to execute GitHub GraphQL API query")

            return func(response.json()["data"], *args, **kwargs)

        return wrapper

    return decorator


@github_graphql_api_query("""
mutation {
  createDiscussion(
    input: {
      repositoryId: "$repo_id"
      categoryId: "$category_id"
      title: "$title"
      body: "$body"
    }
  ) {
    discussion {
      id
      url
    }
  }
}
""")
def create_discussion(data, repo_id, category_id: str, title: str, body: str) -> dict:
    return data["createDiscussion"]["discussion"]


@github_graphql_api_query("""
query {
  repository(name: "$repo_name", owner: "$repo_owner") {
    id
    discussionCategories(first: 100) {
      nodes {
        id
        name
      }
    }
  }
}
""")
def fetch_repository(data, repo_name: str, repo_owner: str):
    return data["repository"]


@github_graphql_api_query("""
mutation {
  updateDiscussion(input: { discussionId: "$discussion_id", title: "$title" }) {
    discussion {
      id
      title
      url
    }
  }
}
""")
def update_discussion(data, discussion_id: str, title: str):
    return data["updateDiscussion"]["discussion"]


@github_graphql_api_query("""
query {
    node(id: "$discussion_id") {
        ... on Discussion {
            id
            title
            body
            }
        }
    }
""")
def get_discussion(data, discussion_id: str):
    return data["node"]