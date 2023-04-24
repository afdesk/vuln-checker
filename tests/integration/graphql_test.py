import pytest

from vuln_checker.gh.graphql import update_discussion, get_discussion

TEST_DISCUSSION_ID = "D_kwDOI_AQL84ATegE"


@pytest.mark.skip
def test_update_discussion():
    title = "test title"
    discussion = update_discussion(discussion_id=TEST_DISCUSSION_ID, title=title)

    assert discussion["id"] == TEST_DISCUSSION_ID
    assert discussion["title"] == title


@pytest.mark.skip
def test_get_discussion():
    discussion = get_discussion(discussion_id=TEST_DISCUSSION_ID)
    assert discussion["id"] == TEST_DISCUSSION_ID
