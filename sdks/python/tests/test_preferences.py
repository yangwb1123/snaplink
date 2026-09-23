from snaplink_sso import Snaplink
from snaplink_sso.preferences import (
    PresentationPreferencesPatch,
    SnaplinkUserPreferencesClient,
    build_login_preference_handoff,
)


class FakeClient:
    def __init__(self):
        self.body = None

    def get_my_preferences(self):
        return {"locale": "zh-CN", "sverp:theme_mode": "dark"}

    def put_my_preferences(self, body):
        self.body = body
        return {"status": "ok"}


def test_preferences_facade_maps_wire_keys():
    raw = FakeClient()
    client = SnaplinkUserPreferencesClient(raw)

    assert client.get_my_preferences().locale == "zh-CN"
    assert client.get_my_preferences().theme_mode == "dark"
    assert client.update_my_preferences(
        PresentationPreferencesPatch(locale="en-US", theme_mode="light")
    ) == {"status": "ok"}
    assert raw.body == {"locale": "en-US", "sverp:theme_mode": "light"}


def test_login_handoff_only_contains_explicit_values():
    assert build_login_preference_handoff(
        PresentationPreferencesPatch(locale="en-US")
    ) == {"presentation_locale": "en-US"}
    assert build_login_preference_handoff(
        PresentationPreferencesPatch(theme_mode="dark")
    ) == {"presentation_theme_mode": "dark"}
    assert build_login_preference_handoff(PresentationPreferencesPatch()) == {}


def test_login_handoff_can_be_passed_to_hosted_login():
    client = Snaplink()
    handoff = build_login_preference_handoff(
        PresentationPreferencesPatch(locale="en-US", theme_mode="dark")
    )
    result = client.login({
        "base_url": "https://sso.example.test",
        "client_id": "web",
        "redirect_uri": "https://app.example.test/callback",
        **handoff,
    })
    assert "presentation_locale=en-US" in result.redirect_url
    assert "presentation_theme_mode=dark" in result.redirect_url
