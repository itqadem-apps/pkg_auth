"""LocalizedText / ServiceName / PermissionVisibility value-object tests."""
import pytest

from pkg_auth.authorization import (
    LocalizedText,
    PermissionVisibility,
    ServiceName,
)


def test_from_input_string_uses_default_locale():
    lt = LocalizedText.from_input("Edit course", default_locale="en")
    assert lt.as_dict() == {"en": "Edit course"}


def test_from_input_none_is_empty():
    assert LocalizedText.from_input(None, default_locale="en").as_dict() == {}


def test_from_input_dict_passthrough():
    lt = LocalizedText.from_input({"en": "a", "ar": "ب"}, default_locale="en")
    assert lt.get("ar") == "ب"


def test_from_input_localized_text_passthrough():
    src = LocalizedText({"en": "x"})
    assert LocalizedText.from_input(src, default_locale="ar") is src


def test_resolve_prefers_locale_then_default_then_any():
    lt = LocalizedText({"ar": "ب", "fr": "f"})
    assert lt.resolve("ar", "en") == "ب"          # exact
    lt2 = LocalizedText({"en": "e", "fr": "f"})
    assert lt2.resolve("ar", "en") == "e"          # default fallback
    lt3 = LocalizedText({"fr": "f"})
    assert lt3.resolve("ar", "en") == "f"          # any
    assert LocalizedText({}).resolve("ar", "en") is None


def test_rejects_empty_value():
    with pytest.raises(ValueError):
        LocalizedText({"en": ""})


def test_values_are_copied_not_aliased():
    src = {"en": "x"}
    lt = LocalizedText(src)
    src["en"] = "mutated"
    assert lt.get("en") == "x"


@pytest.mark.parametrize("ok", ["courses", "media-library", "assess_ments", "a1"])
def test_service_name_accepts_slugs(ok):
    assert str(ServiceName(ok)) == ok


@pytest.mark.parametrize("bad", ["Courses", "1course", "", "with space", "-x"])
def test_service_name_rejects_bad(bad):
    with pytest.raises(ValueError):
        ServiceName(bad)


def test_visibility_values():
    assert PermissionVisibility.PLATFORM_ONLY.value == "platform_only"
    assert PermissionVisibility.SHARED.value == "shared"
    assert PermissionVisibility.TENANT_ONLY.value == "tenant_only"
