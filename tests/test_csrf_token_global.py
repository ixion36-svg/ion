"""The csrf_token Jinja global resolves per-request and is falsy when absent."""

from ion.web._csrf_token import _CSRFTokenProxy, _csrf_token_var


def test_proxy_is_empty_outside_a_request():
    proxy = _CSRFTokenProxy()
    assert str(proxy) == ""


def test_proxy_is_falsy_when_empty():
    # base.html guards the meta tag with `{% if csrf_token %}`, so the proxy
    # must be falsy for anonymous pages rather than always-truthy like a bare
    # object would be.
    assert not _CSRFTokenProxy()


def test_proxy_resolves_the_current_value():
    token = _csrf_token_var.set("deadbeef")
    try:
        assert str(_CSRFTokenProxy()) == "deadbeef"
        assert bool(_CSRFTokenProxy()) is True
    finally:
        _csrf_token_var.reset(token)


def test_proxy_html_escapes_to_the_same_value():
    token = _csrf_token_var.set("deadbeef")
    try:
        assert _CSRFTokenProxy().__html__() == "deadbeef"
    finally:
        _csrf_token_var.reset(token)


def test_make_templates_registers_the_global():
    from ion.web.templating import make_templates

    templates = make_templates()
    assert "csrf_token" in templates.env.globals


def test_template_renders_the_current_token():
    from ion.web.templating import make_templates

    templates = make_templates()
    tpl = templates.env.from_string("{% if csrf_token %}{{ csrf_token }}{% else %}none{% endif %}")
    assert tpl.render() == "none"
    token = _csrf_token_var.set("abc123")
    try:
        assert tpl.render() == "abc123"
    finally:
        _csrf_token_var.reset(token)
