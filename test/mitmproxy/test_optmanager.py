import argparse
import copy
import io
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

import pytest

from mitmproxy import exceptions
from mitmproxy import options
from mitmproxy import optmanager


class TO(optmanager.OptManager):
    def __init__(self):
        super().__init__()
        self.add_option("one", Optional[int], None, "help")
        self.add_option("two", Optional[int], 2, "help")
        self.add_option("bool", bool, False, "help")
        self.add_option("required_int", int, 2, "help")


class TD(optmanager.OptManager):
    def __init__(self):
        super().__init__()
        self.add_option("one", str, "done", "help")
        self.add_option("two", str, "dtwo", "help")


class TD2(TD):
    def __init__(self):
        super().__init__()
        self.add_option("three", str, "dthree", "help")
        self.add_option("four", str, "dfour", "help")


class TM(optmanager.OptManager):
    def __init__(self):
        super().__init__()
        self.add_option("two", Sequence[str], ["foo"], "help")
        self.add_option("one", Optional[str], None, "help")


class TS(optmanager.OptManager):
    def __init__(self):
        super().__init__()
        self.add_option("scripts", Sequence[str], [], "help")
        self.add_option("not_scripts", Sequence[str], [], "help")


def test_defaults():
    o = TD2()
    defaults = {
        "one": "done",
        "two": "dtwo",
        "three": "dthree",
        "four": "dfour",
    }
    for k, v in defaults.items():
        assert o.default(k) == v

    assert not o.has_changed("one")
    newvals = dict(
        one="xone",
        two="xtwo",
        three="xthree",
        four="xfour",
    )
    o.update(**newvals)
    assert o.has_changed("one")
    for k, v in newvals.items():
        assert v == getattr(o, k)
    o.reset()
    assert not o.has_changed("one")

    for k in o.keys():
        assert not o.has_changed(k)


def test_required_int():
    o = TO()
    with pytest.raises(exceptions.OptionsError):
        o._parse_setval(o._options["required_int"], [])


def test_deepcopy():
    o = TD()
    copy.deepcopy(o)


def test_options():
    o = TO()
    assert o.keys() == {"bool", "one", "two", "required_int"}

    assert o.one is None
    assert o.two == 2
    o.one = 1
    assert o.one == 1

    with pytest.raises(TypeError):
        TO(nonexistent="value")
    with pytest.raises(Exception, match="Unknown options"):
        o.nonexistent = "value"
    with pytest.raises(Exception, match="Unknown options"):
        o.update(nonexistent="value")
    assert o.update_known(nonexistent="value") == {"nonexistent": "value"}

    rec = []

    def sub(updated):
        rec.append(copy.copy(o))

    o.changed.connect(sub)

    o.one = 90
    assert len(rec) == 1
    assert rec[-1].one == 90

    o.update(one=3)
    assert len(rec) == 2
    assert rec[-1].one == 3


def test_setter():
    o = TO()
    f = o.setter("two")
    f(99)
    assert o.two == 99
    with pytest.raises(Exception, match="No such option"):
        o.setter("nonexistent")


def test_toggler():
    o = TO()
    f = o.toggler("bool")
    assert o.bool is False
    f()
    assert o.bool is True
    f()
    assert o.bool is False
    with pytest.raises(Exception, match="No such option"):
        o.toggler("nonexistent")

    with pytest.raises(Exception, match="boolean options"):
        o.toggler("one")


class Rec:
    def __init__(self):
        self.called = None

    def __call__(self, *args, **kwargs):
        self.called = (args, kwargs)


def test_subscribe():
    o = TO()
    r = Rec()

    # pytest.raises keeps a reference here that interferes with the cleanup test
    # further down.
    try:
        o.subscribe(r, ["unknown"])
    except exceptions.OptionsError:
        pass
    else:
        raise AssertionError

    assert len(o._subscriptions) == 0

    o.subscribe(r, ["two"])
    o.one = 2
    assert not r.called
    o.two = 3
    assert r.called

    assert len(o.changed.receivers) == 1
    del r
    o.two = 4
    assert len(o._subscriptions) == 0

    class binder:
        def __init__(self):
            self.o = TO()
            self.called = False
            self.o.subscribe(self.bound, ["two"])

        def bound(self, *args, **kwargs):
            self.called = True

    t = binder()
    t.o.one = 3
    assert not t.called
    t.o.two = 3
    assert t.called


def test_rollback():
    o = TO()

    rec = []

    def sub(updated):
        rec.append(copy.copy(o))

    recerr = []

    def errsub(**kwargs):
        recerr.append(kwargs)

    def err(updated):
        if o.one == 10:
            raise exceptions.OptionsError()
        if o.bool is True:
            raise exceptions.OptionsError()

    o.changed.connect(sub)
    o.changed.connect(err)
    o.errored.connect(errsub)

    assert o.one is None
    with pytest.raises(exceptions.OptionsError):
        o.one = 10
    assert o.one is None
    with pytest.raises(exceptions.OptionsError):
        o.bool = True
    assert o.bool is False
    assert isinstance(recerr[0]["exc"], exceptions.OptionsError)
    assert o.one is None
    assert o.bool is False
    assert len(rec) == 4
    assert rec[0].one == 10
    assert rec[1].one is None
    assert rec[2].bool is True
    assert rec[3].bool is False

    with pytest.raises(exceptions.OptionsError):
        with o.rollback({"one"}, reraise=True):
            raise exceptions.OptionsError()


def test_simple():
    o = TO()
    assert repr(o)
    assert "one" in o

    with pytest.raises(Exception, match="No such option"):
        assert o.unknown


def test_items():
    assert TO().items()


def test_serialize():
    def serialize(
        opts: optmanager.OptManager, text: str, defaults: bool = False
    ) -> str:
        buf = io.StringIO()
        optmanager.serialize(opts, buf, text, defaults)
        return buf.getvalue()

    o = TD2()
    o.three = "set"
    assert "dfour" in serialize(o, "", defaults=True)

    data = serialize(o, "")
    assert "dfour" not in data

    o2 = TD2()
    optmanager.load(o2, data)
    assert o2 == o
    assert not o == 42

    t = """
        unknown: foo
    """
    data = serialize(o, t)
    o2 = TD2()
    optmanager.load(o2, data)
    assert o2 == o

    t = "invalid: foo\ninvalid"
    with pytest.raises(Exception, match="Config error"):
        optmanager.load(o2, t)

    t = "invalid"
    with pytest.raises(Exception, match="Config error"):
        optmanager.load(o2, t)

    t = "# a comment"
    optmanager.load(o2, t)
    optmanager.load(o2, "foobar: '123'")
    assert o2.deferred == {"foobar": "123"}

    t = ""
    optmanager.load(o2, t)
    optmanager.load(o2, "foobar: '123'")
    assert o2.deferred == {"foobar": "123"}


def test_serialize_defaults():
    o = options.Options()
    buf = io.StringIO()
    optmanager.serialize(o, buf, "", defaults=True)
    assert buf.getvalue()


def test_saving(tmpdir):
    o = TD2()
    o.three = "set"
    dst = Path(tmpdir.join("conf"))
    optmanager.save(o, dst, defaults=True)

    o2 = TD2()
    optmanager.load_paths(o2, dst)
    o2.three = "foo"
    optmanager.save(o2, dst, defaults=True)

    optmanager.load_paths(o, dst)
    assert o.three == "foo"

    with open(dst, "a") as f:
        f.write("foobar: '123'")
    optmanager.load_paths(o, dst)
    assert o.deferred == {"foobar": "123"}

    with open(dst, "a") as f:
        f.write("'''")
    with pytest.raises(exceptions.OptionsError):
        optmanager.load_paths(o, dst)

    with open(dst, "wb") as f:
        f.write(b"\x01\x02\x03")
    with pytest.raises(exceptions.OptionsError):
        optmanager.load_paths(o, dst)
    with pytest.raises(exceptions.OptionsError):
        optmanager.save(o, dst)

    with open(dst, "wb") as f:
        f.write(b"\xff\xff\xff")
    with pytest.raises(exceptions.OptionsError):
        optmanager.load_paths(o, dst)
    with pytest.raises(exceptions.OptionsError):
        optmanager.save(o, dst)


def test_merge():
    m = TM()
    m.merge(dict(one="two"))
    assert m.one == "two"
    m.merge(dict(one=None))
    assert m.one == "two"
    m.merge(dict(two=["bar"]))
    assert m.two == ["foo", "bar"]


def test_option():
    o = optmanager._Option("test", int, 1, "help", None)
    assert o.current() == 1
    with pytest.raises(TypeError):
        o.set("foo")
    with pytest.raises(TypeError):
        optmanager._Option("test", str, 1, "help", None)

    o2 = optmanager._Option("test", int, 1, "help", None)
    assert o2 == o
    o2.set(5)
    assert o2 != o


def test_dump_defaults():
    o = TTypes()
    buf = io.StringIO()
    optmanager.dump_defaults(o, buf)
    assert buf.getvalue()


def test_dump_dicts():
    o = options.Options()
    assert optmanager.dump_dicts(o)
    assert optmanager.dump_dicts(o, ["http2", "listen_port"])


class TTypes(optmanager.OptManager):
    def __init__(self):
        super().__init__()
        self.add_option("str", str, "str", "help")
        self.add_option("choices", str, "foo", "help", ["foo", "bar", "baz"])
        self.add_option("optstr", Optional[str], "optstr", "help")
        self.add_option("bool", bool, False, "help")
        self.add_option("bool_on", bool, True, "help")
        self.add_option("int", int, 0, "help")
        self.add_option("optint", Optional[int], 0, "help")
        self.add_option("seqstr", Sequence[str], [], "help")
        self.add_option("unknown", float, 0.0, "help")


def test_make_parser():
    parser = argparse.ArgumentParser()
    opts = TTypes()
    opts.make_parser(parser, "str", short="a")
    opts.make_parser(parser, "bool", short="b")
    opts.make_parser(parser, "int", short="c")
    opts.make_parser(parser, "seqstr", short="d")
    opts.make_parser(parser, "bool_on", short="e")

    with pytest.raises(ValueError):
        opts.make_parser(parser, "unknown")

    # Nonexistent options ignore
    opts.make_parser(parser, "nonexistentxxx")


def test_set():
    opts = TTypes()

    opts.set("str=foo")
    assert opts.str == "foo"
    with pytest.raises(exceptions.OptionsError):
        opts.set("str")

    opts.set("optstr=foo")
    assert opts.optstr == "foo"
    opts.set("optstr")
    assert opts.optstr is None
    with pytest.raises(exceptions.OptionsError, match="Received multiple values"):
        opts.set("optstr=foo", "optstr=bar")

    opts.set("bool=false")
    assert opts.bool is False
    opts.set("bool")
    assert opts.bool is True
    opts.set("bool=true")
    assert opts.bool is True
    with pytest.raises(exceptions.OptionsError, match="Failed to parse option bool: "):
        opts.set("bool=wobble")

    opts.set("bool=toggle")
    assert opts.bool is False
    opts.set("bool=toggle")
    assert opts.bool is True

    opts.set("int=1")
    assert opts.int == 1
    with pytest.raises(exceptions.OptionsError, match="Failed to parse option int: "):
        opts.set("int=wobble")
    opts.set("optint")
    assert opts.optint is None

    assert opts.seqstr == []
    opts.set("seqstr=foo")
    assert opts.seqstr == ["foo"]
    opts.set("seqstr=foo", "seqstr=bar")
    assert opts.seqstr == ["foo", "bar"]
    opts.set("seqstr")
    assert opts.seqstr == []

    with pytest.raises(exceptions.OptionsError):
        opts.set("deferredoption=wobble")

    opts.set("deferredoption=wobble", defer=True)
    assert "deferredoption" in opts.deferred
    opts.process_deferred()
    assert "deferredoption" in opts.deferred
    opts.add_option("deferredoption", str, "default", "help")
    opts.process_deferred()
    assert "deferredoption" not in opts.deferred
    assert opts.deferredoption == "wobble"

    opts.set(*("deferredsequenceoption=a", "deferredsequenceoption=b"), defer=True)
    assert "deferredsequenceoption" in opts.deferred
    opts.process_deferred()
    assert "deferredsequenceoption" in opts.deferred
    opts.add_option("deferredsequenceoption", Sequence[str], [], "help")
    opts.process_deferred()
    assert "deferredsequenceoption" not in opts.deferred
    assert opts.deferredsequenceoption == ["a", "b"]


def test_load_paths(tdata):
    opts = TS()
    conf_path = tdata.path("mitmproxy/data/test_config.yml")
    optmanager.load_paths(opts, conf_path)
    assert opts.scripts == [
        str(Path.home().absolute().joinpath("abc")),
        str(Path(conf_path).parent.joinpath("abc")),
        str(Path(conf_path).parent.joinpath("../abc")),
        str(Path("/abc").absolute()),
    ]
    assert opts.not_scripts == ["~/abc", "abc", "../abc", "/abc"]


@pytest.mark.parametrize(
    "script_path, relative_to, expected",
    (
        ("~/abc", ".", Path.home().joinpath("abc")),
        ("/abc", ".", Path("/abc")),
        ("abc", ".", Path(".").joinpath("abc")),
        ("../abc", ".", Path(".").joinpath("../abc")),
        ("~/abc", "/tmp", Path.home().joinpath("abc")),
        ("/abc", "/tmp", Path("/abc")),
        ("abc", "/tmp", Path("/tmp").joinpath("abc")),
        ("../abc", "/tmp", Path("/tmp").joinpath("../abc")),
        ("~/abc", "foo", Path.home().joinpath("abc")),
        ("/abc", "foo", Path("/abc")),
        ("abc", "foo", Path("foo").joinpath("abc")),
        ("../abc", "foo", Path("foo").joinpath("../abc")),
    ),
)
def test_relative_path(script_path, relative_to, expected):
    assert (
        optmanager.relative_path(
            script_path,
            relative_to=relative_to,
        )
        == expected.absolute()
    )


# ---------------------------------------------------------------------------
# Value source tracking
# ---------------------------------------------------------------------------


class TSensitive(optmanager.OptManager):
    def __init__(self):
        super().__init__()
        self.add_option("secret", Optional[str], None, "help", sensitive=True)


def _source(category, location=None):
    return optmanager.Source(category, location)


def test_source_info_default():
    o = TO()
    info = o.source_info("two")
    assert info["effective_value"] == 2
    assert info["effective_source"] == optmanager.Source(optmanager.SOURCE_DEFAULT)
    assert info["at_default"] is True
    assert info["conflict"] is False
    assert info["multiple_sources"] is False
    assert len(info["sources"]) == 1
    assert info["sources"][0]["category"] == "default"
    assert info["sources"][0].get("effective") is True

    with pytest.raises(KeyError):
        o.source_info("nonexistent")


def test_source_info_config_file(tmpdir):
    o = TD()
    p = tmpdir.join("config.yaml")
    p.write("one: fromfile\n")
    optmanager.load_paths(o, p)

    info = o.source_info("one")
    assert info["effective_value"] == "fromfile"
    assert info["effective_source"].category == "config-file"
    assert info["effective_source"].location == str(p)
    rows = info["sources"]
    assert rows[-1].get("effective") is True
    assert rows[0]["reason"].startswith("overridden by")


def test_source_info_multiple_config_files(tmpdir):
    o = TD()
    p1 = tmpdir.join("a.yaml")
    p2 = tmpdir.join("b.yaml")
    p1.write("one: a\n")
    p2.write("one: b\n")
    optmanager.load_paths(o, p1, p2)

    info = o.source_info("one")
    assert info["effective_value"] == "b"
    assert info["effective_source"].location == str(p2)
    config_rows = [r for r in info["sources"] if r["category"] == "config-file"]
    assert [r["location"] for r in config_rows] == [str(p1), str(p2)]
    assert config_rows[0]["value"] == "a"
    assert config_rows[0]["reason"] == f"overridden by config file {p2}"
    assert config_rows[1].get("effective") is True


def test_source_info_override_chain():
    o = TO()
    o.set(
        "two=20",
        _source=_source(optmanager.SOURCE_SET, "command line"),
    )
    optmanager.load(
        o,
        "two: 21",
        _source=_source(optmanager.SOURCE_CONFIG_FILE, "/x/config.yaml"),
    )
    o.update(
        _sources={"two": _source(optmanager.SOURCE_COMMAND_LINE, "--two")},
        two=22,
    )

    assert o.two == 22
    info = o.source_info("two")
    assert info["effective_value"] == 22
    assert info["effective_source"] == _source(optmanager.SOURCE_COMMAND_LINE, "--two")
    assert info["conflict"] is True
    assert info["at_default"] is False

    categories = [r["category"] for r in info["sources"]]
    assert categories == ["default", "set", "config-file", "command-line"]
    values = [r["value"] for r in info["sources"]]
    assert values == [2, 20, 21, 22]
    assert info["sources"][1]["reason"] == "overridden by config file /x/config.yaml"
    assert info["sources"][2]["reason"] == "overridden by command-line --two"
    assert info["sources"][3].get("effective") is True


def test_source_info_same_value_multiple_sources():
    o = TO()
    o.set("two=20", _source=_source(optmanager.SOURCE_SET, "command line"))
    o.update(
        _sources={"two": _source(optmanager.SOURCE_COMMAND_LINE, "--two")},
        two=20,
    )
    info = o.source_info("two")
    assert info["effective_value"] == 20
    assert info["conflict"] is False
    assert info["multiple_sources"] is True
    assert info["sources"][-1]["category"] == "command-line"
    assert info["sources"][-1].get("effective") is True
    assert info["sources"][1]["reason"].startswith("overridden by")


def test_source_info_runtime_revert_falls_back():
    o = TO()
    optmanager.load(
        o,
        "two: 21",
        _source=_source(optmanager.SOURCE_CONFIG_FILE, "/x/config.yaml"),
    )
    o.update(two=99, _source=_source(optmanager.SOURCE_RUNTIME, "web interface"))
    assert o.source_info("two")["effective_source"].category == "runtime"

    # Restoring the value held before the runtime run undoes the override.
    o.update(two=21, _source=_source(optmanager.SOURCE_RUNTIME, "web interface"))
    info = o.source_info("two")
    assert o.two == 21
    assert info["effective_source"].category == "config-file"
    assert info["effective_source"].location == "/x/config.yaml"
    assert info["sources"][-1]["reverted"] is True
    assert "fell back to config file /x/config.yaml" in info["sources"][-1]["reason"]

    # A runtime value that merely coincides with a buried source is not a
    # revert: the last write still wins.
    o.set("two=5", _source=_source(optmanager.SOURCE_SET, "command line"))
    o.update(two=21)
    assert o.source_info("two")["effective_source"].category == "runtime"


def test_source_info_runtime_revert_to_default():
    o = TO()
    o.bool = True
    o.bool = False
    info = o.source_info("bool")
    assert o.bool is False
    assert info["at_default"] is True
    assert info["effective_source"].category == "default"
    assert info["sources"][-1]["reverted"] is True


def test_source_info_reset():
    o = TO()
    o.two = 99
    assert o.source_info("two")["at_default"] is False

    o.reset()
    info = o.source_info("two")
    assert o.two == 2
    assert info["at_default"] is True
    assert info["effective_source"].category == "default"
    # The pre-reset chain is no longer part of the current picture.
    assert len(info["sources"]) == 1

    # Source tracking keeps working after a reset.
    o.two = 7
    info = o.source_info("two")
    assert info["effective_value"] == 7
    assert info["effective_source"].category == "runtime"


def test_source_info_rollback_restores_history():
    o = TO()

    def fail(updated):
        if "two" in updated:
            raise exceptions.OptionsError("nope")

    o.changed.connect(fail)
    with pytest.raises(exceptions.OptionsError):
        o.update(two=99)
    assert o.two == 2
    info = o.source_info("two")
    assert info["at_default"] is True
    assert len(info["sources"]) == 1


def test_source_info_deepcopy_preserves_history():
    o = TO()
    o.set(
        "two=20",
        _source=_source(optmanager.SOURCE_SET, "command line"),
    )
    o2 = copy.deepcopy(o)
    info = o2.source_info("two")
    assert info["effective_value"] == 20
    assert info["effective_source"].category == "set"


def test_source_equality_ignores_history():
    o1 = TD()
    o1.one = "x"
    o2 = TD()
    optmanager.load(o2, "one: x\n")
    assert o1 == o2


def test_source_info_deferred():
    o = TO()
    o.set(
        "deferredoption=wobble",
        defer=True,
        _source=_source(optmanager.SOURCE_SET, "command line"),
    )
    o.add_option("deferredoption", str, "default", "help")
    o.process_deferred()
    info = o.source_info("deferredoption")
    assert info["effective_value"] == "wobble"
    assert info["effective_source"].category == "set"

    # A deferred config value overrides a deferred --set value.
    o2 = TO()
    o2.set(
        "other=fromset",
        defer=True,
        _source=_source(optmanager.SOURCE_SET, "command line"),
    )
    optmanager.load(
        o2,
        "other: fromconfig",
        _source=_source(optmanager.SOURCE_CONFIG_FILE, "/x/config.yaml"),
    )
    o2.add_option("other", str, "default", "help")
    o2.process_deferred()
    info = o2.source_info("other")
    assert info["effective_value"] == "fromconfig"
    assert info["effective_source"].category == "config-file"


def test_source_info_sensitive():
    o = TSensitive()
    info = o.source_info("secret")
    assert info["sensitive"] is True
    assert info["effective_value"] == {"sensitive": True, "set": False}
    for row in info["sources"]:
        assert "value" not in row
        assert row["set"] is False

    o.update(secret="hunter2", _source=_source(optmanager.SOURCE_SET, "set command"))
    info = o.source_info("secret")
    assert info["effective_value"] == {"sensitive": True, "set": True}
    assert all("hunter2" not in str(row) for row in info["sources"])
    assert info["sources"][-1]["set"] is True


def test_effective_value_matches_live_value():
    o = options.Options()
    o.set(
        "listen_port=1234",
        _source=_source(optmanager.SOURCE_SET, "command line"),
    )
    optmanager.load(
        o,
        "showhost: true\nhttp2: false",
        _source=_source(optmanager.SOURCE_CONFIG_FILE, "/x/config.yaml"),
    )
    o.update(
        _sources={
            "listen_port": _source(optmanager.SOURCE_COMMAND_LINE, "--listen-port")
        },
        listen_port=4321,
    )
    o.showhost = False  # runtime revert of the config value
    for name, info in o.source_infos().items():
        if info["sensitive"]:
            continue
        assert info["effective_value"] == getattr(o, name), name


def test_dump_sources():
    o = TO()
    o.set("two=20", _source=_source(optmanager.SOURCE_SET, "command line"))
    o.update(
        _sources={"two": _source(optmanager.SOURCE_COMMAND_LINE, "--two")},
        two=22,
    )

    buf = io.StringIO()
    optmanager.dump_sources(o, buf, "two")
    report = buf.getvalue()
    assert "two\n" in report
    assert "Effective value : 22" in report
    assert "command-line --two" in report
    assert "(effective)" in report
    assert "Summary:" not in report

    buf = io.StringIO()
    optmanager.dump_sources(o, buf)
    report = buf.getvalue()
    assert "Summary:" in report
    assert "two" in report
    assert "Keys with disagreeing sources" in report

    buf = io.StringIO()
    with pytest.raises(exceptions.OptionsError):
        optmanager.dump_sources(o, buf, "nonexistent")


def test_dump_sources_redacts_sensitive_values():
    o = options.Options()
    o.update(cert_passphrase="correct horse battery staple")
    buf = io.StringIO()
    optmanager.dump_sources(o, buf, "cert_passphrase")
    report = buf.getvalue()
    assert "correct horse battery staple" not in report
    assert "[set]" in report
