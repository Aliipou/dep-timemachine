"""Tests for the multi-ecosystem requirements parser."""
import textwrap
from pathlib import Path

import pytest

from dep_timemachine.parsers.requirements_parser import _parse_requirements, _parse_package_json, _parse_go_mod, _parse_gemfile_lock


def test_parse_requirements_basic():
    text = textwrap.dedent("""\
        requests==2.31.0
        flask>=2.3,<3.0
        # comment line
        -r other.txt
        numpy
    """)
    deps = _parse_requirements(text)
    names = [d.name for d in deps]
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names
    assert all(d.ecosystem == "pypi" for d in deps)


def test_parse_requirements_version_spec():
    deps = _parse_requirements("fastapi==0.111.0\n")
    assert deps[0].version_spec == "==0.111.0"


def test_parse_requirements_inline_comment():
    deps = _parse_requirements("httpx>=0.27  # needed for async\n")
    assert deps[0].name == "httpx"
    assert "async" not in deps[0].version_spec


def test_parse_package_json():
    import json
    data = json.dumps({
        "dependencies": {"react": "^18.0.0", "axios": "^1.6.0"},
        "devDependencies": {"jest": "^29.0.0"},
    })
    deps = _parse_package_json(data)
    names = [d.name for d in deps]
    assert "react" in names
    assert "axios" in names
    assert "jest" in names
    assert all(d.ecosystem == "npm" for d in deps)


def test_parse_go_mod():
    text = textwrap.dedent("""\
        module example.com/myapp

        go 1.21

        require (
            github.com/gin-gonic/gin v1.9.1
            github.com/stretchr/testify v1.8.4
        )

        require github.com/go-playground/validator/v10 v10.16.0
    """)
    deps = _parse_go_mod(text)
    names = [d.name for d in deps]
    assert "github.com/gin-gonic/gin" in names
    assert "github.com/stretchr/testify" in names
    assert "github.com/go-playground/validator/v10" in names
    assert all(d.ecosystem == "go" for d in deps)


def test_parse_gemfile_lock():
    text = textwrap.dedent("""\
        GEM
          remote: https://rubygems.org/
          specs:
            rails (7.1.0)
            rack (3.0.4)

        PLATFORMS
          ruby

        BUNDLED WITH
           2.4.10
    """)
    deps = _parse_gemfile_lock(text)
    names = [d.name for d in deps]
    assert "rails" in names
    assert "rack" in names
    assert all(d.ecosystem == "rubygems" for d in deps)
    assert deps[0].version_spec in ("7.1.0", "3.0.4")


def test_parse_requirements_empty():
    deps = _parse_requirements("# only comments\n\n")
    assert deps == []


def test_parse_package_json_invalid():
    deps = _parse_package_json("not json {{{")
    assert deps == []
