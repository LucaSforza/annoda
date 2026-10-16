count-lines:
    @find . -type f -name '*.rs' ! -path './target/*' ! -path '*/tests/*' ! -name '*_tests.rs' ! -name '*_test.rs' ! -name 'test_*.rs' ! -name '*test_fixture.rs' -print0 | xargs -0 awk 'index($$0, "#[cfg(test)]") != 1 && index($$0, "#[path = \"tests/") != 1 && index($$0, "#[path = \"../tests/") != 1 && $$0 != "mod tests;" { lines++ } END { print lines, "total" }'
