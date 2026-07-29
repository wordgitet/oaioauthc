SUBDIRS = src tests
dist_man_MANS = docs/oaioauthc.1
EXTRA_DIST = README.md COPYING AI_DISCLOSURE.md docs/api-compatibility.md \
	.githooks/pre-commit .githooks/pre-push tools/check-tree \
	tools/install-hooks

if ENABLE_FUZZING
.PHONY: fuzz-smoke
fuzz-smoke:
	$(MAKE) -C tests fuzz-smoke
endif
