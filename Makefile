artifact_name       := web-security-node
version             := "unversioned"

.PHONY: clean
clean:
	rm -f ./$(artifact_name)-*.zip
	rm -rf ./build-*
	rm -rf ./dist
	rm -f ./build.log

.PHONY: build
build:
	npm i
	npm run build
	mkdir -p ./dist/web-security-node/
	cp ./src/views/*.njk ./dist/web-security-node/

.PHONY: security-check
security-check:
	npm audit

.PHONY: lint
lint:
	npm run lint

.PHONY: test
test:
	npm run test

.PHONY: sonar
sonar:
	npm run sonarqube

.PHONY: package
package: build
ifndef version
	$(error No version given. Aborting)
endif
	$(info Packaging version: $(version))
	$(eval tmpdir := $(shell mktemp -d build-XXXXXXXXXX))
	cp -r ./dist/* $(tmpdir)
	cp -r ./package.json $(tmpdir)
	cp -r ./package-lock.json $(tmpdir)
	cd $(tmpdir) && npm i --production
	rm $(tmpdir)/package.json $(tmpdir)/package-lock.json
	cd $(tmpdir) && zip -r ../$(artifact_name)-$(version).zip .
	rm -rf $(tmpdir)

.PHONY: security-check
security-check:
	npm audit

.PHONY: dist
dist: lint test clean package
