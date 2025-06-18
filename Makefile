cmake-configure:
	cmake --preset default

build-debug:
	cmake --build build --config Debug

build-release:
	cmake --build build --config Release

test:
	ctest --test-dir build

clean:
	rm -rf build/

archive:
	git archive --prefix=bry-challenge/ --format=zip --output=./bry-challenge.zip HEAD

.PHONY: cmake-configure build-debug build-release test clean
