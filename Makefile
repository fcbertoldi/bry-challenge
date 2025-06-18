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

.PHONY: cmake-configure build-debug build-release test clean
