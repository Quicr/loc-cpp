set shell := ["zsh", "-cu"]

build-dir := "build"

default:
  @just --list

configure:
  cmake -S . -B {{build-dir}} -DLOC_BUILD_TESTS=ON -DLOC_BUILD_EXAMPLES=ON

configure-release:
  cmake -S . -B {{build-dir}} -DCMAKE_BUILD_TYPE=Release

configure-bench:
  cmake -S . -B {{build-dir}} -DLOC_BUILD_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
  cmake --build {{build-dir}}

build:
  cmake --build {{build-dir}}

test:
  ctest --test-dir {{build-dir}} --output-on-failure

unit-test:
  ctest --test-dir {{build-dir}} --output-on-failure -R '^loc_unit_tests$'

integration-test:
  ctest --test-dir {{build-dir}} --output-on-failure -R '^loc_integration_tests$'

run-example:
  ./{{build-dir}}/loc_example

run-bench:
  ./{{build-dir}}/loc_benchmark

install prefix=".local":
  cmake -S . -B {{build-dir}}
  cmake --build {{build-dir}}
  cmake --install {{build-dir}} --prefix {{prefix}}

clean:
  rm -rf {{build-dir}}
