# CMake Integration

## As a Subdirectory

```cmake
add_subdirectory(third_party/loc++)
target_link_libraries(my_app PRIVATE loc::loc)
```

Header-only mode (no tests/examples built):

```cmake
set(LOC_BUILD_API_ONLY ON CACHE BOOL "" FORCE)
add_subdirectory(third_party/loc++)
target_link_libraries(my_app PRIVATE loc::loc)
```

## As an Installed Package

```bash
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build
cmake --install build
```

Or header-only:

```bash
just install-header-only prefix=/usr/local
```

Then:

```cmake
find_package(loc CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE loc::loc)
```

## Notes

- Decode paths are zero-copy. `loc::collect_properties()` returns views into original buffers.
- Decoding requires the encoded private-properties byte length (from a higher-level container or protocol).
