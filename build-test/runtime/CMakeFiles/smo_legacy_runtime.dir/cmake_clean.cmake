file(REMOVE_RECURSE
  "libsmo_legacy_runtime.a"
  "libsmo_legacy_runtime.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/smo_legacy_runtime.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
