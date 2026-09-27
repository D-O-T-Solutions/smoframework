file(REMOVE_RECURSE
  "libsmo_trust.a"
  "libsmo_trust.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/smo_trust.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
