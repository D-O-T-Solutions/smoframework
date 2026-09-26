#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "smo::smo" for configuration "Debug"
set_property(TARGET smo::smo APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(smo::smo PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/smo"
  )

list(APPEND _cmake_import_check_targets smo::smo )
list(APPEND _cmake_import_check_files_for_smo::smo "${_IMPORT_PREFIX}/bin/smo" )

# Import target "smo::smo-node" for configuration "Debug"
set_property(TARGET smo::smo-node APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(smo::smo-node PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/smo-node"
  )

list(APPEND _cmake_import_check_targets smo::smo-node )
list(APPEND _cmake_import_check_files_for_smo::smo-node "${_IMPORT_PREFIX}/bin/smo-node" )

# Import target "smo::smo-cli" for configuration "Debug"
set_property(TARGET smo::smo-cli APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(smo::smo-cli PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/smo-cli"
  )

list(APPEND _cmake_import_check_targets smo::smo-cli )
list(APPEND _cmake_import_check_files_for_smo::smo-cli "${_IMPORT_PREFIX}/bin/smo-cli" )

# Import target "smo::smo-admin" for configuration "Debug"
set_property(TARGET smo::smo-admin APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(smo::smo-admin PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/smo-admin"
  )

list(APPEND _cmake_import_check_targets smo::smo-admin )
list(APPEND _cmake_import_check_files_for_smo::smo-admin "${_IMPORT_PREFIX}/bin/smo-admin" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
