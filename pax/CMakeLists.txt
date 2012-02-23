############################################
#
# How to build bsdpax
#
############################################
IF (ENABLE_PAX)

  SET(bsdpax_SOURCES
    bsdpax.c
    bsdpax.h
    bsdpax_platform.h
    cmdline.c
    copy.c
    getdate.c
    options.c
    options.h
    read.c
    subst.c
    util.c
    write.c
    ../libarchive_fe/err.c
    ../libarchive_fe/err.h
    ../libarchive_fe/lafe_platform.h
    ../libarchive_fe/line_reader.c
    ../libarchive_fe/line_reader.h
  )
  INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../libarchive_fe)
  IF(WIN32 AND NOT CYGWIN)
    LIST(APPEND bsdpax_SOURCES bsdpax_windows.h)
  ENDIF(WIN32 AND NOT CYGWIN)

  # bsdpax documentation
  SET(bsdpax_MANS bsdpax.1)

  # How to build bsdpax
  ADD_EXECUTABLE(bsdpax ${bsdpax_SOURCES})
  IF(ENABLE_PAX_SHARED)
    TARGET_LINK_LIBRARIES(bsdpax archive ${ADDITIONAL_LIBS})
  ELSE(ENABLE_PAX_SHARED)
    TARGET_LINK_LIBRARIES(bsdpax archive_static ${ADDITIONAL_LIBS})
    SET_TARGET_PROPERTIES(bsdpax PROPERTIES COMPILE_DEFINITIONS
    				 LIBARCHIVE_STATIC)
  ENDIF(ENABLE_PAX_SHARED)
  GET_TARGET_PROPERTY(BSDPAX bsdpax LOCATION)

  # Installation rules
  INSTALL(TARGETS bsdpax RUNTIME DESTINATION bin)
  INSTALL_MAN(${bsdpax_MANS})
ENDIF(ENABLE_PAX)

add_subdirectory(test)
