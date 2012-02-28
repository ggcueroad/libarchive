############################################
#
# How to build bsdpax_test
#
############################################
IF(ENABLE_PAX AND ENABLE_TEST)
  SET(bsdpax_test_SOURCES
    main.c
    test.h
    test_0.c
    test_basic.c
    test_format_newc.c
    test_help.c
    test_option_D_upper.c
    test_option_H_upper.c
    test_option_J_upper.c
    test_option_L_upper.c
    test_option_T_upper.c
    test_option_Y_upper.c
    test_option_Z_upper.c
    test_option_a.c
    test_option_b.c
    test_option_c.c
    test_option_compress.c
    test_option_d.c
    test_option_j.c
    test_option_k.c
    test_option_l.c
    test_option_lzma.c
    test_option_n.c
    test_option_nodump.c
    test_option_null.c
    test_option_o.c
    test_option_s.c
    test_option_t.c
    test_option_u.c
    test_option_z.c
    test_options_listopt.c
    test_print_longpath.c
    test_strip_components.c
    test_version.c
  )
  IF(WIN32 AND NOT CYGWIN)
    LIST(APPEND bsdpax_test_SOURCES ../bsdpax_windows.h)
  ENDIF(WIN32 AND NOT CYGWIN)

  #
  # Register target
  #
  ADD_EXECUTABLE(bsdpax_test ${bsdpax_test_SOURCES})
  SET_PROPERTY(TARGET bsdpax_test PROPERTY COMPILE_DEFINITIONS LIST_H)

  #
  # Generate list.h by grepping DEFINE_TEST() lines out of the C sources.
  #
  GENERATE_LIST_H(${CMAKE_CURRENT_BINARY_DIR}/list.h
    ${CMAKE_CURRENT_LIST_FILE} ${bsdpax_test_SOURCES})
  SET_PROPERTY(DIRECTORY APPEND PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_BINARY_DIR})

  # list.h has a line DEFINE_TEST(testname) for every
  # test.  We can use that to define the tests for cmake by
  # defining a DEFINE_TEST macro and reading list.h in.
  MACRO (DEFINE_TEST _testname)
    ADD_TEST(
      NAME bsdpax_${_testname}
      COMMAND bsdpax_test -vv
                          -p $<TARGET_FILE:bsdpax>
                          -r ${CMAKE_CURRENT_SOURCE_DIR}
                          ${_testname})
  ENDMACRO (DEFINE_TEST _testname)

  INCLUDE(${CMAKE_CURRENT_BINARY_DIR}/list.h)

  # Experimental new test handling
  ADD_CUSTOM_TARGET(run_bsdpax_test
	COMMAND	bsdpax_test -p ${BSDPAX} -r ${CMAKE_CURRENT_SOURCE_DIR})
  ADD_DEPENDENCIES(run_bsdpax_test bsdpax)
  ADD_DEPENDENCIES(run_all_tests run_bsdpax_test)

ENDIF (ENABLE_PAX AND ENABLE_TEST)
