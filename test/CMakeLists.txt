set (PROJECT_NAME libdnsrmap-tests)
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})

if (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        file(GLOB HDRS "*.h" )
        file(GLOB SRCS "*.cpp" )
else()
	file(GLOB HDRS "*.h" "../src/include/${CMAKE_SYSTEM_NAME}/*.h" )
	file(GLOB SRCS "*.cpp" )
endif()

add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	target_link_libraries (${PROJECT_NAME}
		 zdnsrmap c dl "${OS_LIBS}" "${GTESTDIR}/${CMAKE_SYSTEM_NAME}/libgtest.a")
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	target_link_libraries (${PROJECT_NAME} ${OS_LIBS} zdnsrmap )
	target_link_libraries (${PROJECT_NAME}
	          debug "${GTESTDIR}/Windows/gtestd.lib"
	          optimized "${GTESTDIR}/Windows/gtest.lib")
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	target_link_libraries (${PROJECT_NAME} zdnsrmap
		 "${OS_LIBS}" "${GTESTDIR}/${CMAKE_SYSTEM_NAME}/libgtest.a" )
endif()
